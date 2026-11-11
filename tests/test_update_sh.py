"""deploy/raspberry-pi/update.sh runs only an image whose attestation verifies, and by digest.

The script runs for real, with fake `docker`, `gh`, `flock` and `timeout` commands first on PATH
that record every call and answer only what update.sh asks. PATH holds nothing else but a few
basic tools (bash, dirname, mkdir, mv, date), so the real docker and gh (both installed on
GitHub's runners) are never reached. HOME is a temporary directory, so the script's state
(the last deployed run ID and its lock) never touches the real one.
"""

import fcntl
import os
import shutil
import stat
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

UPDATE_SCRIPT = Path(__file__).resolve().parent.parent / "deploy" / "raspberry-pi" / "update.sh"
IMAGE_REPOSITORY = "ghcr.io/the-secure-video-call/secure-call-backend"
PUBLISHED_DIGEST = "sha256:" + "ab12" * 16
IMAGE_BY_DIGEST = f"{IMAGE_REPOSITORY}@{PUBLISHED_DIGEST}"
VERIFIED_IMAGE_ID = "sha256:" + "cd34" * 16
CURRENT_GH_VERSION = (
    "gh version 2.103.3 (2026-10-26)\nhttps://github.com/cli/cli/releases/tag/v2.103.3"
)
SOURCE_REPOSITORY = "The-Secure-Video-Call/secure-call-backend"
BUILD_RUN_ID = 43000000000

# The attestation policy. publish-image.yml must check the published image with exactly these
# flags too (tests/test_publish_image_workflow.py).
VERIFY_POLICY_FLAGS = (
    f"--repo {SOURCE_REPOSITORY}",
    f"--signer-workflow {SOURCE_REPOSITORY}/.github/workflows/publish-image.yml",
    "--source-ref refs/heads/main",
    "--predicate-type https://slsa.dev/provenance/v1",
    "--deny-self-hosted-runners",
)
EXPECTED_VERIFY_CALL = " ".join(
    (
        f"gh attestation verify oci://{IMAGE_BY_DIGEST}",
        *VERIFY_POLICY_FLAGS,
        "--format json --jq .[].verificationResult.signature.certificate.runInvocationURI",
    )
)
LOOKUP_CALL = (
    f"docker buildx imagetools inspect {IMAGE_REPOSITORY}:main --format {{{{.Manifest.Digest}}}}"
)
RATE_LIMIT_CALL = "gh api --include /rate_limit"
REFUSED = "refused; the backend was not restarted."

FAKE_DOCKER = """#!/usr/bin/env bash
printf 'docker %s\\n' "$*" >> "$FAKE_CALL_LOG"
if [[ -n "${FAKE_FAILING_DOCKER_COMMAND:-}" && "$*" == "$FAKE_FAILING_DOCKER_COMMAND"* ]]; then
  exit 1
fi
case "$1 ${2:-}" in
  "buildx imagetools")
    if [[ -n "${FAKE_LOOKUP_FAILS:-}" ]]; then exit 1; fi
    printf '%s\\n' "$FAKE_PUBLISHED_DIGEST" ;;
  "image inspect") printf '%s\\n' "$FAKE_IMAGE_ID" ;;
  "compose ps") printf 'backend-container-id\\n' ;;
  "inspect --format") printf '%s\\n' "${FAKE_RUNNING_IMAGE_ID:-$FAKE_IMAGE_ID}" ;;
esac
"""

FAKE_GH = """#!/usr/bin/env bash
printf 'gh %s\\n' "$*" >> "$FAKE_CALL_LOG"
case "$1 ${2:-}" in
  "--version ")
    printf '%s\\n' "$FAKE_GH_VERSION_OUTPUT" ;;
  "api --include")
    if [[ -n "${FAKE_GH_API_FAILS:-}" ]]; then exit 1; fi
    printf 'HTTP/2.0 200 OK\\nContent-Type: application/json; charset=utf-8\\n'
    if [[ -n "${FAKE_TOKEN_EXPIRATION:-}" ]]; then
      printf 'Github-Authentication-Token-Expiration: %s\\n' "$FAKE_TOKEN_EXPIRATION"
    fi
    printf '\\n{"resources": {}}\\n' ;;
  "attestation verify")
    if [[ "$FAKE_VERIFY_RESULT" != "verified" ]]; then
      printf 'Error: no attestation matched the policy\\n' >&2
      exit 1
    fi
    printf '%s\\n' "$FAKE_RUN_INVOCATION_URIS" ;;
  *) exit 2 ;;
esac
"""

FAKE_FLOCK = """#!/usr/bin/env bash
printf 'flock %s\\n' "$*" >> "$FAKE_CALL_LOG"
[[ -z "${FAKE_LOCK_HELD:-}" ]]
"""

# Records the time limit, then runs the command (the fake docker or gh) without one.
FAKE_TIMEOUT = """#!/usr/bin/env bash
printf 'timeout %s\\n' "$*" >> "$FAKE_CALL_LOG"
shift
exec "$@"
"""

FAKES = {"docker": FAKE_DOCKER, "gh": FAKE_GH, "flock": FAKE_FLOCK, "timeout": FAKE_TIMEOUT}
BASIC_TOOLS = ("bash", "dirname", "mkdir", "mv", "date")


def run_invocation_uri(run_id: int, repository: str = SOURCE_REPOSITORY) -> str:
    return f"https://github.com/{repository}/actions/runs/{run_id}/attempts/1"


def timed(seconds: int, call: str) -> list[str]:
    """The fake timeout's line, then the call it ran."""
    return [f"timeout {seconds} {call}", call]


def token_expiration_header(days_from_now: int) -> str:
    """The header's value as GitHub sends it for a fine-grained token."""
    expires_at = datetime.now(UTC) + timedelta(days=days_from_now)
    return expires_at.strftime("%Y-%m-%d %H:%M:%S +0000")


@dataclass(frozen=True)
class UpdateRun:
    exit_code: int
    output: str
    calls: list[str]
    state_directory: Path

    @property
    def deployed_run_id_file(self) -> Path:
        return self.state_directory / "last-deployed-run-id"

    def deployed_run_id(self) -> str | None:
        if not self.deployed_run_id_file.exists():
            return None
        return self.deployed_run_id_file.read_text().strip()

    def restarted_nothing(self) -> bool:
        backend_changes = ("docker compose", "docker image rm", "docker image prune")
        return not any(call.startswith(backend_changes) for call in self.calls)

    def pulled_nothing(self) -> bool:
        return not any(call.startswith(("docker pull", "docker tag")) for call in self.calls)


def run_update_script(
    tmp_path: Path,
    arguments: tuple[str, ...] = (),
    installed_fakes: tuple[str, ...] = tuple(FAKES),
    real_tools: tuple[str, ...] = (),
    deployed_run_id: str | None = None,
    **fake_settings: str,
) -> UpdateRun:
    fake_bin = tmp_path / "fake-bin"
    system_tools = tmp_path / "system-tools"
    home = tmp_path / "home"
    state_directory = home / ".local" / "state" / "secure-call-backend"
    for directory in (fake_bin, system_tools, home):
        directory.mkdir(parents=True, exist_ok=True)
    for fake_name in installed_fakes:
        fake_path = fake_bin / fake_name
        fake_path.write_text(FAKES[fake_name])
        fake_path.chmod(0o755)
    for tool_name in (*BASIC_TOOLS, *real_tools):
        tool_path = shutil.which(tool_name)
        assert tool_path is not None, f"{tool_name} is needed to run update.sh"
        (system_tools / tool_name).symlink_to(tool_path)
    if deployed_run_id is not None:
        state_directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        (state_directory / "last-deployed-run-id").write_text(deployed_run_id + "\n")

    call_log = tmp_path / "calls.log"
    environment = {
        "PATH": f"{fake_bin}{os.pathsep}{system_tools}",
        "HOME": str(home),
        "FAKE_CALL_LOG": str(call_log),
        "FAKE_GH_VERSION_OUTPUT": CURRENT_GH_VERSION,
        "FAKE_VERIFY_RESULT": "verified",
        "FAKE_PUBLISHED_DIGEST": PUBLISHED_DIGEST,
        "FAKE_RUN_INVOCATION_URIS": run_invocation_uri(BUILD_RUN_ID),
        "FAKE_IMAGE_ID": VERIFIED_IMAGE_ID,
        **fake_settings,
    }
    completed = subprocess.run(  # noqa: S603 - our own script, fixed arguments, no user input
        [str(UPDATE_SCRIPT), *arguments],
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    calls = call_log.read_text().splitlines() if call_log.exists() else []
    return UpdateRun(
        completed.returncode, completed.stdout + completed.stderr, calls, state_directory
    )


def assert_refused(run: UpdateRun) -> None:
    assert run.exit_code != 0
    assert REFUSED in run.output
    assert run.restarted_nothing(), run.calls


def test_verified_image_is_run_by_its_digest(tmp_path: Path) -> None:
    run = run_update_script(tmp_path)

    assert run.exit_code == 0, run.output
    assert run.calls == [
        "flock -n 9",
        "gh --version",
        *timed(30, RATE_LIMIT_CALL),
        *timed(120, LOOKUP_CALL),
        *timed(180, EXPECTED_VERIFY_CALL),
        *timed(900, f"docker pull --quiet {IMAGE_BY_DIGEST}"),
        f"docker image inspect --format {{{{.Id}}}} {IMAGE_BY_DIGEST}",
        f"docker tag {IMAGE_BY_DIGEST} {IMAGE_REPOSITORY}:main",
        "docker compose up --detach --no-deps --pull never backend",
        "docker compose ps --all --quiet backend",
        "docker inspect --format {{.Image}} backend-container-id",
        f"docker image rm {IMAGE_BY_DIGEST}",
        "docker image prune --force",
    ]
    assert f"The backend runs {IMAGE_BY_DIGEST} (verified, workflow run {BUILD_RUN_ID})." in (
        run.output
    )


def test_first_deploy_records_the_build_run_privately(tmp_path: Path) -> None:
    run = run_update_script(tmp_path)

    assert run.exit_code == 0, run.output
    assert run.deployed_run_id() == str(BUILD_RUN_ID)
    assert stat.S_IMODE(run.deployed_run_id_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(run.state_directory.stat().st_mode) == 0o700
    assert not (run.state_directory / "last-deployed-run-id.new").exists()


@pytest.mark.parametrize("deployed_run_id", [str(BUILD_RUN_ID - 1), str(BUILD_RUN_ID)])
def test_same_or_newer_build_is_deployed(tmp_path: Path, deployed_run_id: str) -> None:
    run = run_update_script(tmp_path, deployed_run_id=deployed_run_id)

    assert run.exit_code == 0, run.output
    assert "docker compose up --detach --no-deps --pull never backend" in run.calls
    assert run.deployed_run_id() == str(BUILD_RUN_ID)


@pytest.mark.parametrize("arguments", [(), ("--check",)])
def test_older_build_is_refused(tmp_path: Path, arguments: tuple[str, ...]) -> None:
    newer_run_id = str(BUILD_RUN_ID + 1)
    run = run_update_script(tmp_path, arguments, deployed_run_id=newer_run_id)

    assert_refused(run)
    assert run.pulled_nothing()
    assert "Moving :main back to an older image is refused." in run.output
    assert run.deployed_run_id() == newer_run_id


@pytest.mark.parametrize("deployed_run_id", ["", "not-a-run", "123 456", "-5"])
def test_unreadable_deployed_run_id_is_refused(tmp_path: Path, deployed_run_id: str) -> None:
    run = run_update_script(tmp_path, deployed_run_id=deployed_run_id)

    assert_refused(run)
    assert run.pulled_nothing()
    assert "cannot read the last deployed build" in run.output


def test_newest_run_among_several_attestations_counts(tmp_path: Path) -> None:
    run_invocation_uris = "\n".join(
        (run_invocation_uri(BUILD_RUN_ID - 10), run_invocation_uri(BUILD_RUN_ID))
    )
    run = run_update_script(
        tmp_path,
        deployed_run_id=str(BUILD_RUN_ID - 5),
        FAKE_RUN_INVOCATION_URIS=run_invocation_uris,
    )

    assert run.exit_code == 0, run.output
    assert run.deployed_run_id() == str(BUILD_RUN_ID)


@pytest.mark.parametrize(
    "run_invocation_uris",
    [
        "",  # no attestation
        "https://github.com/The-Secure-Video-Call/secure-call-backend/actions/runs/abc/attempts/1",
        "https://example.com/The-Secure-Video-Call/secure-call-backend/actions/runs/5/attempts/1",
        f"{run_invocation_uri(BUILD_RUN_ID)} extra",
        f"{run_invocation_uri(BUILD_RUN_ID)}\nnot a run",
    ],
)
def test_unexpected_build_run_is_refused(tmp_path: Path, run_invocation_uris: str) -> None:
    run = run_update_script(tmp_path, FAKE_RUN_INVOCATION_URIS=run_invocation_uris)

    assert_refused(run)
    assert run.pulled_nothing()
    assert "unexpected workflow run in the attestation" in run.output
    assert run.deployed_run_id() is None


def test_failed_verification_restarts_nothing(tmp_path: Path) -> None:
    run = run_update_script(tmp_path, FAKE_VERIFY_RESULT="not-verified")

    assert_refused(run)
    assert run.pulled_nothing()
    assert EXPECTED_VERIFY_CALL in run.calls
    assert "gh attestation verify could not verify" in run.output
    assert run.deployed_run_id() is None


@pytest.mark.parametrize("failing_command", ["pull", "image inspect", "tag"])
def test_failed_pull_inspect_or_tag_restarts_nothing(tmp_path: Path, failing_command: str) -> None:
    run = run_update_script(tmp_path, FAKE_FAILING_DOCKER_COMMAND=failing_command)

    assert_refused(run)
    assert any(call.startswith(f"docker {failing_command}") for call in run.calls)
    assert run.deployed_run_id() is None


def test_backend_running_another_image_is_stopped(tmp_path: Path) -> None:
    run = run_update_script(tmp_path, FAKE_RUNNING_IMAGE_ID="sha256:" + "ef56" * 16)

    assert run.exit_code != 0
    assert f"not the verified {VERIFIED_IMAGE_ID}. Stopping it." in run.output
    assert run.calls[-1] == "docker compose stop backend"
    assert run.deployed_run_id() is None


def test_check_mode_verifies_and_changes_nothing(tmp_path: Path) -> None:
    run = run_update_script(tmp_path, ("--check",))

    assert run.exit_code == 0, run.output
    assert run.calls == [
        "flock -n 9",
        "gh --version",
        *timed(30, RATE_LIMIT_CALL),
        *timed(120, LOOKUP_CALL),
        *timed(180, EXPECTED_VERIFY_CALL),
    ]
    assert "--check: nothing was pulled or restarted." in run.output
    assert run.deployed_run_id() is None


def test_check_mode_reports_a_failed_verification(tmp_path: Path) -> None:
    run = run_update_script(tmp_path, ("--check",), FAKE_VERIFY_RESULT="not-verified")

    assert_refused(run)
    assert run.pulled_nothing()


def test_concurrent_run_is_refused(tmp_path: Path) -> None:
    run = run_update_script(tmp_path, FAKE_LOCK_HELD="1")

    assert_refused(run)
    assert "another update.sh is running" in run.output
    assert run.calls == ["flock -n 9"]


@pytest.mark.skipif(shutil.which("flock") is None, reason="flock (util-linux) is not installed")
def test_real_flock_refuses_a_second_run(tmp_path: Path) -> None:
    state_directory = tmp_path / "home" / ".local" / "state" / "secure-call-backend"
    state_directory.mkdir(parents=True)
    with (state_directory / "update.lock").open("w") as held_lock:
        fcntl.flock(held_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run = run_update_script(
            tmp_path, installed_fakes=("docker", "gh", "timeout"), real_tools=("flock",)
        )
    assert_refused(run)
    assert "another update.sh is running" in run.output
    assert run.calls == []

    run_without_lock = run_update_script(
        tmp_path / "free", installed_fakes=("docker", "gh", "timeout"), real_tools=("flock",)
    )
    assert run_without_lock.exit_code == 0, run_without_lock.output


@pytest.mark.parametrize("missing_command", list(FAKES))
def test_missing_tool_is_refused(tmp_path: Path, missing_command: str) -> None:
    installed = tuple(name for name in FAKES if name != missing_command)
    run = run_update_script(tmp_path, installed_fakes=installed)

    assert_refused(run)
    assert f"'{missing_command}' is not installed" in run.output
    assert run.calls == []


@pytest.mark.parametrize(
    "gh_version_output",
    [
        "gh version 2.101.9 (2026-09-20)",  # --signer-workflow only matched as a prefix
        "gh version 2.96.0 (2026-07-01)",  # --signer-workflow not even escaped
        "gh version 1.999.0 (2020-01-01)",
        "gh version DEV",
        "",
    ],
)
def test_gh_too_old_or_unreadable_is_refused(tmp_path: Path, gh_version_output: str) -> None:
    run = run_update_script(tmp_path, FAKE_GH_VERSION_OUTPUT=gh_version_output)

    assert_refused(run)
    assert run.calls == ["flock -n 9", "gh --version"]


@pytest.mark.parametrize(
    "gh_version_output", ["gh version 2.102.0 (2026-09-30)", "gh version 3.0.0 (2027-01-01)"]
)
def test_gh_new_enough_is_accepted(tmp_path: Path, gh_version_output: str) -> None:
    run = run_update_script(tmp_path, ("--check",), FAKE_GH_VERSION_OUTPUT=gh_version_output)

    assert run.exit_code == 0, run.output


@pytest.mark.parametrize("days_from_now", [13, 1, 0, -2])
def test_token_expiring_soon_is_warned_about(tmp_path: Path, days_from_now: int) -> None:
    run = run_update_script(tmp_path, FAKE_TOKEN_EXPIRATION=token_expiration_header(days_from_now))

    assert run.exit_code == 0, run.output
    assert "warning: the GitHub token gh uses expires on" in run.output
    assert f"({days_from_now} days left)" in run.output


@pytest.mark.parametrize(
    ("token_expiration", "api_fails"),
    [
        (token_expiration_header(15), ""),
        (token_expiration_header(200), ""),
        ("", ""),  # a token without an expiry date
        ("soon", ""),
        ("", "1"),  # gh api fails
    ],
)
def test_token_expiry_check_never_blocks_or_warns_needlessly(
    tmp_path: Path, token_expiration: str, api_fails: str
) -> None:
    run = run_update_script(
        tmp_path, FAKE_TOKEN_EXPIRATION=token_expiration, FAKE_GH_API_FAILS=api_fails
    )

    assert run.exit_code == 0, run.output
    assert "warning" not in run.output
    assert "docker compose up --detach --no-deps --pull never backend" in run.calls


@pytest.mark.parametrize(
    "published_digest",
    [
        "sha256:" + "ab12" * 15,  # too short
        "sha256:" + "AB12" * 16,  # not how a digest is written
        "sha512:" + "ab12" * 32,
        "<no value>",
        "",
        f"{PUBLISHED_DIGEST}\nsha256:{'ef56' * 16}",  # two digests
        f"{PUBLISHED_DIGEST} --repo attacker/repo",
    ],
)
def test_unreadable_digest_is_refused(tmp_path: Path, published_digest: str) -> None:
    run = run_update_script(tmp_path, FAKE_PUBLISHED_DIGEST=published_digest)

    assert_refused(run)
    assert not any(call.startswith("gh attestation") for call in run.calls)


def test_failed_digest_lookup_is_refused(tmp_path: Path) -> None:
    run = run_update_script(tmp_path, FAKE_LOOKUP_FAILS="1")

    assert_refused(run)
    assert not any(call.startswith("gh attestation") for call in run.calls)


@pytest.mark.parametrize("arguments", [("--force",), ("--check", "--check"), ("check",)])
def test_unknown_arguments_are_refused(tmp_path: Path, arguments: tuple[str, ...]) -> None:
    run = run_update_script(tmp_path, arguments)

    assert_refused(run)
    assert run.calls == []


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck is not installed")
def test_update_script_passes_shellcheck() -> None:
    shellcheck_path = shutil.which("shellcheck")
    assert shellcheck_path is not None
    completed = subprocess.run(  # noqa: S603 - fixed arguments, no user input
        [shellcheck_path, str(UPDATE_SCRIPT)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
