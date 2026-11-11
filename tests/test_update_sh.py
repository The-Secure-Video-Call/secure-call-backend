"""deploy/raspberry-pi/update.sh runs only an image whose attestation verifies, and by digest.

The script runs for real, with fake `docker` and `gh` commands first on PATH that record every
call and answer only what update.sh asks. PATH holds nothing else but bash and dirname, so the
real docker and gh (both installed on GitHub's runners) are never reached.
"""

import os
import shutil
import subprocess
from dataclasses import dataclass
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
EXPECTED_VERIFY_CALL = (
    f"gh attestation verify oci://{IMAGE_BY_DIGEST}"
    f" --repo {SOURCE_REPOSITORY}"
    f" --signer-workflow {SOURCE_REPOSITORY}/.github/workflows/publish-image.yml"
    " --source-ref refs/heads/main"
    " --predicate-type https://slsa.dev/provenance/v1"
    " --deny-self-hosted-runners"
)
LOOKUP_CALL = (
    f"docker buildx imagetools inspect {IMAGE_REPOSITORY}:main --format {{{{.Manifest.Digest}}}}"
)

FAKE_DOCKER = """#!/usr/bin/env bash
printf 'docker %s\\n' "$*" >> "$FAKE_CALL_LOG"
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
if [[ "$1" == "--version" ]]; then
  printf '%s\\n' "$FAKE_GH_VERSION_OUTPUT"
  exit 0
fi
if [[ "$1 ${2:-}" == "attestation verify" && "$FAKE_VERIFY_RESULT" == "verified" ]]; then
  printf 'Verification succeeded!\\n'
  exit 0
fi
printf 'Error: no attestation matched the policy\\n' >&2
exit 1
"""


@dataclass(frozen=True)
class UpdateRun:
    exit_code: int
    output: str
    calls: list[str]

    def docker_calls(self) -> list[str]:
        return [call for call in self.calls if call.startswith("docker ")]


def run_update_script(
    tmp_path: Path,
    arguments: tuple[str, ...] = (),
    installed_fakes: tuple[str, ...] = ("docker", "gh"),
    **fake_settings: str,
) -> UpdateRun:
    fake_bin = tmp_path / "fake-bin"
    system_tools = tmp_path / "system-tools"
    fake_bin.mkdir()
    system_tools.mkdir()
    for fake_name, fake_script in (("docker", FAKE_DOCKER), ("gh", FAKE_GH)):
        if fake_name in installed_fakes:
            fake_path = fake_bin / fake_name
            fake_path.write_text(fake_script)
            fake_path.chmod(0o755)
    for tool_name in ("bash", "dirname"):
        tool_path = shutil.which(tool_name)
        assert tool_path is not None, f"{tool_name} is needed to run update.sh"
        (system_tools / tool_name).symlink_to(tool_path)

    call_log = tmp_path / "calls.log"
    environment = {
        "PATH": f"{fake_bin}{os.pathsep}{system_tools}",
        "HOME": str(tmp_path),
        "FAKE_CALL_LOG": str(call_log),
        "FAKE_GH_VERSION_OUTPUT": CURRENT_GH_VERSION,
        "FAKE_VERIFY_RESULT": "verified",
        "FAKE_PUBLISHED_DIGEST": PUBLISHED_DIGEST,
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
    return UpdateRun(completed.returncode, completed.stdout + completed.stderr, calls)


def assert_refused_before_touching_the_backend(run: UpdateRun) -> None:
    assert run.exit_code != 0
    assert "refused. Nothing was pulled or restarted." in run.output
    assert run.docker_calls() in ([], [LOOKUP_CALL])


def test_verified_image_is_run_by_its_digest(tmp_path: Path) -> None:
    run = run_update_script(tmp_path)

    assert run.exit_code == 0, run.output
    assert run.calls == [
        "gh --version",
        LOOKUP_CALL,
        EXPECTED_VERIFY_CALL,
        f"docker pull --quiet {IMAGE_BY_DIGEST}",
        f"docker image inspect --format {{{{.Id}}}} {IMAGE_BY_DIGEST}",
        f"docker tag {IMAGE_BY_DIGEST} {IMAGE_REPOSITORY}:main",
        "docker compose up --detach --no-deps --pull never backend",
        "docker compose ps --all --quiet backend",
        "docker inspect --format {{.Image}} backend-container-id",
        f"docker image rm {IMAGE_BY_DIGEST}",
        "docker image prune --force",
    ]
    assert f"The backend runs {IMAGE_BY_DIGEST} (verified)." in run.output


def test_failed_verification_restarts_nothing(tmp_path: Path) -> None:
    run = run_update_script(tmp_path, FAKE_VERIFY_RESULT="not-verified")

    assert_refused_before_touching_the_backend(run)
    assert EXPECTED_VERIFY_CALL in run.calls
    assert "gh attestation verify could not verify" in run.output


def test_check_mode_verifies_and_changes_nothing(tmp_path: Path) -> None:
    run = run_update_script(tmp_path, ("--check",))

    assert run.exit_code == 0, run.output
    assert run.calls == ["gh --version", LOOKUP_CALL, EXPECTED_VERIFY_CALL]
    assert "--check: nothing was pulled or restarted." in run.output


def test_check_mode_reports_a_failed_verification(tmp_path: Path) -> None:
    run = run_update_script(tmp_path, ("--check",), FAKE_VERIFY_RESULT="not-verified")

    assert_refused_before_touching_the_backend(run)


@pytest.mark.parametrize("missing_command", ["gh", "docker"])
def test_missing_tool_is_refused(tmp_path: Path, missing_command: str) -> None:
    installed = tuple(name for name in ("docker", "gh") if name != missing_command)
    run = run_update_script(tmp_path, installed_fakes=installed)

    assert_refused_before_touching_the_backend(run)
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

    assert_refused_before_touching_the_backend(run)
    assert run.calls == ["gh --version"]


@pytest.mark.parametrize(
    "gh_version_output", ["gh version 2.102.0 (2026-09-30)", "gh version 3.0.0 (2027-01-01)"]
)
def test_gh_new_enough_is_accepted(tmp_path: Path, gh_version_output: str) -> None:
    run = run_update_script(tmp_path, ("--check",), FAKE_GH_VERSION_OUTPUT=gh_version_output)

    assert run.exit_code == 0, run.output


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

    assert_refused_before_touching_the_backend(run)
    assert not any(call.startswith("gh attestation") for call in run.calls)


def test_failed_digest_lookup_is_refused(tmp_path: Path) -> None:
    run = run_update_script(tmp_path, FAKE_LOOKUP_FAILS="1")

    assert_refused_before_touching_the_backend(run)
    assert not any(call.startswith("gh attestation") for call in run.calls)


@pytest.mark.parametrize("arguments", [("--force",), ("--check", "--check"), ("check",)])
def test_unknown_arguments_are_refused(tmp_path: Path, arguments: tuple[str, ...]) -> None:
    run = run_update_script(tmp_path, arguments)

    assert_refused_before_touching_the_backend(run)
    assert run.calls == []


def test_backend_running_another_image_fails(tmp_path: Path) -> None:
    run = run_update_script(tmp_path, FAKE_RUNNING_IMAGE_ID="sha256:" + "ef56" * 16)

    assert run.exit_code != 0
    assert f"not the verified {VERIFIED_IMAGE_ID}" in run.output
    assert "docker image prune --force" not in run.calls


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
