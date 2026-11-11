"""The Pi's TURN scripts: make-turn-secret.sh (#64) and coturn/install-turn-certificate.sh (#58,
#90). They run for real on copies in a temporary folder, with stand-ins for sudo (records the
call, then installs without changing the owner) and docker (records the call)."""

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy/raspberry-pi"
TURN_HOST_NAME = "turn.securevideocall.com"

FAKE_SUDO = """#!/usr/bin/env bash
echo "sudo $*" >>"$FAKE_LOG"
args=(); skip=0
for a in "$@"; do
  if [ "$skip" = 1 ]; then skip=0; continue; fi
  case "$a" in -o|-g) skip=1;; *) args+=("$a");; esac
done
exec "${args[@]}"
"""
FAKE_DOCKER = """#!/usr/bin/env bash
echo "docker $*" >>"$FAKE_LOG"
case "$*" in
  *" ps "*)
    if [ -n "${FAKE_DOCKER_PS_FAILS:-}" ]; then echo "permission denied" >&2; exit 1; fi
    if [ -n "${FAKE_COTURN_RUNNING:-}" ]; then echo coturn; fi ;;
esac
exit 0
"""


def openssl_3() -> str:
    for candidate in (shutil.which("openssl"), "/opt/homebrew/bin/openssl", "/usr/bin/openssl"):
        if candidate and Path(candidate).exists():
            version = subprocess.run(  # noqa: S603 - a found openssl, fixed argument
                [candidate, "version"], capture_output=True, text=True, check=False
            ).stdout
            if version.startswith("OpenSSL 3"):
                return candidate
    pytest.skip("OpenSSL 3 is needed")


def tool_path(tmp_path: Path) -> tuple[dict[str, str], Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    for name, body in (("sudo", FAKE_SUDO), ("docker", FAKE_DOCKER)):
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    openssl_dir = Path(openssl_3()).parent
    log = tmp_path / "calls.log"
    log.touch()
    env = {
        **{
            k: v
            for k, v in os.environ.items()
            if k not in ("FAKE_COTURN_RUNNING", "FAKE_DOCKER_PS_FAILS")
        },
        "PATH": f"{bin_dir}:{openssl_dir}:/usr/bin:/bin",
        "FAKE_LOG": str(log),
    }
    return env, log


# --- make-turn-secret.sh ------------------------------------------------------------------


def copy_secret_script(tmp_path: Path) -> Path:
    deploy_copy = tmp_path / "deploy"
    deploy_copy.mkdir()
    shutil.copy2(DEPLOY / "make-turn-secret.sh", deploy_copy / "make-turn-secret.sh")
    return deploy_copy


def run_secret_script(
    tmp_path: Path, *arguments: str
) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    env, log = tool_path(tmp_path)
    deploy_copy = tmp_path / "deploy"
    result = subprocess.run(  # noqa: S603 - fixed script, no user input
        ["/bin/bash", str(deploy_copy / "make-turn-secret.sh"), *arguments],
        env=env, capture_output=True, text=True, check=False,
    )  # fmt: skip
    return result, deploy_copy / "secrets", log


def test_new_secret_goes_to_both_files_for_their_own_users_and_is_never_printed(
    tmp_path: Path,
) -> None:
    deploy_copy = copy_secret_script(tmp_path)
    (deploy_copy / ".env").write_text("DJANGO_SECRET_KEY=x\n")
    (deploy_copy / ".env").chmod(0o644)
    result, secrets, log = run_secret_script(tmp_path)

    assert result.returncode == 0, result.stderr
    coturn_line = (secrets / "turn-static-auth-secret.conf").read_text()
    backend_line = (secrets / "turn-shared-secret").read_text()
    secret = backend_line.removesuffix("\n")
    assert re.fullmatch(r"[A-Za-z0-9+/=]{44}", secret)
    assert coturn_line == f"static-auth-secret={secret}\n"
    for secret_file in ("turn-static-auth-secret.conf", "turn-shared-secret"):
        assert stat.S_IMODE((secrets / secret_file).stat().st_mode) == 0o400
    calls = log.read_text()
    assert "install -m 400 -o 65534 -g 65534" in calls
    assert "install -m 400 -o 10001 -g 10001" in calls
    assert secret not in result.stdout + result.stderr + calls
    assert stat.S_IMODE((deploy_copy / ".env").stat().st_mode) == 0o600


def test_from_env_moves_the_existing_secret(tmp_path: Path) -> None:
    existing = "QWxyZWFkeS1zZWN1cmUtc2VjcmV0LWZyb20tZW52LXRlc3Q="  # a test value
    deploy_copy = copy_secret_script(tmp_path)
    (deploy_copy / ".env").write_text(f'TURN_SHARED_SECRET="{existing}"\nOTHER=1\n')
    result, secrets, _ = run_secret_script(tmp_path, "--from-env")

    assert result.returncode == 0, result.stderr
    assert (secrets / "turn-shared-secret").read_text() == f"{existing}\n"
    assert (
        secrets / "turn-static-auth-secret.conf"
    ).read_text() == f"static-auth-secret={existing}\n"
    assert "delete the TURN_SHARED_SECRET line" in result.stdout
    assert existing not in result.stdout + result.stderr


@pytest.mark.parametrize(
    "env_line",
    [
        "TURN_SHARED_SECRET=short",
        "TURN_SHARED_SECRET=has spaces in it but is long enough to pass the length",
        "TURN_SHARED_SECRET=hash#sign-would-start-a-comment-in-coturns-config",
        "TURN_SHARED_SECRET==leading-equals-sign-that-coturns-parser-would-drop-here",
        "TURN_SHARED_SECRET=" + "a" * 257,
        "OTHER=no turn secret here at all",
    ],
)
def test_negative_a_secret_coturn_could_misread_is_refused(tmp_path: Path, env_line: str) -> None:
    deploy_copy = copy_secret_script(tmp_path)
    (deploy_copy / ".env").write_text(env_line + "\n")
    result, secrets, log = run_secret_script(tmp_path, "--from-env")

    assert result.returncode == 1
    assert "nothing was written" in result.stderr
    assert not secrets.exists()
    assert "install" not in log.read_text()


def test_negative_bad_arguments_and_a_missing_env_file(tmp_path: Path) -> None:
    copy_secret_script(tmp_path)
    bad_argument, secrets, _ = run_secret_script(tmp_path, "--rotate")
    missing_env, _, _ = run_secret_script(tmp_path, "--from-env")

    assert bad_argument.returncode == 2
    assert missing_env.returncode == 1
    assert not secrets.exists()


# --- coturn/install-turn-certificate.sh -----------------------------------------------------


def make_certificate(
    directory: Path, name: str, host_name: str, days: int, ca: tuple[Path, Path] | None
) -> tuple[Path, Path]:
    """A P-256 key and a certificate for host_name, signed by `ca` (or self-signed as a CA)."""
    openssl = openssl_3()
    key, certificate = directory / f"{name}.key", directory / f"{name}.crt"
    subprocess.run(  # noqa: S603 - fixed command, no user input
        [openssl, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-out", str(key)],
        check=True, capture_output=True,
    )  # fmt: skip
    if ca is None:
        subprocess.run(  # noqa: S603
            [openssl, "req", "-x509", "-new", "-key", str(key), "-subj", f"/CN={name}",
             "-days", str(days), "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", str(certificate)],
            check=True, capture_output=True,
        )  # fmt: skip
        return key, certificate
    ca_key, ca_certificate = ca
    request, extensions = directory / f"{name}.csr", directory / f"{name}.ext"
    subprocess.run(  # noqa: S603
        [openssl, "req", "-new", "-key", str(key), "-subj", f"/CN={host_name}",
         "-out", str(request)],
        check=True, capture_output=True,
    )  # fmt: skip
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
        f"extendedKeyUsage=serverAuth\nsubjectAltName=DNS:{host_name}\n"
    )
    subprocess.run(  # noqa: S603
        [openssl, "x509", "-req", "-in", str(request), "-CA", str(ca_certificate),
         "-CAkey", str(ca_key), "-set_serial", "7", "-days", str(days),
         "-extfile", str(extensions), "-out", str(certificate)],
        check=True, capture_output=True,
    )  # fmt: skip
    fullchain = directory / f"{name}.fullchain.pem"
    fullchain.write_text(certificate.read_text() + ca_certificate.read_text())
    return key, fullchain


def run_install_script(
    tmp_path: Path,
    fullchain: Path,
    key: Path,
    ca_certificate: Path | None,
    *,
    running: bool = True,
    docker_ps_fails: bool = False,
) -> tuple[subprocess.CompletedProcess[str], Path, str]:
    coturn_copy = tmp_path / "pi/coturn"
    coturn_copy.mkdir(parents=True, exist_ok=True)
    (tmp_path / "pi/compose.yaml").write_text("# stand-in\n")
    shutil.copy2(DEPLOY / "coturn/install-turn-certificate.sh", coturn_copy)
    env, log = tool_path(tmp_path)
    if ca_certificate is not None:
        env["TURN_CERTIFICATE_TEST_CA_FILE"] = str(ca_certificate)
    if running:
        env["FAKE_COTURN_RUNNING"] = "1"
    if docker_ps_fails:
        env["FAKE_DOCKER_PS_FAILS"] = "1"
    log.write_text("")
    result = subprocess.run(  # noqa: S603 - fixed script, no user input
        ["/bin/bash", str(coturn_copy / "install-turn-certificate.sh"), str(fullchain), str(key)],
        env=env, capture_output=True, text=True, check=False,
    )  # fmt: skip
    return result, coturn_copy / "tls", log.read_text()


@pytest.fixture
def test_ca(tmp_path: Path) -> tuple[Path, Path]:
    return make_certificate(tmp_path, "test-ca", "", 30, None)


def test_valid_certificate_is_installed_and_coturn_restarted_once(
    tmp_path: Path, test_ca: tuple[Path, Path]
) -> None:
    key, fullchain = make_certificate(tmp_path, "turn", TURN_HOST_NAME, 30, test_ca)
    result, tls, calls = run_install_script(tmp_path, fullchain, key, test_ca[1])

    assert result.returncode == 0, result.stderr
    assert (tls / "fullchain.pem").read_text() == fullchain.read_text()
    assert (tls / "privkey.pem").read_bytes() == key.read_bytes()
    assert stat.S_IMODE((tls / "privkey.pem").stat().st_mode) == 0o400
    assert stat.S_IMODE((tls / "fullchain.pem").stat().st_mode) == 0o444
    assert "sudo install -m 400 -o 65534 -g 65534" in calls
    assert re.search(r"docker compose -f \S+/compose\.yaml kill -s SIGUSR2 coturn", calls)
    assert "restart" not in calls  # a reload keeps the relays of calls in progress

    again, _, calls_again = run_install_script(tmp_path, fullchain, key, test_ca[1])
    assert again.returncode == 0
    assert "already installed" in again.stdout
    assert "kill" not in calls_again


def test_coturn_not_running_is_not_started(tmp_path: Path, test_ca: tuple[Path, Path]) -> None:
    key, fullchain = make_certificate(tmp_path, "turn", TURN_HOST_NAME, 30, test_ca)
    result, tls, calls = run_install_script(tmp_path, fullchain, key, test_ca[1], running=False)

    assert result.returncode == 0, result.stderr
    assert (tls / "fullchain.pem").exists()
    assert "kill" not in calls


def test_negative_wrong_certificates_install_nothing(
    tmp_path: Path, test_ca: tuple[Path, Path]
) -> None:
    good_key, good_fullchain = make_certificate(tmp_path, "good", TURN_HOST_NAME, 30, test_ca)
    other_key, _ = make_certificate(tmp_path, "other", TURN_HOST_NAME, 30, test_ca)
    _, wrong_name = make_certificate(tmp_path, "wrong-name", "turn.example.invalid", 30, test_ca)
    wrong_name_key = tmp_path / "wrong-name.key"
    expiring_key, expiring = make_certificate(tmp_path, "expiring", TURN_HOST_NAME, 3, test_ca)
    other_ca = make_certificate(tmp_path, "other-ca", "", 30, None)
    cases = [
        (wrong_name, wrong_name_key, test_ca[1], "does not name"),
        (expiring, expiring_key, test_ca[1], "expires within 7 days"),
        (good_fullchain, other_key, test_ca[1], "does not belong"),
        (good_fullchain, good_key, other_ca[1], "does not chain"),
        (good_fullchain, good_key, None, "does not chain"),  # the system CAs don't know our CA
        (good_key, good_key, test_ca[1], "holds something other than certificates"),
    ]
    for case_number, (fullchain, key, ca_certificate, message) in enumerate(cases):
        case_dir = tmp_path / f"case-{case_number}"
        result, tls, calls = run_install_script(case_dir, fullchain, key, ca_certificate)

        assert result.returncode == 1, message
        assert message in result.stderr
        assert "Nothing was installed" in result.stderr
        assert not tls.exists(), message
        assert "docker" not in calls, message
        assert "install" not in calls, message


def test_negative_a_chain_file_with_a_key_or_an_encrypted_key_installs_nothing(
    tmp_path: Path, test_ca: tuple[Path, Path]
) -> None:
    key, fullchain = make_certificate(tmp_path, "turn", TURN_HOST_NAME, 30, test_ca)
    chain_with_key = tmp_path / "chain-with-key.pem"
    chain_with_key.write_text(fullchain.read_text() + key.read_text())
    encrypted_key = tmp_path / "encrypted.key"
    subprocess.run(  # noqa: S603 - fixed command, no user input
        [openssl_3(), "pkey", "-in", str(key), "-aes256", "-passout", "pass:not-empty",
         "-out", str(encrypted_key)],
        check=True, capture_output=True,
    )  # fmt: skip
    cases = [
        (chain_with_key, key, "holds something other than certificates"),
        (fullchain, encrypted_key, "is not an unencrypted private key"),
    ]
    for case_number, (chain, private_key, message) in enumerate(cases):
        result, tls, calls = run_install_script(
            tmp_path / f"case-{case_number}", chain, private_key, test_ca[1]
        )

        assert result.returncode == 1, message
        assert message in result.stderr
        assert not tls.exists()
        assert "install" not in calls


def test_negative_docker_unreachable_installs_nothing(
    tmp_path: Path, test_ca: tuple[Path, Path]
) -> None:
    key, fullchain = make_certificate(tmp_path, "turn", TURN_HOST_NAME, 30, test_ca)
    result, tls, calls = run_install_script(
        tmp_path, fullchain, key, test_ca[1], docker_ps_fails=True
    )

    assert result.returncode == 1
    assert "cannot ask Docker whether coturn runs" in result.stderr
    assert not tls.exists()
    assert "kill" not in calls


def test_the_test_ca_override_is_announced(tmp_path: Path, test_ca: tuple[Path, Path]) -> None:
    key, fullchain = make_certificate(tmp_path, "turn", TURN_HOST_NAME, 30, test_ca)
    result, _, _ = run_install_script(tmp_path, fullchain, key, test_ca[1])

    assert "WARNING: also trusting" in result.stderr


def test_coturn_dir_option_installs_into_the_resolved_stack_folder(
    tmp_path: Path, test_ca: tuple[Path, Path]
) -> None:
    """How secure-call-turn-certificate.service runs it: a copy elsewhere, the folder through a
    link (#90)."""
    key, fullchain = make_certificate(tmp_path, "turn", TURN_HOST_NAME, 30, test_ca)
    stack = tmp_path / "checkout/deploy/raspberry-pi"
    (stack / "coturn").mkdir(parents=True)
    (stack / "compose.yaml").write_text("# stand-in\n")
    link = tmp_path / "etc/coturn"
    link.parent.mkdir()
    link.symlink_to(stack / "coturn")
    script_copy = tmp_path / "lib/install-turn-certificate.sh"
    script_copy.parent.mkdir()
    shutil.copy2(DEPLOY / "coturn/install-turn-certificate.sh", script_copy)
    env, log = tool_path(tmp_path)
    env["TURN_CERTIFICATE_TEST_CA_FILE"] = str(test_ca[1])
    env["FAKE_COTURN_RUNNING"] = "1"
    result = subprocess.run(  # noqa: S603 - fixed script, no user input
        ["/bin/bash", str(script_copy), "--coturn-dir", str(link), str(fullchain), str(key)],
        env=env, capture_output=True, text=True, check=False,
    )  # fmt: skip

    assert result.returncode == 0, result.stderr
    tls = stack.resolve() / "coturn/tls"
    assert (tls / "privkey.pem").read_bytes() == key.read_bytes()
    assert (tls / "fullchain.pem").read_text() == fullchain.read_text()
    assert not (tmp_path / "lib/tls").exists()
    assert f"docker compose -f {stack.resolve()}/coturn/../compose.yaml kill" in log.read_text()


def test_negative_a_folder_that_is_not_the_stacks_or_a_linked_tls_installs_nothing(
    tmp_path: Path, test_ca: tuple[Path, Path]
) -> None:
    key, fullchain = make_certificate(tmp_path, "turn", TURN_HOST_NAME, 30, test_ca)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    no_stack, _, _ = run_install_script(tmp_path / "no-stack", fullchain, key, test_ca[1])
    script = tmp_path / "no-stack/pi/coturn/install-turn-certificate.sh"
    env, _ = tool_path(tmp_path / "no-stack")
    for arguments, message in (
        (["--coturn-dir", str(elsewhere)], "is not the coturn folder next to compose.yaml"),
        (["--coturn-dir", str(tmp_path / "missing")], "is not the coturn folder"),
        (["--coturn-dir"], "Usage:"),
    ):
        result = subprocess.run(  # noqa: S603 - fixed script, no user input
            ["/bin/bash", str(script), *arguments, str(fullchain), str(key)],
            env=env, capture_output=True, text=True, check=False,
        )  # fmt: skip
        assert result.returncode == 2, message
        assert message in result.stderr
    assert no_stack.returncode == 0  # the same copy works where it belongs
    assert not (elsewhere / "tls").exists()

    linked = tmp_path / "linked"
    (linked / "pi/coturn").mkdir(parents=True)
    (linked / "pi/coturn/tls").symlink_to(elsewhere)
    result, _, calls = run_install_script(linked, fullchain, key, test_ca[1])
    assert result.returncode == 1
    assert "is a symbolic link" in result.stderr
    assert list(elsewhere.iterdir()) == []
    assert "install" not in calls


def test_negative_linked_inputs_and_the_test_ca_as_root_install_nothing(
    tmp_path: Path, test_ca: tuple[Path, Path]
) -> None:
    """Root reads the inputs from a folder an unprivileged user writes (#90)."""
    key, fullchain = make_certificate(tmp_path, "turn", TURN_HOST_NAME, 30, test_ca)
    linked_key = tmp_path / "linked.key"
    linked_key.symlink_to(key)
    linked_chain = tmp_path / "linked.pem"
    linked_chain.symlink_to(fullchain)
    for case, (chain, private_key) in enumerate(((fullchain, linked_key), (linked_chain, key))):
        result, tls, calls = run_install_script(
            tmp_path / f"case-{case}", chain, private_key, test_ca[1]
        )
        assert result.returncode == 1
        assert "is a symbolic link; give the file itself" in result.stderr
        assert not tls.exists()
        assert "install" not in calls

    as_root = tmp_path / "as-root"
    (as_root / "bin").mkdir(parents=True)
    (as_root / "bin/id").write_text(
        '#!/bin/sh\nif [ "$1" = -u ]; then echo 0; exit 0; fi\nexec /usr/bin/id "$@"\n'
    )
    (as_root / "bin/id").chmod(0o755)
    result, tls, calls = run_install_script(as_root, fullchain, key, test_ca[1])
    assert result.returncode == 1
    assert "never honoured as root" in result.stderr
    assert not tls.exists()
    assert "docker" not in calls


def test_a_root_owned_copy_that_fell_behind_the_checkout_is_named(
    tmp_path: Path, test_ca: tuple[Path, Path]
) -> None:
    key, fullchain = make_certificate(tmp_path, "turn", TURN_HOST_NAME, 30, test_ca)
    stack = tmp_path / "checkout/deploy/raspberry-pi"
    (stack / "coturn").mkdir(parents=True)
    (stack / "compose.yaml").write_text("# stand-in\n")
    lib = tmp_path / "lib"
    lib.mkdir()
    for name in ("install-turn-certificate.sh", "fetch-turn-certificate.sh"):
        shutil.copy2(DEPLOY / "coturn" / name, lib / name)
        shutil.copy2(DEPLOY / "coturn" / name, stack / "coturn" / name)
    with (stack / "coturn/fetch-turn-certificate.sh").open("a") as pulled:
        pulled.write("# a fix pulled into the checkout\n")
    env, _ = tool_path(tmp_path)
    env["TURN_CERTIFICATE_TEST_CA_FILE"] = str(test_ca[1])
    result = subprocess.run(  # noqa: S603 - fixed script, no user input
        ["/bin/bash", str(lib / "install-turn-certificate.sh"), "--coturn-dir",
         str(stack / "coturn"), str(fullchain), str(key)],
        env=env, capture_output=True, text=True, check=False,
    )  # fmt: skip

    assert result.returncode == 0, result.stderr
    assert f"WARNING: {lib}/fetch-turn-certificate.sh differs from" in result.stderr
    assert "install-turn-certificate.sh differs" not in result.stderr
