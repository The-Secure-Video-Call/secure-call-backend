"""The automatic refresh of coturn's TLS certificate (#90): coturn/sync-turn-certificate.sh on the
coturn Pi, coturn/print-turn-certificate.sh (the forced SSH command on the proxy machine) and the
systemd units. The scripts run for real on copies in a temporary folder, with stand-ins for ssh,
docker and sudo, and once through a real sshd with the README's authorized_keys line."""

import getpass
import os
import re
import shutil
import socket
import stat
import subprocess
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.test_turn_scripts import (
    FAKE_DOCKER,
    FAKE_SUDO,
    TURN_HOST_NAME,
    make_certificate,
    openssl_3,
)

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy/raspberry-pi"
COTURN = DEPLOY / "coturn"
SYNC_SCRIPT = COTURN / "sync-turn-certificate.sh"
PRINT_SCRIPT = COTURN / "print-turn-certificate.sh"
SERVICE = COTURN / "secure-call-turn-certificate.service"
TIMER = COTURN / "secure-call-turn-certificate.timer"
README = DEPLOY / "README.md"
UNRESTRICTED_KEY_MARKER = "secure-call-turn-certificate-key-is-not-restricted"
PROXY_LOGIN = "turn-certificate@192.0.2.10"
CONTAINER = "nginx-proxy-manager-app-1"
CERTIFICATE_NAME = "npm-30"
LIVE_DIR = f"/etc/letsencrypt/live/{CERTIFICATE_NAME}"
INSTALLED_LIB_DIR = "/usr/local/lib/secure-call"
CONFIG_DIR = "/etc/secure-call/turn-certificate"
INSTALLED_PRINT_SCRIPT = "/usr/local/sbin/secure-call-print-turn-certificate"

# ssh on the coturn Pi: records the call, then answers with a file (or, for a key without a forced
# command, does what the proxy's shell would: runs the command the client asked for).
FAKE_SSH = """#!/usr/bin/env bash
echo "ssh $*" >>"$FAKE_LOG"
if [ -n "${FAKE_SSH_UNRESTRICTED:-}" ]; then exec /bin/sh -c "${!#}"; fi
if [ -n "${FAKE_SSH_STDERR:-}" ]; then echo "$FAKE_SSH_STDERR" >&2; fi
cat "$FAKE_SSH_ANSWER"
exit "${FAKE_SSH_STATUS:-0}"
"""
# docker on the proxy machine: `docker exec CONTAINER cat -- FILE...` reads FILEs below a folder
# that stands for the container's file system.
FAKE_PROXY_DOCKER = """#!/usr/bin/env bash
echo "docker $*" >>"$FAKE_LOG"
if [ -n "${FAKE_DOCKER_EXEC_FAILS:-}" ]; then
  echo "Error response from daemon: No such container: $2" >&2; exit 1
fi
if [ "$1" != exec ] || [ "$3" != cat ] || [ "$4" != -- ]; then
  echo "unexpected: $*" >&2; exit 99
fi
shift 4
for file in "$@"; do cat "$FAKE_CONTAINER_ROOT$file" || exit 1; done
"""
# sudo on the proxy machine: the sudoers line allows exactly one command; this runs it.
FAKE_PROXY_SUDO = """#!/usr/bin/env bash
echo "sudo $*" >>"$FAKE_LOG"
if [ "$1" = -n ]; then shift; fi
exec "$@"
"""


def write_tools(bin_dir: Path, tools: dict[str, str]) -> None:
    bin_dir.mkdir(parents=True, exist_ok=True)
    for name, body in tools.items():
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)


def clean_environment() -> dict[str, str]:
    return {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("FAKE_", "TURN_CERTIFICATE_", "SSH_"))
    }


def key_lines(key: Path) -> list[str]:
    """The base64 lines of a PEM key: none of them may ever be printed or logged."""
    return [line for line in key.read_text().splitlines() if not line.startswith("-----")]


@pytest.fixture
def test_ca(tmp_path: Path) -> tuple[Path, Path]:
    return make_certificate(tmp_path, "test-ca", "", 30, None)


def make_expired_certificate(directory: Path, ca: tuple[Path, Path]) -> tuple[Path, Path]:
    """A certificate for the TURN host that expired in 2025, signed by `ca` (`openssl ca`, as
    `x509 -days` cannot make one in the past and OpenSSL 3.0 has no `-not_after`)."""
    openssl = openssl_3()
    database = directory / "expired-ca"
    database.mkdir()
    (database / "index.txt").write_text("")
    (database / "serial").write_text("1000\n")
    (database / "ca.conf").write_text(
        f"[ca]\ndefault_ca = test_ca\n[test_ca]\ndatabase = {database}/index.txt\n"
        f"new_certs_dir = {database}\nserial = {database}/serial\ndefault_md = sha256\n"
        "policy = any_name\nunique_subject = no\nx509_extensions = server\n"
        "[any_name]\ncommonName = supplied\n"
        "[server]\nbasicConstraints = critical,CA:FALSE\nkeyUsage = critical,digitalSignature\n"
        f"extendedKeyUsage = serverAuth\nsubjectAltName = DNS:{TURN_HOST_NAME}\n"
    )
    key, request = directory / "expired.key", directory / "expired.csr"
    certificate = directory / "expired.crt"
    subprocess.run(  # noqa: S603 - fixed command, no user input
        [openssl, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-out", str(key)],
        check=True, capture_output=True,
    )  # fmt: skip
    subprocess.run(  # noqa: S603
        [openssl, "req", "-new", "-key", str(key), "-subj", f"/CN={TURN_HOST_NAME}",
         "-out", str(request)],
        check=True, capture_output=True,
    )  # fmt: skip
    subprocess.run(  # noqa: S603
        [openssl, "ca", "-batch", "-notext", "-config", str(database / "ca.conf"),
         "-cert", str(ca[1]), "-keyfile", str(ca[0]), "-in", str(request),
         "-startdate", "20250101000000Z", "-enddate", "20250201000000Z", "-out", str(certificate)],
        check=True, capture_output=True,
    )  # fmt: skip
    fullchain = directory / "expired.fullchain.pem"
    fullchain.write_text(certificate.read_text() + ca[1].read_text())
    return key, fullchain


# --- coturn/sync-turn-certificate.sh, with stand-ins -------------------------------------------


@dataclass
class Pi:
    """The coturn Pi: root-owned copies of the scripts, the configuration folder, the checkout."""

    sync_script: Path
    config_dir: Path
    tls_dir: Path
    memory_dir: Path
    bin_dir: Path
    log: Path
    env: dict[str, str]

    def calls(self) -> str:
        return self.log.read_text()


def make_pi(tmp_path: Path, ca_certificate: Path | None, *, fake_ssh: bool = True) -> Pi:
    lib = tmp_path / "usr-local-lib-secure-call"
    lib.mkdir()
    for name in ("sync-turn-certificate.sh", "install-turn-certificate.sh"):
        shutil.copy2(COTURN / name, lib / name)
    stack = tmp_path / "checkout/deploy/raspberry-pi"
    (stack / "coturn").mkdir(parents=True)
    (stack / "compose.yaml").write_text("# stand-in\n")
    config_dir = tmp_path / "etc-secure-call-turn-certificate"
    config_dir.mkdir()
    (config_dir / "proxy").write_text(PROXY_LOGIN + "\n")
    (config_dir / "id_ed25519").write_text("stand-in (the fake ssh never reads it)\n")
    (config_dir / "known_hosts").write_text("stand-in\n")
    (config_dir / "coturn").symlink_to(stack / "coturn")
    memory_dir = tmp_path / "shm"
    memory_dir.mkdir()
    bin_dir = tmp_path / "pi-bin"
    tools = {"sudo": FAKE_SUDO, "docker": FAKE_DOCKER}
    if fake_ssh:
        tools["ssh"] = FAKE_SSH
    write_tools(bin_dir, tools)
    log = tmp_path / "calls.log"
    log.touch()
    env = {
        **clean_environment(),
        "PATH": f"{bin_dir}:{Path(openssl_3()).parent}:/usr/bin:/bin",
        "FAKE_LOG": str(log),
        "FAKE_COTURN_RUNNING": "1",
        "TURN_CERTIFICATE_TEST_MEMORY_DIR": str(memory_dir),
    }
    if ca_certificate is not None:
        env["TURN_CERTIFICATE_TEST_CA_FILE"] = str(ca_certificate)
    return Pi(
        lib / "sync-turn-certificate.sh",
        config_dir,
        stack / "coturn/tls",
        memory_dir,
        bin_dir,
        log,
        env,
    )


def run_sync(
    pi: Pi, answer: bytes = b"", *arguments: str, **fake_settings: str
) -> subprocess.CompletedProcess[str]:
    answer_file = pi.memory_dir.parent / "answer-from-the-proxy"
    answer_file.write_bytes(answer)
    pi.log.write_text("")
    env = {**pi.env, "FAKE_SSH_ANSWER": str(answer_file), **fake_settings}
    if not arguments:
        arguments = ("--config-dir", str(pi.config_dir))
    return subprocess.run(  # noqa: S603 - fixed script, no user input
        ["/bin/bash", str(pi.sync_script), *arguments],
        env=env, capture_output=True, text=True, check=False,
    )  # fmt: skip


def assert_nothing_installed_or_leaked(
    pi: Pi, result: subprocess.CompletedProcess[str], key: Path
) -> None:
    assert result.returncode == 1, result.stdout + result.stderr
    assert "Nothing was installed" in result.stderr
    assert not pi.tls_dir.exists()
    assert "kill" not in pi.calls()
    assert "install -m" not in pi.calls()
    assert list(pi.memory_dir.iterdir()) == []
    printed = result.stdout + result.stderr + pi.calls()
    for line in key_lines(key):
        assert line not in printed


def test_sync_installs_a_new_certificate_once_and_a_renewed_one_again(
    tmp_path: Path, test_ca: tuple[Path, Path]
) -> None:
    pi = make_pi(tmp_path, test_ca[1])
    key, fullchain = make_certificate(tmp_path, "turn", TURN_HOST_NAME, 60, test_ca)
    renewed_key, renewed_fullchain = make_certificate(
        tmp_path, "renewed", TURN_HOST_NAME, 90, test_ca
    )

    first = run_sync(pi, fullchain.read_bytes() + key.read_bytes())
    first_calls = pi.calls()
    assert first.returncode == 0, first.stderr
    assert f"Fetching the TURN certificate from {PROXY_LOGIN}." in first.stdout
    assert "Installed the certificate for turn.securevideocall.com" in first.stdout
    assert (pi.tls_dir / "fullchain.pem").read_bytes() == fullchain.read_bytes()
    assert (pi.tls_dir / "privkey.pem").read_bytes() == key.read_bytes()
    assert stat.S_IMODE((pi.tls_dir / "privkey.pem").stat().st_mode) == 0o400
    assert "sudo install -m 400 -o 65534 -g 65534" in first_calls
    assert re.search(r"docker compose -f \S+/compose\.yaml kill -s SIGUSR2 coturn", first_calls)
    assert list(pi.memory_dir.iterdir()) == []  # the answer and the split files are gone

    unchanged = run_sync(pi, fullchain.read_bytes() + key.read_bytes())
    assert unchanged.returncode == 0, unchanged.stderr
    assert "already installed" in unchanged.stdout
    assert "kill" not in pi.calls()

    renewed = run_sync(pi, renewed_fullchain.read_bytes() + renewed_key.read_bytes())
    assert renewed.returncode == 0, renewed.stderr
    assert (pi.tls_dir / "privkey.pem").read_bytes() == renewed_key.read_bytes()
    assert "kill -s SIGUSR2 coturn" in pi.calls()

    for result, calls in ((first, first_calls), (renewed, pi.calls())):
        for line in key_lines(key) + key_lines(renewed_key):
            assert line not in result.stdout + result.stderr + calls


@pytest.mark.parametrize(("proxy", "port"), [(PROXY_LOGIN, "22"), (f"{PROXY_LOGIN}:2222", "2222")])
def test_sync_connects_with_only_its_own_key_and_the_proxys_host_key(
    tmp_path: Path, test_ca: tuple[Path, Path], proxy: str, port: str
) -> None:
    pi = make_pi(tmp_path, test_ca[1])
    (pi.config_dir / "proxy").write_text(proxy + "\n")
    key, fullchain = make_certificate(tmp_path, "turn", TURN_HOST_NAME, 60, test_ca)
    result = run_sync(pi, fullchain.read_bytes() + key.read_bytes())

    assert result.returncode == 0, result.stderr
    ssh_calls = [line for line in pi.calls().splitlines() if line.startswith("ssh ")]
    config = pi.config_dir
    assert ssh_calls == [
        f"ssh -F none -n -T -p {port}"
        " -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no"
        f" -o IdentitiesOnly=yes -o IdentityAgent=none -i {config}/id_ed25519"
        " -o StrictHostKeyChecking=yes -o UpdateHostKeys=no"
        f" -o UserKnownHostsFile={config}/known_hosts -o GlobalKnownHostsFile=/dev/null"
        " -o ForwardAgent=no -o ForwardX11=no -o ClearAllForwardings=yes"
        " -o PermitLocalCommand=no -o ControlMaster=no -o ControlPath=none"
        " -o ConnectTimeout=20 -o ServerAliveInterval=15 -o ServerAliveCountMax=4"
        f" -o LogLevel=ERROR -- {PROXY_LOGIN} echo {UNRESTRICTED_KEY_MARKER}"
    ]


@pytest.mark.parametrize(
    ("certificate_kind", "message"),
    [
        ("wrong host name", "does not name turn.securevideocall.com"),
        ("expired", "expires within 7 days (or already has)"),
        ("expires in 3 days", "expires within 7 days"),
        ("mismatched key", "does not belong to the certificate"),
        ("another CA", "does not chain to a trusted CA"),
    ],
)
def test_negative_a_certificate_the_install_script_refuses_installs_nothing(
    tmp_path: Path, test_ca: tuple[Path, Path], certificate_kind: str, message: str
) -> None:
    pi = make_pi(tmp_path, test_ca[1])
    good_key, good_fullchain = make_certificate(tmp_path, "good", TURN_HOST_NAME, 60, test_ca)
    if certificate_kind == "wrong host name":
        key, fullchain = make_certificate(tmp_path, "bad", "turn.example.invalid", 60, test_ca)
    elif certificate_kind == "expired":
        key, fullchain = make_expired_certificate(tmp_path, test_ca)
    elif certificate_kind == "expires in 3 days":
        key, fullchain = make_certificate(tmp_path, "bad", TURN_HOST_NAME, 3, test_ca)
    elif certificate_kind == "mismatched key":
        key, fullchain = (
            make_certificate(tmp_path, "bad", TURN_HOST_NAME, 60, test_ca)[0],
            good_fullchain,
        )
    else:
        other_ca = make_certificate(tmp_path, "other-ca", "", 30, None)
        key, fullchain = make_certificate(tmp_path, "bad", TURN_HOST_NAME, 60, other_ca)
    result = run_sync(pi, fullchain.read_bytes() + key.read_bytes())

    assert message in result.stderr
    assert "Fetched a certificate and a key" in result.stdout  # the format was fine
    assert_nothing_installed_or_leaked(pi, result, key)
    assert good_key.exists()


EC_PARAMETERS = "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n"

# Each builds the proxy's answer from the right chain and key text, with the refusal it must get.
MALFORMED_ANSWERS: dict[str, tuple[Callable[[str, str], str | bytes], str]] = {
    "a banner before": (
        lambda chain, key: "Welcome to pizero\n" + chain + key,
        "line 1 does not start a certificate",
    ),
    "text after the key": (lambda chain, key: chain + key + "logout\n", "comes after the key"),
    "a blank line between": (
        lambda chain, key: chain + "\n" + key,
        "does not start a certificate or the key",
    ),
    "a second key": (lambda chain, key: chain + key + key, "comes after the key"),
    "a certificate after the key": (lambda chain, key: chain + key + chain, "comes after the key"),
    "the key first": (lambda chain, key: key + chain, "line 1 does not start a certificate"),
    "another PEM block": (
        lambda chain, key: chain + EC_PARAMETERS + key,
        "does not start a certificate or the key",
    ),
    "an encrypted key": (
        lambda chain, key: chain + key.replace("PRIVATE KEY", "ENCRYPTED PRIVATE KEY"),
        "does not start a certificate or the key",
    ),
    "a line that is not base64": (
        lambda chain, key: chain.replace("\n", "\nnot base64!\n", 2) + key,
        "is not base64 inside a PEM block",
    ),
    "a missing END line": (
        lambda chain, key: chain + key.rsplit("-----END", 1)[0],
        "ends inside a PEM block",
    ),
    "no key": (lambda chain, key: chain, "holds no private key"),
    "nothing": (lambda chain, key: "", "holds no certificate"),
    "Windows line ends": (
        lambda chain, key: (chain + key).replace("\n", "\r\n"),
        "not printable ASCII",
    ),
    "a NUL byte": (
        lambda chain, key: (chain + key).encode().replace(b"\n", b"\n\0", 1),
        "not printable ASCII",
    ),
    "more than 64 KiB": (
        lambda chain, key: chain * (65536 // len(chain) + 1) + key,
        "sent more than 65536 bytes",
    ),
}


@pytest.mark.parametrize("case", list(MALFORMED_ANSWERS))
def test_negative_extra_or_malformed_output_from_the_forced_command_installs_nothing(
    tmp_path: Path, test_ca: tuple[Path, Path], case: str
) -> None:
    pi = make_pi(tmp_path, test_ca[1])
    key, fullchain = make_certificate(tmp_path, "turn", TURN_HOST_NAME, 60, test_ca)
    build_answer, message = MALFORMED_ANSWERS[case]
    answer = build_answer(fullchain.read_text(), key.read_text())
    result = run_sync(pi, answer.encode() if isinstance(answer, str) else answer)

    assert message in result.stderr
    assert "Fetched" not in result.stdout  # install-turn-certificate.sh never ran
    assert "docker" not in pi.calls()
    assert_nothing_installed_or_leaked(pi, result, key)


def test_negative_a_key_without_a_forced_command_is_refused_and_named(
    tmp_path: Path, test_ca: tuple[Path, Path]
) -> None:
    pi = make_pi(tmp_path, test_ca[1])
    key, _ = make_certificate(tmp_path, "turn", TURN_HOST_NAME, 60, test_ca)
    result = run_sync(pi, b"", FAKE_SSH_UNRESTRICTED="1")

    assert "lacks restrict and command=" in result.stderr
    assert "can open a shell there" in result.stderr
    assert_nothing_installed_or_leaked(pi, result, key)


@pytest.mark.parametrize(
    ("status", "stderr", "with_answer"),
    [
        ("255", "Host key verification failed.", False),
        ("255", "turn-certificate@192.0.2.10: Permission denied (publickey).", False),
        ("1", "sudo: a password is required", False),
        ("1", "cat: can't open '/etc/letsencrypt/live/npm-30/privkey.pem'", True),
    ],
)
def test_negative_a_failed_fetch_installs_nothing_even_with_an_answer(
    tmp_path: Path, test_ca: tuple[Path, Path], status: str, stderr: str, with_answer: bool
) -> None:
    pi = make_pi(tmp_path, test_ca[1])
    key, fullchain = make_certificate(tmp_path, "turn", TURN_HOST_NAME, 60, test_ca)
    answer = fullchain.read_bytes() + key.read_bytes() if with_answer else b""
    result = run_sync(pi, answer, FAKE_SSH_STATUS=status, FAKE_SSH_STDERR=stderr)

    assert f"failed (exit status {status};" in result.stderr
    assert stderr in result.stderr  # ssh's own message reaches the journal
    assert_nothing_installed_or_leaked(pi, result, key)


@pytest.mark.parametrize(
    "proxy_file",
    [
        "",
        "turn-certificate@",
        "@192.0.2.10",
        "-oProxyCommand=sh@192.0.2.10",
        "turn-certificate@-oProxyCommand=sh",
        "turn-certificate@192.0.2.10 extra",
        "turn-certificate@192.0.2.10;id",
        "turn-certificate@192.0.2.10:22:22",
        "turn-certificate@192.0.2.10\nroot@192.0.2.11",
        "Turn@192.0.2.10",
    ],
)
def test_negative_a_bad_proxy_login_is_refused_before_connecting(
    tmp_path: Path, test_ca: tuple[Path, Path], proxy_file: str
) -> None:
    pi = make_pi(tmp_path, test_ca[1])
    (pi.config_dir / "proxy").write_text(proxy_file + "\n")
    key, fullchain = make_certificate(tmp_path, "turn", TURN_HOST_NAME, 60, test_ca)
    result = run_sync(pi, fullchain.read_bytes() + key.read_bytes())

    assert "must be one line, USER@HOST or USER@HOST:PORT" in result.stderr
    assert "ssh" not in pi.calls()
    assert_nothing_installed_or_leaked(pi, result, key)


@pytest.mark.parametrize("missing", ["proxy", "id_ed25519", "known_hosts", "coturn"])
def test_negative_a_missing_configuration_file_is_refused_before_connecting(
    tmp_path: Path, test_ca: tuple[Path, Path], missing: str
) -> None:
    pi = make_pi(tmp_path, test_ca[1])
    (pi.config_dir / missing).unlink()
    key, fullchain = make_certificate(tmp_path, "turn", TURN_HOST_NAME, 60, test_ca)
    result = run_sync(pi, fullchain.read_bytes() + key.read_bytes())

    assert f"{pi.config_dir}/{missing}" in result.stderr
    assert "ssh" not in pi.calls()
    assert_nothing_installed_or_leaked(pi, result, key)


def test_negative_a_dev_shm_that_is_not_in_memory_is_refused(
    tmp_path: Path, test_ca: tuple[Path, Path]
) -> None:
    pi = make_pi(tmp_path, test_ca[1])
    write_tools(pi.bin_dir, {"stat": '#!/bin/sh\necho "ext2/ext3"\n'})
    del pi.env["TURN_CERTIFICATE_TEST_MEMORY_DIR"]
    key, fullchain = make_certificate(tmp_path, "turn", TURN_HOST_NAME, 60, test_ca)
    result = run_sync(pi, fullchain.read_bytes() + key.read_bytes())

    assert "/dev/shm is not in memory" in result.stderr  # noqa: S108 - a message, not a path
    assert "ssh" not in pi.calls()
    assert_nothing_installed_or_leaked(pi, result, key)


def test_the_test_memory_folder_is_announced_and_bad_arguments_are_refused(
    tmp_path: Path, test_ca: tuple[Path, Path]
) -> None:
    pi = make_pi(tmp_path, test_ca[1])
    key, fullchain = make_certificate(tmp_path, "turn", TURN_HOST_NAME, 60, test_ca)
    result = run_sync(pi, fullchain.read_bytes() + key.read_bytes())
    assert "WARNING: using" in result.stderr
    assert "(TURN_CERTIFICATE_TEST_MEMORY_DIR is for tests only)" in result.stderr

    for arguments in (("--config-dir",), ("--config", str(pi.config_dir)), ("extra", "x", "y")):
        refused = run_sync(pi, b"", *arguments)
        assert refused.returncode == 2
        assert "Usage:" in refused.stderr


# --- coturn/print-turn-certificate.sh (the proxy machine), with stand-ins -----------------------


@dataclass
class Proxy:
    script: Path
    fullchain: bytes
    key: bytes
    log: Path
    env: dict[str, str]


def make_proxy(tmp_path: Path, test_ca: tuple[Path, Path]) -> Proxy:
    key, fullchain = make_certificate(tmp_path, "turn", TURN_HOST_NAME, 60, test_ca)
    container_root = tmp_path / "container"
    (container_root / LIVE_DIR.lstrip("/")).mkdir(parents=True)
    shutil.copy2(fullchain, container_root / LIVE_DIR.lstrip("/") / "fullchain.pem")
    shutil.copy2(key, container_root / LIVE_DIR.lstrip("/") / "privkey.pem")
    bin_dir = tmp_path / "proxy-bin"
    write_tools(bin_dir, {"docker": FAKE_PROXY_DOCKER, "sudo": FAKE_PROXY_SUDO})
    script = tmp_path / "secure-call-print-turn-certificate"
    shutil.copy2(PRINT_SCRIPT, script)
    log = tmp_path / "proxy-calls.log"
    log.touch()
    env = {
        **clean_environment(),
        "PATH": f"{bin_dir}:/usr/bin:/bin",
        "FAKE_LOG": str(log),
        "FAKE_CONTAINER_ROOT": str(container_root),
    }
    return Proxy(script, fullchain.read_bytes(), key.read_bytes(), log, env)


def run_print(
    proxy: Proxy, *arguments: str, stdin: bytes = b"", **settings: str
) -> subprocess.CompletedProcess[bytes]:
    proxy.log.write_text("")
    return subprocess.run(  # noqa: S603 - fixed script, no user input
        ["/bin/bash", str(proxy.script), *arguments],
        env={**proxy.env, **settings}, input=stdin, capture_output=True, check=False,
    )  # fmt: skip


@pytest.mark.parametrize(
    "client_command",
    ["", f"echo {UNRESTRICTED_KEY_MARKER}", "cat /etc/shadow", "npm-31", "--privileged"],
)
def test_print_prints_exactly_the_two_files_whatever_the_client_asks_for(
    tmp_path: Path, test_ca: tuple[Path, Path], client_command: str
) -> None:
    proxy = make_proxy(tmp_path, test_ca)
    result = run_print(
        proxy, CONTAINER, CERTIFICATE_NAME, stdin=b"npm-31\n", SSH_ORIGINAL_COMMAND=client_command
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == proxy.fullchain + proxy.key
    assert result.stderr == b""
    assert proxy.log.read_text() == (
        f"docker exec {CONTAINER} cat -- {LIVE_DIR}/fullchain.pem {LIVE_DIR}/privkey.pem\n"
    )


@pytest.mark.parametrize(
    "arguments",
    [
        (),
        (CONTAINER,),
        (CONTAINER, CERTIFICATE_NAME, "extra"),
        (CONTAINER, "npm-30/../npm-31"),
        (CONTAINER, "../../../etc"),
        (CONTAINER, "npm-30\n"),
        (CONTAINER, "npm-"),
        (CONTAINER, "letsencrypt"),
        ("--privileged", CERTIFICATE_NAME),
        ("-v", CERTIFICATE_NAME),
        ("nginx proxy", CERTIFICATE_NAME),
        ("nginx;id", CERTIFICATE_NAME),
        ("", CERTIFICATE_NAME),
    ],
)
def test_negative_print_refuses_any_other_names_and_reads_nothing(
    tmp_path: Path, test_ca: tuple[Path, Path], arguments: tuple[str, ...]
) -> None:
    proxy = make_proxy(tmp_path, test_ca)
    result = run_print(proxy, *arguments)

    assert result.returncode == 2
    assert b"Nothing was printed" in result.stderr
    assert result.stdout == b""
    assert proxy.log.read_text() == ""


def test_negative_print_fails_when_docker_does(tmp_path: Path, test_ca: tuple[Path, Path]) -> None:
    proxy = make_proxy(tmp_path, test_ca)
    no_container = run_print(proxy, CONTAINER, CERTIFICATE_NAME, FAKE_DOCKER_EXEC_FAILS="1")
    no_certificate = run_print(proxy, CONTAINER, "npm-31")

    assert no_container.returncode != 0
    assert no_container.stdout == b""
    assert b"No such container" in no_container.stderr
    assert no_certificate.returncode != 0
    assert no_certificate.stdout == b""


# --- Both sides through a real sshd, with the README's authorized_keys line ---------------------


def readme_authorized_keys_options() -> str:
    match = re.search(r"echo '(restrict,[^']*?) <the line from part 1>'", README.read_text())
    assert match is not None, "the authorized_keys line in README.md, TURN step 3b"
    return match[1]


def free_local_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
        return port


@dataclass
class RealSshd:
    port: int
    host_public_key: str
    client_key: Path
    client_public_key: str
    authorized_keys: Path


@pytest.fixture
def real_sshd(tmp_path: Path) -> Iterator[RealSshd]:
    sshd = Path("/usr/sbin/sshd")
    if not sshd.exists() or shutil.which("ssh") is None or shutil.which("ssh-keygen") is None:
        pytest.skip("needs OpenSSH's sshd, ssh and ssh-keygen")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", getpass.getuser()):
        pytest.skip("this user name does not fit the proxy login's pattern")
    ssh_dir = tmp_path / "sshd"
    ssh_dir.mkdir(mode=0o700)
    for name in ("host_key", "client_key"):
        subprocess.run(  # noqa: S603 - fixed command, no user input
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(ssh_dir / name)],  # noqa: S607
            check=True, capture_output=True,
        )  # fmt: skip
    port = free_local_port()
    authorized_keys = ssh_dir / "authorized_keys"
    authorized_keys.write_text("")
    config = ssh_dir / "sshd_config"
    config.write_text(
        f"Port {port}\nListenAddress 127.0.0.1\nHostKey {ssh_dir}/host_key\n"
        f"PidFile {ssh_dir}/sshd.pid\nAuthorizedKeysFile {authorized_keys}\nStrictModes no\n"
        "UsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"
        "PubkeyAuthentication yes\nLogLevel ERROR\n"
    )
    server = subprocess.Popen(  # noqa: S603 - fixed command, no user input
        [str(sshd), "-D", "-e", "-f", str(config)],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )  # fmt: skip
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                if server.poll() is not None:
                    pytest.skip(
                        f"sshd did not start: {server.stderr.read() if server.stderr else ''!r}"
                    )
                time.sleep(0.1)
        else:
            pytest.skip("sshd did not start listening")
        host_public_key = " ".join((ssh_dir / "host_key.pub").read_text().split()[:2])
        client_public_key = (ssh_dir / "client_key.pub").read_text().strip()
        yield RealSshd(
            port, host_public_key, ssh_dir / "client_key", client_public_key, authorized_keys
        )
    finally:
        server.terminate()
        server.wait(timeout=10)


def test_the_readme_authorized_keys_line_lets_the_key_fetch_the_certificate_and_nothing_else(
    tmp_path: Path, test_ca: tuple[Path, Path], real_sshd: RealSshd
) -> None:
    (tmp_path / "proxy-machine").mkdir()
    (tmp_path / "coturn-pi").mkdir()
    proxy = make_proxy(tmp_path / "proxy-machine", test_ca)
    pi = make_pi(tmp_path / "coturn-pi", test_ca[1], fake_ssh=False)
    (pi.config_dir / "proxy").write_text(f"{getpass.getuser()}@127.0.0.1:{real_sshd.port}\n")
    shutil.copy2(real_sshd.client_key, pi.config_dir / "id_ed25519")
    (pi.config_dir / "id_ed25519").chmod(0o600)
    (pi.config_dir / "known_hosts").write_text(
        f"[127.0.0.1]:{real_sshd.port} {real_sshd.host_public_key}\n"
    )
    # The README's line, for this machine: the test's address, certificate and script copy, and
    # a PATH with the stand-ins for sudo and docker.
    options = (
        readme_authorized_keys_options()
        .replace("<this Pi LAN IP>", "127.0.0.1")
        .replace("npm-<N>", CERTIFICATE_NAME)
        .replace(
            f'command="sudo -n {INSTALLED_PRINT_SCRIPT}',
            f'command="PATH={proxy.env["PATH"]} FAKE_LOG={proxy.log}'
            f" FAKE_CONTAINER_ROOT={proxy.env['FAKE_CONTAINER_ROOT']}"
            f" sudo -n /bin/bash {proxy.script}",
        )
    )
    assert options.startswith('restrict,from="127.0.0.1",command="PATH=')

    def fetch_with(authorized_keys_line: str) -> subprocess.CompletedProcess[str]:
        real_sshd.authorized_keys.write_text(authorized_keys_line + "\n")
        proxy.log.write_text("")
        return run_sync(pi)

    forced = fetch_with(f"{options} {real_sshd.client_public_key}")
    assert forced.returncode == 0, forced.stderr
    assert "Installed the certificate for turn.securevideocall.com" in forced.stdout
    assert (pi.tls_dir / "privkey.pem").read_bytes() == proxy.key
    assert (
        f"sudo -n /bin/bash {proxy.script} {CONTAINER} {CERTIFICATE_NAME}" in proxy.log.read_text()
    )

    unrestricted = fetch_with(real_sshd.client_public_key)
    assert unrestricted.returncode == 1
    assert "lacks restrict and command=" in unrestricted.stderr

    other_address = fetch_with(
        f"{options.replace('127.0.0.1', '192.0.2.1', 1)} {real_sshd.client_public_key}"
    )
    assert other_address.returncode == 1
    assert "failed (exit status 255;" in other_address.stderr
    assert proxy.log.read_text() == ""
    for result in (forced, unrestricted, other_address):
        for line in proxy.key.decode().splitlines()[1:-1]:
            assert line not in result.stdout + result.stderr


# --- The systemd units -------------------------------------------------------------------------

SERVICE_REQUIRED = {
    "Type": ["oneshot"],
    "ExecStart": [f"{INSTALLED_LIB_DIR}/sync-turn-certificate.sh"],
    "SyslogIdentifier": ["secure-call-turn"],
    "UMask": ["0077"],
    "TemporaryFileSystem": ["/dev/shm:mode=0700,nosuid,noexec"],  # noqa: S108 - its own tmpfs
    "PrivateTmp": ["yes"],
    "CapabilityBoundingSet": ["CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH"],
    "NoNewPrivileges": ["yes"],
    "ProtectSystem": ["full"],
}
TIMER_REQUIRED = {
    "Persistent": ["true"],
    "WantedBy": ["timers.target"],
}


def unit_settings(unit_text: str) -> dict[str, list[str]]:
    settings: dict[str, list[str]] = {}
    for line in unit_text.splitlines():
        if "=" in line and not line.startswith(("#", "[")):
            key, value = line.split("=", 1)
            settings.setdefault(key, []).append(value)
    return settings


def service_problems(unit_text: str) -> list[str]:
    settings = unit_settings(unit_text)
    problems = [key for key, value in SERVICE_REQUIRED.items() if settings.get(key) != value]
    problems += [key for key in ("Environment", "EnvironmentFile", "User") if key in settings]
    return problems


def timer_problems(unit_text: str) -> list[str]:
    settings = unit_settings(unit_text)
    problems = [key for key, value in TIMER_REQUIRED.items() if settings.get(key) != value]
    if "Unit" in settings:  # the timer starts the service of its own name
        problems.append("Unit")
    return problems


def test_the_units_run_the_root_owned_copy_sandboxed_twice_a_day() -> None:
    assert service_problems(SERVICE.read_text()) == []
    assert timer_problems(TIMER.read_text()) == []
    assert unit_settings(TIMER.read_text())["OnCalendar"] == ["*-*-* 04,16:00:00"]


@pytest.mark.parametrize(
    ("old", "new", "problem"),
    [
        (f"ExecStart={INSTALLED_LIB_DIR}/sync-turn-certificate.sh",
         "ExecStart=/home/pi/secure-call-backend/deploy/raspberry-pi/coturn/sync-turn-certificate.sh",
         "ExecStart"),
        ("TemporaryFileSystem=/dev/shm:mode=0700,nosuid,noexec\n", "", "TemporaryFileSystem"),
        ("CAP_DAC_READ_SEARCH\n", "CAP_DAC_READ_SEARCH CAP_SYS_ADMIN\n", "CapabilityBoundingSet"),
        ("NoNewPrivileges=yes\n", "", "NoNewPrivileges"),
        ("UMask=0077\n", "UMask=0022\n", "UMask"),
        ("PrivateTmp=yes\n", "PrivateTmp=yes\nEnvironment=TURN_CERTIFICATE_TEST_MEMORY_DIR=/tmp\n",
         "Environment"),
    ],
)  # fmt: skip
def test_negative_a_weakened_service_is_caught(old: str, new: str, problem: str) -> None:
    unit = SERVICE.read_text()

    assert old in unit
    assert problem in service_problems(unit.replace(old, new, 1))


def test_negative_a_timer_that_skips_missed_runs_is_caught() -> None:
    timer = TIMER.read_text()

    assert "Persistent" in timer_problems(timer.replace("Persistent=true", "Persistent=false"))
    assert "Unit" in timer_problems(timer + "Unit=other.service\n")


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="needs systemd-analyze")
def test_systemd_accepts_the_units(tmp_path: Path) -> None:
    """systemd's own parser, with ExecStart pointing at the repository's script (the root-owned
    copy does not exist here)."""
    shutil.copy2(TIMER, tmp_path / TIMER.name)
    (tmp_path / SERVICE.name).write_text(
        SERVICE.read_text().replace(
            f"{INSTALLED_LIB_DIR}/sync-turn-certificate.sh", str(SYNC_SCRIPT)
        )
    )
    systemd_analyze = shutil.which("systemd-analyze")
    assert systemd_analyze is not None
    result = subprocess.run(  # noqa: S603 - fixed command, no user input
        [systemd_analyze, "verify", str(tmp_path / SERVICE.name), str(tmp_path / TIMER.name)],
        capture_output=True, text=True, check=False,
    )  # fmt: skip

    our_lines = [line for line in result.stderr.splitlines() if "secure-call-turn" in line]
    assert result.returncode == 0, result.stderr
    assert our_lines == [], result.stderr


# --- The README and the scripts agree ----------------------------------------------------------


def test_readme_sets_up_both_machines_with_the_paths_the_scripts_use() -> None:
    readme = README.read_text()
    sync = SYNC_SCRIPT.read_text()
    setup_lines = (
        f"sudo install -d -o root -g root -m 0700 {CONFIG_DIR}",
        "sudo ssh-keygen -q -t ed25519 -N '' -C secure-call-turn-certificate"
        f" -f {CONFIG_DIR}/id_ed25519",
        f"sudo install -o root -g root -m 0755 print-turn-certificate.sh {INSTALLED_PRINT_SCRIPT}",
        "sudo adduser --system --group --shell /bin/sh --home /var/lib/turn-certificate"
        " turn-certificate",
        "sudo visudo -cf turn-certificate.sudoers",
        "sudo install -o root -g root -m 0440 turn-certificate.sudoers"
        " /etc/sudoers.d/secure-call-turn-certificate",
        "sudo install -d -o root -g root -m 0755 /var/lib/turn-certificate/.ssh",
        f"echo 'turn-certificate@<proxy LAN IP>' | sudo tee {CONFIG_DIR}/proxy",
        f"ssh-keyscan -t ed25519 <proxy LAN IP> 2>/dev/null | sudo tee {CONFIG_DIR}/known_hosts",
        f"sudo install -D -o root -g root -m 0755 -t {INSTALLED_LIB_DIR}"
        " coturn/sync-turn-certificate.sh coturn/install-turn-certificate.sh",
        f'sudo ln -sfn "$PWD/coturn" {CONFIG_DIR}/coturn',
        f"sudo install -o root -g root -m 0644 coturn/{SERVICE.name} coturn/{TIMER.name}"
        " /etc/systemd/system/",
        f"sudo systemctl enable --now {TIMER.name}",
        "journalctl -t secure-call-turn",
        'logger -t secure-call-turn "TURN certificate expires within 21 days"',
    )

    for line in setup_lines:
        assert line in readme, line
    assert f"config_dir={CONFIG_DIR}\n" in sync
    assert f"readonly UNRESTRICTED_KEY_MARKER={UNRESTRICTED_KEY_MARKER}\n" in sync


def test_readme_sudoers_line_allows_exactly_the_forced_command() -> None:
    readme = README.read_text()
    sudoers = re.search(r"echo 'turn-certificate ALL=\(root\) NOPASSWD: ([^']+)'", readme)
    options = readme_authorized_keys_options()
    forced = re.fullmatch(r'restrict,from="<this Pi LAN IP>",command="sudo -n ([^"]+)"', options)

    assert sudoers is not None
    assert forced is not None
    assert sudoers[1] == forced[1] == f"{INSTALLED_PRINT_SCRIPT} {CONTAINER} npm-<N>"


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck is not installed")
def test_the_scripts_pass_shellcheck() -> None:
    shellcheck = shutil.which("shellcheck")
    assert shellcheck is not None
    scripts = [SYNC_SCRIPT, PRINT_SCRIPT, COTURN / "install-turn-certificate.sh"]
    result = subprocess.run(  # noqa: S603 - fixed command, no user input
        [shellcheck, *map(str, scripts)], capture_output=True, text=True, check=False
    )

    assert result.returncode == 0, result.stdout
