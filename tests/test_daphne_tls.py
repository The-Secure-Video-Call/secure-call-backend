"""The backend's HTTPS/WSS listener (issue #59): the Dockerfile CMD picks TLS whenever a
certificate is configured, and Daphne then serves only TLS, with a certificate the reverse proxy
can check against our local CA."""

import asyncio
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from websockets.asyncio.client import connect

ROOT = Path(__file__).resolve().parent.parent
BACKEND_NAME = "secure-call-backend"  # the name the proxy checks (proxy_ssl_name)
ALLOWED_ORIGIN = "http://localhost:5173"
HEALTH_REQUEST = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"


def dockerfile_start_script() -> str:
    """The shell script inside the Dockerfile's CMD ["sh", "-c", "..."]."""
    cmd_line = next(
        line for line in (ROOT / "Dockerfile").read_text().splitlines() if line.startswith("CMD ")
    )
    command: list[str] = json.loads(cmd_line.removeprefix("CMD "))
    assert command[:2] == ["sh", "-c"]
    return command[2]


def run_start_script_unchecked(
    tmp_path: Path, env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    """Runs the CMD with stand-ins for daphne and python, which print their arguments."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    for program in ("daphne", "python"):
        stand_in = bin_dir / program
        stand_in.write_text(f'#!/bin/sh\nfor a in "$@"; do echo "{program}: $a"; done\n')
        stand_in.chmod(0o755)
    clean_env = {k: v for k, v in os.environ.items() if not k.startswith(("POSTGRES_", "BACKEND_"))}
    result = subprocess.run(  # noqa: S603 - fixed command, no user input
        ["/bin/sh", "-c", dockerfile_start_script()],
        env={**clean_env, "PATH": f"{bin_dir}:{os.environ['PATH']}", **env},
        capture_output=True,
        text=True,
        check=False,
    )
    return result


def run_start_script(tmp_path: Path, env: dict[str, str]) -> list[str]:
    """Runs the CMD (which must succeed) and returns daphne's arguments."""
    result = run_start_script_unchecked(tmp_path, env)
    assert result.returncode == 0, result.stderr
    return [line.removeprefix("daphne: ") for line in result.stdout.splitlines()]


def test_start_script_serves_tls_only_when_a_certificate_is_configured(tmp_path: Path) -> None:
    tls_arguments = run_start_script(
        tmp_path,
        {"BACKEND_TLS_CERTIFICATE": "/run/secure-call/backend.crt",
         "BACKEND_TLS_KEY": "/run/secure-call/backend.key"},
    )  # fmt: skip
    plain_arguments = run_start_script(tmp_path, {})

    endpoint = (
        "ssl:8000:interface=0.0.0.0:privateKey=/run/secure-call/backend.key"
        ":certKey=/run/secure-call/backend.crt"
    )
    assert tls_arguments[-3:] == ["-e", endpoint, "config.asgi:application"]
    assert "-b" not in tls_arguments
    assert "-p" not in tls_arguments
    all_interfaces = "0.0.0.0"  # noqa: S104 - what the container binds, not this test
    assert plain_arguments[-5:] == ["-b", all_interfaces, "-p", "8000", "config.asgi:application"]


def test_negative_a_certificate_without_a_key_stops_the_start(tmp_path: Path) -> None:
    result = run_start_script_unchecked(tmp_path, {"BACKEND_TLS_CERTIFICATE": "/run/x.crt"})

    assert result.returncode != 0
    assert "BACKEND_TLS_KEY must be set" in result.stderr
    assert result.stdout == ""  # neither the migration nor daphne ran


def test_negative_paths_twisted_would_misread_stop_the_start(tmp_path: Path) -> None:
    for bad_path in ["/run/a:b.key", "/run/a=b.key", "/run/a\\b.key"]:
        env = {"BACKEND_TLS_CERTIFICATE": "/run/x.crt", "BACKEND_TLS_KEY": bad_path}
        result = run_start_script_unchecked(tmp_path, env)

        assert result.returncode != 0, bad_path
        assert "must not contain" in result.stderr
        assert result.stdout == ""


def make_certificates(directory: Path, ca_name: str) -> tuple[Path, Path, Path]:
    """A CA and a server certificate for BACKEND_NAME, made as make-local-certs.sh does."""
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl is needed to make test certificates")

    def run_openssl(*arguments: str) -> None:
        subprocess.run([openssl, *arguments], check=True, capture_output=True)  # noqa: S603

    ec_key = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes"]
    ca_key, ca_certificate = directory / f"{ca_name}.key", directory / f"{ca_name}.crt"
    run_openssl(
        "req", "-x509", *ec_key, "-keyout", str(ca_key), "-subj", f"/CN={ca_name}", "-days", "1",
        "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", str(ca_certificate),
    )  # fmt: skip
    server_key, server_request = directory / "backend.key", directory / "backend.csr"
    server_certificate, extensions = directory / "backend.crt", directory / "backend.ext"
    run_openssl("req", *ec_key, "-keyout", str(server_key), "-subj", "/CN=backend",
                "-out", str(server_request))  # fmt: skip
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
        f"extendedKeyUsage=serverAuth\nsubjectAltName=DNS:{BACKEND_NAME}\n"
    )
    run_openssl(
        "x509", "-req", "-in", str(server_request), "-CA", str(ca_certificate),
        "-CAkey", str(ca_key), "-set_serial", "1", "-days", "1", "-extfile", str(extensions),
        "-out", str(server_certificate),
    )  # fmt: skip
    return ca_certificate, server_certificate, server_key


@pytest.fixture(scope="module")
def tls_daphne(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[int, Path]]:
    directory = tmp_path_factory.mktemp("tls")
    ca_certificate, server_certificate, server_key = make_certificates(directory, "local-ca")
    with socket.socket() as probe_socket:
        probe_socket.bind(("127.0.0.1", 0))
        port: int = probe_socket.getsockname()[1]
    server_environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("POSTGRES_", "DJANGO_", "SIGNALING_", "REDIS_", "BACKEND_"))
    }
    server_environment["DJANGO_SETTINGS_MODULE"] = "config.settings_test"
    server_environment["SIGNALING_ALLOWED_ORIGINS"] = ALLOWED_ORIGIN
    # The same endpoint form as the Dockerfile CMD, on a free local port.
    endpoint = (
        f"ssl:{port}:interface=127.0.0.1:privateKey={server_key}:certKey={server_certificate}"
    )
    server_process = subprocess.Popen(  # noqa: S603 - fixed arguments, no user input
        [sys.executable, "-m", "daphne", "-v", "0", "-e", endpoint, "config.asgi:application"],
        env=server_environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if server_process.poll() is not None:
                pytest.fail("Daphne exited before accepting connections")
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            pytest.fail("Daphne did not start in time")
        yield port, ca_certificate
    finally:
        server_process.terminate()
        server_process.wait(timeout=10)


def proxy_tls_context(ca_certificate: Path) -> ssl.SSLContext:
    """What the reverse proxy does: trust only our CA, check the name, TLS 1.3 only."""
    context = ssl.create_default_context(cafile=str(ca_certificate))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    return context


def get_health(port: int, context: ssl.SSLContext, server_name: str = BACKEND_NAME) -> bytes:
    raw_connection = socket.create_connection(("127.0.0.1", port), timeout=5)
    with context.wrap_socket(raw_connection, server_hostname=server_name) as tls_connection:
        tls_connection.sendall(HEALTH_REQUEST)
        response = b""
        while chunk := tls_connection.recv(4096):
            response += chunk
    return response


def test_health_check_answers_over_tls_1_3(tls_daphne: tuple[int, Path]) -> None:
    port, ca_certificate = tls_daphne
    response = get_health(port, proxy_tls_context(ca_certificate))

    assert response.startswith(b"HTTP/1.1 200 ")
    assert response.endswith(b'{"status": "ok"}')


async def test_signaling_websocket_works_over_tls(tls_daphne: tuple[int, Path]) -> None:
    port, ca_certificate = tls_daphne
    async with connect(
        f"wss://127.0.0.1:{port}/ws/signal/",
        ssl=proxy_tls_context(ca_certificate),
        server_hostname=BACKEND_NAME,
        origin=ALLOWED_ORIGIN,  # type: ignore[arg-type]
    ) as client:
        await client.send(json.dumps({"v": 1, "type": "join", "roomId": "A" * 22}))
        reply = json.loads(await asyncio.wait_for(client.recv(), 5))
    assert reply["type"] == "joined"


def test_negative_plain_http_gets_no_answer(tls_daphne: tuple[int, Path]) -> None:
    port, _ = tls_daphne
    with socket.create_connection(("127.0.0.1", port), timeout=5) as plain_connection:
        plain_connection.sendall(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        try:
            answer = plain_connection.recv(4096)
        except ConnectionResetError:
            answer = b""
    assert not answer.startswith(b"HTTP/")
    assert b"status" not in answer


def test_negative_proxy_refuses_a_certificate_from_another_ca(
    tls_daphne: tuple[int, Path], tmp_path: Path
) -> None:
    port, _ = tls_daphne
    other_ca_certificate, _, _ = make_certificates(tmp_path, "other-ca")
    with pytest.raises(ssl.SSLCertVerificationError):
        get_health(port, proxy_tls_context(other_ca_certificate))


def test_negative_proxy_refuses_a_wrong_name(tls_daphne: tuple[int, Path]) -> None:
    port, ca_certificate = tls_daphne
    with pytest.raises(ssl.SSLCertVerificationError, match=re.escape("not-the-backend")):
        get_health(port, proxy_tls_context(ca_certificate), server_name="not-the-backend")
