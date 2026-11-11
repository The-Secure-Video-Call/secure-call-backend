"""deploy/raspberry-pi/compose.yaml keeps the backend locked down and PostgreSQL TLS-only.
Read as text (no YAML parser is installed); CI's database tests start the real service."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy/raspberry-pi"

BACKEND_REQUIRED = (
    "read_only: true",
    "cap_drop:\n      - ALL",
    "security_opt:\n      - no-new-privileges:true",
    "POSTGRES_USER: ${POSTGRES_APP_USER:-securecall_app}",
    "POSTGRES_PASSWORD: ${POSTGRES_APP_PASSWORD:?",
    "POSTGRES_SSLMODE: verify-full",
    "POSTGRES_SSLROOTCERT: /run/secure-call/local-ca.crt",
    "BACKEND_TLS_CERTIFICATE: /run/secure-call/backend.crt",
    "BACKEND_TLS_KEY: /run/secure-call/backend.key",
)
POSTGRES_REQUIRED = (
    "- ssl=on",
    "- ssl_min_protocol_version=TLSv1.3",
    "- hba_file=/etc/postgresql/pg_hba.conf",
    "source: ./postgres/pg_hba.conf\n        target: /etc/postgresql/pg_hba.conf",
    "source: ./postgres/initdb\n        target: /docker-entrypoint-initdb.d",
    "pg_isready -h 127.0.0.1",
)


def service_block(compose_text: str, service: str) -> str:
    """The lines of one top-level service, up to the next service or top-level key."""
    match = re.search(rf"^  {service}:\n(.*?)(?=^  \S|^\S)", compose_text, re.M | re.S)
    return match.group(1) if match else ""


def missing(block: str, required: tuple[str, ...]) -> list[str]:
    return [item for item in required if item not in block]


def test_backend_runs_read_only_without_capabilities_as_its_own_role() -> None:
    backend = service_block((DEPLOY / "compose.yaml").read_text(), "backend")

    assert missing(backend, BACKEND_REQUIRED) == []
    assert "privileged: true" not in backend
    assert "cap_add" not in backend


def test_postgres_accepts_tls_connections_only() -> None:
    postgres = service_block((DEPLOY / "compose.yaml").read_text(), "postgres")
    rules = [
        line.split()
        for line in (DEPLOY / "postgres/pg_hba.conf").read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    assert missing(postgres, POSTGRES_REQUIRED) == []
    # Only the container's own Unix socket, and TLS over the network: no "host" or "hostnossl".
    assert {rule[0] for rule in rules} == {"local", "hostssl"}
    assert all(rule[-1] == "scram-sha-256" for rule in rules if rule[0] == "hostssl")


def test_negative_a_service_without_the_hardening_is_caught() -> None:
    weakened = "services:\n  backend:\n    image: x\n    read_only: false\n  postgres:\n"

    assert missing(service_block(weakened, "backend"), BACKEND_REQUIRED) == list(BACKEND_REQUIRED)
    assert service_block(weakened, "missing") == ""


def test_certificates_and_keys_are_never_committed() -> None:
    assert "deploy/raspberry-pi/tls/" in (ROOT / ".gitignore").read_text().splitlines()


def test_readme_shows_exactly_the_proxy_lines_ci_tests() -> None:
    advanced_lines = [
        line
        for line in (DEPLOY / "npm-advanced.conf").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    readme = (ROOT / "README.md").read_text()

    assert "proxy_ssl_verify on;" in advanced_lines
    for line in advanced_lines:
        assert f"   {line}\n" in readme, line


COTURN_REQUIRED = (
    "- '${TURN_RELAY_IP:?Set TURN_RELAY_IP in .env}:5349:5349/tcp'",
    "- /run/coturn:size=64k,mode=1777,noexec,nosuid,nodev",
    "source: ./secrets/turn-static-auth-secret.conf\n"
    "        target: /run/secrets/turn-static-auth-secret.conf",
    "source: ./coturn/tls\n        target: /etc/coturn/tls",
    "user: '65534:65534'",
    "driver: none",
)


def compose_coturn_start_script(coturn: str) -> str:
    """The folded `sh -c` script of the coturn entrypoint, as the shell receives it."""
    folded = re.search(r"      - >-\n((?:        .*\n)+)", coturn)
    assert folded is not None, "coturn's entrypoint script (a folded >- block) is missing"
    return " ".join(line.strip() for line in folded.group(1).splitlines()).replace("$$", "$")


def test_coturn_reads_the_secret_from_a_file_and_serves_tls() -> None:
    coturn = service_block((DEPLOY / "compose.yaml").read_text(), "coturn")

    assert missing(coturn, COTURN_REQUIRED) == []
    # No secret value anywhere in the service: only the file path and the check of its format.
    assert "--static-auth-secret" not in coturn
    assert not re.search(r"static-auth-secret=[A-Za-z0-9+/=_-]{8,}", coturn)
    assert "TURN_SHARED_SECRET" not in coturn
    assert "env_file:" not in coturn


def test_coturn_starts_exactly_as_the_ci_test_starts_it() -> None:
    coturn = service_block((DEPLOY / "compose.yaml").read_text(), "coturn")
    test_script = (DEPLOY / "coturn/test-coturn.sh").read_text()
    test_start = re.search(r"^coturn_start_script='(.*)'$", test_script, re.M)

    assert test_start is not None
    assert compose_coturn_start_script(coturn) == test_start.group(1)
    assert "umask 077" in test_start.group(1)
    assert "exec turnserver -c /run/coturn/turnserver.conf" in test_start.group(1)


def test_backend_reads_the_turn_secret_from_a_file() -> None:
    backend = service_block((DEPLOY / "compose.yaml").read_text(), "backend")

    assert "TURN_SHARED_SECRET: ''" in backend
    assert "TURN_SHARED_SECRET_FILE: /run/secure-call/turn-shared-secret" in backend
    assert "source: ./secrets/turn-shared-secret" in backend


def test_negative_a_changed_start_script_is_caught() -> None:
    weakened = (
        "  coturn:\n    entrypoint:\n      - sh\n      - -c\n      - >-\n"
        '        exec turnserver --static-auth-secret=x "$$@"\n      - coturn-start\n'
    )
    assert compose_coturn_start_script(weakened) == 'exec turnserver --static-auth-secret=x "$@"'
    assert "umask 077" not in compose_coturn_start_script(weakened)


def test_turn_secrets_and_certificates_are_never_committed() -> None:
    ignored = (ROOT / ".gitignore").read_text().splitlines()

    assert "deploy/raspberry-pi/secrets/" in ignored
    assert "deploy/raspberry-pi/coturn/tls/" in ignored
