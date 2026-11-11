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
