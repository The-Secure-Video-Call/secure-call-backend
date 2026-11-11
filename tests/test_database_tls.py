"""The PostgreSQL that deploy/raspberry-pi/compose.yaml runs: TLS only, its certificate checked,
and the backend's role without extra rights. CI starts that exact service (see ci.yml); these
tests run only when POSTGRES_SSLMODE is verify-full and the backend's role is configured."""

import os
import shutil
import subprocess
from pathlib import Path

import psycopg
import pytest
from psycopg.conninfo import make_conninfo

TLS_DATABASE_CONFIGURED = os.environ.get("POSTGRES_SSLMODE") == "verify-full" and bool(
    os.environ.get("POSTGRES_APP_USER")
)
requires_tls_database = pytest.mark.skipif(
    not TLS_DATABASE_CONFIGURED,
    reason="no TLS PostgreSQL with the backend's role configured (see ci.yml)",
)


def test_ci_always_runs_these_tests() -> None:
    # GitHub Actions sets CI=true. A change to ci.yml must not turn these into silent skips.
    if os.environ.get("CI") == "true":
        assert TLS_DATABASE_CONFIGURED, "ci.yml must configure the TLS database (see above)"


def connection_info(**overrides: str) -> str:
    """How the backend connects, as its own role; `overrides` change one thing at a time."""
    settings = {
        "host": os.environ.get("POSTGRES_HOST", ""),
        "port": os.environ.get("POSTGRES_PORT", "5432"),
        "dbname": os.environ.get("POSTGRES_DB", "securecall"),
        "user": os.environ.get("POSTGRES_APP_USER", ""),
        "password": os.environ.get("POSTGRES_APP_PASSWORD", ""),
        "sslmode": "verify-full",
        "sslrootcert": os.environ.get("POSTGRES_SSLROOTCERT", ""),
        "connect_timeout": "5",
        **overrides,
    }
    return make_conninfo(**settings)


@requires_tls_database
def test_backend_role_connects_with_tls_1_3() -> None:
    with psycopg.connect(connection_info()) as connection:
        tls = connection.execute(
            "SELECT ssl, version FROM pg_stat_ssl WHERE pid = pg_backend_pid()"
        ).fetchone()
    assert tls == (True, "TLSv1.3")


@requires_tls_database
def test_backend_role_has_no_extra_rights() -> None:
    with psycopg.connect(connection_info()) as connection:
        rights = connection.execute(
            "SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls "
            "FROM pg_roles WHERE rolname = current_user"
        ).fetchone()
        owns_database = connection.execute(
            "SELECT pg_get_userbyid(datdba) = current_user FROM pg_database "
            "WHERE datname = current_database()"
        ).fetchone()
    assert rights == (False, False, False, False, False)
    assert owns_database == (True,)  # so it can run migrations


@requires_tls_database
def test_negative_plaintext_connection_is_refused_by_the_server() -> None:
    with pytest.raises(psycopg.OperationalError, match="no encryption"):
        psycopg.connect(connection_info(sslmode="disable"))


@requires_tls_database
def test_negative_certificate_from_another_ca_is_refused(tmp_path: Path) -> None:
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl is needed to make the other CA")
    other_root_certificate = tmp_path / "other-ca.crt"
    subprocess.run(  # noqa: S603 - fixed command, no user input
        [
            openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-keyout", str(tmp_path / "other-ca.key"), "-subj", "/CN=other CA",
            "-days", "1", "-out", str(other_root_certificate),
        ],
        check=True,
        capture_output=True,
    )  # fmt: skip
    with pytest.raises(psycopg.OperationalError, match="certificate verify failed"):
        psycopg.connect(connection_info(sslrootcert=str(other_root_certificate)))


@requires_tls_database
def test_negative_wrong_host_name_is_refused() -> None:
    # The same server, reached under a name its certificate does not carry.
    wrong_name = connection_info(host="not-in-the-certificate.invalid", hostaddr="127.0.0.1")
    with pytest.raises(psycopg.OperationalError, match="does not match host name"):
        psycopg.connect(wrong_name)
