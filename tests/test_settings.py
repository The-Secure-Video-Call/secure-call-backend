"""Production defaults must be safe: these run the real settings module in a clean process."""

import logging
import os
import re
import subprocess
import sys
from pathlib import Path

from config.settings import LOG_LINE_FORMAT, LOGGING, build_utc_log_formatter
from signaling.rooms import TOTAL_LIFETIME_LIMIT_SECONDS

ROOT = Path(__file__).resolve().parent.parent


DEFAULT_PRINT = (
    "import config.settings as s; "
    "print(s.DEBUG, s.SECURE_SSL_REDIRECT, s.SECURE_HSTS_SECONDS, s.SIGNALING_ALLOWED_ORIGINS)"
)


def load_settings(
    env: dict[str, str], code: str = DEFAULT_PRINT
) -> subprocess.CompletedProcess[str]:
    prefixes = ("DJANGO_", "SIGNALING_", "POSTGRES_", "TURN_", "TRUSTED_")
    clean_env = {k: v for k, v in os.environ.items() if not k.startswith(prefixes)}
    return subprocess.run(  # noqa: S603 - fixed command, no user input
        [sys.executable, "-c", code],
        cwd=ROOT,
        env={**clean_env, **env},
        capture_output=True,
        text=True,
        check=False,
    )


def test_refuses_to_start_without_secret_key_in_production() -> None:
    result = load_settings({})

    assert result.returncode != 0
    assert "DJANGO_SECRET_KEY must be set" in result.stderr


def test_production_defaults_are_secure() -> None:
    result = load_settings({"DJANGO_SECRET_KEY": "k" * 60})

    assert result.returncode == 0, result.stderr
    debug, ssl_redirect, hsts, origins = result.stdout.strip().split(" ", 3)
    assert debug == "False"
    assert ssl_redirect == "True"
    assert int(hsts) >= 31_536_000
    assert origins == "[]"  # no browser origin allowed until configured


def test_debug_mode_allows_vite_dev_server() -> None:
    result = load_settings({"DJANGO_DEBUG": "1"})

    assert result.returncode == 0, result.stderr
    assert "http://localhost:5173" in result.stdout


DB_PRINT = (
    "import config.settings as s; d = s.DATABASES.get('default', {}); "
    "print(d.get('ENGINE', 'none'), d.get('HOST', '-'), d.get('NAME', '-'))"
)


def test_no_database_without_postgres_host() -> None:
    result = load_settings({"DJANGO_SECRET_KEY": "k" * 60}, DB_PRINT)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "none - -"


def test_postgres_settings_come_from_environment(tmp_path: Path) -> None:
    root_certificate = tmp_path / "local-ca.crt"
    root_certificate.write_text("not parsed by the settings\n")
    env = {
        "DJANGO_SECRET_KEY": "k" * 60,
        "POSTGRES_HOST": "127.0.0.1",
        "POSTGRES_DB": "accounts",
        "POSTGRES_PASSWORD": "not-a-real-password",
        "POSTGRES_SSLROOTCERT": str(root_certificate),
    }
    result = load_settings(env, DB_PRINT)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "django.db.backends.postgresql 127.0.0.1 accounts"


DB_TLS_PRINT = (
    "import config.settings as s; o = s.DATABASES['default']['OPTIONS']; "
    "print(o['sslmode'], o.get('sslrootcert', '-'))"
)
DB_ENV = {
    "DJANGO_SECRET_KEY": "k" * 60,
    "POSTGRES_HOST": "postgres",
    "POSTGRES_PASSWORD": "not-a-real-password",
}


def test_database_tls_checks_certificate_and_host_name_by_default(tmp_path: Path) -> None:
    root_certificate = tmp_path / "local-ca.crt"
    root_certificate.write_text("not parsed by the settings\n")
    result = load_settings({**DB_ENV, "POSTGRES_SSLROOTCERT": str(root_certificate)}, DB_TLS_PRINT)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"verify-full {root_certificate}"


def test_database_without_tls_only_when_asked_for_explicitly() -> None:
    result = load_settings({**DB_ENV, "POSTGRES_SSLMODE": "disable"}, DB_TLS_PRINT)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "disable -"


def test_refuses_database_tls_without_a_root_certificate(tmp_path: Path) -> None:
    for root_certificate in ["", str(tmp_path / "missing.crt"), str(tmp_path)]:
        env = {**DB_ENV, "POSTGRES_SSLROOTCERT": root_certificate}
        result = load_settings(env, DB_TLS_PRINT)

        assert result.returncode != 0, root_certificate
        assert "POSTGRES_SSLROOTCERT must name the root certificate" in result.stderr
        assert "not-a-real-password" not in result.stdout + result.stderr


def test_refuses_database_tls_modes_that_fall_back_or_accept_any_certificate(
    tmp_path: Path,
) -> None:
    root_certificate = tmp_path / "local-ca.crt"
    root_certificate.write_text("not parsed by the settings\n")
    for sslmode in ["prefer", "allow", "require", "verify-ca", "VERIFY-FULL", " verify-full", ""]:
        env = {
            **DB_ENV,
            "POSTGRES_SSLMODE": sslmode,
            "POSTGRES_SSLROOTCERT": str(root_certificate),
        }
        result = load_settings(env, DB_TLS_PRINT)

        assert result.returncode != 0, sslmode
        assert "POSTGRES_SSLMODE must be verify-full" in result.stderr


TURN_PRINT = (
    "import config.settings as s; "
    "print(bool(s.TURN_SHARED_SECRET), s.TURN_URLS, s.TURN_CREDENTIAL_TTL_SECONDS)"
)


def test_turn_is_off_by_default_with_four_hour_ttl() -> None:
    result = load_settings({"DJANGO_SECRET_KEY": "k" * 60}, TURN_PRINT)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False [] 14400"


def test_default_turn_ttl_matches_the_room_lifetime_limit() -> None:
    # A TURN credential must not expire before the room does, or an ICE restart late in a call
    # (the relay is the only path in privacy mode) could not get a new allocation.
    result = load_settings(
        {"DJANGO_SECRET_KEY": "k" * 60},
        "import config.settings as s; print(s.DEFAULT_TURN_CREDENTIAL_TTL_SECONDS)",
    )

    assert result.returncode == 0, result.stderr
    assert int(result.stdout.strip()) == TOTAL_LIFETIME_LIMIT_SECONDS


def test_turn_settings_come_from_environment() -> None:
    env = {
        "DJANGO_SECRET_KEY": "k" * 60,
        "TURN_SHARED_SECRET": "s",
        "TURN_URLS": "turn:a.example:3478, turns:a.example:5349",
        "TURN_CREDENTIAL_TTL_SECONDS": "7200",
    }
    result = load_settings(env, TURN_PRINT)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "True ['turn:a.example:3478', 'turns:a.example:5349'] 7200"


def test_bad_turn_settings_stop_startup_without_echoing_the_secret() -> None:
    secret = "very-secret-value"  # noqa: S105 - test value
    bad_envs = [
        {"TURN_URLS": "http://a.example"},
        {"TURN_URLS": "turn:a,turn:b,turn:c,turn:d,turn:e"},
        {"TURN_CREDENTIAL_TTL_SECONDS": "0"},
        {"TURN_CREDENTIAL_TTL_SECONDS": "31536000"},
        {"TURN_CREDENTIAL_TTL_SECONDS": "14401"},
        {"TURN_CREDENTIAL_TTL_SECONDS": "soon"},
    ]
    for bad_env in bad_envs:
        env = {"DJANGO_SECRET_KEY": "k" * 60, "TURN_SHARED_SECRET": secret, **bad_env}
        result = load_settings(env, TURN_PRINT)

        assert result.returncode != 0, bad_env
        assert "ImproperlyConfigured" in result.stderr
        assert secret not in result.stderr
    assert "not-a-real-password" not in result.stdout + result.stderr


def test_refuses_database_without_password_in_production() -> None:
    result = load_settings({"DJANGO_SECRET_KEY": "k" * 60, "POSTGRES_HOST": "127.0.0.1"})

    assert result.returncode != 0
    assert "POSTGRES_PASSWORD must be set" in result.stderr


TRUSTED_PROXY_PRINT = "import config.settings as s; print(s.TRUSTED_PROXY_IPS)"


def test_no_proxy_is_trusted_by_default() -> None:
    result = load_settings({"DJANGO_SECRET_KEY": "k" * 60}, TRUSTED_PROXY_PRINT)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[]"


def test_trusted_proxy_ips_come_from_environment() -> None:
    env = {"DJANGO_SECRET_KEY": "k" * 60, "TRUSTED_PROXY_IPS": "192.168.1.10, fd00::1"}
    result = load_settings(env, TRUSTED_PROXY_PRINT)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "['192.168.1.10', 'fd00::1']"


def test_bad_trusted_proxy_ips_stop_startup_without_echoing_the_value() -> None:
    for bad_value in ("proxy.example", "192.168.1.0/24", "192.168.1.10;evil"):
        env = {"DJANGO_SECRET_KEY": "k" * 60, "TRUSTED_PROXY_IPS": bad_value}
        result = load_settings(env, TRUSTED_PROXY_PRINT)

        assert result.returncode != 0, bad_value
        assert "TRUSTED_PROXY_IPS must be" in result.stderr
        assert bad_value not in result.stderr


def test_turn_ttl_cap_matches_the_room_lifetime_limit() -> None:
    # An override can make credentials shorter, never longer than a room can live.
    result = load_settings(
        {"DJANGO_SECRET_KEY": "k" * 60, "TURN_CREDENTIAL_TTL_SECONDS": "14400"},
        "import config.settings as s; "
        "print(s.MAX_TURN_CREDENTIAL_TTL_SECONDS, s.TURN_CREDENTIAL_TTL_SECONDS)",
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == [str(TOTAL_LIFETIME_LIMIT_SECONDS)] * 2


LOG_LINE_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z (DEBUG|INFO|WARNING|ERROR|CRITICAL) [\w.]+ .+$"
)


def format_log_record(logger_name: str, level: int, message: str) -> str:
    record = logging.LogRecord(logger_name, level, __file__, 1, message, None, None)
    record.created = 0.0  # the Unix epoch, to prove the time is UTC
    return build_utc_log_formatter().format(record)


def test_log_line_has_utc_time_level_and_logger_name() -> None:
    line = format_log_record("signaling.consumers", logging.WARNING, "TURN credential not issued")

    assert LOG_LINE_PATTERN.match(line)
    assert line == "1970-01-01T00:00:00Z WARNING signaling.consumers TURN credential not issued"


def test_console_handler_uses_the_utc_formatter() -> None:
    assert LOGGING["handlers"]["console"]["formatter"] == "utc_line"
    assert LOGGING["formatters"]["utc_line"]["()"] is build_utc_log_formatter


def test_log_line_format_only_allows_time_level_logger_and_message() -> None:
    assert set(re.findall(r"%\((\w+)\)", LOG_LINE_FORMAT)) == {
        "asctime",
        "levelname",
        "name",
        "message",
    }


def test_formatter_adds_no_address_or_room_id_of_its_own() -> None:
    line = format_log_record("signaling.consumers", logging.ERROR, "join rejected")

    text_after_time = line.split(" ", 1)[1]
    assert text_after_time == "ERROR signaling.consumers join rejected"
    assert not re.search(r"\d{1,3}(\.\d{1,3}){3}|[0-9a-f]{1,4}:[0-9a-f]{1,4}:", text_after_time)
