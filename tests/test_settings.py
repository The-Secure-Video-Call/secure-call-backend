"""Production defaults must be safe: these run the real settings module in a clean process."""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_settings(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    clean_env = {k: v for k, v in os.environ.items() if not k.startswith(("DJANGO_", "SIGNALING_"))}
    code = (
        "import config.settings as s; "
        "print(s.DEBUG, s.SECURE_SSL_REDIRECT, s.SECURE_HSTS_SECONDS, s.SIGNALING_ALLOWED_ORIGINS)"
    )
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
