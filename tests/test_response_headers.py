import os
import subprocess
import sys

import pytest
from django.test import Client

from signaling.response_headers import RESPONSE_HEADERS

EXPECTED_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    ),
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), display-capture=()",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def assert_has_all_headers(response_headers: dict[str, str]) -> None:
    for header, value in EXPECTED_HEADERS.items():
        assert response_headers[header] == value


def test_header_table_matches_the_agreed_values() -> None:
    assert RESPONSE_HEADERS == EXPECTED_HEADERS


@pytest.mark.parametrize(("header", "value"), list(EXPECTED_HEADERS.items()))
@pytest.mark.parametrize("path", ["/healthz", "/does-not-exist"])
def test_header_has_exact_value_on_healthz_and_404(
    client: Client, path: str, header: str, value: str
) -> None:
    response = client.get(path)

    assert response.headers[header] == value


def test_headers_are_on_a_405(client: Client) -> None:
    response = client.post("/healthz")

    assert response.status_code == 405
    assert_has_all_headers(dict(response.headers))


def test_headers_are_on_a_400_for_a_disallowed_host(client: Client) -> None:
    response = client.get("/healthz", headers={"Host": "evil.invalid"})

    assert response.status_code == 400
    assert_has_all_headers(dict(response.headers))


def test_headers_are_on_the_https_redirect(settings: object) -> None:
    settings.SECURE_SSL_REDIRECT = True  # type: ignore[attr-defined]

    response = Client().get("/does-not-exist")

    assert response.status_code == 301
    assert_has_all_headers(dict(response.headers))


def test_hsts_appears_exactly_once(client: Client) -> None:
    response = client.get("/healthz", secure=True)

    assert response.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"
    header_names = [name.lower() for name in response.headers]
    assert header_names.count("strict-transport-security") == 1


def test_check_deploy_still_passes() -> None:
    production_like_environment = {
        **os.environ,
        "DJANGO_SETTINGS_MODULE": "config.settings",
        "DJANGO_SECRET_KEY": "check-deploy-only-" + "k7Zp9" * 12,
        "DJANGO_ALLOWED_HOSTS": "signal.example.invalid",
        "SIGNALING_ALLOWED_ORIGINS": "https://call.example.invalid",
    }
    for test_only_variable in ("DJANGO_DEBUG", "DJANGO_SECURE_SSL_REDIRECT"):
        production_like_environment.pop(test_only_variable, None)

    result = subprocess.run(
        [sys.executable, "manage.py", "check", "--deploy", "--fail-level", "WARNING"],
        capture_output=True,
        text=True,
        check=False,
        env=production_like_environment,
    )

    assert result.returncode == 0, result.stderr
