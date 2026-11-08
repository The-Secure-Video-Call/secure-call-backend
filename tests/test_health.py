import pytest
from django.test import Client


def test_healthz_returns_ok(client: Client) -> None:
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.parametrize(
    ("header", "value"),
    [
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("X-Content-Type-Options", "nosniff"),
        ("Cross-Origin-Opener-Policy", "same-origin"),
    ],
)
def test_healthz_sends_security_headers(client: Client, header: str, value: str) -> None:
    response = client.get("/healthz")

    assert response.headers[header] == value


def test_healthz_rejects_post(client: Client) -> None:
    response = client.post("/healthz")

    assert response.status_code == 405


def test_unknown_path_is_404(client: Client) -> None:
    assert client.get("/admin/").status_code == 404
