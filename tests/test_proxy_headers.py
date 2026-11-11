"""The reverse proxy adds the backend's security headers to the responses it makes itself
(deploy/raspberry-pi/npm-advanced.conf, #61). Those values must be exactly what the backend sends,
so the two never drift apart; and the proxy lines must keep refusing plain HTTP (#56)."""

import re
from pathlib import Path

import pytest
from django.test import Client

ADVANCED_CONF = Path(__file__).resolve().parent.parent / "deploy/raspberry-pi/npm-advanced.conf"
ADD_HEADER = re.compile(r'^add_header ([A-Za-z-]+) "([^"]*)" always;$')


def proxy_headers(conf_text: str) -> dict[str, str]:
    """The `add_header NAME "value" always;` lines, by lower-case name; any other form fails."""
    headers: dict[str, str] = {}
    for line in conf_text.splitlines():
        if not line.startswith("add_header"):
            continue
        match = ADD_HEADER.match(line)
        assert match is not None, f'not of the form add_header NAME "value" always;: {line}'
        assert match.group(1).lower() not in headers, f"added twice: {match.group(1)}"
        headers[match.group(1).lower()] = match.group(2)
    return headers


def mismatches(proxy: dict[str, str], backend: dict[str, str]) -> list[str]:
    return sorted(
        name for name in proxy.keys() | backend.keys() if proxy.get(name) != backend.get(name)
    )


@pytest.fixture
def backend_security_headers(client: Client) -> dict[str, str]:
    """What the backend sends on /healthz over HTTPS, without the headers any response has."""
    response = client.get("/healthz", secure=True)
    assert response.status_code == 200
    ordinary = {"content-type", "content-length", "vary", "x-served-by"}
    return {
        name.lower(): value
        for name, value in response.headers.items()
        if name.lower() not in ordinary
    }


def test_proxy_adds_exactly_the_backends_security_headers(
    backend_security_headers: dict[str, str],
) -> None:
    proxy = proxy_headers(ADVANCED_CONF.read_text())

    assert len(proxy) == 8
    assert mismatches(proxy, backend_security_headers) == []


def test_negative_a_changed_or_missing_header_is_caught(
    backend_security_headers: dict[str, str],
) -> None:
    changed = ADVANCED_CONF.read_text().replace(
        'add_header X-Frame-Options "DENY" always;',
        'add_header X-Frame-Options "SAMEORIGIN" always;',
    )
    missing_csp = "\n".join(
        line
        for line in ADVANCED_CONF.read_text().splitlines()
        if not line.startswith("add_header Content-Security-Policy")
    )

    assert mismatches(proxy_headers(changed), backend_security_headers) == ["x-frame-options"]
    assert mismatches(proxy_headers(missing_csp), backend_security_headers) == [
        "content-security-policy"
    ]
    with pytest.raises(AssertionError, match="not of the form"):
        proxy_headers('add_header X-Frame-Options "DENY";')  # without "always"


def test_proxy_refuses_plain_http_except_the_acme_challenge_and_hides_nothing() -> None:
    conf = ADVANCED_CONF.read_text()
    directives = [line.strip() for line in conf.splitlines() if not line.lstrip().startswith("#")]

    assert 'if ($scheme = "http") {' in directives
    # The normalised path, which nginx picks the location by: a dot-segment cannot get past it.
    assert 'if ($uri ~ "^/\\.well-known/acme-challenge/") {' in directives
    assert not any("$request_uri" in line for line in directives)
    # The proxy's own 502 and 504 carry the headers too.
    assert "error_page 502 @proxy_502;" in directives
    assert "error_page 504 @proxy_504;" in directives
    assert "return 400;" in directives
    assert not any(line.startswith("return 301") for line in directives)
    # Hiding the backend's copies would strip them from proxied responses (see the file).
    assert not any(line.startswith("proxy_hide_header") for line in directives)
