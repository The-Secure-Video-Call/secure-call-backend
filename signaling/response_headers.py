"""Middleware that adds the browser-hardening headers Django has no setting for.

The server serves no HTML, only the WebSocket and /healthz, so the policies are as strict as
they can be. HSTS, nosniff, Referrer-Policy, COOP and X-Frame-Options stay with Django's own
settings in config/settings.py.
"""

from collections.abc import Callable

from django.http import HttpRequest, HttpResponseBase

RESPONSE_HEADERS: dict[str, str] = {
    "Content-Security-Policy": (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    ),
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), display-capture=()",
    "Cross-Origin-Resource-Policy": "same-origin",
}


class ResponseHeadersMiddleware:
    """Sets RESPONSE_HEADERS on every HTTP response, overwriting any other value.

    It is the first entry in MIDDLEWARE, so it also wraps the redirects of SecurityMiddleware
    and the error responses Django builds from exceptions (404, 405, 400 for a disallowed host).
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponseBase]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponseBase:
        response = self.get_response(request)
        for header_name, header_value in RESPONSE_HEADERS.items():
            response.headers[header_name] = header_value
        return response
