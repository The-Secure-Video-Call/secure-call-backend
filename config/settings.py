"""Django settings for the Secure Call signaling server.

Everything environment-specific comes from environment variables, and the defaults are the
safe production values: DEBUG is off and the server refuses to start without a secret key.
For local development, set DJANGO_DEBUG=1 (see README.md).

Signaling stores nothing. A PostgreSQL database can be connected (POSTGRES_* variables) for
future user accounts only; it must never hold call data such as room IDs, call times, IP
addresses or message contents.
"""

import ipaddress
import logging
import os
import time
from pathlib import Path
from typing import Any

from django.core.exceptions import ImproperlyConfigured
from django.core.management.utils import get_random_secret_key

BASE_DIR = Path(__file__).resolve().parent.parent


def env_bool(name: str, *, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_list(name: str, *, default: list[str]) -> list[str]:
    value = os.environ.get(name)
    if value is None:
        return default
    return [item.strip() for item in value.split(",") if item.strip()]


DEBUG = env_bool("DJANGO_DEBUG")

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "")
if not SECRET_KEY:
    if not DEBUG:
        raise ImproperlyConfigured("DJANGO_SECRET_KEY must be set when DJANGO_DEBUG is off.")
    # Development only: a throwaway key per process.
    SECRET_KEY = get_random_secret_key()

ALLOWED_HOSTS = env_list(
    "DJANGO_ALLOWED_HOSTS", default=["localhost", "127.0.0.1"] if DEBUG else []
)

INSTALLED_APPS = [
    "daphne",  # must come first: provides the ASGI `runserver`
    "channels",
    "signaling",
]

MIDDLEWARE = [
    # First, so it also covers the responses of the middleware below.
    "signaling.response_headers.ResponseHeadersMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
ASGI_APPLICATION = "config.asgi.application"
TEMPLATES: list[dict[str, object]] = []

# --- Database --------------------------------------------------------------------------------

# Optional PostgreSQL, for future user accounts only (see the module docstring). Without
# POSTGRES_HOST there is no database at all. The database must only be reachable from the
# backend's own machine or private network: never expose port 5432 to the internet.
POSTGRES_HOST = os.environ.get("POSTGRES_HOST", "")
# TLS with the server's certificate and host name checked against a pinned root certificate,
# or, only when asked for explicitly and only for a database on this machine (or with DEBUG
# on), no TLS at all: a local development database. The modes
# in between ("prefer", "allow", "require", "verify-ca") either fall back to plaintext silently
# or accept any certificate, so they are refused.
POSTGRES_SSLMODES_ALLOWED = ("verify-full", "disable")
POSTGRES_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")
DATABASES: dict[str, dict[str, object]] = {}
if POSTGRES_HOST:
    POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "")
    if not POSTGRES_PASSWORD and not DEBUG:
        raise ImproperlyConfigured("POSTGRES_PASSWORD must be set when POSTGRES_HOST is set.")
    POSTGRES_SSLMODE = os.environ.get("POSTGRES_SSLMODE", "verify-full")
    if POSTGRES_SSLMODE not in POSTGRES_SSLMODES_ALLOWED:
        raise ImproperlyConfigured(
            "POSTGRES_SSLMODE must be verify-full (the default) or, for a local development "
            "database only, disable."
        )
    if (
        POSTGRES_SSLMODE == "disable"
        and not DEBUG
        and POSTGRES_HOST not in POSTGRES_LOCAL_HOSTS
        and not POSTGRES_HOST.startswith("/")  # a Unix socket directory
    ):
        raise ImproperlyConfigured(
            "POSTGRES_SSLMODE=disable is only allowed for a database on this machine "
            "(localhost, 127.0.0.1, ::1 or a socket directory) or with DJANGO_DEBUG on."
        )
    POSTGRES_OPTIONS: dict[str, object] = {"sslmode": POSTGRES_SSLMODE, "connect_timeout": 5}
    if POSTGRES_SSLMODE == "verify-full":
        POSTGRES_SSLROOTCERT = os.environ.get("POSTGRES_SSLROOTCERT", "")
        if not POSTGRES_SSLROOTCERT or not Path(POSTGRES_SSLROOTCERT).is_file():
            raise ImproperlyConfigured(
                "POSTGRES_SSLROOTCERT must name the root certificate file that signed the "
                "database's certificate (deploy/raspberry-pi/tls/local-ca.crt on the Pi)."
            )
        POSTGRES_OPTIONS["sslrootcert"] = POSTGRES_SSLROOTCERT
    DATABASES["default"] = {
        "ENGINE": "django.db.backends.postgresql",
        "HOST": POSTGRES_HOST,
        "PORT": os.environ.get("POSTGRES_PORT", "5432"),
        "NAME": os.environ.get("POSTGRES_DB", "securecall"),
        "USER": os.environ.get("POSTGRES_USER", "securecall"),
        "PASSWORD": POSTGRES_PASSWORD,
        # ASGI: no persistent connections (Django's advice); add pooling with real traffic.
        "CONN_MAX_AGE": 0,
        "OPTIONS": POSTGRES_OPTIONS,
    }

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = False
USE_TZ = True

# Channel layer: in-memory for development and tests (single process only); Redis when
# REDIS_URL is set, so several server processes can share rooms.
REDIS_URL = os.environ.get("REDIS_URL", "")
CHANNEL_LAYERS: dict[str, dict[str, object]] = (
    {
        "default": {
            "BACKEND": "channels_redis.core.RedisChannelLayer",
            "CONFIG": {"hosts": [REDIS_URL]},
        }
    }
    if REDIS_URL
    else {"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}}
)

# --- Signaling -------------------------------------------------------------------------------

# Browser origins allowed to open a WebSocket, e.g. "https://call.example.com". Every other
# origin is rejected before the consumer runs. The Vite dev server is allowed in DEBUG.
SIGNALING_ALLOWED_ORIGINS = env_list(
    "SIGNALING_ALLOWED_ORIGINS", default=["http://localhost:5173"] if DEBUG else []
)
# Largest accepted WebSocket message, in bytes (PLAN.md section 3.5).
SIGNALING_MAX_MESSAGE_BYTES = 64 * 1024
# IPs of the reverse proxy (Nginx Proxy Manager's LAN IP). Only from these peers is
# X-Forwarded-For believed, to find the client IP for rate limits (signaling/client_address.py).
# Empty by default: then the header is ignored. Plain IP addresses, no ranges.
TRUSTED_PROXY_IPS = env_list("TRUSTED_PROXY_IPS", default=[])
for _trusted_proxy_ip in TRUSTED_PROXY_IPS:
    try:
        ipaddress.ip_address(_trusted_proxy_ip)
    except ValueError:
        raise ImproperlyConfigured(
            "TRUSTED_PROXY_IPS must be comma-separated IP addresses."
        ) from None

# --- TURN credentials ------------------------------------------------------------------------

# Short-lived HMAC credentials for coturn (PLAN.md 3.5). The feature is off unless BOTH
# TURN_SHARED_SECRET and TURN_URLS are set; then `joined` has no `turn` field. The secret
# comes from the environment only and is never logged or sent to clients.
TURN_SHARED_SECRET = os.environ.get("TURN_SHARED_SECRET", "")
TURN_URLS = env_list("TURN_URLS", default=[])
# Never longer than a room can live (signaling.rooms.TOTAL_LIFETIME_LIMIT_SECONDS, 4 h); the
# consumer also shortens each credential to the time its room has left. tests/test_settings.py
# keeps the values equal (this module cannot import signaling.rooms, which imports Channels).
MAX_TURN_CREDENTIAL_TTL_SECONDS = 4 * 60 * 60
# Default: as long as a room can live (signaling.rooms.TOTAL_LIFETIME_LIMIT_SECONDS, 4 h), so a
# credential never expires mid-call. coturn renews an existing allocation after expiry, but a
# new allocation (an ICE restart after a network change) needs a valid credential, and in
# privacy mode the relay is the only path. tests/test_settings.py keeps the two values equal.
DEFAULT_TURN_CREDENTIAL_TTL_SECONDS = 4 * 60 * 60
try:
    TURN_CREDENTIAL_TTL_SECONDS = int(
        os.environ.get("TURN_CREDENTIAL_TTL_SECONDS", str(DEFAULT_TURN_CREDENTIAL_TTL_SECONDS))
    )
except ValueError:
    raise ImproperlyConfigured("TURN_CREDENTIAL_TTL_SECONDS must be a whole number.") from None
if not 1 <= TURN_CREDENTIAL_TTL_SECONDS <= MAX_TURN_CREDENTIAL_TTL_SECONDS:
    raise ImproperlyConfigured(
        f"TURN_CREDENTIAL_TTL_SECONDS must be between 1 and {MAX_TURN_CREDENTIAL_TTL_SECONDS}."
    )
if TURN_URLS and not (
    len(TURN_URLS) <= 4 and all(url.startswith(("turn:", "turns:")) for url in TURN_URLS)
):
    # Fail at startup instead of on the first join. The message never includes the values.
    raise ImproperlyConfigured("TURN_URLS needs 1-4 URLs, each starting with turn: or turns:.")

# --- Security headers and HTTPS (production) -------------------------------------------------

# TLS is terminated by the reverse proxy (Caddy), which must set X-Forwarded-Proto itself and
# never pass a client-supplied value through.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = env_bool("DJANGO_SECURE_SSL_REDIRECT", default=not DEBUG)
SECURE_REDIRECT_EXEMPT = [r"^healthz$"]  # internal health checks use plain HTTP
SECURE_HSTS_SECONDS = 0 if DEBUG else 31_536_000
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
SECURE_REFERRER_POLICY = "no-referrer"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
X_FRAME_OPTIONS = "DENY"

SILENCED_SYSTEM_CHECKS = [
    # HSTS preload is a commitment to the browser preload list; decide once the domain is final.
    "security.W021",
]

LOG_LINE_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"
LOG_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def build_utc_log_formatter() -> logging.Formatter:
    """Log lines carry an ISO 8601 UTC time, the level and the logger name, and nothing else."""
    utc_formatter = logging.Formatter(LOG_LINE_FORMAT, datefmt=LOG_TIME_FORMAT)
    utc_formatter.converter = time.gmtime
    return utc_formatter


LOGGING: dict[str, Any] = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"utc_line": {"()": build_utc_log_formatter}},
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "utc_line"}},
    # Default to warnings only: never log message payloads, room IDs or IP addresses.
    "root": {"handlers": ["console"], "level": os.environ.get("DJANGO_LOG_LEVEL", "WARNING")},
}
