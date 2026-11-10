"""Django settings for the Secure Call signaling server.

Everything environment-specific comes from environment variables, and the defaults are the
safe production values: DEBUG is off and the server refuses to start without a secret key.
For local development, set DJANGO_DEBUG=1 (see README.md).

Signaling stores nothing. A PostgreSQL database can be connected (POSTGRES_* variables) for
future user accounts only; it must never hold call data such as room IDs, call times, IP
addresses or message contents.
"""

import os
from pathlib import Path

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
DATABASES: dict[str, dict[str, object]] = {}
if POSTGRES_HOST:
    POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "")
    if not POSTGRES_PASSWORD and not DEBUG:
        raise ImproperlyConfigured("POSTGRES_PASSWORD must be set when POSTGRES_HOST is set.")
    DATABASES["default"] = {
        "ENGINE": "django.db.backends.postgresql",
        "HOST": POSTGRES_HOST,
        "PORT": os.environ.get("POSTGRES_PORT", "5432"),
        "NAME": os.environ.get("POSTGRES_DB", "securecall"),
        "USER": os.environ.get("POSTGRES_USER", "securecall"),
        "PASSWORD": POSTGRES_PASSWORD,
        # ASGI: no persistent connections (Django's advice); add pooling with real traffic.
        "CONN_MAX_AGE": 0,
        "OPTIONS": {
            "sslmode": os.environ.get("POSTGRES_SSLMODE", "prefer"),
            "connect_timeout": 5,
        },
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

# --- TURN credentials ------------------------------------------------------------------------

# Short-lived HMAC credentials for coturn (PLAN.md 3.5). The feature is off unless BOTH
# TURN_SHARED_SECRET and TURN_URLS are set; then `joined` has no `turn` field. The secret
# comes from the environment only and is never logged or sent to clients.
TURN_SHARED_SECRET = os.environ.get("TURN_SHARED_SECRET", "")
TURN_URLS = env_list("TURN_URLS", default=[])
MAX_TURN_CREDENTIAL_TTL_SECONDS = 24 * 3600  # "short-lived": never more than a day
try:
    TURN_CREDENTIAL_TTL_SECONDS = int(os.environ.get("TURN_CREDENTIAL_TTL_SECONDS", "3600"))
except ValueError:
    raise ImproperlyConfigured("TURN_CREDENTIAL_TTL_SECONDS must be a whole number.") from None
if not 1 <= TURN_CREDENTIAL_TTL_SECONDS <= MAX_TURN_CREDENTIAL_TTL_SECONDS:
    raise ImproperlyConfigured("TURN_CREDENTIAL_TTL_SECONDS must be between 1 and 86400.")
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

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    # Default to warnings only: never log message payloads, room IDs or IP addresses.
    "root": {"handlers": ["console"], "level": os.environ.get("DJANGO_LOG_LEVEL", "WARNING")},
}
