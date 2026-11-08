"""Settings for the test suite and type checking: production settings plus test-only values.

Values are set as environment defaults before importing the real settings, so tests exercise
the same code path as production.
"""

import os

os.environ.setdefault("DJANGO_SECRET_KEY", "test-only-secret-key-" + "x" * 50)
os.environ.setdefault("DJANGO_ALLOWED_HOSTS", "testserver,localhost")
os.environ.setdefault("SIGNALING_ALLOWED_ORIGINS", "http://localhost:5173")
os.environ.setdefault("DJANGO_SECURE_SSL_REDIRECT", "0")

from config.settings import *  # noqa: F403
