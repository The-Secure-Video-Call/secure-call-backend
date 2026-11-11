# Signaling server image. Built for the Raspberry Pi (arm64) and amd64 by
# .github/workflows/publish-image.yml and published to ghcr.io.

# uv as its own pinned stage, so Dependabot (which reads FROM lines) can update it.
FROM ghcr.io/astral-sh/uv:0.13.7@sha256:96f40d3904aad8d0bd010539001d36c8e2188b981e1334471a90c4a1d93bb490 AS uv

# --- Build stage: install the locked dependencies into /app/.venv with uv --------------------
FROM python:3.14-slim@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f AS build
COPY --from=uv /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /app
COPY pyproject.toml uv.lock .python-version ./
RUN uv sync --locked --no-dev --no-install-project
COPY manage.py ./
COPY config ./config
COPY signaling ./signaling

# --- Runtime stage: same Python, no build tools, non-root user --------------------------------
FROM python:3.14-slim@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f
# Security fix not yet in the pinned base image: zlib1g from Debian's trixie-security (DSA-6613-1:
# CVE-2026-85091, CVE-2026-76844; the base has 1:1.3.dfsg+really1.3.1-1+b1). The exact version is
# pinned, so the build stays reproducible and fails loudly if Debian replaces it; apt checks the
# archive's signature. Remove this block once Dependabot bumps the base to a rebuild that contains
# the fix (test-image's Trivy scan fails while a fixable HIGH/CRITICAL package is left).
ARG ZLIB1G_FIXED_VERSION=1:1.3.dfsg+really1.3.1-1+deb13u1
RUN apt-get update \
    && apt-get install --yes --no-install-recommends --only-upgrade "zlib1g=${ZLIB1G_FIXED_VERSION}" \
    && dpkg-query --showformat='${Version}' --show zlib1g | grep -qxF "${ZLIB1G_FIXED_VERSION}" \
    && rm -rf /var/lib/apt/lists/*
# No pip at run time: the app's packages come from uv.lock at build time (/app/.venv), and the
# base image's pip carries its own copies of urllib3, msgpack and setuptools code that the image
# scan flags (and that nothing here uses). The bundled wheel for re-creating pip goes too.
RUN python -m pip uninstall --yes --root-user-action=ignore pip \
    && rm -rf /usr/local/lib/python3.14/ensurepip/_bundled \
    && ! python -c "import pip" 2>/dev/null
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app
WORKDIR /app
COPY --from=build /app /app
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    DJANGO_SETTINGS_MODULE=config.settings
USER app
EXPOSE 8000
# Apply database migrations when a database is configured, then serve. Daphne runs with
# -v 0 so its access log (which records visitor IP addresses) is off. A WebSocket ping goes out
# every 10 s and a client that has not answered 20 s later is dropped (worst case about 30 s),
# which runs the consumer's disconnect so the peer gets peer-left and the seat is freed.
# --websocket_timeout caps a socket's total lifetime at 14700 s (4 h room limit + 5 min);
# Daphne's default is 24 h. The consumer also closes a socket that is out of a room for 10 s.
CMD ["sh", "-c", "if [ -n \"${POSTGRES_HOST:-}\" ]; then python manage.py migrate --noinput; fi; exec daphne -v 0 --ping-interval 10 --ping-timeout 20 --websocket_timeout 14700 -b 0.0.0.0 -p 8000 config.asgi:application"]
