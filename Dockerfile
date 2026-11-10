# syntax=docker/dockerfile:1
# Signaling server image. Built for the Raspberry Pi (arm64) and amd64 by
# .github/workflows/publish-image.yml and published to ghcr.io.

# --- Build stage: install the locked dependencies into /app/.venv with uv --------------------
FROM python:3.14-slim@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f AS build
COPY --from=ghcr.io/astral-sh/uv:0.12.13@sha256:b485bd65cc2cf1c9a93b3554012c9c3778cf7b1b5fd3d3096ce9e1226c97e1e6 /uv /bin/uv
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
CMD ["sh", "-c", "if [ -n \"${POSTGRES_HOST:-}\" ]; then python manage.py migrate --noinput; fi; exec daphne -v 0 --ping-interval 10 --ping-timeout 20 -b 0.0.0.0 -p 8000 config.asgi:application"]
