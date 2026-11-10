# Secure Call — backend

The signaling server for [Secure Call](https://github.com/The-Secure-Video-Call/secure-call), a
secure 1-to-1 video calling web app. Browsers use it only to find each other: it relays
end-to-end encrypted connection messages it cannot read, and never sees audio or video.
The architecture and security design are in the web app's
[PLAN.md](https://github.com/The-Secure-Video-Call/secure-call/blob/main/PLAN.md).

> Status: M0 (repository and tooling). The WebSocket endpoint validates messages and answers
> `ping`; rooms and relaying arrive in M1.

## Stack

Python 3.14 · Django 6.1 · Channels 4.3 + Daphne (WebSockets) · Pydantic 2 (message validation) ·
uv · ruff · mypy · pytest. Optional PostgreSQL 18 (psycopg 3), reserved for future user accounts:
signaling itself stores nothing.

## Run locally

Requirements: [uv](https://docs.astral.sh/uv/) (it installs Python 3.14 for you).

```sh
uv sync
DJANGO_DEBUG=1 uv run daphne -b 127.0.0.1 -p 8000 config.asgi:application
```

- `http://127.0.0.1:8000/healthz` returns `{"status": "ok"}`.
- `ws://127.0.0.1:8000/ws/signal/` accepts connections from the Vite dev server
  (`http://localhost:5173`). Send `{"v":1,"type":"ping"}` to get a `pong`.

## Checks (the same ones CI runs)

```sh
uv run ruff check
uv run ruff format --check
uv run mypy .
uv run pytest
uv run pip-audit
```

## Configuration

All settings come from environment variables. Defaults are safe for production: DEBUG is off and
the server refuses to start without a secret key.

| Variable | Meaning |
|---|---|
| `DJANGO_SECRET_KEY` | Required in production. Long random string. |
| `DJANGO_DEBUG` | `1` for local development only. |
| `DJANGO_ALLOWED_HOSTS` | Comma-separated host names this server answers to. |
| `SIGNALING_ALLOWED_ORIGINS` | Comma-separated browser origins allowed to open a WebSocket, e.g. `https://call.example.com`. Empty means none. |
| `TRUSTED_PROXY_IPS` | Comma-separated IPs of the reverse proxy (for the Pi: the Nginx Proxy Manager machine's LAN IP). Only from these peers is the rightmost `X-Forwarded-For` entry used as the client IP for rate limits; from anyone else the header is ignored. Empty (default) means no proxy is trusted, and behind a proxy all visitors then share one limit. The proxy must append to `X-Forwarded-For` (Nginx's default) or overwrite it; a CDN in front of the proxy would make the CDN the "client". IPv6 clients are counted per /64. |
| `REDIS_URL` | Optional. Use Redis for the channel layer so several server processes can share rooms. |
| `POSTGRES_HOST` | Optional. Set it to connect PostgreSQL; leave it unset for no database. |
| `POSTGRES_PORT`, `POSTGRES_DB`, `POSTGRES_USER` | Default `5432`, `securecall`, `securecall`. |
| `POSTGRES_PASSWORD` | Required when `POSTGRES_HOST` is set (outside DEBUG). |
| `POSTGRES_SSLMODE` | Default `prefer`. Use `require` if the database is on another machine. |
| `DJANGO_SECURE_SSL_REDIRECT` | Defaults to on in production. TLS is terminated by the reverse proxy. |
| `DJANGO_LOG_LEVEL` | Defaults to `WARNING`. |

Rate limits (in memory only, keyed by an HMAC of the client IP; constants in `signaling/rate_limits.py`):
20 joins per IP per minute, 120 TURN credentials per IP per hour (over it, `joined` has no `turn`),
and per connection a burst of 100 messages refilled at 20 per second. Over a join or message
limit the server sends `error rate-limited` and closes with application code `4029`.

In production, run Daphne with `-v 0` so its access log (which contains client IP addresses) is
off.

## Database (PostgreSQL)

The database is connected now but holds nothing yet. It is reserved for future user accounts and
must never store call data: no room IDs, call times, IP addresses or message contents.

The database runs next to the backend on the Raspberry Pi (see below). For database tools it is
published on `127.0.0.1:5434` by default (`POSTGRES_PUBLISH_ADDR` and `POSTGRES_PUBLISH_PORT` in
`.env`); never forward that port on your router. CI starts a throwaway PostgreSQL for every run, so the connection is tested on each PR.

## Deploying to the Raspberry Pi

```
Browser --wss://signal.securevideocall.com--> router :443 --> Nginx Proxy Manager
        --> Pi :8001 (secure-call-backend container) --> PostgreSQL container
```

**How updates arrive:** every merge to `main` runs **Publish backend image**
(`.github/workflows/publish-image.yml`). After approval in the repo's **production**
environment, it builds the image for arm64 (the Pi) and amd64 and publishes it as
`ghcr.io/the-secure-video-call/secure-call-backend:main`. On the Pi, `update.sh` (run by cron)
pulls a new image and restarts the backend. GitHub never connects to the Pi.

### One-time setup on the Pi

Requirements: 64-bit OS, Docker with the Compose plugin, Nginx Proxy Manager already running.

1. **DNS:** in ServerByt's DNS editor, point `signal.securevideocall.com` (A record) at your
   home's static IP.
2. **Router:** forward TCP 80 and 443 to the Pi (Nginx Proxy Manager). Never forward 81 (its
   admin page) or 5432 (the database).
3. **Get the files and fill in the settings:**
   ```sh
   git clone https://github.com/The-Secure-Video-Call/secure-call-backend.git
   cd secure-call-backend/deploy/raspberry-pi
   cp .env.example .env        # set BACKEND_PUBLISH_ADDR, DJANGO_SECRET_KEY, POSTGRES_PASSWORD
   docker compose up -d
   ```
4. **Nginx Proxy Manager, Add Proxy Host:** domain `signal.securevideocall.com`; scheme `http`,
   forward hostname `127.0.0.1` (proxy on this Pi) or this Pi's home-network IP (proxy on another
   machine), port `8001`; **Websockets Support** and **Block
   Common Exploits** on. SSL tab: request a Let's Encrypt certificate; **Force SSL**, **HTTP/2**
   and **HSTS** on.
5. **Automatic updates:** `crontab -e`, then add (with your path):
   ```
   */5 * * * * /home/pi/secure-call-backend/deploy/raspberry-pi/update.sh >/dev/null 2>&1
   ```
6. **Check:** `curl https://signal.securevideocall.com/healthz` returns `{"status": "ok"}`.

To look inside the database from the Pi: `docker compose exec postgres psql -U securecall
securecall`, or point a database tool at port `5434`.

## Protocol contract

`signaling/protocol.py` (Pydantic) is the source of truth for the message format. It is exported
as JSON Schema to `protocol/schema/`, and `protocol/fixtures/` holds valid and invalid example
messages. The web client tests its own schemas against the same fixtures. After changing the
models, run `uv run python -m signaling.export_schema`; a test fails if the schema files are out
of date.

## License

Copyright (C) 2026 Usman Khan and contributors.

This program is free software: you can redistribute it and/or modify it under the terms of the
GNU Affero General Public License, version 3 only, as published by the Free Software Foundation.
See [LICENSE](LICENSE) for the full text.

If you run a modified version of this software as a network service, the AGPL requires you to
offer the source code of your modified version to its users.
