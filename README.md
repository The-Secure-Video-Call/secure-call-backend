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
uv · ruff · mypy · pytest. No database: the server stores nothing.

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
| `REDIS_URL` | Optional. Use Redis for the channel layer so several server processes can share rooms. |
| `DJANGO_SECURE_SSL_REDIRECT` | Defaults to on in production. TLS is terminated by the reverse proxy. |
| `DJANGO_LOG_LEVEL` | Defaults to `WARNING`. |

In production, run Daphne with `-v 0` so its access log (which contains client IP addresses) is
off.

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
