# Secure Call — backend

The signaling server for [Secure Call](https://github.com/The-Secure-Video-Call/secure-call), a
secure 1-to-1 video calling web app. Browsers use it only to find each other: it relays
end-to-end encrypted connection messages it cannot read, and never sees audio or video.
The architecture and security design are in the web app's
[PLAN.md](https://github.com/The-Secure-Video-Call/secure-call/blob/main/PLAN.md).

> Status: M0–M4 complete. The signaling server and coturn TURN relay run in production on a
> Raspberry Pi at `signal.securevideocall.com`.

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
python3 scripts/check_pinned_references.py
uv run ruff check
uv run ruff format --check
uv run mypy .
uv run pytest
uv run pip-audit --strict
```

Every GitHub Action is pinned to a full commit SHA and every container image to an `@sha256:`
digest, because a tag can be moved to other code. `scripts/check_pinned_references.py` fails CI
on anything else (our own images, built here or on the Pi, are the only exceptions). Dependabot
proposes the updates every week.

## Configuration

All settings come from environment variables. Defaults are safe for production: DEBUG is off and
the server refuses to start without a secret key.

| Variable | Meaning |
|---|---|
| `DJANGO_SECRET_KEY` | Required in production. Long random string. |
| `DJANGO_DEBUG` | `1` for local development only. |
| `DJANGO_ALLOWED_HOSTS` | Comma-separated host names this server answers to. |
| `SIGNALING_ALLOWED_ORIGINS` | Comma-separated browser origins allowed to open a WebSocket, e.g. `https://call.example.com`. Empty means none. |
| `TRUSTED_PROXY_IPS` | Comma-separated IPs of the reverse proxy (for the Pi: the Nginx Proxy Manager machine's LAN IP). Only from these peers is the rightmost `X-Forwarded-For` entry used as the client IP for rate limits; from anyone else the header is ignored. Empty (default) means no proxy is trusted, and behind a proxy all visitors then share one limit. The proxy must append to `X-Forwarded-For` (Nginx's default) or overwrite it; a CDN in front of the proxy would make the CDN the "client". IPv6 clients are counted per /64, /56 and /48, and 6to4, Teredo and NAT64 addresses as the IPv4 address inside them (see Rate limits). |
| `REDIS_URL` | Optional. Use Redis for the channel layer so several server processes can share rooms. |
| `POSTGRES_HOST` | Optional. Set it to connect PostgreSQL; leave it unset for no database. |
| `POSTGRES_PORT`, `POSTGRES_DB`, `POSTGRES_USER` | Default `5432`, `securecall`, `securecall`. |
| `POSTGRES_PASSWORD` | Required when `POSTGRES_HOST` is set (outside DEBUG). |
| `POSTGRES_SSLMODE` | Default `prefer`. Use `require` if the database is on another machine. |
| `DJANGO_SECURE_SSL_REDIRECT` | Defaults to on in production. TLS is terminated by the reverse proxy. |
| `DJANGO_LOG_LEVEL` | Defaults to `WARNING`. Every log line reads `<ISO 8601 UTC time>Z <LEVEL> <logger name> <message>`, e.g. `2026-11-10T20:42:01Z WARNING signaling.consumers TURN credential not issued`. The format adds no IP addresses, room IDs or message contents, and this server's own log calls never include them. At `INFO` or lower, Daphne and Django's own loggers may log addresses, so keep the default and run Daphne with `-v 0`. |

Rate limits (in memory only, keyed by an HMAC of the client address; constants in
`signaling/rate_limits.py`): 20 joins per client per minute, 120 TURN credentials per client per
hour (over it, `joined` has no `turn`; a credential lasts up to 4 h, so up to 480 per client can be
valid at once), and per connection a burst of 100 messages refilled at 20 per second. A client is
an IPv4 address or an IPv6 /64. Over a join or message limit the server sends `error rate-limited`
and closes with application code `4029`.

Open connections are capped at 20 per client and 500 in total (per process); over a cap the socket
is accepted, sent `error rate-limited` and closed with `4029`. A connection that sends no `join`
within 10 s is closed with `4008`; the same applies for 10 s after a `leave` (the client may
`join` again in that time). A socket's total lifetime is capped by Daphne's `--websocket_timeout`,
set in the `Dockerfile` to 14700 s (4 h room limit + 5 min; Daphne's default is 24 h), after which
it is closed. The cap counts from when the socket opened, not from when a room was joined, so a
client that leaves and joins a new room on the same socket can be closed (code `1000`) before that
room's own 4 h are up, and should reconnect.

IPv6 clients are also counted by their /56 and their /48, with 4 and 16 times the caps:

| Limit | Per /64 (or IPv4 address) | Per /56 | Per /48 |
|---|---|---|---|
| Joins per minute | 20 | 80 | 320 |
| TURN credentials per hour | 120 | 480 | 1,920 |
| Open connections | 20 | 80 | 320 |

One customer can hold 256 (/56) or 65,536 (/48) /64s, and many ISPs give each household a /56 or
a /60 out of a /48 shared by 256 or more households. So one /56 can use at most a quarter of its
/48, and one /64 a quarter of its /56. An action must pass all three; the server checks them all
before it charges any, so a refusal by one charges none. IPv4 is counted once, as before, and so
are 6to4, Teredo and NAT64 (`64:ff9b::/96`) addresses, as the IPv4 address inside them. The total
of 500 connections is unchanged.

What is still possible:
- 4 /64s use up their /56, and 4 /56s (16 /64s across them) use up their /48. A customer with a
  /60 can lock the other customers of its /56 out of joins (for a minute), TURN credentials (for
  an hour, so their privacy-mode calls fail closed) or connections (while it holds them); one with
  4 /56s can do the same to the rest of its /48. ISPs that put many customers' /64s in one /48
  (mobile carriers) share its caps among them.
- Someone with many /48s gets 16 times the caps for each: a tunnel broker gives out routed /48s
  for free, and an LIR's /29 holds 524,288 of them. Two /48s (320 connections each) fill all 500
  connection slots of a process; over IPv4 it takes 25 addresses.
- Evicting an entry resets its counters. It happens once 500 other /48s, 1,000 other /56s or
  10,000 other /64s (or IPv4 addresses) have been charged after the entry's last allowed event; a
  refused request does not count. They need not be the abuser's: a busy server evicts capped
  entries by itself, and someone with more prefixes than that can cycle them so that the tier no
  longer limits them (the finer tiers still do). Eviction only lowers counts and never locks
  anyone out.

The counters take at most about 115 MiB per process (the worst case is worked out in
`signaling/rate_limits.py`). **Deploy this before giving the backend an IPv6 address.**

In production, run Daphne with `-v 0` so its access log (which contains client IP addresses) is
off.

## Security headers

Every HTTP response (`/healthz`, errors and redirects included) carries:

| Header | Value | Set by |
|---|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` (once) | Django settings |
| `X-Content-Type-Options` | `nosniff` | Django settings |
| `Referrer-Policy` | `no-referrer` | Django settings |
| `Cross-Origin-Opener-Policy` | `same-origin` | Django settings |
| `X-Frame-Options` | `DENY` | Django settings |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` | `signaling/response_headers.py` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), display-capture=()` | `signaling/response_headers.py` |
| `Cross-Origin-Resource-Policy` | `same-origin` | `signaling/response_headers.py` |

Not covered: responses Daphne or the proxy produce before Django runs (for example a malformed
HTTP request) and the WebSocket handshake rejections from the Origin check. The `Server` header
comes from Nginx Proxy Manager, not from this app; hiding version details there (for example
`server_tokens off`) is the owner's setting.

Check the live headers with `curl -sI https://signal.securevideocall.com/healthz`.

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

**How updates arrive:** every pull request and every merge to `main` runs **Publish backend
image** (`.github/workflows/publish-image.yml`), which builds the image, smoke-tests it and scans
its Debian packages with Trivy: a HIGH or CRITICAL vulnerability that has a fix fails the run
(those Debian has no fixed package for yet are left out: no rebuild could remove them). On
`main`, after approval in the repo's **production** environment, it builds the image for arm64
(the Pi) and amd64 with an SBOM and BuildKit provenance in the image index, publishes it as
`ghcr.io/the-secure-video-call/secure-call-backend:main`, and signs a build provenance attestation
for its digest. On the Pi, `update.sh` verifies that attestation with `gh attestation verify` and
only then runs that exact digest and restarts the backend (see "Updating the backend" in
`deploy/raspberry-pi/README.md`). GitHub never connects to the Pi.

### One-time setup on the Pi

Requirements: 64-bit OS, Docker with the Compose and buildx plugins (both come with Docker's
own packages), gh 2.102.0 or newer (step 5), Nginx Proxy Manager already running.

1. **DNS:** in ServerByt's DNS editor, point `signal.securevideocall.com` (A record) at your
   home's static IP.
2. **Router:** forward TCP 80 and 443 to the machine that runs Nginx Proxy Manager, to the ports
   it publishes (for example 40080 and 40443 if its container maps them there). Never forward its
   admin port (81 inside the container) or 5432 (the database).
3. **Get the files and fill in the settings:**
   ```sh
   git clone https://github.com/The-Secure-Video-Call/secure-call-backend.git
   cd secure-call-backend/deploy/raspberry-pi
   cp .env.example .env        # set BACKEND_PUBLISH_ADDR, DJANGO_SECRET_KEY, POSTGRES_PASSWORD
   docker compose up -d postgres
   ./update.sh                 # after the gh setup in step 5: pulls only a verified backend image
   docker compose up -d
   ```
   Run `update.sh` before the first full `docker compose up -d`: compose would otherwise pull
   `:main` itself, without verifying it. Once `update.sh` has put the verified image there,
   compose uses it and pulls no backend image.
4. **Nginx Proxy Manager, Add Proxy Host:** domain `signal.securevideocall.com`; scheme `http`,
   forward hostname `127.0.0.1` (proxy on this Pi) or this Pi's home-network IP (proxy on another
   machine), port `8001`; **Websockets Support** and **Block
   Common Exploits** on. SSL tab: request a Let's Encrypt certificate; **Force SSL**, **HTTP/2**
   and **HSTS** on. **Advanced tab**, Custom Nginx Configuration:
   ```nginx
   access_log off;
   ```
   so the proxy keeps no record of who connected when (PLAN.md §3.5: no request logging of IP
   addresses; this app's own logs never contain them). The proxy still writes this host's error
   log (`/data/logs/proxy-host-<id>_error.log`), and a line there can name a client address when
   a connection fails. The Advanced tab cannot turn it off (another `error_log` only adds a
   destination). Either accept that (it holds failures only), or keep all of the proxy's logs in
   memory by adding `tmpfs: ["/data/logs:size=16m"]` to its service in its own compose file (this
   affects every host on that proxy, and the logs then vanish on restart).
5. **Updates:** install gh and give it a read-only token once (the one-time setup in
   `deploy/raspberry-pi/README.md`, "Updating the backend"), check with
   `deploy/raspberry-pi/update.sh --check`, then run `deploy/raspberry-pi/update.sh` whenever a new
   image is published. **Automatic updates** (optional): `crontab -e`, then add (with your path):
   ```
   */5 * * * * /home/pi/secure-call-backend/deploy/raspberry-pi/update.sh >/dev/null 2>&1
   ```
   This discards the output, so an image that fails verification is skipped silently (the
   backend keeps running the last verified one); drop `>/dev/null 2>&1` to get cron's mail.
6. **Check:** `curl https://signal.securevideocall.com/healthz` returns `{"status": "ok"}`.
   Then make a short call and, on the proxy machine, check that this host's access log stays
   empty (replace the container name and look up the host's `<id>` first):
   ```sh
   docker exec nginx-proxy-manager-app-1 sh -c 'grep -l signal.securevideocall.com /data/nginx/proxy_host/*.conf'
   docker exec nginx-proxy-manager-app-1 sh -c 'wc -c /data/logs/proxy-host-<id>_access.log*'
   ```

### Uptime monitoring

The web repository's `Uptime` workflow (`.github/workflows/uptime.yml` in secure-call) checks
`https://securevideocall.com/` and `https://signal.securevideocall.com/healthz` every 10 minutes
from GitHub's runners, outside the home network. When either fails three tries in a row, it opens
the issue "Uptime: securevideocall.com is down" in that repository, which notifies its watchers,
and closes it when both answer again. It reads only those two public URLs and records only which
one failed and when: no personal data, and nothing runs on the Pis. If only the signaling server
is down, check the proxy machine first (`docker ps -a` there): the backend answers on its own
with `curl -H 'Host: signal.securevideocall.com' http://<this Pi's LAN IP>:8001/healthz`.
GitHub turns the schedule off after 60 days without activity in the web repository, and a push
does not turn it back on: re-enable it on that repository's Actions tab, or with
`gh workflow enable uptime.yml -R The-Secure-Video-Call/secure-call`.

To look inside the database from the Pi: `docker compose exec postgres psql -U securecall
securecall`, or point a database tool at port `5434`.

**PostgreSQL updates:** `compose.yaml` pins `postgres:18` by digest. After merging a Dependabot
PR that bumps it, run on the Pi (`update.sh` only updates the backend):

```sh
cd ~/secure-call-backend && git pull
cd deploy/raspberry-pi && docker compose pull postgres && docker compose up -d postgres
```

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
