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
| `POSTGRES_SSLMODE` | Default `verify-full`: TLS, with the server's certificate and host name checked against `POSTGRES_SSLROOTCERT`. The only other value accepted is `disable`, for a local development database; `prefer`, `require` and the rest are refused, as they fall back to plaintext or accept any certificate. |
| `POSTGRES_SSLROOTCERT` | Required with `verify-full`: the root certificate that signed the database's certificate. On the Pi, compose.yaml sets it. |
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
`.env`); never forward that port on your router.

- **TLS only.** PostgreSQL has a certificate from our own small certificate authority
  (`deploy/raspberry-pi/make-local-certs.sh`, which deletes the CA's key once it has signed). Its
  access rules (`deploy/raspberry-pi/postgres/pg_hba.conf`) have no plaintext entry, so the server
  itself refuses a connection without TLS, and TLS 1.3 is the minimum. The backend checks the
  certificate and the host name (`verify-full`).
- **Least privilege.** The backend connects as its own role, `securecall_app`
  (`deploy/raspberry-pi/postgres/initdb/10-app-role.sh`), which owns the database so it can run
  migrations, and nothing more: no superuser, no creating roles or databases. The superuser
  (`POSTGRES_USER`) is for maintenance only, and the backend never receives its password.
- **Tested on every PR.** CI starts PostgreSQL from `deploy/raspberry-pi/compose.yaml` itself and
  checks, in `tests/test_database_tls.py`, that plaintext, a certificate from another CA and a
  wrong host name are refused, and that the backend's role has no extra rights.
- **For local development** without TLS, set `POSTGRES_SSLMODE=disable` explicitly.

## Deploying to the Raspberry Pi

```
Browser --wss://signal.securevideocall.com--> router :443 --> Nginx Proxy Manager
        --https, checked against our CA--> Pi :8001 (secure-call-backend container)
        --TLS, checked--> PostgreSQL container
```

**How updates arrive:** every pull request and every merge to `main` runs **Publish backend
image** (`.github/workflows/publish-image.yml`), which builds the image, smoke-tests it and scans
its Debian and Python packages with Trivy: a HIGH or CRITICAL vulnerability that has a fix fails
the run (those without a fixed package yet are left out: no rebuild could remove them). On
`main`, after approval in the repo's **production** environment, it builds the image for arm64
(the Pi) and amd64 without any build cache, with an SBOM and BuildKit provenance in the image
index, publishes it as `:sha-<commit>`, signs a build provenance attestation for its digest,
checks that attestation exactly as the Pi will, and only then points
`ghcr.io/the-secure-video-call/secure-call-backend:main` at it. On the Pi, `update.sh` verifies
the attestation with `gh attestation verify`, refuses a build older than the one it deployed
last, and only then runs that exact digest and restarts the backend (see "Updating the backend"
in `deploy/raspberry-pi/README.md`). GitHub never connects to the Pi.

### One-time setup on the Pi

Requirements: 64-bit OS, Docker with the Compose and buildx plugins (both come with Docker's
own packages), gh 2.102.0 or newer with a read-only token, set up once as described under
"Updating the backend" in `deploy/raspberry-pi/README.md` (do that before step 3), Nginx Proxy
Manager already running.

1. **DNS:** in ServerByt's DNS editor, point `signal.securevideocall.com` (A record) at your
   home's static IP.
2. **Router:** forward TCP 80 and 443 to the machine that runs Nginx Proxy Manager, to the ports
   it publishes (for example 40080 and 40443 if its container maps them there). Never forward its
   admin port (81 inside the container) or 5432 (the database).
3. **Get the files and fill in the settings:**
   ```sh
   git clone https://github.com/The-Secure-Video-Call/secure-call-backend.git
   cd secure-call-backend/deploy/raspberry-pi
   cp .env.example .env        # set BACKEND_PUBLISH_ADDR, DJANGO_SECRET_KEY, POSTGRES_PASSWORD,
                               # POSTGRES_APP_PASSWORD
   ./make-local-certs.sh       # TLS certificates for the database and the backend, into
                               # ./tls/ (asks for sudo once)
   ./make-turn-secret.sh       # the TURN secret, into ./secrets/ (deploy/raspberry-pi/README.md)
   # and the TURN certificate: deploy/raspberry-pi/README.md, TURN step 3b
   docker compose up -d postgres
   ./update.sh                 # pulls and starts only a verified backend image
   docker compose up -d
   ```
   compose never pulls the backend image itself (`pull_policy: never`), so `update.sh` must run
   before the first full `docker compose up -d`, which otherwise stops with "No such image".
4. **Nginx Proxy Manager.** First copy this Pi's `tls/local-ca.crt` (public, but copy it over SSH
   so nobody can swap it) into the proxy's data folder, so it is `/data/secure-call/local-ca.crt`
   inside the proxy's container, for example from the proxy machine:
   ```sh
   scp <pi>:secure-call-backend/deploy/raspberry-pi/tls/local-ca.crt .
   docker exec nginx-proxy-manager-app-1 mkdir -p /data/secure-call
   docker cp local-ca.crt nginx-proxy-manager-app-1:/data/secure-call/local-ca.crt
   ```
   Then **Add Proxy Host:** domain `signal.securevideocall.com`; scheme **`https`**, forward
   hostname `127.0.0.1` (proxy on this Pi) or this Pi's home-network IP (proxy on another
   machine), port `8001`; **Websockets Support** and **Block
   Common Exploits** on. SSL tab: request a Let's Encrypt certificate; **HTTP/2** on, and
   **Force SSL** and **HSTS** **off**: the lines below replace both. They answer plain HTTP
   with an error instead of a redirect, so a client wrongly using `http://` or `ws://` is
   noticed (#56), but still let Let's Encrypt's challenge through for renewals; and they send
   the backend's security headers (HSTS among them) on the pages the proxy makes itself, such
   as that error and its 405 for TRACE (#61). **Advanced tab**, Custom Nginx Configuration: the
   lines of `deploy/raspberry-pi/npm-advanced.conf` (CI runs exactly these against the
   backend; its comments explain each part). Add no Custom Locations to this host:
   ```nginx
   access_log off;
   set $refuse_plain_http "";
   if ($scheme = "http") {
     set $refuse_plain_http "1";
   }
   if ($uri ~ "^/\.well-known/acme-challenge/") {
     set $refuse_plain_http "";
   }
   if ($refuse_plain_http) {
     return 400;
   }
   add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
   add_header X-Content-Type-Options "nosniff" always;
   add_header X-Frame-Options "DENY" always;
   add_header Referrer-Policy "no-referrer" always;
   add_header Cross-Origin-Opener-Policy "same-origin" always;
   add_header Cross-Origin-Resource-Policy "same-origin" always;
   add_header Content-Security-Policy "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'" always;
   add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), display-capture=()" always;
   charset utf-8;
   error_page 502 @proxy_502;
   error_page 504 @proxy_504;
   location @proxy_502 {
     return 502;
   }
   location @proxy_504 {
     return 504;
   }
   proxy_ssl_verify on;
   proxy_ssl_trusted_certificate /data/secure-call/local-ca.crt;
   proxy_ssl_name secure-call-backend;
   proxy_ssl_server_name on;
   proxy_ssl_protocols TLSv1.3;
   ```
   The backend speaks only HTTPS/WSS on 8001 (`BACKEND_TLS_CERTIFICATE` in `compose.yaml`), so
   room IDs and TURN credentials never cross the home network in plaintext, and without
   `proxy_ssl_verify` anyone on that network could pose as the backend. A host that works is
   no proof the check is on (without these lines it works too), so check, with the host's id
   from step 7 (5 here); this must print the three lines:
   ```sh
   docker exec nginx-proxy-manager-app-1 sh -c \
     'grep -E "proxy_ssl_(verify on|trusted_certificate|name)" /data/nginx/proxy_host/5.conf'
   ```
   Then, from anywhere, each of these must print its status and `8` (the 8 security headers,
   each once; a `9` or more means one came twice, for example with Force SSL or HSTS left on):
   ```sh
   headers='^(strict-transport-security|x-content-type-options|x-frame-options|referrer-policy|cross-origin-opener-policy|cross-origin-resource-policy|content-security-policy|permissions-policy):'
   for check in 'http://signal.securevideocall.com/healthz' '-X TRACE https://signal.securevideocall.com/' 'https://signal.securevideocall.com/healthz'; do
     curl -sS -o /dev/null -D - $check | tee >(head -n 1 >&2) | grep -ciE "$headers"
   done   # 400 then 8, 405 then 8, 200 then 8
   ```
   and a renewal must still work (Let's Encrypt's challenge comes over plain HTTP). With the
   host's id from step 6 (5 here), as Nginx Proxy Manager runs it itself:
   ```sh
   cert=$(docker exec nginx-proxy-manager-app-1 grep -o 'npm-[0-9]*' /data/nginx/proxy_host/5.conf | head -n 1)
   docker exec nginx-proxy-manager-app-1 certbot renew --dry-run --config /etc/letsencrypt.ini \
     --work-dir /tmp/letsencrypt-lib --logs-dir /data/logs --cert-name "$cert" --preferred-challenges http
   ```
   (If you set `PUID`/`PGID` for the proxy's container, add `-u <PUID>:<PGID>` after `exec`.)
   The CDN in front of the static site (StackCDN) makes two responses of its own, its `http://`
   to `https://` redirect and its 405 for TRACE, and they carry none of the site's headers. Its
   "Security Headers" panel cannot change that: tested on 2026-11-11, a header set there was
   added a second time to every response from the site and did not reach those two (#61). So
   the panel stays empty: the site's headers come only from its `.htaccess`, and the two CDN
   responses have no body worth protecting.

   `access_log off;` means the proxy keeps no record of who connected when (PLAN.md §3.5: no request logging of IP
   addresses; this app's own logs never contain them). The proxy still writes this host's error
   log (`/data/logs/proxy-host-<id>_error.log`), and a line there can name a client address when
   a connection fails. The Advanced tab cannot turn it off (another `error_log` only adds a
   destination). Either accept that (it holds failures only), or keep all of the proxy's logs in
   memory by adding `tmpfs: ["/data/logs:size=16m"]` to its service in its own compose file (this
   affects every host on that proxy, and the logs then vanish on restart).
5. **Updates:** run `deploy/raspberry-pi/update.sh` whenever a new image is published
   (`--check` only verifies). **Automatic updates** (optional): `crontab -e`, then add (with your
   path):
   ```
   */5 * * * * /home/pi/secure-call-backend/deploy/raspberry-pi/update.sh 2>&1 | logger -t secure-call-update
   ```
   An image that fails a check is skipped (the backend keeps running the last verified one), and
   `journalctl -t secure-call-update --since today` shows why; a Pi sends no mail, so the
   journal is where refusals and token expiry warnings end up.
6. **Firewall:** install `deploy/raspberry-pi/firewall.sh` and its systemd unit as
   `deploy/raspberry-pi/README.md` ("Firewall") describes. Then the backend and PostgreSQL can
   reach nothing but each other, only the proxy (`TRUSTED_PROXY_IPS`) reaches port 8001, and
   coturn reaches public addresses only, never the home network or the Pi itself. The rules touch
   only this stack's two Docker bridges, not the Pi's other containers.
7. **Check:** `curl https://signal.securevideocall.com/healthz` returns `{"status": "ok"}`.
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
is down, check the proxy machine first (`docker ps -a` there): the backend answers on its own,
from `deploy/raspberry-pi` on this Pi, with `curl --cacert tls/local-ca.crt --resolve
secure-call-backend:8001:127.0.0.1 -H 'Host: signal.securevideocall.com'
https://secure-call-backend:8001/healthz` (use this Pi's LAN IP instead of 127.0.0.1 if the
backend is published on it).
GitHub turns the schedule off after 60 days without activity in the web repository, and a push
does not turn it back on: re-enable it on that repository's Actions tab, or with
`gh workflow enable uptime.yml -R The-Secure-Video-Call/secure-call`.

To look inside the database from the Pi: `docker compose exec postgres psql -U securecall
securecall`. A database tool on port `5434` must use TLS and trust our CA, for example
`psql "host=127.0.0.1 port=5434 dbname=securecall user=securecall sslmode=verify-full
sslrootcert=tls/local-ca.crt"` from `deploy/raspberry-pi`.

**Certificate renewal:** `make-local-certs.sh` prints when the certificates expire (825 days).
Before then, or if a key may have leaked, run it again (it makes a new CA and new certificates
for PostgreSQL and the backend). The proxy reads its CA file only when it loads its
configuration, so without a reload it keeps refusing the new certificate:

1. On the proxy machine, put the new `tls/local-ca.crt` **after** the old one in
   `/data/secure-call/local-ca.crt` (both trusted for a moment), then
   `docker exec nginx-proxy-manager-app-1 sh -c 'nginx -t && nginx -s reload'`.
2. On this Pi: `docker compose up -d --force-recreate postgres backend`.
3. On the proxy machine, leave only the new CA in the file and reload again (as in 1). After a
   suspected compromise, skip the overlap: replace the file, reload and recreate at once.

**Moving an existing Pi to the hardened setup (once).** This brings, together: the database on
TLS only with the backend's own role (#57, #62), TLS from the proxy to the backend (#59), the
TURN secret in root-only files and TURN over TLS (#64, #58), the proxy refusing plain HTTP and
sending the security headers on its own pages (#56, #61), the firewall (#63), and `update.sh`
running only verified images (#67). The database holds nothing yet, so its volume is recreated
(the backend's role is made only when the database is first created). The image before this
set speaks plain HTTP and cannot read the TURN secret from its file; the new one speaks HTTPS
only. So between steps 3 and 5 calls get no TURN relay (calls that need it, such as privacy
mode, fail), and in step 5 signaling is down for the minute between the update and the proxy
change: do steps 3 to 5 in one sitting, at a quiet time.

1. **Before you merge anything of this set:** the "Publish backend image" run of #80 must have
   finished (it makes the first attested image). Approve no other publish run until step 5. On
   this Pi, comment out the `update.sh` line in `crontab -e`.
2. **Merge, in this order:** #77, #79, #85, #86, #87. Their "Publish backend image" run waits for
   your approval: **don't approve it yet.**
3. **On this Pi**, in `deploy/raspberry-pi`:
   ```sh
   git pull
   # update.sh's one-time setup (deploy/raspberry-pi/README.md, "Updating the backend"): gh
   # 2.102.0 or newer, its read-only token, the registry login. Then this must print "Verified":
   ./update.sh --check
   python3 -c "import secrets; print(secrets.token_urlsafe(32))"   # a new password
   nano .env            # add POSTGRES_APP_PASSWORD=<it>, different from POSTGRES_PASSWORD
   ./make-local-certs.sh   # TLS certificates for the database and the backend (asks for sudo)
   ./make-turn-secret.sh   # a NEW TURN secret into secrets/ (the old one was visible in ps)
   ```
   Then the TURN certificate (deploy/raspberry-pi/README.md, TURN step 3b: fetch it from the
   proxy machine into `/dev/shm` and run `./coturn/install-turn-certificate.sh`), and on the
   router forward **5349/tcp** to this Pi. Then:
   ```sh
   docker compose down --volumes    # pgdata, which holds nothing, is the only volume; this also
                                    # gives the networks their new bridge names (#63)
   docker compose up -d postgres
   ./update.sh                      # starts the verified image of #80 (still plain HTTP)
   docker compose up -d --build     # coturn with TLS and its secret file
   ```
   Signaling keeps working: that image ignores the new TLS settings (its start-up migration fails
   harmlessly, and signaling does not use the database).
4. **On the proxy machine**, copy `tls/local-ca.crt` into the proxy (setup step 4), but don't
   change the host yet.
5. **Approve the publish** of step 2 and wait until it finishes. Then `./update.sh` on this Pi,
   and **at once**, in Nginx Proxy Manager: switch the signal host to `https`, turn its **Force
   SSL** and **HSTS** off, paste all of `npm-advanced.conf` into the Advanced tab, and run setup
   step 4's checks (the three `proxy_ssl` lines, the header counts, the dry-run renewal).
6. **Firewall** (deploy/raspberry-pi/README.md, "Firewall", setup steps 2 to 5; step 1 was the
   `down`/`up` above): check `TRUSTED_PROXY_IPS` and `TURN_PUBLIC_IP` in `.env`, apply by hand,
   check, then install the systemd unit. Keep a second SSH session open while you do it.
7. **In `.env`:** delete the `TURN_SHARED_SECRET` line (nothing reads it any more), and in
   `TURN_URLS` replace `turn:turn.securevideocall.com:3478?transport=tcp` with
   `turns:turn.securevideocall.com:5349?transport=tcp`. Then `docker compose up -d backend`.
8. **Check:**
   ```sh
   docker compose ps    # backend, postgres and coturn running
   docker compose exec postgres psql -U securecall -d securecall -Atc \
     "select rolname from pg_roles where rolname = 'securecall_app'"   # securecall_app
   # The backend itself reaches the database (its start-up migration does not stop on a failure):
   docker compose exec backend python manage.py migrate --check && echo database reachable
   curl https://signal.securevideocall.com/healthz     # {"status": "ok"}
   # Prints nothing: the secret is in no process's arguments and in neither container's settings.
   { ps -eo args; docker inspect secure-call-coturn secure-call-backend; } \
     | grep -F -f <(sudo cat secrets/turn-shared-secret)
   stat -c %a .env      # 600
   sudo secure-call-firewall --check    # ends with "Secure Call firewall: active."
   ```
   Then make a test call, one in privacy mode too (it needs the relay), and check the TURN
   certificate from outside (TURN step 3b's `openssl s_client` line).
9. **Put the cron line back,** in its new form with the journal (deploy/raspberry-pi/README.md,
   "Updating the backend"), and add the TURN certificate's expiry warning (TURN step 3b).

If PostgreSQL's first start fails (see `docker compose logs postgres`),
the half-created database must be removed before trying again: `docker compose down
--volumes`.

**PostgreSQL updates:** `compose.yaml` pins `postgres:18` by digest. After merging a Dependabot
PR that bumps it, run on the Pi (`update.sh` only updates the backend):

```sh
cd ~/secure-call-backend && git pull
cd deploy/raspberry-pi && docker compose pull postgres && docker compose up -d postgres
```

## Logs

Every log the project produces or depends on. Our own logs (backend, PostgreSQL, coturn) may
never contain message contents, room IDs, IP addresses or usernames (PLAN.md §3); the proxy's error
log and the static host's and CDN's logs can contain IP addresses (see their rows). Logs stay on the machine that wrote them; if they are ever
copied off the Pi, copy them to a host we control, never to a third-party logging service.

| Log | Where it lives | May contain | Retention | Who may read it |
|---|---|---|---|---|
| Backend (Daphne and Django) | Docker `local` log of the `secure-call-backend` container on the Pi (`docker compose logs backend`) | Warnings and errors from this app: time, level, logger name and message, including request paths of 4xx responses and rejected Host headers; never client addresses. Daphne runs with `-v 0`, so there is no access log | Rotated by `compose.yaml`: at most 3 files of 10 MB (about 30 MB), oldest dropped first | The Pi's owner and users in the `docker` group (root-equivalent), so keep that group trusted |
| PostgreSQL | Docker `local` log of the `postgres` container on the Pi | Server start-up, checkpoint and error messages. It holds no call data (see Database). Error lines (for example a failed login) can name the database role and the connecting address (the backend container, or for tools on the published port the Docker gateway or a home-LAN device), never a caller's address | Same rotation: 3 files of 10 MB | Same as the backend |
| coturn | Discarded: `logging: driver: none` and a read-only root filesystem in `compose.yaml` (coturn prints TURN usernames on failed logins). Whether to keep any of it is decided in #70 | Nothing is stored | None; gone as soon as it is written | Nobody |
| Nginx Proxy Manager | On the proxy machine, `/data/logs/` inside its container. This host's access log is off (setup step 4); the error log is kept | Error log: failed connections, which can name a client address | Managed by the proxy's own log rotation, not by this repo; check it on the proxy machine. Optionally keep it in memory (step 4) | The proxy machine's owner and its `docker` group |
| Static host and CDN (securevideocall.com) | The web app's host and CDN, outside this repo | Whatever that provider records for requests to static files, typically client addresses. We do not control it | The provider's own policy; document it in the web repository's `docs/data-inventory.md` (secure-call#124) | The provider's staff and the account owners |
| GitHub Actions | GitHub, per workflow run of this repository | Build and test output. Workflows must not print secrets or call data | GitHub's default (90 days for logs and artifacts) | Collaborators with access to this repository; public repository logs are readable by anyone |

Rollout of the rotation on the Pi: `cd deploy/raspberry-pi && docker compose up -d`. This recreates
the backend and PostgreSQL containers with the new log settings; older `json-file` logs of the
replaced containers are removed with them.

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
