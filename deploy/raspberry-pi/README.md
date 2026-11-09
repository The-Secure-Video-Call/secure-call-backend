# Raspberry Pi test server

`compose.yaml` runs the backend, PostgreSQL and coturn. Copy `.env.example` to `.env`, fill in
the values marked "set", then `docker compose up -d`.

## TURN

coturn relays media for callers behind strict NATs. It runs with `network_mode: host` and the
hardened config in `coturn/turnserver.conf`. The config refuses to relay to private, loopback,
link-local and multicast addresses, so a credential holder cannot reach your home network.
Do not remove those lines.

Manual steps (owner):

1. **DNS at ServerByt:** add an A record `turn.securevideocall.com` pointing to the home static IP.
2. **Router port forwards to the Pi:** `3478` UDP and TCP, and `49160-49200` UDP.
   Forward nothing else for TURN (no 5349, no 443).
3. **Secret:** on the Pi run `openssl rand -base64 32` and put the result in `.env` as
   `TURN_SHARED_SECRET`. Then `docker compose up -d coturn`. The same value goes to the backend
   later (#26). Never commit it.
   Also set `TURN_EXTERNAL_IP` (`<public IP>/<Pi LAN IP>`); without it the relay advertises the LAN address.
   Note the secret is visible to local users of the Pi via `docker inspect`.
4. **Backend `TURN_*`:** keep `TURN_SHARED_SECRET`/`TURN_URLS` unset for the backend until
   The-Secure-Video-Call/secure-call#47 is live.
5. **Check it works:**
   - From another machine: generate a credential
     (`user=$(( $(date +%s) + 600 )); pass=$(printf %s $user | openssl dgst -sha1 -hmac "$SECRET" -binary | openssl base64)`)
     and run `turnutils_uclient -y -u $user -w $pass -e 8.8.8.8 -n 1 -m 1 turn.securevideocall.com`.
   - Or open https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/, add
     `turn:turn.securevideocall.com:3478` with that username and password, and gather: a
     `relay` candidate should appear.
6. **Image pin:** the image is pinned to `4.6.3` plus its `@sha256:` digest (taken from the CI
   pull). When upgrading, update both, e.g. from `docker buildx imagetools inspect coturn/coturn:<tag>`.

### Quotas

Sized for a 200 Mbit/s line: `max-bps=500000` (4 Mbit/s per session, enough for a 720p call),
`bps-capacity=18750000` (150 Mbit/s, 75% of the line, so the house keeps headroom),
`user-quota=12` and `total-quota=100` as specified in the issue. Note the 41-port relay range
(49160-49200) limits real capacity to about 41 allocations, below `total-quota`.

### Tests

`coturn/test-coturn.sh` starts the pinned image with this config and a test secret and checks
that a valid credential can bind a public peer (8.8.8.8), that wrong and expired credentials get
no allocation, and that 15 private, loopback, link-local, multicast and IPv4-mapped peers get
`403 Forbidden IP`. It needs Docker and is run by CI.

Do not add `denied-peer-ip=::ffff:0.0.0.0-::ffff:255.255.255.255`: coturn matches IPv4 peers
against the mapped range too, so it refuses every public IPv4 peer. The config denies only the
mapped forms of the private ranges.

### Refresh after expiry (input for #26)

`coturn/refresh_after_expiry.py` allocates with a credential that expires 5 s later, waits 10 s,
and sends a Refresh. CI prints `REFRESH AFTER EXPIRY: allowed` or `REFRESH AFTER EXPIRY: refused`.
Result: **pending the next CI run** (fill in here, then set the credential TTL in #26 accordingly:
if refresh is allowed, an expired credential keeps its existing allocation alive, so the TTL only
needs to cover call setup; if refused, the TTL must cover the longest call or the client must
fetch a new credential before it expires).
