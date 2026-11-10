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
   And set `TURN_RELAY_IP` to the Pi's LAN IPv4 (the second half of `TURN_EXTERNAL_IP`), so relays
   are IPv4-only (see "IPv6" below). Compose refuses to start without it.
   Note the secret is visible to local users of the Pi via `docker inspect`.
4. **Backend `TURN_*`:** keep `TURN_SHARED_SECRET`/`TURN_URLS` unset for the backend until
   The-Secure-Video-Call/secure-call#47 is live.
5. **Check it works:**
   - From another machine: generate a credential
     (`user=$(( $(date +%s) + 600 )); pass=$(printf %s $user | openssl dgst -sha1 -hmac "$SECRET" -binary | openssl base64)`)
     and run `turnutils_uclient -u $user -w $pass -e 8.8.8.8 -n 1 -m 1 turn.securevideocall.com`.
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
The bandwidth cap is the tighter limit: `bps-capacity` / `max-bps` = 18750000 / 500000 allows
about 37 concurrent relayed allocations. A 38th gets `486 (Allocation Bandwidth Quota Reached)`.
This is intended; the test restarts coturn between groups of checks so it never hits it.

### Tests

`coturn/test-coturn.sh` starts the pinned image with this config and a test secret (a fresh
credential per check, so `user-quota` never interferes; coturn is restarted between groups for
the bandwidth quota). It checks that:

- a valid credential can relay to a public peer (8.8.8.8);
- wrong and expired credentials get no allocation, shown by a 4xx error line (a timeout, a client
  crash or a failed `docker exec` fails the check);
- 8 private, loopback, link-local, multicast and unspecified IPv4 peers get
  `channel bind: error 403 (Forbidden IP)`;
- the edges of each denied range (`0.0.0.1`, `100.127.255.255`, `172.31.255.255`, `198.19.0.1`,
  `192.0.0.1`, `240.0.0.1`, `255.255.255.255`) get the same refusal, and their neighbours
  (`11.0.0.1`, `100.128.0.1`, `172.32.0.1`, `198.20.0.1`, `1.1.1.1`) are allowed;
- a raw STUN probe (`coturn/address_family_probe.py`) gets `440` for an IPv6 relay request, and
  `403` or `443` from CreatePermission for 7 IPv6 and IPv4-mapped peers on an IPv4 allocation
  (with a public IPv4 peer as a control that must succeed);
- logs contain no username or peer IP, the config enables no `verbose`, `syslog` or
  `log-binding`, no log files exist in the container, and the CLI port is closed.

It needs Docker and is run by CI.

Do not add `denied-peer-ip=::ffff:0.0.0.0-::ffff:255.255.255.255`: coturn matches IPv4 peers
against the mapped range too, so it refuses every public IPv4 peer. The config denies only the
mapped forms of the private ranges. No `denied-peer-ip` range may start at `0.0.0.0` or `::`
(the ranges start at `0.0.0.1` and `::ffff:0.0.0.1`), because an "any" address as the lower
bound matches every peer: removing `denied-peer-ip=::` is what made public peers work in CI
run 42690621732.

### IPv6

This relay is IPv4-only. coturn uses host networking, so without a fixed relay address it could
hand out IPv6 relays, and home devices with global IPv6 addresses are not covered by any deny
range (their traffic would also come from inside the LAN, past the router's IPv6 firewall).
So `compose.yaml` passes `--relay-ip=${TURN_RELAY_IP}` (the Pi's LAN IPv4, the same address as
the second half of `TURN_EXTERNAL_IP`), and `turnserver.conf` sets
`allocation-default-address-family=ipv4`. Relays then only exist on one IPv4 address, and an
IPv6 relay request should be answered with `440`. I found no 4.6.3 option that refuses IPv6
allocation more directly. The test (`address_family_probe.py`) checks the `440` and the
refusals of IPv6 and mapped peers; if 4.6.3 answers differently, CI shows the real code.

coturn also *listens* only on `TURN_RELAY_IP` and `127.0.0.1` (`--listening-ip`), not on every
interface of the Pi (IPv6, Docker bridges). `no-rfc5780` turns off NAT behaviour discovery,
which needs two public IPs and is not used by WebRTC, and the pid file lives on the `/var/tmp`
tmpfs because the root filesystem is read-only. The test fails on any WARNING or ERROR line in
coturn's startup output, so an option coturn does not understand shows up in CI.
The IPv6 and mapped deny ranges in `turnserver.conf` stay as defence in depth.

### Logging

coturn does not log sessions: session lines can contain usernames and peer IPs, which must
never be logged. In 4.6.3 `log-file` is only a base name, so coturn always writes a small dated
log file (`turn_<pid>_<date>.log`) and prints one startup line, `log file opened: /var/log/...`,
to `docker logs`. The read-only root filesystem plus 1 MB in-memory (`tmpfs`) mounts for
`/var/tmp`, `/tmp` and `/var/log` keep that file in memory: nothing coturn writes can reach the
Pi's disk, and it vanishes when the container stops. The mounts are `noexec,nosuid,nodev`, the
container drops all capabilities except `NET_BIND_SERVICE`. That one is needed because the image
puts a file capability on the `turnserver` binary, and the kernel refuses to start it without it.
`no-new-privileges` is not set, because it blocks that file capability too (CI run 42757878869).

Checked in CI (an earlier run, before the allow-list and `cap_drop`): the dated log file has 2 startup lines and no test username or
peer IP; `/dev/shm/mongoc-1` holds only binary counters; `/var/tmp/turnserver.pid` is the pid.

**coturn's console output is discarded** (`logging: driver: none` in `compose.yaml`). Even with
logging off, coturn prints the TURN username of every failed login to its console (for example
internet scanners trying random logins), and Docker would otherwise save that on the Pi's disk.
So `docker compose logs coturn` shows nothing. To debug a coturn that will not start, set the
driver to `json-file` temporarily, look, and set it back.

The test inspects the container (as root, before each restart and at the end): a log file on the
real filesystem fails, and a file on the tmpfs mounts is printed (masked) and fails if it contains
a test username or peer IP. The test container keeps Docker's default logs only so it can check
what coturn prints:
- coturn's startup banner (captured before any client connects, so it holds no user data) has no
  `WARNING` or `ERROR` line, and coturn loaded exactly the `denied-peer-ip` ranges of `turnserver.conf`;
- after all the test traffic, the only lines beyond the banner are allocation counters and the
  failed-login lines for the test's own deliberate failures (wrong password, expired login);
- the username of a login that worked never appears;
- `compose.yaml` keeps coturn's console output discarded.

Follow-up (not done): the `NET_BIND_SERVICE` capability exists only because of the file capability on
`turnserver`. A small derived image that runs `setcap -r` on the binary would allow `cap_drop: ALL` plus
`no-new-privileges`, at the cost of the pinned upstream digest (it would have to be built and pinned in CI).
`NET_BIND_SERVICE` only allows binding ports below 1024, which is low risk.

### Refresh after expiry (input for #26)

`coturn/refresh_after_expiry.py` allocates with a credential that expires 5 s later, waits 10 s,
and sends a Refresh. CI prints `REFRESH AFTER EXPIRY: allowed` or `REFRESH AFTER EXPIRY: refused`.
Result (CI run 42688739841): `REFRESH AFTER EXPIRY: allowed`. coturn renews an allocation after
the credential has expired, so a 1-hour credential TTL does not drop long calls; the TTL only
needs to cover call setup. (If this ever reads `refused`, the TTL must cover the longest call or
the client must fetch a new credential before it expires.)
