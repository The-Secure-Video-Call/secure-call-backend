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
   Also set `TURN_PUBLIC_IP` (the home's public IPv4, which must be static: if it changes, update
   `.env` and restart coturn). Compose passes it as `--external-ip=<public IP>/<Pi LAN IP>` and also as
   `--denied-peer-ip=<public IP>`, so nobody can be relayed to the router through the public
   address (hairpin NAT), even if the value is wrong in a way that defeats coturn's own rewrite.
   And set `TURN_RELAY_IP` to the Pi's LAN IPv4, so relays are IPv4-only (see "IPv6" below).
   Compose refuses to start without either value.
   Note the secret is visible to local users of the Pi via `docker inspect`.
   On the Pi, use zram or no swap: swapped memory (the secret, and the in-memory log mounts
   below) could otherwise reach the SD card. `ulimits: core: 0` already prevents core dumps.
4. **Backend `TURN_*`:** keep `TURN_SHARED_SECRET`/`TURN_URLS` unset for the backend until
   The-Secure-Video-Call/secure-call#47 is live.
5. **Check it works:**
   - **On the Pi**, create a short-lived test credential. Read the secret from `.env` there
     (`SECRET=$(grep '^TURN_SHARED_SECRET=' .env | cut -d= -f2-)`), then:
     `user=$(( $(date +%s) + 600 )); pass=$(printf %s "$user" | openssl dgst -sha1 -hmac "$SECRET" -binary | openssl base64); echo "$user $pass"`.
     Copy only that username and password to the other machine, never the shared secret. They
     stop working after 10 minutes.
   - From another machine, run
     `turnutils_uclient -u "$user" -w "$pass" -e 8.8.8.8 -n 1 -m 1 turn.securevideocall.com`.
   - Or open https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/, add
     `turn:turn.securevideocall.com:3478` with that username and password, and gather: a
     `relay` candidate should appear.
6. **Image pin:** the image is pinned to `4.6.3` plus its `@sha256:` digest (taken from the CI
   pull). When upgrading, update both, e.g. from `docker buildx imagetools inspect coturn/coturn:<tag>`.

### Quotas

Sized for a 200 Mbit/s line: `max-bps=500000` (4 Mbit/s per session, enough for a 720p call),
`bps-capacity=18750000` (150 Mbit/s, 75% of the line, so the house keeps headroom),
`user-quota=6` (usernames are per join; a browser needs about 2 allocations, plus 2 more during
an ICE restart) and `total-quota=100`. Note the 41-port relay range
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
  (with a public IPv4 peer as a control that must succeed). CreatePermission for the stand-in
  public IP and for the relay's own IP is printed but not asserted (see "Our own addresses");
- a second raw STUN probe (`coturn/relay_reachability_probe.py`) checks where packets go (see
  "Our own addresses");
- turnserver is pid 1 and not root (`Uid` and `Gid` non-zero), with `CapEff` 0 and `NoNewPrivs` 1;
- logs contain no username or peer IP, the config enables no `verbose`, `syslog` or
  `log-binding`, no log files exist in the container, and the CLI port is closed.

It needs Docker and is run by CI.

Do not add `denied-peer-ip=::ffff:0.0.0.0-::ffff:255.255.255.255`: coturn matches IPv4 peers
against the mapped range too, so it refuses every public IPv4 peer. The config denies only the
mapped forms of the private ranges. No `denied-peer-ip` range may start at `0.0.0.0` or `::`
(the ranges start at `0.0.0.1` and `::ffff:0.0.0.1`), because an "any" address as the lower
bound matches every peer: removing `denied-peer-ip=::` is what made public peers work in CI
run 42690621732.

### Our own addresses

CI run 42770315949 showed that CreatePermission for the stand-in public IP (also passed as
`--denied-peer-ip`) and for the relay's own IP returns success. That is deliberate in coturn: two
clients relaying through the same server must reach each other's relay addresses, and in privacy
mode both people use this relay. A permission is not data, so `relay_reachability_probe.py` tests
where packets go:

- **Relay to relay must work:** allocation A permits B's relayed address (the public form), sends,
  and B must receive it; then the same from B to A.
- **Nothing else may be reached through our own addresses:** UDP listeners on the relay IP
  (port 40001) and on `127.0.0.1` (port 40002), outside the relay port range, must receive nothing
  when an allocation sends to the public IP, the relay IP and loopback (after trying to create
  permissions). A self-check first proves the listeners can receive.

If the listeners ever receive something, coturn forwards to a non-relay port on its own address
(on the Pi: the Pi's or the router's own UDP services). That needs another control, such as a
firewall rule on the Pi, not a weaker config. Result: pending the next CI run. `--denied-peer-ip`
for the public IP stays until that run shows whether it blocks relay-to-relay or nothing at all;
this section will then say which. The flag is defence in depth, not the control: the control is
coturn's rewrite of the public IP to the relay IP. The loopback listener passes either way (nothing
received); if the deny list refuses the permission, the output says so and it is not a hairpin
test. Not covered yet: a packet that really leaves for the WAN address (it would need the
stand-in address added to the runner's loopback). If a firewall rule is ever needed, a dedicated
uid instead of the shared 65534 would make an owner match precise.

turnserver must be able to read the mounted config: keep `coturn/turnserver.conf` world-readable
(`chmod 644`) on the Pi, or it fails at startup as a non-root user.

turnserver runs as `65534:65534` (`user:` in compose, `--user` in the test): with
`entrypoint: ['turnserver']` the image's own switch to an unprivileged user is skipped, and CI run
42770315949 showed `CapEff 0x400`, a root process.

### IPv6

This relay is IPv4-only. coturn uses host networking, so without a fixed relay address it could
hand out IPv6 relays, and home devices with global IPv6 addresses are not covered by any deny
range (their traffic would also come from inside the LAN, past the router's IPv6 firewall).
So `compose.yaml` passes `--relay-ip=${TURN_RELAY_IP}` (the Pi's LAN IPv4, the same address as
the second half of `--external-ip`), and `turnserver.conf` sets
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
never be logged. The config has `log-file=stdout` plus `no-stdout-log` (an earlier
`log-file=/dev/null` did not stop coturn creating a dated `turn_<pid>_<date>.log`, because it
builds the file name from the setting). The read-only root filesystem plus 1 MB in-memory
(`tmpfs`) mounts for `/var/tmp`, `/tmp` and `/var/log` mean that nothing coturn writes, a log
file included, can reach the Pi's disk, and it vanishes when the container stops. The mounts are
`noexec,nosuid,nodev`. The container drops all capabilities except `NET_BIND_SERVICE`, because
the image puts a file capability on the `turnserver` binary and the kernel refuses to start it
if that capability is not even in the bounding set (CI run 42757878869). With
`no-new-privileges:true` the file capability is then not granted, so turnserver runs with no
effective capabilities (`CapEff` 0, asserted by the test). It is also started directly
(`entrypoint: ['turnserver']`), so the image's shell entrypoint never expands the secret.

Earlier CI runs showed: `/dev/shm/mongoc-1` holds only binary counters, and
`/var/tmp/turnserver.pid` is the pid. The test prints any file it finds on the tmpfs mounts
(masked) and fails if one holds a test username or peer IP.

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
- after all the test traffic (including the refresh probe), the only lines beyond the banner are:
  allocation counters; failed-login lines for the test's own deliberate failures (wrong password,
  expired login); deny lines (`A peer IP ... denied in the range ...`) naming only a peer the
  test asked for, or the relay's own address, and a range from the config or the command-line
  `--denied-peer-ip`; and the `Terminating on signal 15` line when the test restarts coturn;
- the username of a login that worked never appears;
- `compose.yaml` keeps coturn's console output discarded.

Fallback if CI shows that coturn does not start with `no-new-privileges`: build a small derived
image (compose `build:`, pinned base digest) that runs `setcap -r` on `turnserver`, and run it
with `cap_drop: ALL` and no capabilities at all.

### Refresh after expiry (informational, for #26)

`coturn/refresh_after_expiry.py` allocates with a credential that expires 5 s later, waits 25 s
(the test runs coturn with `--stale-nonce=20`, so the nonce has been rotated by then), and sends a
Refresh, retrying once with the new nonce. CI prints `REFRESH AFTER EXPIRY: allowed` or
`REFRESH AFTER EXPIRY: refused`, and whether the server rotated the nonce.
An earlier probe, without a nonce rotation (CI run 42688739841), printed `allowed`. The result
of the probe across a nonce rotation is pending the next CI run.
With secure-call-backend#32 a credential lasts as long as the room (4 h), so this result is
informational: it only matters if the credential lifetime is ever shortened again.
