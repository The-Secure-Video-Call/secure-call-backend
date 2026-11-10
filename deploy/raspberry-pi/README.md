# Raspberry Pi test server

`compose.yaml` runs the backend, PostgreSQL and coturn. Copy `.env.example` to `.env`, fill in
the values marked "set", then `docker compose up -d`.

## TURN

coturn relays media for callers behind strict NATs. It runs on its **own Docker bridge network**
(`turn`, subnet `172.30.200.0/29`, no IPv6, coturn at the fixed address `172.30.200.2`, the Pi as
gateway `172.30.200.1`) with the hardened config in `coturn/turnserver.conf`. The config refuses to
relay to private, loopback, link-local and multicast addresses, so a credential holder cannot reach
your home network. Do not remove those lines.

Published ports (only on the Pi's LAN address, `TURN_RELAY_IP`, never on every interface):
`3478` UDP and TCP, and `49160-49200` UDP. The router forwards are unchanged.

**Why not host networking:** coturn exempts its own addresses from the deny list (two clients on
one relay must reach each other's relay addresses). On the host network its own address is the
Pi, and CI run 48e8d0b showed that data sent through the relay to a non-relay UDP port on the
relay's LAN address was delivered: any UDP service on the Pi would have been reachable from the
internet with a TURN login. In its own network the only thing at coturn's own address is coturn.
The Pi's LAN IP (192.168/16 or 10/8) and the bridge gateway (172.16/12) are covered by the normal
deny ranges. **Accepted by design:** sending to another port on coturn's own container address can
only reach coturn itself, because nothing else runs in that container.

**Limits:** the deny ranges cover RFC 1918 and CGNAT space only; if the home LAN or Docker's
address pools use other space, nothing denies it. The subnet `172.30.200.0/29` must not overlap
another Docker network. The deny list constrains peers requested through the TURN protocol, not
code running inside a compromised container: that could still reach the Pi's services through the
gateway `172.30.200.1`, which is why the container has no capabilities, no-new-privileges and a
read-only root. A `DOCKER-USER` firewall rule dropping traffic from the `turn` bridge to the Pi
is optional extra hardening. A bare `docker compose pull` also tries to pull
`secure-call-coturn:local`; `update.sh` only names the backend.

**Derived image:** `compose.yaml` builds `coturn/Dockerfile` (the pinned upstream image plus
removing the file capability from `turnserver`, running as 65534), so no capability needs adding
back. The first start, and every change to the Dockerfile, needs `docker compose up -d --build
coturn`. `update.sh` only runs `pull backend` and `up -d backend`, so it never builds or restarts
coturn (and, as `--build` is not used, never rebuilds it): upgrading coturn is a manual
`docker compose up -d --build coturn` after changing the digest in the Dockerfile.

**Pi time sync:** the REST credentials carry a Unix expiry time, so coturn and the backend need a
correct clock, including right after a reboot (a Pi has no battery clock). Enable
`systemd-time-wait-sync.service` (`sudo systemctl enable systemd-time-wait-sync`) and start Docker
after `time-sync.target` (`sudo systemctl edit docker`, add `[Unit]` `After=time-sync.target`
`Wants=time-sync.target`).

Manual steps (owner):

1. **DNS at ServerByt:** add an A record `turn.securevideocall.com` pointing to the home static IP.
2. **Router port forwards to the Pi:** `3478` UDP and TCP, and `49160-49200` UDP.
   Forward nothing else for TURN (no 5349, no 443).
3. **Secret:** on the Pi run `openssl rand -base64 32` and put the result in `.env` as
   `TURN_SHARED_SECRET`. The same value goes to the backend
   later (#26). Never commit it.
   Also set `TURN_PUBLIC_IP` (the home's public IPv4, which must be static: if it changes, update
   `.env` and restart coturn). Compose passes it as `--external-ip=<public IP>/172.30.200.2` and also as
   `--denied-peer-ip=<public IP>` (defence in depth; relay-to-relay still works with it).
   And set `TURN_RELAY_IP` to the Pi's LAN IPv4 (its default-route address, since Docker's NAT
   sends outgoing relay traffic from there): the ports are published on that address only.
   Compose refuses to start without either value; as it checks the whole file, a `.env` missing
   any of the three `TURN_*` values also makes `update.sh` fail. Then `docker compose up -d --build coturn`.
   Note the secret is visible to local users of the Pi via `docker inspect`.
   On the Pi, use zram or no swap: swapped memory (the secret, and the in-memory log mounts
   below) could otherwise reach the SD card. `ulimits: core: 0` already prevents core dumps.
4. **Backend `TURN_*`:** keep `TURN_SHARED_SECRET`/`TURN_URLS` unset for the backend until
   The-Secure-Video-Call/secure-call#47 is live. `TURN_URLS` is commented out in `.env.example`:
   uncomment it only after the rate limits (#35) are live and DNS and the router forwards are done.
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
6. **Image pin:** `coturn/Dockerfile` pins the base to `4.6.3` plus its `@sha256:` digest (taken
   from the CI pull). When upgrading, update both, e.g. from
   `docker buildx imagetools inspect coturn/coturn:<tag>`, then rebuild.

### Quotas

Sized for a 200 Mbit/s line: `max-bps=500000` (4 Mbit/s per session, enough for a 720p call),
`bps-capacity=18750000` (150 Mbit/s, 75% of the line, so the house keeps headroom),
`user-quota=6`, `max-allocate-lifetime=600` and `total-quota=100` (see below for what these do
and do not limit). Note the 41-port relay range
(49160-49200) limits real capacity to about 41 allocations, below `total-quota`.
The bandwidth cap is the tighter limit: `bps-capacity` / `max-bps` = 18750000 / 500000 allows
about 37 concurrent relayed allocations. A 38th gets `486 (Allocation Bandwidth Quota Reached)`.
This is intended; the test restarts coturn between groups of checks so it never hits it.

#### Why `user-quota=6` (reasoned, not yet measured)

GitHub Actions has no Safari and I could not run Chrome against the container, so the number comes
from how browsers gather relay candidates: one allocation per TURN URL (we send two: UDP and TCP)
per network interface they use. That is 2 on one interface, and an ICE restart briefly keeps the
old allocations next to the new ones: 4. `6` is that plus a margin of 2; `4` would leave none. A
phone on Wi-Fi and mobile data at once could reach 8 during a restart; it would then get `486`
for the extras (the ones that worked stay, and direct candidates still exist outside privacy
mode). **To check on real devices:** open `chrome://webrtc-internals` (and Safari's Web Inspector)
during a call and an ICE restart, and count the relay candidates gathered per peer connection.
If the maximum seen is below 4, the quota can go lower; if it is above 6, raise it.

#### What one client can still do

`user-quota` counts per username, and **every credential has a new username**, so it limits one
credential, not one client. With 41 relay ports and `user-quota=6`, **about 7 credentials fill
every relay port** (41 / 6 rounded up); `bps-capacity` / `max-bps` (about 37 sessions at full
rate) is reached with fewer allocations per credential. What brakes the number of credentials:

- the backend's cap of 120 credentials per client IP per hour (`signaling/rate_limits.py`). It
  cannot be lower, because many people share one address, so 7 is well inside it;
- the backend's cap of 20 credentials per room (`signaling/rooms.py`), which stops a reconnect
  loop in one occupied room from being an endless credential source. The count lives only while
  the room exists (we keep no list of old room IDs), so **it resets when the room empties: one
  client that leaves and rejoins the same ID, or a script that creates rooms, is not stopped by
  it.** It is a guard against runaway reconnects, not a defence against a hostile client. Also
  note it is shared by both members: one of them reconnecting 20 times leaves the room without
  a relay until it ends (privacy-mode calls then fail closed).

So **one client can still fill the relay.** The impact is availability only: media stays
DTLS-SRTP encrypted and the peer deny list is unchanged; while the relay is full, privacy-mode
calls fail closed ("Privacy mode needs our relay...") and normal calls lose their TURN fallback
(direct calls still work). Closing this needs the relay to know who asked for a credential (for
example a per-client allocation count in coturn, or an authenticated user), which is outside
`turnserver.conf` in 4.6.3 and outside the current design (no accounts).

#### How long one allocation can live

`max-allocate-lifetime=600` limits each Allocate or Refresh to 10 minutes (coturn's default is
an hour), so a client that stops refreshing loses its relay port within 10 minutes. It does not
limit the total: a client can keep refreshing. coturn 4.6.3 has no option to refuse a Refresh after
the REST credential's expiry or to cap an allocation's total life. What it actually does is
checked by the CI probe (next sections). So an allocation lives as long as the client keeps
refreshing it, and the credential's expiry (up to the 4 h room lifetime) does not end it.

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
- one credential gets 6 allocations and the 7th is refused with `486`
  (`coturn/allocation_quota_probe.py`);
- a second raw STUN probe (`coturn/relay_reachability_probe.py`) checks where packets go (see
  "Our own addresses");
- the test builds `coturn/Dockerfile`, creates the same bridge network and runs the image with the
  same flags as `compose.yaml`; turnserver is pid 1 and not root (`Uid` and `Gid` non-zero), with
  `CapEff` 0 and `NoNewPrivs` 1, has no file capability, and starts as uid 65534 with all
  capabilities dropped;
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

CI run 48e8d0b (host networking) showed that CreatePermission for the stand-in public IP (also
passed as `--denied-peer-ip`) and for the relay's own IP returns success, and that data sent to a
non-relay port on the relay's own LAN address was delivered. That is how coturn works: two clients
relaying through the same server must reach each other's relay addresses, and in privacy mode both
people use this relay. It is why coturn now runs on its own bridge network (see "TURN" above), so
its own address is the container's. `relay_reachability_probe.py` tests where packets go:

- **Relay to relay must work:** allocation A permits B's relayed address (the public form), sends,
  and B must receive it; then the same from B to A.
- **The Docker host must not be reachable:** UDP listeners on the host's LAN IPv4 (port 40001) and
  on the bridge gateway (port 40002), outside the relay port range, must receive nothing when an
  allocation sends to them directly, or to the public IP (which coturn rewrites to its own
  container address). A self-check first proves the listeners can receive. Both host addresses
  are in the deny ranges, so their permissions are normally refused (the output names the
  outcome); the public-IP route is the one that exercises the exempted own address.

Sending to another port on coturn's own container address can only reach coturn itself, because
nothing else runs in that container (accepted by design). `--denied-peer-ip` for the public IP
stays: relay-to-relay worked with it set (CI run 48e8d0b), so it breaks nothing; it is defence in
depth, and the control is the network separation plus coturn's rewrite of the public IP to the
container address. Not covered: a packet that really leaves for the WAN address (it would need the
stand-in address added to the runner). Result of the new probes: pending the next CI run.

turnserver must be able to read the mounted config: keep `coturn/turnserver.conf` world-readable
(`chmod 644`) on the Pi, or it fails at startup as a non-root user.

turnserver runs as `65534:65534` (`user:` in compose, `--user` in the test, `USER` in the
Dockerfile): with `entrypoint: ['turnserver']` the upstream image's own switch to an unprivileged
user is skipped, and CI run 42770315949 showed `CapEff 0x400`, a root process.

### IPv6

This relay is IPv4-only. coturn runs on a network without IPv6 (`enable_ipv6: false`), relays on
the single address `172.30.200.2` (`--relay-ip`), and `turnserver.conf` sets
`allocation-default-address-family=ipv4`. An IPv6 relay request is answered with `440`. I found no
4.6.3 option that refuses IPv6 allocation more directly. The test (`address_family_probe.py`)
checks the `440` and the refusals of IPv6 and mapped peers; if 4.6.3 answers differently, CI shows
the real code.

coturn also *listens* only on `172.30.200.2` and `127.0.0.1` (`--listening-ip`). `no-rfc5780` turns off NAT behaviour discovery,
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
`noexec,nosuid,nodev`. The container drops all capabilities and adds none: the upstream image puts
a file capability (`CAP_NET_BIND_SERVICE`) on the `turnserver` binary, the kernel refuses to start
it if that capability is not in the bounding set (CI run 42757878869), and Docker grants a
`cap_add` capability to the non-root process too (`CapEff 0x400`, CI run 48e8d0b). So
`coturn/Dockerfile` removes the file capability (`setcap -r`, or a plain `cp` of the binary, which
does not copy the capability attribute), and the test asserts that turnserver has none, starts
with every capability dropped, and runs with `CapEff` 0 and `no-new-privileges:true`. It is also
started directly (`entrypoint: ['turnserver']`), so no shell ever expands the secret.

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
  test asked for (including the Docker host's addresses), or the relay's own address, and a range from the config or the command-line
  `--denied-peer-ip`; and the `Terminating on signal 15` line when the test restarts coturn;
- the username of a login that worked never appears;
- `compose.yaml` keeps coturn's console output discarded.


### Refresh after expiry (asserted in CI since #37; background from #26)

`test-coturn.sh` now asserts the probe result against `expected_refresh_after_expiry`. It is
`allowed`, the only result seen so far (coturn 4.6.3 has no option to change it), and a change
(for example after an image bump) fails the test so these notes get updated.


`coturn/refresh_after_expiry.py` allocates with a credential that expires 5 s later, waits 25 s
(the test runs coturn with `--stale-nonce=20`, so the nonce has been rotated by then), and sends a
Refresh, retrying once with the new nonce. CI prints `REFRESH AFTER EXPIRY: allowed` or
`REFRESH AFTER EXPIRY: refused`, and whether the server rotated the nonce.
An earlier probe, without a nonce rotation (CI run 42688739841), printed `allowed`. The result
of the probe across a nonce rotation is pending the next CI run.
With secure-call-backend#32 a credential lasts as long as the room (4 h), so this result is
informational: it only matters if the credential lifetime is ever shortened again.
