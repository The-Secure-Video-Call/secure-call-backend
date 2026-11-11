# Raspberry Pi test server

`compose.yaml` runs the backend, PostgreSQL and coturn. First do the one-time setup under
"Updating the backend" below (gh and its token), then copy `.env.example` to `.env`, fill in the
values marked "set", run `./make-local-certs.sh` (README.md, "One-time setup on the Pi"),
and run `docker compose up -d postgres`, `./update.sh` and `docker compose up -d`, in that
order. compose never pulls the backend image itself
(`pull_policy: never`): a bare `docker compose up -d` before `update.sh` stops with "No such
image" instead of running an unverified one.

## Updating the backend

Run `./update.sh` in this folder, as the user that runs Docker. It:

1. looks up the digest that `ghcr.io/the-secure-video-call/secure-call-backend:main` points to
   (`docker buildx imagetools inspect`);
2. checks that exact image with `gh attestation verify`: its signed build provenance must say it
   was built by this repository's `.github/workflows/publish-image.yml`, from `refs/heads/main`, on
   a GitHub-hosted runner (the attestation is signed with a short-lived Sigstore certificate
   issued for that workflow run, so a registry login alone cannot forge it);
3. refuses an image built by an older workflow run than the image it deployed last (the run ID
   comes from the attestation's certificate), so moving `:main` back to an older, possibly
   vulnerable, attested image does not work;
4. only then pulls the image **by that digest**, points the local `:main` tag at it and runs
   `docker compose up -d --no-deps --pull never backend` (only the backend container is
   touched), checks that the backend container runs exactly the verified image (and stops it if
   not), and records the run ID.

If `docker`, `gh`, `flock` or `timeout` is missing, gh is older than 2.102.0, another update.sh is
still running, a lookup times out or fails, or a check fails, it prints why, exits non-zero and
does not restart the backend. `./update.sh --check` does steps 1 to 3 only and changes nothing.
compose.yaml sets `pull_policy: never` for the backend, so `docker compose pull` and
`docker compose up` never fetch `:main` themselves; do not `docker pull` it by hand either.

update.sh keeps its lock and the last deployed run ID in `~/.local/state/secure-call-backend/`
(mode 700, outside the git checkout). The first run accepts any verified image and records it.
To go back to an older version on purpose, revert the change on `main`: the new run then
publishes it.

It also warns (and carries on) when gh's token expires within 14 days.

**One-time setup on the Pi** (as the same user):

1. **gh 2.102.0 or newer**, from GitHub's own apt repository
   ([install steps](https://github.com/cli/cli/blob/trunk/docs/install_linux.md#debian)); `apt
   upgrade` then keeps it current. Debian's own `gh` package is too old (no `gh attestation`), and
   before 2.102.0 gh checked `--signer-workflow` and `--source-ref` less strictly, so update.sh
   refuses older versions. Check with `gh --version`. `flock` and `timeout` come with Raspberry
   Pi OS (util-linux and coreutils).
2. **A read-only GitHub token for gh.** `gh attestation verify` will not run without a login, even
   for a public repository. Do not use the browser login (`gh auth login` without a token): it
   asks for the `repo` scope, write access to every repository you can reach. Instead, on
   github.com, Settings, Developer settings, Fine-grained personal access tokens, Generate new
   token: resource owner your own account, **Repository access: Public repositories** (read-only),
   **no permissions** at all, and an expiry date. It can read only what is public anyway. Then on
   the Pi run `gh auth login --with-token`, paste the token, press Enter and then Ctrl-D, so the
   token never appears in a command line or the shell history. gh keeps it in
   `~/.config/gh/hosts.yml`, readable only by you (a Pi has no keyring, so gh warns that it is
   stored in plain text). `gh auth status` shows the login. When the token expires, update.sh
   refuses with gh's "please run: gh auth login" message: make a new one the same way.
3. **Registry login.** The image on ghcr.io is not public, so Docker on the Pi is logged in to
   ghcr.io: `docker login ghcr.io --username <your GitHub user> --password-stdin`, with a classic
   token that has only `read:packages` **and an expiry date** (renew it the same way). Docker
   stores it in `~/.docker/config.json`; run `chmod 600 ~/.docker/config.json` so only you can
   read it. gh reads that same Docker login to look up the image, so run update.sh as that user.
   (Making the package public on GitHub would remove the need for this token, since the image
   is built from this public repository; that is the owner's decision.)
4. **Check:** `./update.sh --check` prints `Verified ...` and changes nothing.

**From cron:** Raspberry Pi OS sends no mail, so send the output to the system journal instead of
discarding it (with your path):

```
*/5 * * * * /home/pi/secure-call-backend/deploy/raspberry-pi/update.sh 2>&1 | logger -t secure-call-update
```

Then `journalctl -t secure-call-update --since today` shows every run, refusals and token expiry
warnings included. The lock means a run that takes longer than 5 minutes is never overlapped by
the next one.

To look at what a published image contains, `docker buildx imagetools inspect
ghcr.io/the-secure-video-call/secure-call-backend:main --format '{{ json .SBOM }}'` shows its
SBOM, and `--format '{{ json .Provenance }}'` the BuildKit provenance.

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

**Limits:** the deny ranges cover RFC 1918, CGNAT and the other IANA special-purpose IPv4 blocks
listed in `coturn/turnserver.conf`; if the home LAN or Docker's address pools use public address
space, nothing denies it. The subnet `172.30.200.0/29` must not overlap
another Docker network. The deny list constrains peers requested through the TURN protocol, not
code running inside a compromised container: that could still reach the Pi's services through the
gateway `172.30.200.1`, which is why the container has no capabilities, no-new-privileges and a
read-only root. A `DOCKER-USER` firewall rule dropping traffic from the `turn` bridge to the Pi
is optional extra hardening. A bare `docker compose pull` also tries to pull
`secure-call-coturn:local`; `update.sh` only names the backend.

**Derived image:** `compose.yaml` builds `coturn/Dockerfile` (the pinned upstream image plus
removing the file capability from `turnserver`, running as 65534), so no capability needs adding
back. The first start, and every change to the Dockerfile, needs `docker compose up -d --build
coturn`. `update.sh` only pulls and restarts the backend, so it never builds or restarts
coturn (and, as `--build` is not used, never rebuilds it): upgrading coturn is a manual
`docker compose up -d --build coturn` after changing the digest in the Dockerfile.

**Changing only `coturn/turnserver.conf`** (for example the deny list): the file is bind-mounted,
not built into the image, and coturn reads it only at start. `--build` then changes nothing and
compose does not recreate the container. After `git pull`, run
`docker compose up -d --force-recreate coturn` (or `docker compose restart coturn`) when no call
is running.

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
   any of the three `TURN_*` values (or `POSTGRES_APP_PASSWORD`) also makes `update.sh` fail. Then `docker compose up -d --build coturn`.
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
6. **Image pin:** `coturn/Dockerfile` pins the base to `4.18.0` plus its `@sha256:` digest.
   Dependabot proposes upgrades (it watches `deploy/raspberry-pi/coturn`); the CI `coturn` job must
   pass before one is merged. After merging, rebuild on the Pi when no call is running:
   `git pull`, then `docker compose up -d --build coturn`.
   - **4.6.3 → 4.18.0 (#47):** 4.18 fixes published advisories that apply to this setup:
     GHSA-4v97-rxjj-4f99 (an IPv6 address comparison, fixed in 4.16.0), GHSA-m562-mf7x-q7rr
     (STUN length truncation on TCP, 4.15.0), GHSA-847g-qmc6-6m4r ("even-port" denial of
     service, 4.17.0) and GHSA-5538-7cxj-5jcc (attributes after MESSAGE-INTEGRITY, 4.15.0). It no
     longer sends reason texts in error replies and logs in a new format, so `test-coturn.sh`
     reads error codes and both formats. `no-dtls`, `no-cli` and `no-rfc5780` are deprecated or
     no-ops (DTLS, the CLI and RFC 5780 are off unless `dtls`, `cli` or `rfc5780` is set, and the
     test fails if one is), and `simple-log` does nothing with `log-file=stdout`, so all four are
     gone. The logging settings moved to the top of `turnserver.conf` and onto compose's command
     line: a warning logged before them made 4.18 open a default log file.

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
rate) is reached with fewer allocations per credential. The only brake on the number of
credentials is the backend's cap of 120 per client per hour, a client being an IPv4 address or an
IPv6 /64; an IPv6 /56 gets 480 and a /48 1,920 per hour in all (`signaling/rate_limits.py`). It
cannot be lower, because many people share one address, so 7 is well inside it.

A per-room credential budget was tried (#39) and removed: rooms are free to create and its count
reset when a room emptied, so it did not stop a hostile client, while a long call with many
reconnects could use it up and lose privacy mode. The per-IP cap has the same effect at a higher
threshold: over it, `joined` has no `turn` and privacy-mode calls fail closed for everyone on
that address (or IPv6 /56 or /48) until the hour window frees credentials.

**Decision (#55, ASVS V17.3.1 / V2.4.1): accepted limit of a single Pi; the credential cap stays
at 120 per client per hour.** Lowering it would not help: 7 credentials already fill the 41 ports,
so any cap that still lets a shared address (a household, an office, a mobile carrier's NAT) make
a call would also let one client make 7. A cap low enough to matter (6 or fewer per hour) would
lock out ordinary users who reconnect. Against sockets held open for nothing, the existing
10-minute limit on a member alone in a room (`WAITING_ALONE_LIMIT_SECONDS` in
`signaling/rooms.py`, close `room-expired`, restarted when a partner leaves) already frees the
connection slot and ends the room, so no new timeout was added.

So **one client can still fill the relay.** The impact is availability only: media stays
DTLS-SRTP encrypted and the peer deny list is unchanged; while the relay is full, privacy-mode
calls fail closed ("Privacy mode needs our relay...") and normal calls lose their TURN fallback
(direct calls still work). Closing this needs the relay to know who asked for a credential (for
example a per-client allocation count in coturn, or an authenticated user), which is outside
`turnserver.conf` in 4.18 and outside the current design (no accounts).

#### How long one allocation can live

`max-allocate-lifetime=600` limits each Allocate or Refresh to 10 minutes (coturn's default is
an hour), so a client that stops refreshing loses its relay port within 10 minutes. It does not
limit the total: a client can keep refreshing. coturn 4.18 has no option to refuse a Refresh after
the REST credential's expiry or to cap an allocation's total life. What it actually does is
checked by the CI probe (next sections). So an allocation lives as long as the client keeps
refreshing it, and the credential's expiry (up to the 4 h room lifetime) does not end it.

#### Accepted risk: Refresh with an expired credential (ASVS V9.2.1, Low)

Listed in the [security review](https://github.com/The-Secure-Video-Call/secure-call/blob/main/docs/security-review.md)
(section Gaps, V9.2.1) and accepted here (issue #54).

- **What coturn 4.18 does:** it refuses an expired credential for a new Allocate, but accepts a
  Refresh with one. A relay allocation can therefore outlive its credential and its room, for as
  long as the client keeps refreshing it. coturn has no option to refuse this or to cap an
  allocation's total life.
- **Credentials are not revoked on `leave`:** the signaling server hands out a stateless HMAC
  credential and keeps no list of them, so leaving a room does not invalidate it. It stays valid
  until its expiry (never later than the room's end).
- **Why it is acceptable:** it affects relay availability only (a relay port stays occupied
  longer than intended, within the quotas above). Media stays DTLS-SRTP encrypted, so the relay
  never sees it in the clear, and the peer deny list still applies to every allocation, so it
  cannot be used to reach private addresses.
- **How it is pinned:** the "Refresh-after-expiry probe" in `coturn/test-coturn.sh` (it
  prints `PASS: refresh after expiry is allowed, as documented`) fails if coturn's behaviour
  changes. Keep that check.
- **When to revisit:** on every coturn upgrade, re-run `test-coturn.sh` and reconsider this. If
  coturn gains a cap on allocation lifetime or can refuse a Refresh with an expired credential,
  turn it on, change `expected_refresh_after_expiry` to `refused`, and close #54. Until then,
  keep the issue open as the record.

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
  `192.0.0.1`, `240.0.0.1`, `255.255.255.255`, and `.1` and `.255` of `192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24` and `192.88.99.0/24`) get the same refusal, and their neighbours
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

**Backend:** `signal.securevideocall.com` must stay without an AAAA record until the backend with
the per-/56 and per-/48 rate limits (#38) is deployed; before that, one person with a /48 gets a
separate limit per /64.

This relay is IPv4-only. coturn runs on a network without IPv6 (`enable_ipv6: false`), relays on
the single address `172.30.200.2` (`--relay-ip`), and `turnserver.conf` sets
`allocation-default-address-family=ipv4`. An IPv6 relay request is answered with `440`. There is
no option that refuses IPv6 allocation more directly (4.6.3 and 4.18.0). The test
(`address_family_probe.py`) checks the `440` and the refusals of IPv6 and mapped peers (4.18
answers IPv4-mapped peers on an IPv4 relay with `443`, 4.6.3 with `403`; both are accepted); if
coturn answers differently, CI shows the real code.

coturn also *listens* only on `172.30.200.2` and `127.0.0.1` (`--listening-ip`). RFC 5780 NAT
behaviour discovery, which needs two public IPs and is not used by WebRTC, is off (the default in
4.18), and the pid file lives on the `/var/tmp` tmpfs because the root filesystem is read-only.
The test fails on any WARNING or ERROR line in coturn's startup output (except the two notices
about the unused default TLS certificate and key), so an option coturn does not understand shows
up in CI.
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

**Decision (#70, ASVS V16.3.4): coturn's errors stay discarded.** coturn has no setting that
prints errors but leaves out the username: the failed-login line is a normal error line and
carries the username, which holds a timestamp and a value derived from the room. Dropping only
those lines would need a filter between coturn and Docker, and a new moving part that handles
that output is worse than the gap. So no `turnserver.conf` change is made. A coturn that does
not start is still visible: the container exits, and `docker compose ps` shows it. Revisit if
coturn gains an option to leave usernames out of its error lines.

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
`allowed`, the only result seen so far (coturn 4.6.3 and 4.18.0; neither has an option to change
it), and a change
(for example after an image bump) fails the test so these notes get updated.


`coturn/refresh_after_expiry.py` allocates with a credential that expires 5 s later, waits 25 s
(the test runs coturn with `--stale-nonce=20`, so the nonce has been rotated by then), and sends a
Refresh, retrying once with the new nonce. CI prints `REFRESH AFTER EXPIRY: allowed` or
`REFRESH AFTER EXPIRY: refused`, and whether the server rotated the nonce.
An earlier probe, without a nonce rotation (CI run 42688739841), printed `allowed`. The result
of the probe across a nonce rotation is pending the next CI run.
With secure-call-backend#32 a credential lasts as long as the room (4 h), so this result is
informational: it only matters if the credential lifetime is ever shortened again.
