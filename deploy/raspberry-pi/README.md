# Raspberry Pi test server

`compose.yaml` runs the backend, PostgreSQL and coturn. First do the one-time setup under
"Updating the backend" below (gh and its token), then copy `.env.example` to `.env`, fill in the
values marked "set", run `./make-local-certs.sh` (README.md, "One-time setup on the Pi"),
and run `docker compose up -d postgres`, `./update.sh` and `docker compose up -d`, in that
order. Then install the firewall ("Firewall" below). compose never pulls the backend image itself
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

## Firewall

`firewall.sh` limits what this stack's containers can reach and who can reach them (#63). The Pi
runs other Docker projects too, so it touches only this stack's two bridges, which
`compose.yaml` names: `br-securecall` (backend and PostgreSQL, `172.30.200.16/28`) and `br-turn`
(coturn, `172.30.200.0/29`). Its rules live in two chains of its own: `SECURE-CALL-FWD`, jumped
to first from Docker's `DOCKER-USER` (which Docker runs before its own forwarding rules), and
`SECURE-CALL-IN`, jumped to first from `INPUT` (traffic to the Pi itself never passes
`DOCKER-USER`). Apart from those two jump rules it changes nothing outside its chains, and never
flushes a built-in or Docker chain. Every rule names one of the two bridges; the first rule of each
chain only lets packets of connections already allowed go on to the next rules (`RETURN`, not
`ACCEPT`), so it decides nothing for anyone else's traffic. Each run rebuilds both chains in one
atomic `iptables-restore --noflush`, so running it again is safe.

In this order (the first rule that matches decides):

| From or to the two bridges | What happens |
|---|---|
| Replies to allowed connections, related ICMP errors | go on to Docker's own rules |
| Backend and PostgreSQL to each other | allowed |
| New connections from `br-securecall` to anything else (internet, LAN, the Pi) | rejected (neither needs any; rejected rather than dropped, so a mistake shows at once instead of as a hang) |
| New connections from `br-turn` | public addresses only: never into `br-securecall` (not even through a published port on the Pi's address, such as PostgreSQL's), nor the ranges `coturn/turnserver.conf` denies (RFC 1918, CGNAT, loopback, link-local, reserved and documentation blocks), multicast, or the home's public IP (`TURN_PUBLIC_IP`) |
| Into the backend's published port (`BACKEND_PUBLISH_ADDR:8001`) | from `TRUSTED_PROXY_IPS` (the proxy) only; any other LAN device is dropped |
| Into PostgreSQL's published port | as published (`POSTGRES_PUBLISH_ADDR`, `127.0.0.1` by default: the Pi only) |
| New TCP connections to coturn's 3478 and 5349 | per source address: at most 64 open at once, 30 in a row, then 60 a minute |
| Into coturn | its published ports only: 3478 UDP and TCP, 5349 TCP, 49160-49200 UDP |
| New connections from either bridge to the Pi itself (gateway, LAN address, any other) | rejected (`br-securecall`) or dropped (`br-turn`), in `INPUT` |
| IPv6 from either bridge to the Pi | dropped (both networks are IPv4 only) |

`./firewall.sh --print` shows the exact rules without changing anything (it needs no root).
The proxy's IP comes from `TRUSTED_PROXY_IPS` in `.env` (or `--proxy-ip`), the public IP from
`TURN_PUBLIC_IP` (or `--turn-public-ip`). The script reads `.env` line by line and never runs it
(so `${...}` in a value is not expanded: write the address itself).

**When a value is wrong.** A bad value given with `--proxy-ip` or `--turn-public-ip` is refused,
and nothing changes. A value in `.env` (what the unit reads at boot) never leaves the Pi without
the rules: they are applied anyway and fail closed, and the script exits 1 so the unit shows as
failed. An IPv6 entry in `TRUSTED_PROXY_IPS` (the backend accepts those) is skipped with a
warning, as the backend's port is published on IPv4 only. Any other entry that is not an IPv4
address is left out with an error. With no usable IPv4 proxy address, **nobody** may connect to
the backend's published port until `.env` is fixed. Without a usable `TURN_PUBLIC_IP`, only the
rule for that one address is left out.

**TCP limits on coturn.** coturn has no per-address connection limit, and on 5349 every connection
costs a full TLS handshake (it keeps no session cache), which is heavy on a Pi. So, per source
address, `turn_tcp_max_connections_per_source=64` connections may be open at once,
`turn_tcp_new_connections_burst=30` may be opened in a row, and after that
`turn_tcp_new_connections_per_minute=60` (constants at the top of `firewall.sh`). A browser opens
one connection per TCP URL (TCP and TLS) per network interface it uses: 2 per caller, 4 during an
ICE restart (the old ones stay for a moment), 8 on two interfaces. Everyone behind one address
shares the limits: a household, but also a carrier-grade NAT, where one address can stand for
many mobile users. 64 open connections are 32 ordinary callers or 8 worst-case ones; a larger
crowd behind one address would see some TCP and TLS relay connections dropped (their UDP
candidates still work). Lower limits protect the Pi better and fit fewer people behind one
address; `tests/test_firewall.py` fails if they leave less room than 8 worst-case callers at once,
or 2 opening theirs in a row. The rate is remembered for 35 s after an address goes quiet (longer
than the 30 s a full burst takes to refill), in a table of at most 262,144 addresses. **Not
covered:** a flood from many addresses at once; and forged source addresses: a SYN flood with
random sources can fill that table, and while it is full, connections from addresses not yet in it
are dropped (TCP and TLS TURN only, UDP is unaffected) until entries expire. The table's name
carries a checksum of these values, so changed values take effect on the next run.
The limits count by the address the Pi sees, so the router must keep the callers' own
addresses on its port forwards (most do). Check during a call over TURN-over-TLS, on the Pi:
`sudo conntrack -L -p tcp --dport 5349` (from `sudo apt install conntrack`) must show the
callers' public addresses as `src=`, not the router's LAN address.

**Not covered:** for a few seconds after boot or a Docker restart, the containers run before the
unit has applied the rules (it has to run after Docker, which creates `DOCKER-USER`). Docker's
nftables firewall backend has no `DOCKER-USER`, and the script refuses to run with it. A home LAN
in public address space is not denied (as in `turnserver.conf`). A proxy on this Pi on the host
network (`BACKEND_PUBLISH_ADDR=127.0.0.1`) never passes these rules; a proxy container on
another Docker network of this Pi does, and its container address must then be in
`TRUSTED_PROXY_IPS`.

### Setup (once, on the Pi, in `deploy/raspberry-pi`)

**Keep a second SSH session open** while you do this. The rules only touch traffic from and to
the two bridges, never SSH or the Pi's own traffic, but if something goes wrong,
`sudo ./firewall.sh --remove` (once installed: `sudo secure-call-firewall --remove`) in that
session takes them all out. Until step 4, a reboot removes them too.

1. **Give the networks their bridge names** (right after the `git pull` that brings this, at a
   quiet time: calls drop for a moment): `docker compose down && docker compose up -d`. Never add
   `--volumes`, which deletes the database. Check (`ip` takes one device at a time):
   `ip -br addr show br-securecall` shows `172.30.200.17/28` and `ip -br addr show br-turn` shows
   `172.30.200.1/29`. Later `down`/`up` runs need nothing: the rules match
   the bridges by name.
2. **Check `.env`:** `TRUSTED_PROXY_IPS` is the proxy machine's LAN IP (the backend uses it too)
   and `TURN_PUBLIC_IP` is set. Then look at the rules: `./firewall.sh --print` must end without
   an `ERROR` line.
3. **Apply by hand and check:** `sudo ./firewall.sh`, then `sudo ./firewall.sh --check` (it shows
   the rules with their counters and ends with `Secure Call firewall: active.`),
   `curl https://signal.securevideocall.com/healthz` from outside the home, and a test call.
4. **Make it permanent** with the systemd unit. It runs a root-owned copy of the script (the
   repository can be changed by your login user, and the unit runs as root) and reads the two
   values from this folder's `.env` through a link that only root can change. It runs whenever
   Docker starts (`WantedBy=docker.service`) and again after every Docker restart
   (`PartOf=docker.service`):
   ```sh
   sudo install -o root -g root -m 0755 firewall.sh /usr/local/sbin/secure-call-firewall
   sudo install -o root -g root -m 0644 secure-call-firewall.service /etc/systemd/system/
   sudo install -d -o root -g root -m 0755 /etc/secure-call
   sudo ln -sfn "$PWD/.env" /etc/secure-call/firewall.env
   sudo systemctl daemon-reload
   sudo systemctl enable --now secure-call-firewall
   sudo secure-call-firewall --check
   ```
   **After every reboot** (and after a Docker update), check that it ran cleanly:
   `systemctl is-failed secure-call-firewall` must print `active`. `failed` means a value in
   `.env` is wrong (`journalctl -u secure-call-firewall` says which); the rules are in place
   anyway, failing closed, so the backend may be unreachable until it is fixed.
5. **Check from the containers.** For the `/dev/tcp` lines, exit code `124` (timed out) is what
   the firewall gives; `0` (connected) or `1` (refused) means the packet got through:
   ```sh
   # coturn: the router, the Pi itself (gateway and LAN address) and the LAN are unreachable ...
   docker compose exec coturn timeout 5 bash -c 'echo > /dev/tcp/<router LAN IP>/80'; echo $?
   docker compose exec coturn timeout 5 bash -c 'echo > /dev/tcp/172.30.200.1/22'; echo $?
   docker compose exec coturn timeout 5 bash -c 'echo > /dev/tcp/<this Pi LAN IP>/22'; echo $?
   # ... and the internet is reachable (0)
   docker compose exec coturn timeout 5 bash -c 'echo > /dev/tcp/1.1.1.1/443'; echo $?
   # The backend reaches PostgreSQL and nothing else (ConnectionRefusedError, at once)
   docker compose exec backend python manage.py migrate --check && echo database reachable
   docker compose exec backend python -c "import socket; socket.create_connection(('1.1.1.1', 443), 5)"
   # From a LAN device that is not the proxy: no answer at all (curl: timed out)
   curl -k --max-time 5 https://<this Pi LAN IP>:8001/healthz
   ```
   Then check the relay still works (TURN, step 5 below) and make a test call.

**Undo:** `sudo systemctl disable --now secure-call-firewall && sudo secure-call-firewall --remove`.
Stopping the unit (or Docker) alone leaves the rules in place.

**After a change:** to `TRUSTED_PROXY_IPS` or `TURN_PUBLIC_IP` in `.env`, run
`sudo systemctl restart secure-call-firewall`. To `firewall.sh` (after a `git pull`), repeat the
first `sudo install` line of step 4, then restart the unit. If `.env` moves, repeat the `ln` line.

**Tests:** `tests/test_firewall.py` runs the script against stand-ins for iptables (the exact
rules and their order, running twice, `--remove` leaving everything else as it was, refused and
fail-closed values, the same names and ports as `compose.yaml`, the same ranges as
`turnserver.conf`, and edited copies of those files and of the unit to show the checks catch a
change). CI (`ci/test-firewall.sh`) applies it on the runner, with the backend and a stand-in for
coturn on their real bridges, a network namespace as the home network, and each check run without
the firewall first: the backend reaches PostgreSQL but not the internet, the LAN or the runner;
only the stand-in proxy reaches the backend's published port (with an IPv6 entry in
`TRUSTED_PROXY_IPS` skipped); coturn's network reaches the internet but not the LAN (10/8,
172.16/12, 192.168/16), the stand-in home public address, the runner, or PostgreSQL's port
published on every address, and only coturn's ports are reachable from outside, with the TCP
limits holding; another container is unaffected; the unit re-applies after Docker restarts; and
`--remove` leaves no rule behind. Not tested in CI: a reboot, the Pi's own kernel and iptables,
and IPv6 (CI's containers have no IPv6 to try it with).

## TURN

coturn relays media for callers behind strict NATs. It runs on its **own Docker bridge network**
(`turn`, Linux bridge `br-turn`, subnet `172.30.200.0/29`, no IPv6, coturn at the fixed address
`172.30.200.2`, the Pi as gateway `172.30.200.1`) with the hardened config in
`coturn/turnserver.conf`. The config refuses to
relay to private, loopback, link-local and multicast addresses, so a credential holder cannot reach
your home network. Do not remove those lines.

Published ports (only on the Pi's LAN address, `TURN_RELAY_IP`, never on every interface):
`3478` UDP and TCP, `5349` TCP (TURN over TLS), and `49160-49200` UDP.

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
space, nothing denies it. The subnets `172.30.200.0/29` (`turn`) and `172.30.200.16/28`
(`internal`) must not overlap another Docker network. The deny list constrains peers requested
through the TURN protocol, not code running inside a compromised container. For that,
`firewall.sh` (see "Firewall" above) drops every new connection from the `br-turn` bridge to a
non-public address (in `DOCKER-USER`, mirroring the deny list) and to the Pi itself (in `INPUT`:
the gateway `172.30.200.1`, the Pi's LAN address and any other; traffic to the Pi never passes
`DOCKER-USER`, so a rule there alone would not stop it). The container also has no capabilities,
no-new-privileges and a read-only root. A bare `docker compose pull` also tries to pull
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
2. **Router port forwards to the Pi:** `3478` UDP and TCP, `5349` TCP, and `49160-49200` UDP.
   Forward nothing else for TURN (no 5349 UDP: DTLS is off; no 443, which is the proxy's).
3. **Secret:** in `deploy/raspberry-pi`, run `./make-turn-secret.sh` (it asks for sudo). It
   makes a random secret and writes it, never printing it, to the two files compose mounts:
   `secrets/turn-static-auth-secret.conf` for coturn (owner 65534, mode 400) and
   `secrets/turn-shared-secret` for the backend (owner 10001, mode 400). coturn joins it to
   its config in memory at start, so it is on no command line and in no environment: neither
   `ps` nor `docker inspect` shows it (CI checks that). It also makes `.env` mode 600.
   **Rotating:** run it again, then `docker compose up -d --force-recreate coturn backend` at a
   quiet time (credentials issued with the old secret stop working). Never commit `secrets/`.
   Also set `TURN_PUBLIC_IP` (the home's public IPv4, which must be static: if it changes, update
   `.env` and restart coturn). Compose passes it as `--external-ip=<public IP>/172.30.200.2` and also as
   `--denied-peer-ip=<public IP>` (defence in depth; relay-to-relay still works with it).
   And set `TURN_RELAY_IP` to the Pi's LAN IPv4 (its default-route address, since Docker's NAT
   sends outgoing relay traffic from there): the ports are published on that address only.
   Compose refuses to start without either value; as it checks the whole file, a `.env` missing
   either `TURN_*` value (or `POSTGRES_APP_PASSWORD`) also makes `update.sh` fail. Then do step
   3b and `docker compose up -d --build coturn`.
   On the Pi, use zram or no swap: swapped memory (the secret, and the in-memory log mounts
   below) could otherwise reach the SD card. `ulimits: core: 0` already prevents core dumps.
3b. **Certificate for TURN over TLS (`turns:`, port 5349):** browsers check it, so it must be
   publicly trusted. Nginx Proxy Manager gets and renews it (port 80 reaches the proxy), and a
   timer on this Pi copies every renewal to coturn (#90).
   - In Nginx Proxy Manager: **SSL Certificates → Add SSL Certificate → Let's Encrypt**,
     domain `turn.securevideocall.com` (the A record of step 1). Then, on the proxy machine,
     this prints the certificate's folder name, `npm-<N>`, which the steps below use:
     ```sh
     docker exec nginx-proxy-manager-app-1 sh -c 'grep -l turn.securevideocall.com /etc/letsencrypt/renewal/*.conf'
     ```
   - **How the copy works:** twice a day, `secure-call-turn-certificate.timer` starts
     `secure-call-turn-certificate.service`, which runs in two steps:
     1. As `turn-certificate-fetch`, a user with no rights of its own,
        `coturn/fetch-turn-certificate.sh` logs in to the proxy machine with an SSH key of its own.
        The proxy machine accepts that key only from this Pi, and only for one command,
        `coturn/print-turn-certificate.sh`. That command prints the certificate's `fullchain.pem`
        and `privkey.pem` and nothing else, whatever the client asks for. The key gets no shell
        and no forwarding. The answer goes into memory (`/run`), and must be nothing but
        certificates followed by one key.
     2. Only then, as root, `install-turn-certificate.sh` checks the certificate and installs it
        if it changed.

     The private key is never printed or logged, and is written nowhere but memory and
     `coturn/tls/`. The SSH key can fetch only what coturn holds anyway.
   - **On this Pi (part 1):** the user for the first step, and the SSH key, in a folder only root
     can read. The key has no passphrase, as the timer runs unattended. Copy the line the last
     command prints:
     ```sh
     sudo adduser --system --group --no-create-home --home /nonexistent turn-certificate-fetch
     sudo install -d -o root -g root -m 0700 /etc/secure-call/turn-certificate
     sudo ssh-keygen -q -t ed25519 -N '' -C secure-call-turn-certificate -f /etc/secure-call/turn-certificate/id_ed25519
     sudo cat /etc/secure-call/turn-certificate/id_ed25519.pub
     ```
   - **On the proxy machine:** an account for that key that can run one command only. **Keep a
     second SSH session open** while you do this, in case a sudo or sshd change goes wrong. Copy
     `coturn/print-turn-certificate.sh` there (for example with `scp`). Then, in the folder you
     copied it to, run this, with `npm-<N>` from above, this Pi's LAN IP and the line from part 1:
     ```sh
     sudo install -o root -g root -m 0755 print-turn-certificate.sh /usr/local/sbin/secure-call-print-turn-certificate
     sudo adduser --system --group --shell /bin/sh --home /var/lib/turn-certificate turn-certificate
     sudo chown root:root /var/lib/turn-certificate
     sudo chmod 0755 /var/lib/turn-certificate
     echo 'Defaults!/usr/local/sbin/secure-call-print-turn-certificate !log_output' > turn-certificate.sudoers
     echo 'turn-certificate ALL=(root) NOPASSWD: /usr/local/sbin/secure-call-print-turn-certificate nginx-proxy-manager-app-1 npm-<N>' >> turn-certificate.sudoers
     sudo visudo -cf turn-certificate.sudoers && sudo install -o root -g root -m 0440 turn-certificate.sudoers /etc/sudoers.d/secure-call-turn-certificate
     sudo install -d -o root -g root -m 0755 /var/lib/turn-certificate/.ssh
     echo 'restrict,from="<this Pi LAN IP>",command="LC_ALL=C sudo -n /usr/local/sbin/secure-call-print-turn-certificate nginx-proxy-manager-app-1 npm-<N>" <the line from part 1>' | sudo tee /var/lib/turn-certificate/.ssh/authorized_keys
     sudo tee -a /etc/ssh/sshd_config <<'EOF'

     # secure-call-backend #90: the coturn Pi's key may only fetch the TURN certificate.
     Match User turn-certificate
         AuthenticationMethods publickey
         DisableForwarding yes
         PermitTTY no
         PermitTunnel no
         PermitUserRC no
         ForceCommand LC_ALL=C sudo -n /usr/local/sbin/secure-call-print-turn-certificate nginx-proxy-manager-app-1 npm-<N>
     Match all
     EOF
     sudo sshd -t && sudo systemctl reload ssh
     sudo sshd -T -C user=turn-certificate,host=pi,addr=<this Pi LAN IP> | grep -Ei '^(forcecommand|disableforwarding|permittty) '
     sudo sshd -T -C user="$USER",host=pi,addr=<this Pi LAN IP> | grep -i '^forcecommand '
     ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
     ```
     - **The account** has no password. Its only right is that sudo line, which allows exactly
       that command line, with no other arguments, and never records the command's output
       (`!log_output`, which would put the key on the disk). The file is installed only if
       `visudo -cf` accepts it, as a broken file in `/etc/sudoers.d/` would stop sudo working. The
       account's home, `.ssh` and `authorized_keys` belong to root, so the account cannot change
       them.
     - **Two locks:** `restrict` turns off the terminal, every kind of forwarding and `~/.ssh/rc`;
       `from=` accepts the key only from this Pi; `command=` runs that command whatever the
       client asks for, in the C locale whatever the client sends (`LC_*`). The `Match` block at
       the end of `sshd_config` enforces the same again for the account, whatever its
       `authorized_keys` says. `Match all` closes it, so lines added to the file later apply to
       everyone again.
     - **Checks:** `sshd -t` must print nothing, and sshd is reloaded only then; if it prints an
       error, fix `sshd_config` before you close the other session. The first `sshd -T` command
       must print the `forcecommand` line above, `disableforwarding yes` and `permittty no`; the
       second, for your own login, `forcecommand none`. Note the fingerprint the last command
       prints.
     - If `/etc/ssh/sshd_config` has an `AllowUsers` or `AllowGroups` line, add
       `turn-certificate` to it.
   - **On this Pi (part 2),** in `deploy/raspberry-pi`, with the proxy machine's LAN IP. First the
     proxy's login and host key:
     ```sh
     echo 'turn-certificate@<proxy LAN IP>' | sudo tee /etc/secure-call/turn-certificate/proxy
     ssh-keyscan -t ed25519 <proxy LAN IP> 2>/dev/null | sudo tee /etc/secure-call/turn-certificate/known_hosts
     sudo ssh-keygen -lf /etc/secure-call/turn-certificate/known_hosts
     ```
     The fingerprint must be the one the proxy machine printed. If it is not, run
     `sudo rm /etc/secure-call/turn-certificate/known_hosts` and stop. If the proxy's SSH listens
     on another port, write `turn-certificate@<proxy LAN IP>:<port>` and use
     `ssh-keyscan -p <port>`. Then root-owned copies of the two scripts (the unit runs them, and
     your login user can change the repository), a link to this checkout's `coturn/`, the
     units, and a first run:
     ```sh
     sudo install -D -o root -g root -m 0755 -t /usr/local/lib/secure-call coturn/fetch-turn-certificate.sh coturn/install-turn-certificate.sh
     sudo ln -sfn "$PWD/coturn" /etc/secure-call/turn-certificate/coturn
     sudo install -o root -g root -m 0644 coturn/secure-call-turn-certificate.service coturn/secure-call-turn-certificate.timer /etc/systemd/system/
     sudo systemctl daemon-reload
     sudo systemctl start secure-call-turn-certificate.service
     journalctl -u secure-call-turn-certificate.service -n 20
     sudo systemctl enable --now secure-call-turn-certificate.timer
     ```
     The journal must end with `Installed the certificate for turn.securevideocall.com, valid
     until ...` (the first time) or `The certificate is already installed`.
     `systemctl list-timers secure-call-turn-certificate.timer` shows the next run.
   - **What is checked:** the fetch refuses an answer that:
     - is larger than 64 KiB;
     - holds anything but certificates followed by one private key (a banner, a blank line, text
       after the key, Windows line ends);
     - comes from a login that ran the fetch's own command, because neither `command=` nor
       `ForceCommand` forces one for the key. The message says so.

     Then the install script refuses a certificate that does not name
     `turn.securevideocall.com`, does not chain to a trusted CA, expires within 7 days or does not
     match the key, and a chain file that holds anything but certificates. It installs into
     `coturn/tls/` (key owner 65534, mode 400) and tells a running coturn to reload the
     certificate (`SIGUSR2`): calls in progress keep their relays. If the certificate has not
     changed, it does nothing.
   - **When a run fails,** `journalctl -u secure-call-turn-certificate.service` says why, and
     `systemctl status secure-call-turn-certificate.service` shows `failed`. Common causes:
     - `Host key verification failed`: the proxy's host key changed. Repeat the `ssh-keyscan`
       check.
     - `Permission denied (publickey)`: check the `authorized_keys` line, its `from=` address,
       and `AllowUsers`.
     - `sudo: a password is required`: the sudoers line must match the command after `sudo -n`
       in `command=` and `ForceCommand` exactly.
     - `does not belong to the certificate`: a renewal landed between the two files. The next
       run fixes it.
   - **Renewal:** Nginx Proxy Manager renews the certificate by itself about 30 days before it
     expires, and the next run copies it. Let's Encrypt's certificates get shorter (64 days from
     February 2027, 45 from February 2028), which changes nothing here. Keep this daily cron line
     (`crontab -e`) as a check that does not depend on the timer. It asks coturn itself, and logs
     a warning 21 days ahead (`journalctl -t secure-call-turn`):
     ```
     0 9 * * * echo | openssl s_client -connect turn.securevideocall.com:5349 -servername turn.securevideocall.com 2>/dev/null | openssl x509 -noout -checkend 1814400 >/dev/null || logger -t secure-call-turn "TURN certificate expires within 21 days"
     ```
   - **After a change** (each run warns in the journal when a root-owned copy differs from the
     checkout):
     - a `git pull` that changes `coturn/fetch-turn-certificate.sh` or
       `coturn/install-turn-certificate.sh`: repeat the `sudo install -D` line;
     - one that changes a unit: repeat its `sudo install` line, then `sudo systemctl daemon-reload`;
     - one that changes `coturn/print-turn-certificate.sh`: copy it to the proxy machine again and
       repeat its `sudo install` line there;
     - the certificate deleted and added again in Nginx Proxy Manager: it gets a new `npm-<N>`.
       Change it in the sudoers line, the `authorized_keys` line and `ForceCommand`, then
       `sudo sshd -t && sudo systemctl reload ssh`;
     - the checkout moved: repeat the `ln` line.
   - **By hand** (for example before the proxy machine's account exists): fetch both files
     straight from the proxy machine into memory, so the key never lands on either SD card.
     `<proxy>` is your own SSH login on the proxy machine. The install runs with `sudo`, as
     `coturn/tls/` belongs to root once the timer has created it:
     ```sh
     umask 077
     ssh <proxy> 'docker exec nginx-proxy-manager-app-1 cat /etc/letsencrypt/live/npm-<N>/fullchain.pem' > /dev/shm/turn-fullchain.pem
     ssh <proxy> 'docker exec nginx-proxy-manager-app-1 cat /etc/letsencrypt/live/npm-<N>/privkey.pem' > /dev/shm/turn-privkey.pem
     sudo ./coturn/install-turn-certificate.sh /dev/shm/turn-fullchain.pem /dev/shm/turn-privkey.pem
     rm /dev/shm/turn-fullchain.pem /dev/shm/turn-privkey.pem
     ```
   - **Undo,** on both machines (removing only this Pi's side leaves the key working):
     - on this Pi:
       ```sh
       sudo systemctl disable --now secure-call-turn-certificate.timer
       sudo rm /etc/systemd/system/secure-call-turn-certificate.service /etc/systemd/system/secure-call-turn-certificate.timer
       sudo systemctl daemon-reload
       sudo rm -r /etc/secure-call/turn-certificate /usr/local/lib/secure-call
       sudo deluser --system turn-certificate-fetch
       ```
     - on the proxy machine: delete the lines from the `# secure-call-backend #90` comment to
       `Match all` at the end of `/etc/ssh/sshd_config` (`sudo nano /etc/ssh/sshd_config`), then:
       ```sh
       sudo sshd -t && sudo systemctl reload ssh
       sudo rm /etc/sudoers.d/secure-call-turn-certificate /usr/local/sbin/secure-call-print-turn-certificate
       sudo deluser --system --remove-home turn-certificate
       ```
   - **Accepted limit:** TURN over UDP (3478) still sends the TURN username and the peer
     permissions in plaintext (the media itself is DTLS-SRTP either way). UDP is kept for call
     quality; the TCP fallback is TLS only (`turns:`, no plain `turn:` TCP URL).
   - **Check:** `openssl s_client -brief -connect turn.securevideocall.com:5349 -servername
     turn.securevideocall.com </dev/null` shows `Verification: OK` and `TLSv1.3`.
4. **Backend `TURN_URLS`:** it is the switch (the secret file is always there); keep it unset until
   The-Secure-Video-Call/secure-call#47 is live. `TURN_URLS` is commented out in `.env.example`:
   uncomment it only after the rate limits (#35) are live and DNS and the router forwards are done.
5. **Check it works:**
   - **On the Pi**, create a short-lived test credential. Read the secret there
     (`SECRET=$(sudo cat secrets/turn-shared-secret)`), then:
     `user=$(( $(date +%s) + 600 )); pass=$(printf %s "$user" | openssl dgst -sha1 -hmac "$SECRET" -binary | openssl base64); echo "$user $pass"`.
     Copy only that username and password to the other machine, never the shared secret. They
     stop working after 10 minutes.
   - From another machine, run
     `turnutils_uclient -u "$user" -w "$pass" -e 8.8.8.8 -n 1 -m 1 turn.securevideocall.com`.
   - Or open https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/, add
     `turn:turn.securevideocall.com:3478` with that username and password, and gather: a
     `relay` candidate should appear. Then the same with
     `turns:turn.securevideocall.com:5349?transport=tcp` (TURN over TLS).
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
from how browsers gather relay candidates: one allocation per TURN URL (we send two: UDP on 3478
and TLS on 5349)
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
Dockerfile): with compose's own entrypoint (the start script ending in `exec turnserver`) the
upstream image's own switch to an unprivileged
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
started by a short `sh -c` script that only copies the secret file into its config in memory
and then `exec`s turnserver, so no shell ever expands the secret and turnserver is pid 1.

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
