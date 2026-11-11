#!/usr/bin/env bash
# CI only (.github/workflows/ci.yml, check job): the automatic refresh of coturn's certificate
# (#90), set up on the runner with the commands of README.md, TURN step 3b, and run by the real
# unit under systemd, sandbox included. The runner is both machines: its own sshd (127.0.0.1), the
# account turn-certificate and a container named like Nginx Proxy Manager's stand in for the proxy
# machine, and this checkout for the coturn Pi. It checks that:
#   - the first run installs the certificate (key owner 65534, mode 400) and logs the outcome;
#   - a second run changes nothing, and a renewed certificate in the container is installed;
#   - a certificate for another name is refused, and what is installed stays;
#   - either lock alone (authorized_keys or sshd_config) forces the command, and a key with
#     neither is refused and named;
#   - the key opens no shell, terminal or forwarding, and sudo runs nothing else for the account;
#   - no line of a private key is ever in the journal, and no fetched file is left behind.
# A test CA is added to the runner's trust store for the run, as Let's Encrypt cannot issue here.
# The proxy machine runs Raspberry Pi OS (Debian bookworm) with classic sudo, so the runner is
# switched to classic sudo first (Ubuntu 25.10 and later default to sudo-rs, whose sudoers
# dialect differs: it has no log_output, for one).
# Needs Docker, passwordless sudo, systemd, openssl, and the backend image (built by a step
# before; it stands in for Nginx Proxy Manager's image). Run from deploy/raspberry-pi.
set -euo pipefail
cd "$(dirname "$0")/.."

readonly CONFIG_DIR=/etc/secure-call/turn-certificate
readonly CONTAINER=nginx-proxy-manager-app-1
readonly CERTIFICATE=npm-30
readonly PRINT_SCRIPT=/usr/local/sbin/secure-call-print-turn-certificate
readonly PRINT_COMMAND="$PRINT_SCRIPT $CONTAINER $CERTIFICATE"
readonly STAND_IN_IMAGE=ghcr.io/the-secure-video-call/secure-call-backend:main
readonly TEST_CA_IN_STORE=/usr/local/share/ca-certificates/secure-call-ci-test-ca.crt
readonly UNIT=secure-call-turn-certificate.service
readonly FORCED_COMMAND="LC_ALL=C sudo -n $PRINT_COMMAND"
work="$(mktemp -d)"
live="$work/live"
failures=0

fail() {
  echo "FAIL: $*"
  failures=$((failures + 1))
}
pass() { echo "PASS: $*"; }

reload_sshd() { sudo sshd -t && { sudo systemctl reload ssh 2>/dev/null || sudo systemctl restart ssh; }; }

cleanup() {
  set +e
  sudo systemctl disable --now secure-call-turn-certificate.timer >/dev/null 2>&1
  sudo rm -f "/etc/systemd/system/$UNIT" /etc/systemd/system/secure-call-turn-certificate.timer
  sudo systemctl daemon-reload
  sudo rm -rf /usr/local/lib/secure-call "$CONFIG_DIR" /etc/sudoers.d/secure-call-turn-certificate \
    "$PRINT_SCRIPT" coturn/tls
  if [ -f "$work/sshd_config.before" ]; then
    sudo cp "$work/sshd_config.before" /etc/ssh/sshd_config
    reload_sshd
  fi
  sudo deluser --system --remove-home turn-certificate >/dev/null 2>&1
  sudo deluser --system turn-certificate-fetch >/dev/null 2>&1
  sudo rm -f "$TEST_CA_IN_STORE"
  sudo update-ca-certificates --fresh >/dev/null 2>&1
  docker rm -f "$CONTAINER" >/dev/null 2>&1
  rm -rf "$work"
}
trap cleanup EXIT

# $1 = name, $2 = host name: $work/$1.key and $work/$1.fullchain.pem, signed by the test CA.
make_certificate() {
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/$1.key"
  openssl req -new -key "$work/$1.key" -subj "/CN=$2" -out "$work/$1.csr"
  printf '%s\n' basicConstraints=critical,CA:FALSE keyUsage=critical,digitalSignature \
    extendedKeyUsage=serverAuth "subjectAltName=DNS:$2" >"$work/$1.ext"
  openssl x509 -req -in "$work/$1.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" \
    -set_serial "0x$(openssl rand -hex 8)" -days 60 -extfile "$work/$1.ext" \
    -out "$work/$1.crt" 2>/dev/null
  cat "$work/$1.crt" "$work/ca.crt" >"$work/$1.fullchain.pem"
}

# What the container's /etc/letsencrypt/live/npm-30/ holds: $1's certificate and key.
put_in_container() {
  cp "$work/$1.fullchain.pem" "$live/fullchain.pem"
  cp "$work/$1.key" "$live/privkey.pem"
}

journal_cursor() { sudo journalctl -n 1 -q --no-pager --show-cursor | sed -n 's/^-- cursor: //p'; }

# One run of the unit: its exit status, and the unit's journal lines in $work/journal.
run_unit() {
  local status=0 cursor
  cursor="$(journal_cursor)"
  # This script starts the unit more often than systemd's start limit (5 in 10 s) allows.
  sudo systemctl reset-failed "$UNIT" 2>/dev/null || true
  sudo systemctl start "$UNIT" || status=$?
  sudo journalctl --sync
  # shellcheck disable=SC2024 # the runner's own user writes its own file
  sudo journalctl --no-pager -q -o cat -u "$UNIT" --after-cursor "$cursor" >"$work/journal"
  sed 's/^/    journal: /' "$work/journal"
  return "$status"
}

installed_key_is() { sudo cmp -s "$work/$1.key" coturn/tls/privkey.pem; }

# ssh with the Pi's key, as the fetch would ($@ = more options, then the command if any).
ssh_as_the_pi() {
  sudo ssh -F none -n -o BatchMode=yes -o IdentitiesOnly=yes -i "$CONFIG_DIR/id_ed25519" \
    -o UserKnownHostsFile="$CONFIG_DIR/known_hosts" -o StrictHostKeyChecking=yes \
    -o ExitOnForwardFailure=yes -o ConnectTimeout=10 "$@"
}

# Classic sudo for sudo and visudo: through Ubuntu's alternatives if it has them, otherwise
# through links in /usr/local, which comes first on PATH and in sudo's secure_path.
use_classic_sudo() {
  local name classic
  if [ ! -x /usr/bin/sudo.ws ] && ! sudo -V 2>/dev/null | grep -q '^Sudo version 1\.'; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq sudo >/dev/null
  fi
  for name in sudo visudo; do
    classic="$(update-alternatives --list "$name" 2>/dev/null | grep '\.ws$' | head -n 1 || true)"
    if [ -n "$classic" ]; then sudo update-alternatives --set "$name" "$classic" >/dev/null; fi
  done
  if ! sudo -V 2>/dev/null | grep -q '^Sudo version 1\.' && [ -x /usr/bin/sudo.ws ]; then
    sudo ln -sfn /usr/bin/sudo.ws /usr/local/bin/sudo
  fi
  if ! sudo visudo -V 2>/dev/null | grep -q '^visudo version 1\.' && [ -x /usr/sbin/visudo.ws ]; then
    sudo ln -sfn /usr/sbin/visudo.ws /usr/local/sbin/visudo
  fi
  hash -r
}

echo "== Setup =="
start_cursor="$(journal_cursor)"
use_classic_sudo
sudo_version="$(sudo -V 2>/dev/null | head -n 1 || true)"
visudo_version="$(sudo visudo -V 2>/dev/null | head -n 1 || true)"
if [[ $sudo_version == "Sudo version 1."* && $visudo_version == "visudo version 1."* ]]; then
  pass "classic sudo, as on the proxy machine: $sudo_version, $visudo_version"
else
  echo "Classic sudo is needed; sudo says '$sudo_version', visudo '$visudo_version'."
  exit 1
fi
openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -subj /CN=secure-call-ci-test-ca -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign -keyout "$work/ca.key" -out "$work/ca.crt" \
  2>/dev/null
sudo install -m 0644 "$work/ca.crt" "$TEST_CA_IN_STORE"
sudo update-ca-certificates >/dev/null
make_certificate first turn.securevideocall.com
make_certificate renewed turn.securevideocall.com
make_certificate wrong-name turn.example.invalid
mkdir -m 0755 "$live"
put_in_container first
chmod 0644 "$live"/*
docker run -d --name "$CONTAINER" --user 0:0 --entrypoint sleep \
  -v "$live:/etc/letsencrypt/live/$CERTIFICATE:ro" "$STAND_IN_IMAGE" infinity >/dev/null

if [ ! -x /usr/sbin/sshd ]; then
  sudo apt-get update -qq
  sudo apt-get install -y -qq openssh-server >/dev/null
fi
# Ubuntu may start sshd through ssh.socket.
if ! ssh-keyscan -t ed25519 127.0.0.1 >/dev/null 2>&1; then
  sudo systemctl start ssh.socket 2>/dev/null || sudo systemctl start ssh
fi
for attempt in $(seq 1 20); do
  if ssh-keyscan -t ed25519 127.0.0.1 >/dev/null 2>&1; then break; fi
  if [ "$attempt" = 20 ]; then
    echo "sshd does not answer on 127.0.0.1:22"
    sudo systemctl status ssh.socket ssh.service --no-pager || true
    exit 1
  fi
  sleep 0.5
done
sudo cp /etc/ssh/sshd_config "$work/sshd_config.before"

# The coturn Pi's part 1.
sudo adduser --system --group --no-create-home --home /nonexistent turn-certificate-fetch \
  >/dev/null
sudo install -d -o root -g root -m 0700 "$CONFIG_DIR"
sudo ssh-keygen -q -t ed25519 -N '' -C secure-call-turn-certificate -f "$CONFIG_DIR/id_ed25519"
public_key="$(sudo cat "$CONFIG_DIR/id_ed25519.pub")"

# The proxy machine's part (the script comes from this checkout).
sudo install -o root -g root -m 0755 coturn/print-turn-certificate.sh "$PRINT_SCRIPT"
sudo adduser --system --group --shell /bin/sh --home /var/lib/turn-certificate turn-certificate \
  >/dev/null
sudo chown root:root /var/lib/turn-certificate
sudo chmod 0755 /var/lib/turn-certificate
echo "Defaults!$PRINT_SCRIPT !log_output" >"$work/turn-certificate.sudoers"
echo "turn-certificate ALL=(root) NOPASSWD: $PRINT_COMMAND" >>"$work/turn-certificate.sudoers"
sudo visudo -cf "$work/turn-certificate.sudoers" \
  && sudo install -o root -g root -m 0440 "$work/turn-certificate.sudoers" \
    /etc/sudoers.d/secure-call-turn-certificate
sudo install -d -o root -g root -m 0755 /var/lib/turn-certificate/.ssh
forced_line="restrict,from=\"127.0.0.1\",command=\"$FORCED_COMMAND\" $public_key"
echo "$forced_line" | sudo tee /var/lib/turn-certificate/.ssh/authorized_keys >/dev/null
sudo tee -a /etc/ssh/sshd_config >/dev/null <<EOF

# secure-call-backend #90: the coturn Pi's key may only fetch the TURN certificate.
Match User turn-certificate
    AuthenticationMethods publickey
    DisableForwarding yes
    PermitTTY no
    PermitTunnel no
    PermitUserRC no
    ForceCommand $FORCED_COMMAND
Match all
EOF
sudo cp /etc/ssh/sshd_config "$work/sshd_config.locked"
reload_sshd
effective="$(sudo sshd -T -C user=turn-certificate,host=pi,addr=127.0.0.1)"
others="$(sudo sshd -T -C "user=$USER,host=pi,addr=127.0.0.1")"
if grep -qx "forcecommand $FORCED_COMMAND" <<<"$effective" \
  && grep -qx 'disableforwarding yes' <<<"$effective" && grep -qx 'permittty no' <<<"$effective" \
  && grep -qx 'forcecommand none' <<<"$others"; then
  pass "sshd -T: the Match block applies to turn-certificate only"
else
  fail "sshd -T for turn-certificate: $(grep -E '^(forcecommand|disableforwarding|permittty) ' \
    <<<"$effective" | tr '\n' ';'); for $USER: $(grep '^forcecommand ' <<<"$others")"
fi

# The coturn Pi's part 2.
echo 'turn-certificate@127.0.0.1' | sudo tee "$CONFIG_DIR/proxy" >/dev/null
ssh-keyscan -t ed25519 127.0.0.1 2>/dev/null | sudo tee "$CONFIG_DIR/known_hosts" >/dev/null
known="$(sudo ssh-keygen -lf "$CONFIG_DIR/known_hosts" | awk '{ print $2 }')"
actual="$(ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{ print $2 }')"
if [ -n "$known" ] && [ "$known" = "$actual" ]; then
  pass "the README's host key check matches the proxy's fingerprint"
else
  fail "host key fingerprints: known_hosts '$known', sshd '$actual'"
fi
sudo install -D -o root -g root -m 0755 -t /usr/local/lib/secure-call \
  coturn/fetch-turn-certificate.sh coturn/install-turn-certificate.sh
sudo ln -sfn "$PWD/coturn" "$CONFIG_DIR/coturn"
sudo install -o root -g root -m 0644 "coturn/$UNIT" coturn/secure-call-turn-certificate.timer \
  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now secure-call-turn-certificate.timer
if systemctl list-timers --all --no-pager | grep -q secure-call-turn-certificate.timer; then
  pass "the timer is scheduled"
else
  fail "the timer is not scheduled"
fi

echo "== The first run installs the certificate =="
if run_unit && grep -q 'Fetched a certificate and a key' "$work/journal" \
  && grep -q 'Installed the certificate for turn.securevideocall.com' "$work/journal" \
  && installed_key_is first && cmp -s "$work/first.fullchain.pem" coturn/tls/fullchain.pem; then
  pass "installed"
else
  fail "the first run did not install the certificate"
fi
owner_and_mode="$(sudo stat -c '%u %a' coturn/tls/privkey.pem 2>/dev/null || true)"
if [ "$owner_and_mode" = "65534 400" ]; then
  pass "the key belongs to coturn's user, mode 400"
else
  fail "the key's owner and mode: '$owner_and_mode'"
fi
if grep -q 'coturn is not running' "$work/journal"; then
  pass "coturn, not running in this job, is left alone"
else
  fail "the journal does not say what happened to coturn"
fi
if grep -q 'WARNING' "$work/journal"; then
  fail "a warning in the journal (a copy that differs from the checkout?)"
fi

echo "== A second run changes nothing; a renewal is installed =="
if run_unit && grep -q 'already installed' "$work/journal" && installed_key_is first; then
  pass "unchanged"
else
  fail "a second run with the same certificate"
fi
put_in_container renewed
if run_unit && grep -q 'Installed the certificate' "$work/journal" && installed_key_is renewed; then
  pass "the renewed certificate is installed"
else
  fail "the renewed certificate was not installed"
fi

echo "== Refused =="
put_in_container wrong-name
if ! run_unit && grep -q 'does not name turn.securevideocall.com' "$work/journal" \
  && installed_key_is renewed; then
  pass "a certificate for another name is refused, and the installed one stays"
else
  fail "a certificate for another name"
fi
put_in_container renewed

echo "== Each lock alone forces the command; neither is refused =="
echo "$public_key" | sudo tee /var/lib/turn-certificate/.ssh/authorized_keys >/dev/null
if run_unit && grep -q 'already installed' "$work/journal"; then
  pass "a bare authorized_keys line: sshd_config's ForceCommand still forces the command"
else
  fail "a bare authorized_keys line with the Match block"
fi
sudo cp "$work/sshd_config.before" /etc/ssh/sshd_config
reload_sshd
if ! run_unit && grep -q 'can open a shell there' "$work/journal" && installed_key_is renewed; then
  pass "neither lock: the key is refused, and named"
else
  fail "neither lock"
fi
echo "$forced_line" | sudo tee /var/lib/turn-certificate/.ssh/authorized_keys >/dev/null
if run_unit && grep -q 'already installed' "$work/journal"; then
  pass "authorized_keys alone forces the command"
else
  fail "authorized_keys alone"
fi
sudo cp "$work/sshd_config.locked" /etc/ssh/sshd_config
reload_sshd

echo "== The key opens no shell, terminal or forwarding =="
first_line="$(ssh_as_the_pi -T turn-certificate@127.0.0.1 'id; cat /etc/passwd' \
  | head -n 1 || true)"
if [ "$first_line" = '-----BEGIN CERTIFICATE-----' ]; then
  pass "asked to run 'id', the login printed the certificate instead"
else
  fail "the login ran something else: '$first_line'"
fi
tty_messages="$(ssh_as_the_pi -tt turn-certificate@127.0.0.1 2>&1 >/dev/null || true)"
if grep -q 'PTY allocation request failed' <<<"$tty_messages"; then
  pass "no terminal"
else
  fail "a terminal was not refused: $tty_messages"
fi
status=0
forwarded="$(ssh_as_the_pi -W 127.0.0.1:22 turn-certificate@127.0.0.1 2>"$work/messages")" \
  || status=$?
if [ "$status" = 255 ] && ! grep -q 'SSH-2.0' <<<"$forwarded" \
  && grep -Eq 'stdio forwarding failed|administratively prohibited' "$work/messages"; then
  pass "no connection elsewhere (-W)"
else
  fail "-W through the proxy: exit status $status, $(tr '\n' ' ' <"$work/messages")"
fi
# Accepted, -N would wait until timeout ends it (124); refused, ssh exits at once (255).
status=0
timeout 20 sudo ssh -F none -n -N -o BatchMode=yes -o IdentitiesOnly=yes \
  -i "$CONFIG_DIR/id_ed25519" -o UserKnownHostsFile="$CONFIG_DIR/known_hosts" \
  -o StrictHostKeyChecking=yes -o ExitOnForwardFailure=yes -R 127.0.0.1:40998:127.0.0.1:22 \
  turn-certificate@127.0.0.1 2>"$work/messages" || status=$?
if [ "$status" = 255 ] && grep -q 'remote port forwarding failed' "$work/messages"; then
  pass "no forwarded port (-R)"
else
  fail "-R through the proxy: exit status $status, $(tr '\n' ' ' <"$work/messages")"
fi
print_command=("$PRINT_SCRIPT" "$CONTAINER" "$CERTIFICATE")
allowed_first_line=""
# shellcheck disable=SC2024 # the runner's own user writes its own file
if sudo -u turn-certificate sudo -n "${print_command[@]}" >"$work/allowed"; then
  allowed_first_line="$(head -n 1 "$work/allowed")"
fi
rm -f "$work/allowed"
# sudo -l asks sudo itself whether a command line is allowed, without running it.
if sudo -u turn-certificate sudo -n -l "$PRINT_SCRIPT" "$CONTAINER" npm-31 >/dev/null 2>&1 \
  || sudo -u turn-certificate sudo -n -l "$PRINT_SCRIPT" >/dev/null 2>&1 \
  || sudo -u turn-certificate sudo -n -l /bin/sh >/dev/null 2>&1; then
  fail "sudo allows turn-certificate something other than the one command line"
elif ! sudo -u turn-certificate sudo -n -l "${print_command[@]}" >/dev/null 2>&1; then
  fail "sudo does not allow turn-certificate the one command line"
elif [ "$allowed_first_line" = '-----BEGIN CERTIFICATE-----' ]; then
  pass "sudo runs exactly the one command line for turn-certificate"
else
  fail "sudo does not run the allowed command for turn-certificate"
fi

echo "== Nothing leaked or left behind =="
sudo journalctl --sync
# shellcheck disable=SC2024 # the runner's own user writes its own file
sudo journalctl --no-pager -q -o cat --after-cursor "$start_cursor" >"$work/whole-journal"
leaked=0
for name in first renewed wrong-name; do
  sed '1d;$d' "$work/$name.key" >"$work/$name.key-lines"
  if grep -qF -f "$work/$name.key-lines" "$work/whole-journal"; then
    fail "a line of the $name key is in the journal"
    leaked=1
  fi
done
if [ "$leaked" = 0 ]; then pass "no key line anywhere in the journal since the setup"; fi
if [ -e /run/secure-call-turn-certificate ]; then
  fail "/run/secure-call-turn-certificate is still there after the runs"
else
  pass "systemd removed the fetch's folder"
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures check(s) failed."
  exit 1
fi
echo "All TURN certificate refresh checks passed."
