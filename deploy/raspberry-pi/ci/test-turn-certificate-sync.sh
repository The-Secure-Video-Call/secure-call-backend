#!/usr/bin/env bash
# CI only (.github/workflows/ci.yml, check job): the automatic refresh of coturn's certificate
# (#90), set up on the runner with the commands of README.md, TURN step 3b, and run by the real
# unit under systemd, sandbox included. The runner is both machines: its own sshd (127.0.0.1), the
# account turn-certificate and a container named like Nginx Proxy Manager's stand in for the proxy
# machine, and this checkout for the coturn Pi. It checks that:
#   - the first run installs the certificate (key owner 65534, mode 400) and logs the outcome;
#   - a second run changes nothing, and a renewed certificate in the container is installed;
#   - a certificate for another name, or the key without restrict and command=, is refused, and
#     what is installed stays;
#   - the key opens no shell on the proxy: whatever its login asks for, it gets the certificate;
#   - no line of a private key is ever in the journal, and nothing is left in the host's /dev/shm.
# A test CA is added to the runner's trust store for the run, as Let's Encrypt cannot issue here.
# Needs Docker, passwordless sudo, systemd, openssl, and the backend image (built by a step
# before; it stands in for Nginx Proxy Manager's image). Run from deploy/raspberry-pi.
set -euo pipefail
cd "$(dirname "$0")/.."

readonly CONFIG_DIR=/etc/secure-call/turn-certificate
readonly CONTAINER=nginx-proxy-manager-app-1
readonly CERTIFICATE=npm-30
readonly PRINT_COMMAND="/usr/local/sbin/secure-call-print-turn-certificate $CONTAINER $CERTIFICATE"
readonly STAND_IN_IMAGE=ghcr.io/the-secure-video-call/secure-call-backend:main
readonly TEST_CA_IN_STORE=/usr/local/share/ca-certificates/secure-call-ci-test-ca.crt
work="$(mktemp -d)"
live="$work/live"
failures=0

fail() {
  echo "FAIL: $*"
  failures=$((failures + 1))
}
pass() { echo "PASS: $*"; }

cleanup() {
  set +e
  sudo systemctl disable --now secure-call-turn-certificate.timer >/dev/null 2>&1
  sudo rm -f /etc/systemd/system/secure-call-turn-certificate.service \
    /etc/systemd/system/secure-call-turn-certificate.timer
  sudo systemctl daemon-reload
  sudo rm -rf /usr/local/lib/secure-call "$CONFIG_DIR" /etc/sudoers.d/secure-call-turn-certificate \
    /usr/local/sbin/secure-call-print-turn-certificate coturn/tls
  sudo deluser --system --remove-home turn-certificate >/dev/null 2>&1
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

# One run of the unit: its exit status, and what it logged (secure-call-turn) in $work/journal.
run_unit() {
  local status=0 cursor
  cursor="$(sudo journalctl -n 1 -q --no-pager --show-cursor | sed -n 's/^-- cursor: //p')"
  sudo systemctl start secure-call-turn-certificate.service || status=$?
  sudo journalctl --sync
  sudo journalctl --no-pager -q -o cat -t secure-call-turn --after-cursor "$cursor" \
    >"$work/journal"
  cat "$work/journal" >>"$work/all-journals"
  sed 's/^/    journal: /' "$work/journal"
  return "$status"
}

installed_key_is() { sudo cmp -s "$work/$1.key" coturn/tls/privkey.pem; }

echo "== Setup =="
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

touch "$work/start"
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

# The proxy machine's part, as in the README (the script comes from this checkout).
sudo install -o root -g root -m 0755 coturn/print-turn-certificate.sh \
  /usr/local/sbin/secure-call-print-turn-certificate
sudo adduser --system --group --shell /bin/sh --home /var/lib/turn-certificate turn-certificate \
  >/dev/null
echo "turn-certificate ALL=(root) NOPASSWD: $PRINT_COMMAND" >"$work/turn-certificate.sudoers"
sudo visudo -cf "$work/turn-certificate.sudoers"
sudo install -o root -g root -m 0440 "$work/turn-certificate.sudoers" \
  /etc/sudoers.d/secure-call-turn-certificate
sudo install -d -o root -g root -m 0755 /var/lib/turn-certificate/.ssh

# The coturn Pi's part 1, then the authorized_keys line with its key.
sudo install -d -o root -g root -m 0700 "$CONFIG_DIR"
sudo ssh-keygen -q -t ed25519 -N '' -C secure-call-turn-certificate -f "$CONFIG_DIR/id_ed25519"
public_key="$(sudo cat "$CONFIG_DIR/id_ed25519.pub")"
forced_line="restrict,from=\"127.0.0.1\",command=\"sudo -n $PRINT_COMMAND\" $public_key"
echo "$forced_line" | sudo tee /var/lib/turn-certificate/.ssh/authorized_keys >/dev/null

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
  coturn/sync-turn-certificate.sh coturn/install-turn-certificate.sh
sudo ln -sfn "$PWD/coturn" "$CONFIG_DIR/coturn"
sudo install -o root -g root -m 0644 coturn/secure-call-turn-certificate.service \
  coturn/secure-call-turn-certificate.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now secure-call-turn-certificate.timer
if systemctl list-timers --all --no-pager | grep -q secure-call-turn-certificate.timer; then
  pass "the timer is scheduled"
else
  fail "the timer is not scheduled"
fi

echo "== The first run installs the certificate =="
if run_unit && grep -q 'Installed the certificate for turn.securevideocall.com' "$work/journal" \
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
echo "$public_key" | sudo tee /var/lib/turn-certificate/.ssh/authorized_keys >/dev/null
if ! run_unit && grep -q 'lacks restrict and command=' "$work/journal" \
  && installed_key_is renewed; then
  pass "the key without restrict and command= is refused, and named"
else
  fail "the key without restrict and command="
fi
echo "$forced_line" | sudo tee /var/lib/turn-certificate/.ssh/authorized_keys >/dev/null

echo "== The key opens no shell on the proxy =="
first_line="$(sudo ssh -F none -n -T -o BatchMode=yes -o IdentitiesOnly=yes \
  -i "$CONFIG_DIR/id_ed25519" -o UserKnownHostsFile="$CONFIG_DIR/known_hosts" \
  -o StrictHostKeyChecking=yes turn-certificate@127.0.0.1 'id; cat /etc/passwd' \
  | head -n 1 || true)"
if [ "$first_line" = '-----BEGIN CERTIFICATE-----' ]; then
  pass "asked to run 'id', the login printed the certificate instead"
else
  fail "the login ran something else: '$first_line'"
fi
if run_unit; then pass "the restored line works again"; else fail "the restored line"; fi

echo "== Nothing leaked =="
for name in first renewed wrong-name; do
  sed '1d;$d' "$work/$name.key" >"$work/$name.key-lines"
  if grep -qF -f "$work/$name.key-lines" "$work/all-journals"; then
    fail "a line of the $name key is in the journal"
  fi
done
pass "no key line in the journal"
if find /dev/shm -maxdepth 1 -mindepth 1 -user root -newer "$work/start" | grep -q .; then
  fail "the runs left something in the host's /dev/shm"
else
  pass "nothing in the host's /dev/shm (the unit has its own)"
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures check(s) failed."
  exit 1
fi
echo "All TURN certificate refresh checks passed."
