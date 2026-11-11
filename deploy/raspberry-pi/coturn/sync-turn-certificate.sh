#!/usr/bin/env bash
# Fetches the TURN certificate from the proxy machine and installs it for coturn (#90; README.md,
# TURN step 3b). secure-call-turn-certificate.timer runs it twice a day, as root, from a
# root-owned copy next to a root-owned copy of install-turn-certificate.sh:
#
#   /usr/local/lib/secure-call/sync-turn-certificate.sh [--config-dir DIR]
#
# DIR (default /etc/secure-call/turn-certificate, root only) holds:
#   proxy        one line, the SSH login on the proxy machine: USER@HOST or USER@HOST:PORT
#   id_ed25519   the SSH key that the proxy machine accepts only from this Pi and only for its
#                forced command, print-turn-certificate.sh
#   known_hosts  the proxy machine's host key; no other host key is trusted
#   coturn       a symbolic link to this folder (deploy/raspberry-pi/coturn) in the checkout
#
# 1. The proxy's answer goes into a private folder in /dev/shm, which must be in memory (the unit
#    gives every run a fresh one of its own). It is never printed or logged.
# 2. It must be nothing but one or more certificates followed by one private key, in PEM lines of
#    printable ASCII. Anything else (a banner, a blank line, a second key, text after the key) is
#    refused. If the proxy ran the command this script asks for instead of its forced command,
#    the key is not restricted there; that is refused too, with a message that says so.
# 3. install-turn-certificate.sh, next to this script, then checks the certificate (the name, a
#    trusted chain, 7 or more days left, the key matching) and installs it into coturn/tls/ only
#    if it changed, telling coturn to reload. Its messages are this run's outcome in the journal.
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
readonly SCRIPT_DIR="$script_dir"
readonly MAX_ANSWER_BYTES=65536
# What this script asks the proxy to run. With the forced command in place, sshd runs that instead
# and this text never comes back; without it, the proxy's shell runs it and the answer is this.
readonly UNRESTRICTED_KEY_MARKER=secure-call-turn-certificate-key-is-not-restricted
readonly PROXY_PATTERN='^([a-z_][a-z0-9_-]{0,31})@([A-Za-z0-9][A-Za-z0-9.-]{0,252})(:([0-9]{1,5}))?$'
# Only for tests (not every test machine has a /dev/shm): another folder in its place.
readonly TEST_MEMORY_DIR="${TURN_CERTIFICATE_TEST_MEMORY_DIR:-}"

# The proxy's answer, line by line: certificates (fullchain.pem), then one private key
# (privkey.pem), and nothing else. Messages name line numbers only, never their contents.
readonly PEM_GRAMMAR='
function fail(reason) { problem = reason; exit 1 }
BEGIN { state = "outside" }
{
  if (state == "outside") {
    if (keys == 0 && $0 == "-----BEGIN CERTIFICATE-----") {
      state = "inside"; end_line = "-----END CERTIFICATE-----"; output = fullchain_file
      certificates++
    } else if (keys == 0 && certificates > 0 && $0 ~ /^-----BEGIN (EC |RSA )?PRIVATE KEY-----$/) {
      state = "inside"; end_line = "-----END " substr($0, 12); output = key_file
      keys++
    } else if (keys > 0) {
      fail("line " NR " comes after the key")
    } else {
      fail("line " NR " does not start a certificate" (certificates > 0 ? " or the key" : ""))
    }
  } else if ($0 == end_line) {
    state = "outside"
  } else if ($0 !~ "^[A-Za-z0-9+/=]+$" || length($0) > 76) {
    fail("line " NR " is not base64 inside a PEM block")
  }
  print > output
}
END {
  if (problem != "") { print problem; exit 1 }
  if (state != "outside") { print "it ends inside a PEM block"; exit 1 }
  if (certificates == 0) { print "it holds no certificate"; exit 1 }
  if (keys == 0) { print "it holds no private key"; exit 1 }
}'

refuse() {
  echo "sync-turn-certificate.sh: $1 Nothing was installed." >&2
  exit 1
}

config_dir=/etc/secure-call/turn-certificate
if [ "$#" -eq 2 ] && [ "$1" = --config-dir ]; then
  config_dir="$2"
elif [ "$#" -ne 0 ]; then
  echo "Usage: $0 [--config-dir DIR]" >&2
  exit 2
fi
readonly CONFIG_DIR="$config_dir"

if [ -n "$TEST_MEMORY_DIR" ]; then
  echo "sync-turn-certificate.sh: WARNING: using $TEST_MEMORY_DIR instead of /dev/shm" \
    "(TURN_CERTIFICATE_TEST_MEMORY_DIR is for tests only)." >&2
  memory_dir="$TEST_MEMORY_DIR"
else
  memory_dir=/dev/shm
  case "$(stat -f -c %T "$memory_dir" 2>/dev/null || true)" in
    tmpfs | ramfs) ;;
    *) refuse "/dev/shm is not in memory (tmpfs), and the key must never reach a disk." ;;
  esac
fi
if [ ! -d "$memory_dir" ] || [ ! -w "$memory_dir" ]; then
  refuse "cannot write to $memory_dir."
fi

if [ ! -f "$CONFIG_DIR/proxy" ]; then
  refuse "$CONFIG_DIR/proxy is missing (README.md, TURN step 3b)."
fi
proxy="$(cat "$CONFIG_DIR/proxy")"
if [[ ! $proxy =~ $PROXY_PATTERN ]]; then
  refuse "$CONFIG_DIR/proxy must be one line, USER@HOST or USER@HOST:PORT."
fi
readonly PROXY_LOGIN="${BASH_REMATCH[1]}@${BASH_REMATCH[2]}"
readonly PROXY_PORT="${BASH_REMATCH[4]:-22}"
for required_file in id_ed25519 known_hosts; do
  if [ ! -f "$CONFIG_DIR/$required_file" ]; then
    refuse "$CONFIG_DIR/$required_file is missing (README.md, TURN step 3b)."
  fi
done
if [ ! -d "$CONFIG_DIR/coturn" ]; then
  refuse "$CONFIG_DIR/coturn is not a link to deploy/raspberry-pi/coturn (README.md, TURN step 3b)."
fi

umask 077
work_dir="$(mktemp -d "$memory_dir/secure-call-turn-certificate.XXXXXXXX")"
trap 'rm -rf "$work_dir"' EXIT
trap 'exit 1' HUP INT TERM
answer="$work_dir/answer"

# No configuration file, agent, password, prompt, forwarding or connection sharing: only this key,
# and only this host key. sshd ignores the command asked for when the key has a forced command.
ssh_command=(
  ssh -F none -n -T -p "$PROXY_PORT"
  -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no
  -o IdentitiesOnly=yes -o IdentityAgent=none -i "$CONFIG_DIR/id_ed25519"
  -o StrictHostKeyChecking=yes -o UpdateHostKeys=no
  -o UserKnownHostsFile="$CONFIG_DIR/known_hosts" -o GlobalKnownHostsFile=/dev/null
  -o ForwardAgent=no -o ForwardX11=no -o ClearAllForwardings=yes -o PermitLocalCommand=no
  -o ControlMaster=no -o ControlPath=none
  -o ConnectTimeout=20 -o ServerAliveInterval=15 -o ServerAliveCountMax=4 -o LogLevel=ERROR
  -- "$PROXY_LOGIN" "echo $UNRESTRICTED_KEY_MARKER"
)
echo "Fetching the TURN certificate from $PROXY_LOGIN."
# At most one byte more than allowed is kept, so a runaway answer cannot fill the memory.
fetch_status=0
"${ssh_command[@]}" | head -c "$((MAX_ANSWER_BYTES + 1))" >"$answer" || fetch_status=$?
if [ "$(($(wc -c <"$answer")))" -gt "$MAX_ANSWER_BYTES" ]; then
  refuse "the proxy sent more than $MAX_ANSWER_BYTES bytes."
fi
if [ "$fetch_status" -ne 0 ]; then
  refuse "fetching from $PROXY_LOGIN failed (exit status $fetch_status; the message from ssh or the proxy, if any, is above)."
fi
if [ "$(head -n 1 "$answer")" = "$UNRESTRICTED_KEY_MARKER" ]; then
  refuse "$PROXY_LOGIN ran this script's own command instead of print-turn-certificate.sh, so its authorized_keys line for this key lacks restrict and command= and the key can open a shell there. Fix that line first (README.md, TURN step 3b)."
fi
if [ "$(($(LC_ALL=C tr -d '\n -~' <"$answer" | wc -c)))" -ne 0 ]; then
  refuse "the proxy's answer holds bytes that are not printable ASCII."
fi
if ! problem="$(LC_ALL=C awk -v fullchain_file="$work_dir/fullchain.pem" \
  -v key_file="$work_dir/privkey.pem" "$PEM_GRAMMAR" "$answer")"; then
  refuse "the proxy's answer is not just certificates followed by one private key: $problem."
fi
echo "Fetched a certificate and a key; checking them."

"$SCRIPT_DIR/install-turn-certificate.sh" --coturn-dir "$CONFIG_DIR/coturn" \
  "$work_dir/fullchain.pem" "$work_dir/privkey.pem"
