#!/bin/bash
# Fetches the TURN certificate and its key from the proxy machine (#90; README.md, TURN step 3b).
# secure-call-turn-certificate.service runs a root-owned copy twice a day, as an unprivileged user
# of its own; afterwards, as root, install-turn-certificate.sh checks and installs what it fetched:
#
#   fetch-turn-certificate.sh CONFIG_DIR OUTPUT_DIR
#
# CONFIG_DIR (the unit's credentials, copied by systemd from /etc/secure-call/turn-certificate/,
# which only root can read) holds:
#   proxy        one line, the SSH login on the proxy machine: USER@HOST or USER@HOST:PORT
#   id_ed25519   the SSH key the proxy machine accepts only from this Pi and only for its forced
#                command, print-turn-certificate.sh
#   known_hosts  the proxy machine's host key; no other host key is trusted
# OUTPUT_DIR must be in memory (the unit's runtime folder in /run, which systemd removes when the
# run ends). On success it holds fullchain.pem and privkey.pem; otherwise neither.
#
# 1. The proxy's answer is kept in OUTPUT_DIR (at most 64 KiB) and never printed or logged.
#    Messages from ssh and the proxy are logged, cut to 4 KiB of printable text.
# 2. It must be nothing but one or more certificates followed by one private key, in PEM lines of
#    printable ASCII. Anything else (a banner, a blank line, a second key, text after the key) is
#    refused.
# 3. If the proxy ran the command this script asks for, instead of its forced command, nothing on
#    the proxy machine forces one for this key; that is refused, with a message that says so.
# It never runs as root: it handles what the proxy machine sends, and only installing needs root.
set -euo pipefail
export LC_ALL=C

readonly MAX_ANSWER_BYTES=65536
readonly MAX_MESSAGE_BYTES=4096
# What this script asks the proxy to run. With a forced command in place, sshd runs that instead
# and this text never comes back; without one, the proxy's shell runs it and the answer is this.
readonly UNRESTRICTED_KEY_MARKER=secure-call-turn-certificate-key-is-not-restricted
readonly PROXY_PATTERN='^([a-z_][a-z0-9_-]{0,31})@([A-Za-z0-9][A-Za-z0-9.-]{0,252})(:([0-9]{1,5}))?$'

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
  echo "fetch-turn-certificate.sh: $1 Nothing was fetched." >&2
  exit 1
}

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 CONFIG_DIR OUTPUT_DIR" >&2
  exit 2
fi
readonly CONFIG_DIR="$1"
readonly OUTPUT_DIR="$2"
if [ "$(id -u)" -eq 0 ]; then
  refuse "it must not run as root (secure-call-turn-certificate.service runs it as its own user)."
fi

if [ -L "$OUTPUT_DIR" ] || [ ! -d "$OUTPUT_DIR" ] || [ ! -w "$OUTPUT_DIR" ]; then
  refuse "$OUTPUT_DIR is not a folder this user can write."
fi
case "$(stat -f -c %T "$OUTPUT_DIR" 2>/dev/null || true)" in
  tmpfs | ramfs) ;;
  *) refuse "$OUTPUT_DIR is not in memory (tmpfs), and the key must never reach a disk." ;;
esac

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

umask 077
rm -f -- "$OUTPUT_DIR/fullchain.pem" "$OUTPUT_DIR/privkey.pem"
work_dir="$(mktemp -d "$OUTPUT_DIR/fetch.XXXXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT
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
# At most one byte more than allowed is kept, so a runaway answer cannot fill the memory; ssh's
# and the proxy's messages are cut short and stripped of control characters before they are logged.
fetch_status=0
"${ssh_command[@]}" 2> >(tr -cd '\n -~' | head -c "$MAX_MESSAGE_BYTES" >&2) \
  | head -c "$((MAX_ANSWER_BYTES + 1))" >"$answer" || fetch_status=$?
if [ "$(($(wc -c <"$answer")))" -gt "$MAX_ANSWER_BYTES" ]; then
  refuse "the proxy sent more than $MAX_ANSWER_BYTES bytes."
fi
if [ "$fetch_status" -ne 0 ]; then
  refuse "fetching from $PROXY_LOGIN failed (exit status $fetch_status; the message from ssh or the proxy, if any, is above)."
fi
if [ "$(head -n 1 "$answer")" = "$UNRESTRICTED_KEY_MARKER" ]; then
  refuse "$PROXY_LOGIN ran this script's own command instead of print-turn-certificate.sh: neither its authorized_keys line for this key (command=) nor its sshd_config (ForceCommand) forces one, so the key can open a shell there. Fix that first (README.md, TURN step 3b)."
fi
if [ "$(($(tr -d '\n -~' <"$answer" | wc -c)))" -ne 0 ]; then
  refuse "the proxy's answer holds bytes that are not printable ASCII."
fi
if ! problem="$(awk -v fullchain_file="$work_dir/fullchain.pem" \
  -v key_file="$work_dir/privkey.pem" "$PEM_GRAMMAR" "$answer")"; then
  refuse "the proxy's answer is not just certificates followed by one private key: $problem."
fi
mv -- "$work_dir/fullchain.pem" "$work_dir/privkey.pem" "$OUTPUT_DIR/"
echo "Fetched a certificate and a key; install-turn-certificate.sh checks them next."
