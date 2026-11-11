#!/bin/bash
# Installs the certificate coturn presents for TURN over TLS (turns:, port 5349, #58):
#
#   ./coturn/install-turn-certificate.sh [--coturn-dir DIR] FULLCHAIN.pem PRIVKEY.pem
#
# for example the files of the Let's Encrypt certificate for turn.securevideocall.com that Nginx
# Proxy Manager keeps renewed (README.md, TURN step 3b). DIR is the stack's coturn folder (next to
# compose.yaml), by default the one this script is in; secure-call-turn-certificate.service runs a
# root-owned copy of this script with it, on what fetch-turn-certificate.sh fetched (#90).
#
# Browsers check this certificate, so it must be publicly trusted. The two files (never symbolic
# links) are first copied into a private temporary folder, and only those copies are checked and
# installed. Nothing is installed unless all of these hold:
#   - FULLCHAIN.pem holds certificates only (no key or anything else that would become readable);
#   - the certificate names turn.securevideocall.com;
#   - it chains to a CA this machine trusts (the system's CA store) and is for TLS servers;
#   - it is valid for at least 7 more days;
#   - PRIVKEY.pem is an unencrypted private key that belongs to it.
# Then it goes to coturn/tls/ (fullchain.pem mode 444; privkey.pem owned by coturn's user 65534,
# mode 400, which needs sudo), and a running coturn is told to reload it (SIGUSR2): coturn keeps
# its relays, so calls in progress are not dropped, and keeps the old certificate if the new one
# cannot be loaded.
set -euo pipefail
export LC_ALL=C

readonly TURN_HOST_NAME=turn.securevideocall.com
readonly COTURN_UID=65534          # compose.yaml: user: '65534:65534'
readonly MIN_VALID_SECONDS=$((7 * 24 * 60 * 60))
# Only for tests, and never as root: one more CA to trust, on top of the system's CA store.
readonly TEST_CA_FILE="${TURN_CERTIFICATE_TEST_CA_FILE:-}"
# The root-owned copies secure-call-turn-certificate.service runs, next to this one, and the units.
readonly COPIES_OF_THE_CHECKOUT=(
  "$(dirname "$0")/fetch-turn-certificate.sh=fetch-turn-certificate.sh"
  "$(dirname "$0")/install-turn-certificate.sh=install-turn-certificate.sh"
  /etc/systemd/system/secure-call-turn-certificate.service=secure-call-turn-certificate.service
  /etc/systemd/system/secure-call-turn-certificate.timer=secure-call-turn-certificate.timer
)

refuse() {
  echo "install-turn-certificate.sh: $1 Nothing was installed." >&2
  exit 1
}

coturn_dir="$(dirname "$0")"
if [ "$#" -eq 4 ] && [ "$1" = --coturn-dir ]; then
  coturn_dir="$2"
  shift 2
fi
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 [--coturn-dir DIR] FULLCHAIN.pem PRIVKEY.pem" >&2
  exit 2
fi
# The physical path (a link such as /etc/secure-call/turn-certificate/coturn resolved), checked to
# be next to compose.yaml, so tls/ is never written anywhere else.
if ! COTURN_DIR="$(cd -- "$coturn_dir" 2>/dev/null && pwd -P)" \
  || [ ! -f "$COTURN_DIR/../compose.yaml" ]; then
  echo "install-turn-certificate.sh: $coturn_dir is not the coturn folder next to compose.yaml." >&2
  exit 2
fi
readonly COTURN_DIR
readonly TLS_DIR="$COTURN_DIR/tls"
readonly COMPOSE_FILE="$COTURN_DIR/../compose.yaml"
# Root writes there, so it must be the folder itself, not a link.
if [ -L "$TLS_DIR" ]; then
  refuse "$TLS_DIR is a symbolic link, not a folder."
fi
# Root reads them, and they may come from a folder an unprivileged user can write.
for input in "$1" "$2"; do
  if [ -L "$input" ]; then refuse "$input is a symbolic link; give the file itself."; fi
done
if [ -n "$TEST_CA_FILE" ]; then
  if [ "$(id -u)" -eq 0 ]; then
    refuse "TURN_CERTIFICATE_TEST_CA_FILE is set, and it is never honoured as root."
  fi
  echo "install-turn-certificate.sh: WARNING: also trusting $TEST_CA_FILE" \
    "(TURN_CERTIFICATE_TEST_CA_FILE is for tests only)." >&2
fi
for copy_and_original in "${COPIES_OF_THE_CHECKOUT[@]}"; do
  copy="${copy_and_original%%=*}"
  original="$COTURN_DIR/${copy_and_original#*=}"
  if [ -f "$copy" ] && [ -f "$original" ] && ! cmp -s "$copy" "$original"; then
    echo "install-turn-certificate.sh: WARNING: $copy differs from $original; install it again" \
      "(README.md, TURN step 3b, \"After a change\")." >&2
  fi
done

umask 077
if [ -d /dev/shm ] && [ -w /dev/shm ]; then
  work_dir="$(mktemp -d -p /dev/shm)"
else
  work_dir="$(mktemp -d)"
fi
trap 'rm -rf "$work_dir"' EXIT
trap 'exit 1' HUP INT TERM
cp -- "$1" "$work_dir/fullchain.pem" 2>/dev/null || refuse "cannot read $1."
cp -- "$2" "$work_dir/privkey.pem" 2>/dev/null || refuse "cannot read $2."
fullchain="$work_dir/fullchain.pem"
private_key="$work_dir/privkey.pem"

if grep -E '^-----BEGIN ' "$fullchain" | grep -qvx -- '-----BEGIN CERTIFICATE-----'; then
  refuse "$1 holds something other than certificates."
fi
# The first certificate in the file is the server's own; the rest are intermediates.
openssl x509 -in "$fullchain" -out "$work_dir/leaf.pem" 2>/dev/null \
  || refuse "$1 holds no certificate."
if ! openssl x509 -in "$work_dir/leaf.pem" -noout -checkhost "$TURN_HOST_NAME" \
  | grep -q 'does match certificate'; then
  refuse "the certificate does not name $TURN_HOST_NAME."
fi
if ! openssl x509 -in "$work_dir/leaf.pem" -noout -checkend "$MIN_VALID_SECONDS" >/dev/null; then
  refuse "the certificate expires within 7 days (or already has)."
fi
trust=()
if [ -n "$TEST_CA_FILE" ]; then trust=(-CAfile "$TEST_CA_FILE"); fi
if ! openssl verify ${trust[@]+"${trust[@]}"} -purpose sslserver -untrusted "$fullchain" \
  "$work_dir/leaf.pem" >/dev/null 2>&1; then
  refuse "the certificate does not chain to a trusted CA for TLS servers."
fi
certificate_public_key="$(openssl x509 -in "$work_dir/leaf.pem" -noout -pubkey \
  | openssl pkey -pubin -outform DER | openssl dgst -sha256)"
# -passin pass: makes an encrypted key fail here instead of prompting (coturn could not load it).
private_key_public_key="$(openssl pkey -in "$private_key" -passin pass: -pubout -outform DER \
  2>/dev/null | openssl dgst -sha256)" || refuse "$2 is not an unencrypted private key."
[ "$certificate_public_key" = "$private_key_public_key" ] \
  || refuse "the private key does not belong to the certificate."

# Whether coturn runs decides the reload below; an error from Docker must not pass for "no".
if ! running_services="$(docker compose -f "$COMPOSE_FILE" ps --status running --services)"; then
  refuse "cannot ask Docker whether coturn runs (see the error above)."
fi

if [ -f "$TLS_DIR/fullchain.pem" ] && [ -e "$TLS_DIR/privkey.pem" ] \
  && cmp -s "$fullchain" "$TLS_DIR/fullchain.pem"; then
  echo "The certificate is already installed; coturn was not told to reload."
  exit 0
fi

as_root=()
if [ "$(id -u)" -ne 0 ]; then as_root=(sudo); fi
mkdir -p -- "$TLS_DIR"
# Work inside the folder itself from here on, so a link put in its place now changes nothing.
cd -P -- "$TLS_DIR"
[ "$(pwd -P)" = "$TLS_DIR" ] || refuse "$TLS_DIR was replaced while installing."
chmod 755 .
${as_root[@]+"${as_root[@]}"} install -m 400 -o "$COTURN_UID" -g "$COTURN_UID" \
  "$private_key" ./privkey.pem
install -m 444 "$fullchain" ./fullchain.pem
echo "Installed the certificate for $TURN_HOST_NAME, valid until" \
  "$(openssl x509 -in "$work_dir/leaf.pem" -noout -enddate | cut -d= -f2)."

if grep -qx coturn <<<"$running_services"; then
  docker compose -f "$COMPOSE_FILE" kill -s SIGUSR2 coturn
  echo "Told coturn to reload its certificate (calls in progress keep their relays)."
else
  echo "coturn is not running; it uses the certificate when it starts."
fi
