#!/usr/bin/env bash
# Installs the certificate coturn presents for TURN over TLS (turns:, port 5349, #58):
#
#   ./coturn/install-turn-certificate.sh FULLCHAIN.pem PRIVKEY.pem
#
# for example the files of the Let's Encrypt certificate for turn.securevideocall.com that Nginx
# Proxy Manager keeps renewed (README.md, "TURN over TLS"). Browsers check this certificate, so it
# must be publicly trusted. Nothing is installed unless all of these hold:
#   - the certificate names turn.securevideocall.com;
#   - it chains to a CA this machine trusts (the system's CA store) and is for TLS servers;
#   - it is valid for at least 7 more days;
#   - the private key belongs to it.
# Then it goes to coturn/tls/ (fullchain.pem mode 444; privkey.pem owned by coturn's user 65534,
# mode 400, which needs sudo), and coturn is restarted if the certificate changed: coturn reads it
# only at start. A restart drops the relays of calls in progress, so do this at a quiet time.
set -euo pipefail

readonly TURN_HOST_NAME=turn.securevideocall.com
readonly COTURN_UID=65534          # compose.yaml: user: '65534:65534'
readonly MIN_VALID_SECONDS=$((7 * 24 * 60 * 60))
readonly COTURN_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly TLS_DIR="$COTURN_DIR/tls"
# Only for tests: a CA file to trust instead of the system's CA store.
readonly CA_FILE="${TURN_CERTIFICATE_TEST_CA_FILE:-}"

refuse() {
  echo "install-turn-certificate.sh: $1 Nothing was installed." >&2
  exit 1
}

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 FULLCHAIN.pem PRIVKEY.pem" >&2
  exit 2
fi
fullchain="$1"
private_key="$2"
[ -r "$fullchain" ] || refuse "cannot read $fullchain."
[ -r "$private_key" ] || refuse "cannot read $private_key."

umask 077
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
# The first certificate in the file is the server's own; the rest are intermediates.
openssl x509 -in "$fullchain" -out "$work_dir/leaf.pem" 2>/dev/null \
  || refuse "$fullchain holds no certificate."

if ! openssl x509 -in "$work_dir/leaf.pem" -noout -checkhost "$TURN_HOST_NAME" \
  | grep -q 'does match certificate'; then
  refuse "the certificate does not name $TURN_HOST_NAME."
fi
if ! openssl x509 -in "$work_dir/leaf.pem" -noout -checkend "$MIN_VALID_SECONDS" >/dev/null; then
  refuse "the certificate expires within 7 days (or already has)."
fi
trust=()
if [ -n "$CA_FILE" ]; then trust=(-CAfile "$CA_FILE"); fi
if ! openssl verify ${trust[@]+"${trust[@]}"} -purpose sslserver -untrusted "$fullchain" \
  "$work_dir/leaf.pem" >/dev/null 2>&1; then
  refuse "the certificate does not chain to a trusted CA for TLS servers."
fi
certificate_public_key="$(openssl x509 -in "$work_dir/leaf.pem" -noout -pubkey \
  | openssl pkey -pubin -outform DER | openssl dgst -sha256)"
private_key_public_key="$(openssl pkey -in "$private_key" -pubout -outform DER 2>/dev/null \
  | openssl dgst -sha256)" || refuse "$private_key is not a private key."
[ "$certificate_public_key" = "$private_key_public_key" ] \
  || refuse "the private key does not belong to the certificate."

if [ -f "$TLS_DIR/fullchain.pem" ] && cmp -s "$fullchain" "$TLS_DIR/fullchain.pem"; then
  echo "The certificate is already installed; coturn was not restarted."
  exit 0
fi

as_root=()
if [ "$(id -u)" -ne 0 ]; then as_root=(sudo); fi
mkdir -p "$TLS_DIR"
chmod 755 "$TLS_DIR"
${as_root[@]+"${as_root[@]}"} install -m 400 -o "$COTURN_UID" -g "$COTURN_UID" \
  "$private_key" "$TLS_DIR/privkey.pem"
install -m 444 "$fullchain" "$TLS_DIR/fullchain.pem"
echo "Installed the certificate for $TURN_HOST_NAME, valid until" \
  "$(openssl x509 -in "$work_dir/leaf.pem" -noout -enddate | cut -d= -f2)."

if docker compose -f "$COTURN_DIR/../compose.yaml" ps --status running --services 2>/dev/null \
  | grep -qx coturn; then
  docker compose -f "$COTURN_DIR/../compose.yaml" restart coturn
  echo "Restarted coturn."
else
  echo "coturn is not running; it uses the certificate when it starts."
fi
