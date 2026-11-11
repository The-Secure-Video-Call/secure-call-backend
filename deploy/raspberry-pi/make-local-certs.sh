#!/usr/bin/env bash
# Makes the certificates for the connections inside this deployment, signed by a small local
# certificate authority (CA) of our own, into ./tls/ (never committed):
#   tls/local-ca.crt                 the CA certificate: what the clients trust (not secret)
#   tls/postgres.crt, postgres.key   PostgreSQL's server certificate and key (key: mode 600)
#
# The CA's private key exists only while this script runs and is deleted at the end, so nothing
# can sign another certificate later. To renew (before the expiry date printed below) or after a
# suspected compromise, run this script again: it makes a new CA and new certificates. Then
# restart PostgreSQL and the backend (see README.md, "Database (PostgreSQL)").
#
# ECDSA P-256 with SHA-256, TLS server use only. Needs OpenSSL 3.
set -euo pipefail

readonly VALID_DAYS=825
readonly DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly TLS_DIR="$DEPLOY_DIR/tls"

if ! openssl version | grep -q '^OpenSSL 3\.'; then
  echo "make-local-certs.sh needs OpenSSL 3 (found: $(openssl version))." >&2
  exit 1
fi

umask 077
# In memory where possible, so the CA's key never touches the SD card.
if [ -d /dev/shm ] && [ -w /dev/shm ]; then
  work_dir="$(mktemp -d -p /dev/shm)"
else
  work_dir="$(mktemp -d)"
fi
trap 'rm -rf "$work_dir"' EXIT

mkdir -p "$TLS_DIR"
# The directory and the certificates are readable by the containers' users; keys are not.
chmod 755 "$TLS_DIR"

new_ec_key() {
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -pkeyopt ec_param_enc:named_curve -out "$1"
}

# A minimal OpenSSL config, so the system's openssl.cnf cannot add extensions of its own:
# every extension below is set explicitly.
printf '%s\n' '[req]' 'distinguished_name = req_dn' 'prompt = no' '[req_dn]' \
  >"$work_dir/openssl.cnf"

new_ec_key "$work_dir/ca.key"
openssl req -config "$work_dir/openssl.cnf" -x509 -new -key "$work_dir/ca.key" -sha256 \
  -days "$VALID_DAYS" \
  -subj "/CN=secure-call local CA" \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -out "$work_dir/local-ca.crt"

# issue_server_certificate NAME SUBJECT_ALT_NAMES
issue_server_certificate() {
  local name="$1" subject_alt_names="$2"
  new_ec_key "$work_dir/$name.key"
  openssl req -config "$work_dir/openssl.cnf" -new -key "$work_dir/$name.key" \
    -subj "/CN=$name" -out "$work_dir/$name.csr"
  printf '%s\n' \
    'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature' \
    'extendedKeyUsage=serverAuth' \
    "subjectAltName=$subject_alt_names" >"$work_dir/$name.ext"
  openssl x509 -req -in "$work_dir/$name.csr" -CA "$work_dir/local-ca.crt" \
    -CAkey "$work_dir/ca.key" -set_serial "0x$(openssl rand -hex 16)" -sha256 \
    -days "$VALID_DAYS" -extfile "$work_dir/$name.ext" -out "$work_dir/$name.crt"
  openssl verify -CAfile "$work_dir/local-ca.crt" "$work_dir/$name.crt" >/dev/null
}

# "postgres" is the name the backend uses on the Docker network; localhost and 127.0.0.1 are
# for database tools on the Pi (the port is published on 127.0.0.1 by default).
issue_server_certificate postgres 'DNS:postgres,DNS:localhost,IP:127.0.0.1'

# Replace the old files only once everything above has succeeded.
for certificate_name in local-ca postgres; do
  install -m 644 "$work_dir/$certificate_name.crt" "$TLS_DIR/$certificate_name.crt"
done
install -m 600 "$work_dir/postgres.key" "$TLS_DIR/postgres.key"

echo "Made $TLS_DIR/{local-ca.crt,postgres.crt,postgres.key}."
echo "They expire on $(openssl x509 -in "$TLS_DIR/local-ca.crt" -noout -enddate | cut -d= -f2):"
echo "run this script again before then. The CA's private key has been deleted."
