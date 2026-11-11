#!/usr/bin/env bash
# Runs on the PROXY machine (the one with Nginx Proxy Manager), not on the coturn Pi (#90). It is
# the forced command of the one SSH key that sync-turn-certificate.sh on the coturn Pi uses
# (README.md, TURN step 3b):
#
#   print-turn-certificate.sh CONTAINER CERTIFICATE   e.g. nginx-proxy-manager-app-1 npm-30
#
# It prints exactly two files of that certificate in Nginx Proxy Manager's container, and nothing
# else: /etc/letsencrypt/live/CERTIFICATE/fullchain.pem, then privkey.pem. It only reads them and
# writes no file. It takes no input from the client: the command the client asked for
# (SSH_ORIGINAL_COMMAND), stdin and the environment are ignored. Both names come from the
# authorized_keys and sudoers lines on the proxy machine, so the key can fetch this one
# certificate and do nothing else. Installed root-owned as
# /usr/local/sbin/secure-call-print-turn-certificate and run through sudo: reading the files needs
# Docker, and the SSH account has no other rights.
set -euo pipefail

# Docker's own rule for container names (so never an option such as "--privileged").
readonly CONTAINER_PATTERN='^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$'
# Nginx Proxy Manager names its certificates npm-<number>: no "/" and no "..".
readonly CERTIFICATE_PATTERN='^npm-[0-9]{1,9}$'

refuse() {
  echo "print-turn-certificate.sh: $1 Nothing was printed." >&2
  exit 2
}

if [ "$#" -ne 2 ]; then
  refuse "usage: $0 CONTAINER CERTIFICATE (for example nginx-proxy-manager-app-1 npm-30)."
fi
if [[ ! $1 =~ $CONTAINER_PATTERN ]]; then
  refuse "the container name is not a Docker container name."
fi
if [[ ! $2 =~ $CERTIFICATE_PATTERN ]]; then
  refuse "the certificate name is not npm-<number>."
fi
readonly LIVE_DIR="/etc/letsencrypt/live/$2"

# One cat for both files, so they are read at almost the same moment. If a renewal lands in
# between and they don't match, the coturn Pi refuses them and fetches again on its next run.
docker exec "$1" cat -- "$LIVE_DIR/fullchain.pem" "$LIVE_DIR/privkey.pem" </dev/null
