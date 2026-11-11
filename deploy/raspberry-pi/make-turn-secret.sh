#!/usr/bin/env bash
# Writes the TURN shared secret into the two files that coturn and the backend read (compose.yaml),
# so it is on no command line, in no environment and in no `docker inspect` output (#64):
#   secrets/turn-static-auth-secret.conf  "static-auth-secret=<secret>", owner 65534 (coturn), 400
#   secrets/turn-shared-secret            "<secret>", owner 10001 (the backend image's user), 400
# The secret is never printed. It passes only through a temporary file (in memory where possible)
# that is deleted at the end. Writing files for another user needs root, so this uses sudo.
#
#   ./make-turn-secret.sh             a new random secret: first setup, or rotation
#   ./make-turn-secret.sh --from-env  moves TURN_SHARED_SECRET from .env into the files (once, when
#                                     upgrading to this version); then delete that line from .env
#
# Afterwards: docker compose up -d --force-recreate coturn backend
# A new secret makes every TURN credential issued before it invalid, so rotate at a quiet time.
set -euo pipefail

readonly DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly SECRETS_DIR="$DEPLOY_DIR/secrets"
readonly COTURN_UID=65534       # compose.yaml: user: '65534:65534'
readonly BACKEND_IMAGE_UID=10001  # Dockerfile: useradd --uid 10001
# Base64 (openssl rand -base64 32 gives 44 characters): nothing coturn's config parser or the
# backend's one-line file could misread, such as spaces, quotes or "#"; no leading "=" (coturn's
# parser would drop it, the backend not) and at most 256 characters (coturn reads lines in parts).
readonly SECRET_PATTERN='^[A-Za-z0-9+/_-][A-Za-z0-9+/=_-]{31,255}$'

mode="${1:-new}"
case "$mode" in
  new | --from-env) ;;
  *)
    echo "Usage: $0 [--from-env]" >&2
    exit 2
    ;;
esac

umask 077
if [ -d /dev/shm ] && [ -w /dev/shm ]; then
  work_dir="$(mktemp -d -p /dev/shm)"
else
  work_dir="$(mktemp -d)"
fi
trap 'rm -rf "$work_dir"' EXIT
secret_file="$work_dir/secret"

if [ "$mode" = new ]; then
  openssl rand -base64 32 | tr -d '\n' >"$secret_file"
else
  if [ ! -f "$DEPLOY_DIR/.env" ]; then
    echo "make-turn-secret.sh: no .env next to this script." >&2
    exit 1
  fi
  # The last TURN_SHARED_SECRET= line, without optional surrounding quotes.
  sed -n 's/^TURN_SHARED_SECRET=//p' "$DEPLOY_DIR/.env" | tail -n 1 \
    | sed -e "s/^[\"']//" -e "s/[\"']$//" | tr -d '\r\n' >"$secret_file"
fi
if ! grep -Eq "$SECRET_PATTERN" "$secret_file"; then
  echo "make-turn-secret.sh: the secret must be at least 32 base64 characters" \
    "(openssl rand -base64 32); nothing was written." >&2
  exit 1
fi

{ printf 'static-auth-secret='; cat "$secret_file"; echo; } >"$work_dir/turn-static-auth-secret.conf"
{ cat "$secret_file"; echo; } >"$work_dir/turn-shared-secret"

as_root=()
if [ "$(id -u)" -ne 0 ]; then as_root=(sudo); fi
mkdir -p "$SECRETS_DIR"
chmod 755 "$SECRETS_DIR"
${as_root[@]+"${as_root[@]}"} install -m 400 -o "$COTURN_UID" -g "$COTURN_UID" \
  "$work_dir/turn-static-auth-secret.conf" "$SECRETS_DIR/turn-static-auth-secret.conf"
${as_root[@]+"${as_root[@]}"} install -m 400 -o "$BACKEND_IMAGE_UID" -g "$BACKEND_IMAGE_UID" \
  "$work_dir/turn-shared-secret" "$SECRETS_DIR/turn-shared-secret"
# .env still holds the other secrets (Django's key, the database passwords): owner only.
if [ -f "$DEPLOY_DIR/.env" ]; then chmod 600 "$DEPLOY_DIR/.env"; fi

echo "Wrote $SECRETS_DIR/{turn-static-auth-secret.conf,turn-shared-secret} (the secret is not shown)."
if [ "$mode" = --from-env ]; then
  echo "Now delete the TURN_SHARED_SECRET line from .env; nothing reads it any more."
fi
echo "Then: docker compose up -d --force-recreate coturn backend"
