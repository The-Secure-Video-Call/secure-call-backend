#!/usr/bin/env bash
# Starts the pinned coturn image with turnserver.conf and a test secret, then uses the image's
# turnutils_uclient to check that a valid credential allocates and that wrong credentials,
# expired credentials and private peers are refused. Needs Docker.
# Run from anywhere: deploy/raspberry-pi/coturn/test-coturn.sh
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
image="$(sed -n 's|^ *image: \(coturn/coturn:[^ ]*\).*|\1|p' "$here/../compose.yaml" | head -n1)"
test_secret="ci-only-test-secret-not-used-anywhere"
container_name="coturn-test"
failures=0

cleanup() { docker rm -f "$container_name" >/dev/null 2>&1; }
trap cleanup EXIT

# $1 = expiry unix time. Prints "username password" (coturn REST credential, PLAN.md 3.5).
make_credential() {
  local username="$1" password
  password="$(printf '%s' "$username" | openssl dgst -sha1 -hmac "$test_secret" -binary | openssl base64)"
  echo "$username $password"
}

# $1 username, $2 password, $3 peer ip. Prints the client's output.
run_client() {
  docker exec "$container_name" timeout 20 turnutils_uclient -v -y -u "$1" -w "$2" -e "$3" -n 1 -m 1 127.0.0.1 2>&1
}

# $1 label, $2 ok|refused, $3 client output
expect() {
  local label="$1" want="$2" output="$3" got
  # An unreachable container or a client crash must never count as "refused".
  if grep -Eqi 'Error response from daemon|No such container|is not running' <<<"$output"; then
    echo "FAIL: $label (container or client not usable)"; failures=$((failures + 1)); return
  fi
  # Assumption, verify on first CI run: refusals print 401/403/Forbidden/Unauthorized or an error.
  if grep -Eqi '401|403|unauthorized|forbidden|cannot create|error' <<<"$output"; then got=refused; else got=ok; fi
  if [ "$got" = "$want" ]; then
    echo "PASS: $label"
  else
    echo "FAIL: $label (wanted $want, got $got)"
    echo "$output" | tail -n 15
    failures=$((failures + 1))
  fi
}

cleanup
docker run -d --name "$container_name" --network host \
  -v "$here/turnserver.conf:/etc/coturn/turnserver.conf:ro" \
  "$image" -c /etc/coturn/turnserver.conf --static-auth-secret="$test_secret" --external-ip=127.0.0.1 >/dev/null || exit 1
for _ in $(seq 1 20); do
  (exec 3<>/dev/tcp/127.0.0.1/3478) 2>/dev/null && break
  sleep 1
done

now="$(date +%s)"
read -r good_user good_pass < <(make_credential $((now + 600)))
read -r old_user old_pass < <(make_credential $((now - 60)))
public_peer="8.8.8.8"

expect "valid credential allocates" ok "$(run_client "$good_user" "$good_pass" "$public_peer")"
expect "wrong credential refused" refused "$(run_client "$good_user" "wrong-password" "$public_peer")"
expect "expired credential refused" refused "$(run_client "$old_user" "$old_pass" "$public_peer")"
for private_peer in 127.0.0.1 192.168.1.10 10.0.0.5 172.16.0.5 169.254.1.1 0.0.0.0 100.64.0.1 \
  224.0.0.1 ::1 fc00::1 fe80::1 ::ffff:10.0.0.5 ::ffff:127.0.0.1; do
  expect "relay to $private_peer refused" refused "$(run_client "$good_user" "$good_pass" "$private_peer")"
done

# The server logs must not contain the username or the peer IP.
if docker logs "$container_name" 2>&1 | grep -Fq -e "$good_user" -e "$public_peer"; then
  echo "FAIL: coturn logs contain a username or peer IP"; failures=$((failures + 1))
else
  echo "PASS: logs contain no username or peer IP"
fi

# The admin CLI must be off.
if (exec 3<>/dev/tcp/127.0.0.1/5766) 2>/dev/null; then
  echo "FAIL: CLI port 5766 is open"; failures=$((failures + 1))
else
  echo "PASS: CLI port 5766 closed"
fi

# Informational probe (not asserted): is an allocation refresh refused once the username
# has expired? The credential expires in 5 s; the client keeps the allocation open longer.
read -r short_user short_pass < <(make_credential $(($(date +%s) + 5)))
echo "--- refresh-after-expiry probe (informational, read the output) ---"
docker exec "$container_name" timeout 40 turnutils_uclient -v -y -u "$short_user" -w "$short_pass" \
  -e "$public_peer" -n 1 -m 30 -l 100 127.0.0.1 2>&1 | tail -n 20

if [ "$failures" -eq 0 ]; then
  echo "All coturn checks passed."
else
  echo "$failures coturn check(s) failed."
  exit 1
fi
