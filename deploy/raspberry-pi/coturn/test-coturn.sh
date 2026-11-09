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

# $1 label, $2 bound|forbidden|no_allocation, $3 client output
# turnutils_uclient (4.6.3) prints, as seen in CI:
#   allocation worked:      "Received relay addr: ..." (after a 401 challenge, which is NOT a refusal)
#   peer allowed:           "channel bind: success"
#   peer denied by config:  "channel bind: error 403 (Forbidden IP)"
# bound         = allocation worked AND the channel bind to the peer succeeded
# forbidden     = allocation worked AND the channel bind was refused with 403 (never a success)
# no_allocation = no relay address was ever granted (bad or expired credential)
expect() {
  local label="$1" want="$2" output="$3" got
  # An unreachable container or a client crash must never count as a result.
  if grep -Eqi 'Error response from daemon|No such container|is not running' <<<"$output"; then
    echo "FAIL: $label (container or client not usable)"; failures=$((failures + 1)); return
  fi
  if grep -Fq 'channel bind: success' <<<"$output"; then
    got=bound
  elif grep -Fq 'Received relay addr' <<<"$output" && grep -Fq 'channel bind: error 403' <<<"$output"; then
    got=forbidden
  elif ! grep -Fq 'Received relay addr' <<<"$output"; then
    got=no_allocation
  else
    got=unclear
  fi
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

expect "valid credential allocates and may relay to a public peer" bound "$(run_client "$good_user" "$good_pass" "$public_peer")"
expect "wrong credential refused" no_allocation "$(run_client "$good_user" "wrong-password" "$public_peer")"
expect "expired credential refused" no_allocation "$(run_client "$old_user" "$old_pass" "$public_peer")"
for private_peer in 127.0.0.1 192.168.1.10 10.0.0.5 172.16.0.5 169.254.1.1 0.0.0.0 100.64.0.1 \
  224.0.0.1 ::1 fc00::1 fe80::1 ::ffff:10.0.0.5 ::ffff:127.0.0.1 ::ffff:192.168.1.10 ::ffff:169.254.1.1; do
  expect "relay to $private_peer refused" forbidden "$(run_client "$good_user" "$good_pass" "$private_peer")"
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

# Refresh-after-expiry probe (result recorded in README.md for #26, not asserted): allocate
# with a credential that expires 5 s later, wait 10 s, then send a Refresh for that allocation.
# The server runs with host networking, so the probe on the runner reaches it on 127.0.0.1.
read -r short_user short_pass < <(make_credential $(($(date +%s) + 5)))
probe_output="$(python3 -I "$here/refresh_after_expiry.py" "$short_user" "$short_pass" 10 2>&1)"
if grep -Eq '^REFRESH AFTER EXPIRY: (allowed|refused)$' <<<"$probe_output"; then
  grep -E '^REFRESH AFTER EXPIRY: (allowed|refused)$' <<<"$probe_output"
else
  echo "FAIL: refresh-after-expiry probe did not produce a result"
  echo "$probe_output" | tail -n 5
  failures=$((failures + 1))
fi

if [ "$failures" -eq 0 ]; then
  echo "All coturn checks passed."
else
  echo "$failures coturn check(s) failed."
  exit 1
fi
