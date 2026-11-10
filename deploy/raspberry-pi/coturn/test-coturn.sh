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

usernames_file="$(mktemp)"

cleanup() { docker rm -f "$container_name" >/dev/null 2>&1; rm -f "$usernames_file"; }
trap cleanup EXIT

# $1 = seconds until the credential expires (negative = already expired). Prints
# "username password" (coturn REST credential, PLAN.md 3.5). Every call gets its own random
# username, so user-quota=12 never interferes between checks.
make_credential() {
  local username password
  username="$(( $(date +%s) + $1 )):$(openssl rand -hex 6)"
  password="$(printf '%s' "$username" | openssl dgst -sha1 -hmac "$test_secret" -binary | openssl base64)"
  echo "$username" >>"$usernames_file"
  echo "$username $password"
}

# $1 = seconds until expiry, $2 = peer ip, $3 = optional wrong password. Uses a fresh credential.
# Prints the client's output. No -y: that is client-to-client mode, which ignores -e and binds
# the client's own relay address instead of the peer.
run_client() {
  local username password
  read -r username password < <(make_credential "$1")
  if [ -n "${3-}" ]; then password="$3"; fi
  local client_output client_exit_code
  client_output="$(docker exec "$container_name" timeout 20 turnutils_uclient -v -u "$username" -w "$password" -e "$2" -n 1 -m 1 127.0.0.1 2>&1)"
  client_exit_code=$?
  # The exit code travels with the output, so expect() can reject a timeout or a crash.
  printf '%s\nCLIENT_EXIT_CODE=%s\n' "$client_output" "$client_exit_code"
}

# $1 label, $2 bound|forbidden|no_allocation, $3 client output
# turnutils_uclient (4.6.3) prints, as seen in CI:
#   allocation worked:      "Received relay addr: ..." (after a 401 challenge, which is NOT a refusal)
#   peer allowed:           "channel bind: success"
#   peer denied by config:  "channel bind: error 403 (Forbidden IP)"
# bound         = allocation worked AND the channel bind to the peer succeeded
# forbidden     = allocation worked AND the channel bind was refused with
#               "error 403 (Forbidden IP)" (never a success, never another 403)
# no_allocation = no relay address was granted AND the output shows a 4xx error line (positive
#               evidence of a refusal, e.g. 401 for a bad or expired credential)
# Anything else ("unclear") fails. IPv6 and IPv4-mapped peers are not tested here: the client
# only gets IPv4 relays; address_family_probe.py checks them with specific error codes.
expect() {
  local label="$1" want="$2" output="$3" got exit_code
  # An unreachable container, a timeout or a client crash must never count as a result.
  exit_code="$(sed -n 's/^CLIENT_EXIT_CODE=//p' <<<"$output" | tail -n 1)"
  if [ -z "$exit_code" ] \
    || grep -Eqi 'OCI runtime exec failed|Error response from daemon|No such container|is not running' <<<"$output" \
    || [[ "$exit_code" =~ ^(124|125|126|127|1[3-4][0-9])$ ]]; then
    echo "FAIL: $label (container or client not usable, exit code '${exit_code}')"
    echo "$output" | tail -n 15
    failures=$((failures + 1)); return
  fi
  # bound: a relay address was granted, the server sent no error (the 401 challenge that starts
  # every long-term-credential exchange is not an error), and either a bind/permission success
  # line is present or the send summary shows messages sent with 0 dropped. 8.8.8.8 does not
  # echo, so a reply is not expected.
  if grep -Fq 'Received relay addr' <<<"$output" \
    && ! grep -Eq 'error (40[02-9]|4[1-9][0-9]|5[0-9][0-9])' <<<"$output" \
    && { grep -Fq 'channel bind: success' <<<"$output" \
      || { grep -Eq 'tot_send_msgs=[1-9]' <<<"$output" && grep -Eq 'total send dropped 0([^0-9]|$)' <<<"$output"; }; }; then
    got=bound
  elif grep -Fq 'Received relay addr' <<<"$output" \
    && grep -Eq 'channel bind: error 403.*Forbidden IP' <<<"$output"; then
    got=forbidden
  elif ! grep -Fq 'Received relay addr' <<<"$output" && grep -Eqi 'error[ :]*4[0-9][0-9]' <<<"$output"; then
    got=no_allocation
  else
    got=unclear
  fi
  if [ "$got" = "$want" ]; then
    echo "PASS: $label"
    # Show the whole client output for the valid check, so the log shows which line proves it.
    if [ "$want" = bound ]; then echo "--- full client output ---"; echo "$output"; echo "--- end ---"; fi
  else
    echo "FAIL: $label (wanted $want, got $got)"
    if [ "$want" = bound ]; then echo "$output"; else echo "$output" | tail -n 15; fi
    failures=$((failures + 1))
  fi
}

wait_for_turn_port() {
  local attempt
  for attempt in $(seq 1 20); do
    (exec 3<>/dev/tcp/127.0.0.1/3478) 2>/dev/null && return 0
    sleep 1
  done
  return 1
}

restart_coturn() { docker restart "$container_name" >/dev/null && wait_for_turn_port; }

# The Pi passes --relay-ip=$TURN_RELAY_IP (its LAN IPv4); the test uses the runner's own IPv4.
relay_ip="$(hostname -I | tr ' ' '\n' | grep -m1 -E '^[0-9]+(\.[0-9]+){3}$')"
relay_ip="${relay_ip:-127.0.0.1}"

cleanup
docker run -d --name "$container_name" --network host \
  -v "$here/turnserver.conf:/etc/coturn/turnserver.conf:ro" \
  "$image" -c /etc/coturn/turnserver.conf --static-auth-secret="$test_secret" \
  --external-ip=127.0.0.1 --relay-ip="$relay_ip" >/dev/null || exit 1
wait_for_turn_port || { echo "FAIL: coturn did not start"; exit 1; }

# bps-capacity / max-bps allows about 37 concurrent allocations (README). Each group below stays
# well under that, and coturn is restarted (fresh state) between groups.
restart_or_exit() { restart_coturn || { echo "FAIL: coturn did not restart"; exit 1; }; }

public_peer="8.8.8.8"

echo "== Group 1: credentials and common private peers =="
expect "valid credential allocates and may relay to a public peer" bound "$(run_client 600 "$public_peer")"
expect "wrong credential refused" no_allocation "$(run_client 600 "$public_peer" "wrong-password")"
expect "expired credential refused" no_allocation "$(run_client -60 "$public_peer")"
for private_peer in 127.0.0.1 192.168.1.10 10.0.0.5 172.16.0.5 169.254.1.1 0.0.0.0 100.64.0.1 \
  224.0.0.1; do
  expect "relay to $private_peer refused" forbidden "$(run_client 600 "$private_peer")"
done

restart_or_exit
echo "== Group 2: range edges are denied =="
for edge_peer in 0.0.0.1 100.127.255.255 172.31.255.255 198.19.0.1 192.0.0.1 240.0.0.1 255.255.255.255; do
  expect "range edge $edge_peer refused" forbidden "$(run_client 600 "$edge_peer")"
done

restart_or_exit
echo "== Group 3: neighbours of the denied ranges are allowed =="
for neighbour_peer in 11.0.0.1 100.128.0.1 172.32.0.1 198.20.0.1 1.1.1.1; do
  expect "neighbour $neighbour_peer allowed" bound "$(run_client 600 "$neighbour_peer")"
done

restart_or_exit
echo "== Group 4: IPv6 relay request and IPv6 / IPv4-mapped peers (raw STUN) =="
read -r probe_user probe_pass < <(make_credential 600)
# Not -I: the probe imports refresh_after_expiry.py from its own folder (repo code, not user input).
address_family_output="$(python3 "$here/address_family_probe.py" "$probe_user" "$probe_pass" 2>&1)"
echo "$address_family_output"
# $1 = label as printed by the probe, $2 = regex the outcome must match
expect_probe() {
  if grep -Eq "^PROBE $1: $2\$" <<<"$address_family_output"; then
    echo "PASS: $1 -> expected outcome"
  else
    echo "FAIL: $1 (wanted $2)"; failures=$((failures + 1))
  fi
}
# 440 Address Family not Supported: the relay has no IPv6 address. Control: a public IPv4 peer works.
expect_probe "ipv6 relay request" "error 440"
expect_probe "permission $public_peer" "success"
# 403 Forbidden (deny list) or 443 Peer Address Family Mismatch (IPv6 peer on an IPv4 relay).
for ipv6_peer in ::1 fc00::1 fe80::1 ::ffff:10.0.0.5 ::ffff:127.0.0.1 ::ffff:192.168.1.10 ::ffff:169.254.1.1; do
  expect_probe "permission $ipv6_peer" "error (403|443)"
done

# The server logs must not contain any username or the peer IP. Logging is off in the config, so
# they should be empty; if not, show the offending lines with the values masked.
server_logs="$(docker logs "$container_name" 2>&1)"
if grep -Fq -f "$usernames_file" <<<"$server_logs" || grep -Fq "$public_peer" <<<"$server_logs"; then
  echo "FAIL: coturn logs contain a username or peer IP. Offending lines (values masked):"
  grep -F -e "$public_peer" -f "$usernames_file" <<<"$server_logs" | head -n 10 \
    | sed -E 's/[0-9]{9,}:[0-9a-f]{12}/<USERNAME>/g; s/[0-9]{1,3}(\.[0-9]{1,3}){3}/<IP>/g'
  failures=$((failures + 1))
else
  echo "PASS: logs contain no username or peer IP"
fi

# Logging must stay off by configuration, not only by luck: no verbose, syslog or log-binding
# option in the config (comments ignored) or on the container's command line.
if grep -Ev '^[[:space:]]*#' "$here/turnserver.conf" \
  | grep -Eiq '^[[:space:]]*(verbose|syslog|log-binding|Verbose)([[:space:]]|=|$)'; then
  echo "FAIL: turnserver.conf enables verbose, syslog or log-binding"; failures=$((failures + 1))
elif grep -Ev '^[[:space:]]*#' "$here/../compose.yaml" | grep -Eq -- "--verbose|--syslog|--log-binding|'-v'|'-V'"; then
  echo "FAIL: compose.yaml passes a verbose, syslog or log-binding option"; failures=$((failures + 1))
else
  echo "PASS: config has no verbose, syslog or log-binding"
fi

# No log files may exist in the container after the run (regular files written in the last
# hour that look like logs). A failing docker exec is a failure, not "no files".
log_files_output="$(docker exec "$container_name" find / -xdev -type f -mmin -60 \
  \( -name '*.log' -o -name 'turn_*' -o -path '/var/log/*' \) 2>&1)"
log_files_exit_code=$?
if [ "$log_files_exit_code" -ne 0 ]; then
  echo "FAIL: could not search the container for log files (exit $log_files_exit_code)"
  echo "$log_files_output" | tail -n 5
  failures=$((failures + 1))
elif [ -n "$log_files_output" ]; then
  echo "FAIL: log files exist in the container:"; echo "$log_files_output" | head -n 10
  failures=$((failures + 1))
else
  echo "PASS: no log files in the container"
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
# Restart first, so the probe starts from fresh state and shares no quota with the other checks.
if ! restart_coturn; then
  echo "FAIL: coturn did not restart"; failures=$((failures + 1))
fi
read -r short_user short_pass < <(make_credential 5)
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
