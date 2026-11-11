#!/usr/bin/env bash
# Starts the pinned coturn image with turnserver.conf and a test secret, then uses the image's
# turnutils_uclient to check that a valid credential allocates and that wrong credentials,
# expired credentials and private peers are refused. Needs Docker.
# Run from anywhere: deploy/raspberry-pi/coturn/test-coturn.sh
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
image="secure-call-coturn:test"
test_secret="ci-only-test-secret-not-used-anywhere"
container_name="coturn-test"
# Same network as compose.yaml: its own bridge, a small subnet inside 172.16.0.0/12 (denied as a
# peer), coturn at a fixed address. The gateway is the Docker host (the runner here, the Pi there).
network_name="coturn-test-net"
network_subnet="172.30.200.0/29"
gateway_ip="172.30.200.1"
container_ip="172.30.200.2"
# Stands in for the home's public IP: the Pi passes --external-ip=<public>/<relay> and
# --denied-peer-ip=<public> (compose.yaml), so a peer at the public IP is refused explicitly.
test_public_ip="203.0.113.7"
failures=0

usernames_file="$(mktemp)"
# Usernames of the deliberate failures (wrong password, expired): coturn may log these.
failed_login_usernames_file="$(mktemp)"
peers_file="$(mktemp)"
denied_ranges_file="$(mktemp)"
# The certificate and the secret file coturn reads (made below, once the early cleanup ran).
test_files_dir=""
turn_host_name="turn.securevideocall.com"
# Extra turnutils_uclient arguments; the TLS group sets them to -t -S -p 5349.
uclient_transport_args=()

cleanup() { docker rm -f "$container_name" >/dev/null 2>&1; docker network rm "$network_name" >/dev/null 2>&1; rm -f "$usernames_file" "$failed_login_usernames_file" "$peers_file" "$denied_ranges_file"; if [ -n "$test_files_dir" ]; then rm -rf "$test_files_dir"; fi; }
trap cleanup EXIT

# $1 = seconds until the credential expires (negative = already expired). Prints
# "username password" (coturn REST credential, PLAN.md 3.5). Every call gets its own random
# username, so user-quota=6 never interferes between checks.
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
  echo "$2" >>"$peers_file"
  if [ -n "${3-}" ]; then password="$3"; fi
  if [ -n "${3-}" ] || [ "$1" -lt 0 ]; then echo "$username" >>"$failed_login_usernames_file"; fi
  local client_output client_exit_code
  client_output="$(docker exec "$container_name" timeout 20 turnutils_uclient -v ${uclient_transport_args[@]+"${uclient_transport_args[@]}"} -u "$username" -w "$password" -e "$2" -n 1 -m 1 127.0.0.1 2>&1)"
  client_exit_code=$?
  # The exit code travels with the output, so expect() can reject a timeout or a crash.
  printf '%s\nCLIENT_EXIT_CODE=%s\n' "$client_output" "$client_exit_code"
}

# $1 label, $2 bound|forbidden|no_allocation, $3 client output
# turnutils_uclient prints, as seen in CI (coturn 4.18.0; 4.6.3 wording in brackets):
#   allocation worked:      "Received relay addr: ..." (after a 401 challenge, which is NOT a refusal)
#   peer allowed:           "cb response received:" then "success: 0x<channel>"
#                           ["channel bind: success"]
#   peer denied by config:  "channel bind: error 403 ()" ["channel bind: error 403 (Forbidden IP)"]
#   login refused:          "ERROR Cannot complete Allocation" ["ERROR: Cannot complete Allocation"]
# coturn 4.18 no longer sends reason texts (less amplification), so a refusal is read from its
# code. For a UDP allocation, coturn's ChannelBind answers 403 only when good_peer_addr() rejects
# the peer (ns_turn_server.c, handle_turn_channel_bind; the one other 403 is for TCP relays,
# which no-tcp-relay turns off), so a 403 there is the deny list / peer policy and nothing else.
# bound         = allocation worked, no error 4xx/5xx, AND a channel bind to the peer succeeded
# forbidden     = allocation worked, every channel bind was refused with 403, none succeeded
# no_allocation = no relay address was granted AND the output shows a 4xx error line or
#               "Cannot complete Allocation" (positive evidence of a refusal, e.g. 401 for a bad
#               or expired credential)
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
  local channel_bind_succeeded=no
  # "success: 0x<channel>" is printed only by uclient's ChannelBind success path
  # (startuclient.c), so it counts wherever it appears.
  if grep -Fq 'channel bind: success' <<<"$output" \
    || grep -Eq 'success: 0x[0-9a-fA-F]+' <<<"$output"; then
    channel_bind_succeeded=yes
  fi
  if grep -Fq 'Received relay addr' <<<"$output" \
    && ! grep -Eq 'error (40[02-9]|4[1-9][0-9]|5[0-9][0-9])' <<<"$output" \
    && { [ "$channel_bind_succeeded" = yes ] \
      || { grep -Eq 'tot_send_msgs=[1-9]' <<<"$output" && grep -Eq 'total send dropped 0([^0-9]|$)' <<<"$output"; }; }; then
    got=bound
  elif grep -Fq 'Received relay addr' <<<"$output" \
    && [ "$channel_bind_succeeded" = no ] \
    && grep -Eq 'channel bind: error 403( \((Forbidden IP)?\))?[[:space:]]*$' <<<"$output" \
    && ! grep -E 'channel bind: error' <<<"$output" | grep -Evq 'channel bind: error 403( \((Forbidden IP)?\))?[[:space:]]*$'; then
    got=forbidden
  elif ! grep -Fq 'Received relay addr' <<<"$output" \
    && grep -Eqi 'error[ :]*4[0-9][0-9]|ERROR:? Cannot complete Allocation' <<<"$output"; then
    # A wrong or expired credential: the client prints "ERROR: Cannot complete Allocation" (exit
    # code 255) after the repeated 401 challenges, with no explicit 401 line.
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
    (exec 3<>/dev/tcp/"$container_ip"/3478) 2>/dev/null && return 0
    sleep 1
  done
  return 1
}

# Masks usernames and IPv4 addresses so a failing check can show a line without leaking values.
mask_values() { sed -E 's/[0-9]{9,}:[0-9a-f]{12}/<USERNAME>/g; s/[0-9]{1,3}(\.[0-9]{1,3}){3}/<IP>/g'; }

# Looks for log files in the container, as root (so a permission error cannot hide a file):
#  - on the real (non-tmpfs) filesystem: any log-like file written in the last hour fails. The
#    root filesystem is read-only in compose.yaml, so there should be none. -xdev skips the tmpfs
#    mounts, which are searched separately below.
#  - on the tmpfs mounts (/var/tmp, /tmp, /var/log): files are reported (name, line count, masked
#    first lines, to show what wrote them); a file containing a test username or peer IP fails.
# tmpfs contents vanish when the container stops, so this also runs before every restart.
inspect_log_files() {
  local when="$1" real_files real_exit tmpfs_files tmpfs_exit file line_count
  real_files="$(docker exec --privileged -u 0 "$container_name" find / -xdev -type f -mmin -60 \
    \( -name '*.log' -o -name 'turn_*' -o -path '/var/log/*' \) 2>&1)"
  real_exit=$?
  if [ "$real_exit" -ne 0 ]; then
    echo "FAIL: could not search the container for log files ($when, exit $real_exit)"
    echo "$real_files" | tail -n 5
    failures=$((failures + 1))
  elif [ -n "$real_files" ]; then
    echo "FAIL: log files exist on the container's real filesystem ($when):"
    echo "$real_files" | head -n 10
    failures=$((failures + 1))
  else
    echo "PASS: no log files on the real filesystem ($when)"
  fi
  tmpfs_files="$(docker exec --privileged -u 0 "$container_name" find /var/tmp /tmp /var/log /dev/shm -type f 2>&1)"
  tmpfs_exit=$?
  if [ "$tmpfs_exit" -ne 0 ]; then
    echo "FAIL: could not search the tmpfs mounts for log files ($when, exit $tmpfs_exit)"
    echo "$tmpfs_files" | tail -n 5
    failures=$((failures + 1))
    return
  fi
  if [ -z "$tmpfs_files" ]; then
    echo "PASS: no files on the tmpfs mounts ($when)"
    return
  fi
  while IFS= read -r file; do
    # Expected: the pid file, and the shared-memory statistics segment of the MongoDB driver linked
    # into coturn (no log data). Anything else, above all a log file, means coturn wrote a log: the
    # config is meant to send every line to stdout, which compose.yaml discards on the Pi.
    case "$file" in
      /var/tmp/turnserver.pid | /dev/shm/mongoc-*) ;;
      *)
        echo "FAIL: unexpected file on a tmpfs mount ($when): $file (coturn must not write a log file)"
        failures=$((failures + 1))
        ;;
    esac
    line_count="$(docker exec --privileged -u 0 "$container_name" wc -l "$file" 2>&1 | awk '{print $1}')"
    echo "NOTE: tmpfs file $file ($when): $line_count lines. First lines (values masked):"
    docker exec --privileged -u 0 "$container_name" head -n 5 "$file" 2>&1 | mask_values | sed 's/^/    /'
    if docker exec --privileged -u 0 "$container_name" cat "$file" 2>/dev/null \
      | grep -Fwq -f "$usernames_file" -f "$peers_file"; then
      echo "FAIL: $file contains a test username or peer IP ($when)"
      failures=$((failures + 1))
    else
      echo "PASS: $file contains no test username or peer IP ($when)"
    fi
  done <<<"$tmpfs_files"
}

restart_coturn() {
  inspect_log_files "before restart"
  docker restart "$container_name" >/dev/null && wait_for_turn_port
}

# The Docker host's own LAN IPv4 (the runner here, the Pi's LAN IP on the Pi). The probes listen on
# it and on the bridge gateway, and must see nothing arrive through the relay.
host_lan_ip="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.*src \([0-9.]*\).*/\1/p' | head -n1)"
[ -n "$host_lan_ip" ] || host_lan_ip="$(hostname -I | tr ' ' '\n' | grep -m1 -E '^[0-9]+(\.[0-9]+){3}$')"
if [ -z "$host_lan_ip" ]; then echo "FAIL: no IPv4 address on this host"; exit 1; fi
# The raw STUN probes talk to coturn at its container address (the host reaches the bridge).
export TURN_SERVER_HOST="$container_ip"

cleanup # also removes the temp files; they are recreated on first use
# Peers the test asks for (the log checks look for them): the Docker host's addresses.
printf '%s\n' "$host_lan_ip" "$gateway_ip" >>"$peers_file"

# Test stand-ins for what compose.yaml mounts on the Pi: a TLS certificate for the TURN host name
# from a throwaway CA (the Pi uses the publicly trusted one, coturn/install-turn-certificate.sh),
# and the "static-auth-secret=..." file (make-turn-secret.sh). On the Pi the key and the secret
# file are owned by coturn's user with mode 400; this test runs without root, so they are 0444.
test_files_dir="$(mktemp -d)"
mkdir -p "$test_files_dir/tls"
test_ec_key=(-newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes)
openssl req -x509 "${test_ec_key[@]}" -keyout "$test_files_dir/ca.key" -subj "/CN=coturn test CA" \
  -days 1 -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -out "$test_files_dir/ca.crt" 2>/dev/null \
  && openssl req "${test_ec_key[@]}" -keyout "$test_files_dir/tls/privkey.pem" -subj "/CN=$turn_host_name" \
    -out "$test_files_dir/leaf.csr" 2>/dev/null \
  && printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' \
    'extendedKeyUsage=serverAuth' "subjectAltName=DNS:$turn_host_name" >"$test_files_dir/leaf.ext" \
  && openssl x509 -req -in "$test_files_dir/leaf.csr" -CA "$test_files_dir/ca.crt" \
    -CAkey "$test_files_dir/ca.key" -set_serial 1 -days 1 -extfile "$test_files_dir/leaf.ext" \
    -out "$test_files_dir/leaf.crt" 2>/dev/null \
  && cat "$test_files_dir/leaf.crt" "$test_files_dir/ca.crt" >"$test_files_dir/tls/fullchain.pem" \
  || { echo "FAIL: could not make the test TLS certificate"; exit 1; }
printf 'static-auth-secret=%s\n' "$test_secret" >"$test_files_dir/turn-static-auth-secret.conf"
chmod 0755 "$test_files_dir/tls"
chmod 0444 "$test_files_dir/tls/fullchain.pem" "$test_files_dir/tls/privkey.pem" \
  "$test_files_dir/turn-static-auth-secret.conf"
# How compose.yaml starts coturn (tests/test_compose_hardening.py keeps the two identical): the
# secret is joined to the config in memory, readable by coturn's user only, and turnserver
# becomes pid 1 with no secret on its command line.
coturn_start_script='umask 077 && { cat /etc/coturn/turnserver.conf && echo && cat /run/secrets/turn-static-auth-secret.conf; } > /run/coturn/turnserver.conf && exec turnserver -c /run/coturn/turnserver.conf "$@"'
echo "== Build the derived image (coturn/Dockerfile) =="
docker build -q -t "$image" "$here" || { echo "FAIL: docker build"; exit 1; }
docker network create --driver bridge --subnet "$network_subnet" --gateway "$gateway_ip" "$network_name" >/dev/null \
  || { echo "FAIL: could not create the docker network"; exit 1; }
# Same hardening as compose.yaml: own bridge network with a fixed address (no host networking),
# read-only root filesystem, small tmpfs mounts only, no capabilities at all (the derived image has
# no file capability on turnserver), no-new-privileges, no core dumps, the same start script
# (turnserver ends up as pid 1, the secret only in a mode-600 file in memory), and the same
# mounts. Ports are not published here: the clients and probes reach the container on the bridge.
# Test-only differences from the Pi: the test secret and certificate, a documentation address as
# the public IP, and
# --stale-nonce=20 (the nonce rotates after 20 s, so the refresh probe below also covers a nonce
# rotation; the Pi keeps the config's default).
docker run -d --name "$container_name" --network "$network_name" --ip "$container_ip" --read-only \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --ulimit core=0 --user 65534:65534 \
  --tmpfs /var/tmp:size=1m,mode=1777,noexec,nosuid,nodev \
  --tmpfs /tmp:size=1m,mode=1777,noexec,nosuid,nodev \
  --tmpfs /var/log:size=1m,mode=1777,noexec,nosuid,nodev \
  --tmpfs /run/coturn:size=64k,mode=1777,noexec,nosuid,nodev \
  -v "$here/turnserver.conf:/etc/coturn/turnserver.conf:ro" \
  -v "$test_files_dir/turn-static-auth-secret.conf:/run/secrets/turn-static-auth-secret.conf:ro" \
  -v "$test_files_dir/tls:/etc/coturn/tls:ro" \
  --entrypoint sh \
  "$image" -c "$coturn_start_script" coturn-start --log-file=stdout --no-stdout-log \
  --external-ip="$test_public_ip/$container_ip" --denied-peer-ip="$test_public_ip" \
  --relay-ip="$container_ip" --listening-ip="$container_ip" --listening-ip=127.0.0.1 \
  --stale-nonce=20 >/dev/null || exit 1
if ! wait_for_turn_port; then
  echo "FAIL: coturn did not start. Diagnostics:"
  echo "-- docker logs:"
  docker logs "$container_name" 2>&1 | mask_values | sed "s|$test_secret|<SECRET>|g" | tail -n 30
  echo "-- docker inspect (status exit-code error):"
  docker inspect --format "{{.State.Status}} {{.State.ExitCode}} {{.State.Error}}" "$container_name" 2>&1
  echo "-- file capabilities on turnserver:"
  for turnserver_path in /usr/bin/turnserver /usr/local/bin/turnserver; do
    # getcap may be missing from the image; fall back to getfattr, then to python3's getxattr.
    docker run --rm --network none --entrypoint sh "$image" -c \
      "command -v turnserver; ls -l $turnserver_path; if command -v getcap >/dev/null; then getcap $turnserver_path; \
       elif command -v getfattr >/dev/null; then getfattr -d -m - $turnserver_path; \
       else echo 'no getcap or getfattr in the image'; fi" 2>&1 \
      | mask_values | sed "s|$test_secret|<SECRET>|g; s|^|  |"
  done
  exit 1
fi

# coturn prints a startup banner even with logging off. Capture it now, before any client has
# connected, so it cannot hold user data. At the end, no line outside this banner may appear.
# Every line becomes "LEVEL: message". coturn 4.18 writes "2026-11-10T13:36:16.103+0000 INFO
# message" (ISO time, the level without a colon); 4.6.3 wrote "0: (1): INFO: message".
strip_log_prefix() {
  sed -E 's/^[0-9]+: \([0-9]+\): //; s/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?([+-][0-9]{4}|Z) (DEBUG|INFO|WARNING|ERROR) /\3: /'
}
sleep 2 # let the banner finish printing after the port opens
startup_banner="$(docker logs "$container_name" 2>&1 | strip_log_prefix | sort -u)"

# turnserver is pid 1 (entrypoint) and must run with no effective capabilities: the file
# capability NET_BIND_SERVICE is not granted under no-new-privileges. A compromised turnserver on
# the host network could otherwise bind ports below 1024 (53, 67, ...) on the home LAN.
process_status="$(docker exec -u 0 "$container_name" sh -c 'cat /proc/1/comm; grep -E "^(Uid|Gid|CapEff|NoNewPrivs):" /proc/1/status' 2>&1)"
echo "turnserver process (pid 1):"; sed 's/^/    /' <<<"$process_status"
# Uid and Gid are "real effective saved filesystem": none may be 0 (turnserver never runs as root;
# --user 65534:65534 is set because --entrypoint turnserver skips the image's switch of user).
if [ "$(sed -n '1p' <<<"$process_status")" = "turnserver" ] \
  && grep -Eq '^Uid:([[:space:]]+[1-9][0-9]*){4}$' <<<"$process_status" \
  && grep -Eq '^Gid:([[:space:]]+[1-9][0-9]*){4}$' <<<"$process_status" \
  && grep -Eq '^CapEff:[[:space:]]+0+$' <<<"$process_status" \
  && grep -Eq '^NoNewPrivs:[[:space:]]+1$' <<<"$process_status"; then
  echo "PASS: turnserver is pid 1, not root (Uid/Gid non-zero), with CapEff 0 and NoNewPrivs 1"
else
  echo "FAIL: turnserver is not pid 1 as a non-root user with CapEff 0 and NoNewPrivs 1:"
  echo "$process_status" | head -n 6
  failures=$((failures + 1))
fi

# The secret is on no command line and in no environment (#64): neither pid 1's command line
# and environment nor `docker inspect` contains it. The config that holds it is in memory, mode
# 600, owned by coturn's user. (That coturn uses it is shown by the valid logins below.)
pid1_command_line="$(docker exec -u 0 "$container_name" sh -c 'tr "\000" " " </proc/1/cmdline' 2>&1)"
secret_places="$(printf '%s\n' "$pid1_command_line"; docker exec -u 0 "$container_name" sh -c 'tr "\000" "\n" </proc/1/environ' 2>&1; docker inspect "$container_name" 2>&1)"
secret_config_owner="$(docker exec -u 0 "$container_name" stat -c '%a %u' /run/coturn/turnserver.conf 2>&1)"
if grep -Fq -- "$test_secret" <<<"$secret_places"; then
  echo "FAIL: the TURN secret appears on pid 1's command line, in its environment or in docker inspect"
  failures=$((failures + 1))
elif ! grep -Eq '^turnserver -c /run/coturn/turnserver\.conf ' <<<"$pid1_command_line"; then
  echo "FAIL: turnserver does not run with the config made in memory (/run/coturn/turnserver.conf)"
  failures=$((failures + 1))
elif [ "$secret_config_owner" != "600 65534" ]; then
  echo "FAIL: the config with the secret is not mode 600 owned by 65534 (got: $secret_config_owner)"
  failures=$((failures + 1))
else
  echo "PASS: the secret is on no command line, in no environment and not in docker inspect; its config is mode 600, owned by coturn's user"
fi

# The derived image must leave no file capability on turnserver. Two checks, in a throwaway
# container with no network:
#  1. getcap / getfattr (whichever the image has) shows no capability on the binary;
#  2. turnserver still starts as uid 65534 with every capability dropped and WITHOUT
#     no-new-privileges: with a file capability present the kernel refuses to exec it then.
file_capability_report="$(docker run --rm --network none --user 0 --entrypoint sh "$image" -c \
  'p="$(command -v turnserver)"; ls -l "$p"; if command -v getcap >/dev/null; then echo "getcap: [$(getcap "$p")]"; \
   elif command -v getfattr >/dev/null; then echo "getfattr: [$(getfattr -d -m security.capability "$p" 2>&1 | grep -c security.capability)]"; \
   else echo "NO_TOOL"; fi' 2>&1)"
echo "turnserver file capability report:"; sed 's/^/    /' <<<"$file_capability_report"
if grep -Eq '^getcap: \[\]$|^getfattr: \[0\]$|^NO_TOOL$' <<<"$file_capability_report" \
  && ! grep -Eq 'cap_|getfattr: \[[1-9]' <<<"$file_capability_report"; then
  echo "PASS: turnserver has no file capability (or no tool to show one; the exec check below decides)"
else
  echo "FAIL: turnserver still has a file capability"; failures=$((failures + 1))
fi
exec_check_output="$(docker run --rm --network none --user 65534:65534 --cap-drop ALL --entrypoint turnserver "$image" -h 2>&1)"
if grep -Eqi 'coturn|turnserver' <<<"$exec_check_output" \
  && ! grep -Eqi 'operation not permitted|permission denied|exec format|cannot execute' <<<"$exec_check_output"; then
  echo "PASS: turnserver starts as uid 65534 with all capabilities dropped and no no-new-privileges"
else
  echo "FAIL: turnserver does not start as uid 65534 with all capabilities dropped (file capability left?)"
  echo "$exec_check_output" | head -n 5
  failures=$((failures + 1))
fi

# Sockets, read from the container's own /proc/net (its network namespace) before any client
# runs, as "address:port" in /proc's hex: TCP listeners must be coturn's 3478 (0D96) or its TLS
# listener on 5349 (14E5), and every UDP socket coturn's 3478, or Docker's embedded DNS on
# 127.0.0.11 (0B00007F, which Docker itself runs in every container on a user-defined network,
# on random ports). So no DTLS listener on 5349/udp, no CLI
# (127.0.0.1:5766 by default), no web-admin or prometheus port, and no other UDP service, which
# matters because --external-ip puts this container's address on coturn's peer whitelist.
# No relay port is open yet at this point. Reading nothing, or no 3478, fails.
tcp_listeners="$(docker exec -u 0 "$container_name" cat /proc/net/tcp /proc/net/tcp6 2>/dev/null \
  | awk '$4 == "0A" && $2 ~ /:[0-9A-F]+$/ {print $2}' | sort -u)"
udp_sockets="$(docker exec -u 0 "$container_name" cat /proc/net/udp /proc/net/udp6 2>/dev/null \
  | awk '$2 ~ /:[0-9A-F]+$/ {print $2}' | sort -u)"
echo "TCP listeners (hex address:port):"; sed 's/^/    /' <<<"$tcp_listeners"
echo "UDP sockets (hex address:port):"; sed 's/^/    /' <<<"$udp_sockets"
unexpected_sockets="$( { grep -Ev '^0B00007F:|:0D96$|:14E5$' <<<"$tcp_listeners"; \
  grep -Ev '^0B00007F:|:0D96$' <<<"$udp_sockets"; } | grep -v '^$' || true)"
if ! grep -Eq ':0D96$' <<<"$tcp_listeners" || ! grep -Eq ':0D96$' <<<"$udp_sockets" \
  || ! grep -Eq ':14E5$' <<<"$tcp_listeners"; then
  echo "FAIL: coturn's 3478 or its TLS listener on 5349 is missing from the socket tables"
  failures=$((failures + 1))
elif [ -n "$unexpected_sockets" ]; then
  echo "FAIL: a socket other than 3478, TLS on 5349/tcp (and Docker's DNS on 127.0.0.11) is open"
  failures=$((failures + 1))
else
  echo "PASS: TCP on 3478 and 5349 (TLS), UDP on 3478 only (plus Docker's DNS): no DTLS, CLI, web-admin or other port"
fi

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

# A fresh coturn first: every probe keeps about 4 of the 41 relay ports (min-port..max-port) until
# coturn restarts, so one group of 15 probes ran out of ports ("no available ports").
restart_or_exit
echo "== Group 2b: edges of the documentation and 6to4 anycast blocks are denied =="
# 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and 192.88.99.0/24: one probe per range at each
# edge (documentation blocks, and the deprecated 6to4 anycast block). 203.0.113.7 (the stand-in
# public IP) is not probed here: coturn maps it to the relay's private address, which is allowed
# before any deny range; Group 5's relay-to-relay check asserts that.
for edge_peer in 192.0.2.1 192.0.2.255 198.51.100.1 198.51.100.255 203.0.113.1 203.0.113.255 \
  192.88.99.1 192.88.99.255; do
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
printf '%s\n' "$test_public_ip" ::1 fc00::1 fe80::1 ::ffff:10.0.0.5 ::ffff:127.0.0.1 ::ffff:192.168.1.10 ::ffff:169.254.1.1 >>"$peers_file"
# Extra IPv4 peers for the probe: the "home public IP" (--denied-peer-ip) and the relay's own address.
address_family_output="$(python3 "$here/address_family_probe.py" "$probe_user" "$probe_pass" "$test_public_ip" "$container_ip" "$gateway_ip" "$host_lan_ip" 2>&1)"
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
# The public IP (also --denied-peer-ip) and the relay's own IP: CI showed coturn answers
# CreatePermission with success for both, because it exempts its own addresses from the deny list
# (two clients on the same relay must reach each other's relay addresses). A permission is not
# data, so these two are informational here; Group 5 checks where packets really go.
grep -E "^PROBE permission ($test_public_ip|$container_ip):" <<<"$address_family_output" | sed 's/^/NOTE (informational): /'
# The Docker host's addresses are not coturn's own: the bridge gateway is inside 172.16.0.0/12 and
# must be refused with 403. The host's LAN address is printed (a CI runner could in theory have a
# public one, so it is not asserted; Group 5 checks that nothing arrives either way).
expect_probe "permission $gateway_ip" "error 403"
grep -E "^PROBE permission $host_lan_ip:" <<<"$address_family_output" | sed 's/^/NOTE (informational): /'
# 403 Forbidden (deny list) or 443 Peer Address Family Mismatch (IPv6 peer on an IPv4 relay).
for ipv6_peer in ::1 fc00::1 fe80::1 ::ffff:10.0.0.5 ::ffff:127.0.0.1 ::ffff:192.168.1.10 ::ffff:169.254.1.1; do
  expect_probe "permission $ipv6_peer" "error (403|443)"
done

restart_or_exit
echo "== Group 5: relay-to-relay works, the Docker host is not reachable through the relay (raw STUN) =="
read -r reach_user_a reach_pass_a < <(make_credential 600)
read -r reach_user_b reach_pass_b < <(make_credential 600)
reachability_output="$(python3 "$here/relay_reachability_probe.py" "$reach_user_a" "$reach_pass_a" \
  "$reach_user_b" "$reach_pass_b" "$test_public_ip" "$host_lan_ip" "$gateway_ip" 2>&1)"
reachability_exit_code=$?
echo "$reachability_output"
expect_reachability() {
  if [ "$reachability_exit_code" -eq 0 ] && grep -Eq "^PROBE $1: $2\$" <<<"$reachability_output"; then
    echo "PASS: $1 -> $2"
  else
    echo "FAIL: $1 (wanted $2; probe exit code $reachability_exit_code)"; failures=$((failures + 1))
  fi
}
# Privacy mode on both sides: each allocation reaches the other's relayed address.
expect_reachability "relay A->B" "delivered"
expect_reachability "relay B->A" "delivered"
# The Docker host (the runner's LAN IPv4 and the bridge gateway) is not reachable: listeners on
# non-relay ports there receive nothing when an allocation sends to them directly, or to the public
# IP (which coturn rewrites to its own container address, where only coturn listens). If either
# says RECEIVED, stop, do not weaken anything, and report it with this output. The host addresses
# are in the deny ranges, so their permissions are normally refused (printed). Sending to another
# port on coturn's own container address can only reach coturn itself: accepted by design.
expect_reachability "listener $host_lan_ip:40001" "nothing received \(.*\)"
expect_reachability "listener $gateway_ip:40002" "nothing received \(.*\)"

# user-quota: one credential may hold 6 allocations; the 7th gets 486 (Allocation Quota Reached).
# This limits one credential, NOT one client (every credential has a new username).
restart_or_exit
echo "== Group 6: user-quota (6 allocations per credential) =="
read -r quota_user quota_pass < <(make_credential 600)
quota_output="$(python3 "$here/allocation_quota_probe.py" "$quota_user" "$quota_pass" 7 "$container_ip" 2>&1)"
quota_exit_code=$?
echo "$quota_output"
for allocation_number in 1 2 3 4 5 6; do
  if [ "$quota_exit_code" -eq 0 ] && grep -Fxq "ALLOCATION $allocation_number: success" <<<"$quota_output"; then
    echo "PASS: allocation $allocation_number of 6 allowed"
  else
    echo "FAIL: allocation $allocation_number of 6 (probe exit code $quota_exit_code)"; failures=$((failures + 1))
  fi
done
if [ "$quota_exit_code" -eq 0 ] && grep -Fxq 'ALLOCATION 7: error 486' <<<"$quota_output"; then
  echo "PASS: allocation 7 over user-quota refused with 486"
else
  echo "FAIL: allocation 7 should get error 486 (probe exit code $quota_exit_code)"; failures=$((failures + 1))
fi

# TURN over TLS on 5349 (#58), as a browser uses a turns: URL. The certificate verifies for the TURN
# host name; only TLS 1.2 and 1.3 are accepted, and for 1.2 only ECDHE with AEAD ciphers; a TLS
# allocation works with a valid credential and is refused with a wrong one.
restart_or_exit
echo "== Group 7: TURN over TLS on 5349 =="
tls_handshake() {
  timeout 10 openssl s_client -brief -connect "$container_ip:5349" -servername "$turn_host_name" \
    -CAfile "$test_files_dir/ca.crt" -verify_return_error "$@" </dev/null 2>&1
}
for tls_version in -tls1_3 -tls1_2; do
  tls_output="$(tls_handshake -verify_hostname "$turn_host_name" "$tls_version")"
  if grep -Fq 'CONNECTION ESTABLISHED' <<<"$tls_output" && grep -Eq '^Verification: OK' <<<"$tls_output" \
    && grep -Eq '^Ciphersuite: (TLS_(AES_(128|256)_GCM_SHA(256|384)|CHACHA20_POLY1305_SHA256)|ECDHE-(ECDSA|RSA)-(AES(128|256)-GCM-SHA(256|384)|CHACHA20-POLY1305))$' <<<"$tls_output"; then
    echo "PASS: TLS ($tls_version) on 5349 with a verified certificate for $turn_host_name and an AEAD cipher: $(grep -E '^Ciphersuite:' <<<"$tls_output")"
  else
    echo "FAIL: no verified TLS ($tls_version) with an AEAD cipher on 5349:"; head -n 8 <<<"$tls_output"
    failures=$((failures + 1))
  fi
done
# Each must fail: TLS 1.1 (the client allows it here, so the server must refuse), a TLS 1.2
# cipher without forward secrecy or AEAD, and a certificate check for another host name.
while IFS='|' read -r tls_label tls_arguments; do
  # shellcheck disable=SC2086 # the arguments are fixed words, split on purpose
  tls_output="$(tls_handshake $tls_arguments)"
  if grep -Fq 'CONNECTION ESTABLISHED' <<<"$tls_output"; then
    echo "FAIL: $tls_label was accepted"; failures=$((failures + 1))
  else
    echo "PASS: $tls_label refused"
  fi
done <<EOF
TLS 1.1|-tls1_1 -cipher DEFAULT:@SECLEVEL=0 -verify_hostname $turn_host_name
TLS 1.2 with AES-CBC and SHA-1 (no AEAD)|-tls1_2 -cipher ECDHE-ECDSA-AES128-SHA -verify_hostname $turn_host_name
TLS 1.2 without ECDHE (no forward secrecy)|-tls1_2 -cipher AES128-GCM-SHA256 -verify_hostname $turn_host_name
a certificate check for another host name|-verify_hostname not-the-turn-host.example
EOF
uclient_transport_args=(-t -S -p 5349)
expect "valid credential allocates over TLS" bound "$(run_client 600 "$public_peer")"
expect "wrong credential refused over TLS" no_allocation "$(run_client 600 "$public_peer" "wrong-password")"
uclient_transport_args=()

# Refresh-after-expiry probe (asserted against expected_refresh_after_expiry below, see README.md):
# allocate with a credential that expires 5 s later, wait 25 s (longer than the test-only
# --stale-nonce=20, so the server has rotated the nonce), then send a Refresh for that allocation.
# It runs BEFORE the log checks below, so its traffic is checked too. The probe reaches the server
# on its container address on the bridge. Restart first, so the probe
# starts from fresh state and shares no quota with the other checks.
if ! restart_coturn; then
  echo "FAIL: coturn did not restart"; failures=$((failures + 1))
fi
read -r short_user short_pass < <(make_credential 5)
probe_output="$(python3 -I "$here/refresh_after_expiry.py" "$short_user" "$short_pass" 25 "$container_ip" 2>&1)"
# What coturn does (4.6.3 and 4.18.0 alike), as found by this probe. coturn has no option to change it, so this pins the
# behaviour: if an image bump changes it, the test fails and the README and turnserver.conf comments
# must be updated (and this flipped to refused if coturn then refuses).
expected_refresh_after_expiry="allowed"
if grep -Eq '^REFRESH AFTER EXPIRY: (allowed|refused)$' <<<"$probe_output"; then
  grep -E '^REFRESH AFTER EXPIRY: (allowed|refused)$' <<<"$probe_output"
  if grep -Fxq "REFRESH AFTER EXPIRY: $expected_refresh_after_expiry" <<<"$probe_output"; then
    echo "PASS: refresh after expiry is $expected_refresh_after_expiry, as documented"
  else
    echo "FAIL: refresh after expiry is not $expected_refresh_after_expiry; update README.md and turnserver.conf"
    failures=$((failures + 1))
  fi
  grep -E '^\(' <<<"$probe_output" # notes: nonce rotation seen or not, error code if refused
  # A refused refresh may make coturn print "Cannot find credentials of user" for this username,
  # like the deliberate failed logins; accept that line for it (the Pi discards console output).
  if grep -Fxq 'REFRESH AFTER EXPIRY: refused' <<<"$probe_output"; then
    echo "$short_user" >>"$failed_login_usernames_file"
  fi
else
  echo "FAIL: refresh-after-expiry probe did not produce a result"
  echo "$probe_output" | tail -n 5
  failures=$((failures + 1))
fi

# The server logs must not contain any username or test peer IP. Logging is off in the config, but
# coturn still prints a startup banner (captured above, before any client connected, so it
# holds no user data). Rules:
#   - the banner has no WARNING or ERROR line (for example an option coturn does not understand);
#   - coturn loaded every denied-peer-ip range of turnserver.conf, and nothing else ("Black listing:");
#   - after all the test traffic, every log line is a banner line: any session, user, allocation
#     or peer line coturn printed during the test would be new, and fails.
grep -E '^denied-peer-ip=' "$here/turnserver.conf" | cut -d= -f2- | sort -u >"$denied_ranges_file"
if [ ! -s "$denied_ranges_file" ]; then
  echo "FAIL: no denied-peer-ip ranges found in turnserver.conf"; failures=$((failures + 1))
fi
# Plus the one deny range of the command line (--denied-peer-ip=<public IP>, as compose.yaml does).
{ cat "$denied_ranges_file"; echo "$test_public_ip"; } | sort -u >"$denied_ranges_file.new" \
  && mv "$denied_ranges_file.new" "$denied_ranges_file"
# Any WARNING or ERROR line fails (for example a certificate coturn cannot load, or an option it
# does not understand). The two lines coturn 4.18 prints when the default certificate files are
# missing are still accepted, for an image that prints them although cert/pkey are set.
# A DTLS cipher-suite line means coturn built a DTLS context (with "dtls", DTLS would also be
# accepted on the shared 3478 listener, which the socket check cannot see): that fails too.
banner_problems="$(grep -E '(^|: )(WARNING|ERROR)|^INFO: DTLS cipher suite:' <<<"$startup_banner" \
  | grep -Evx 'WARNING: (Certificate|Private key) file not found or not readable: //turn_server_(cert|pkey)\.pem' || true)"
if [ -n "$banner_problems" ]; then
  echo "FAIL: coturn's startup banner has a WARNING or ERROR line (values masked):"
  head -n 10 <<<"$banner_problems" | mask_values
  failures=$((failures + 1))
fi
listed_ranges="$(sed -n 's/^INFO: Black listing: //p' <<<"$startup_banner" | sort -u)"
# A single address may be printed as "a-a"; compare it as "a".
listed_ranges="$(sed -E 's/^([^-]+)-\1$/\1/' <<<"$listed_ranges" | sort -u)"
if [ "$listed_ranges" != "$(cat "$denied_ranges_file")" ]; then
  echo "FAIL: the deny ranges coturn loaded differ from turnserver.conf (values masked):"
  diff <(cat "$denied_ranges_file") <(printf '%s\n' "$listed_ranges") | head -n 10 | mask_values
  failures=$((failures + 1))
fi
server_logs="$(docker logs "$container_name" 2>&1)"
# Besides the banner, coturn prints these runtime lines with logging off (4.18.0 wording; 4.6.3
# had a "session <id>:" prefix and "check_stun_auth:" before the failed-login text):
#   - an allocation counter (no username, no address);
#   - "credentials of user <name> are wrong (...)" / "... have expired (...)" / "Cannot find
#     credentials of user <name>" for a failed login;
#   - "A peer IP <ip> denied in the range: <range> in server <n> (session <id>)" when the deny list
#     refuses a peer, and "A peer IP <ip> denied: link-local/unique-local/site-local scope ..." for
#     IPv6 scopes coturn 4.18 always refuses;
#   - "stateless-nonce: listener fast-path challenge active" (no data);
#   - "Terminating on signal 15" and "All worker threads joined" when it stops.
# On the Pi, compose.yaml discards coturn's console output (logging driver "none"), so neither
# reaches the disk; this test container keeps Docker's default logs only to inspect them. A
# failed-login line is accepted here only for the test's own deliberate failures, and the
# username of a login that worked must never appear anywhere.
if ! awk '/^  coturn:/{in_coturn=1; next} /^  [a-z]/{in_coturn=0} in_coturn && /^ +driver: none$/{found=1} END{exit !found}' "$here/../compose.yaml"; then
  echo "FAIL: compose.yaml does not discard coturn's console output (logging driver none)"
  failures=$((failures + 1))
fi
new_log_lines=""
unexpected_deny_lines=""
while IFS= read -r log_line; do
  [ -z "${log_line//[[:space:]]/}" ] && continue
  grep -Fxq -e "$log_line" <<<"$startup_banner" && continue
  [[ "$log_line" =~ ^(DEBUG|INFO):\ Global\ turn\ allocation\ count\ (incremented|decremented),\ now\ [0-9]+$ ]] && continue
  [ "$log_line" = "INFO: stateless-nonce: listener fast-path challenge active" ] && continue
  if { [[ "$log_line" =~ ^ERROR:\ session\ [0-9]+:\ check_stun_auth:\ Cannot\ find\ credentials\ of\ user\ \<(.+)\>$ ]] \
      || [[ "$log_line" =~ ^ERROR:\ credentials\ of\ user\ \<(.+)\>\ (are\ wrong\ \(message\ integrity\ does\ not\ match\ any\ auth\ secret\)|have\ expired\ \(the\ time-limited\ username\ timestamp\ is\ in\ the\ past\))$ ]] \
      || [[ "$log_line" =~ ^ERROR:\ Cannot\ find\ credentials\ of\ user\ \<(.+)\>$ ]]; } \
    && grep -Fxq -e "${BASH_REMATCH[1]}" "$failed_login_usernames_file"; then
    continue
  fi
  # coturn refusing, in one of our configured deny ranges, a peer the test deliberately asked
  # for, or the relay's own address (the runner's LAN IPv4 here, the Pi's on the Pi): the test
  # traffic makes coturn try to relay towards it, and the deny list correctly refuses that.
  if [[ "$log_line" =~ ^ERROR:\ A\ peer\ IP\ ([^ ]+)\ denied:\ link-local/unique-local/site-local\ scope\ is\ not\ a\ permitted\ relay\ peer\ in\ server\ [0-9]+\ \(session\ [0-9]+\)$ ]] \
    && grep -Fxq -e "${BASH_REMATCH[1]}" "$peers_file"; then
    continue
  fi
  if [[ "$log_line" =~ ^ERROR:\ session\ [0-9]+:\ A\ peer\ IP\ ([^ ]+)\ denied\ in\ the\ range:\ ([^ ]+)\ in\ server\ [0-9]+\ ?$ ]] \
    || [[ "$log_line" =~ ^ERROR:\ A\ peer\ IP\ ([^ ]+)\ denied\ in\ the\ range[:=]\ ([^ ]+)\ in\ server\ [0-9]+\ \(session\ [0-9]+\)$ ]]; then
    denied_peer="${BASH_REMATCH[1]}"
    denied_range="$(sed -E 's/^([^-]+)-\1$/\1/' <<<"${BASH_REMATCH[2]}")"
    if { grep -Fxq -e "$denied_peer" "$peers_file" || [ "$denied_peer" = "$container_ip" ]; } \
      && grep -Fxq -e "$denied_range" "$denied_ranges_file"; then
      continue
    fi
    # Deny lines only ever name the test's own synthetic peers and deny ranges, never a real
    # user's address, so print them unmasked: the exact range is what tells us what to fix.
    unexpected_deny_lines+="$log_line"$'\n'
  fi
  # coturn stopping when the test restarts it between groups.
  [ "$log_line" = "INFO: Terminating on signal 15" ] && continue
  [ "$log_line" = "INFO: All worker threads joined" ] && continue
  new_log_lines+="$log_line"$'\n'
done < <(strip_log_prefix <<<"$server_logs")
valid_usernames="$(grep -v -x -F -f "$failed_login_usernames_file" "$usernames_file" || true)"
if [ -n "$new_log_lines" ]; then
  echo "FAIL: coturn logged lines beyond its startup banner during the test (values masked):"
  printf '%s' "$new_log_lines" | head -n 10 | mask_values
  if [ -n "$unexpected_deny_lines" ]; then
    echo "  Deny lines outside the test's peers or deny ranges (unmasked: synthetic test peers only):"
    printf '%s' "$unexpected_deny_lines" | head -n 10 | sed 's/^/    /'
  fi
  failures=$((failures + 1))
elif [ -n "$valid_usernames" ] && grep -Fwq -f <(printf '%s\n' "$valid_usernames") <<<"$server_logs"; then
  echo "FAIL: coturn logs contain the username of a login that worked (values masked)"
  failures=$((failures + 1))
else
  echo "PASS: docker logs hold only coturn's startup banner ($(wc -l <"$denied_ranges_file" | tr -d ' ') deny ranges, all from the config), allocation counters and the deliberate failed logins; no other username, no session or peer line, no WARNING; compose discards coturn's console output"
fi

# Logging must stay off, and features coturn 4.18 keeps off by default must stay off, by
# configuration, not by luck: none of these options in the config (comments ignored) or on the
# container's command line. DTLS, the CLI, web-admin, prometheus, RFC 5780, loopback or
# whitelisted peers, mobility, server relay and multiplexed peers are all opt-in in 4.18
# (mainrelay.c defaults), so the absence of these words is what keeps them off. TLS is on (#58),
# with exactly the settings below.
opt_in_options='verbose|Verbose|syslog|log-binding|dtls|cli|web-admin|prometheus|rfc5780|allow-loopback-peers|allowed-peer-ip|mobility|server-relay|multiplex-peer'
tls_settings="$(grep -E '^[[:space:]]*(tls-listening-port|alt-tls-listening-port|cert|pkey|pkey-pwd|no-tlsv1|no-tlsv1_1|no-tlsv1_2|no-tls|cipher-list|dh-file|ec-curve-name|ca-file)([=[:space:]]|$)' "$here/turnserver.conf" | sort)"
expected_tls_settings="$(printf '%s\n' 'tls-listening-port=5349' 'cert=/etc/coturn/tls/fullchain.pem' \
  'pkey=/etc/coturn/tls/privkey.pem' 'no-tlsv1' 'no-tlsv1_1' \
  'cipher-list="ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"' | sort)"
if [ "$tls_settings" = "$expected_tls_settings" ]; then
  echo "PASS: turnserver.conf has exactly the expected TLS settings (5349, the mounted certificate, TLS 1.2+, AEAD ciphers)"
else
  echo "FAIL: turnserver.conf's TLS settings differ from the expected ones:"
  diff <(printf '%s\n' "$expected_tls_settings") <(printf '%s\n' "$tls_settings") | head -n 10
  failures=$((failures + 1))
fi
if grep -Ev '^[[:space:]]*#' "$here/turnserver.conf" \
  | grep -Eq "^[[:space:]]*($opt_in_options)([[:space:]]|=|\$)"; then
  echo "FAIL: turnserver.conf enables an option that must stay off"; failures=$((failures + 1))
elif grep -Ev '^[[:space:]]*#' "$here/../compose.yaml" \
  | grep -Eq -- "--($opt_in_options)(['\"=[:space:]]|\$)|'-v'|'-V'"; then
  echo "FAIL: compose.yaml passes an option that must stay off"; failures=$((failures + 1))
else
  echo "PASS: no verbose or syslog logging, and no opt-in TLS/DTLS, CLI, web-admin or peer option"
fi

# No log file may hold a username or peer IP, and none may exist outside the tmpfs mounts.
inspect_log_files "end of run"

# The admin CLI must be off: the socket check above covers 5766 on every address (the CLI binds
# 127.0.0.1 by default, which a probe from outside the container could never see).

if [ "$failures" -eq 0 ]; then
  echo "All coturn checks passed."
else
  echo "$failures coturn check(s) failed."
  exit 1
fi
