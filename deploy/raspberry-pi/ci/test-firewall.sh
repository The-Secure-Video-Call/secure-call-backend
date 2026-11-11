#!/usr/bin/env bash
# CI only (.github/workflows/ci.yml, check job): applies firewall.sh on the runner for real and
# proves what it lets through, with this stack as compose.yaml runs it (PostgreSQL and the backend
# are already up). Needs Docker, passwordless sudo, ip, curl and the repository's .venv.
#
# A network namespace "lan" stands in for the rest of the home network and the internet: the
# runner is 10.250.0.1 there (the Pi's LAN address: the backend and coturn's stand-in are
# published on it), 10.250.0.2 is the reverse proxy (TRUSTED_PROXY_IPS), 10.250.0.3 another LAN
# device or an internet peer, .4 and .5 clients for the TCP limits. Listeners: 10.250.0.2:40900
# in "lan" (a private address that is not the Pi), and port 40901 on the runner (the Pi itself,
# through a bridge's gateway or its LAN address). coturn's stand-in is coturn's own service from
# compose.yaml (network, fixed address, user, no capabilities) running Python from the backend
# image, tagged with coturn's image name, so it can listen on coturn's ports and probe from there.
#
# Every check runs first without the firewall, where everything it will block must get through
# (so the setup can tell the difference), and then with it. Run from deploy/raspberry-pi.
set -euo pipefail
cd "$(dirname "$0")/.."

repository_root="$(cd ../.. && pwd)"
host_python="$repository_root/.venv/bin/python"
backend_image=ghcr.io/the-secure-video-call/secure-call-backend:main
pi_lan_ip=10.250.0.1
proxy_ip=10.250.0.2
lan_device_ip=10.250.0.3
connlimit_client_ip=10.250.0.4
hashlimit_client_ip=10.250.0.5
lan_target="$proxy_ip:40900"
pi_port=40901
turn_gateway=172.30.200.1
coturn_ip=172.30.200.2
failures=0

fail() {
  echo "FAIL: $*"
  failures=$((failures + 1))
}

cleanup() {
  set +e
  if [ -n "${pi_listener_pid:-}" ]; then kill "$pi_listener_pid" 2>/dev/null; fi
  sudo ip netns pids lan 2>/dev/null | xargs -r sudo kill 2>/dev/null
  docker rm -f turn-probe >/dev/null 2>&1
  sudo systemctl disable --now secure-call-firewall >/dev/null 2>&1
  sudo ./firewall.sh --remove >/dev/null 2>&1
  sudo rm -f /usr/local/sbin/secure-call-firewall /etc/systemd/system/secure-call-firewall.service
  sudo systemctl daemon-reload
  sudo ip netns del lan 2>/dev/null
  sudo ip link del lan-host 2>/dev/null
}
trap cleanup EXIT

in_backend() { docker compose exec -T backend python - "$@" <ci/firewall_probe.py; }
in_turn_network() { docker exec turn-probe python /probe/firewall_probe.py "$@"; }
in_other_project() { docker run --rm -i --network bridge "$backend_image" python - "$@" <ci/firewall_probe.py; }
on_lan() { sudo ip netns exec lan "$host_python" ci/firewall_probe.py "$@"; }
on_pi() { "$host_python" ci/firewall_probe.py "$@"; }

# curl's exit code for the backend's health check through its published port: 0 = it answered,
# 28 = no connection in time (dropped). $1 = the source address in "lan", or "" for the Pi itself.
backend_https_exit_code() {
  local exit_code=0 runner=() source_option=()
  if [ -n "$1" ]; then
    runner=(sudo ip netns exec lan)
    source_option=(--interface "$1")
  fi
  ${runner[@]+"${runner[@]}"} curl -fsS -o /dev/null --connect-timeout 3 --max-time 6 --tlsv1.3 \
    --cacert tls/local-ca.crt --resolve "secure-call-backend:8001:$pi_lan_ip" \
    -H 'Host: signal.example.invalid' -H 'X-Forwarded-Proto: https' \
    ${source_option[@]+"${source_option[@]}"} https://secure-call-backend:8001/healthz 2>/dev/null \
    || exit_code=$?
  echo "$exit_code"
}

expect_https() { # $1 = description, $2 = open|blocked, $3 = curl's exit code
  if { [ "$2" = open ] && [ "$3" = 0 ]; } || { [ "$2" = blocked ] && [ "$3" = 28 ]; }; then
    echo "OK: $1: $2"
  else
    fail "$1: curl exit code $3, expected $2"
  fi
}

expect_backend_https_from_lan() { # $1 = source address in "lan", $2 = open|blocked
  expect_https "HTTPS to the backend's published port from $1" "$2" "$(backend_https_exit_code "$1")"
}

wait_for_backend() {
  for _ in $(seq 1 60); do
    [ "$(backend_https_exit_code "$proxy_ip")" = 0 ] && return 0
    sleep 1
  done
  docker compose logs backend | tail -n 20
  return 1
}

expect_one_jump() { # $1 = iptables or ip6tables, $2 = the chain that jumps, $3 = our chain
  local rules jumps first_rule
  rules="$(sudo "$1" -S "$2")"
  jumps="$(grep -cxF -- "-A $2 -j $3" <<<"$rules" || true)"
  first_rule="$(grep -m 1 '^-A ' <<<"$rules" || true)"
  if [ "$jumps" = 1 ] && [ "$first_rule" = "-A $2 -j $3" ]; then
    echo "OK: $1 $2 holds exactly one jump to $3, as its first rule"
  else
    fail "$1 $2 holds $jumps jump(s) to $3; its first rule is: $first_rule"
  fi
}

expect_one_jump_each() {
  expect_one_jump iptables DOCKER-USER SECURE-CALL-FWD
  expect_one_jump iptables INPUT SECURE-CALL-IN
  if sudo ip6tables -S INPUT >/dev/null 2>&1; then expect_one_jump ip6tables INPUT SECURE-CALL-IN; fi
}

# $1 = how what the firewall blocks shows: "open" (without it) or "blocked" (with it).
run_checks() {
  local stopped="$1"
  echo "-- From the backend's container (br-securecall): PostgreSQL only"
  in_backend check tcp:postgres:5432=open "tcp:1.1.1.1:443=$stopped" "tcp:$lan_target=$stopped" \
    "tcp:$backend_gateway:$pi_port=$stopped" "tcp:$pi_lan_ip:$pi_port=$stopped" \
    || fail "connections from the backend's container"
  echo "-- From coturn's network (br-turn): public addresses only"
  in_turn_network check tcp:1.1.1.1:443=open udp:1.1.1.1:53=open "tcp:$lan_target=$stopped" \
    "udp:$lan_target=$stopped" "tcp:$turn_gateway:$pi_port=$stopped" "tcp:$pi_lan_ip:$pi_port=$stopped" \
    || fail "connections from coturn's network"
  echo "-- Into the backend's published port: from the proxy only"
  expect_backend_https_from_lan "$proxy_ip" open
  expect_backend_https_from_lan "$lan_device_ip" "$stopped"
  echo "-- Into coturn's published ports from outside: coturn's ports only (3478, 5349, 49160-49200)"
  on_lan check --source "$lan_device_ip" "tcp:$pi_lan_ip:3478=open" "udp:$pi_lan_ip:3478=open" \
    "tcp:$pi_lan_ip:5349=open" "udp:$pi_lan_ip:49160=open" "udp:$pi_lan_ip:49200=open" \
    "udp:$pi_lan_ip:49201=$stopped" "tcp:$pi_lan_ip:40902=$stopped" \
    || fail "connections into coturn's published ports"
  echo "-- The Pi itself into its containers (their replies come back through INPUT)"
  on_pi check "tcp:$coturn_ip:3478=open" || fail "the Pi to coturn's container"
  expect_https "HTTPS to the backend from the Pi itself" open "$(backend_https_exit_code "")"
  echo "-- Another project's container (Docker's default bridge): never affected"
  in_other_project check tcp:1.1.1.1:443=open "tcp:$lan_target=open" "tcp:$pi_lan_ip:$pi_port=open" \
    || fail "connections from another project's container"
}

# $1 = without|with. One address keeps connections open, another opens them in a row: with the
# firewall, the first 24 stay open and the 25th is dropped, and after a burst of 30 new ones the
# rest are held to about one per second (firewall.sh's turn_tcp_* values).
check_tcp_limits() {
  local held burst made seconds
  held="$(on_lan held --source "$connlimit_client_ip" "$pi_lan_ip:3478" 25)"
  burst="$(on_lan burst --source "$hashlimit_client_ip" "$pi_lan_ip:5349" 45)"
  echo "Held open at once from $connlimit_client_ip to 3478: $held"
  echo "In a row from $hashlimit_client_ip to 5349: $burst"
  read -r _ made _ _ _ seconds _ <<<"$burst"
  seconds="${seconds%.*}"
  if [ "$1" = without ]; then
    [ "$held" = "made 25 of 25" ] || fail "without the firewall, 25 connections held open: $held"
    [ "$made" = 45 ] || fail "without the firewall, 45 connections in a row: $burst"
  else
    [ "$held" = "made 24 of 25" ] || fail "with the firewall, expected 24 of 25 held open: $held"
    if [ "$made" -lt 30 ] || [ "$made" -ge 45 ] || [ "$made" -gt $((30 + seconds + 2)) ]; then
      fail "with the firewall, expected the burst of 30 and then about one per second: $burst"
    fi
    on_lan check --source "$connlimit_client_ip" "tcp:$pi_lan_ip:3478=open" \
      || fail "a connection after the held ones closed"
  fi
}

echo "== A stand-in home network (namespace \"lan\") =="
sudo ip netns add lan
sudo ip link add lan-host type veth peer name lan-peer
sudo ip link set lan-peer netns lan
sudo ip addr add "$pi_lan_ip/24" dev lan-host
sudo ip link set lan-host up
for address in "$proxy_ip" "$lan_device_ip" "$connlimit_client_ip" "$hashlimit_client_ip"; do
  sudo ip netns exec lan ip addr add "$address/24" dev lan-peer
done
sudo ip netns exec lan ip link set lan-peer up
sudo ip netns exec lan ip link set lo up
on_lan listen "tcp:$lan_target" "udp:$lan_target" >/dev/null &
on_pi listen "tcp:0.0.0.0:$pi_port" >/dev/null &
pi_listener_pid=$!

echo "== The stack, as on the Pi: the backend published on the LAN address, the proxy trusted =="
echo "TRUSTED_PROXY_IPS=$proxy_ip" >>.env
chmod 600 .env
BACKEND_PUBLISH_ADDR="$pi_lan_ip" docker compose up -d --no-deps --pull never backend
wait_for_backend || { echo "FAIL: the backend did not answer on $pi_lan_ip:8001"; exit 1; }
backend_gateway="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' "$(docker compose ps -q backend)")"
docker tag "$backend_image" secure-call-coturn:local
mkdir -p coturn/tls
docker compose run -d --no-deps --pull never --name turn-probe \
  -v "$PWD/ci/firewall_probe.py:/probe/firewall_probe.py:ro" \
  -p "$pi_lan_ip:3478:3478/udp" -p "$pi_lan_ip:3478:3478/tcp" -p "$pi_lan_ip:5349:5349/tcp" \
  -p "$pi_lan_ip:49160:49160/udp" -p "$pi_lan_ip:49200:49200/udp" \
  -p "$pi_lan_ip:49201:49201/udp" -p "$pi_lan_ip:40902:40902/tcp" \
  --entrypoint python coturn /probe/firewall_probe.py listen \
  tcp:0.0.0.0:3478 udp:0.0.0.0:3478 tcp:0.0.0.0:5349 udp:0.0.0.0:49160 udp:0.0.0.0:49200 \
  udp:0.0.0.0:49201 tcp:0.0.0.0:40902 >/dev/null
turn_probe_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' turn-probe)"
if [ "$turn_probe_ip" != "$coturn_ip" ]; then
  echo "FAIL: coturn's stand-in got $turn_probe_ip, not coturn's fixed address $coturn_ip"
  exit 1
fi
for attempt in $(seq 1 10); do
  in_turn_network check tcp:127.0.0.1:3478=open >/dev/null && on_pi check "tcp:127.0.0.1:$pi_port=open" >/dev/null \
    && on_lan check "tcp:$lan_target=open" >/dev/null && break
  [ "$attempt" = 10 ] && { echo "FAIL: the listeners did not start"; exit 1; }
  sleep 1
done
ip -o -4 addr show dev br-securecall | grep -qF "inet $backend_gateway/28 " \
  || fail "no bridge br-securecall with $backend_gateway/28 (compose.yaml's internal network)"
ip -o -4 addr show dev br-turn | grep -qF "inet $turn_gateway/29 " \
  || fail "no bridge br-turn with $turn_gateway/29 (compose.yaml's turn network)"
echo "Bridges: br-securecall (gateway $backend_gateway), br-turn (gateway $turn_gateway); coturn's stand-in at $turn_probe_ip"

echo "== Without the firewall: everything it will block still gets through =="
run_checks open
check_tcp_limits without

echo "== firewall.sh, applied twice (values from .env) =="
sudo ./firewall.sh
sudo ./firewall.sh
expect_one_jump_each
applied_rules="$(sudo iptables -S SECURE-CALL-FWD | grep -c '^-A' || true)"
printed_rules="$(./firewall.sh --print | grep -c '^-A SECURE-CALL-FWD' || true)"
[ "$applied_rules" = "$printed_rules" ] || fail "SECURE-CALL-FWD holds $applied_rules rules, --print shows $printed_rules"
sudo iptables -S SECURE-CALL-FWD
sudo iptables -S SECURE-CALL-IN

echo "== With the firewall =="
run_checks blocked
check_tcp_limits with
echo "-- The backend still reaches PostgreSQL as its own role over TLS 1.3"
docker compose exec -T backend python -c "import django; django.setup(); from django.db import connection; c = connection.cursor(); c.execute('SELECT current_user, ssl, version FROM pg_stat_ssl WHERE pid = pg_backend_pid()'); row = c.fetchone(); assert row == ('securecall_app', True, 'TLSv1.3'), row; print('OK: the backend reaches PostgreSQL as', row[0], 'over', row[2])" \
  || fail "the backend no longer reaches PostgreSQL"
sudo ./firewall.sh --check || fail "--check says the firewall is not active"

echo "== The systemd unit, installed as README.md says, re-applies after Docker restarts =="
sudo install -o root -g root -m 0755 firewall.sh /usr/local/sbin/secure-call-firewall
sed "s|/home/pi/secure-call-backend/deploy/raspberry-pi|$PWD|" secure-call-firewall.service \
  | sudo tee /etc/systemd/system/secure-call-firewall.service >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable --now secure-call-firewall
if ! systemctl is-active --quiet secure-call-firewall; then
  systemctl status --no-pager secure-call-firewall || true
  fail "the unit did not start"
fi
started_before="$(systemctl show -p ExecMainStartTimestampMonotonic --value secure-call-firewall)"
sudo systemctl restart docker
restarted=0
for _ in $(seq 1 60); do
  started_after="$(systemctl show -p ExecMainStartTimestampMonotonic --value secure-call-firewall)"
  if systemctl is-active --quiet secure-call-firewall && [ "$started_after" -gt "$started_before" ]; then
    restarted=1
    break
  fi
  sleep 1
done
if [ "$restarted" = 1 ]; then
  echo "OK: the unit ran again after Docker restarted"
else
  systemctl status --no-pager secure-call-firewall || true
  fail "the unit did not run again after Docker restarted"
fi
expect_one_jump_each
sudo secure-call-firewall --check >/dev/null || fail "--check after the Docker restart"
wait_for_backend || fail "the backend did not come back after the Docker restart"
expect_backend_https_from_lan "$lan_device_ip" blocked
in_backend check "tcp:1.1.1.1:443=blocked" || fail "the backend after the Docker restart"

echo "== --remove takes out the chains and their jumps, and nothing else =="
sudo systemctl disable --now secure-call-firewall
sudo secure-call-firewall --remove
if sudo iptables -S | grep -F SECURE-CALL; then fail "iptables still holds the rules above"; fi
if sudo ip6tables -S 2>/dev/null | grep -F SECURE-CALL; then fail "ip6tables still holds the rules above"; fi
if sudo ./firewall.sh --check >/dev/null; then fail "--check says active after --remove"; fi
expect_backend_https_from_lan "$lan_device_ip" open
in_backend check "tcp:1.1.1.1:443=open" || fail "the backend after --remove"

if [ "$failures" -gt 0 ]; then
  echo "$failures check(s) failed."
  exit 1
fi
echo "All firewall checks passed."
