#!/usr/bin/env bash
# Host firewall for this compose stack on the Pi (secure-call-backend#63; README.md "Firewall").
#
# The Pi runs other Docker projects too, so every rule is scoped to this stack's two bridges,
# which compose.yaml names: br-securecall (backend and PostgreSQL) and br-turn (coturn). The rules
# live in chains of their own: SECURE-CALL-FWD, jumped to from Docker's DOCKER-USER (which Docker
# runs before its own FORWARD rules), and SECURE-CALL-IN, jumped to from INPUT (traffic to the Pi
# itself never passes FORWARD). Every rule names one of the two bridges, except the first of each
# chain, which lets packets of connections already allowed go on to the rules after it (RETURN,
# not ACCEPT, so nobody else's traffic is decided here). Outside the two chains only their single
# jump rule each is added; no built-in or Docker chain is ever flushed. Each run rebuilds both
# chains in one atomic iptables-restore (--noflush: only the chains named in it change).
#
#   sudo ./firewall.sh [--env-file FILE] [--proxy-ip IP]... [--turn-public-ip IP]
#                           apply, or apply again (the same result however often it runs)
#   ./firewall.sh --print [the same options]
#                           print the rules it would apply; needs no root, changes nothing
#   sudo ./firewall.sh --check    show the rules, their counters and jumps; exit 0 only if active
#   sudo ./firewall.sh --remove   delete the two chains and their jumps, nothing else
#
# The reverse proxy's IPv4 address(es): --proxy-ip (repeat it, or separate with commas), else
# TRUSTED_PROXY_IPS from FILE. The home's public IPv4: --turn-public-ip, else TURN_PUBLIC_IP from
# FILE. FILE defaults to the .env next to this script. It is read line by line, never run.
set -euo pipefail

forward_chain=SECURE-CALL-FWD
input_chain=SECURE-CALL-IN

# Keep these equal to compose.yaml (tests/test_firewall.py checks them).
backend_bridge=br-securecall
turn_bridge=br-turn
backend_container_port=8000
postgres_container_port=5432
coturn_ip=172.30.200.2
coturn_udp_ports=3478,49160:49200
coturn_tcp_ports=3478,5349

# Where coturn may not send to: every IPv4 range of turnserver.conf's denied-peer-ip lines, plus
# multicast (no-multicast-peers there); the home's public IP is added as compose.yaml adds it to
# coturn (--denied-peer-ip). That covers the home LAN (RFC 1918), the Pi's other Docker networks
# (172.16.0.0/12, 192.168.0.0/16), CGNAT and loopback. tests/test_firewall.py keeps this equal to
# turnserver.conf.
turn_denied_ranges=(
  0.0.0.0/8
  10.0.0.0/8
  100.64.0.0/10
  127.0.0.0/8
  169.254.0.0/16
  172.16.0.0/12
  192.0.0.0/24
  192.0.2.0/24
  192.88.99.0/24
  192.168.0.0/16
  198.18.0.0/15
  198.51.100.0/24
  203.0.113.0/24
  224.0.0.0/4
  240.0.0.0/4
)

# New TCP connections to coturn's 3478 (TURN over TCP) and 5349 (TURN over TLS), per source
# address. coturn has no per-address connection limit, and on 5349 every connection costs a full
# TLS handshake (no session cache). A browser opens one connection per TCP URL (we send two: TCP
# and TLS) per network interface it uses, so 2 per caller, 4 during an ICE restart (the old ones
# stay for a moment), 8 on two interfaces. The limits leave room for several callers behind one
# address (a household, or a carrier-grade NAT) and still stop one address from flooding coturn.
# UDP is not limited here (coturn's quotas cover it). README.md "Firewall" lists these values.
turn_tcp_max_connections_per_source=24 # open at once (connlimit)
turn_tcp_new_connections_burst=30      # opened in a row before the rate applies (hashlimit)
turn_tcp_new_connections_per_minute=60 # sustained, once the burst is used up (hashlimit)
# hashlimit's table name (at most 15 characters), and how long a quiet address is remembered:
# longer than a full burst takes to refill (30 / 60 per minute = 30 s), so pausing does not reset it.
turn_tcp_hashlimit_name=securecall-turn
turn_tcp_hashlimit_expire_milliseconds=60000

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
env_file="$script_directory/.env"

die() {
  echo "firewall.sh: $*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Usage: firewall.sh [--env-file FILE] [--proxy-ip IP]... [--turn-public-ip IP]   apply
       firewall.sh --print [--env-file FILE] [--proxy-ip IP]... [--turn-public-ip IP]
       firewall.sh --check
       firewall.sh --remove
USAGE
}

usage_error() {
  echo "firewall.sh: $*" >&2
  usage >&2
  exit 2
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

# Four decimal numbers 0-255 without leading zeros (iptables would read 010 as octal 8), not the
# unspecified or the broadcast address. No names, ranges or IPv6: the backend and coturn are
# published on IPv4 only.
is_ipv4() {
  local value="$1" octet
  local pattern='^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$'
  [[ $value =~ $pattern ]] || return 1
  for octet in "${BASH_REMATCH[@]:1}"; do
    [[ $octet =~ ^(0|[1-9][0-9]*)$ ]] || return 1
    [ "$octet" -le 255 ] || return 1
  done
  [ "$value" != 0.0.0.0 ] && [ "$value" != 255.255.255.255 ]
}

require_ipv4() { # $1 = value, $2 = where it came from
  is_ipv4 "$1" || die "$2: '$1' is not an IPv4 address (four numbers 0-255, no leading zeros, no range, name or IPv6). Nothing was changed."
}

# The value of the last "KEY=value" line of the env file, as docker compose reads it: quotes
# around it, or a " #" comment after an unquoted value, are not part of it. Fails without a line.
read_env_value() { # $1 = key
  local line value
  line="$(grep -E "^[[:space:]]*$1=" "$env_file" | tail -n 1)" || true
  [ -n "$line" ] || return 1
  value="$(trim "${line#*=}")"
  case "$value" in
    \"*)
      value="${value#\"}"
      value="${value%%\"*}"
      ;;
    \'*)
      value="${value#\'}"
      value="${value%%\'*}"
      ;;
    *) value="${value%%[[:space:]]#*}" ;;
  esac
  trim "$value"
}

require_env_file() {
  [ -r "$env_file" ] || die "cannot read $env_file. Pass --env-file FILE (the stack's .env), or --proxy-ip and --turn-public-ip. Nothing was changed."
}

proxy_ips=()
turn_public_ip=""

# Fills proxy_ips and turn_public_ip from the options, else from the env file, and checks them.
resolve_values() {
  local list source part known duplicate
  if [ "${#proxy_ip_arguments[@]}" -gt 0 ]; then
    list="$(
      IFS=,
      echo "${proxy_ip_arguments[*]}"
    )"
    source="--proxy-ip"
  else
    require_env_file
    list="$(read_env_value TRUSTED_PROXY_IPS)" \
      || die "no TRUSTED_PROXY_IPS line in $env_file: set it to the reverse proxy's LAN IP (the backend needs it too), or pass --proxy-ip. Nothing was changed."
    source="TRUSTED_PROXY_IPS in $env_file"
  fi
  # `read` below takes one line only, so a second line would be dropped unchecked.
  case "$list" in
    *$'\n'*) require_ipv4 "$list" "$source" ;;
  esac
  local parts=()
  IFS=, read -r -a parts <<<"$list"
  for part in ${parts[@]+"${parts[@]}"}; do
    part="$(trim "$part")"
    [ -n "$part" ] || continue
    require_ipv4 "$part" "$source"
    duplicate=0
    for known in ${proxy_ips[@]+"${proxy_ips[@]}"}; do
      if [ "$known" = "$part" ]; then duplicate=1; fi
    done
    if [ "$duplicate" = 0 ]; then proxy_ips+=("$part"); fi
  done
  [ "${#proxy_ips[@]}" -gt 0 ] \
    || die "$source is empty: set the reverse proxy's LAN IP (the only address allowed to reach the backend's published port). Nothing was changed."

  if [ -n "$turn_public_ip_argument" ]; then
    turn_public_ip="$turn_public_ip_argument"
    source="--turn-public-ip"
  else
    require_env_file
    turn_public_ip="$(read_env_value TURN_PUBLIC_IP)" \
      || die "no TURN_PUBLIC_IP line in $env_file (compose.yaml needs it too), or pass --turn-public-ip. Nothing was changed."
    source="TURN_PUBLIC_IP in $env_file"
  fi
  require_ipv4 "$turn_public_ip" "$source"
}

ipv4_forward_rules() {
  local rule="-A $forward_chain" proxy_ip range
  local coturn_tcp="-d $coturn_ip/32 -o $turn_bridge -p tcp -m multiport --dports $coturn_tcp_ports"
  # Packets of connections already allowed (replies, and related ICMP errors) go on unchanged.
  echo "$rule -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN"
  # The backend and PostgreSQL talk to each other (seen here only when br_netfilter is loaded) and
  # start no connection to anything else: they need nothing outside their bridge.
  echo "$rule -i $backend_bridge -o $backend_bridge -j RETURN"
  echo "$rule -i $backend_bridge -j DROP"
  # Into their bridge only through a published port (DNAT): the backend's only from the reverse
  # proxy; PostgreSQL's from wherever POSTGRES_PUBLISH_ADDR publishes it (127.0.0.1 by default,
  # which only the Pi itself reaches, and not through this chain).
  for proxy_ip in "${proxy_ips[@]}"; do
    echo "$rule -s $proxy_ip/32 -o $backend_bridge -p tcp -m tcp --dport $backend_container_port -m conntrack --ctstate DNAT -j RETURN"
  done
  echo "$rule -o $backend_bridge -p tcp -m tcp --dport $postgres_container_port -m conntrack --ctstate DNAT -j RETURN"
  echo "$rule -o $backend_bridge -j DROP"
  # coturn's TCP ports: per source address, at most this many connections open at once, and new
  # ones at this rate. Before the RETURN below, or they would never apply.
  echo "$rule $coturn_tcp -m conntrack --ctstate NEW -m connlimit --connlimit-above $turn_tcp_max_connections_per_source --connlimit-mask 32 --connlimit-saddr -j DROP"
  echo "$rule $coturn_tcp -m conntrack --ctstate NEW -m hashlimit --hashlimit-above $turn_tcp_new_connections_per_minute/minute --hashlimit-burst $turn_tcp_new_connections_burst --hashlimit-mode srcip --hashlimit-name $turn_tcp_hashlimit_name --hashlimit-htable-expire $turn_tcp_hashlimit_expire_milliseconds -j DROP"
  # Into coturn's bridge only through coturn's published ports.
  echo "$rule -d $coturn_ip/32 -o $turn_bridge -p udp -m multiport --dports $coturn_udp_ports -m conntrack --ctstate DNAT -j RETURN"
  echo "$rule $coturn_tcp -m conntrack --ctstate DNAT -j RETURN"
  echo "$rule -o $turn_bridge -j DROP"
  # Out of coturn's bridge only to public addresses (relaying to them is coturn's job): never the
  # LAN, the Pi's other networks or the home's own public address.
  for range in "${turn_denied_ranges[@]}"; do
    echo "$rule -d $range -i $turn_bridge -j DROP"
  done
  echo "$rule -d $turn_public_ip/32 -i $turn_bridge -j DROP"
}

# Neither bridge may open a connection to the Pi itself: its gateway address on the bridge, its
# LAN address or any other. Replies to connections the Pi opened go on unchanged.
ipv4_input_rules() {
  echo "-A $input_chain -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN"
  echo "-A $input_chain -i $backend_bridge -j DROP"
  echo "-A $input_chain -i $turn_bridge -j DROP"
}

# Both networks are IPv4 only (compose.yaml), so IPv6 from them to the Pi (link-local, if the
# kernel gives the interfaces such addresses) has no use at all. Nothing is forwarded over IPv6:
# link-local addresses are not routed, and the networks have no other IPv6 address.
ipv6_input_rules() {
  echo "-A $input_chain -i $backend_bridge -j DROP"
  echo "-A $input_chain -i $turn_bridge -j DROP"
}

# How many times $1's chain $2 holds the plain jump to $3.
count_jumps() {
  "$1" -w -S "$2" 2>/dev/null | grep -cxF -- "-A $2 -j $3" || true
}

repeat_line() { # $1 = count, $2 = line
  local count=0
  while [ "$count" -lt "$1" ]; do
    echo "$2"
    count=$((count + 1))
  done
}

ipv4_restore_input() { # $1, $2 = jumps already in DOCKER-USER and in INPUT
  echo '*filter'
  echo ":$forward_chain - [0:0]"
  echo ":$input_chain - [0:0]"
  echo "-F $forward_chain"
  echo "-F $input_chain"
  ipv4_forward_rules
  ipv4_input_rules
  repeat_line "$1" "-D DOCKER-USER -j $forward_chain"
  echo "-I DOCKER-USER 1 -j $forward_chain"
  repeat_line "$2" "-D INPUT -j $input_chain"
  echo "-I INPUT 1 -j $input_chain"
  echo COMMIT
}

ipv6_restore_input() { # $1 = jumps already in INPUT
  echo '*filter'
  echo ":$input_chain - [0:0]"
  echo "-F $input_chain"
  ipv6_input_rules
  repeat_line "$1" "-D INPUT -j $input_chain"
  echo "-I INPUT 1 -j $input_chain"
  echo COMMIT
}

ipv6_available() {
  command -v ip6tables >/dev/null 2>&1 \
    && command -v ip6tables-restore >/dev/null 2>&1 \
    && ip6tables -w -S INPUT >/dev/null 2>&1
}

require_iptables() {
  local error_output
  if ! error_output="$(iptables -w -S INPUT 2>&1 >/dev/null)"; then
    die "iptables does not work here (${error_output:-no output}). Run it as root (sudo). Nothing was changed."
  fi
}

# The two bridges that do not exist (yet). The rules match them by name, so they apply as soon as
# Docker creates them; until then they protect nothing.
missing_bridges() {
  local bridge
  command -v ip >/dev/null 2>&1 || return 0
  for bridge in "$backend_bridge" "$turn_bridge"; do
    ip -o link show dev "$bridge" >/dev/null 2>&1 || echo "$bridge"
  done
}

apply() {
  local error_output missing forward_jumps input_jumps ipv6_summary
  resolve_values
  require_iptables
  if ! error_output="$(iptables -w -S DOCKER-USER 2>&1 >/dev/null)"; then
    die "Docker's DOCKER-USER chain is missing (${error_output:-no output}). Start Docker first: it creates the chain (with Docker's nftables firewall backend there is none, and this script needs the iptables backend). Nothing was changed."
  fi
  missing="$(missing_bridges)"
  if [ -n "$missing" ]; then
    echo "firewall.sh: WARNING: no interface named $(echo "$missing" | tr '\n' ' ')yet. The rules apply once Docker creates it; if the stack is running, recreate its networks (README.md, Firewall, step 1)." >&2
  fi
  forward_jumps="$(count_jumps iptables DOCKER-USER "$forward_chain")"
  input_jumps="$(count_jumps iptables INPUT "$input_chain")"
  ipv4_restore_input "$forward_jumps" "$input_jumps" | iptables-restore -w --noflush
  if ipv6_available; then
    input_jumps="$(count_jumps ip6tables INPUT "$input_chain")"
    ipv6_restore_input "$input_jumps" | ip6tables-restore -w --noflush
    ipv6_summary="IPv6: $input_chain from INPUT."
  else
    ipv6_summary="IPv6: ip6tables does not work on this host, so no IPv6 rules (the bridges are IPv4 only)."
  fi
  echo "Secure Call firewall applied. IPv4: $forward_chain from DOCKER-USER, $input_chain from INPUT. $ipv6_summary"
  local allowed="${proxy_ips[0]}" proxy_ip
  for proxy_ip in "${proxy_ips[@]:1}"; do allowed="$allowed, $proxy_ip"; done
  echo "Only $allowed may connect to the backend's published port."
  echo "Check: firewall.sh --check. Undo: firewall.sh --remove."
}

print_rules() {
  resolve_values
  echo "# IPv4, chain $forward_chain (jumped to first from DOCKER-USER):"
  ipv4_forward_rules
  echo "# IPv4, chain $input_chain (jumped to first from INPUT):"
  ipv4_input_rules
  echo "# IPv6, chain $input_chain (jumped to first from INPUT; only where ip6tables works):"
  ipv6_input_rules
}

show_chain() { # $1 = iptables or ip6tables, $2 = our chain, $3 = the chain that jumps to it
  local jumps position
  if ! "$1" -w -S "$2" >/dev/null 2>&1; then
    echo "$1: chain $2 does not exist."
    return 1
  fi
  jumps="$(count_jumps "$1" "$3" "$2")"
  position="$("$1" -w -S "$3" | grep -E "^-A $3( |\$)" | grep -nxF -- "-A $3 -j $2" | head -n 1 | cut -d: -f1)" || true
  echo "== $1: $2, jumped to from $3: $jumps jump(s), the first at position ${position:-none} =="
  "$1" -w -L "$2" -v -n -x --line-numbers
  if [ "$jumps" != 1 ]; then
    echo "$1: expected exactly one jump from $3 to $2, found $jumps."
    return 1
  fi
  if [ "$position" != 1 ]; then
    echo "WARNING: other rules in $3 run before $2 and could decide traffic of these bridges first. Run firewall.sh again to put it back on top."
  fi
}

check() {
  local active=1 missing
  require_iptables
  show_chain iptables "$forward_chain" DOCKER-USER || active=0
  show_chain iptables "$input_chain" INPUT || active=0
  if ipv6_available; then
    show_chain ip6tables "$input_chain" INPUT || active=0
  else
    echo "IPv6: ip6tables does not work on this host; no IPv6 rules are expected."
  fi
  missing="$(missing_bridges)"
  if [ -n "$missing" ]; then
    echo "No interface named $(echo "$missing" | tr '\n' ' ')exists: the rules match nothing on it until compose.yaml's networks are (re)created."
    active=0
  fi
  if [ "$active" = 1 ]; then
    echo "Secure Call firewall: active."
    return 0
  fi
  echo "Secure Call firewall: NOT (fully) active."
  return 1
}

remove_chain() { # $1 = iptables or ip6tables, $2 = our chain, $3 = the chain that jumps to it
  local removed=0
  while "$1" -w -C "$3" -j "$2" >/dev/null 2>&1; do
    "$1" -w -D "$3" -j "$2"
    removed=$((removed + 1))
  done
  if "$1" -w -S "$2" >/dev/null 2>&1; then
    "$1" -w -F "$2"
    "$1" -w -X "$2"
    echo "$1: removed $2 and $removed jump(s) to it from $3."
  else
    echo "$1: there was no $2."
  fi
}

remove() {
  require_iptables
  remove_chain iptables "$forward_chain" DOCKER-USER
  remove_chain iptables "$input_chain" INPUT
  if ipv6_available; then
    remove_chain ip6tables "$input_chain" INPUT
  fi
  echo "Secure Call firewall removed; nothing else was changed."
}

mode=apply
value_option_given=0
proxy_ip_arguments=()
turn_public_ip_argument=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --check | --remove | --print)
      [ "$mode" = apply ] || usage_error "use only one of --check, --remove and --print"
      mode="${1#--}"
      ;;
    --env-file | --proxy-ip | --turn-public-ip)
      [ "$#" -ge 2 ] || usage_error "$1 needs a value"
      case "$1" in
        --env-file) env_file="$2" ;;
        --proxy-ip) proxy_ip_arguments+=("$2") ;;
        --turn-public-ip) turn_public_ip_argument="$2" ;;
      esac
      value_option_given=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) usage_error "unknown argument: $1" ;;
  esac
  shift
done
if [ "$value_option_given" = 1 ] && { [ "$mode" = check ] || [ "$mode" = remove ]; }; then
  usage_error "--$mode takes no other option"
fi

case "$mode" in
  apply) apply ;;
  print) print_rules ;;
  check) check ;;
  remove) remove ;;
esac
