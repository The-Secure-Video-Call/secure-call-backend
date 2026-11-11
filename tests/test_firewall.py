"""deploy/raspberry-pi/firewall.sh (#63) and its systemd unit. The script runs for real on a copy,
against stand-ins for iptables, ip6tables, their -restore commands and `ip link show` that keep
the filter table in JSON files and log every call. CI also applies it on the runner for real
(deploy/raspberry-pi/ci/test-firewall.sh)."""

import ipaddress
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy/raspberry-pi"
FORWARD_CHAIN = "SECURE-CALL-FWD"
INPUT_CHAIN = "SECURE-CALL-IN"
PROXY_IP = "192.168.1.201"
PUBLIC_IP = "203.0.113.7"

# The stand-ins, run as `python -IS fake.py <tool name> <arguments>`. Like the real tools, a
# restore without --noflush empties the whole table, a ":CHAIN" line creates or flushes a chain,
# and a failing line leaves the table as it was.
FAKE_FIREWALL_TOOLS = r"""
import json
import os
import shlex
import sys
from pathlib import Path

BUILT_IN = ("INPUT", "FORWARD", "OUTPUT")
VERDICTS = ("ACCEPT", "DROP", "RETURN", "REJECT")


class Failure(Exception):
    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


def table_path(family):
    return Path(os.environ["FAKE_DIR"]) / f"filter{family}.json"


def log(line):
    with open(os.environ["FAKE_LOG"], "a") as log_file:
        log_file.write(line + "\n")


def target_of(rule):
    words = rule.split()
    return words[words.index("-j") + 1] if "-j" in words else None


def need_chain(chains, name):
    if name not in chains:
        raise Failure("No chain/target/match by that name.")


def run_command(chains, words):
    option, rest = words[0], words[1:]
    if option == "-S":
        output = []
        for name in rest[:1] or list(chains):
            need_chain(chains, name)
            output.append(f"-P {name} ACCEPT" if name in BUILT_IN else f"-N {name}")
            output += [f"-A {name} {rule}" for rule in chains[name]]
        return output
    if option == "-L":
        need_chain(chains, rest[0])
        rules = chains[rest[0]]
        return [f"Chain {rest[0]}"] + [f"{n} 0 0 {rule}" for n, rule in enumerate(rules, 1)]
    name = rest[0] if rest else None
    if option == "-N":
        if name in chains:
            raise Failure("Chain already exists.")
        chains[name] = []
    elif option == "-F":
        for flushed in [name] if name else list(chains):
            need_chain(chains, flushed)
            chains[flushed] = []
    elif option == "-X":
        need_chain(chains, name)
        if name in BUILT_IN or chains[name]:
            raise Failure("Directory not empty, or a built-in chain.")
        if any(target_of(rule) == name for rules in chains.values() for rule in rules):
            raise Failure("Too many links.")
        del chains[name]
    elif option in ("-A", "-I", "-C", "-D"):
        need_chain(chains, name)
        rule_words = rest[1:]
        position = 1
        if option == "-I" and rule_words and rule_words[0].isdigit():
            position = int(rule_words.pop(0))
        rule = " ".join(rule_words)
        target = target_of(rule)
        if target and target not in VERDICTS and target not in chains:
            raise Failure(f"Couldn't load target `{target}'", 2)
        if option == "-A":
            chains[name].append(rule)
        elif option == "-I":
            chains[name].insert(position - 1, rule)
        elif rule not in chains[name]:
            raise Failure("Bad rule (does a matching rule exist in that chain?).")
        elif option == "-D":
            chains[name].remove(rule)
    else:
        raise Failure(f"unknown option {option}", 2)
    return []


def restore(chains, words):
    if "--noflush" not in words and "-n" not in words:
        chains = {name: [] for name in BUILT_IN}
    for number, line in enumerate(sys.stdin.read().splitlines(), 1):
        log("  " + line)
        line = line.strip()
        try:
            if not line or line.startswith("#") or line in ("*filter", "COMMIT"):
                continue
            if line.startswith("*"):
                raise Failure("only the filter table is faked")
            if line.startswith(":"):
                name, policy = line[1:].split()[:2]
                if name in BUILT_IN:
                    log(f"POLICY {name} {policy}")
                else:
                    chains[name] = []
                continue
            run_command(chains, shlex.split(line))
        except Failure as failure:
            raise Failure(f"line {number} failed: {failure}") from None
    return chains


def main():
    tool, words = sys.argv[1], sys.argv[2:]
    log(" ".join([tool, *words]))
    try:
        if tool == "ip":
            if words[-1] in os.environ.get("FAKE_BRIDGES", "").split(","):
                print(f"7: {words[-1]}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500")
                return 0
            raise Failure(f'Device "{words[-1]}" does not exist.')
        family = "6" if tool.startswith("ip6") else "4"
        if family == "6" and os.environ.get("FAKE_IPV6_BROKEN"):
            raise Failure("can't initialize ip6tables table `filter'", 3)
        if os.environ.get("FAKE_NOT_ROOT"):
            raise Failure("Permission denied (you must be root)", 4)
        words = [word for word in words if word != "-w"]
        chains = json.loads(table_path(family).read_text())
        if tool.endswith("-restore"):
            chains = restore(chains, words)
        else:
            output = run_command(chains, words)
            if output:
                print("\n".join(output))
        table_path(family).write_text(json.dumps(chains))
        return 0
    except Failure as failure:
        print(f"{tool}: {failure}", file=sys.stderr)
        return failure.code


sys.exit(main())
"""

TOOLS = ("iptables", "ip6tables", "iptables-restore", "ip6tables-restore", "ip")

# What another Docker project and the Pi itself already have: it must survive untouched.
OTHER_IPV4_RULES: dict[str, list[str]] = {
    "INPUT": ["-i lo -j ACCEPT", "-p tcp -m tcp --dport 22 -j ACCEPT"],
    "FORWARD": ["-j DOCKER-USER", "-j DOCKER-FORWARD"],
    "OUTPUT": [],
    "DOCKER-USER": ["-i br-otherproject -j ACCEPT"],
    "DOCKER-FORWARD": ["-o br-otherproject -j ACCEPT", "-i br-otherproject -j ACCEPT"],
}
OTHER_IPV6_RULES: dict[str, list[str]] = {
    "INPUT": ["-i lo -j ACCEPT"],
    "FORWARD": ["-j DOCKER-USER"],
    "OUTPUT": [],
    "DOCKER-USER": [],
}

COTURN_TCP = "-d 172.30.200.2/32 -o br-turn -p tcp -m multiport --dports 3478,5349"
EXPECTED_FORWARD_RULES = [
    "-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
    "-i br-securecall -o br-securecall -j RETURN",
    "-i br-securecall -j DROP",
    f"-s {PROXY_IP}/32 -o br-securecall -p tcp -m tcp --dport 8000 -m conntrack --ctstate DNAT"
    " -j RETURN",
    "-o br-securecall -p tcp -m tcp --dport 5432 -m conntrack --ctstate DNAT -j RETURN",
    "-o br-securecall -j DROP",
    f"{COTURN_TCP} -m conntrack --ctstate NEW -m connlimit --connlimit-above 24"
    " --connlimit-mask 32 --connlimit-saddr -j DROP",
    f"{COTURN_TCP} -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 60/minute"
    " --hashlimit-burst 30 --hashlimit-mode srcip --hashlimit-name securecall-turn"
    " --hashlimit-htable-expire 60000 -j DROP",
    "-d 172.30.200.2/32 -o br-turn -p udp -m multiport --dports 3478,49160:49200"
    " -m conntrack --ctstate DNAT -j RETURN",
    f"{COTURN_TCP} -m conntrack --ctstate DNAT -j RETURN",
    "-o br-turn -j DROP",
    *(
        f"-d {denied} -i br-turn -j DROP"
        for denied in (
            "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
            "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
            "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
            "224.0.0.0/4", "240.0.0.0/4", f"{PUBLIC_IP}/32",
        )
    ),
]  # fmt: skip
EXPECTED_INPUT_RULES = [
    "-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
    "-i br-securecall -j DROP",
    "-i br-turn -j DROP",
]
EXPECTED_IPV6_INPUT_RULES = ["-i br-securecall -j DROP", "-i br-turn -j DROP"]


class FakeHost:
    """A copy of firewall.sh with its .env, and the stand-in tools on PATH."""

    def __init__(
        self,
        tmp_path: Path,
        ipv4: dict[str, list[str]] = OTHER_IPV4_RULES,
        *,
        env_text: str | None = f"TRUSTED_PROXY_IPS={PROXY_IP}\nTURN_PUBLIC_IP={PUBLIC_IP}\n",
    ) -> None:
        self.directory = tmp_path
        self.deploy = tmp_path / "deploy"
        self.deploy.mkdir()
        shutil.copy2(DEPLOY / "firewall.sh", self.deploy / "firewall.sh")
        if env_text is not None:
            (self.deploy / ".env").write_text(env_text)
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        fake = tmp_path / "fake_firewall_tools.py"
        fake.write_text(FAKE_FIREWALL_TOOLS)
        for tool in TOOLS:
            wrapper = bin_dir / tool
            wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" -IS "{fake}" {tool} "$@"\n')
            wrapper.chmod(0o755)
        self.log = tmp_path / "calls.log"
        self.log.touch()
        self.write_table("4", ipv4)
        self.write_table("6", OTHER_IPV6_RULES)
        self.env = {
            "PATH": f"{bin_dir}:/usr/bin:/bin",
            "FAKE_DIR": str(tmp_path),
            "FAKE_LOG": str(self.log),
            "FAKE_BRIDGES": "br-securecall,br-turn",
            "LC_ALL": "C",
        }

    def write_table(self, family: str, chains: dict[str, list[str]]) -> None:
        (self.directory / f"filter{family}.json").write_text(json.dumps(chains))

    def table(self, family: str) -> dict[str, list[str]]:
        chains: dict[str, list[str]] = json.loads(
            (self.directory / f"filter{family}.json").read_text()
        )
        return chains

    def run(self, *arguments: str, **extra_env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - the script under test, fixed arguments
            ["/bin/bash", str(self.deploy / "firewall.sh"), *arguments],
            env={**self.env, **extra_env}, capture_output=True, text=True, check=False,
        )  # fmt: skip

    def calls(self) -> list[str]:
        return [line for line in self.log.read_text().splitlines() if not line.startswith(" ")]


def printed_rules(output: str) -> dict[str, list[str]]:
    """--print's rules by section ("4 SECURE-CALL-FWD", "4 SECURE-CALL-IN", "6 SECURE-CALL-IN")."""
    sections: dict[str, list[str]] = {}
    section = ""
    for line in output.splitlines():
        if header := re.match(r"# IPv(\d), chain (\S+) ", line):
            section = f"{header[1]} {header[2]}"
            sections[section] = []
        elif line.startswith("-A "):
            chain, rule = line[3:].split(" ", 1)
            assert section.endswith(chain)
            sections[section].append(rule)
    return sections


def applied(tables: dict[str, list[str]], chain: str) -> list[str]:
    return tables.get(chain, [])


# --- The rules ---------------------------------------------------------------------------------


def test_print_shows_exactly_these_rules_and_touches_nothing(tmp_path: Path) -> None:
    host = FakeHost(tmp_path)
    result = host.run("--print")

    assert result.returncode == 0, result.stderr
    assert printed_rules(result.stdout) == {
        f"4 {FORWARD_CHAIN}": EXPECTED_FORWARD_RULES,
        f"4 {INPUT_CHAIN}": EXPECTED_INPUT_RULES,
        f"6 {INPUT_CHAIN}": EXPECTED_IPV6_INPUT_RULES,
    }
    assert host.calls() == []


def test_applies_its_own_chains_and_leaves_everything_else_alone(tmp_path: Path) -> None:
    host = FakeHost(tmp_path)
    result = host.run()

    assert result.returncode == 0, result.stderr
    ipv4, ipv6 = host.table("4"), host.table("6")
    assert applied(ipv4, FORWARD_CHAIN) == EXPECTED_FORWARD_RULES
    assert applied(ipv4, INPUT_CHAIN) == EXPECTED_INPUT_RULES
    assert applied(ipv6, INPUT_CHAIN) == EXPECTED_IPV6_INPUT_RULES
    assert ipv4["DOCKER-USER"] == [f"-j {FORWARD_CHAIN}", *OTHER_IPV4_RULES["DOCKER-USER"]]
    assert ipv4["INPUT"] == [f"-j {INPUT_CHAIN}", *OTHER_IPV4_RULES["INPUT"]]
    assert ipv6["INPUT"] == [f"-j {INPUT_CHAIN}", *OTHER_IPV6_RULES["INPUT"]]
    for chain in ("FORWARD", "OUTPUT", "DOCKER-FORWARD"):
        assert ipv4[chain] == OTHER_IPV4_RULES[chain]
    for chain in ("FORWARD", "OUTPUT", "DOCKER-USER"):
        assert ipv6[chain] == OTHER_IPV6_RULES[chain]
    assert f"Only {PROXY_IP} may connect" in result.stdout


def test_running_twice_leaves_exactly_one_jump_and_the_same_rules(tmp_path: Path) -> None:
    host = FakeHost(tmp_path)
    host.run()
    once = (host.table("4"), host.table("6"))
    second = host.run()

    assert second.returncode == 0, second.stderr
    assert (host.table("4"), host.table("6")) == once
    assert host.table("4")["DOCKER-USER"].count(f"-j {FORWARD_CHAIN}") == 1
    assert host.table("4")["INPUT"].count(f"-j {INPUT_CHAIN}") == 1
    assert host.table("6")["INPUT"].count(f"-j {INPUT_CHAIN}") == 1


def test_stale_rules_and_extra_or_moved_jumps_are_replaced(tmp_path: Path) -> None:
    stale = {
        **OTHER_IPV4_RULES,
        "DOCKER-USER": ["-i br-x -j ACCEPT", f"-j {FORWARD_CHAIN}", f"-j {FORWARD_CHAIN}"],
        FORWARD_CHAIN: ["-j ACCEPT"],
        INPUT_CHAIN: [],
    }
    host = FakeHost(tmp_path, stale)
    result = host.run()

    assert result.returncode == 0, result.stderr
    assert host.table("4")["DOCKER-USER"] == [f"-j {FORWARD_CHAIN}", "-i br-x -j ACCEPT"]
    assert host.table("4")[FORWARD_CHAIN] == EXPECTED_FORWARD_RULES


def test_coturn_tcp_limits_come_before_its_accept_and_spare_a_callers_connections() -> None:
    rules = EXPECTED_FORWARD_RULES
    tcp_return = rules.index(f"{COTURN_TCP} -m conntrack --ctstate DNAT -j RETURN")
    limits = [index for index, rule in enumerate(rules) if "limit-" in rule]
    script = (DEPLOY / "firewall.sh").read_text()

    def constant(name: str) -> int:
        match = re.search(rf"^{name}=(\d+)", script, re.M)
        assert match is not None, name
        return int(match[1])

    assert len(limits) == 2
    assert all(rules.index("-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN") < index
               for index in limits)  # fmt: skip
    assert max(limits) < tcp_return
    assert all(COTURN_TCP in rules[index] and "-j DROP" in rules[index] for index in limits)
    assert not any("limit-" in rule for rule in rules if "-p udp" in rule or "8000" in rule)
    # One caller: 2 TCP URLs (TCP and TLS) x 2 network interfaces x 2 during an ICE restart.
    connections_per_caller = 2 * 2 * 2
    assert constant("turn_tcp_max_connections_per_source") >= 2 * connections_per_caller
    assert constant("turn_tcp_new_connections_burst") >= 2 * connections_per_caller
    expire_seconds = constant("turn_tcp_hashlimit_expire_milliseconds") / 1000
    refill_seconds = constant("turn_tcp_new_connections_burst") / (
        constant("turn_tcp_new_connections_per_minute") / 60
    )
    assert expire_seconds > refill_seconds
    hashlimit_name = re.search(r"^turn_tcp_hashlimit_name=(\S+)$", script, re.M)
    assert hashlimit_name is not None
    assert len(hashlimit_name[1]) <= 15  # the kernel's limit for a hashlimit table name


def test_negative_limits_after_the_accept_would_be_caught() -> None:
    def limits_apply(rules: list[str]) -> bool:
        tcp_return = next(i for i, rule in enumerate(rules) if rule.endswith("DNAT -j RETURN")
                          and COTURN_TCP in rule)  # fmt: skip
        return all(i < tcp_return for i, rule in enumerate(rules) if "limit-" in rule) and any(
            "limit-" in rule for rule in rules
        )

    limits = [rule for rule in EXPECTED_FORWARD_RULES if "limit-" in rule]
    moved = [rule for rule in EXPECTED_FORWARD_RULES if "limit-" not in rule] + limits
    without = [rule for rule in EXPECTED_FORWARD_RULES if "limit-" not in rule]

    assert limits_apply(EXPECTED_FORWARD_RULES)
    assert not limits_apply(moved)
    assert not limits_apply(without)


# --- Removing, checking --------------------------------------------------------------------------


def test_remove_deletes_only_its_own_chains_and_jumps(tmp_path: Path) -> None:
    host = FakeHost(tmp_path)
    host.run()
    result = host.run("--remove")

    assert result.returncode == 0, result.stderr
    assert host.table("4") == OTHER_IPV4_RULES
    assert host.table("6") == OTHER_IPV6_RULES
    again = host.run("--remove")
    assert again.returncode == 0, again.stderr
    assert f"there was no {FORWARD_CHAIN}" in again.stdout
    assert host.table("4") == OTHER_IPV4_RULES


def test_negative_never_flushes_or_deletes_anyone_elses_chain(tmp_path: Path) -> None:
    host = FakeHost(tmp_path)
    host.run()
    host.run()
    host.run("--check")
    host.run("--remove")
    calls = host.calls()
    log_text = host.log.read_text()

    flush_or_delete = [call for call in calls if re.search(r" -[FXPZ]( |$)", call)]
    assert flush_or_delete
    assert all(call.endswith((f" {FORWARD_CHAIN}", f" {INPUT_CHAIN}")) for call in flush_or_delete)
    restores = [call for call in calls if call.split()[0].endswith("-restore")]
    assert len(restores) == 4
    assert all("--noflush" in call.split() for call in restores)
    assert "POLICY" not in log_text  # no built-in chain was declared (that would set its policy)
    own_chains = (FORWARD_CHAIN, INPUT_CHAIN)
    jump_lines = (
        ["-I", "DOCKER-USER", "1", "-j", FORWARD_CHAIN], ["-D", "DOCKER-USER", "-j", FORWARD_CHAIN],
        ["-I", "INPUT", "1", "-j", INPUT_CHAIN], ["-D", "INPUT", "-j", INPUT_CHAIN],
    )  # fmt: skip
    for line in (line.strip() for line in log_text.splitlines() if line.startswith("  ")):
        words = line.split()
        if line in ("*filter", "COMMIT"):
            continue
        if line.startswith(":"):
            assert words[0][1:] in own_chains, line
        elif words[0] in ("-A", "-F"):
            assert words[1] in own_chains, line
        else:
            assert words in jump_lines, line


def test_check_passes_only_when_everything_is_in_place(tmp_path: Path) -> None:
    host = FakeHost(tmp_path)
    before = host.run("--check")
    host.run()
    active = host.run("--check")
    missing_bridge = host.run("--check", FAKE_BRIDGES="br-turn")
    tables = host.table("4")
    tables["DOCKER-USER"].append(f"-j {FORWARD_CHAIN}")
    host.write_table("4", tables)
    two_jumps = host.run("--check")

    assert before.returncode == 1
    assert "does not exist" in before.stdout
    assert active.returncode == 0, active.stdout + active.stderr
    assert "Secure Call firewall: active." in active.stdout
    assert f"{FORWARD_CHAIN}, jumped to from DOCKER-USER: 1 jump(s)" in active.stdout
    assert missing_bridge.returncode == 1
    assert "br-securecall" in missing_bridge.stdout
    assert two_jumps.returncode == 1
    assert "found 2" in two_jumps.stdout


# --- Where the values come from ------------------------------------------------------------------


@pytest.mark.parametrize(
    "env_text",
    [
        None,
        f"TURN_PUBLIC_IP={PUBLIC_IP}\n",
        f"TRUSTED_PROXY_IPS=\nTURN_PUBLIC_IP={PUBLIC_IP}\n",
        f"TRUSTED_PROXY_IPS= , ,\nTURN_PUBLIC_IP={PUBLIC_IP}\n",
        f"TRUSTED_PROXY_IPS={PROXY_IP}\n",
    ],
    ids=["no-env-file", "no-proxy-line", "empty-proxy", "only-commas", "no-public-ip"],
)
def test_negative_refuses_to_run_without_the_proxy_or_public_ip(
    tmp_path: Path, env_text: str | None
) -> None:
    host = FakeHost(tmp_path, env_text=env_text)
    result = host.run()
    printed = host.run("--print")

    assert result.returncode == 1
    assert re.search(r"TRUSTED_PROXY_IPS|TURN_PUBLIC_IP|--env-file", result.stderr)
    assert "Nothing was changed." in result.stderr
    assert printed.returncode == 1
    assert host.table("4") == OTHER_IPV4_RULES
    assert host.table("6") == OTHER_IPV6_RULES
    assert not any(call.split()[0].endswith("-restore") for call in host.calls())


NOT_IPV4 = [
    "192.168.1.300",
    "192.168.1.0/24",
    "192.168.1",
    "proxy.lan",
    "010.0.0.1",
    "0.0.0.0",  # noqa: S104 - a value the script must refuse, nothing binds to it
    "255.255.255.255",
    "fd00::1",
    "192.168.1.2 -j ACCEPT",
    "192.168.1.2;reboot",
    "$(touch pwned)",
]


@pytest.mark.parametrize("value", NOT_IPV4)
@pytest.mark.parametrize("where", ["--proxy-ip", "TRUSTED_PROXY_IPS", "TURN_PUBLIC_IP"])
def test_negative_refuses_a_value_that_is_not_an_ipv4_address(
    tmp_path: Path, value: str, where: str
) -> None:
    proxy_value = value if where == "TRUSTED_PROXY_IPS" else PROXY_IP
    public_value = value if where == "TURN_PUBLIC_IP" else PUBLIC_IP
    host = FakeHost(
        tmp_path,
        env_text=f"TRUSTED_PROXY_IPS={proxy_value}\nTURN_PUBLIC_IP={public_value}\n",
    )
    result = host.run(*(["--proxy-ip", value] if where == "--proxy-ip" else []))

    assert result.returncode == 1, result.stdout
    assert "is not an IPv4 address" in result.stderr
    assert host.table("4") == OTHER_IPV4_RULES
    assert host.calls() == []
    assert not (host.deploy / "pwned").exists()
    assert not (tmp_path / "pwned").exists()


@pytest.mark.parametrize("option", ["--proxy-ip", "--turn-public-ip"])
def test_negative_a_second_line_in_a_command_line_value_is_refused(
    tmp_path: Path, option: str
) -> None:
    host = FakeHost(tmp_path)
    result = host.run(option, "192.168.1.2\n-A INPUT -j ACCEPT")

    assert result.returncode == 1
    assert "is not an IPv4 address" in result.stderr
    assert host.calls() == []


def test_values_are_read_from_the_env_file_without_running_it(tmp_path: Path) -> None:
    env_text = (
        "TRUSTED_PROXY_IPS=192.168.1.9\n"
        f"DJANGO_SECRET_KEY=$(touch {tmp_path}/pwned)\n"
        f"`touch {tmp_path}/pwned`\n"
        'TRUSTED_PROXY_IPS="192.168.1.201, 192.168.1.202,192.168.1.201" # the proxy\n'
        "TURN_PUBLIC_IP='203.0.113.7'\n"
        "# TURN_PUBLIC_IP=198.51.100.1\n"
    )
    host = FakeHost(tmp_path, env_text=env_text)
    result = host.run()

    assert result.returncode == 0, result.stderr
    rules = host.table("4")[FORWARD_CHAIN]
    proxy_rules = [rule for rule in rules if rule.startswith("-s ")]
    assert [rule.split()[1] for rule in proxy_rules] == ["192.168.1.201/32", "192.168.1.202/32"]
    assert f"-d {PUBLIC_IP}/32 -i br-turn -j DROP" in rules
    assert not (tmp_path / "pwned").exists()


def test_command_line_values_need_no_env_file(tmp_path: Path) -> None:
    host = FakeHost(tmp_path, env_text=None)
    result = host.run(
        "--proxy-ip", "10.0.0.5", "--proxy-ip", "10.0.0.6, 10.0.0.7",
        "--turn-public-ip", "198.51.100.9",
    )  # fmt: skip

    assert result.returncode == 0, result.stderr
    rules = host.table("4")[FORWARD_CHAIN]
    assert [rule.split()[1] for rule in rules if rule.startswith("-s ")] == [
        "10.0.0.5/32",
        "10.0.0.6/32",
        "10.0.0.7/32",
    ]
    assert "-d 198.51.100.9/32 -i br-turn -j DROP" in rules


@pytest.mark.parametrize(
    "arguments",
    [
        ["--flush"],
        ["--check", "--remove"],
        ["--remove", "--proxy-ip", PROXY_IP],
        ["--check", "--env-file", ".env"],
        ["--proxy-ip"],
        ["192.168.1.201"],
    ],
)
def test_negative_bad_arguments_change_nothing(tmp_path: Path, arguments: list[str]) -> None:
    host = FakeHost(tmp_path)
    result = host.run(*arguments)

    assert result.returncode == 2
    assert "Usage:" in result.stderr
    assert host.calls() == []


def test_negative_refuses_when_dockers_chain_is_missing(tmp_path: Path) -> None:
    without_docker = {"INPUT": ["-i lo -j ACCEPT"], "FORWARD": [], "OUTPUT": []}
    host = FakeHost(tmp_path, without_docker)
    result = host.run()

    assert result.returncode == 1
    assert "DOCKER-USER chain is missing" in result.stderr
    assert host.table("4") == without_docker


def test_negative_without_root_it_says_so_and_changes_nothing(tmp_path: Path) -> None:
    host = FakeHost(tmp_path)
    results = [host.run(*mode, FAKE_NOT_ROOT="1") for mode in ([], ["--check"], ["--remove"])]

    for result in results:
        assert result.returncode == 1
        assert "Run it as root" in result.stderr
    assert host.table("4") == OTHER_IPV4_RULES


def test_without_working_ip6tables_only_ipv4_is_applied(tmp_path: Path) -> None:
    host = FakeHost(tmp_path)
    result = host.run(FAKE_IPV6_BROKEN="1")
    check = host.run("--check", FAKE_IPV6_BROKEN="1")
    removed = host.run("--remove", FAKE_IPV6_BROKEN="1")

    assert result.returncode == 0, result.stderr
    assert "ip6tables does not work on this host" in result.stdout
    assert check.returncode == 0, check.stdout
    assert removed.returncode == 0, removed.stderr
    assert host.table("4") == OTHER_IPV4_RULES
    assert host.table("6") == OTHER_IPV6_RULES


def test_a_missing_bridge_is_a_warning_not_a_failure(tmp_path: Path) -> None:
    host = FakeHost(tmp_path)
    result = host.run(FAKE_BRIDGES="")

    assert result.returncode == 0, result.stderr
    assert "WARNING: no interface named br-securecall br-turn yet" in result.stderr
    assert host.table("4")[FORWARD_CHAIN] == EXPECTED_FORWARD_RULES


# --- The same values as compose.yaml, turnserver.conf and test-coturn.sh ------------------------


def network_block(compose_text: str, network: str) -> str:
    networks = compose_text.split("\nnetworks:\n", 1)[1].split("\nvolumes:\n", 1)[0]
    match = re.search(rf"^  {network}:\n((?:    .*\n|\s*#.*\n)+)", networks + "\n", re.M)
    assert match is not None, network
    return match[1]


def service_block(compose_text: str, service: str) -> str:
    match = re.search(rf"^  {service}:\n(.*?)(?=^  \S|^\S)", compose_text, re.M | re.S)
    assert match is not None, service
    return match[1]


def published_container_ports(service: str, protocol: str) -> set[int]:
    """The container ports of a service's `ports:` lines ('host:port:container[-last][/udp]')."""
    ports: set[int] = set()
    mappings = re.findall(r"^\s+- '[^']*?:(\d+)(?:-(\d+))?(?:/(udp|tcp))?'$", service, re.M)
    for first, last, line_protocol in mappings:
        if (line_protocol or "tcp") == protocol:
            ports.update(range(int(first), int(last or first) + 1))
    return ports


def multiport_ports(text: str) -> set[int]:
    ports: set[int] = set()
    for part in text.split(","):
        first, _, last = part.partition(":")
        ports.update(range(int(first), int(last or first) + 1))
    return ports


def test_rules_match_compose_yaml(tmp_path: Path) -> None:
    compose = (DEPLOY / "compose.yaml").read_text()
    internal, turn = network_block(compose, "internal"), network_block(compose, "turn")
    coturn, backend = service_block(compose, "coturn"), service_block(compose, "backend")
    postgres = service_block(compose, "postgres")
    rules = FakeHost(tmp_path).run("--print").stdout

    assert "com.docker.network.bridge.name: br-securecall" in internal
    assert "com.docker.network.bridge.name: br-turn" in turn
    for block in (internal, turn):
        assert "enable_ipv6: false" in block
    assert "subnet: 172.30.200.16/28" in internal
    assert "subnet: 172.30.200.0/29" in turn
    assert not ipaddress.ip_network("172.30.200.16/28").overlaps(
        ipaddress.ip_network("172.30.200.0/29")
    )
    assert "ipv4_address: 172.30.200.2" in coturn
    assert published_container_ports(backend, "tcp") == {8000}
    assert published_container_ports(postgres, "tcp") == {5432}
    udp = re.search(r"-p udp -m multiport --dports (\S+) .*-j RETURN", rules)
    tcp = re.search(r"-p tcp -m multiport --dports (\S+) -m conntrack --ctstate DNAT", rules)
    assert udp is not None
    assert tcp is not None
    assert multiport_ports(udp[1]) == published_container_ports(coturn, "udp")
    assert multiport_ports(tcp[1]) == published_container_ports(coturn, "tcp")


def test_negative_a_changed_port_list_is_caught() -> None:
    coturn = (
        "    ports:\n      - '${TURN_RELAY_IP}:3478:3478/udp'\n      - '1.2.3.4:5349:5349/tcp'\n"
    )

    assert published_container_ports(coturn, "udp") == {3478}
    assert multiport_ports("3478,49160:49200") != published_container_ports(coturn, "udp")


def test_coturn_may_not_send_where_turnserver_conf_denies(tmp_path: Path) -> None:
    config = (DEPLOY / "coturn/turnserver.conf").read_text()
    denied_in_config: list[ipaddress.IPv4Network] = []
    for first, last in re.findall(r"^denied-peer-ip=([\d.]+)-([\d.]+)$", config, re.M):
        denied_in_config += ipaddress.summarize_address_range(
            ipaddress.IPv4Address(first), ipaddress.IPv4Address(last)
        )
    rules = FakeHost(tmp_path).run("--print").stdout
    denied_by_firewall = [
        ipaddress.IPv4Network(network)
        for network in re.findall(r"-d (\S+) -i br-turn -j DROP", rules)
    ]
    # Beyond the config: multicast (no-multicast-peers there), 0.0.0.0 itself, the public IP.
    extras = [ipaddress.IPv4Network(n) for n in ("224.0.0.0/4", "0.0.0.0/32", f"{PUBLIC_IP}/32")]

    assert "no-multicast-peers" in config
    assert len(denied_in_config) > 10
    assert set(ipaddress.collapse_addresses(denied_by_firewall)) == set(
        ipaddress.collapse_addresses(denied_in_config + extras)
    )


def test_the_coturn_test_network_is_the_compose_one() -> None:
    compose = (DEPLOY / "compose.yaml").read_text()
    test_script = (DEPLOY / "coturn/test-coturn.sh").read_text()
    turn = network_block(compose, "turn")

    def variable(name: str) -> str:
        match = re.search(rf'^{name}="(.*)"$', test_script, re.M)
        assert match is not None, name
        return match[1]

    assert f"subnet: {variable('network_subnet')}" in turn
    assert f"gateway: {variable('gateway_ip')}" in turn
    assert "--opt com.docker.network.bridge.name=br-turn" in test_script


# --- Persistence -------------------------------------------------------------------------------

UNIT_PLACEHOLDER = "/home/pi/secure-call-backend/deploy/raspberry-pi"


def unit_settings(unit_text: str) -> dict[str, list[str]]:
    settings: dict[str, list[str]] = {}
    for line in unit_text.splitlines():
        if "=" in line and not line.startswith(("#", "[")):
            key, value = line.split("=", 1)
            settings.setdefault(key, []).append(value)
    return settings


def test_unit_reapplies_after_docker_starts_or_restarts() -> None:
    settings = unit_settings((DEPLOY / "secure-call-firewall.service").read_text())

    assert settings["After"] == ["docker.service"]
    assert settings["Requires"] == ["docker.service"]
    assert settings["PartOf"] == ["docker.service"]
    assert settings["WantedBy"] == ["docker.service"]
    assert settings["Type"] == ["oneshot"]
    assert settings["RemainAfterExit"] == ["yes"]
    assert settings["ExecStart"] == [
        f"/usr/local/sbin/secure-call-firewall --env-file {UNIT_PLACEHOLDER}/.env"
    ]
    assert "ExecStop" not in settings
    assert settings["NoNewPrivileges"] == ["yes"]


def test_negative_a_unit_running_the_repository_copy_would_be_caught() -> None:
    weakened = unit_settings(
        "[Service]\nExecStart=/home/pi/secure-call-backend/deploy/raspberry-pi/firewall.sh\n"
    )

    assert not weakened["ExecStart"][0].startswith("/usr/local/sbin/")
    assert "After" not in weakened


def test_readme_installs_the_unit_and_documents_the_limits() -> None:
    readme = (DEPLOY / "README.md").read_text()
    script = (DEPLOY / "firewall.sh").read_text()

    assert (
        "sudo install -o root -g root -m 0755 firewall.sh /usr/local/sbin/secure-call-firewall"
        in readme
    )
    assert f'sed "s|{UNIT_PLACEHOLDER}|$PWD|" secure-call-firewall.service' in readme
    assert "sudo secure-call-firewall --remove" in readme
    for name in (
        "turn_tcp_max_connections_per_source",
        "turn_tcp_new_connections_burst",
        "turn_tcp_new_connections_per_minute",
    ):
        value = re.search(rf"^{name}=(\d+)", script, re.M)
        assert value is not None
        assert f"`{name}={value[1]}`" in readme, name
