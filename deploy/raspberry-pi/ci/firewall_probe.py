"""CI only (ci/test-firewall.sh): connection probes that show what firewall.sh lets through. It
runs on the runner, in a network namespace and inside the containers (the backend image), so it
uses the standard library only.

    firewall_probe.py check [--source ADDRESS] KIND:HOST:PORT=EXPECTED ...
    firewall_probe.py held [--source ADDRESS] HOST:PORT COUNT [PACE_AFTER SECONDS]
    firewall_probe.py burst [--source ADDRESS] HOST:PORT COUNT
    firewall_probe.py listen KIND:ADDRESS:PORT ...

KIND is tcp or udp, EXPECTED open, blocked, refused or any. For tcp, "open" means the connection
was made; for udp, that an answer came back (the listeners echo, a public DNS server answers the
query sent). "blocked" means nothing at all came back in time: no connection, no refusal, no ICMP
error, so the packets were dropped on the way. "refused" means a reset or an ICMP "port
unreachable" came back at once (a REJECT rule, or nothing listening). "any" only prints the
result. `check` exits 1 if any result is not the expected one.

`held` opens COUNT TCP connections one after the other and keeps them all open (after the first
PACE_AFTER, it waits SECONDS before each further one, to stay inside a rate limit). `burst` opens
COUNT and closes each at once (with a reset, so it no longer counts as open). Both print how many
were made, as "made N of COUNT" (for the connlimit and hashlimit rules).
`listen` accepts TCP connections (kept until the other side closes) and echoes UDP datagrams,
until it is killed.
"""

import selectors
import socket
import struct
import sys
import time
from typing import NamedTuple

TIMEOUT_SECONDS = 3.0
# Shorter than Linux's first SYN retransmission (1 s): one dropped SYN is one refused attempt.
LIMIT_TIMEOUT_SECONDS = 0.5
OPEN_ATTEMPTS = 3
# A DNS query for example.com (A): a public DNS server answers it, and the listeners echo it.
DNS_QUERY = bytes.fromhex("1d0b01000001000000000000076578616d706c6503636f6d0000010001")


class Target(NamedTuple):
    kind: str
    host: str
    port: int


def parse_target(text: str) -> Target:
    kind, host, port = text.split(":")
    if kind not in {"tcp", "udp"} or not host or not port.isdigit():
        raise ValueError(text)
    return Target(kind, host, int(port))


def try_tcp(target: Target, source: str | None, timeout: float = TIMEOUT_SECONDS) -> str:
    source_address = (source, 0) if source else None
    try:
        connection = socket.create_connection(
            (target.host, target.port), timeout=timeout, source_address=source_address
        )
    except TimeoutError:
        return "blocked"
    except ConnectionRefusedError:
        return "refused"
    except OSError as error:
        return f"error ({error})"
    connection.close()
    return "open"


def try_udp(target: Target, source: str | None) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        if source:
            udp_socket.bind((source, 0))
        udp_socket.settimeout(TIMEOUT_SECONDS)
        try:
            # Connected, so an ICMP error comes back as an exception instead of being ignored.
            udp_socket.connect((target.host, target.port))
            udp_socket.send(DNS_QUERY)
            udp_socket.recv(2048)
        except TimeoutError:
            return "blocked"
        except ConnectionRefusedError:
            return "refused"
        except OSError as error:
            return f"error ({error})"
    return "open"


def check(expectations: list[str], source: str | None) -> int:
    failures = 0
    for expectation in expectations:
        target_text, expected = expectation.rsplit("=", 1)
        if expected not in {"open", "blocked", "refused", "any"}:
            raise ValueError(expectation)
        target = parse_target(target_text)
        attempts = OPEN_ATTEMPTS if expected == "open" else 1
        for attempt in range(attempts):
            result = try_tcp(target, source) if target.kind == "tcp" else try_udp(target, source)
            if result == expected or attempt == attempts - 1:
                break
            time.sleep(1)
        verdict = "OK" if result == expected else "INFO" if expected == "any" else "FAIL"
        if verdict == "FAIL":
            failures += 1
        from_text = f" from {source}" if source else ""
        print(f"{verdict}: {target.kind} {target.host}:{target.port}{from_text}: {result}"
              f" (expected {expected})")  # fmt: skip
    return 1 if failures else 0


def host_and_port(text: str) -> tuple[str, int]:
    host, port = text.rsplit(":", 1)
    return host, int(port)


def held(
    address: tuple[str, int], count: int, source: str | None, pace_after: int, seconds: float
) -> int:
    connections: list[socket.socket] = []
    source_address = (source, 0) if source else None
    for attempt in range(count):
        if attempt >= pace_after:
            time.sleep(seconds)
        try:
            connections.append(
                socket.create_connection(
                    address, timeout=LIMIT_TIMEOUT_SECONDS, source_address=source_address
                )
            )
        except OSError:
            continue
    print(f"made {len(connections)} of {count}")
    for connection in connections:
        connection.close()
    return 0


def burst(address: tuple[str, int], count: int, source: str | None) -> int:
    made = 0
    source_address = (source, 0) if source else None
    started = time.monotonic()
    for _ in range(count):
        try:
            connection = socket.create_connection(
                address, timeout=LIMIT_TIMEOUT_SECONDS, source_address=source_address
            )
        except OSError:
            continue
        made += 1
        # A reset closes it at once (conntrack CLOSE), so connlimit stops counting it.
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        connection.close()
    print(f"made {made} of {count} in {time.monotonic() - started:.1f} s")
    return 0


def listen(specifications: list[str]) -> int:
    selector = selectors.DefaultSelector()
    servers: dict[int, tuple[str, socket.socket]] = {}
    for specification in specifications:
        target = parse_target(specification)
        kind = socket.SOCK_STREAM if target.kind == "tcp" else socket.SOCK_DGRAM
        server = socket.socket(socket.AF_INET, kind)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((target.host, target.port))
        if target.kind == "tcp":
            server.listen(128)
        server.setblocking(False)
        selector.register(server, selectors.EVENT_READ)
        servers[server.fileno()] = (target.kind, server)
    print("listening", flush=True)
    while True:
        for key, _ in selector.select():
            role, ready = servers[key.fd]
            try:
                if role == "tcp":
                    connection, _ = ready.accept()
                    connection.setblocking(False)
                    selector.register(connection, selectors.EVENT_READ)
                    servers[connection.fileno()] = ("connection", connection)
                elif role == "udp":
                    datagram, sender = ready.recvfrom(2048)
                    ready.sendto(datagram, sender)
                elif not ready.recv(2048):
                    raise ConnectionResetError
            except BlockingIOError:
                continue
            except OSError:
                if role == "connection":
                    selector.unregister(ready)
                    del servers[key.fd]
                    ready.close()


def main(arguments: list[str]) -> int:
    command, rest = arguments[0], arguments[1:]
    source = None
    if rest[:1] == ["--source"]:
        source, rest = rest[1], rest[2:]
    if command == "check":
        return check(rest, source)
    if command == "held":
        count = int(rest[1])
        pace_after, seconds = (int(rest[2]), float(rest[3])) if len(rest) > 2 else (count, 0.0)
        return held(host_and_port(rest[0]), count, source, pace_after, seconds)
    if command == "burst":
        return burst(host_and_port(rest[0]), int(rest[1]), source)
    if command == "listen":
        return listen(rest)
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
