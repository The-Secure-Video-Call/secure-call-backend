"""Probe: does coturn refuse an allocation over `user-quota` with 486?

Usage: allocation_quota_probe.py USERNAME PASSWORD ALLOCATION_COUNT [SERVER_HOST]

Makes ALLOCATION_COUNT Allocate requests with ONE REST credential, each from its own UDP socket
(so its own 5-tuple, like each TURN port a browser opens), and keeps every socket open so no
allocation expires or is closed meanwhile. Prints one line per attempt:
"ALLOCATION <n>: success" or "ALLOCATION <n>: error <code>".
Exits with status 2 (and prints nothing on stdout) if the probe itself could not run. Standard
library only; talks only to the server it is given.
"""

import socket
import struct
import sys

from refresh_after_expiry import (
    ALLOCATE_REQUEST,
    ALLOCATE_SUCCESS,
    ATTR_NONCE,
    ATTR_REALM,
    ATTR_REQUESTED_TRANSPORT,
    UDP_PROTOCOL_NUMBER,
    ProbeError,
    build_request,
    encode_attribute,
    error_code_of,
    exchange,
)

MAX_ALLOCATION_COUNT = 20


def allocate_once(
    server_socket: socket.socket, username: bytes, password: bytes
) -> tuple[bool, int]:
    """Challenge, then authenticated Allocate. Returns (succeeded, error code or 0)."""
    transport = encode_attribute(ATTR_REQUESTED_TRANSPORT, struct.pack("!B3x", UDP_PROTOCOL_NUMBER))
    _type, challenge = exchange(server_socket, build_request(ALLOCATE_REQUEST, transport, None))
    if error_code_of(challenge) != 401 or ATTR_REALM not in challenge:
        raise ProbeError(f"expected a 401 challenge, got error {error_code_of(challenge)}")
    message_type, attributes = exchange(
        server_socket,
        build_request(
            ALLOCATE_REQUEST,
            transport,
            (username, challenge[ATTR_REALM], challenge[ATTR_NONCE], password),
        ),
    )
    if message_type == ALLOCATE_SUCCESS:
        return True, 0
    return False, error_code_of(attributes)


def main(arguments: list[str]) -> int:
    if len(arguments) not in (3, 4):
        print(__doc__, file=sys.stderr)
        return 2
    username = arguments[0].encode()
    password = arguments[1].encode()
    allocation_count = int(arguments[2])
    server_host = arguments[3] if len(arguments) == 4 else "127.0.0.1"
    if not 1 <= allocation_count <= MAX_ALLOCATION_COUNT:
        raise ProbeError(f"allocation count must be 1 to {MAX_ALLOCATION_COUNT}")

    open_sockets: list[socket.socket] = []
    results: list[str] = []
    try:
        for attempt_number in range(1, allocation_count + 1):
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server_socket.settimeout(5)
            server_socket.connect((server_host, 3478))
            open_sockets.append(server_socket)
            succeeded, error_code = allocate_once(server_socket, username, password)
            outcome = "success" if succeeded else f"error {error_code}"
            results.append(f"ALLOCATION {attempt_number}: {outcome}")
    finally:
        for server_socket in open_sockets:
            server_socket.close()
    print("\n".join(results))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except ProbeError as probe_error:
        print(f"probe could not run: {probe_error}", file=sys.stderr)
        sys.exit(2)
