"""Probe: does the relay refuse IPv6 relays and IPv6 / IPv4-mapped peers with specific errors?

Usage: address_family_probe.py USERNAME PASSWORD [EXTRA_PEER ...]    (server: 127.0.0.1:3478)

1. Allocate asking for an IPv6 relay (REQUESTED-ADDRESS-FAMILY = IPv6).
2. Allocate an IPv4 relay, then CreatePermission for a public IPv4 peer (control: must succeed),
   for each EXTRA_PEER (the caller expects a refusal) and for IPv6 and IPv4-mapped IPv6 peers
   (must be refused).
Prints one line per check: "PROBE <label>: success" or "PROBE <label>: error <code>".
Exits with status 2 (nothing on stdout) if the probe itself could not run. Standard library only.
"""

import ipaddress
import os
import socket
import struct
import sys

from refresh_after_expiry import (
    ALLOCATE_REQUEST,
    ALLOCATE_SUCCESS,
    ATTR_NONCE,
    ATTR_REALM,
    ATTR_REQUESTED_TRANSPORT,
    MAGIC_COOKIE,
    STALE_NONCE_ERROR_CODE,
    UDP_PROTOCOL_NUMBER,
    ProbeError,
    build_request,
    encode_attribute,
    error_code_of,
    exchange,
)

CREATE_PERMISSION_REQUEST = 0x0008
CREATE_PERMISSION_SUCCESS = 0x0108
ATTR_REQUESTED_ADDRESS_FAMILY = 0x0017
ATTR_XOR_PEER_ADDRESS = 0x0012
FAMILY_IPV6 = 0x02

PUBLIC_PEER = "8.8.8.8"
REFUSED_PEERS = [
    "::1",
    "fc00::1",
    "fe80::1",
    "::ffff:10.0.0.5",
    "::ffff:127.0.0.1",
    "::ffff:192.168.1.10",
    "::ffff:169.254.1.1",
]

Credentials = tuple[bytes, bytes, bytes, bytes]


def xor_peer_address(peer: str, transaction_id: bytes, port: int = 9) -> bytes:
    address = ipaddress.ip_address(peer)
    port_field = struct.pack("!H", port ^ (MAGIC_COOKIE >> 16))
    cookie = struct.pack("!I", MAGIC_COOKIE)
    if address.version == 4:
        masked = bytes(a ^ b for a, b in zip(address.packed, cookie, strict=True))
        value = struct.pack("!BB", 0, 0x01) + port_field + masked
    else:
        mask = cookie + transaction_id
        masked = bytes(a ^ b for a, b in zip(address.packed, mask, strict=True))
        value = struct.pack("!BB", 0, FAMILY_IPV6) + port_field + masked
    return encode_attribute(ATTR_XOR_PEER_ADDRESS, value)


def outcome_of(message_type: int, success_type: int, attributes: dict[int, bytes]) -> str:
    if message_type == success_type:
        return "success"
    return f"error {error_code_of(attributes)}"


def request_with_fresh_nonce(
    server: socket.socket, message_type: int, attributes: bytes, credentials: Credentials
) -> tuple[int, dict[int, bytes], bytes]:
    """Sends an authenticated request; retries once with the new nonce on 438. Returns the nonce."""
    username, realm, nonce, password = credentials
    for _attempt in range(2):
        response_type, response_attributes = exchange(
            server, build_request(message_type, attributes, (username, realm, nonce, password))
        )
        if (
            error_code_of(response_attributes) == STALE_NONCE_ERROR_CODE
            and ATTR_NONCE in response_attributes
        ):
            nonce = response_attributes[ATTR_NONCE]
            continue
        break
    return response_type, response_attributes, nonce


def create_permission(server: socket.socket, peer: str, credentials: Credentials) -> str:
    username, realm, nonce, password = credentials
    transaction_id = os.urandom(12)
    request = build_request(
        CREATE_PERMISSION_REQUEST,
        xor_peer_address(peer, transaction_id),
        (username, realm, nonce, password),
        transaction_id,
    )
    message_type, attributes = exchange(server, request)
    return outcome_of(message_type, CREATE_PERMISSION_SUCCESS, attributes)


def challenge(server: socket.socket) -> tuple[bytes, bytes]:
    transport = encode_attribute(ATTR_REQUESTED_TRANSPORT, struct.pack("!B3x", UDP_PROTOCOL_NUMBER))
    _type, attributes = exchange(server, build_request(ALLOCATE_REQUEST, transport, None))
    if error_code_of(attributes) != 401 or ATTR_REALM not in attributes:
        raise ProbeError("expected a 401 challenge")
    return attributes[ATTR_REALM], attributes[ATTR_NONCE]


def new_socket(server_host: str) -> socket.socket:
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.settimeout(5)
    server.connect((server_host, 3478))
    return server


def main(arguments: list[str]) -> int:
    if len(arguments) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    username = arguments[0].encode()
    password = arguments[1].encode()
    extra_peers = arguments[2:]
    server_host = "127.0.0.1"
    transport = encode_attribute(ATTR_REQUESTED_TRANSPORT, struct.pack("!B3x", UDP_PROTOCOL_NUMBER))
    results: list[str] = []

    # 1. An IPv6 relay must be refused (RFC 8656: 440 Address Family not Supported).
    server = new_socket(server_host)
    realm, nonce = challenge(server)
    family = encode_attribute(ATTR_REQUESTED_ADDRESS_FAMILY, struct.pack("!B3x", FAMILY_IPV6))
    message_type, attributes, _nonce = request_with_fresh_nonce(
        server, ALLOCATE_REQUEST, transport + family, (username, realm, nonce, password)
    )
    results.append(
        f"PROBE ipv6 relay request: {outcome_of(message_type, ALLOCATE_SUCCESS, attributes)}"
    )
    server.close()

    # 2. On an IPv4 allocation: a public peer works (control), IPv6 and mapped peers do not.
    server = new_socket(server_host)
    realm, nonce = challenge(server)
    message_type, attributes, nonce = request_with_fresh_nonce(
        server, ALLOCATE_REQUEST, transport, (username, realm, nonce, password)
    )
    if message_type != ALLOCATE_SUCCESS:
        raise ProbeError(f"IPv4 allocation failed with error {error_code_of(attributes)}")
    credentials = (username, realm, nonce, password)
    results.append(
        f"PROBE permission {PUBLIC_PEER}: {create_permission(server, PUBLIC_PEER, credentials)}"
    )
    for peer in [*extra_peers, *REFUSED_PEERS]:
        results.append(f"PROBE permission {peer}: {create_permission(server, peer, credentials)}")
    server.close()

    print("\n".join(results))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except ProbeError as probe_error:
        print(f"probe could not run: {probe_error}", file=sys.stderr)
        sys.exit(2)
