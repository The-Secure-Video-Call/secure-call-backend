"""Probe: does coturn still accept an allocation refresh after the credential has expired?

Usage: refresh_after_expiry.py USERNAME PASSWORD WAIT_SECONDS [SERVER_HOST]

Allocates over UDP with the given REST credential, waits WAIT_SECONDS (longer than the
credential's remaining life), then sends a Refresh with the same long-term credential.
Prints exactly one line: "REFRESH AFTER EXPIRY: allowed" or "REFRESH AFTER EXPIRY: refused".
Exits with status 2 (and prints nothing on stdout) if the probe itself could not run, so a
broken probe is never reported as a result. Standard library only; talks only to the server
it is given.
"""

import hashlib
import hmac
import os
import socket
import struct
import sys
import time

MAGIC_COOKIE = 0x2112A442
ALLOCATE_REQUEST = 0x0003
ALLOCATE_SUCCESS = 0x0103
REFRESH_REQUEST = 0x0004
REFRESH_SUCCESS = 0x0104
ATTR_USERNAME = 0x0006
ATTR_MESSAGE_INTEGRITY = 0x0008
ATTR_ERROR_CODE = 0x0009
ATTR_REALM = 0x0014
ATTR_NONCE = 0x0015
ATTR_LIFETIME = 0x000D
ATTR_REQUESTED_TRANSPORT = 0x0019
UDP_PROTOCOL_NUMBER = 17
STALE_NONCE_ERROR_CODE = 438


class ProbeError(Exception):
    """The probe could not run (network problem or an unexpected server reply)."""


def pad_to_four_bytes(value: bytes) -> bytes:
    return value + b"\x00" * (-len(value) % 4)


def encode_attribute(attribute_type: int, value: bytes) -> bytes:
    return struct.pack("!HH", attribute_type, len(value)) + pad_to_four_bytes(value)


def build_request(
    message_type: int,
    attributes: bytes,
    credentials: tuple[bytes, bytes, bytes, bytes] | None,
) -> bytes:
    """credentials = (username, realm, nonce, password); adds USERNAME/REALM/NONCE/integrity."""
    transaction_id = os.urandom(12)
    body = attributes
    if credentials is not None:
        username, realm, nonce, password = credentials
        body += encode_attribute(ATTR_USERNAME, username)
        body += encode_attribute(ATTR_REALM, realm)
        body += encode_attribute(ATTR_NONCE, nonce)
        # The header length must already count the 24-byte MESSAGE-INTEGRITY attribute.
        header = struct.pack("!HHI", message_type, len(body) + 24, MAGIC_COOKIE) + transaction_id
        key = hashlib.md5(username + b":" + realm + b":" + password).digest()  # noqa: S324
        integrity = hmac.new(key, header + body, hashlib.sha1).digest()
        body += encode_attribute(ATTR_MESSAGE_INTEGRITY, integrity)
    header = struct.pack("!HHI", message_type, len(body), MAGIC_COOKIE) + transaction_id
    return header + body


def parse_response(datagram: bytes) -> tuple[int, dict[int, bytes]]:
    if len(datagram) < 20:
        raise ProbeError("short STUN response")
    message_type, body_length, _cookie = struct.unpack("!HHI", datagram[:8])
    attributes: dict[int, bytes] = {}
    offset = 20
    end = min(20 + body_length, len(datagram))
    while offset + 4 <= end:
        attribute_type, attribute_length = struct.unpack("!HH", datagram[offset : offset + 4])
        attributes[attribute_type] = datagram[offset + 4 : offset + 4 + attribute_length]
        offset += 4 + attribute_length + (-attribute_length % 4)
    return message_type, attributes


def error_code_of(attributes: dict[int, bytes]) -> int:
    raw_error = attributes.get(ATTR_ERROR_CODE, b"")
    if len(raw_error) < 4:
        return 0
    return raw_error[2] * 100 + raw_error[3]


def exchange(server: socket.socket, request: bytes) -> tuple[int, dict[int, bytes]]:
    try:
        server.send(request)
        return parse_response(server.recv(2048))
    except OSError as error:
        raise ProbeError(f"network error: {error}") from error


def main(arguments: list[str]) -> int:
    if len(arguments) not in (3, 4):
        print(__doc__, file=sys.stderr)
        return 2
    username = arguments[0].encode()
    password = arguments[1].encode()
    wait_seconds = float(arguments[2])
    server_host = arguments[3] if len(arguments) == 4 else "127.0.0.1"

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.settimeout(5)
    server.connect((server_host, 3478))
    transport = encode_attribute(ATTR_REQUESTED_TRANSPORT, struct.pack("!B3x", UDP_PROTOCOL_NUMBER))

    # 1. Unauthenticated Allocate to learn realm and nonce (expected 401).
    message_type, attributes = exchange(server, build_request(ALLOCATE_REQUEST, transport, None))
    if error_code_of(attributes) != 401 or ATTR_REALM not in attributes:
        raise ProbeError(f"expected a 401 challenge, got type {message_type:#06x}")
    realm = attributes[ATTR_REALM]
    nonce = attributes[ATTR_NONCE]

    # 2. Authenticated Allocate while the credential is still valid.
    message_type, attributes = exchange(
        server, build_request(ALLOCATE_REQUEST, transport, (username, realm, nonce, password))
    )
    if message_type != ALLOCATE_SUCCESS:
        raise ProbeError(f"allocation failed with error {error_code_of(attributes)}")

    # 3. Wait until the credential has expired, then refresh the same allocation.
    time.sleep(wait_seconds)
    lifetime = encode_attribute(ATTR_LIFETIME, struct.pack("!I", 600))
    for _attempt in range(2):
        message_type, attributes = exchange(
            server, build_request(REFRESH_REQUEST, lifetime, (username, realm, nonce, password))
        )
        if error_code_of(attributes) == STALE_NONCE_ERROR_CODE and ATTR_NONCE in attributes:
            nonce = attributes[ATTR_NONCE]  # the server rotated the nonce; ask again
            continue
        break

    if message_type == REFRESH_SUCCESS:
        print("REFRESH AFTER EXPIRY: allowed")
    else:
        print("REFRESH AFTER EXPIRY: refused")
        print(f"(server answered with error {error_code_of(attributes)})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except ProbeError as probe_error:
        print(f"probe could not run: {probe_error}", file=sys.stderr)
        sys.exit(2)
