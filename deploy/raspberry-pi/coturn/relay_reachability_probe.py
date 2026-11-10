"""Probe: where do packets sent through the relay actually go?

Usage: relay_reachability_probe.py USER_A PASSWORD_A USER_B PASSWORD_B PUBLIC_IP RELAY_IP
(server: 127.0.0.1:3478; PUBLIC_IP and RELAY_IP are the --external-ip pair the server runs with)

coturn exempts its own addresses from the deny list (two clients on the same relay must reach
each other), so a CreatePermission to them succeeds. A permission is not data. This probe checks
the data:

1. Relay to relay (must work, the "both people use our relay" case): allocation A creates a
   permission for allocation B's XOR-RELAYED-ADDRESS, sends data, and B must receive it. Then the
   same in the other direction.
2. Nothing else may be reached through our own addresses: UDP listeners on RELAY_IP:40001 and
   127.0.0.1:40002 (ports outside the relay range) must receive NOTHING when allocation A sends
   to PUBLIC_IP:40001, RELAY_IP:40001 and 127.0.0.1:40002 (after trying to create permissions;
   a Send without a permission is dropped, so each verdict names the permission outcome).
   A self-check first proves the listeners can receive.

Prints one line per check: "PROBE <label>: <outcome>". Exits with status 2 (nothing on stdout)
if the probe itself could not run. Standard library only.
"""

import os
import select
import socket
import struct
import sys
import time

from address_family_probe import (
    Credentials,
    challenge,
    create_permission,
    new_socket,
    request_with_fresh_nonce,
    xor_peer_address,
)
from refresh_after_expiry import (
    ALLOCATE_REQUEST,
    ALLOCATE_SUCCESS,
    ATTR_REQUESTED_TRANSPORT,
    MAGIC_COOKIE,
    UDP_PROTOCOL_NUMBER,
    ProbeError,
    build_request,
    encode_attribute,
    error_code_of,
    parse_response,
)

SEND_INDICATION = 0x0016
DATA_INDICATION = 0x0017
ATTR_XOR_RELAYED_ADDRESS = 0x0016
ATTR_DATA = 0x0013
RELAY_LISTENER_PORT = 40001  # not 5353 (mDNS, may be taken); outside the relay range 49160-49200
LOOPBACK_LISTENER_PORT = 40002
SERVER_HOST = "127.0.0.1"

Relayed = tuple[str, int]


def allocate(username: bytes, password: bytes) -> tuple[socket.socket, Credentials, Relayed]:
    server = new_socket(SERVER_HOST)
    realm, nonce = challenge(server)
    transport = encode_attribute(ATTR_REQUESTED_TRANSPORT, struct.pack("!B3x", UDP_PROTOCOL_NUMBER))
    message_type, attributes, nonce = request_with_fresh_nonce(
        server, ALLOCATE_REQUEST, transport, (username, realm, nonce, password)
    )
    if message_type != ALLOCATE_SUCCESS or ATTR_XOR_RELAYED_ADDRESS not in attributes:
        raise ProbeError(f"allocation failed with error {error_code_of(attributes)}")
    raw_address = attributes[ATTR_XOR_RELAYED_ADDRESS]
    port = struct.unpack("!H", raw_address[2:4])[0] ^ (MAGIC_COOKIE >> 16)
    cookie = struct.pack("!I", MAGIC_COOKIE)
    ip_bytes = bytes(a ^ b for a, b in zip(raw_address[4:8], cookie, strict=True))
    return server, (username, realm, nonce, password), (socket.inet_ntoa(ip_bytes), port)


def send_indication(server: socket.socket, peer: str, port: int, payload: bytes) -> None:
    transaction_id = os.urandom(12)
    attributes = xor_peer_address(peer, transaction_id, port) + encode_attribute(ATTR_DATA, payload)
    try:
        server.send(build_request(SEND_INDICATION, attributes, None, transaction_id))
    except OSError as error:
        raise ProbeError(f"network error: {error}") from error


def received_data(server: socket.socket, wait_seconds: float) -> bytes | None:
    """Returns the DATA of the next Data indication within wait_seconds, else None."""
    deadline = time.monotonic() + wait_seconds
    while (remaining := deadline - time.monotonic()) > 0:
        server.settimeout(remaining)
        try:
            message_type, attributes = parse_response(server.recv(2048))
        except TimeoutError:
            return None
        except OSError as error:
            raise ProbeError(f"network error: {error}") from error
        if message_type == DATA_INDICATION:
            return attributes.get(ATTR_DATA)
    return None


def listener_on(address: str, port: int) -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        listener.bind((address, port))
    except OSError as error:
        raise ProbeError(f"cannot listen on {address}:{port}: {error}") from error
    return listener


def drain(listener: socket.socket, wait_seconds: float) -> list[bytes]:
    datagrams: list[bytes] = []
    while select.select([listener], [], [], wait_seconds)[0]:
        datagrams.append(listener.recv(2048))
        wait_seconds = 0.1
    return datagrams


def main(arguments: list[str]) -> int:
    if len(arguments) != 6:
        print(__doc__, file=sys.stderr)
        return 2
    user_a, password_a, user_b, password_b = (argument.encode() for argument in arguments[:4])
    public_ip, relay_ip = arguments[4], arguments[5]
    results: list[str] = []

    # 1. Relay to relay, both directions.
    server_a, credentials_a, relayed_a = allocate(user_a, password_a)
    server_b, credentials_b, relayed_b = allocate(user_b, password_b)
    results.append(f"PROBE relayed address is the public form: {relayed_a[0] == public_ip}")
    # Each side permits the other's relayed address as the allocation reports it.
    a_permits_b = create_permission(server_a, relayed_b[0], credentials_a)
    b_permits_a = create_permission(server_b, relayed_a[0], credentials_b)
    results.append(f"PROBE A permits B's relayed address: {a_permits_b}")
    results.append(f"PROBE B permits A's relayed address: {b_permits_a}")
    send_indication(server_a, relayed_b[0], relayed_b[1], b"relay-a-to-b")
    got_by_b = received_data(server_b, 3)
    results.append(
        f"PROBE relay A->B: {'delivered' if got_by_b == b'relay-a-to-b' else 'NOT delivered'}"
    )
    send_indication(server_b, relayed_a[0], relayed_a[1], b"relay-b-to-a")
    got_by_a = received_data(server_a, 3)
    results.append(
        f"PROBE relay B->A: {'delivered' if got_by_a == b'relay-b-to-a' else 'NOT delivered'}"
    )

    # 2. Our own addresses must not reach anything but relay ports.
    relay_listener = listener_on(relay_ip, RELAY_LISTENER_PORT)
    loopback_listener = listener_on("127.0.0.1", LOOPBACK_LISTENER_PORT)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.sendto(b"self-check", (relay_ip, RELAY_LISTENER_PORT))
    sender.sendto(b"self-check", ("127.0.0.1", LOOPBACK_LISTENER_PORT))
    self_check_ok = drain(relay_listener, 2) == [b"self-check"]
    self_check_ok = drain(loopback_listener, 2) == [b"self-check"] and self_check_ok
    if not self_check_ok:
        raise ProbeError("the listeners cannot receive a direct datagram")
    sender.close()
    targets = [
        (public_ip, RELAY_LISTENER_PORT),
        (relay_ip, RELAY_LISTENER_PORT),
        ("127.0.0.1", LOOPBACK_LISTENER_PORT),
    ]
    permission_by_ip: dict[str, str] = {}
    for target_ip in dict.fromkeys(ip for ip, _port in targets):
        # The permission may succeed or be refused. coturn drops a Send without a permission, so
        # a listener verdict only counts as a hairpin test when the permission succeeded.
        outcome = create_permission(server_a, target_ip, credentials_a)
        if outcome == "error 438":
            raise ProbeError("stale nonce while creating a permission")
        permission_by_ip[target_ip] = outcome
        results.append(f"PROBE permission outcome {target_ip}: {outcome}")
    for target_ip, target_port in targets:
        send_indication(server_a, target_ip, target_port, b"hairpin-test")
    time.sleep(2)
    for label_ip, label_port, listener in (
        (relay_ip, RELAY_LISTENER_PORT, relay_listener),
        ("127.0.0.1", LOOPBACK_LISTENER_PORT, loopback_listener),
    ):
        received = drain(listener, 0.5)
        permission = permission_by_ip[label_ip]
        if received:
            verdict = f"RECEIVED {len(received)}"
        elif permission == "success":
            verdict = "nothing received (permission success)"
        else:
            verdict = f"nothing received (permission refused: {permission}, not a hairpin test)"
        results.append(f"PROBE listener {label_ip}:{label_port}: {verdict}")
    for open_socket in (server_a, server_b, relay_listener, loopback_listener):
        open_socket.close()

    print("\n".join(results))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except ProbeError as probe_error:
        print(f"probe could not run: {probe_error}", file=sys.stderr)
        sys.exit(2)
