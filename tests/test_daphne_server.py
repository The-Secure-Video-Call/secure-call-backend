"""Close codes and room cleanup through a real Daphne server.

`WebsocketCommunicator` talks to the consumer directly, so it accepts close codes that Daphne
(Autobahn) rejects. These tests start Daphne in a subprocess and connect real WebSocket clients.
"""

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Awaitable, Callable, Iterator

import pytest
from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed

from signaling.consumers import (
    CLOSE_MESSAGE_TOO_BIG,
    CLOSE_POLICY_VIOLATION,
    CLOSE_UNSUPPORTED_DATA,
)

ALLOWED_ORIGIN = "http://localhost:5173"
ROOM_ID = "A" * 22
RECEIVE_TIMEOUT_SECONDS = 5


def find_free_port() -> int:
    with socket.socket() as probe_socket:
        probe_socket.bind(("127.0.0.1", 0))
        port: int = probe_socket.getsockname()[1]
    return port


@pytest.fixture(scope="module")
def daphne_url() -> Iterator[str]:
    port = find_free_port()
    # Never inherit real secrets, origins or a real database from the surrounding environment.
    server_environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("POSTGRES_", "DJANGO_", "SIGNALING_", "REDIS_"))
    }
    server_environment["DJANGO_SETTINGS_MODULE"] = "config.settings_test"
    server_environment["SIGNALING_ALLOWED_ORIGINS"] = ALLOWED_ORIGIN
    server_process = subprocess.Popen(  # noqa: S603 - fixed arguments, no user input
        [
            sys.executable,
            "-m",
            "daphne",
            "-b",
            "127.0.0.1",
            "-p",
            str(port),
            "config.asgi:application",
        ],
        env=server_environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if server_process.poll() is not None:
                pytest.fail("Daphne exited before accepting connections")
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            pytest.fail("Daphne did not start in time")
        yield f"ws://127.0.0.1:{port}/ws/signal/"
    finally:
        server_process.terminate()
        server_process.wait(timeout=10)


async def join_room(url: str) -> tuple[ClientConnection, dict[str, str]]:
    client = await connect(url, origin=ALLOWED_ORIGIN)  # type: ignore[arg-type]
    await client.send(json.dumps({"v": 1, "type": "join", "roomId": ROOM_ID}))
    return client, await receive_json(client)


async def receive_json(client: ClientConnection) -> dict[str, str]:
    raw_message = await asyncio.wait_for(client.recv(), RECEIVE_TIMEOUT_SECONDS)
    parsed: dict[str, str] = json.loads(raw_message)
    return parsed


async def assert_closed_with_code(client: ClientConnection, expected_code: int) -> None:
    with pytest.raises(ConnectionClosed):
        await asyncio.wait_for(client.recv(), RECEIVE_TIMEOUT_SECONDS)
    assert client.close_code == expected_code


async def assert_room_cleaned_up_after_bad_input(
    url: str,
    send_bad_input: Callable[[ClientConnection], Awaitable[None]],
    expected_close_code: int,
) -> None:
    first, first_joined = await join_room(url)
    assert first_joined["role"] == "first"
    second, second_joined = await join_room(url)
    assert second_joined["role"] == "second"
    assert (await receive_json(first))["type"] == "peer-joined"

    await send_bad_input(first)
    await assert_closed_with_code(first, expected_close_code)
    assert (await receive_json(second))["type"] == "peer-left"

    third, third_joined = await join_room(url)
    assert third_joined["role"] == "second"  # not "room-full"
    await second.close()
    await third.close()


async def test_malformed_message_closes_with_4008_and_cleans_up_room(daphne_url: str) -> None:
    async def send_malformed_signal(client: ClientConnection) -> None:
        await client.send('{"v":1,"type":"signal","payload":"not base64!"}')

    await assert_room_cleaned_up_after_bad_input(
        daphne_url, send_malformed_signal, CLOSE_POLICY_VIOLATION
    )


async def test_binary_frame_closes_with_4003_and_cleans_up_room(daphne_url: str) -> None:
    async def send_binary_frame(client: ClientConnection) -> None:
        await client.send(b"\x00\x01\x02")

    await assert_room_cleaned_up_after_bad_input(
        daphne_url, send_binary_frame, CLOSE_UNSUPPORTED_DATA
    )


async def test_oversized_message_closes_with_4009_and_cleans_up_room(daphne_url: str) -> None:
    async def send_oversized_signal(client: ClientConnection) -> None:
        await client.send(
            json.dumps({"v": 1, "type": "signal", "payload": "A" * (64 * 1024), "iv": "A" * 16})
        )

    await assert_room_cleaned_up_after_bad_input(
        daphne_url, send_oversized_signal, CLOSE_MESSAGE_TOO_BIG
    )
