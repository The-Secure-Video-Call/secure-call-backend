"""Dead-connection detection through a real Daphne server started with short ping values."""

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator

import pytest
from websockets.asyncio.client import ClientConnection, connect

ALLOWED_ORIGIN = "http://localhost:5173"
PING_INTERVAL_SECONDS = 1
PING_TIMEOUT_SECONDS = 2
RECEIVE_TIMEOUT_SECONDS = 10
DEAD_ROOM_ID = "D" * 22
IDLE_ROOM_ID = "I" * 22


def find_free_port() -> int:
    with socket.socket() as probe_socket:
        probe_socket.bind(("127.0.0.1", 0))
        port: int = probe_socket.getsockname()[1]
    return port


@pytest.fixture(scope="module")
def daphne_url() -> Iterator[str]:
    port = find_free_port()
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
            "--ping-interval",
            str(PING_INTERVAL_SECONDS),
            "--ping-timeout",
            str(PING_TIMEOUT_SECONDS),
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


async def join_room(url: str, room_id: str) -> tuple[ClientConnection, dict[str, str]]:
    client = await connect(url, origin=ALLOWED_ORIGIN)  # type: ignore[arg-type]
    await client.send(json.dumps({"v": 1, "type": "join", "roomId": room_id}))
    return client, await receive_json(client)


async def receive_json(client: ClientConnection) -> dict[str, str]:
    raw_message = await asyncio.wait_for(client.recv(), RECEIVE_TIMEOUT_SECONDS)
    parsed: dict[str, str] = json.loads(raw_message)
    return parsed


async def test_client_that_stops_answering_pings_is_removed(daphne_url: str) -> None:
    silent, silent_joined = await join_room(daphne_url, DEAD_ROOM_ID)
    assert silent_joined["role"] == "first"
    healthy, healthy_joined = await join_room(daphne_url, DEAD_ROOM_ID)
    assert healthy_joined["role"] == "second"
    assert (await receive_json(silent))["type"] == "peer-joined"

    # Stop reading from the socket, so the server's pings are never answered (like a phone
    # that left the network without a close frame).
    silent.transport.pause_reading()

    assert (await receive_json(healthy))["type"] == "peer-left"

    newcomer, newcomer_joined = await join_room(daphne_url, DEAD_ROOM_ID)
    assert newcomer_joined["role"] == "second"  # not "room-full"
    silent.transport.abort()
    await healthy.close()
    await newcomer.close()


async def test_idle_client_that_answers_pings_is_not_removed(daphne_url: str) -> None:
    idle, idle_joined = await join_room(daphne_url, IDLE_ROOM_ID)
    assert idle_joined["role"] == "first"

    # Idle for well beyond interval + timeout; the client library answers pings by itself.
    await asyncio.sleep(2 * (PING_INTERVAL_SECONDS + PING_TIMEOUT_SECONDS))

    other, other_joined = await join_room(daphne_url, IDLE_ROOM_ID)
    assert other_joined["role"] == "second"  # the idle member is still in the room
    assert (await receive_json(idle))["type"] == "peer-joined"
    await idle.close()
    await other.close()
