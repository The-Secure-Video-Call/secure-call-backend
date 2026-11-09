import asyncio
import json
from collections.abc import AsyncIterator

import pytest
from channels.testing import WebsocketCommunicator

from config.asgi import application
from signaling.consumers import CLOSE_MESSAGE_TOO_BIG, CLOSE_POLICY_VIOLATION
from signaling.rooms import RoomRegistry, group_name_for_room, room_registry

PATH = "/ws/signal/"
ROOM_ID = "A" * 22
OTHER_ROOM_ID = "B" * 22
JOINED_FIRST = {"v": 1, "type": "joined", "role": "first"}
JOINED_SECOND = {"v": 1, "type": "joined", "role": "second"}
PEER_JOINED = {"v": 1, "type": "peer-joined"}
PEER_LEFT = {"v": 1, "type": "peer-left"}
BAD_MESSAGE = {"v": 1, "type": "error", "code": "bad-message"}


def join_text(room_id: str = ROOM_ID) -> str:
    return json.dumps({"v": 1, "type": "join", "roomId": room_id})


def signal_text(payload: str) -> str:
    return json.dumps({"v": 1, "type": "signal", "payload": payload})


async def connect_client() -> WebsocketCommunicator:
    client = WebsocketCommunicator(
        application, PATH, headers=[(b"origin", b"http://localhost:5173")]
    )
    connected, _ = await client.connect()
    assert connected
    return client


async def join_client(room_id: str = ROOM_ID) -> WebsocketCommunicator:
    client = await connect_client()
    await client.send_to(text_data=join_text(room_id))
    return client


async def make_full_room() -> tuple[WebsocketCommunicator, WebsocketCommunicator]:
    """Two clients in ROOM_ID with all join-time messages already consumed."""
    first = await join_client()
    assert json.loads(await first.receive_from()) == JOINED_FIRST
    second = await join_client()
    assert json.loads(await second.receive_from()) == JOINED_SECOND
    assert json.loads(await first.receive_from()) == PEER_JOINED
    return first, second


@pytest.fixture(autouse=True)
async def check_no_room_left_behind() -> AsyncIterator[None]:
    yield
    await asyncio.sleep(0.05)  # let disconnect handlers finish
    assert room_registry.room_count() == 0


async def test_roles_and_peer_joined() -> None:
    first, second = await make_full_room()
    assert await second.receive_nothing()
    await first.disconnect()
    await second.disconnect()


async def test_signal_is_relayed_unchanged_both_ways_and_never_echoed() -> None:
    first, second = await make_full_room()

    from_first = signal_text("SGVsbG8gd29ybGQ=")
    await first.send_to(text_data=from_first)
    assert await second.receive_from() == from_first
    assert await first.receive_nothing()

    from_second = json.dumps({"v": 1, "type": "signal", "payload": "AAAA", "iv": "A" * 16})
    await second.send_to(text_data=from_second)
    assert await first.receive_from() == from_second
    assert await second.receive_nothing()
    await first.disconnect()
    await second.disconnect()


async def test_third_client_gets_room_full_and_is_closed() -> None:
    first, second = await make_full_room()
    third = await join_client()
    assert json.loads(await third.receive_from()) == {"v": 1, "type": "error", "code": "room-full"}
    assert (await third.receive_output())["type"] == "websocket.close"
    await third.disconnect()
    # The full room is unaffected: nobody gets peer-left or peer-joined.
    assert await first.receive_nothing()
    assert await second.receive_nothing()
    await first.disconnect()
    await second.disconnect()


async def test_rooms_do_not_leak_messages_to_each_other() -> None:
    first_a = await join_client(ROOM_ID)
    first_b = await join_client(OTHER_ROOM_ID)
    second_a = await join_client(ROOM_ID)
    second_b = await join_client(OTHER_ROOM_ID)
    for client in (first_a, first_b, second_a, second_b):
        await client.receive_from()  # joined
    await first_a.receive_from()  # peer-joined
    await first_b.receive_from()  # peer-joined

    message = signal_text("QUFB")
    await first_a.send_to(text_data=message)
    assert await second_a.receive_from() == message
    assert await first_b.receive_nothing()
    assert await second_b.receive_nothing()
    for client in (first_a, first_b, second_a, second_b):
        await client.disconnect()


async def test_disconnect_sends_peer_left_and_room_can_be_reused() -> None:
    first, second = await make_full_room()

    await second.disconnect()
    assert json.loads(await first.receive_from()) == PEER_LEFT
    third = await join_client()
    assert json.loads(await third.receive_from()) == JOINED_SECOND
    await first.disconnect()
    await third.disconnect()


async def test_leave_sends_peer_left_and_stops_relaying() -> None:
    first, second = await make_full_room()

    await second.send_to(text_data='{"v":1,"type":"leave"}')
    assert json.loads(await first.receive_from()) == PEER_LEFT
    assert await second.receive_nothing()
    await second.send_to(text_data=signal_text("QUFB"))
    assert json.loads(await second.receive_from()) == BAD_MESSAGE
    assert await first.receive_nothing()
    await first.disconnect()
    await second.disconnect()


async def test_signal_before_join_is_bad_message() -> None:
    client = await connect_client()
    await client.send_to(text_data=signal_text("QUFB"))
    assert json.loads(await client.receive_from()) == BAD_MESSAGE
    await client.disconnect()


async def test_leave_before_join_is_bad_message() -> None:
    client = await connect_client()
    await client.send_to(text_data='{"v":1,"type":"leave"}')
    assert json.loads(await client.receive_from()) == BAD_MESSAGE
    await client.disconnect()


async def test_second_join_is_bad_message_and_keeps_first_room() -> None:
    client = await join_client()
    await client.receive_from()
    await client.send_to(text_data=join_text(OTHER_ROOM_ID))
    assert json.loads(await client.receive_from()) == BAD_MESSAGE
    # The other room was not entered: a new client there is the first member.
    other = await join_client(OTHER_ROOM_ID)
    assert json.loads(await other.receive_from()) == JOINED_FIRST
    await client.disconnect()
    await other.disconnect()


async def test_malformed_signal_in_room_closes_connection() -> None:
    client = await join_client()
    await client.receive_from()
    await client.send_to(text_data='{"v":1,"type":"signal","payload":"not base64!"}')
    assert await client.receive_output() == {
        "type": "websocket.close",
        "code": CLOSE_POLICY_VIOLATION,
    }
    await client.disconnect()


async def test_oversized_signal_closes_connection_and_is_not_relayed() -> None:
    first, second = await make_full_room()

    await first.send_to(text_data=signal_text("A" * (64 * 1024)))
    assert await first.receive_output() == {
        "type": "websocket.close",
        "code": CLOSE_MESSAGE_TOO_BIG,
    }
    await first.disconnect()
    assert json.loads(await second.receive_from()) == PEER_LEFT
    await second.disconnect()


async def test_registry_never_exceeds_two_members_under_concurrency() -> None:
    registry = RoomRegistry()
    roles = await asyncio.gather(*(registry.add_member(ROOM_ID, f"channel-{n}") for n in range(10)))
    assert sorted(role for role in roles if role is not None) == ["first", "second"]
    for n in range(10):
        await registry.remove_member(ROOM_ID, f"channel-{n}")
    assert registry.room_count() == 0


def test_group_name_does_not_contain_room_id() -> None:
    assert ROOM_ID not in group_name_for_room(ROOM_ID)
