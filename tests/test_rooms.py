import asyncio
import json
from collections.abc import AsyncIterator

import pytest
from channels.layers import get_channel_layer
from channels.testing import WebsocketCommunicator

from config.asgi import application
from signaling import consumers
from signaling.consumers import CLOSE_MESSAGE_TOO_BIG, CLOSE_POLICY_VIOLATION
from signaling.rooms import (
    TOTAL_LIFETIME_LIMIT_SECONDS,
    WAITING_ALONE_LIMIT_SECONDS,
    RoomRegistry,
    group_name_for_room,
    room_registry,
)

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


def signal_text(payload: str, iv: str | None = "A" * 16) -> str:
    return json.dumps({"v": 1, "type": "signal", "payload": payload, "iv": iv})


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


@pytest.mark.parametrize(
    "bad_text",
    [
        '{"v":1,"type":"signal","payload":"QUFB"}',
        signal_text("QUFB", iv=None),
        signal_text("QUFB", iv="A" * 15),
        signal_text("QUFB", iv="A" * 17),
        signal_text("QUFB", iv="AAAAAAAAAAAA!AAA"),
    ],
    ids=["missing-iv", "iv-null", "iv-too-short", "iv-too-long", "iv-not-base64"],
)
async def test_signal_with_missing_or_bad_iv_is_closed_and_not_relayed(bad_text: str) -> None:
    first, second = await make_full_room()

    await first.send_to(text_data=bad_text)
    assert (await first.receive_output()) == {
        "type": "websocket.close",
        "code": CLOSE_POLICY_VIOLATION,
    }
    await first.disconnect()
    # The only thing the other member sees is the peer leaving, never the signal.
    assert json.loads(await second.receive_from()) == PEER_LEFT
    assert await second.receive_nothing()
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


# --- Room expiry (short durations; no real 10-minute sleeps) ---------------------------------

ROOM_EXPIRED = {"v": 1, "type": "error", "code": "room-expired"}
LONG_SECONDS = 60.0


def use_short_registry(
    monkeypatch: pytest.MonkeyPatch, waiting_alone_limit: float, total_lifetime_limit: float
) -> RoomRegistry:
    short_registry = RoomRegistry(waiting_alone_limit, total_lifetime_limit)
    monkeypatch.setattr(consumers, "room_registry", short_registry)
    return short_registry


async def assert_told_room_expired_and_closed(client: WebsocketCommunicator) -> None:
    assert json.loads(await client.receive_from()) == ROOM_EXPIRED
    closing = await client.receive_output()
    assert closing["type"] == "websocket.close"
    assert closing.get("code", 1000) == 1000  # normal close


def test_production_limits_are_ten_minutes_and_four_hours() -> None:
    assert WAITING_ALONE_LIMIT_SECONDS == 600
    assert TOTAL_LIFETIME_LIMIT_SECONDS == 14_400


async def test_person_waiting_alone_gets_room_expired_and_is_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = use_short_registry(monkeypatch, 0.2, LONG_SECONDS)
    client = await join_client()
    assert json.loads(await client.receive_from()) == JOINED_FIRST
    await assert_told_room_expired_and_closed(client)
    assert registry.room_count() == 0
    await client.disconnect()


async def test_second_person_joining_stops_the_waiting_timer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = use_short_registry(monkeypatch, 0.3, LONG_SECONDS)
    first, second = await make_full_room()
    await asyncio.sleep(0.6)  # twice the waiting limit
    assert await first.receive_nothing()
    assert await second.receive_nothing()
    assert registry.room_count() == 1
    await first.send_to(text_data=signal_text("QUFB"))  # the call carries on
    assert json.loads(await second.receive_from())["type"] == "signal"
    await first.disconnect()
    await second.disconnect()


async def test_waiting_timer_restarts_for_the_person_who_stayed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = use_short_registry(monkeypatch, 0.3, LONG_SECONDS)
    first, second = await make_full_room()
    await asyncio.sleep(0.5)  # longer than the limit, but the room has two people
    await second.disconnect()
    assert json.loads(await first.receive_from()) == PEER_LEFT
    await assert_told_room_expired_and_closed(first)
    assert registry.room_count() == 0
    await first.disconnect()


async def test_total_limit_closes_both_members_during_a_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = use_short_registry(monkeypatch, LONG_SECONDS, 0.3)
    first, second = await make_full_room()
    await assert_told_room_expired_and_closed(first)
    await assert_told_room_expired_and_closed(second)
    assert registry.room_count() == 0
    await first.disconnect()
    await second.disconnect()


async def test_timers_are_cancelled_when_room_empties() -> None:
    tasks_before = asyncio.all_tasks()
    registry = RoomRegistry(LONG_SECONDS, LONG_SECONDS)
    await registry.add_member(ROOM_ID, "channel-1")
    await registry.add_member(ROOM_ID, "channel-2")
    await registry.remove_member(ROOM_ID, "channel-1")
    await registry.remove_member(ROOM_ID, "channel-2")
    await asyncio.sleep(0.05)  # let cancelled tasks finish
    assert registry.room_count() == 0
    assert asyncio.all_tasks() == tasks_before


async def test_expired_room_keeps_no_members_and_closed_connections_reach_nobody(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = use_short_registry(monkeypatch, LONG_SECONDS, 0.5)
    old_first, old_second = await make_full_room()
    await assert_told_room_expired_and_closed(old_first)
    await assert_told_room_expired_and_closed(old_second)
    assert registry.room_count() == 0

    newcomer = await join_client()
    assert json.loads(await newcomer.receive_from()) == JOINED_FIRST  # fresh room
    # Leftover traffic and disconnects from the expired connections must not reach the newcomer.
    await old_first.send_to(text_data=signal_text("QUFB"))
    await old_first.send_to(text_data='{"v":1,"type":"leave"}')
    await old_first.disconnect()
    await old_second.disconnect()
    assert await newcomer.receive_nothing()
    assert registry.room_count() == 1
    await newcomer.disconnect()


async def test_same_room_id_after_expiry_creates_a_fresh_room(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = use_short_registry(monkeypatch, 0.2, LONG_SECONDS)
    expired = await join_client()
    await expired.receive_from()  # joined
    await assert_told_room_expired_and_closed(expired)
    rejoined = await join_client()
    assert json.loads(await rejoined.receive_from()) == JOINED_FIRST
    assert registry.room_count() == 1
    await expired.disconnect()
    await rejoined.disconnect()


async def do_nothing_when_room_expires(room_id: str, channel_names: list[str]) -> None:
    """Simulates a lost expiry notification: the old connection is still open and in the group."""


async def test_signal_from_connection_of_expired_room_is_not_relayed_to_new_room(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = RoomRegistry(0.2, LONG_SECONDS, do_nothing_when_room_expires)
    monkeypatch.setattr(consumers, "room_registry", registry)
    stale = await join_client()
    assert json.loads(await stale.receive_from()) == JOINED_FIRST
    await asyncio.sleep(0.4)  # the registry has expired the room; the connection never heard
    assert registry.room_count() == 0

    newcomer = await join_client()
    assert json.loads(await newcomer.receive_from()) == JOINED_FIRST
    await stale.send_to(text_data=signal_text("QUFB"))
    assert await newcomer.receive_nothing()
    await stale.disconnect()
    await newcomer.disconnect()


async def test_stale_room_expired_event_after_leave_and_rejoin_is_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = use_short_registry(monkeypatch, LONG_SECONDS, LONG_SECONDS)
    first = await join_client()
    assert json.loads(await first.receive_from()) == JOINED_FIRST
    channel_name = registry._rooms_by_room_id[ROOM_ID].channel_names[0]
    await first.send_to(text_data='{"v":1,"type":"leave"}')
    await first.send_to(text_data=join_text())
    assert json.loads(await first.receive_from()) == JOINED_FIRST
    # An expiry event for the previous incarnation of this room arrives late.
    channel_layer = get_channel_layer()
    assert channel_layer is not None
    await channel_layer.send(
        channel_name, {"type": "room_expired", "group_name": group_name_for_room(ROOM_ID)}
    )
    assert await first.receive_nothing()
    assert registry.room_count() == 1
    await first.disconnect()


async def test_turn_credential_budget_is_per_room_and_starts_again_when_recreated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("signaling.rooms.MAX_TURN_CREDENTIALS_PER_ROOM", 2)
    registry = RoomRegistry()
    await registry.add_member(ROOM_ID, "channel-a")
    await registry.add_member(OTHER_ROOM_ID, "channel-b")

    assert registry.try_take_turn_credential_slot(ROOM_ID)
    assert registry.try_take_turn_credential_slot(ROOM_ID)
    assert not registry.try_take_turn_credential_slot(ROOM_ID)  # used up
    assert not registry.try_take_turn_credential_slot(ROOM_ID)  # and it stays used up
    assert registry.try_take_turn_credential_slot(OTHER_ROOM_ID)  # another room is unaffected

    await registry.remove_member(ROOM_ID, "channel-a")  # the room empties and is deleted
    await registry.add_member(ROOM_ID, "channel-c")  # same ID, a new room
    assert registry.try_take_turn_credential_slot(ROOM_ID)

    await registry.remove_member(ROOM_ID, "channel-c")
    await registry.remove_member(OTHER_ROOM_ID, "channel-b")


async def test_turn_credential_slot_is_refused_for_a_room_that_does_not_exist() -> None:
    assert not RoomRegistry().try_take_turn_credential_slot(ROOM_ID)
