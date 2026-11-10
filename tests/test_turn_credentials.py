import base64
import json
import logging
from types import SimpleNamespace

import pytest
from channels.testing import WebsocketCommunicator
from django.test import override_settings
from pydantic import ValidationError

from config.asgi import application
from signaling.consumers import SignalingConsumer
from signaling.protocol import JoinedMessage, ServerMessage, TurnCredentials
from signaling.rooms import TOTAL_LIFETIME_LIMIT_SECONDS, RoomRegistry, room_registry
from signaling.turn_credentials import (
    issue_turn_credentials,
    make_turn_credential,
    make_turn_username,
)

SHARED_SECRET = "test-shared-secret-do-not-leak"  # noqa: S105 - test value, not a real secret
TURN_URLS = ["turn:turn.example.com:3478?transport=udp", "turns:turn.example.com:5349"]
ALLOWED_ORIGIN = b"http://localhost:5173"
ROOM_ID = "A" * 22


def test_credential_matches_rfc_2202_hmac_sha1_test_vector() -> None:
    # RFC 2202 test case 2, published independently of this code: key "Jefe".
    credential = make_turn_credential("Jefe", "what do ya want for nothing?")

    expected_hex = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
    assert base64.b64decode(credential).hex() == expected_hex


def test_credential_matches_known_answer_in_coturn_format() -> None:
    # Computed outside this code (OpenSSL 3.6), cross-checked with Python hmac + hashlib:
    #   printf '%s' "$username" | openssl dgst -sha1 -hmac "$secret" -binary | openssl base64
    # with secret = SHARED_SECRET and username = "1700003600:AAECAwQFBgcICQoLDA0ODw".
    username = make_turn_username(1_700_003_600, bytes(range(16)))
    assert username == "1700003600:AAECAwQFBgcICQoLDA0ODw"

    assert make_turn_credential(SHARED_SECRET, username) == "zqLrZg/hlbZwDap9GTW4GMooDRI="


def test_username_is_expiry_then_base64url_of_16_random_bytes() -> None:
    username = make_turn_username(1_700_003_600, bytes(range(16)))

    assert username == "1700003600:AAECAwQFBgcICQoLDA0ODw"


def test_expiry_is_now_plus_ttl_using_a_fake_clock() -> None:
    credentials = issue_turn_credentials(SHARED_SECRET, TURN_URLS, 3600, now_unix_time=1_000_000)

    assert credentials.username.split(":")[0] == "1003600"
    assert credentials.credential == make_turn_credential(SHARED_SECRET, credentials.username)


def test_two_issues_get_different_usernames() -> None:
    first = issue_turn_credentials(SHARED_SECRET, TURN_URLS, 3600, now_unix_time=1_000_000)
    second = issue_turn_credentials(SHARED_SECRET, TURN_URLS, 3600, now_unix_time=1_000_000)

    assert first.username != second.username
    assert first.credential != second.credential


@pytest.mark.parametrize(
    "bad_urls",
    [["http://turn.example.com"], [], ["turn:a"] * 5, ["stun:turn.example.com"], ["turn:"]],
)
def test_schema_rejects_bad_urls(bad_urls: list[str]) -> None:
    with pytest.raises(ValidationError):
        TurnCredentials(urls=bad_urls, username="1:a", credential="abc=")


def test_schema_rejects_extra_field_and_overlong_values() -> None:
    base = {"urls": TURN_URLS, "username": "1:a", "credential": "abc="}
    with pytest.raises(ValidationError):
        TurnCredentials.model_validate({**base, "ttl": 1})
    with pytest.raises(ValidationError):
        TurnCredentials.model_validate({**base, "username": "x" * 129})
    with pytest.raises(ValidationError):
        TurnCredentials.model_validate({**base, "credential": ""})


def test_joined_without_turn_serializes_without_the_field() -> None:
    assert json.loads(JoinedMessage(role="first").model_dump_json(exclude_none=True)) == {
        "v": 1,
        "type": "joined",
        "role": "first",
    }


async def join_and_read_joined(room_id: str = ROOM_ID) -> tuple[str, dict[str, object]]:
    ws = WebsocketCommunicator(application, "/ws/signal/", headers=[(b"origin", ALLOWED_ORIGIN)])
    await ws.connect()
    await ws.send_to(text_data=json.dumps({"v": 1, "type": "join", "roomId": room_id}))
    text = await ws.receive_from()
    await ws.disconnect()
    return text, json.loads(text)


@override_settings(TURN_SHARED_SECRET=SHARED_SECRET, TURN_URLS=TURN_URLS)
async def test_joined_has_turn_when_both_settings_are_set(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG):
        text, joined = await join_and_read_joined("B" * 22)

    ServerMessage.model_validate_json(text)
    turn = joined["turn"]
    assert isinstance(turn, dict)
    assert turn["urls"] == TURN_URLS
    assert SHARED_SECRET not in text
    assert SHARED_SECRET not in caplog.text
    assert turn["credential"] not in caplog.text


@override_settings(TURN_SHARED_SECRET=SHARED_SECRET, TURN_URLS=TURN_URLS)
async def test_two_connections_get_different_usernames() -> None:
    _, first = await join_and_read_joined("C" * 22)
    _, second = await join_and_read_joined("D" * 22)

    assert isinstance(first["turn"], dict)
    assert isinstance(second["turn"], dict)
    assert first["turn"]["username"] != second["turn"]["username"]


@override_settings(TURN_SHARED_SECRET="", TURN_URLS=TURN_URLS)
async def test_joined_has_no_turn_without_secret() -> None:
    _, joined = await join_and_read_joined("E" * 22)

    assert joined == {"v": 1, "type": "joined", "role": "first"}


@override_settings(TURN_SHARED_SECRET=SHARED_SECRET, TURN_URLS=[])
async def test_joined_has_no_turn_without_urls() -> None:
    text, joined = await join_and_read_joined("F" * 22)

    assert "turn" not in joined
    assert SHARED_SECRET not in text


def use_fake_clocks(
    monkeypatch: pytest.MonkeyPatch, wall_start: int
) -> tuple[list[int], list[float]]:
    """Separate fake clocks: wall time where credentials are issued, monotonic in the registry.

    Only these two are replaced (not asyncio or Channels), so a test can step the wall clock
    (as NTP does after a Pi boots) while monotonic time keeps flowing.
    """
    wall = [wall_start]
    monotonic = [0.0]
    monkeypatch.setattr("signaling.consumers.time", SimpleNamespace(time=lambda: float(wall[0])))
    monkeypatch.setattr(room_registry, "_monotonic_clock", lambda: monotonic[0])
    return wall, monotonic


def expiry_of(joined: dict[str, object]) -> int:
    turn = joined["turn"]
    assert isinstance(turn, dict)
    assert turn["credential"] == make_turn_credential(SHARED_SECRET, str(turn["username"]))
    return int(str(turn["username"]).split(":")[0])


async def open_and_join(room_id: str) -> tuple[WebsocketCommunicator, dict[str, object]]:
    ws = WebsocketCommunicator(application, "/ws/signal/", headers=[(b"origin", ALLOWED_ORIGIN)])
    await ws.connect()
    await ws.send_to(text_data=json.dumps({"v": 1, "type": "join", "roomId": room_id}))
    return ws, json.loads(await ws.receive_from())


async def join_late(
    room_id: str, monotonic: list[float], seconds_after_room_start: float
) -> tuple[dict[str, object], dict[str, object]]:
    """First person joins at monotonic 0, the second `seconds_after_room_start` later."""
    first_ws, first = await open_and_join(room_id)
    monotonic[0] = seconds_after_room_start
    second_ws, second = await open_and_join(room_id)
    await first_ws.disconnect()
    await second_ws.disconnect()
    return first, second


@override_settings(TURN_SHARED_SECRET=SHARED_SECRET, TURN_URLS=TURN_URLS)
async def test_late_joiner_credential_ends_when_the_room_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, monotonic = use_fake_clocks(monkeypatch, 1_000_000)
    first, second = await join_late("G" * 22, monotonic, 10_000)

    assert expiry_of(first) == 1_000_000 + TOTAL_LIFETIME_LIMIT_SECONDS
    # The room has 4400 s left: never now + 4 h, which would outlive the room by 10 000 s.
    assert expiry_of(second) == 1_000_000 + TOTAL_LIFETIME_LIMIT_SECONDS - 10_000


@override_settings(TURN_SHARED_SECRET=SHARED_SECRET, TURN_URLS=TURN_URLS)
async def test_a_wall_clock_step_does_not_change_the_lifetime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wall, monotonic = use_fake_clocks(monkeypatch, 1_000_000)
    first_ws, _ = await open_and_join("J" * 22)
    wall[0] -= 3 * 60 * 60  # NTP steps a fast clock back 3 h ...
    monotonic[0] = 10_000  # ... while real time moves on 10 000 s
    second_ws, second = await open_and_join("J" * 22)
    await first_ws.disconnect()
    await second_ws.disconnect()

    # Lifetime = the 4400 s the room really has left, from the (corrected) wall clock now.
    assert expiry_of(second) == wall[0] + TOTAL_LIFETIME_LIMIT_SECONDS - 10_000


@override_settings(TURN_SHARED_SECRET=SHARED_SECRET, TURN_URLS=TURN_URLS)
async def test_a_join_in_the_last_second_gets_one_second(monkeypatch: pytest.MonkeyPatch) -> None:
    wall, monotonic = use_fake_clocks(monkeypatch, 1_000_000)
    _, second = await join_late("K" * 22, monotonic, TOTAL_LIFETIME_LIMIT_SECONDS - 1)

    assert expiry_of(second) == wall[0] + 1


@override_settings(TURN_SHARED_SECRET=SHARED_SECRET, TURN_URLS=TURN_URLS)
async def test_no_credential_once_the_room_has_no_time_left(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    room_id = "L" * 22
    _, monotonic = use_fake_clocks(monkeypatch, 1_000_000)
    with caplog.at_level(logging.WARNING):
        _, second = await join_late(room_id, monotonic, TOTAL_LIFETIME_LIMIT_SECONDS)

    assert "turn" not in second
    assert "TURN credential not issued" in caplog.text
    assert room_id not in caplog.text


@override_settings(
    TURN_SHARED_SECRET=SHARED_SECRET, TURN_URLS=TURN_URLS, TURN_CREDENTIAL_TTL_SECONDS=3600
)
async def test_a_shorter_configured_ttl_still_applies(monkeypatch: pytest.MonkeyPatch) -> None:
    wall, _ = use_fake_clocks(monkeypatch, 2_000_000)
    ws, joined = await open_and_join("M" * 22)
    await ws.disconnect()

    assert expiry_of(joined) == wall[0] + 3600


@override_settings(TURN_SHARED_SECRET=SHARED_SECRET, TURN_URLS=TURN_URLS)
def test_no_credential_for_a_room_that_is_gone() -> None:
    assert SignalingConsumer().issue_turn_credentials(None) is None


async def test_remaining_lifetime_uses_the_monotonic_clock() -> None:
    monotonic = [500.0]

    async def ignore_expiry(room_id: str, channel_names: list[str]) -> None:
        return None

    registry = RoomRegistry(notify_room_expired=ignore_expiry, monotonic_clock=lambda: monotonic[0])
    await registry.add_member("N" * 22, "channel-a")
    monotonic[0] = 1_500.0

    assert registry.remaining_lifetime_seconds("N" * 22) == TOTAL_LIFETIME_LIMIT_SECONDS - 1_000
    assert registry.remaining_lifetime_seconds("O" * 22) is None
    await registry.remove_member("N" * 22, "channel-a")


@override_settings(TURN_SHARED_SECRET=SHARED_SECRET, TURN_URLS=TURN_URLS)
async def test_room_over_its_credential_budget_still_joins_without_a_relay(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr("signaling.rooms.MAX_TURN_CREDENTIALS_PER_ROOM", 3)
    room_id = "P" * 22
    other_room_id = "Q" * 22
    holder_ws, holder = await open_and_join(room_id)  # keeps the room alive; credential 1
    assert "turn" in holder
    with caplog.at_level(logging.DEBUG):
        # Reconnects of the second person: credentials 2 and 3, then the budget is used up.
        for _ in range(2):
            reconnecting_ws, reconnected = await open_and_join(room_id)
            assert "turn" in reconnected
            await reconnecting_ws.disconnect()
        over_budget_ws, over_budget = await open_and_join(room_id)
        other_room_ws, other_room = await open_and_join(other_room_id)

    # The join works (a role, not an error); only the relay is missing.
    assert over_budget == {"v": 1, "type": "joined", "role": "second"}
    assert "turn" in other_room  # the budget is per room
    assert room_id not in caplog.text
    assert "127.0.0.1" not in caplog.text
    for client in (holder_ws, over_budget_ws, other_room_ws):
        await client.disconnect()

    # Everyone left, so the room is gone; the same ID is a new room with a new budget.
    recreated_ws, recreated = await open_and_join(room_id)
    await recreated_ws.disconnect()
    assert "turn" in recreated
