import base64
import json
import logging

import pytest
from channels.testing import WebsocketCommunicator
from django.test import override_settings
from pydantic import ValidationError

from config.asgi import application
from signaling.protocol import JoinedMessage, ServerMessage, TurnCredentials
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
