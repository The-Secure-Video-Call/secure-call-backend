"""Every client and server message type against its valid and invalid fixtures.

Fixtures live in protocol/fixtures/{client,server}/{valid,invalid}/. Invalid files are named
`<type>--<reason>.json`. The web client's zod schemas run against the same files.
"""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from signaling.protocol import (
    MAX_PAYLOAD_CHARS,
    ClientMessage,
    ServerMessage,
    SignalMessage,
)

FIXTURES = Path(__file__).resolve().parent.parent / "protocol" / "fixtures"
MODELS: dict[str, type[ClientMessage] | type[ServerMessage]] = {
    "client": ClientMessage,
    "server": ServerMessage,
}
CASES = [
    (direction, kind, path)
    for direction in MODELS
    for kind in ("valid", "invalid")
    for path in sorted((FIXTURES / direction / kind).glob("*.json"))
]
CLIENT_TYPES = ["join", "signal", "leave", "ping"]
SERVER_TYPES = ["joined", "peer-joined", "peer-left", "signal", "error", "pong"]


def case_id(case: tuple[str, str, Path]) -> str:
    return f"{case[0]}/{case[1]}/{case[2].stem}"


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_fixture(case: tuple[str, str, Path]) -> None:
    direction, kind, path = case
    text = path.read_text(encoding="utf-8")
    if kind == "valid":
        parsed = MODELS[direction].model_validate_json(text)
        assert parsed.root.type == json.loads(text)["type"]
    else:
        with pytest.raises(ValidationError):
            MODELS[direction].model_validate_json(text)


@pytest.mark.parametrize(
    ("direction", "types"), [("client", CLIENT_TYPES), ("server", SERVER_TYPES)]
)
def test_every_type_has_valid_and_two_invalid_fixtures(direction: str, types: list[str]) -> None:
    for message_type in types:
        valid = list((FIXTURES / direction / "valid").glob(f"{message_type}*.json"))
        invalid = list((FIXTURES / direction / "invalid").glob(f"{message_type}--*.json"))
        assert valid, f"{direction} {message_type}: no valid fixture"
        assert len(invalid) >= 2, f"{direction} {message_type}: needs two invalid fixtures"


def test_oversized_payload_is_rejected_in_both_directions() -> None:
    # Too large for a fixture file (64 KiB), so it is built here. Clients should do the same.
    payload = "A" * (MAX_PAYLOAD_CHARS + 1)
    text = json.dumps({"v": 1, "type": "signal", "payload": payload, "iv": "A" * 16})
    for model in (ClientMessage, ServerMessage):
        with pytest.raises(ValidationError):
            model.model_validate_json(text)


def test_largest_payload_is_accepted_and_one_more_rejected() -> None:
    SignalMessage(payload="A" * MAX_PAYLOAD_CHARS, iv="A" * 16)
    with pytest.raises(ValidationError):
        SignalMessage(payload="A" * (MAX_PAYLOAD_CHARS + 1), iv="A" * 16)


def test_largest_signal_message_fits_the_size_limit() -> None:
    message = SignalMessage(payload="A" * MAX_PAYLOAD_CHARS, iv="A" * 16)
    assert len(message.model_dump_json().encode()) <= 64 * 1024


@pytest.mark.parametrize(
    "iv", [None, "", "A" * 15, "A" * 17, "AAAAAAAAAAAA!AAA", "AAAAAAAAAAAAAA=="]
)
def test_signal_with_a_bad_iv_is_rejected(iv: str | None) -> None:
    text = json.dumps({"v": 1, "type": "signal", "payload": "AAAA", "iv": iv})
    with pytest.raises(ValidationError):
        ClientMessage.model_validate_json(text)
    with pytest.raises(ValidationError):
        ServerMessage.model_validate_json(text)


def test_signal_without_iv_is_rejected() -> None:
    text = json.dumps({"v": 1, "type": "signal", "payload": "AAAA"})
    with pytest.raises(ValidationError):
        ClientMessage.model_validate_json(text)
    with pytest.raises(ValidationError):
        ServerMessage.model_validate_json(text)
