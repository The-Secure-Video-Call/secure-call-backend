import json

from channels.testing import WebsocketCommunicator
from django.conf import settings

from config.asgi import application
from signaling.consumers import (
    CLOSE_MESSAGE_TOO_BIG,
    CLOSE_POLICY_VIOLATION,
    CLOSE_UNSUPPORTED_DATA,
)

PATH = "/ws/signal/"
ALLOWED_ORIGIN = b"http://localhost:5173"


def communicator(origin: bytes | None = ALLOWED_ORIGIN, path: str = PATH) -> WebsocketCommunicator:
    headers = [(b"origin", origin)] if origin is not None else []
    return WebsocketCommunicator(application, path, headers=headers)


async def test_ping_gets_pong() -> None:
    ws = communicator()
    connected, _ = await ws.connect()
    assert connected

    await ws.send_to(text_data='{"v":1,"type":"ping"}')
    assert json.loads(await ws.receive_from()) == {"v": 1, "type": "pong"}
    await ws.disconnect()


async def test_unknown_type_closes_connection() -> None:
    ws = communicator()
    await ws.connect()

    await ws.send_to(text_data='{"v":1,"type":"teleport"}')
    assert await ws.receive_output() == {"type": "websocket.close", "code": CLOSE_POLICY_VIOLATION}


async def test_join_without_room_id_closes_connection() -> None:
    ws = communicator()
    await ws.connect()

    await ws.send_to(text_data='{"v":1,"type":"join"}')
    assert await ws.receive_output() == {"type": "websocket.close", "code": CLOSE_POLICY_VIOLATION}


async def test_room_messages_not_yet_supported_without_closing() -> None:
    ws = communicator()
    await ws.connect()

    await ws.send_to(text_data='{"v":1,"type":"join","roomId":"' + "A" * 22 + '"}')
    assert json.loads(await ws.receive_from()) == {
        "v": 1,
        "type": "error",
        "code": "unsupported-type",
    }
    await ws.send_to(text_data='{"v":1,"type":"ping"}')
    assert json.loads(await ws.receive_from())["type"] == "pong"
    await ws.disconnect()


async def test_origin_not_allowed_is_rejected() -> None:
    ws = communicator(origin=b"https://evil.example")
    connected, _ = await ws.connect()
    assert not connected


async def test_missing_origin_is_rejected() -> None:
    ws = communicator(origin=None)
    connected, _ = await ws.connect()
    assert not connected


async def test_malformed_json_closes_connection() -> None:
    ws = communicator()
    await ws.connect()

    await ws.send_to(text_data="{not json")
    assert await ws.receive_output() == {"type": "websocket.close", "code": CLOSE_POLICY_VIOLATION}


async def test_invalid_envelope_closes_connection() -> None:
    ws = communicator()
    await ws.connect()

    await ws.send_to(text_data='{"v":1,"type":"ping","extra":"field"}')
    assert await ws.receive_output() == {"type": "websocket.close", "code": CLOSE_POLICY_VIOLATION}


async def test_binary_frame_closes_connection() -> None:
    ws = communicator()
    await ws.connect()

    await ws.send_to(bytes_data=b"\x00\x01")
    assert await ws.receive_output() == {"type": "websocket.close", "code": CLOSE_UNSUPPORTED_DATA}


async def test_oversized_message_closes_connection() -> None:
    ws = communicator()
    await ws.connect()

    padding = "a" * settings.SIGNALING_MAX_MESSAGE_BYTES
    await ws.send_to(text_data=json.dumps({"v": 1, "type": "ping", "pad": padding}))
    assert await ws.receive_output() == {"type": "websocket.close", "code": CLOSE_MESSAGE_TOO_BIG}
