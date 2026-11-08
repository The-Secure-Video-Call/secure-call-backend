"""WebSocket consumer for signaling.

M0 placeholder: validates every message against the protocol envelope and answers `ping`.
Rooms and message relaying arrive in M1. Security rules that already apply (PLAN.md 3.5):
- the Origin was checked before this consumer runs (see config/asgi.py);
- binary frames and messages over SIGNALING_MAX_MESSAGE_BYTES close the connection;
- malformed messages close the connection;
- message contents are never logged.
"""

from channels.generic.websocket import AsyncWebsocketConsumer
from django.conf import settings
from pydantic import BaseModel, ValidationError

from signaling.protocol import PROTOCOL_VERSION, Envelope, ErrorMessage

# WebSocket close codes (RFC 6455, section 7.4.1).
CLOSE_UNSUPPORTED_DATA = 1003
CLOSE_POLICY_VIOLATION = 1008
CLOSE_MESSAGE_TOO_BIG = 1009


class SignalingConsumer(AsyncWebsocketConsumer):
    async def connect(self) -> None:
        await self.accept()

    async def receive(self, text_data: str | None = None, bytes_data: bytes | None = None) -> None:
        if text_data is None:
            await self.close(code=CLOSE_UNSUPPORTED_DATA)
            return
        if len(text_data.encode("utf-8")) > settings.SIGNALING_MAX_MESSAGE_BYTES:
            await self.close(code=CLOSE_MESSAGE_TOO_BIG)
            return
        try:
            message = Envelope.model_validate_json(text_data)
        except ValidationError:
            await self.close(code=CLOSE_POLICY_VIOLATION)
            return

        if message.type == "ping":
            await self.send_message(Envelope(v=PROTOCOL_VERSION, type="pong"))
        else:
            await self.send_message(ErrorMessage(code="unsupported-type"))

    async def send_message(self, message: BaseModel) -> None:
        await self.send(text_data=message.model_dump_json())
