"""WebSocket consumer for signaling.

Validates every message against the `ClientMessage` union (unknown types close the
connection) and answers `ping`. Room logic (join/signal/leave) arrives in the next M1 issue;
until then those messages are answered with `unsupported-type`.
Security rules that already apply (PLAN.md 3.5):
- the Origin was checked before this consumer runs (see config/asgi.py);
- binary frames and messages over SIGNALING_MAX_MESSAGE_BYTES close the connection;
- malformed messages close the connection;
- message contents are never logged.
"""

from channels.generic.websocket import AsyncWebsocketConsumer
from django.conf import settings
from pydantic import BaseModel, ValidationError

from signaling.protocol import ClientMessage, ErrorMessage, PingMessage, PongMessage

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
            message = ClientMessage.model_validate_json(text_data).root
        except ValidationError:
            await self.close(code=CLOSE_POLICY_VIOLATION)
            return

        if isinstance(message, PingMessage):
            await self.send_message(PongMessage())
        else:
            await self.send_message(ErrorMessage(code="unsupported-type"))

    async def send_message(self, message: BaseModel) -> None:
        await self.send(text_data=message.model_dump_json())
