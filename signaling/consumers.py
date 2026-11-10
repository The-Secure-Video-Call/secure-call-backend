"""WebSocket consumer for signaling.

Validates every message against the `ClientMessage` union (unknown types close the
connection), answers `ping` and runs rooms: `join`, `signal` and `leave`.
Security rules (PLAN.md 3.5):
- the Origin was checked before this consumer runs (see config/asgi.py);
- binary frames and messages over SIGNALING_MAX_MESSAGE_BYTES close the connection;
- malformed messages close the connection;
- bad connections are closed with application codes, because Daphne (Autobahn) only lets an
  application send 1000 or 3000-4999 (anything else raises and skips `disconnect`):
  4003 unsupported data (a binary frame), 4008 policy violation (a malformed or invalid message),
  4009 message too big, 4029 rate limited (too many joins or messages; `error rate-limited` is
  sent first; see rate_limits.py). 1000 stays the normal close (`room-full`, `room-expired`);
- a room holds at most two connections and expires (see rooms.py): members get `room-expired`;
- `signal` text is relayed to the other member exactly as received. It is validated like every
  message but never stored or logged; message contents and room IDs are never logged.

Relaying uses one Channels group per room. A group send reaches every member including the
sender, so each relayed event carries the sender's channel name and the sender skips it.
"""

import logging
import math
import time
from typing import Any

from channels.generic.websocket import AsyncWebsocketConsumer
from django.conf import settings
from pydantic import BaseModel, ValidationError

from signaling.protocol import (
    ClientMessage,
    ErrorMessage,
    JoinedMessage,
    JoinMessage,
    LeaveMessage,
    PeerJoinedMessage,
    PeerLeftMessage,
    PingMessage,
    PongMessage,
    SignalMessage,
    TurnCredentials,
)
from signaling.rate_limits import (
    TokenBucket,
    client_key_for_ip,
    new_join_limiter,
    new_message_bucket,
    new_turn_credential_limiter,
)
from signaling.rooms import group_name_for_room, room_registry
from signaling.turn_credentials import issue_turn_credentials

# Application close codes: the standard RFC 6455 meaning (1003, 1008, 1009) in the last digits.
CLOSE_UNSUPPORTED_DATA = 4003
CLOSE_POLICY_VIOLATION = 4008
CLOSE_MESSAGE_TOO_BIG = 4009
CLOSE_RATE_LIMITED = 4029

# Per client IP, in memory only (tests replace these with ones that use a fake clock).
join_limiter = new_join_limiter()
turn_credential_limiter = new_turn_credential_limiter()


logger = logging.getLogger(__name__)


class SignalingConsumer(AsyncWebsocketConsumer):
    room_id: str | None = None
    client_key: bytes
    message_bucket: TokenBucket

    async def connect(self) -> None:
        # Counters are keyed by an HMAC of the client IP (set by ClientAddressMiddleware).
        self.client_key = client_key_for_ip(self.scope.get("client_ip", "unknown"))
        self.message_bucket = new_message_bucket()
        await self.accept()

    async def disconnect(self, code: int) -> None:
        await self.leave_room()

    async def receive(self, text_data: str | None = None, bytes_data: bytes | None = None) -> None:
        if not self.message_bucket.try_take_token():
            await self.send_message(ErrorMessage(code="rate-limited"))
            await self.leave_room_then_close(CLOSE_RATE_LIMITED)
            return
        if text_data is None:
            await self.leave_room_then_close(CLOSE_UNSUPPORTED_DATA)
            return
        if len(text_data.encode("utf-8")) > settings.SIGNALING_MAX_MESSAGE_BYTES:
            await self.leave_room_then_close(CLOSE_MESSAGE_TOO_BIG)
            return
        try:
            message = ClientMessage.model_validate_json(text_data).root
        except ValidationError:
            await self.leave_room_then_close(CLOSE_POLICY_VIOLATION)
            return

        if isinstance(message, PingMessage):
            await self.send_message(PongMessage())
        elif isinstance(message, JoinMessage):
            await self.join_room(message.roomId)
        elif isinstance(message, SignalMessage):
            await self.relay_signal_to_peer(text_data)
        elif isinstance(message, LeaveMessage):
            if self.room_id is None:
                await self.send_message(ErrorMessage(code="bad-message"))
            else:
                await self.leave_room()

    async def join_room(self, room_id: str) -> None:
        if self.room_id is not None:
            await self.send_message(ErrorMessage(code="bad-message"))
            return
        if not join_limiter.try_acquire(self.client_key):
            await self.send_message(ErrorMessage(code="rate-limited"))
            await self.close(code=CLOSE_RATE_LIMITED)
            return
        group_name = group_name_for_room(room_id)
        room_seconds_left: float | None = None

        async def remember_room_and_join_group() -> None:
            nonlocal room_seconds_left
            # Runs under the registry lock. Setting room_id first means disconnect() cleans up
            # even if this task is cancelled halfway.
            self.room_id = room_id
            # Read under the same lock, so it belongs to the room just joined (not to a room that
            # expired and was recreated under the same ID while we awaited something).
            room_seconds_left = room_registry.remaining_lifetime_seconds(room_id)
            await self.channel_layer.group_add(group_name, self.channel_name)

        role = await room_registry.add_member(
            room_id, self.channel_name, remember_room_and_join_group
        )
        if role is None:
            await self.send_message(ErrorMessage(code="room-full"))
            await self.close()
            return
        turn = self.issue_turn_credentials(room_seconds_left)
        await self.send_message(JoinedMessage(role=role, turn=turn))
        if role == "second":
            await self.send_event_to_peer(group_name, "peer_joined", PeerJoinedMessage())

    def issue_turn_credentials(self, room_seconds_left: float | None) -> TurnCredentials | None:
        """New credentials for this connection that never outlive the room's 4-hour limit.

        The lifetime is min(TTL, time the room has left), measured on the monotonic clock; the
        wall clock is only read once, to turn that lifetime into the absolute expiry coturn checks.
        None when TURN is not fully configured, when the room is gone, or in its last second.
        """
        if not settings.TURN_SHARED_SECRET or not settings.TURN_URLS:
            return None
        if room_seconds_left is None:
            return None
        credential_ttl_seconds = min(
            settings.TURN_CREDENTIAL_TTL_SECONDS, math.floor(room_seconds_left)
        )
        if credential_ttl_seconds <= 0:
            # No room ID or address here: only enough to notice the case.
            logger.warning("TURN credential not issued: the room has no time left.")
            return None
        # Charged only when a credential is really issued (after the room-time checks above).
        # The room's own budget first: a room that is used up must not also spend its IP's cap.
        if self.room_id is None or not room_registry.try_take_turn_credential_slot(self.room_id):
            return None  # this room has had its share: the join works, just without a relay
        if not turn_credential_limiter.try_acquire(self.client_key):
            return None  # over the hourly cap: the join works, just without a relay
        return issue_turn_credentials(
            settings.TURN_SHARED_SECRET,
            settings.TURN_URLS,
            credential_ttl_seconds,
            int(time.time()),
        )

    async def relay_signal_to_peer(self, signal_text: str) -> None:
        if self.room_id is None:
            await self.send_message(ErrorMessage(code="bad-message"))
            return
        if not room_registry.is_member(self.room_id, self.channel_name):
            return  # our room expired and the close is on its way: relay nothing
        await self.send_event_to_peer(group_name_for_room(self.room_id), "peer_signal", signal_text)

    async def leave_room_then_close(self, close_code: int) -> None:
        """Defence in depth: clean up first so the peer gets `peer-left` even if closing fails.

        The close still happens if cleanup raises, so a bad connection never stays open.
        """
        try:
            await self.leave_room()
        finally:
            await self.close(code=close_code)

    async def leave_room(self) -> None:
        room_id = self.room_id
        if room_id is None:
            return
        self.room_id = None
        group_name = group_name_for_room(room_id)
        await room_registry.remove_member(room_id, self.channel_name)
        await self.channel_layer.group_discard(group_name, self.channel_name)
        await self.send_event_to_peer(group_name, "peer_left", PeerLeftMessage())

    async def send_event_to_peer(
        self, group_name: str, event_type: str, body: BaseModel | str
    ) -> None:
        text = body if isinstance(body, str) else body.model_dump_json()
        await self.channel_layer.group_send(
            group_name,
            {"type": event_type, "text": text, "sender_channel_name": self.channel_name},
        )

    async def forward_event_text_unless_from_self(self, event: dict[str, Any]) -> None:
        if event["sender_channel_name"] != self.channel_name:
            await self.send(text_data=event["text"])

    # Channels calls these handlers by the event "type" above.
    async def peer_joined(self, event: dict[str, Any]) -> None:
        await self.forward_event_text_unless_from_self(event)

    async def peer_signal(self, event: dict[str, Any]) -> None:
        await self.forward_event_text_unless_from_self(event)

    async def peer_left(self, event: dict[str, Any]) -> None:
        await self.forward_event_text_unless_from_self(event)

    async def room_expired(self, event: dict[str, Any]) -> None:
        """The registry removed our room (waiting or total limit). Tell the client and close."""
        room_id = self.room_id
        if room_id is None or group_name_for_room(room_id) != event["group_name"]:
            return  # stale: we already left that room (and maybe joined another)
        if room_registry.is_member(room_id, self.channel_name):
            return  # stale: we left and rejoined the same room ID; this is a live new room
        self.room_id = None
        await self.channel_layer.group_discard(group_name_for_room(room_id), self.channel_name)
        await self.send_message(ErrorMessage(code="room-expired"))
        await self.close()

    async def send_message(self, message: BaseModel) -> None:
        # exclude_none: an unset optional field (`turn`) is left out, never sent as null. No
        # other server message has an optional field; keep it that way or change this.
        await self.send(text_data=message.model_dump_json(exclude_none=True))
