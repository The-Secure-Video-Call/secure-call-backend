"""Signaling protocol models: the source of truth for the message format.

These models are exported as JSON Schema to `protocol/schema/` (run
`uv run python -m signaling.export_schema`) so the web client can check its own zod schemas
against the same contract and the same example messages in `protocol/fixtures/`.

Every message is `{"v": 1, "type": ..., ...}`. All models forbid unknown fields and are strict
(no type coercion). The server treats `payload` as an opaque base64 string: it is length- and
alphabet-checked here, never decoded, parsed or logged.
"""

from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

PROTOCOL_VERSION: Final = 1

# The whole message must fit SIGNALING_MAX_MESSAGE_BYTES (64 KiB, see config/settings.py). The
# payload may use at most that minus 1 KiB, which leaves room for the envelope and `iv`.
MAX_PAYLOAD_CHARS: Final = 64 * 1024 - 1024

ROOM_ID_PATTERN: Final = r"^[A-Za-z0-9_-]{22,43}$"  # base64url, no padding
BASE64_PATTERN: Final = r"^[A-Za-z0-9+/]+={0,2}$"  # standard base64
IV_PATTERN: Final = r"^[A-Za-z0-9+/]{16}$"  # base64 of exactly 12 bytes (no padding needed)

_STRICT = ConfigDict(extra="forbid", frozen=True, strict=True)


class Envelope(BaseModel):
    """Outer shape of every message in both directions. Unknown fields are rejected."""

    model_config = _STRICT

    v: Literal[1] = Field(description="Protocol version.")
    type: str = Field(
        pattern=r"^[a-z][a-z-]{0,31}$",
        description="Message type, e.g. 'ping'. Lowercase letters and dashes only.",
    )


# --- Client -> server -------------------------------------------------------------------------


class JoinMessage(BaseModel):
    """Ask to enter a room. `roomId` is derived in the browser; the room secret never leaves it."""

    model_config = _STRICT

    v: Literal[1] = 1
    type: Literal["join"] = "join"
    roomId: str = Field(  # noqa: N815 - wire format is camelCase
        pattern=ROOM_ID_PATTERN, description="base64url, 22-43 characters."
    )


class SignalMessage(BaseModel):
    """Opaque data for the other peer. Same shape in both directions."""

    model_config = _STRICT

    v: Literal[1] = 1
    type: Literal["signal"] = "signal"
    payload: str = Field(
        pattern=BASE64_PATTERN,
        min_length=1,
        max_length=MAX_PAYLOAD_CHARS,
        description="Opaque base64 string. Never decoded by the server.",
    )
    iv: str | None = Field(
        default=None,
        pattern=IV_PATTERN,
        description="Base64 of 12 bytes. Optional in M1, required from M2 (encryption).",
    )


class LeaveMessage(BaseModel):
    model_config = _STRICT

    v: Literal[1] = 1
    type: Literal["leave"] = "leave"


class PingMessage(BaseModel):
    model_config = _STRICT

    v: Literal[1] = 1
    type: Literal["ping"] = "ping"


ClientMessageUnion = Annotated[
    JoinMessage | SignalMessage | LeaveMessage | PingMessage,
    Field(discriminator="type"),
]


class ClientMessage(RootModel[ClientMessageUnion]):
    """Any message a client may send. Unknown `type` values are rejected."""

    model_config = ConfigDict(frozen=True, strict=True)


# --- Server -> client -------------------------------------------------------------------------


class JoinedMessage(BaseModel):
    """Sent to a client that entered a room. TURN credentials are added in M3."""

    model_config = _STRICT

    v: Literal[1] = 1
    type: Literal["joined"] = "joined"
    role: Literal["first", "second"]


class PeerJoinedMessage(BaseModel):
    model_config = _STRICT

    v: Literal[1] = 1
    type: Literal["peer-joined"] = "peer-joined"


class PeerLeftMessage(BaseModel):
    model_config = _STRICT

    v: Literal[1] = 1
    type: Literal["peer-left"] = "peer-left"


class ErrorMessage(BaseModel):
    """Sent by the server when it can't act on a message."""

    model_config = _STRICT

    v: Literal[1] = 1
    type: Literal["error"] = "error"
    code: Literal["room-full", "room-expired", "rate-limited", "bad-message", "unsupported-type"]


class PongMessage(BaseModel):
    model_config = _STRICT

    v: Literal[1] = 1
    type: Literal["pong"] = "pong"


ServerMessageUnion = Annotated[
    JoinedMessage
    | PeerJoinedMessage
    | PeerLeftMessage
    | SignalMessage
    | ErrorMessage
    | PongMessage,
    Field(discriminator="type"),
]


class ServerMessage(RootModel[ServerMessageUnion]):
    """Any message the server may send."""

    model_config = ConfigDict(frozen=True, strict=True)


SCHEMAS: dict[str, type[BaseModel]] = {
    "envelope": Envelope,
    "client-message": ClientMessage,
    "server-message": ServerMessage,
    "join": JoinMessage,
    "signal": SignalMessage,
    "leave": LeaveMessage,
    "ping": PingMessage,
    "joined": JoinedMessage,
    "peer-joined": PeerJoinedMessage,
    "peer-left": PeerLeftMessage,
    "error": ErrorMessage,
    "pong": PongMessage,
}
