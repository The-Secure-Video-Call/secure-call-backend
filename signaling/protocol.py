"""Signaling protocol models: the source of truth for the message format.

These models are exported as JSON Schema to `protocol/schema/` (run
`uv run python -m signaling.export_schema`) so the web client can check its own zod schemas
against the same contract and the same example messages in `protocol/fixtures/`.

M0 placeholder: only the envelope shared by every message, plus ping/pong. The real
messages from PLAN.md section 6 (join, signal, leave, ...) arrive in M1/M2.
"""

from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field

PROTOCOL_VERSION: Final = 1


class Envelope(BaseModel):
    """Outer shape of every message in both directions. Unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    v: Literal[1] = Field(description="Protocol version.")
    type: str = Field(
        pattern=r"^[a-z][a-z-]{0,31}$",
        description="Message type, e.g. 'ping'. Lowercase letters and dashes only.",
    )


class ErrorMessage(BaseModel):
    """Sent by the server when it can't act on a message."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    v: Literal[1] = 1
    type: Literal["error"] = "error"
    code: Literal["bad-message", "unsupported-type"]


SCHEMAS: dict[str, type[BaseModel]] = {
    "envelope": Envelope,
    "error": ErrorMessage,
}
