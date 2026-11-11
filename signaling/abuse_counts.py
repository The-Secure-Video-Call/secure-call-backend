"""Counts of refusals, logged as one identifier-free warning line every few minutes.

ASVS V16.3 wants refusals to be visible, but the privacy rules forbid logging who or what was
refused. So this module keeps five plain integers in process memory and, every
REPORT_INTERVAL_SECONDS, logs one line of counts (only if one is non-zero) and resets them.

- Nothing here ever receives an IP address, room ID, username or message content: the only way in
  is `count(kind)` with a fixed `AbuseKind`, so an identifier cannot reach the line by accident.
- Increments have no `await`, so on the single-threaded event loop they cannot interleave.
- Counts are lost on restart and never stored anywhere else.
- Accepted trade-off: a line is a count for a window of a few minutes, so on a very quiet server
  a "1" says that one such event happened in that window (still no who, which room or what).
  `turn_credentials_issued` is requested by issue #71 and is the only non-refusal count.
"""

import asyncio
import enum
import logging

REPORT_INTERVAL_SECONDS = 300

logger = logging.getLogger(__name__)


class AbuseKind(enum.Enum):
    RATE_LIMIT_REFUSALS = "rate_limit_refusals"
    INVALID_OR_OVERSIZED_MESSAGES = "invalid_or_oversized_messages"
    ORIGIN_REJECTIONS = "origin_rejections"
    ROOM_FULL = "room_full"
    TURN_CREDENTIALS_ISSUED = "turn_credentials_issued"


counts_by_kind: dict[AbuseKind, int] = dict.fromkeys(AbuseKind, 0)
reporter_task: asyncio.Task[None] | None = None


def count(kind: AbuseKind) -> None:
    counts_by_kind[kind] += 1


def report_and_reset_counts() -> None:
    """Log one line of counts if any is non-zero, then reset all of them."""
    if not any(counts_by_kind.values()):
        return
    summary = " ".join(f"{kind.value}={counts_by_kind[kind]}" for kind in AbuseKind)
    for kind in AbuseKind:
        counts_by_kind[kind] = 0
    logger.warning("Counts since the last report: %s", summary)


async def report_counts_forever() -> None:
    while True:
        await asyncio.sleep(REPORT_INTERVAL_SECONDS)
        report_and_reset_counts()


def start_reporting_if_needed() -> None:
    """Start the periodic report on the running loop (again, if its loop has gone away)."""
    global reporter_task
    running_loop = asyncio.get_running_loop()
    if (
        reporter_task is None
        or reporter_task.done()
        or reporter_task.get_loop() is not running_loop
    ):
        reporter_task = running_loop.create_task(report_counts_forever())
