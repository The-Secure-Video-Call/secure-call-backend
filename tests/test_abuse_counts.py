import asyncio
import json
import logging
from collections.abc import Iterator

import pytest
from channels.testing import WebsocketCommunicator
from django.test import override_settings

from config.asgi import application
from signaling import abuse_counts, consumers
from signaling.abuse_counts import (
    AbuseKind,
    count,
    report_and_reset_counts,
    start_reporting_if_needed,
)
from signaling.rate_limits import TokenBucket

PATH = "/ws/signal/"
ALLOWED_ORIGIN = b"http://localhost:5173"
ROOM_ID_SENTINEL = "room-id-sentinel-0123456789abcdef"
CONTENT_SENTINEL = "message-content-sentinel"
TURN_TEST_SECRET = "test-shared-secret"  # noqa: S105 - test value, not a real secret


@pytest.fixture(autouse=True)
def zero_counts() -> Iterator[None]:
    for kind in AbuseKind:
        abuse_counts.counts_by_kind[kind] = 0
    abuse_counts.reporter_task = None
    yield
    leftover_task = abuse_counts.reporter_task
    if leftover_task is not None and not leftover_task.done():
        leftover_task.cancel()
    abuse_counts.reporter_task = None


def make_client(origin: bytes = ALLOWED_ORIGIN) -> WebsocketCommunicator:
    client = WebsocketCommunicator(application, PATH, headers=[(b"origin", origin)])
    client.scope["client"] = ["203.0.113.7", 50000]
    return client


def test_report_has_the_right_counts_then_resets(caplog: pytest.LogCaptureFixture) -> None:
    count(AbuseKind.RATE_LIMIT_REFUSALS)
    count(AbuseKind.RATE_LIMIT_REFUSALS)
    count(AbuseKind.ROOM_FULL)
    with caplog.at_level(logging.WARNING, logger="signaling.abuse_counts"):
        report_and_reset_counts()
    assert [record.getMessage() for record in caplog.records] == [
        "Counts since the last report: rate_limit_refusals=2 invalid_or_oversized_messages=0 "
        "origin_rejections=0 room_full=1 turn_credentials_issued=0"
    ]
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="signaling.abuse_counts"):
        report_and_reset_counts()
    assert caplog.records == []  # reset after the line, so nothing left to report


def test_nothing_is_logged_when_every_count_is_zero(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        report_and_reset_counts()
    assert caplog.records == []


async def test_origin_rejection_is_counted() -> None:
    client = make_client(origin=b"http://evil.example")
    connected, _ = await client.connect()
    assert not connected
    assert abuse_counts.counts_by_kind[AbuseKind.ORIGIN_REJECTIONS] == 1


async def test_allowed_origin_is_not_counted() -> None:
    client = make_client()
    connected, _ = await client.connect()
    assert connected
    await client.disconnect()
    assert abuse_counts.counts_by_kind[AbuseKind.ORIGIN_REJECTIONS] == 0


async def test_malformed_and_oversized_messages_are_counted() -> None:
    malformed = make_client()
    await malformed.connect()
    await malformed.send_to(text_data='{"v":1,"type":"teleport"}')
    await malformed.receive_output()
    oversized = make_client()
    await oversized.connect()
    await oversized.send_to(text_data="x" * 100_000)
    await oversized.receive_output()
    assert abuse_counts.counts_by_kind[AbuseKind.INVALID_OR_OVERSIZED_MESSAGES] == 2


async def test_third_member_counts_room_full() -> None:
    clients = [make_client() for _ in range(3)]
    join_text = json.dumps({"v": 1, "type": "join", "roomId": ROOM_ID_SENTINEL})
    for client in clients:
        await client.connect()
        await client.send_to(text_data=join_text)
        await client.receive_output()  # joined, or error room-full
    assert abuse_counts.counts_by_kind[AbuseKind.ROOM_FULL] == 1
    for client in clients:
        await client.disconnect()


async def test_report_never_contains_identifiers(caplog: pytest.LogCaptureFixture) -> None:
    """Negative test: IP address, room ID and message content must not reach the log line."""
    refused = make_client(origin=b"http://evil.example")
    await refused.connect()
    bad = make_client()
    await bad.connect()
    await bad.send_to(
        text_data=json.dumps(
            {"v": 1, "type": "join", "roomId": ROOM_ID_SENTINEL, "extra": CONTENT_SENTINEL}
        )
    )
    await bad.receive_output()
    with caplog.at_level(logging.DEBUG):
        report_and_reset_counts()
    line = " ".join(record.getMessage() for record in caplog.records)
    assert "invalid_or_oversized_messages=1" in line
    assert "origin_rejections=1" in line
    for forbidden in ("203.0.113.7", ROOM_ID_SENTINEL, CONTENT_SENTINEL, "evil.example"):
        assert forbidden not in line


@override_settings(TURN_SHARED_SECRET=TURN_TEST_SECRET, TURN_URLS=["turn:turn.example:3478"])
async def test_issued_turn_credentials_are_counted() -> None:
    client = make_client()
    await client.connect()
    await client.send_to(text_data=json.dumps({"v": 1, "type": "join", "roomId": ROOM_ID_SENTINEL}))
    await client.receive_output()
    await client.disconnect()
    assert abuse_counts.counts_by_kind[AbuseKind.TURN_CREDENTIALS_ISSUED] == 1


def frozen_clock() -> float:
    return 0.0


async def test_bad_origins_alone_start_the_reporter_and_get_logged(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(abuse_counts, "REPORT_INTERVAL_SECONDS", 0.01)
    assert abuse_counts.reporter_task is None
    client = make_client(origin=b"http://evil.example")
    with caplog.at_level(logging.WARNING, logger="signaling.abuse_counts"):
        connected, _ = await client.connect()
        assert not connected
        assert abuse_counts.reporter_task is not None
        await asyncio.sleep(0.1)
    lines = [record.getMessage() for record in caplog.records]
    assert any("origin_rejections=1" in line for line in lines)
    assert not any("evil.example" in line for line in lines)


def test_count_without_a_running_loop_still_counts_and_does_not_raise() -> None:
    count(AbuseKind.ROOM_FULL)
    assert abuse_counts.counts_by_kind[AbuseKind.ROOM_FULL] == 1
    assert abuse_counts.reporter_task is None


async def test_one_reporter_task_is_kept_and_a_new_one_starts_only_after_it_finished() -> None:
    start_reporting_if_needed()
    first_task = abuse_counts.reporter_task
    assert first_task is not None
    start_reporting_if_needed()
    count(AbuseKind.ROOM_FULL)
    assert abuse_counts.reporter_task is first_task  # still running: no second task

    first_task.cancel()
    await asyncio.gather(first_task, return_exceptions=True)
    assert first_task.done()
    start_reporting_if_needed()
    second_task = abuse_counts.reporter_task
    assert second_task is not None
    assert second_task is not first_task
    assert not second_task.done()


async def test_message_rate_limit_is_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(consumers, "new_message_bucket", lambda: TokenBucket(20.0, 2, frozen_clock))
    client = make_client()
    await client.connect()
    ping = json.dumps({"v": 1, "type": "ping"})
    for _ in range(2):
        await client.send_to(text_data=ping)
        await client.receive_output()
    assert abuse_counts.counts_by_kind[AbuseKind.RATE_LIMIT_REFUSALS] == 0
    await client.send_to(text_data=ping)
    await client.receive_output()  # error rate-limited
    assert abuse_counts.counts_by_kind[AbuseKind.RATE_LIMIT_REFUSALS] == 1
    await client.disconnect()


async def test_wrong_time_messages_are_counted_as_invalid() -> None:
    client = make_client()
    await client.connect()
    for wrong_time_message in (
        {"v": 1, "type": "leave"},
        {"v": 1, "type": "signal", "payload": "AAAA", "iv": "A" * 16},
    ):
        await client.send_to(text_data=json.dumps(wrong_time_message))
        reply = json.loads(await client.receive_from())
        assert reply == {"v": 1, "type": "error", "code": "bad-message"}
    join_text = json.dumps({"v": 1, "type": "join", "roomId": ROOM_ID_SENTINEL})
    await client.send_to(text_data=join_text)
    await client.receive_output()
    await client.send_to(text_data=join_text)  # joining twice
    await client.receive_output()
    assert abuse_counts.counts_by_kind[AbuseKind.INVALID_OR_OVERSIZED_MESSAGES] == 3
    await client.disconnect()
