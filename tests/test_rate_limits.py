import json
import logging

import pytest
from channels.routing import URLRouter
from channels.security.websocket import OriginValidator
from channels.testing import WebsocketCommunicator
from django.test import override_settings

from config.asgi import application
from signaling import consumers
from signaling.client_address import ClientAddressMiddleware
from signaling.consumers import CLOSE_RATE_LIMITED
from signaling.rate_limits import (
    JOIN_WINDOW_SECONDS,
    MAX_JOINS_PER_WINDOW,
    MAX_TURN_CREDENTIALS_PER_WINDOW,
    MESSAGE_BURST_SIZE,
    SlidingWindowLimiter,
    TokenBucket,
    client_key_for_ip,
    new_join_limiter,
    new_turn_credential_limiter,
)
from signaling.rooms import room_registry
from signaling.routing import websocket_urlpatterns

PATH = "/ws/signal/"
PROXY_IP = "192.168.1.10"
CLIENT_IP = "203.0.113.7"
OTHER_CLIENT_IP = "203.0.113.8"
SECRET = "s" * 40
TURN_URLS = ["turn:turn.example.com:3478"]
RATE_LIMITED = {"v": 1, "type": "error", "code": "rate-limited"}
PING = '{"v":1,"type":"ping"}'


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def room_id_number(number: int) -> str:
    return f"{number:022d}"


def join_text(number: int = 0) -> str:
    return json.dumps({"v": 1, "type": "join", "roomId": room_id_number(number)})


def open_client(
    peer_ip: str = CLIENT_IP, forwarded_for: str | None = None
) -> WebsocketCommunicator:
    headers = [(b"origin", b"http://localhost:5173")]
    if forwarded_for is not None:
        headers.append((b"x-forwarded-for", forwarded_for.encode()))
    client = WebsocketCommunicator(application, PATH, headers=headers)
    client.scope["client"] = [peer_ip, 50000]
    return client


async def join_once(
    number: int, peer_ip: str = CLIENT_IP, forwarded_for: str | None = None
) -> tuple[WebsocketCommunicator, dict[str, object]]:
    """Open a connection, join room `number` and return the first answer."""
    client = open_client(peer_ip, forwarded_for)
    connected, _ = await client.connect()
    assert connected
    await client.send_to(text_data=join_text(number))
    return client, json.loads(await client.receive_from())


@pytest.fixture
def join_clock(monkeypatch: pytest.MonkeyPatch) -> FakeClock:
    clock = FakeClock()
    monkeypatch.setattr(
        consumers,
        "join_limiter",
        SlidingWindowLimiter(MAX_JOINS_PER_WINDOW, JOIN_WINDOW_SECONDS, clock=clock),
    )
    return clock


# --- Unit tests ------------------------------------------------------------------------------


def test_sliding_window_allows_the_limit_then_refuses_then_recovers() -> None:
    clock = FakeClock()
    limiter = SlidingWindowLimiter(3, 60.0, clock=clock)
    key = client_key_for_ip(CLIENT_IP)

    assert [limiter.try_acquire(key) for _ in range(4)] == [True, True, True, False]
    clock.now += 59.0
    assert not limiter.try_acquire(key)
    clock.now += 1.1
    assert limiter.try_acquire(key)


def test_refused_events_are_not_counted() -> None:
    clock = FakeClock()
    limiter = SlidingWindowLimiter(1, 60.0, clock=clock)
    key = client_key_for_ip(CLIENT_IP)

    assert limiter.try_acquire(key)
    for _ in range(50):
        clock.now += 1.0
        assert not limiter.try_acquire(key)
    clock.now += 11.0  # 61 s after the one counted event
    assert limiter.try_acquire(key)


def test_clients_have_separate_counters() -> None:
    limiter = SlidingWindowLimiter(1, 60.0, clock=FakeClock())

    assert limiter.try_acquire(client_key_for_ip(CLIENT_IP))
    assert not limiter.try_acquire(client_key_for_ip(CLIENT_IP))
    assert limiter.try_acquire(client_key_for_ip(OTHER_CLIENT_IP))


def test_maps_stay_bounded_under_many_distinct_clients() -> None:
    limiter = SlidingWindowLimiter(5, 3600.0, max_tracked_clients=100, clock=FakeClock())

    for number in range(1000):
        assert limiter.try_acquire(client_key_for_ip(f"10.0.{number // 256}.{number % 256}"))
        assert limiter.tracked_client_count() <= 100
    assert limiter.tracked_client_count() == 100


def test_idle_clients_expire_from_the_map() -> None:
    clock = FakeClock()
    limiter = SlidingWindowLimiter(5, 60.0, clock=clock)
    for number in range(50):
        limiter.try_acquire(client_key_for_ip(f"10.0.0.{number}"))
    clock.now += 61.0

    limiter.try_acquire(client_key_for_ip(CLIENT_IP))

    assert limiter.tracked_client_count() == 1


def test_counter_keys_are_hmacs_not_raw_addresses() -> None:
    limiter = SlidingWindowLimiter(5, 60.0, clock=FakeClock())
    limiter.try_acquire(client_key_for_ip(CLIENT_IP))

    (stored_key,) = limiter.event_times_by_client_key
    assert isinstance(stored_key, bytes)
    assert CLIENT_IP.encode() not in stored_key
    assert len(stored_key) == 32
    assert client_key_for_ip(CLIENT_IP) == client_key_for_ip(CLIENT_IP)
    assert client_key_for_ip(CLIENT_IP) != client_key_for_ip(OTHER_CLIENT_IP)


def test_token_bucket_allows_a_burst_then_refills() -> None:
    clock = FakeClock()
    bucket = TokenBucket(20.0, 100, clock=clock)

    assert all(bucket.try_take_token() for _ in range(100))
    assert not bucket.try_take_token()
    clock.now += 0.1  # 2 tokens
    assert bucket.try_take_token()
    assert bucket.try_take_token()
    assert not bucket.try_take_token()
    clock.now += 3600.0  # never more than the burst size
    assert sum(bucket.try_take_token() for _ in range(150)) == 100


# --- Joins -----------------------------------------------------------------------------------


async def test_21st_join_in_a_minute_is_rate_limited_and_closed(join_clock: FakeClock) -> None:
    for number in range(MAX_JOINS_PER_WINDOW):
        client, answer = await join_once(number)
        assert answer["type"] == "joined"
        await client.disconnect()

    client, answer = await join_once(MAX_JOINS_PER_WINDOW)

    assert answer == RATE_LIMITED
    assert await client.receive_output() == {"type": "websocket.close", "code": CLOSE_RATE_LIMITED}
    await client.disconnect()


async def test_other_ip_is_not_affected_and_the_window_resets(join_clock: FakeClock) -> None:
    for number in range(MAX_JOINS_PER_WINDOW):
        client, _ = await join_once(number)
        await client.disconnect()

    limited_client, answer = await join_once(100)
    assert answer == RATE_LIMITED
    await limited_client.disconnect()

    other_client, other_answer = await join_once(101, peer_ip=OTHER_CLIENT_IP)
    assert other_answer["type"] == "joined"
    await other_client.disconnect()

    join_clock.now += JOIN_WINDOW_SECONDS + 1
    later_client, later_answer = await join_once(102)
    assert later_answer["type"] == "joined"
    await later_client.disconnect()


async def test_limit_is_per_ip_behind_a_trusted_proxy(
    join_clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    trusted_application = _application_trusting(monkeypatch, PROXY_IP)
    for number in range(MAX_JOINS_PER_WINDOW):
        client = _client_for(trusted_application, PROXY_IP, CLIENT_IP)
        await client.connect()
        await client.send_to(text_data=join_text(number))
        assert json.loads(await client.receive_from())["type"] == "joined"
        await client.disconnect()

    limited = _client_for(trusted_application, PROXY_IP, CLIENT_IP)
    await limited.connect()
    await limited.send_to(text_data=join_text(200))
    assert json.loads(await limited.receive_from()) == RATE_LIMITED
    await limited.disconnect()

    other = _client_for(trusted_application, PROXY_IP, OTHER_CLIENT_IP)
    await other.connect()
    await other.send_to(text_data=join_text(201))
    assert json.loads(await other.receive_from())["type"] == "joined"
    await other.disconnect()


async def test_spoofed_forwarded_for_from_untrusted_peer_does_not_change_bucket(
    join_clock: FakeClock,
) -> None:
    # No trusted proxy configured (the default): changing the header each time must not help.
    for number in range(MAX_JOINS_PER_WINDOW):
        client, answer = await join_once(number, forwarded_for=f"198.51.100.{number}")
        assert answer["type"] == "joined"
        await client.disconnect()

    client, answer = await join_once(300, forwarded_for="198.51.100.250")

    assert answer == RATE_LIMITED
    await client.disconnect()


async def test_forged_leftmost_entry_from_trusted_proxy_does_not_change_bucket(
    join_clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    trusted_application = _application_trusting(monkeypatch, PROXY_IP)
    for number in range(MAX_JOINS_PER_WINDOW):
        client = _client_for(trusted_application, PROXY_IP, f"198.51.100.{number}, {CLIENT_IP}")
        await client.connect()
        await client.send_to(text_data=join_text(number))
        assert json.loads(await client.receive_from())["type"] == "joined"
        await client.disconnect()

    client = _client_for(trusted_application, PROXY_IP, f"198.51.100.250, {CLIENT_IP}")
    await client.connect()
    await client.send_to(text_data=join_text(400))
    assert json.loads(await client.receive_from()) == RATE_LIMITED
    await client.disconnect()


async def test_rate_limit_leaves_no_ip_or_room_id_in_logs_or_errors(
    join_clock: FakeClock, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG):
        for number in range(MAX_JOINS_PER_WINDOW):
            client, _ = await join_once(number, forwarded_for=OTHER_CLIENT_IP)
            await client.disconnect()
        client, answer = await join_once(500, forwarded_for=OTHER_CLIENT_IP)
        await client.disconnect()

    assert answer == RATE_LIMITED  # fixed text: no address or room ID in it
    for secret_text in (CLIENT_IP, OTHER_CLIENT_IP, room_id_number(500), room_id_number(0)):
        assert secret_text not in caplog.text


async def test_over_limit_join_does_not_enter_a_room(join_clock: FakeClock) -> None:
    for _ in range(MAX_JOINS_PER_WINDOW):
        client, _answer = await join_once(7)  # same room again and again: each connection leaves
        await client.disconnect()
    client, answer = await join_once(7)
    await client.disconnect()

    assert answer == RATE_LIMITED
    assert room_registry.room_count() == 0


# --- TURN credentials ------------------------------------------------------------------------


@override_settings(TURN_SHARED_SECRET=SECRET, TURN_URLS=TURN_URLS)
async def test_credential_cap_leaves_joined_without_turn_and_the_call_works(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = FakeClock()
    monkeypatch.setattr(consumers, "join_limiter", SlidingWindowLimiter(1000, 60.0, clock=clock))
    monkeypatch.setattr(
        consumers,
        "turn_credential_limiter",
        SlidingWindowLimiter(MAX_TURN_CREDENTIALS_PER_WINDOW, 3600.0, clock=clock),
    )
    for number in range(MAX_TURN_CREDENTIALS_PER_WINDOW):
        client, answer = await join_once(number)
        assert "turn" in answer
        await client.disconnect()

    first, answer = await join_once(900)
    assert answer == {"v": 1, "type": "joined", "role": "first"}  # no turn, join not refused
    second = open_client()
    await second.connect()
    await second.send_to(text_data=join_text(900))
    assert json.loads(await second.receive_from())["role"] == "second"
    assert json.loads(await first.receive_from())["type"] == "peer-joined"
    signal = json.dumps({"v": 1, "type": "signal", "payload": "QUFB", "iv": "A" * 16})
    await first.send_to(text_data=signal)
    assert await second.receive_from() == signal
    await first.disconnect()
    await second.disconnect()

    clock.now += 3601.0
    later, later_answer = await join_once(901)
    assert "turn" in later_answer
    await later.disconnect()


# --- Messages --------------------------------------------------------------------------------


async def test_burst_of_100_messages_passes_and_a_sustained_flood_is_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = FakeClock()  # time stands still, so nothing is refilled during the flood
    monkeypatch.setattr(consumers, "new_message_bucket", lambda: TokenBucket(20.0, 100, clock))
    client = open_client()
    await client.connect()

    for _ in range(MESSAGE_BURST_SIZE):
        await client.send_to(text_data=PING)
    for _ in range(MESSAGE_BURST_SIZE):
        assert json.loads(await client.receive_from())["type"] == "pong"

    await client.send_to(text_data=PING)
    assert json.loads(await client.receive_from()) == RATE_LIMITED
    assert await client.receive_output() == {"type": "websocket.close", "code": CLOSE_RATE_LIMITED}
    await client.disconnect()


async def test_flooding_member_leaves_the_room_and_the_peer_is_told(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = FakeClock()
    monkeypatch.setattr(consumers, "new_message_bucket", lambda: TokenBucket(20.0, 3, clock))
    first, _ = await join_once(1)  # 1 message
    second, _ = await join_once(1, peer_ip=OTHER_CLIENT_IP)
    assert json.loads(await first.receive_from())["type"] == "peer-joined"

    for _ in range(2):
        await second.send_to(text_data=PING)
        await second.receive_from()
    await second.send_to(text_data=PING)  # the 4th message of this connection

    assert json.loads(await second.receive_from()) == RATE_LIMITED
    assert (await second.receive_output())["code"] == CLOSE_RATE_LIMITED
    await second.disconnect()
    assert json.loads(await first.receive_from()) == {"v": 1, "type": "peer-left"}
    await first.disconnect()


# --- Helpers for tests that trust a proxy ----------------------------------------------------


def _application_trusting(monkeypatch: pytest.MonkeyPatch, proxy_ip: str) -> object:
    return OriginValidator(
        ClientAddressMiddleware(URLRouter(websocket_urlpatterns), [proxy_ip]),
        ["http://localhost:5173"],
    )


def _client_for(
    trusted_application: object, peer_ip: str, forwarded_for: str
) -> WebsocketCommunicator:
    headers = [
        (b"origin", b"http://localhost:5173"),
        (b"x-forwarded-for", forwarded_for.encode()),
    ]
    client = WebsocketCommunicator(trusted_application, PATH, headers=headers)
    client.scope["client"] = [peer_ip, 50000]
    return client


def test_new_limiters_use_the_documented_limits() -> None:
    assert new_join_limiter().max_events == 20
    assert new_join_limiter().window_seconds == 60.0
    assert new_turn_credential_limiter().max_events == 120
    assert new_turn_credential_limiter().window_seconds == 3600.0
