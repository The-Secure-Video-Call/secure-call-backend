import asyncio
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass

import pytest
from channels.routing import URLRouter
from channels.security.websocket import OriginValidator
from channels.testing import WebsocketCommunicator
from django.test import override_settings

from config.asgi import application
from signaling import consumers
from signaling.client_address import IPV6_PREFIX_LENGTH, ClientAddressMiddleware, group_client_ip
from signaling.consumers import CLOSE_RATE_LIMITED
from signaling.rate_limits import (
    CLIENT_TIERS,
    JOIN_WINDOW_SECONDS,
    MAX_CONNECTIONS_PER_CLIENT,
    MAX_CONNECTIONS_TOTAL,
    MAX_JOINS_PER_WINDOW,
    MAX_TURN_CREDENTIALS_PER_WINDOW,
    MESSAGE_BURST_SIZE,
    TURN_CREDENTIAL_WINDOW_SECONDS,
    ClientKeys,
    ClientTier,
    ConnectionLimiter,
    SlidingWindowLimiter,
    TieredConnectionLimiter,
    TieredSlidingWindowLimiter,
    TokenBucket,
    client_key_for_ip,
    client_keys_for_ip,
    new_connection_limiter,
    new_join_limiter,
    new_turn_credential_limiter,
)
from signaling.rooms import room_registry
from signaling.routing import websocket_urlpatterns

PATH = "/ws/signal/"
PROXY_IP = "192.168.1.10"
CLIENT_IP = "203.0.113.7"
OTHER_CLIENT_IP = "203.0.113.8"
IPV6_CLIENT_IP = "2001:db8:1:1::5"
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
        TieredSlidingWindowLimiter(MAX_JOINS_PER_WINDOW, JOIN_WINDOW_SECONDS, clock=clock),
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


def test_eviction_removes_the_least_recently_active_key() -> None:
    limiter = SlidingWindowLimiter(5, 60.0, max_tracked_clients=2, clock=FakeClock())
    first_key, second_key, third_key = (
        client_key_for_ip(ip) for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3")
    )
    assert limiter.try_acquire(first_key)
    assert limiter.try_acquire(second_key)
    assert limiter.try_acquire(first_key)  # now the most recently active

    assert limiter.try_acquire(third_key)  # the map is full: one key must go

    assert list(limiter.event_times_by_client_key) == [first_key, third_key]
    assert len(limiter.event_times_by_client_key[first_key]) == 2  # kept with its counts


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
    monkeypatch.setattr(
        consumers, "join_limiter", TieredSlidingWindowLimiter(1000, 60.0, clock=clock)
    )
    monkeypatch.setattr(
        consumers,
        "turn_credential_limiter",
        TieredSlidingWindowLimiter(MAX_TURN_CREDENTIALS_PER_WINDOW, 3600.0, clock=clock),
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


def sliding_window_limits_by_tier(
    limiter: TieredSlidingWindowLimiter,
) -> list[tuple[int, float, int]]:
    """(cap, window, most keys kept) of every tier, coarsest first."""
    return [
        (tier_limiter.max_events, tier_limiter.window_seconds, tier_limiter.max_tracked_clients)
        for tier_limiter in limiter.limiters
    ]


def test_new_limiters_use_the_documented_limits() -> None:
    # /48, /56 and /64: 16, 4 and 1 times the caps, all with the same window.
    assert sliding_window_limits_by_tier(new_join_limiter()) == [
        (320, 60.0, 500),
        (80, 60.0, 1_000),
        (20, 60.0, 10_000),
    ]
    assert sliding_window_limits_by_tier(new_turn_credential_limiter()) == [
        (1_920, 3600.0, 500),
        (480, 3600.0, 1_000),
        (120, 3600.0, 10_000),
    ]


# --- Connection caps and the join timeout ----------------------------------------------------

CAP_PER_CLIENT = 3
CAP_TOTAL = 5
PONG = {"v": 1, "type": "pong"}


# Both peers are tested wherever a slot must be given back: IPv6 takes a slot in all three tiers.
# The second value is the number of slots each tier (/48, /56, /64) holds while it is connected.
PEERS = [
    pytest.param(CLIENT_IP, [0, 0, 1], id="ipv4"),
    pytest.param(IPV6_CLIENT_IP, [1, 1, 1], id="ipv6"),
]


@pytest.fixture
def small_connection_limiter(monkeypatch: pytest.MonkeyPatch) -> TieredConnectionLimiter:
    limiter = TieredConnectionLimiter(CAP_PER_CLIENT, CAP_TOTAL)
    monkeypatch.setattr(consumers, "connection_limiter", limiter)
    return limiter


def connection_counts_by_tier(limiter: TieredConnectionLimiter) -> list[int]:
    return [tier_limiter.total_connection_count for tier_limiter in limiter.limiters]


def connection_counts_by_tier_and_key(limiter: TieredConnectionLimiter) -> list[dict[bytes, int]]:
    return [dict(tier_limiter.connection_count_by_client_key) for tier_limiter in limiter.limiters]


def assert_no_connections_counted(limiter: ConnectionLimiter | TieredConnectionLimiter) -> None:
    tier_limiters = limiter.limiters if isinstance(limiter, TieredConnectionLimiter) else [limiter]
    for tier_limiter in tier_limiters:
        assert tier_limiter.total_connection_count == 0
        assert tier_limiter.connection_count_by_client_key == {}


async def open_connected_client(peer_ip: str = CLIENT_IP) -> WebsocketCommunicator:
    client = open_client(peer_ip)
    connected, _ = await client.connect()
    assert connected
    return client


async def assert_refused_with_rate_limited(client: WebsocketCommunicator) -> str:
    refusal_text = str(await client.receive_from())
    assert json.loads(refusal_text) == RATE_LIMITED
    assert await client.receive_output() == {
        "type": "websocket.close",
        "code": CLOSE_RATE_LIMITED,
    }
    await client.wait()
    return refusal_text


async def let_server_notice_close() -> None:
    await asyncio.sleep(0.05)


def test_connection_limiter_caps_per_client_and_in_total() -> None:
    limiter = ConnectionLimiter(2, 3)
    key = client_key_for_ip(CLIENT_IP)

    assert [limiter.try_acquire(key) for _ in range(3)] == [True, True, False]
    assert limiter.try_acquire(client_key_for_ip(OTHER_CLIENT_IP))
    assert not limiter.try_acquire(client_key_for_ip("203.0.113.9"))  # global cap of 3


def test_connection_limiter_release_never_goes_negative_and_drops_empty_keys() -> None:
    limiter = ConnectionLimiter(2, 3)
    key = client_key_for_ip(CLIENT_IP)

    limiter.release(key)  # never acquired
    assert_no_connections_counted(limiter)
    assert limiter.try_acquire(key)
    limiter.release(key)
    limiter.release(key)  # released twice
    assert_no_connections_counted(limiter)


def test_connection_limiter_map_stays_bounded_by_the_global_cap() -> None:
    limiter = ConnectionLimiter(1, 50)

    for number in range(1000):
        limiter.try_acquire(client_key_for_ip(f"10.0.{number // 256}.{number % 256}"))
    assert len(limiter.connection_count_by_client_key) == 50


def test_new_connection_limiter_uses_the_documented_caps() -> None:
    assert (MAX_CONNECTIONS_PER_CLIENT, MAX_CONNECTIONS_TOTAL) == (20, 500)
    # Only the /64 (and IPv4) tier has the total cap: every connection is counted there.
    caps_by_tier = [
        (tier_limiter.max_per_client, tier_limiter.max_total)
        for tier_limiter in new_connection_limiter().limiters
    ]
    assert caps_by_tier == [(320, None), (80, None), (20, 500)]


async def test_connection_over_the_client_cap_is_refused_and_other_ip_is_not(
    small_connection_limiter: TieredConnectionLimiter,
) -> None:
    accepted = [await open_connected_client() for _ in range(CAP_PER_CLIENT)]

    await assert_refused_with_rate_limited(await open_connected_client())
    other_ip_client = await open_connected_client(OTHER_CLIENT_IP)
    await other_ip_client.send_to(text_data=PING)
    assert json.loads(await other_ip_client.receive_from()) == PONG

    # The refused connection never held a slot.
    assert small_connection_limiter.total_connection_count == CAP_PER_CLIENT + 1
    for client in [*accepted, other_ip_client]:
        await client.disconnect()
    assert_no_connections_counted(small_connection_limiter)


async def test_global_cap_refuses_even_a_new_ip(
    small_connection_limiter: TieredConnectionLimiter,
) -> None:
    accepted = [
        await open_connected_client(f"203.0.113.{number}") for number in range(10, 10 + CAP_TOTAL)
    ]

    await assert_refused_with_rate_limited(await open_connected_client("198.51.100.1"))

    await accepted[0].disconnect()  # a freed slot is usable again
    again = await open_connected_client("198.51.100.1")
    await again.send_to(text_data=PING)
    assert json.loads(await again.receive_from()) == PONG
    for client in [*accepted[1:], again]:
        await client.disconnect()
    assert_no_connections_counted(small_connection_limiter)


@pytest.mark.parametrize(("peer_ip", "slots_by_tier"), PEERS)
async def test_slot_is_released_on_normal_disconnect(
    small_connection_limiter: TieredConnectionLimiter, peer_ip: str, slots_by_tier: list[int]
) -> None:
    client, _ = await join_once(1, peer_ip)
    assert connection_counts_by_tier(small_connection_limiter) == slots_by_tier

    await client.disconnect()

    assert_no_connections_counted(small_connection_limiter)


@pytest.mark.parametrize(("peer_ip", "slots_by_tier"), PEERS)
async def test_slot_is_released_when_the_server_closes_a_bad_connection(
    small_connection_limiter: TieredConnectionLimiter, peer_ip: str, slots_by_tier: list[int]
) -> None:
    client = await open_connected_client(peer_ip)
    assert connection_counts_by_tier(small_connection_limiter) == slots_by_tier
    await client.send_to(text_data="{not json")
    await client.receive_output()  # the close
    await client.wait()

    assert_no_connections_counted(small_connection_limiter)


@pytest.mark.parametrize(("peer_ip", "slots_by_tier"), PEERS)
async def test_slot_is_released_when_the_application_task_is_cancelled(
    small_connection_limiter: TieredConnectionLimiter, peer_ip: str, slots_by_tier: list[int]
) -> None:
    client = await open_connected_client(peer_ip)
    assert connection_counts_by_tier(small_connection_limiter) == slots_by_tier

    client.future.cancel()  # an abnormal end: no websocket.disconnect is ever delivered
    await let_server_notice_close()

    assert_no_connections_counted(small_connection_limiter)


@pytest.mark.parametrize(("peer_ip", "slots_by_tier"), PEERS)
async def test_slot_is_released_when_connect_fails_halfway(
    small_connection_limiter: TieredConnectionLimiter,
    monkeypatch: pytest.MonkeyPatch,
    peer_ip: str,
    slots_by_tier: list[int],
) -> None:
    slots_while_accepting: list[list[int]] = []

    async def failing_accept(self: object, subprotocol: str | None = None) -> None:
        slots_while_accepting.append(connection_counts_by_tier(small_connection_limiter))
        raise RuntimeError("accept failed")

    monkeypatch.setattr(consumers.SignalingConsumer, "accept", failing_accept)

    with pytest.raises(RuntimeError):
        await open_client(peer_ip).connect()

    assert slots_while_accepting == [slots_by_tier]  # the slots were taken before it failed
    assert_no_connections_counted(small_connection_limiter)


# Many clients, in different IPv4 addresses or in different IPv6 /48s, /56s and /64s.
CYCLING_PEER_ADDRESSES = [
    pytest.param(lambda number: f"203.0.113.{number % 7}", id="ipv4"),
    pytest.param(lambda number: f"2001:db8:{number % 3}:{number % 7:x}00::5", id="ipv6"),
]


@pytest.mark.parametrize("address_for_number", CYCLING_PEER_ADDRESSES)
async def test_counters_return_to_zero_after_many_cycles(
    small_connection_limiter: TieredConnectionLimiter, address_for_number: Callable[[int], str]
) -> None:
    for number in range(60):
        client = await open_connected_client(address_for_number(number))
        if number % 3 == 0:
            await client.send_to(text_data="{not json")
            await client.receive_output()
            await client.wait()
        elif number % 3 == 1:
            client.future.cancel()
            await let_server_notice_close()
        else:
            await client.disconnect()
        assert connection_counts_by_tier(small_connection_limiter) == [0, 0, 0]

    assert_no_connections_counted(small_connection_limiter)


@pytest.mark.parametrize(("peer_ip", "slots_by_tier"), PEERS)
async def test_closing_one_connection_gives_back_exactly_one_slot_per_tier(
    small_connection_limiter: TieredConnectionLimiter, peer_ip: str, slots_by_tier: list[int]
) -> None:
    accepted = [await open_connected_client(peer_ip) for _ in range(CAP_PER_CLIENT)]
    full = [CAP_PER_CLIENT * slots for slots in slots_by_tier]
    assert connection_counts_by_tier(small_connection_limiter) == full

    await accepted[0].disconnect()  # disconnect() and __call__'s finally both run

    # Given back once, not twice: a double release would let two more connections in.
    assert connection_counts_by_tier(small_connection_limiter) == [
        (CAP_PER_CLIENT - 1) * slots for slots in slots_by_tier
    ]
    replacement = await open_connected_client(peer_ip)
    await replacement.send_to(text_data=PING)
    assert json.loads(await replacement.receive_from()) == PONG
    await assert_refused_with_rate_limited(await open_connected_client(peer_ip))
    for client in [*accepted[1:], replacement]:
        await client.disconnect()
    assert_no_connections_counted(small_connection_limiter)


async def test_spoofed_forwarded_for_from_an_untrusted_peer_does_not_change_bucket(
    small_connection_limiter: TieredConnectionLimiter,
) -> None:
    accepted = []
    for number in range(CAP_PER_CLIENT):
        client = open_client(CLIENT_IP, forwarded_for=f"198.51.100.{number}")
        connected, _ = await client.connect()
        assert connected
        accepted.append(client)

    spoofing_client = open_client(CLIENT_IP, forwarded_for="198.51.100.200")
    await spoofing_client.connect()
    await assert_refused_with_rate_limited(spoofing_client)

    assert len(small_connection_limiter.limiters[-1].connection_count_by_client_key) == 1
    for client in accepted:
        await client.disconnect()


async def test_refused_connection_cannot_join_a_room(
    small_connection_limiter: TieredConnectionLimiter,
) -> None:
    accepted = [await open_connected_client() for _ in range(CAP_PER_CLIENT)]
    refused = await open_connected_client()
    await refused.send_to(text_data=join_text(7))  # sent before the close is processed
    await refused.receive_from()  # rate-limited error
    await refused.receive_output()  # the close
    await refused.wait()

    assert room_registry.room_count() == 0
    for client in accepted:
        await client.disconnect()


async def test_refusal_logs_and_sends_no_ip_address(
    small_connection_limiter: TieredConnectionLimiter, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    accepted = [await open_connected_client() for _ in range(CAP_PER_CLIENT)]

    refusal_text = await assert_refused_with_rate_limited(await open_connected_client())

    assert CLIENT_IP not in caplog.text
    assert CLIENT_IP not in refusal_text
    for client in accepted:
        await client.disconnect()


@pytest.mark.parametrize(("peer_ip", "slots_by_tier"), PEERS)
async def test_connection_that_never_joins_is_closed(
    small_connection_limiter: TieredConnectionLimiter,
    monkeypatch: pytest.MonkeyPatch,
    peer_ip: str,
    slots_by_tier: list[int],
) -> None:
    monkeypatch.setattr(consumers, "JOIN_TIMEOUT_SECONDS", 0.1)
    client = await open_connected_client(peer_ip)
    await client.send_to(text_data=PING)  # keeping it alive does not count as joining
    assert json.loads(await client.receive_from()) == PONG
    assert connection_counts_by_tier(small_connection_limiter) == slots_by_tier

    assert await client.receive_output() == {
        "type": "websocket.close",
        "code": consumers.CLOSE_POLICY_VIOLATION,
    }
    await client.disconnect()
    assert_no_connections_counted(small_connection_limiter)


async def test_connection_that_joins_in_time_stays_open(
    small_connection_limiter: TieredConnectionLimiter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(consumers, "JOIN_TIMEOUT_SECONDS", 0.2)
    client, answer = await join_once(2)
    assert answer["type"] == "joined"

    await asyncio.sleep(0.4)
    await client.send_to(text_data=PING)

    assert json.loads(await client.receive_from()) == PONG
    await client.disconnect()


# --- IPv6 tiers: /48, /56 and /64 ------------------------------------------------------------

OTHER_48_IP = "2001:db8:2:1::5"


@dataclass(frozen=True)
class TierCase:
    """Clients that share the prefix of one tier but are in different prefixes of every finer
    tier, so that tier alone can refuse them; and a neighbour in another prefix of that tier
    (sharing every coarser one), which it must not refuse."""

    tier_index: int
    address_for_number: Callable[[int], str]
    neighbour_address: str

    @property
    def clients_allowed_at_base_cap_1(self) -> int:
        return CLIENT_TIERS[self.tier_index].cap_factor


TIER_CASES = [
    # 2001:db8:1::/48, a different /56 each: 2001:db8:1:000::, 2001:db8:1:100::, ...
    pytest.param(
        TierCase(0, lambda number: f"2001:db8:1:{number:x}00::5", OTHER_48_IP), id="slash-48"
    ),
    # 2001:db8:1:100::/56, a different /64 each: 2001:db8:1:100::, 2001:db8:1:101::, ...
    pytest.param(
        TierCase(1, lambda number: f"2001:db8:1:1{number:02x}::5", "2001:db8:1:200::5"),
        id="slash-56",
    ),
    # 2001:db8:1:1::/64, a different address each.
    pytest.param(
        TierCase(2, lambda number: f"2001:db8:1:1::{number + 1:x}", "2001:db8:1:2::5"),
        id="slash-64",
    ),
]
COARSE_TIER_CASES = TIER_CASES[:2]


def client_keys_of_address(address: str) -> ClientKeys:
    """The keys the consumer uses for a client connecting from `address`."""
    return client_keys_for_ip(group_client_ip(address))


def event_counts_by_tier(limiter: TieredSlidingWindowLimiter) -> list[list[tuple[bytes, int]]]:
    """Every tier's keys in map order (least recently active first) with their event counts."""
    return [
        [
            (client_key, len(event_times))
            for client_key, event_times in tier.event_times_by_client_key.items()
        ]
        for tier in limiter.limiters
    ]


async def assert_connected_then_refused_on_join(client: WebsocketCommunicator, number: int) -> None:
    await client.send_to(text_data=PING)
    assert json.loads(await client.receive_from()) == PONG  # connected, not refused at connect
    await client.send_to(text_data=join_text(number))
    assert json.loads(await client.receive_from()) == RATE_LIMITED
    assert await client.receive_output() == {"type": "websocket.close", "code": CLOSE_RATE_LIMITED}
    await client.disconnect()


def test_client_tiers_are_slash_48_slash_56_and_slash_64_coarsest_first() -> None:
    tiers = [
        (tier.ipv6_prefix_length, tier.cap_factor, tier.max_tracked_clients)
        for tier in CLIENT_TIERS
    ]
    # One /56 gets a quarter of its /48, one /64 a quarter of its /56.
    assert tiers == [(48, 16, 500), (56, 4, 1_000), (64, 1, 10_000)]
    assert CLIENT_TIERS[-1].ipv6_prefix_length == IPV6_PREFIX_LENGTH  # client_address.py's group


def test_client_keys_are_one_hmac_per_tier_and_ipv4_has_only_the_finest() -> None:
    slash_48_key, slash_56_key, slash_64_key = client_keys_for_ip("2001:db8:1:1::")
    assert slash_64_key == client_key_for_ip("2001:db8:1:1::")
    for key in (slash_48_key, slash_56_key, slash_64_key):
        assert isinstance(key, bytes)
        assert len(key) == 32
        assert b"2001" not in key
    # 2001:db8:1:: is the text of its /48, its /56 and its /64: still three different keys.
    assert len(set(client_keys_for_ip("2001:db8:1::"))) == 3

    same_slash_56 = client_keys_for_ip("2001:db8:1:ff::")
    assert same_slash_56[:2] == (slash_48_key, slash_56_key)
    assert same_slash_56[2] != slash_64_key
    same_slash_48 = client_keys_for_ip("2001:db8:1:100::")
    assert same_slash_48[0] == slash_48_key
    assert same_slash_48[1] != slash_56_key
    other_slash_48 = client_keys_for_ip("2001:db8:2:1::")
    assert set(other_slash_48).isdisjoint({slash_48_key, slash_56_key, slash_64_key})

    # IPv4 and "unknown" are counted once, by the finest tier.
    assert client_keys_for_ip(CLIENT_IP) == (None, None, client_key_for_ip(CLIENT_IP))
    assert client_keys_for_ip("unknown") == (None, None, client_key_for_ip("unknown"))


@pytest.mark.parametrize("case", TIER_CASES)
def test_tier_case_addresses_share_only_their_own_tier(case: TierCase) -> None:
    """Checks the test data above: otherwise a tier test could pass for the wrong tier."""
    count = case.clients_allowed_at_base_cap_1 + 1
    keys_by_client = [client_keys_of_address(case.address_for_number(n)) for n in range(count)]
    neighbour_keys = client_keys_of_address(case.neighbour_address)
    for tier_index in range(len(CLIENT_TIERS)):
        distinct_keys = {client_keys[tier_index] for client_keys in keys_by_client}
        assert len(distinct_keys) == (1 if tier_index <= case.tier_index else count)
        shares_with_neighbour = neighbour_keys[tier_index] == keys_by_client[0][tier_index]
        assert shares_with_neighbour == (tier_index < case.tier_index)


def test_can_acquire_counts_nothing_and_adds_moves_or_evicts_no_key() -> None:
    clock = FakeClock()
    limiter = SlidingWindowLimiter(1, 60.0, max_tracked_clients=2, clock=clock)
    first_key, second_key, new_key = (
        client_key_for_ip(ip) for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3")
    )
    assert limiter.try_acquire(first_key)
    assert limiter.try_acquire(second_key)

    assert not limiter.can_acquire(first_key, clock.now)
    assert limiter.can_acquire(new_key, clock.now)  # the map is full, yet nothing is evicted

    assert list(limiter.event_times_by_client_key) == [first_key, second_key]  # order kept
    assert [len(times) for times in limiter.event_times_by_client_key.values()] == [1, 1]


@pytest.mark.parametrize("case", TIER_CASES)
def test_refusal_by_any_tier_charges_no_tier(case: TierCase) -> None:
    limiter = TieredSlidingWindowLimiter(1, 60.0, clock=FakeClock())
    allowed = case.clients_allowed_at_base_cap_1
    for number in range(allowed):
        assert limiter.try_acquire(client_keys_of_address(case.address_for_number(number)))
    counts_before_refusal = event_counts_by_tier(limiter)

    for number in range(allowed, allowed + 5):
        assert not limiter.try_acquire(client_keys_of_address(case.address_for_number(number)))

    assert event_counts_by_tier(limiter) == counts_before_refusal  # same keys, order and counts


def test_refusal_by_a_coarse_tier_adds_moves_or_evicts_no_entry() -> None:
    # Small maps, so an insert would have to evict: /48 x2 (10 keys), /56 x2 (10), /64 x1 (3).
    tiers = (ClientTier(48, 2, 10), ClientTier(56, 2, 10), ClientTier(64, 1, 3))
    limiter = TieredSlidingWindowLimiter(1, 60.0, tiers=tiers, clock=FakeClock())

    def keys_of(address: str) -> ClientKeys:
        return client_keys_for_ip(group_client_ip(address), tiers)

    assert limiter.try_acquire(keys_of("2001:db8:1:100::5"))
    assert limiter.try_acquire(keys_of("2001:db8:1:200::5"))  # 2001:db8:1::/48 is now full
    assert limiter.try_acquire(keys_of(OTHER_48_IP))  # newer than it, so later in the /48 map
    counts_before_refusal = event_counts_by_tier(limiter)

    for number in range(3, 23):  # fresh /56s and /64s of the full /48
        assert not limiter.try_acquire(keys_of(f"2001:db8:1:{number:x}00::5"))

    # The full /48 was not moved to the recently-active end, and the full /64 map evicted nothing.
    assert event_counts_by_tier(limiter) == counts_before_refusal


def test_refusal_by_the_slash_64_charges_or_moves_no_coarse_entry() -> None:
    limiter = TieredSlidingWindowLimiter(1, 60.0, clock=FakeClock())
    keys = client_keys_of_address(IPV6_CLIENT_IP)
    assert limiter.try_acquire(keys)
    assert limiter.try_acquire(client_keys_of_address(OTHER_48_IP))  # newer in every map
    counts_before_refusal = event_counts_by_tier(limiter)

    assert not limiter.try_acquire(keys)  # its /64 is full; its /56 and /48 are not

    # Its /48 and /56 entries keep their counts and stay the least recently active.
    assert event_counts_by_tier(limiter) == counts_before_refusal


def test_ipv4_is_counted_by_the_finest_tier_only() -> None:
    limiter = TieredSlidingWindowLimiter(2, 60.0, clock=FakeClock())
    keys = client_keys_for_ip(CLIENT_IP)
    assert [limiter.try_acquire(keys) for _ in range(3)] == [True, True, False]
    assert [tier.tracked_client_count() for tier in limiter.limiters] == [0, 0, 1]


@pytest.mark.parametrize("case", TIER_CASES)
def test_each_tier_recovers_after_its_window(case: TierCase) -> None:
    clock = FakeClock()
    limiter = TieredSlidingWindowLimiter(1, JOIN_WINDOW_SECONDS, clock=clock)
    allowed = case.clients_allowed_at_base_cap_1
    keys_by_client = [
        client_keys_of_address(case.address_for_number(number)) for number in range(allowed + 1)
    ]
    assert [limiter.try_acquire(keys) for keys in keys_by_client] == [True] * allowed + [False]

    clock.now += JOIN_WINDOW_SECONDS - 1.0
    assert not limiter.try_acquire(keys_by_client[-1])
    clock.now += 1.1  # just over the window since the first event
    assert limiter.try_acquire(keys_by_client[-1])


def test_maps_stay_bounded_under_many_distinct_prefixes() -> None:
    tiers = (ClientTier(48, 16, 5), ClientTier(56, 4, 10), ClientTier(64, 1, 50))
    limiter = TieredSlidingWindowLimiter(5, 60.0, tiers=tiers, clock=FakeClock())
    for number in range(500):
        client_ip = group_client_ip(f"2001:db8:{number:x}:1::5")
        assert limiter.try_acquire(client_keys_for_ip(client_ip, tiers))
        tracked_counts = [tier.tracked_client_count() for tier in limiter.limiters]
        assert all(
            count <= tier.max_tracked_clients
            for count, tier in zip(tracked_counts, tiers, strict=True)
        )
    assert [tier.tracked_client_count() for tier in limiter.limiters] == [5, 10, 50]


def test_many_slash_64s_of_one_slash_48_cannot_evict_its_coarse_entries() -> None:
    tiers = (ClientTier(48, 1, 50), ClientTier(56, 1, 50), ClientTier(64, 1, 50))
    limiter = TieredSlidingWindowLimiter(1000, 60.0, tiers=tiers, clock=FakeClock())
    for number in range(500):  # 500 /64s in two /56s (2001:db8:1::/56 and 2001:db8:1:100::/56)
        client_ip = group_client_ip(f"2001:db8:1:{number:x}::5")
        assert limiter.try_acquire(client_keys_for_ip(client_ip, tiers))
    slash_48_counts, slash_56_counts, slash_64_counts = event_counts_by_tier(limiter)
    assert [count for _, count in slash_48_counts] == [500]  # one entry: nothing evicted or reset
    assert [count for _, count in slash_56_counts] == [256, 244]
    assert len(slash_64_counts) == 50


def test_tiered_connection_limiter_takes_and_gives_back_every_tier_together() -> None:
    limiter = TieredConnectionLimiter(1, 3)
    ipv6_keys = client_keys_of_address(IPV6_CLIENT_IP)
    assert limiter.try_acquire(ipv6_keys)
    assert limiter.try_acquire(client_keys_for_ip(CLIENT_IP))
    assert connection_counts_by_tier(limiter) == [1, 1, 2]
    assert limiter.total_connection_count == 2

    assert not limiter.try_acquire(ipv6_keys)  # its /64 is full: no tier takes a slot
    assert connection_counts_by_tier(limiter) == [1, 1, 2]

    limiter.release(ipv6_keys)
    limiter.release(client_keys_for_ip(CLIENT_IP))
    assert_no_connections_counted(limiter)


def test_tiered_connection_total_cap_is_enforced_by_the_finest_tier() -> None:
    limiter = TieredConnectionLimiter(5, 2)
    assert limiter.try_acquire(client_keys_of_address("2001:db8:1:1::5"))
    assert limiter.try_acquire(client_keys_of_address("2001:db8:2:1::5"))
    third_keys = client_keys_of_address("2001:db8:3:1::5")

    # Refused by the global cap of 2, though its own /48, /56 and /64 hold no connection.
    assert not limiter.try_acquire(third_keys)

    assert connection_counts_by_tier(limiter) == [2, 2, 2]
    assert all(
        third_keys[index] not in limiter.limiters[index].connection_count_by_client_key
        for index in range(3)
    )


# --- IPv6 tiers through the consumer ---------------------------------------------------------


@pytest.mark.parametrize("case", TIER_CASES)
async def test_each_tier_refuses_joins_over_its_cap(
    case: TierCase, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # A base cap of 1 join: the /64 allows 1, the /56 4 and the /48 16 per window.
    join_limiter = TieredSlidingWindowLimiter(1, JOIN_WINDOW_SECONDS, clock=FakeClock())
    monkeypatch.setattr(consumers, "join_limiter", join_limiter)
    caplog.set_level(logging.DEBUG)
    allowed = case.clients_allowed_at_base_cap_1
    for number in range(allowed):
        client, answer = await join_once(number, case.address_for_number(number))
        assert answer["type"] == "joined"
        await client.disconnect()  # so no connection cap plays a part
    counts_before_refusal = event_counts_by_tier(join_limiter)

    refused = await open_connected_client(case.address_for_number(allowed))
    await assert_connected_then_refused_on_join(refused, 100)

    assert event_counts_by_tier(join_limiter) == counts_before_refusal
    neighbour, neighbour_answer = await join_once(101, case.neighbour_address)
    assert neighbour_answer["type"] == "joined"
    await neighbour.disconnect()
    assert "2001:db8" not in caplog.text


@pytest.mark.parametrize("case", COARSE_TIER_CASES)
async def test_join_refused_by_a_coarse_tier_charges_no_finer_tier(
    case: TierCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    join_limiter = TieredSlidingWindowLimiter(1, JOIN_WINDOW_SECONDS, clock=FakeClock())
    monkeypatch.setattr(consumers, "join_limiter", join_limiter)
    allowed = case.clients_allowed_at_base_cap_1
    for number in range(allowed):
        client, _ = await join_once(number, case.address_for_number(number))
        await client.disconnect()

    refused_address = case.address_for_number(allowed)
    refused = await open_connected_client(refused_address)
    await assert_connected_then_refused_on_join(refused, 100)

    refused_keys = client_keys_of_address(refused_address)
    for tier_index in range(case.tier_index + 1, len(CLIENT_TIERS)):
        finer_tier = join_limiter.limiters[tier_index]
        assert refused_keys[tier_index] not in finer_tier.event_times_by_client_key
        assert finer_tier.tracked_client_count() == allowed


@override_settings(TURN_SHARED_SECRET=SECRET, TURN_URLS=TURN_URLS)
@pytest.mark.parametrize("case", TIER_CASES)
async def test_each_tier_withholds_turn_credentials_over_its_cap(
    case: TierCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A base cap of 1 credential: the /64 gets 1, the /56 4 and the /48 16 per window. Joins
    # keep their real caps, which these few joins stay under.
    credential_limiter = TieredSlidingWindowLimiter(
        1, TURN_CREDENTIAL_WINDOW_SECONDS, clock=FakeClock()
    )
    monkeypatch.setattr(consumers, "turn_credential_limiter", credential_limiter)
    allowed = case.clients_allowed_at_base_cap_1
    for number in range(allowed):
        client, answer = await join_once(number, case.address_for_number(number))
        assert answer["type"] == "joined"
        assert "turn" in answer
        await client.disconnect()
    counts_before_refusal = event_counts_by_tier(credential_limiter)

    refused, refused_answer = await join_once(100, case.address_for_number(allowed))

    assert refused_answer["type"] == "joined"  # the join still works...
    assert "turn" not in refused_answer  # ...without a relay
    assert event_counts_by_tier(credential_limiter) == counts_before_refusal
    await refused.disconnect()
    neighbour, neighbour_answer = await join_once(101, case.neighbour_address)
    assert neighbour_answer["type"] == "joined"
    assert "turn" in neighbour_answer
    await neighbour.disconnect()


@override_settings(TURN_SHARED_SECRET=SECRET, TURN_URLS=TURN_URLS)
@pytest.mark.parametrize("case", COARSE_TIER_CASES)
async def test_credential_refused_by_a_coarse_tier_charges_no_finer_tier(
    case: TierCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    credential_limiter = TieredSlidingWindowLimiter(
        1, TURN_CREDENTIAL_WINDOW_SECONDS, clock=FakeClock()
    )
    monkeypatch.setattr(consumers, "turn_credential_limiter", credential_limiter)
    allowed = case.clients_allowed_at_base_cap_1
    for number in range(allowed):
        client, _ = await join_once(number, case.address_for_number(number))
        await client.disconnect()

    refused_address = case.address_for_number(allowed)
    refused, refused_answer = await join_once(100, refused_address)
    assert refused_answer["type"] == "joined"
    assert "turn" not in refused_answer
    await refused.disconnect()

    refused_keys = client_keys_of_address(refused_address)
    for tier_index in range(case.tier_index + 1, len(CLIENT_TIERS)):
        finer_tier = credential_limiter.limiters[tier_index]
        assert refused_keys[tier_index] not in finer_tier.event_times_by_client_key
        assert finer_tier.tracked_client_count() == allowed


@pytest.mark.parametrize("case", TIER_CASES)
async def test_each_tier_refuses_connections_over_its_cap(
    case: TierCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A base cap of 1 connection: the /64 holds 1, the /56 4 and the /48 16 at once.
    connection_limiter = TieredConnectionLimiter(1, MAX_CONNECTIONS_TOTAL)
    monkeypatch.setattr(consumers, "connection_limiter", connection_limiter)
    allowed = case.clients_allowed_at_base_cap_1
    accepted = [
        await open_connected_client(case.address_for_number(number)) for number in range(allowed)
    ]
    slots_before_refusal = connection_counts_by_tier_and_key(connection_limiter)

    refused = open_client(case.address_for_number(allowed))
    connected, _ = await refused.connect()
    assert connected  # accepted, then told `rate-limited` and closed
    # Right after connect() returns, before the close is read: it holds no slot in any tier.
    assert connection_limiter.total_connection_count == allowed
    assert connection_counts_by_tier_and_key(connection_limiter) == slots_before_refusal
    await assert_refused_with_rate_limited(refused)
    assert connection_counts_by_tier_and_key(connection_limiter) == slots_before_refusal

    neighbour = await open_connected_client(case.neighbour_address)
    await neighbour.send_to(text_data=PING)
    assert json.loads(await neighbour.receive_from()) == PONG
    for client in [*accepted, neighbour]:
        await client.disconnect()
    assert_no_connections_counted(connection_limiter)


async def test_ipv4_clients_never_touch_the_coarse_tiers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    join_limiter = TieredSlidingWindowLimiter(5, JOIN_WINDOW_SECONDS, clock=FakeClock())
    monkeypatch.setattr(consumers, "join_limiter", join_limiter)
    clients = []
    for number in range(5):
        client, answer = await join_once(number)
        assert answer["type"] == "joined"
        clients.append(client)
    assert [tier.tracked_client_count() for tier in join_limiter.limiters] == [0, 0, 1]
    assert connection_counts_by_tier(consumers.connection_limiter) == [0, 0, 5]
    for client in clients:
        await client.disconnect()


async def test_forged_forwarded_for_from_an_untrusted_peer_does_not_pick_the_prefixes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No proxy is trusted, so the forged header is ignored and the peer's own prefixes count.
    join_limiter = TieredSlidingWindowLimiter(1, JOIN_WINDOW_SECONDS, clock=FakeClock())
    monkeypatch.setattr(consumers, "join_limiter", join_limiter)
    client, answer = await join_once(1, IPV6_CLIENT_IP, forwarded_for=OTHER_48_IP)
    assert answer["type"] == "joined"
    await client.disconnect()

    refused = open_client(IPV6_CLIENT_IP, forwarded_for="2001:db8:3:1::5")
    await refused.connect()
    await assert_connected_then_refused_on_join(refused, 2)

    other, other_answer = await join_once(3, OTHER_48_IP)
    assert other_answer["type"] == "joined"  # the forged prefixes were never charged
    await other.disconnect()


@pytest.mark.parametrize("proxy_ip", [PROXY_IP, "2001:db8:ffff::10"])
async def test_behind_a_trusted_proxy_every_tier_counts_the_rightmost_entry(
    proxy_ip: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    trusted_application = _application_trusting(monkeypatch, proxy_ip)
    real_ip = "2001:db8:a:1::5"  # /48 A, added by the proxy
    forged_ip = "2001:db8:b:1::5"  # /48 B, sent by the client
    client = _client_for(trusted_application, proxy_ip, f"{forged_ip}, {real_ip}")
    await client.connect()
    await client.send_to(text_data=join_text(1))
    assert json.loads(await client.receive_from())["type"] == "joined"

    # Every tier holds A's key only: not B's, and not the proxy's.
    real_keys = client_keys_of_address(real_ip)
    joins_by_tier = [
        list(tier.event_times_by_client_key) for tier in consumers.join_limiter.limiters
    ]
    assert joins_by_tier == [[key] for key in real_keys]
    assert connection_counts_by_tier_and_key(consumers.connection_limiter) == [
        {key: 1} for key in real_keys
    ]
    await client.disconnect()


# 203.0.113.7 (CLIENT_IP) inside each kind of transition address.
TRANSITION_ADDRESSES_OF_CLIENT_IP = [
    pytest.param("2002:cb00:7107::1", id="6to4"),
    pytest.param("2001:0:4136:e378:8000:63bf:34ff:8ef8", id="teredo"),
    pytest.param("64:ff9b::203.0.113.7", id="nat64"),
]


@pytest.mark.parametrize("transition_ip", TRANSITION_ADDRESSES_OF_CLIENT_IP)
async def test_transition_address_shares_the_bucket_of_its_ipv4(
    transition_ip: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    join_limiter = TieredSlidingWindowLimiter(1, JOIN_WINDOW_SECONDS, clock=FakeClock())
    monkeypatch.setattr(consumers, "join_limiter", join_limiter)
    ipv4_client, ipv4_answer = await join_once(1, CLIENT_IP)
    assert ipv4_answer["type"] == "joined"
    await ipv4_client.disconnect()

    transition_client = await open_connected_client(transition_ip)
    await assert_connected_then_refused_on_join(transition_client, 2)

    # Counted as IPv4: once, by the finest tier, with no /48 or /56 of its own.
    assert [tier.tracked_client_count() for tier in join_limiter.limiters] == [0, 0, 1]
