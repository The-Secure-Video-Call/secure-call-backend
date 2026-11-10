"""In-memory limits (PLAN.md section 3): joins and TURN credentials per client IP, open
connections per client IP and in total, and messages per connection.

Privacy rules:
- everything lives in memory only: nothing is written to disk, and a restart forgets it all;
- nothing is logged here, and no IP address or room ID appears in any error text;
- counters are keyed by an HMAC of the IP with a random per-process key (`client_key_for_ip`),
  so raw addresses are not kept in the maps;
- entries expire when their window passes, and at most MAX_TRACKED_CLIENTS keys are kept
  (the least recently active is evicted first), so memory cannot grow without bound.

IPv6 clients are counted twice: by /64 (the fine key, the same caps as one IPv4 address) and by
/48 (the coarse key, with COARSE_CAP_FACTOR times the caps), because one customer can control
65,536 /64s and each would otherwise get its own limits and map entries. An action must pass both.
The coarse limiter is charged first and given back when the fine one refuses, so a refusal never
leaves a charge, and a /48 over its cap never touches (or evicts from) the fine map. IPv4 has no
coarse key and is counted once, as before. A /48 is one map entry however many /64s it uses, so
evicting entries (which resets counters) takes MAX_TRACKED_CLIENTS distinct /48s active within
the window, each a separate customer allocation; /64s of one /48 cannot do it.

The clock is passed in so tests can fake it. With several server processes each one counts on
its own, so the effective limit is the limit times the number of processes.
"""

import hashlib
import hmac
import secrets
import time
from collections import OrderedDict, deque
from collections.abc import Callable

from signaling.client_address import coarse_ipv6_prefix

# Joins: at most 20 per client IP per minute. A reconnecting browser retries after 1, 2, 4, 8
# and 15 s for up to 2 minutes (about 8 joins), so this leaves room for a few tabs and retries.
MAX_JOINS_PER_WINDOW = 20
JOIN_WINDOW_SECONDS = 60.0

# TURN credentials: at most 120 per client IP per hour. Many people can share one address (a
# household, an office, a mobile carrier's NAT), and every join and signaling reconnect uses one,
# so 30 was reached in normal use. Over the limit the join still works but `joined` has no `turn`,
# so a script cannot collect unlimited relay credentials. A credential lives up to 4 h (the room
# lifetime) against this 1 h window, so up to 480 per IP can be valid at once. This cap does not
# protect the relay's capacity: coturn's `user-quota` counts per username, and every credential
# has a new one. What the relay carries is capped by its global limits in turnserver.conf (41
# relay ports, `total-quota`, and `bps-capacity` for about 37 sessions), however many credentials
# exist; about 7 credentials fill it (see "What one client can still do" in
# deploy/raspberry-pi/README.md).
MAX_TURN_CREDENTIALS_PER_WINDOW = 120
TURN_CREDENTIAL_WINDOW_SECONDS = 3600.0

# Messages per connection: a token bucket. ICE candidates arrive in bursts, so allow 100 at
# once and refill 20 per second.
MESSAGES_REFILLED_PER_SECOND = 20.0
MESSAGE_BURST_SIZE = 100

# Open WebSocket connections, counted from accept to disconnect (joined or not). A browser uses
# one per tab, so 20 per client IP leaves room for a household or office behind one address. The
# global cap keeps many addresses together from exhausting a Raspberry Pi (memory, Daphne slots).
# Over either cap the connection is accepted, told `rate-limited` and closed with 4029 (see
# consumers.py). Counts are per process: with several server processes each one counts on its own.
MAX_CONNECTIONS_PER_CLIENT = 20
MAX_CONNECTIONS_TOTAL = 500

# A connection that has not sent a `join` after this long is closed (code 4008). A browser joins
# right after the socket opens, so 10 s leaves room for a slow mobile network.
JOIN_TIMEOUT_SECONDS = 10.0

# The coarse (IPv6 /48) caps are this many times the per-/64 caps: a /48 may hold several
# households or an office, but not 65,536 times one client. The global connection cap is unchanged.
COARSE_CAP_FACTOR = 4
MAX_JOINS_PER_WINDOW_COARSE = COARSE_CAP_FACTOR * MAX_JOINS_PER_WINDOW
MAX_TURN_CREDENTIALS_PER_WINDOW_COARSE = COARSE_CAP_FACTOR * MAX_TURN_CREDENTIALS_PER_WINDOW
MAX_CONNECTIONS_PER_CLIENT_COARSE = COARSE_CAP_FACTOR * MAX_CONNECTIONS_PER_CLIENT

# Most client keys one limiter keeps. When full, the least recently active key is evicted.
MAX_TRACKED_CLIENTS = 10_000

Clock = Callable[[], float]

# Random per process and never stored or logged: the HMAC key for the counter keys only.
_client_key_secret = secrets.token_bytes(32)


def client_key_for_ip(client_ip: str) -> bytes:
    """Counter key for a client IP: an HMAC, so the raw address is not kept in the maps."""
    return hmac.new(_client_key_secret, client_ip.encode("utf-8"), hashlib.sha256).digest()


def coarse_client_key_for_ip(client_ip: str) -> bytes | None:
    """Counter key for the IPv6 /48 of a client IP (same secret), or None for IPv4."""
    prefix = coarse_ipv6_prefix(client_ip)
    if prefix is None:
        return None
    return hmac.new(
        _client_key_secret, b"coarse:" + prefix.encode("utf-8"), hashlib.sha256
    ).digest()


class SlidingWindowLimiter:
    """Allows at most `max_events` per `window_seconds` for each client key."""

    def __init__(
        self,
        max_events: int,
        window_seconds: float,
        max_tracked_clients: int = MAX_TRACKED_CLIENTS,
        clock: Clock = time.monotonic,
    ) -> None:
        self.max_events = max_events
        self.window_seconds = window_seconds
        self.max_tracked_clients = max_tracked_clients
        self.clock = clock
        # Ordered by each key's newest event (oldest first), so expired keys are at the front.
        self.event_times_by_client_key: OrderedDict[bytes, deque[float]] = OrderedDict()

    def try_acquire(self, client_key: bytes) -> bool:
        """Count one event and return True, or return False (counting nothing) when over."""
        now = self.clock()
        window_start = now - self.window_seconds
        self.drop_expired_clients(window_start)
        event_times = self.event_times_by_client_key.get(client_key)
        if event_times is None:
            while len(self.event_times_by_client_key) >= self.max_tracked_clients:
                self.event_times_by_client_key.popitem(last=False)
            event_times = deque()
            self.event_times_by_client_key[client_key] = event_times
        while event_times and event_times[0] <= window_start:
            event_times.popleft()
        if len(event_times) >= self.max_events:
            return False  # refused events are not counted, so a patient client gets back in
        event_times.append(now)
        self.event_times_by_client_key.move_to_end(client_key)
        return True

    def give_back(self, client_key: bytes) -> None:
        """Undo the newest event of a `try_acquire` that just succeeded (nothing ran between)."""
        event_times = self.event_times_by_client_key.get(client_key)
        if event_times is None:
            return
        event_times.pop()
        if not event_times:
            del self.event_times_by_client_key[client_key]  # an empty key must not stay

    def drop_expired_clients(self, window_start: float) -> None:
        while self.event_times_by_client_key:
            oldest_client_key = next(iter(self.event_times_by_client_key))
            if self.event_times_by_client_key[oldest_client_key][-1] > window_start:
                return
            del self.event_times_by_client_key[oldest_client_key]

    def tracked_client_count(self) -> int:
        return len(self.event_times_by_client_key)


def try_acquire_coarse_then_fine(
    fine_limiter: SlidingWindowLimiter,
    coarse_limiter: SlidingWindowLimiter,
    client_key: bytes,
    coarse_client_key: bytes | None,
) -> bool:
    """Charge the coarse limiter, then the fine one; give the coarse one back if fine refuses.

    Coarse goes first on purpose: a /48 over its cap is refused without touching the fine map,
    so fresh /64s from it cannot insert fine entries and evict other clients' entries.
    """
    if coarse_client_key is not None and not coarse_limiter.try_acquire(coarse_client_key):
        return False  # the fine limiter is never touched
    if not fine_limiter.try_acquire(client_key):
        if coarse_client_key is not None:
            coarse_limiter.give_back(coarse_client_key)
        return False
    return True


class ConnectionLimiter:
    """Counts open connections per client key and in total.

    `try_acquire` takes a slot and `release` gives it back. A key is deleted when its count
    reaches zero, so the map holds at most `max_total` keys. `release` of an unknown key does
    nothing, so a count can never go negative.
    """

    def __init__(self, max_per_client: int, max_total: int) -> None:
        self.max_per_client = max_per_client
        self.max_total = max_total
        self.connection_count_by_client_key: dict[bytes, int] = {}
        self.total_connection_count = 0

    def try_acquire(self, client_key: bytes) -> bool:
        if self.total_connection_count >= self.max_total:
            return False
        client_connection_count = self.connection_count_by_client_key.get(client_key, 0)
        if client_connection_count >= self.max_per_client:
            return False
        self.connection_count_by_client_key[client_key] = client_connection_count + 1
        self.total_connection_count += 1
        return True

    def release(self, client_key: bytes) -> None:
        client_connection_count = self.connection_count_by_client_key.get(client_key)
        if client_connection_count is None:
            return
        if client_connection_count <= 1:
            del self.connection_count_by_client_key[client_key]
        else:
            self.connection_count_by_client_key[client_key] = client_connection_count - 1
        self.total_connection_count -= 1


class TokenBucket:
    """Allows bursts up to `burst_size`, refilled at `refill_per_second`."""

    def __init__(
        self, refill_per_second: float, burst_size: int, clock: Clock = time.monotonic
    ) -> None:
        self.refill_per_second = refill_per_second
        self.burst_size = burst_size
        self.clock = clock
        self.tokens = float(burst_size)
        self.last_refill_time = clock()

    def try_take_token(self) -> bool:
        now = self.clock()
        elapsed_seconds = max(0.0, now - self.last_refill_time)
        self.last_refill_time = now
        refilled_tokens = self.tokens + elapsed_seconds * self.refill_per_second
        self.tokens = min(float(self.burst_size), refilled_tokens)
        if self.tokens < 1.0:
            return False
        self.tokens -= 1.0
        return True


def new_join_limiter() -> SlidingWindowLimiter:
    return SlidingWindowLimiter(MAX_JOINS_PER_WINDOW, JOIN_WINDOW_SECONDS)


def new_turn_credential_limiter() -> SlidingWindowLimiter:
    return SlidingWindowLimiter(MAX_TURN_CREDENTIALS_PER_WINDOW, TURN_CREDENTIAL_WINDOW_SECONDS)


def new_connection_limiter() -> ConnectionLimiter:
    return ConnectionLimiter(MAX_CONNECTIONS_PER_CLIENT, MAX_CONNECTIONS_TOTAL)


def new_coarse_join_limiter() -> SlidingWindowLimiter:
    return SlidingWindowLimiter(MAX_JOINS_PER_WINDOW_COARSE, JOIN_WINDOW_SECONDS)


def new_coarse_turn_credential_limiter() -> SlidingWindowLimiter:
    return SlidingWindowLimiter(
        MAX_TURN_CREDENTIALS_PER_WINDOW_COARSE, TURN_CREDENTIAL_WINDOW_SECONDS
    )


def new_coarse_connection_limiter() -> ConnectionLimiter:
    return ConnectionLimiter(MAX_CONNECTIONS_PER_CLIENT_COARSE, MAX_CONNECTIONS_TOTAL)


def new_message_bucket() -> TokenBucket:
    return TokenBucket(MESSAGES_REFILLED_PER_SECOND, MESSAGE_BURST_SIZE)
