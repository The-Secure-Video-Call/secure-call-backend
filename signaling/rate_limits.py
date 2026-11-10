"""In-memory rate limits (PLAN.md section 3): joins and TURN credentials per client IP, and
messages per connection.

Privacy rules:
- everything lives in memory only: nothing is written to disk, and a restart forgets it all;
- nothing is logged here, and no IP address or room ID appears in any error text;
- counters are keyed by an HMAC of the IP with a random per-process key (`client_key_for_ip`),
  so raw addresses are not kept in the maps;
- entries expire when their window passes, and at most MAX_TRACKED_CLIENTS keys are kept
  (the least recently active is evicted first), so memory cannot grow without bound.

The clock is passed in so tests can fake it. With several server processes each one counts on
its own, so the effective limit is the limit times the number of processes.
"""

import hashlib
import hmac
import secrets
import time
from collections import OrderedDict, deque
from collections.abc import Callable

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
# exist; about 7 credentials fill it (see deploy/raspberry-pi/README.md). The per-room budget
# (`MAX_TURN_CREDENTIALS_PER_ROOM` in rooms.py) is separate; it resets when a room empties, so
# it does not stop a client that rejoins or creates rooms.
MAX_TURN_CREDENTIALS_PER_WINDOW = 120
TURN_CREDENTIAL_WINDOW_SECONDS = 3600.0

# Messages per connection: a token bucket. ICE candidates arrive in bursts, so allow 100 at
# once and refill 20 per second.
MESSAGES_REFILLED_PER_SECOND = 20.0
MESSAGE_BURST_SIZE = 100

# Most client keys one limiter keeps. When full, the least recently active key is evicted.
MAX_TRACKED_CLIENTS = 10_000

Clock = Callable[[], float]

# Random per process and never stored or logged: the HMAC key for the counter keys only.
_client_key_secret = secrets.token_bytes(32)


def client_key_for_ip(client_ip: str) -> bytes:
    """Counter key for a client IP: an HMAC, so the raw address is not kept in the maps."""
    return hmac.new(_client_key_secret, client_ip.encode("utf-8"), hashlib.sha256).digest()


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

    def drop_expired_clients(self, window_start: float) -> None:
        while self.event_times_by_client_key:
            oldest_client_key = next(iter(self.event_times_by_client_key))
            if self.event_times_by_client_key[oldest_client_key][-1] > window_start:
                return
            del self.event_times_by_client_key[oldest_client_key]

    def tracked_client_count(self) -> int:
        return len(self.event_times_by_client_key)


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


def new_message_bucket() -> TokenBucket:
    return TokenBucket(MESSAGES_REFILLED_PER_SECOND, MESSAGE_BURST_SIZE)
