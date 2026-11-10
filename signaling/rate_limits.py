"""In-memory limits (PLAN.md section 3): joins and TURN credentials per client, open connections
per client and in total, and messages per connection.

Privacy rules:
- everything lives in memory only: nothing is written to disk, and a restart forgets it all;
- nothing is logged here, and no IP address or room ID appears in any error text;
- counters are keyed by an HMAC of the address or prefix with a random per-process key
  (`client_keys_for_ip`), so raw addresses are not kept in the maps;
- entries expire when their window passes, and each map keeps at most its tier's
  `max_tracked_clients` keys (the least recently active is evicted first), so memory cannot grow
  without bound (worst case below).

Client tiers (CLIENT_TIERS). An IPv4 address is one client, counted once. An IPv6 client is
counted three times: by its /64 with the per-client caps, by its /56 with 4 times them and by its
/48 with 16 times them. One customer can hold 256 (/56) or 65,536 (/48) /64s, and many ISPs hand
each household a /56 or a /60 out of a /48 shared by 256 or more households (RIPE-690), so a
single coarse /48 tier would let one household lock out its neighbours. With three tiers:
- an action must pass every tier. All tiers are checked first and charged only if all allow it,
  coarsest first, so a refusal by any tier charges nothing anywhere and adds, moves or evicts no
  map entry: fresh /64s of a /48 over its cap cannot push other clients' entries out;
- one /64 can use at most a quarter of its /56, and one /56 at most a quarter of its /48.
  An IPv6 transition address (6to4, Teredo, NAT64) is counted as the IPv4 address inside it
  (client_address.py), so it gets no coarse tiers.

What is still possible:
- 4 /64s use up their /56, and 4 /56s (16 /64s spread over them) use up their /48. A customer
  with a /60 (16 /64s) can lock out the other customers of its /56, and someone with 4 /56s (or a
  /54) the rest of its /48;
- ISPs that put many customers' /64s in one /48 or /56 (mobile carriers) share its caps among
  them;
- a holder of many /48s scales linearly: each /48 gets 16 times the per-client caps. A tunnel
  broker gives out routed /48s for free, and an LIR's /29 holds 524,288 of them;
- the /48 connection cap (320) is 64% of MAX_CONNECTIONS_TOTAL (500), so two /48s fill every
  connection slot of the process (over IPv4 it takes 25 addresses). Smaller coarse connection
  caps would bring back the lockout of a /48's other customers, for connections;
- eviction resets an entry's counters. A full map evicts its least recently charged key, and a
  refused request does not count as activity, so an entry goes once `max_tracked_clients` other
  prefixes of its tier (500 /48s, 1,000 /56s, 10,000 /64s or IPv4 addresses) have been charged
  after its last allowed event. They need not be the abuser's: a server with that many active
  prefixes per window evicts capped entries by itself, and someone with more than that many can
  cycle them so that the tier no longer limits them (the finer tiers still do). Eviction only
  lowers counts, so it never locks anyone out.

Memory. A sliding-window map holds up to `max_tracked_clients` keys with up to its cap of event
times each, at about 33 bytes per event time plus about 0.7 KiB per key (CPython 3.14: about
1.4 KiB per key at 20 events, 16 KiB at 480, 61 KiB at 1,920). Worst case per process:
- joins: 500 x 320 + 1,000 x 80 + 10,000 x 20 events, about 22 MiB;
- TURN credentials: 500 x 1,920 + 1,000 x 480 + 10,000 x 120 events, about 92 MiB;
- connections: one count per key, and every tier holds at most MAX_CONNECTIONS_TOTAL keys.
The coarse tiers keep fewer keys than the /64 one because each of their keys holds more events.

The clock is passed in so tests can fake it. With several server processes each one counts on
its own, so the effective limit is the limit times the number of processes.
"""

import hashlib
import hmac
import secrets
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from signaling.client_address import IPV6_PREFIX_LENGTH, ipv6_prefix

# Joins: at most 20 per client per minute. A reconnecting browser retries after 1, 2, 4, 8
# and 15 s for up to 2 minutes (about 8 joins), so this leaves room for a few tabs and retries.
MAX_JOINS_PER_WINDOW = 20
JOIN_WINDOW_SECONDS = 60.0

# TURN credentials: at most 120 per client per hour. Many people can share one address (a
# household, an office, a mobile carrier's NAT), and every join and signaling reconnect uses one,
# so 30 was reached in normal use. Over the limit the join still works but `joined` has no `turn`,
# so a script cannot collect unlimited relay credentials. A credential lives up to 4 h (the room
# lifetime) against this 1 h window, so up to 480 per client can be valid at once. This cap does
# not protect the relay's capacity: coturn's `user-quota` counts per username, and every
# credential has a new one. What the relay carries is capped by its global limits in
# turnserver.conf (41 relay ports, `total-quota`, and `bps-capacity` for about 37 sessions),
# however many credentials exist; about 7 credentials fill it (see "What one client can still
# do" in deploy/raspberry-pi/README.md).
MAX_TURN_CREDENTIALS_PER_WINDOW = 120
TURN_CREDENTIAL_WINDOW_SECONDS = 3600.0

# Messages per connection: a token bucket. ICE candidates arrive in bursts, so allow 100 at
# once and refill 20 per second.
MESSAGES_REFILLED_PER_SECOND = 20.0
MESSAGE_BURST_SIZE = 100

# Open WebSocket connections, counted from accept to disconnect (joined or not). A browser uses
# one per tab, so 20 per client leaves room for a household or office behind one address. The
# global cap keeps many addresses together from exhausting a Raspberry Pi (memory, Daphne slots).
# Over either cap the connection is accepted, told `rate-limited` and closed with 4029 (see
# consumers.py). Counts are per process: with several server processes each one counts on its own.
MAX_CONNECTIONS_PER_CLIENT = 20
MAX_CONNECTIONS_TOTAL = 500

# A connection that has not sent a `join` after this long is closed (code 4008). A browser joins
# right after the socket opens, so 10 s leaves room for a slow mobile network.
JOIN_TIMEOUT_SECONDS = 10.0

# Most client keys the /64 (and IPv4) map keeps. When full, the least recently active key is
# evicted.
MAX_TRACKED_CLIENTS = 10_000


@dataclass(frozen=True)
class ClientTier:
    """One way of grouping clients: IPv6 addresses by `ipv6_prefix_length` bits, with
    `cap_factor` times the per-client caps, in a map of at most `max_tracked_clients` keys.
    The finest tier also counts IPv4 addresses; the coarser ones count IPv6 only."""

    ipv6_prefix_length: int
    cap_factor: int
    max_tracked_clients: int


# Coarsest first: the order in which every action is checked and then charged.
CLIENT_TIERS: tuple[ClientTier, ...] = (
    ClientTier(ipv6_prefix_length=48, cap_factor=16, max_tracked_clients=500),
    ClientTier(ipv6_prefix_length=56, cap_factor=4, max_tracked_clients=1_000),
    ClientTier(
        ipv6_prefix_length=IPV6_PREFIX_LENGTH,
        cap_factor=1,
        max_tracked_clients=MAX_TRACKED_CLIENTS,
    ),
)

# One counter key per tier of CLIENT_TIERS, in the same order. None where the tier does not
# apply (the coarse tiers for IPv4 and "unknown"); the finest tier always has a key.
ClientKeys = tuple[bytes | None, ...]

Clock = Callable[[], float]

# Random per process and never stored or logged: the HMAC key for the counter keys only.
_client_key_secret = secrets.token_bytes(32)


def client_key_for_ip(client_ip: str) -> bytes:
    """Counter key for a client IP: an HMAC, so the raw address is not kept in the maps."""
    return hmac.new(_client_key_secret, client_ip.encode("utf-8"), hashlib.sha256).digest()


def ipv6_prefix_key_for_ip(client_ip: str, prefix_length: int) -> bytes | None:
    """Counter key for the IPv6 prefix of `prefix_length` bits that contains `client_ip` (same
    secret, the length is part of the text), or None for IPv4 and "unknown"."""
    prefix = ipv6_prefix(client_ip, prefix_length)
    if prefix is None:
        return None
    return hmac.new(
        _client_key_secret, f"/{prefix_length}:{prefix}".encode(), hashlib.sha256
    ).digest()


def client_keys_for_ip(client_ip: str, tiers: Sequence[ClientTier] = CLIENT_TIERS) -> ClientKeys:
    """The counter key of `client_ip` (`scope["client_ip"]`) in every tier, coarsest first.

    The finest tier's key is `client_key_for_ip(client_ip)`: the IPv4 address or IPv6 /64 that
    ClientAddressMiddleware grouped it to. The coarser tiers key IPv6 by their own prefix.
    """
    *coarse_tiers, _finest_tier = tiers
    coarse_keys = [
        ipv6_prefix_key_for_ip(client_ip, tier.ipv6_prefix_length) for tier in coarse_tiers
    ]
    return (*coarse_keys, client_key_for_ip(client_ip))


def pair_limiters_with_keys[Limiter](
    limiters: Sequence[Limiter], client_keys: ClientKeys
) -> list[tuple[Limiter, bytes]]:
    """Each tier's limiter with the client's key in that tier, coarsest first, skipping the tiers
    the client has no key in. The keys must be for the same tiers as the limiters."""
    return [
        (limiter, client_key)
        for limiter, client_key in zip(limiters, client_keys, strict=True)
        if client_key is not None
    ]


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
        if not self.can_acquire(client_key, now):
            return False  # refused events are not counted, so a patient client gets back in
        self.record_event(client_key, now)
        return True

    def can_acquire(self, client_key: bytes, now: float) -> bool:
        """Whether one more event at `now` is within the cap.

        Counts nothing, and adds, moves or evicts no key: it only forgets expired events.
        """
        window_start = now - self.window_seconds
        self.drop_expired_clients(window_start)
        event_times = self.event_times_by_client_key.get(client_key)
        if event_times is None:
            return self.max_events > 0
        while event_times and event_times[0] <= window_start:
            event_times.popleft()
        if not event_times:
            # Defensive: cannot happen while the map is ordered by newest event (above), but an
            # empty key must never stay, or drop_expired_clients would fail on it.
            del self.event_times_by_client_key[client_key]
        return len(event_times) < self.max_events

    def record_event(self, client_key: bytes, now: float) -> None:
        """Count one event at `now`. Only after `can_acquire(client_key, now)` said yes."""
        event_times = self.event_times_by_client_key.get(client_key)
        if event_times is None:
            while len(self.event_times_by_client_key) >= self.max_tracked_clients:
                self.event_times_by_client_key.popitem(last=False)
            event_times = deque()
            self.event_times_by_client_key[client_key] = event_times
        event_times.append(now)
        self.event_times_by_client_key.move_to_end(client_key)

    def drop_expired_clients(self, window_start: float) -> None:
        while self.event_times_by_client_key:
            oldest_client_key = next(iter(self.event_times_by_client_key))
            if self.event_times_by_client_key[oldest_client_key][-1] > window_start:
                return
            del self.event_times_by_client_key[oldest_client_key]

    def tracked_client_count(self) -> int:
        return len(self.event_times_by_client_key)


class TieredSlidingWindowLimiter:
    """One SlidingWindowLimiter per client tier, with the tier's `cap_factor` times `max_events`
    and the same window.

    `try_acquire` checks every tier that has a key, coarsest first, and charges them all only if
    all of them allow it (at one clock reading), so a refusal anywhere charges nothing anywhere.
    """

    def __init__(
        self,
        max_events: int,
        window_seconds: float,
        tiers: Sequence[ClientTier] = CLIENT_TIERS,
        clock: Clock = time.monotonic,
    ) -> None:
        self.clock = clock
        self.limiters = tuple(
            SlidingWindowLimiter(
                max_events * tier.cap_factor, window_seconds, tier.max_tracked_clients, clock
            )
            for tier in tiers
        )

    def try_acquire(self, client_keys: ClientKeys) -> bool:
        now = self.clock()
        limiters_with_keys = pair_limiters_with_keys(self.limiters, client_keys)
        if not all(
            limiter.can_acquire(client_key, now) for limiter, client_key in limiters_with_keys
        ):
            return False
        for limiter, client_key in limiters_with_keys:
            limiter.record_event(client_key, now)
        return True


class ConnectionLimiter:
    """Counts open connections per client key and, when `max_total` is set, in total.

    `try_acquire` takes a slot and `release` gives it back. A key is deleted when its count
    reaches zero, so the map holds at most as many keys as there are open connections. `release`
    of an unknown key does nothing, so a count can never go negative.
    """

    def __init__(self, max_per_client: int, max_total: int | None) -> None:
        self.max_per_client = max_per_client
        self.max_total = max_total
        self.connection_count_by_client_key: dict[bytes, int] = {}
        self.total_connection_count = 0

    def try_acquire(self, client_key: bytes) -> bool:
        if not self.can_acquire(client_key):
            return False
        self.acquire(client_key)
        return True

    def can_acquire(self, client_key: bytes) -> bool:
        """Whether one more connection fits. Changes nothing."""
        if self.max_total is not None and self.total_connection_count >= self.max_total:
            return False
        return self.connection_count_by_client_key.get(client_key, 0) < self.max_per_client

    def acquire(self, client_key: bytes) -> None:
        """Take a slot. Only after `can_acquire(client_key)` said yes."""
        client_connection_count = self.connection_count_by_client_key.get(client_key, 0)
        self.connection_count_by_client_key[client_key] = client_connection_count + 1
        self.total_connection_count += 1

    def release(self, client_key: bytes) -> None:
        client_connection_count = self.connection_count_by_client_key.get(client_key)
        if client_connection_count is None:
            return
        if client_connection_count <= 1:
            del self.connection_count_by_client_key[client_key]
        else:
            self.connection_count_by_client_key[client_key] = client_connection_count - 1
        self.total_connection_count -= 1


class TieredConnectionLimiter:
    """One ConnectionLimiter per client tier, with the tier's `cap_factor` times
    `max_per_client`.

    Only the finest tier has the `max_total` cap: every connection (IPv4 too) has a key there, so
    it alone can enforce the total. A coarse tier counts IPv6 only, so a total cap there could
    never be the one that refuses. A coarse tier is charged only together with the finest one,
    so its map too holds at most `max_total` keys.

    `try_acquire` checks every tier that has a key and takes a slot in all of them only if all
    of them allow it; `release` gives back the slot in every one of them.
    """

    def __init__(
        self, max_per_client: int, max_total: int, tiers: Sequence[ClientTier] = CLIENT_TIERS
    ) -> None:
        *coarse_tiers, finest_tier = tiers
        self.limiters = (
            *(ConnectionLimiter(max_per_client * tier.cap_factor, None) for tier in coarse_tiers),
            ConnectionLimiter(max_per_client * finest_tier.cap_factor, max_total),
        )

    @property
    def total_connection_count(self) -> int:
        return self.limiters[-1].total_connection_count

    def try_acquire(self, client_keys: ClientKeys) -> bool:
        limiters_with_keys = pair_limiters_with_keys(self.limiters, client_keys)
        if not all(limiter.can_acquire(client_key) for limiter, client_key in limiters_with_keys):
            return False
        for limiter, client_key in limiters_with_keys:
            limiter.acquire(client_key)
        return True

    def release(self, client_keys: ClientKeys) -> None:
        for limiter, client_key in pair_limiters_with_keys(self.limiters, client_keys):
            limiter.release(client_key)


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


def new_join_limiter() -> TieredSlidingWindowLimiter:
    return TieredSlidingWindowLimiter(MAX_JOINS_PER_WINDOW, JOIN_WINDOW_SECONDS)


def new_turn_credential_limiter() -> TieredSlidingWindowLimiter:
    return TieredSlidingWindowLimiter(
        MAX_TURN_CREDENTIALS_PER_WINDOW, TURN_CREDENTIAL_WINDOW_SECONDS
    )


def new_connection_limiter() -> TieredConnectionLimiter:
    return TieredConnectionLimiter(MAX_CONNECTIONS_PER_CLIENT, MAX_CONNECTIONS_TOTAL)


def new_message_bucket() -> TokenBucket:
    return TokenBucket(MESSAGES_REFILLED_PER_SECOND, MESSAGE_BURST_SIZE)
