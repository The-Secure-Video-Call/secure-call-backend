"""Room membership and expiry: which connections are in which room, and for how long.

State lives in this process's memory behind a lock, so it is only correct with ONE server
process. Nothing is written to disk. Message relaying already goes through the Channels layer
(see consumers.py), so moving to several processes means replacing `RoomRegistry` with a
Redis-backed one (atomic add/remove of members, e.g. a Lua script; expiry as key TTLs plus a
notification to the members' channels); the consumer would not change. Room IDs are never logged.

Expiry: a room is closed after `WAITING_ALONE_LIMIT_SECONDS` with exactly one member, or
`TOTAL_LIFETIME_LIMIT_SECONDS` after it was created. Joining the same room ID afterwards simply
creates a new room (no list of old room IDs is kept).
"""

import asyncio
import contextlib
import hashlib
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Final, Literal

from channels.layers import get_channel_layer

MAX_MEMBERS_PER_ROOM: Final = 2
# Production expiry limits (PLAN.md section 7). Fixed in code on purpose: not environment variables.
WAITING_ALONE_LIMIT_SECONDS: Final = 10 * 60
TOTAL_LIFETIME_LIMIT_SECONDS: Final = 4 * 60 * 60
# TURN credentials one room may be given over its life: 2 members plus reconnects (the web client
# reconnects with backoff and every join gets fresh credentials). A guard against runaway
# reconnects only: the count dies with the room (no old room IDs are kept), so leaving and
# rejoining, or creating rooms, is not stopped. Shared by both members (see README.md).
MAX_TURN_CREDENTIALS_PER_ROOM: Final = 20

Role = Literal["first", "second"]
NotifyRoomExpired = Callable[[str, list[str]], Awaitable[None]]


def group_name_for_room(room_id: str) -> str:
    """Channels group name for a room. Hashed so the room ID itself never reaches the layer."""
    return "room." + hashlib.sha256(room_id.encode("ascii")).hexdigest()


async def send_room_expired_to_channels(room_id: str, channel_names: list[str]) -> None:
    """Remove each connection from the room's group, then tell it the room expired.

    Runs while the registry lock is held, so the room ID cannot be reused before the old
    connections are out of the group. The consumer then sends the error and closes. A failure for
    one connection must not stop the others from being told.
    """
    channel_layer = get_channel_layer()
    if channel_layer is None:
        return
    group_name = group_name_for_room(room_id)
    for channel_name in channel_names:
        with contextlib.suppress(Exception):
            await channel_layer.group_discard(group_name, channel_name)
        with contextlib.suppress(Exception):
            await channel_layer.send(
                channel_name, {"type": "room_expired", "group_name": group_name}
            )


@dataclass
class _Room:
    channel_names: list[str] = field(default_factory=list)
    waiting_alone_timer: asyncio.Task[None] | None = None
    total_lifetime_timer: asyncio.Task[None] | None = None
    # When the total-lifetime limit closes the room, on the monotonic clock that asyncio's timer
    # also uses (so wall-clock steps, for example NTP after boot, cannot skew it).
    closes_at_monotonic_time: float = 0.0
    # Credentials handed out for this room so far. Dies with the room, so a recreated room ID
    # starts again at 0 (no list of old room IDs is kept).
    turn_credentials_issued: int = 0


class RoomRegistry:
    """Rooms and their expiry timers.

    Two timers per room: a waiting timer that runs while exactly one member is present, and a
    total-lifetime timer that runs from room creation. When either fires, the room is removed and
    its members are told via `notify_room_expired`. Timers are cancelled when the room empties.
    """

    def __init__(
        self,
        waiting_alone_limit_seconds: float = WAITING_ALONE_LIMIT_SECONDS,
        total_lifetime_limit_seconds: float = TOTAL_LIFETIME_LIMIT_SECONDS,
        notify_room_expired: NotifyRoomExpired = send_room_expired_to_channels,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._rooms_by_room_id: dict[str, _Room] = {}
        self._lock = asyncio.Lock()
        self._waiting_alone_limit_seconds = waiting_alone_limit_seconds
        self._total_lifetime_limit_seconds = total_lifetime_limit_seconds
        self._notify_room_expired = notify_room_expired
        self._monotonic_clock = monotonic_clock

    async def add_member(
        self,
        room_id: str,
        channel_name: str,
        run_while_locked_after_adding: Callable[[], Awaitable[None]] | None = None,
    ) -> Role | None:
        """Add a member. Returns its role, or None when the room already has two members.

        `run_while_locked_after_adding` runs before the lock is released, so the next join of the
        same room cannot start until this member is fully set up (no lost `peer-joined`).
        """
        async with self._lock:
            room = self._rooms_by_room_id.get(room_id)
            if room is None:
                room = _Room(
                    closes_at_monotonic_time=self._monotonic_clock()
                    + self._total_lifetime_limit_seconds
                )
                self._rooms_by_room_id[room_id] = room
                room.total_lifetime_timer = asyncio.create_task(
                    self._expire_after(
                        self._total_lifetime_limit_seconds, room_id, room, only_if_alone=False
                    )
                )
            if len(room.channel_names) >= MAX_MEMBERS_PER_ROOM:
                return None
            room.channel_names.append(channel_name)
            if len(room.channel_names) == 1:
                self._start_waiting_alone_timer(room_id, room)
            else:
                self._cancel_waiting_alone_timer(room)
            if run_while_locked_after_adding is not None:
                await run_while_locked_after_adding()
            return "first" if len(room.channel_names) == 1 else "second"

    async def remove_member(self, room_id: str, channel_name: str) -> None:
        """Remove a member; an empty room is deleted and its timers are cancelled."""
        async with self._lock:
            room = self._rooms_by_room_id.get(room_id)
            if room is None or channel_name not in room.channel_names:
                return
            room.channel_names.remove(channel_name)
            if room.channel_names:
                self._start_waiting_alone_timer(room_id, room)
            else:
                del self._rooms_by_room_id[room_id]
                self._cancel_timers(room)

    def is_member(self, room_id: str, channel_name: str) -> bool:
        room = self._rooms_by_room_id.get(room_id)
        return room is not None and channel_name in room.channel_names

    def remaining_lifetime_seconds(self, room_id: str) -> float | None:
        """Seconds until the total-lifetime limit closes the room, or None if it is gone."""
        room = self._rooms_by_room_id.get(room_id)
        if room is None:
            return None
        return room.closes_at_monotonic_time - self._monotonic_clock()

    def try_take_turn_credential_slot(self, room_id: str) -> bool:
        """Count one TURN credential for this room and return True, or False when it is used up.

        No await inside, so the check and the count cannot interleave with another join.
        """
        room = self._rooms_by_room_id.get(room_id)
        if room is None or room.turn_credentials_issued >= MAX_TURN_CREDENTIALS_PER_ROOM:
            return False
        room.turn_credentials_issued += 1
        return True

    def room_count(self) -> int:
        return len(self._rooms_by_room_id)

    def _start_waiting_alone_timer(self, room_id: str, room: _Room) -> None:
        self._cancel_waiting_alone_timer(room)
        room.waiting_alone_timer = asyncio.create_task(
            self._expire_after(self._waiting_alone_limit_seconds, room_id, room, only_if_alone=True)
        )

    @staticmethod
    def _cancel_waiting_alone_timer(room: _Room) -> None:
        if room.waiting_alone_timer is not None:
            room.waiting_alone_timer.cancel()
            room.waiting_alone_timer = None

    @staticmethod
    def _cancel_timers(room: _Room) -> None:
        """Cancel both timers, except the one running this code (a task must not cancel itself)."""
        current_task = asyncio.current_task()
        # The running task stays referenced by the room until it finishes, so it can't be
        # garbage-collected midway.
        if room.waiting_alone_timer is not current_task:
            if room.waiting_alone_timer is not None:
                room.waiting_alone_timer.cancel()
            room.waiting_alone_timer = None
        if room.total_lifetime_timer is not current_task:
            if room.total_lifetime_timer is not None:
                room.total_lifetime_timer.cancel()
            room.total_lifetime_timer = None

    async def _expire_after(
        self, delay_seconds: float, room_id: str, room: _Room, *, only_if_alone: bool
    ) -> None:
        await asyncio.sleep(delay_seconds)
        async with self._lock:
            # The room may have emptied, been replaced by a new one with the same ID, or (for the
            # waiting timer) gained a second member while this task waited for the lock.
            if self._rooms_by_room_id.get(room_id) is not room:
                return
            if only_if_alone and len(room.channel_names) != 1:
                return
            del self._rooms_by_room_id[room_id]
            expired_channel_names = list(room.channel_names)
            room.channel_names.clear()
            self._cancel_timers(room)
            # Still under the lock: nobody can recreate this room ID before the old members are
            # out of its group.
            await self._notify_room_expired(room_id, expired_channel_names)


room_registry = RoomRegistry()
