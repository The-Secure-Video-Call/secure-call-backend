"""Room membership: which connections are in which room. Nothing else is kept.

State lives in this process's memory behind a lock, so it is only correct with ONE server
process. Message relaying already goes through the Channels layer (see consumers.py), so moving
to several processes means replacing `RoomRegistry` with a Redis-backed one (atomic add/remove
of members, e.g. a Lua script); the consumer would not change. Room IDs are never logged.
"""

import asyncio
import hashlib
from collections.abc import Awaitable, Callable
from typing import Final, Literal

MAX_MEMBERS_PER_ROOM: Final = 2

Role = Literal["first", "second"]


def group_name_for_room(room_id: str) -> str:
    """Channels group name for a room. Hashed so the room ID itself never reaches the layer."""
    return "room." + hashlib.sha256(room_id.encode("ascii")).hexdigest()


class RoomRegistry:
    def __init__(self) -> None:
        self._channel_names_by_room_id: dict[str, list[str]] = {}
        self._lock = asyncio.Lock()

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
            channel_names = self._channel_names_by_room_id.setdefault(room_id, [])
            if len(channel_names) >= MAX_MEMBERS_PER_ROOM:
                return None
            channel_names.append(channel_name)
            if run_while_locked_after_adding is not None:
                await run_while_locked_after_adding()
            return "first" if len(channel_names) == 1 else "second"

    async def remove_member(self, room_id: str, channel_name: str) -> None:
        """Remove a member; an empty room is deleted."""
        async with self._lock:
            channel_names = self._channel_names_by_room_id.get(room_id)
            if channel_names is None or channel_name not in channel_names:
                return
            channel_names.remove(channel_name)
            if not channel_names:
                del self._channel_names_by_room_id[room_id]

    def room_count(self) -> int:
        return len(self._channel_names_by_room_id)


room_registry = RoomRegistry()
