"""CI only: joins a room over a signaling WebSocket URL and fails unless the server answers
`joined`. Used to check a WebSocket passes through the proxy configuration (ci.yml).

    python websocket_join.py ws://127.0.0.1:18080/ws/signal/ https://call.example.invalid
"""

import asyncio
import json
import sys

from websockets.asyncio.client import connect


async def join_room(url: str, origin: str) -> str:
    async with connect(url, origin=origin) as client:  # type: ignore[arg-type]
        await client.send(json.dumps({"v": 1, "type": "join", "roomId": "C" * 22}))
        reply = json.loads(await asyncio.wait_for(client.recv(), 10))
    return str(reply.get("type"))


def main() -> int:
    url, origin = sys.argv[1], sys.argv[2]
    reply_type = asyncio.run(join_room(url, origin))
    print(f"WebSocket through {url}: {reply_type}")
    return 0 if reply_type == "joined" else 1


if __name__ == "__main__":
    sys.exit(main())
