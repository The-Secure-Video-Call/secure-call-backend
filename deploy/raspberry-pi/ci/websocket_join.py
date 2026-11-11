"""CI only: joins a room over a signaling WebSocket URL and fails unless the server answers
`joined`. Used to check a WebSocket passes through the proxy configuration (ci.yml).

    python websocket_join.py wss://127.0.0.1:18443/ws/signal/ https://call.example.invalid

For wss:// the front certificate is CI's throwaway one, so it is not checked here; the proxy's
check of the backend's certificate (the point of the test) happens behind it.
"""

import asyncio
import json
import ssl
import sys

from websockets.asyncio.client import connect


def front_tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # CI's self-signed front certificate only
    return context


async def join_room(url: str, origin: str) -> str:
    tls = front_tls_context() if url.startswith("wss://") else None
    async with connect(url, origin=origin, ssl=tls) as client:  # type: ignore[arg-type]
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
