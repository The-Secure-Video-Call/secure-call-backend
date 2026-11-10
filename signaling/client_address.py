"""Find the real client IP behind the reverse proxy (Nginx Proxy Manager).

Behind the proxy, the TCP peer (`scope["client"]`) is the proxy for every caller. The proxy adds
the address it saw to the END of `X-Forwarded-For`; anything before it was sent by the client
and can be forged. So:
- the header is used only when the TCP peer is in TRUSTED_PROXY_IPS (empty by default);
- then the RIGHTMOST entry is the client, never the leftmost;
- from any other peer, the header is ignored and the TCP peer address is used;
- an unparseable entry is not trusted either: the TCP peer address is used.

The result is stored in `scope["client_ip"]`, used only to key the in-memory rate limits
(rate_limits.py). It is never logged or stored.
"""

import ipaddress
from collections.abc import Awaitable, Callable, Iterable, MutableMapping
from typing import Any

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

# Used when the server gives no peer address at all (not the case under Daphne).
UNKNOWN_CLIENT_IP = "unknown"
IPV6_PREFIX_LENGTH = 64


def normalize_ip(address_text: str) -> str | None:
    """Canonical text for an IP address (IPv4-mapped IPv6 becomes IPv4), or None if invalid."""
    try:
        address = ipaddress.ip_address(address_text.strip())
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return str(address)


def rightmost_forwarded_for_ip(headers: Iterable[tuple[bytes, bytes]]) -> str | None:
    """The last address of X-Forwarded-For (repeated headers count as one list, in order)."""
    entries: list[str] = []
    for header_name, header_value in headers:
        if header_name.lower() == b"x-forwarded-for":
            entries.extend(header_value.decode("latin-1").split(","))
    non_empty_entries = [entry for entry in entries if entry.strip()]
    if not non_empty_entries:
        return None
    return normalize_ip(non_empty_entries[-1])


class ClientAddressMiddleware:
    def __init__(self, inner_app: ASGIApp, trusted_proxy_ips: Iterable[str]) -> None:
        self.inner_app = inner_app
        normalized_ips = (normalize_ip(proxy_ip) for proxy_ip in trusted_proxy_ips)
        self.trusted_proxy_ips = frozenset(ip for ip in normalized_ips if ip is not None)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "websocket":
            scope = dict(scope)
            scope["client_ip"] = self.client_ip_for(scope)
        await self.inner_app(scope, receive, send)

    def client_ip_for(self, scope: Scope) -> str:
        client = scope.get("client")
        peer_ip = normalize_ip(str(client[0])) if client else None
        if peer_ip is None:
            return UNKNOWN_CLIENT_IP
        if peer_ip in self.trusted_proxy_ips:
            forwarded_ip = rightmost_forwarded_for_ip(scope.get("headers", []))
            if forwarded_ip is not None:
                return group_ipv6_by_prefix(forwarded_ip)
        return group_ipv6_by_prefix(peer_ip)


def group_ipv6_by_prefix(normalized_ip: str) -> str:
    """One IPv6 /64 is one customer, so it counts as one client (else a /64 has 2^64 buckets)."""
    address = ipaddress.ip_address(normalized_ip)
    if isinstance(address, ipaddress.IPv6Address):
        return str(
            ipaddress.ip_network(f"{address}/{IPV6_PREFIX_LENGTH}", strict=False).network_address
        )
    return normalized_ip
