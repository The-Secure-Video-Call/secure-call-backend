"""Find the real client IP behind the reverse proxy (Nginx Proxy Manager).

Behind the proxy, the TCP peer (`scope["client"]`) is the proxy for every caller. The proxy adds
the address it saw to the END of `X-Forwarded-For`; anything before it was sent by the client
and can be forged. So:
- the header is used only when the TCP peer is in TRUSTED_PROXY_IPS (empty by default);
- then the RIGHTMOST entry is the client, never the leftmost;
- from any other peer, the header is ignored and the TCP peer address is used;
- an unparseable entry is not trusted either: the TCP peer address is used.

The address found is then grouped (`group_client_ip`): an IPv6 transition address becomes the
IPv4 address inside it, other IPv6 addresses become their /64, and IPv4 stays as it is. The
result is stored in `scope["client_ip"]`, used only to key the in-memory rate limits
(rate_limits.py, which also counts IPv6 clients by their /56 and /48). It is never logged or
stored.
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
# NAT64 well-known prefix (RFC 6052): the low 32 bits are the IPv4 address of the host behind
# the translator. The local-use prefix 64:ff9b:1::/48 (RFC 8215) has no fixed layout, so it is
# grouped like any other IPv6 address.
NAT64_WELL_KNOWN_PREFIX = ipaddress.IPv6Network("64:ff9b::/96")


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
        # Compared as sent, before grouping: a transition address is never trusted as the proxy
        # whose IPv4 address it embeds.
        if peer_ip in self.trusted_proxy_ips:
            forwarded_ip = rightmost_forwarded_for_ip(scope.get("headers", []))
            if forwarded_ip is not None:
                return group_client_ip(forwarded_ip)
        return group_client_ip(peer_ip)


def group_client_ip(normalized_ip: str) -> str:
    """The address the rate limits count a client by.

    - An IPv6 transition address (6to4, Teredo, NAT64) becomes the IPv4 address inside it, so it
      shares that address's bucket: else one IPv4 host would own a whole 6to4 /48, and a Teredo
      or NAT64 client would get limits apart from its own IPv4 address.
    - Any other IPv6 address becomes its /64: one /64 is one customer, so it counts as one client
      (else a /64 has 2^64 buckets).
    - IPv4 stays as it is.
    """
    address = ipaddress.ip_address(normalized_ip)
    if isinstance(address, ipaddress.IPv4Address):
        return normalized_ip
    embedded_ipv4 = ipv4_inside_transition_address(address)
    if embedded_ipv4 is not None:
        return str(embedded_ipv4)
    return str(
        ipaddress.ip_network(f"{address}/{IPV6_PREFIX_LENGTH}", strict=False).network_address
    )


def ipv4_inside_transition_address(address: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """The client's IPv4 address inside a 6to4, Teredo or NAT64 address, or None for others.

    - 6to4 (2002::/16): the /48 belongs to the IPv4 host in bits 16-47.
    - Teredo (2001::/32): the client's public IPv4 address (de-obfuscated), not the server's.
    - NAT64 (64:ff9b::/96): the IPv4 host behind the translator, in the low 32 bits.
    """
    if address.sixtofour is not None:
        return address.sixtofour
    if address.teredo is not None:
        _teredo_server_ipv4, teredo_client_ipv4 = address.teredo
        return teredo_client_ipv4
    if address in NAT64_WELL_KNOWN_PREFIX:
        return ipaddress.IPv4Address(int(address) & 0xFFFF_FFFF)
    return None


def ipv6_prefix(client_ip: str, prefix_length: int) -> str | None:
    """The IPv6 network of `prefix_length` bits that contains `client_ip`, or None for IPv4 and
    for "unknown"."""
    try:
        address = ipaddress.ip_address(client_ip)
    except ValueError:
        return None
    if not isinstance(address, ipaddress.IPv6Address):
        return None
    return str(ipaddress.ip_network(f"{address}/{prefix_length}", strict=False).network_address)
