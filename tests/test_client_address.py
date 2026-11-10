from collections.abc import MutableMapping
from typing import Any

import pytest

from signaling.client_address import (
    UNKNOWN_CLIENT_IP,
    ClientAddressMiddleware,
    Receive,
    Scope,
    Send,
    ipv6_prefix,
    normalize_ip,
)

PROXY_IP = "192.168.1.10"
CLIENT_IP = "203.0.113.7"
FORGED_IP = "198.51.100.99"


async def no_receive() -> MutableMapping[str, Any]:
    return {}


async def no_send(message: MutableMapping[str, Any]) -> None:
    return None


async def resolve_client_ip(
    trusted_proxy_ips: list[str],
    peer_ip: str | None,
    forwarded_for_values: list[str],
    scope_type: str = "websocket",
) -> str | None:
    seen_scopes: list[Scope] = []

    async def inner_app(scope: Scope, receive: Receive, send: Send) -> None:
        seen_scopes.append(scope)

    scope: Scope = {
        "type": scope_type,
        "client": [peer_ip, 50000] if peer_ip is not None else None,
        "headers": [(b"x-forwarded-for", value.encode()) for value in forwarded_for_values],
    }
    await ClientAddressMiddleware(inner_app, trusted_proxy_ips)(scope, no_receive, no_send)
    assert "client_ip" not in scope  # the caller's scope is not modified
    client_ip: str | None = seen_scopes[0].get("client_ip")
    return client_ip


async def test_trusted_proxy_gives_the_rightmost_entry() -> None:
    assert await resolve_client_ip([PROXY_IP], PROXY_IP, [CLIENT_IP]) == CLIENT_IP


async def test_rightmost_entry_wins_over_a_forged_leftmost_one() -> None:
    forged_chain = f"{FORGED_IP}, 10.9.9.9, {CLIENT_IP}"
    assert await resolve_client_ip([PROXY_IP], PROXY_IP, [forged_chain]) == CLIENT_IP


async def test_repeated_headers_count_as_one_list_in_order() -> None:
    assert await resolve_client_ip([PROXY_IP], PROXY_IP, [FORGED_IP, CLIENT_IP]) == CLIENT_IP


async def test_untrusted_peer_header_is_ignored() -> None:
    # A direct caller forging the header must stay in its own bucket.
    assert await resolve_client_ip([PROXY_IP], CLIENT_IP, [FORGED_IP]) == CLIENT_IP
    assert await resolve_client_ip([PROXY_IP], CLIENT_IP, [f"{FORGED_IP}, {PROXY_IP}"]) == CLIENT_IP


async def test_header_is_ignored_when_no_proxy_is_trusted() -> None:
    assert await resolve_client_ip([], PROXY_IP, [FORGED_IP]) == PROXY_IP


async def test_trusted_proxy_without_header_gives_the_peer() -> None:
    assert await resolve_client_ip([PROXY_IP], PROXY_IP, []) == PROXY_IP


@pytest.mark.parametrize("bad_value", ["not-an-ip", "1.2.3.4:80", "1.2.3.999", "unknown"])
async def test_unparseable_rightmost_entry_falls_back_to_the_peer(bad_value: str) -> None:
    # The earlier entry is not used instead: it is the one the client could have forged.
    forwarded_for = f"{FORGED_IP}, {bad_value}"
    assert await resolve_client_ip([PROXY_IP], PROXY_IP, [forwarded_for]) == PROXY_IP


async def test_ipv6_and_ipv4_mapped_addresses_are_normalized() -> None:
    assert normalize_ip("::ffff:203.0.113.7") == CLIENT_IP
    assert await resolve_client_ip(["::ffff:192.168.1.10"], PROXY_IP, [CLIENT_IP]) == CLIENT_IP


async def test_ipv6_addresses_in_one_slash_64_count_as_one_client() -> None:
    first = await resolve_client_ip([PROXY_IP], PROXY_IP, ["2001:DB8:1:2:aaaa::1"])
    second = await resolve_client_ip([PROXY_IP], PROXY_IP, ["2001:db8:1:2:bbbb::9"])
    other_prefix = await resolve_client_ip([PROXY_IP], PROXY_IP, ["2001:db8:1:3::1"])
    direct = await resolve_client_ip([], "2001:db8:1:2:cccc::5", [])

    assert first == second == direct == "2001:db8:1:2::"
    assert other_prefix == "2001:db8:1:3::"


def test_ipv6_prefix_is_the_network_of_that_length_and_ipv4_has_none() -> None:
    assert ipv6_prefix("2001:db8:1:2::", 48) == "2001:db8:1::"
    assert ipv6_prefix("2001:db8:1:ffff::", 48) == "2001:db8:1::"
    assert ipv6_prefix("2001:db8:2:2::", 48) == "2001:db8:2::"
    assert ipv6_prefix("2001:db8:1:1ff::", 56) == "2001:db8:1:100::"
    assert ipv6_prefix("2001:db8:1:200::", 56) == "2001:db8:1:200::"
    assert ipv6_prefix(CLIENT_IP, 48) is None
    assert ipv6_prefix(UNKNOWN_CLIENT_IP, 56) is None


@pytest.mark.parametrize(
    ("transition_ip", "embedded_ipv4"),
    [
        pytest.param("2002:c000:204::1", "192.0.2.4", id="6to4"),
        pytest.param("2002:c000:204:ffff::9", "192.0.2.4", id="6to4-another-subnet"),
        # RFC 4380's example: server 65.54.227.120, client 192.0.2.45 (stored inverted).
        pytest.param("2001:0:4136:e378:8000:63bf:3fff:fdd2", "192.0.2.45", id="teredo"),
        pytest.param("64:ff9b::192.0.2.33", "192.0.2.33", id="nat64"),
    ],
)
async def test_transition_addresses_count_as_the_ipv4_inside_them(
    transition_ip: str, embedded_ipv4: str
) -> None:
    assert await resolve_client_ip([], transition_ip, []) == embedded_ipv4
    assert await resolve_client_ip([PROXY_IP], PROXY_IP, [transition_ip]) == embedded_ipv4


@pytest.mark.parametrize(
    ("address", "slash_64"),
    [
        pytest.param("2003:c000:204::1", "2003:c000:204::", id="next-to-6to4"),
        pytest.param(
            "2001:1:4136:e378:8000:63bf:3fff:fdd2", "2001:1:4136:e378::", id="next-to-teredo"
        ),
        # The NAT64 local-use prefix has no fixed layout, and this one is outside the /96.
        pytest.param("64:ff9b:1::c000:221", "64:ff9b:1::", id="nat64-local-use"),
        pytest.param("64:ff9b::1:c000:221", "64:ff9b::", id="next-to-nat64"),
    ],
)
async def test_addresses_next_to_the_transition_prefixes_stay_grouped_by_slash_64(
    address: str, slash_64: str
) -> None:
    assert await resolve_client_ip([], address, []) == slash_64


async def test_transition_address_is_not_trusted_as_the_proxy_inside_it() -> None:
    # 2002:c0a8:10a::/48 is the 6to4 network of PROXY_IP (192.168.1.10). Only the proxy's own
    # address is trusted, so this peer's forged header is ignored: it counts as itself.
    assert await resolve_client_ip([PROXY_IP], "2002:c0a8:10a::1", [FORGED_IP]) == PROXY_IP


async def test_missing_peer_address_gives_unknown() -> None:
    assert await resolve_client_ip([PROXY_IP], None, [FORGED_IP]) == UNKNOWN_CLIENT_IP


async def test_other_scope_types_are_passed_through_untouched() -> None:
    assert await resolve_client_ip([PROXY_IP], PROXY_IP, [CLIENT_IP], scope_type="http") is None
