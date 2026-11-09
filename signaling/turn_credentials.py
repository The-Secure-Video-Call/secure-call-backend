"""Short-lived TURN credentials (PLAN.md 3.5), in the coturn REST API scheme (`use-auth-secret`).

    username   = "<expiry unix time>:<random 16 bytes, base64url, no padding>"
    credential = base64(HMAC-SHA1(shared secret, username))

HMAC-SHA1 is not a choice: it is exactly what coturn computes and compares, so SHA-1 is
required here. It is used as a MAC (not for collision resistance), where SHA-1 is still sound.

Every connection gets a fresh random username, so a credential is never shared between people.
The shared secret and the credentials are never logged. The server can only hand out
credentials; the TURN relay sees encrypted media only, because DTLS-SRTP is end to end.

Small pure functions, standard library only. The clock is passed in so tests can fake it.
"""

import base64
import hashlib
import hmac
import secrets

from signaling.protocol import TurnCredentials

RANDOM_USERNAME_BYTES = 16


def make_turn_username(expiry_unix_time: int, random_bytes: bytes) -> str:
    random_part = base64.urlsafe_b64encode(random_bytes).decode("ascii").rstrip("=")
    return f"{expiry_unix_time}:{random_part}"


def make_turn_credential(shared_secret: str, username: str) -> str:
    digest = hmac.new(
        shared_secret.encode("utf-8"),
        username.encode("utf-8"),
        hashlib.sha1,  # coturn's REST API scheme requires HMAC-SHA1
    ).digest()
    return base64.b64encode(digest).decode("ascii")


def issue_turn_credentials(
    shared_secret: str,
    turn_urls: list[str],
    credential_ttl_seconds: int,
    now_unix_time: int,
) -> TurnCredentials:
    """Return credentials with a new random username that expire at now + the TTL."""
    username = make_turn_username(
        now_unix_time + credential_ttl_seconds, secrets.token_bytes(RANDOM_USERNAME_BYTES)
    )
    return TurnCredentials(
        urls=turn_urls,
        username=username,
        credential=make_turn_credential(shared_secret, username),
    )
