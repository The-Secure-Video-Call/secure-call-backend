"""The Origin check of config/asgi.py, with a count of rejections (and nothing else).

Same decision as Channels' `OriginValidator`; the rejected Origin value is not looked at again,
stored or logged.
"""

from typing import Any

from channels.security.websocket import OriginValidator

from signaling.abuse_counts import AbuseKind, count


class CountingOriginValidator(OriginValidator):  # type: ignore[misc]
    def valid_origin(self, parsed_origin: Any) -> bool:
        is_valid = bool(super().valid_origin(parsed_origin))
        if not is_valid:
            count(AbuseKind.ORIGIN_REJECTIONS)
        return is_valid
