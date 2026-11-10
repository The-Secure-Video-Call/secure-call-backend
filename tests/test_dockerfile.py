"""The Dockerfile CMD must cap a socket's total lifetime just above the 4 h room limit."""

import re
from pathlib import Path

from daphne.cli import CommandLineInterface

from signaling.rooms import TOTAL_LIFETIME_LIMIT_SECONDS

DOCKERFILE_TEXT = (Path(__file__).parent.parent / "Dockerfile").read_text()


def test_daphne_websocket_timeout_is_just_above_the_room_limit() -> None:
    found = re.search(r"exec daphne [^\"]*--websocket_timeout (\d+)", DOCKERFILE_TEXT)
    assert found is not None, "the Dockerfile CMD must pass --websocket_timeout to daphne"
    websocket_timeout_seconds = int(found.group(1))
    assert websocket_timeout_seconds > TOTAL_LIFETIME_LIMIT_SECONDS
    assert websocket_timeout_seconds <= TOTAL_LIFETIME_LIMIT_SECONDS + 15 * 60


def test_daphne_accepts_the_websocket_timeout_option() -> None:
    parsed_arguments = CommandLineInterface().parser.parse_args(
        ["--websocket_timeout", "14700", "app:application"]
    )
    assert parsed_arguments.websocket_timeout == 14700
