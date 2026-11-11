"""The backend and PostgreSQL containers must have rotating Docker logs (README "Logs")."""

import re
from pathlib import Path

import pytest

COMPOSE_TEXT = (
    Path(__file__).parent.parent / "deploy" / "raspberry-pi" / "compose.yaml"
).read_text()
SERVICES_THAT_MUST_ROTATE = ("backend", "postgres")


def extract_service_block(compose_text: str, service_name: str) -> str:
    """Return the lines of one service: everything indented below its name."""
    found = re.search(
        rf"^  {re.escape(service_name)}:\n((?:(?:    .*)?\n)+)", compose_text, flags=re.MULTILINE
    )
    assert found is not None, f"service {service_name} not found"
    return found.group(1)


def find_rotation_problems(service_block: str) -> list[str]:
    logging_found = re.search(
        r"^    logging:\n((?:      .*\n)+)", service_block, flags=re.MULTILINE
    )
    if logging_found is None:
        return ["no logging: block"]
    logging_block = logging_found.group(1)
    problems: list[str] = []
    if not re.search(r"^      driver: local$", logging_block, flags=re.MULTILINE):
        problems.append("driver is not local")
    if not re.search(
        r"^        max-size: ['\"]?[1-9]\d*[kmg]['\"]?$", logging_block, flags=re.MULTILINE
    ):
        problems.append("no max-size")
    if not re.search(
        r"^        max-file: ['\"]?[1-9]\d*['\"]?$", logging_block, flags=re.MULTILINE
    ):
        problems.append("no max-file")
    return problems


@pytest.mark.parametrize("service_name", SERVICES_THAT_MUST_ROTATE)
def test_compose_rotates_logs_of_backend_and_postgres(service_name: str) -> None:
    assert find_rotation_problems(extract_service_block(COMPOSE_TEXT, service_name)) == []


def test_service_without_log_rotation_fails() -> None:
    service_block = "    image: example\n    restart: unless-stopped\n"
    assert find_rotation_problems(service_block) == ["no logging: block"]


def test_service_with_logging_but_no_limits_fails() -> None:
    service_block = "    image: example\n    logging:\n      driver: local\n"
    assert find_rotation_problems(service_block) == ["no max-size", "no max-file"]


def test_service_with_zero_max_file_fails() -> None:
    service_block = (
        "    logging:\n      driver: local\n      options:\n"
        "        max-size: 10m\n        max-file: '0'\n"
    )
    assert find_rotation_problems(service_block) == ["no max-file"]


def test_service_with_other_driver_fails() -> None:
    service_block = (
        "    logging:\n      driver: json-file\n      options:\n"
        "        max-size: 10m\n        max-file: '3'\n"
    )
    assert find_rotation_problems(service_block) == ["driver is not local"]


def test_coturn_logs_stay_discarded() -> None:
    coturn_block = extract_service_block(COMPOSE_TEXT, "coturn")
    assert re.search(r"^    logging:\n      driver: none$", coturn_block, flags=re.MULTILINE)
