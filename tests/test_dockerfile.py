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


def apt_upgrades_without_exact_versions(dockerfile_text: str) -> list[str]:
    """Packages that `apt-get install` lines install without an exact `=version`."""
    loose = []
    for install in re.findall(r"apt-get install[^\n&]*", dockerfile_text):
        words = [word.strip("\"'") for word in install.split()[2:]]
        packages = [word for word in words if word and not word.startswith(("-", "\\"))]
        loose += [package for package in packages if "=" not in package]
    return loose


def test_security_patches_in_the_image_are_exact_and_checked() -> None:
    # A package patched on top of the base image (zlib1g, DSA-6613-1) is pinned to one version and
    # checked after install, so the image stays reproducible and a missing version fails the build.
    assert apt_upgrades_without_exact_versions(DOCKERFILE_TEXT) == []
    if "apt-get install" in DOCKERFILE_TEXT:
        assert "dpkg-query" in DOCKERFILE_TEXT
        assert "rm -rf /var/lib/apt/lists/*" in DOCKERFILE_TEXT


def test_negative_an_unpinned_apt_install_is_caught() -> None:
    assert apt_upgrades_without_exact_versions(
        "RUN apt-get install --yes --only-upgrade zlib1g curl=8.0\n"
    ) == ["zlib1g"]


def test_runtime_image_has_no_pip() -> None:
    # pip is not needed to serve (the venv is built by uv), and its vendored libraries are flagged
    # by the image scan; the runtime stage removes it and checks that it is gone.
    runtime_stage = DOCKERFILE_TEXT.rsplit("\nFROM ", 1)[1]

    assert "pip uninstall --yes" in runtime_stage
    assert '! python -c "import pip"' in runtime_stage
