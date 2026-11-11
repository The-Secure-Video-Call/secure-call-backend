"""Every Dependabot entry waits 7 days after a release (SECURITY.md, "Fixing vulnerable
dependencies"). Read as text: no YAML parser is installed."""

import re
from pathlib import Path

DEPENDABOT = Path(__file__).resolve().parent.parent / ".github/dependabot.yml"


def entries_without_cooldown(dependabot_text: str) -> list[str]:
    """The ecosystem of each entry that lacks `cooldown: default-days: 7`."""
    entries = re.split(r"^  - (?=package-ecosystem:)", dependabot_text, flags=re.M)[1:]
    return [
        entry.splitlines()[0]
        for entry in entries
        if not re.search(r"^    cooldown:\n      default-days: 7$", entry, re.M)
    ]


def test_every_dependabot_entry_has_the_7_day_cooldown() -> None:
    text = DEPENDABOT.read_text()

    assert text.count("package-ecosystem:") == 5
    assert entries_without_cooldown(text) == []


def test_negative_an_entry_without_the_cooldown_is_caught() -> None:
    text = (
        "updates:\n"
        "  - package-ecosystem: uv\n    schedule:\n      interval: weekly\n"
        "    cooldown:\n      default-days: 7\n"
        "  - package-ecosystem: docker\n    schedule:\n      interval: weekly\n"
        "    cooldown:\n      default-days: 1\n"
    )

    assert entries_without_cooldown(text) == ["package-ecosystem: docker"]
