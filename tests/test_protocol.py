"""The protocol contract: example messages and the exported JSON Schema.

The web client runs its own schemas against the same fixtures, so both sides agree on what a
valid message is.
"""

from pathlib import Path

import pytest
from pydantic import ValidationError

from signaling.export_schema import SCHEMA_DIR, render_schemas
from signaling.protocol import Envelope

FIXTURES = Path(__file__).resolve().parent.parent / "protocol" / "fixtures"
VALID = sorted((FIXTURES / "valid").glob("*.json"))
INVALID = sorted((FIXTURES / "invalid").glob("*.json"))


def test_fixtures_exist() -> None:
    assert VALID
    assert INVALID


@pytest.mark.parametrize("fixture", VALID, ids=lambda p: p.stem)
def test_valid_fixture_is_accepted(fixture: Path) -> None:
    Envelope.model_validate_json(fixture.read_text(encoding="utf-8"))


@pytest.mark.parametrize("fixture", INVALID, ids=lambda p: p.stem)
def test_invalid_fixture_is_rejected(fixture: Path) -> None:
    with pytest.raises(ValidationError):
        Envelope.model_validate_json(fixture.read_text(encoding="utf-8"))


def test_exported_schema_is_up_to_date() -> None:
    expected = render_schemas()
    on_disk = {path.name: path.read_text(encoding="utf-8") for path in SCHEMA_DIR.glob("*.json")}

    assert on_disk == expected, "Run: uv run python -m signaling.export_schema"
