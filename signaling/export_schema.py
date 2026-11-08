"""Write the protocol's JSON Schema files to `protocol/schema/`.

Run after changing `signaling/protocol.py`:  uv run python -m signaling.export_schema
A test fails if the committed files are out of date.
"""

import json
from pathlib import Path

from signaling.protocol import SCHEMAS

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "protocol" / "schema"


def render_schemas() -> dict[str, str]:
    """Return {file name: JSON text} for every protocol schema."""
    return {
        f"{name}.schema.json": json.dumps(model.model_json_schema(), indent=2, sort_keys=True)
        + "\n"
        for name, model in SCHEMAS.items()
    }


def main() -> None:
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    for file_name, text in render_schemas().items():
        (SCHEMA_DIR / file_name).write_text(text, encoding="utf-8")
        print(f"wrote protocol/schema/{file_name}")


if __name__ == "__main__":
    main()
