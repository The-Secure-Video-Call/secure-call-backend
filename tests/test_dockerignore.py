from pathlib import Path

DOCKERIGNORE_PATH = Path(__file__).resolve().parent.parent / ".dockerignore"
FILES_KEPT_OUT_OF_IMAGE = ("config/settings_test.py", "signaling/export_schema.py")


def find_missing_dockerignore_entries(dockerignore_text: str) -> list[str]:
    entries = {
        line.strip()
        for line in dockerignore_text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    return [file for file in FILES_KEPT_OUT_OF_IMAGE if file not in entries]


def test_dockerignore_excludes_test_settings_and_dev_tools() -> None:
    assert find_missing_dockerignore_entries(DOCKERIGNORE_PATH.read_text()) == []


def test_missing_dockerignore_entry_is_detected() -> None:
    for excluded_file in FILES_KEPT_OUT_OF_IMAGE:
        text_without_entry = DOCKERIGNORE_PATH.read_text().replace(excluded_file, "")
        assert find_missing_dockerignore_entries(text_without_entry) == [excluded_file]


def test_commented_out_entry_does_not_count() -> None:
    assert find_missing_dockerignore_entries("# config/settings_test.py\n") == list(
        FILES_KEPT_OUT_OF_IMAGE
    )
