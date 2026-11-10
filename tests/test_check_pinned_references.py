"""The pin check must catch every movable reference and accept pinned ones."""

from pathlib import Path

import pytest

from scripts.check_pinned_references import (
    find_unpinned_actions,
    find_unpinned_images_in_dockerfile,
    find_unpinned_images_in_yaml,
    find_unpinned_references,
    main,
)

ROOT = Path(__file__).resolve().parent.parent
SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
DIGEST = "sha256:" + "a" * 64


def test_the_repository_itself_is_fully_pinned() -> None:
    assert find_unpinned_references(ROOT) == []


@pytest.mark.parametrize(
    "line",
    [
        f"      - uses: actions/checkout@{SHA} # v7.0.1",
        f"        uses: 'docker/build-push-action@{SHA}'",
        "      - uses: ./.github/actions/local-thing",
        f"      - uses: docker://alpine:3@{DIGEST}",
    ],
)
def test_pinned_actions_pass(line: str) -> None:
    assert find_unpinned_actions(line) == []


@pytest.mark.parametrize(
    "line",
    [
        "      - uses: actions/checkout@v7",  # a tag can be moved
        "      - uses: actions/checkout@main",  # a branch moves all the time
        "      - uses: actions/checkout@3d3c42e",  # a short SHA can become ambiguous
        "      - uses: actions/checkout",  # no ref at all
        '        uses: "anthropics/claude-code-action@v1"',
        f"      - uses: actions/checkout@{SHA.upper()}",  # not how GitHub writes a SHA
        "      - uses: docker://alpine:3",
    ],
)
def test_unpinned_actions_fail(line: str) -> None:
    assert len(find_unpinned_actions(line)) == 1


def test_images_need_a_digest_unless_they_are_our_own() -> None:
    yaml_text = "\n".join(
        [
            "    image: postgres:18",
            f"    image: postgres:18@{DIGEST}",
            "    image: ghcr.io/the-secure-video-call/secure-call-backend:main",
            "    image: secure-call-coturn:local",
            "    image: ghcr.io/the-secure-video-call/secure-call-backend:latest",
        ]
    )

    unpinned = find_unpinned_images_in_yaml(yaml_text)

    assert [reference.line_number for reference in unpinned] == [1, 5]


def test_dockerfile_base_images_need_a_digest_but_build_stages_do_not() -> None:
    dockerfile_text = "\n".join(
        [
            f"FROM python:3.14-slim@{DIGEST} AS build",
            "COPY --from=ghcr.io/astral-sh/uv:0.12.13 /uv /bin/uv",
            f"COPY --from=ghcr.io/astral-sh/uv:0.12.13@{DIGEST} /uv /bin/uv",
            "FROM python:3.14-slim",
            "COPY --from=build /app /app",
            "FROM --platform=linux/arm64 debian:13",
        ]
    )

    unpinned = find_unpinned_images_in_dockerfile(dockerfile_text)

    assert [reference.line_number for reference in unpinned] == [2, 4, 6]


def test_main_reports_each_problem_and_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("steps:\n  - uses: actions/checkout@v7\n")
    (tmp_path / "Dockerfile").write_text("FROM python:3.14-slim\n")

    exit_code = main([str(tmp_path)])

    output = capsys.readouterr().out
    assert exit_code == 1
    assert ".github/workflows/ci.yml:2: actions/checkout@v7" in output
    assert "Dockerfile:1: python:3.14-slim" in output


def test_main_passes_when_everything_is_pinned(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(f"steps:\n  - uses: actions/checkout@{SHA}\n")

    assert main([str(tmp_path)]) == 0
