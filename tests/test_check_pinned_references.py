"""The pin check must catch every movable reference, in every form, and accept pinned ones."""

import re
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
PINNED_BASE = f"FROM python@{DIGEST}\n"


def test_the_repository_itself_is_fully_pinned() -> None:
    assert find_unpinned_references(ROOT) == []


@pytest.mark.parametrize(
    "text",
    [
        f"      - uses: actions/checkout@{SHA} # v7.0.1",
        f"        uses: 'docker/build-push-action@{SHA}'",
        f"    uses: org/repo/.github/workflows/build.yml@{SHA}",
        "      - uses: ./.github/actions/local-thing",
        f"      - uses: docker://alpine:3@{DIGEST}",
        "  test-image:\n    runs-on: ubuntu-latest",  # a job name ending in -image is no image
    ],
)
def test_pinned_actions_pass(text: str) -> None:
    assert find_unpinned_actions(text) == []
    assert find_unpinned_images_in_yaml(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "      - uses: actions/checkout@v7",  # a tag can be moved
        "      - uses: actions/checkout@main",  # a branch moves all the time
        "      - uses: actions/checkout@3d3c42e",  # a short SHA can become ambiguous
        "      - uses: actions/checkout",  # no ref at all
        '        uses: "anthropics/claude-code-action@v1"',
        f"      - uses: actions/checkout@{SHA.upper()}",  # not how GitHub writes a SHA
        f"      - uses: actions/checkout@v7@{SHA}",  # ends in a SHA, but is not one
        "      - uses: docker://alpine:3",
        "    uses: org/repo/.github/workflows/build.yml@v1",  # a reusable workflow
        "      - {name: co, uses: actions/checkout@v7}",  # flow style
        "      - uses:\n          actions/checkout@v7",  # value on the next line
        "      - uses: # comment\n          actions/checkout@v7",
        "      - uses: >-\n          actions/checkout@v7",  # block scalar
        '      - "uses": actions/checkout@v7',  # quoted key
        "      - uses : actions/checkout@v7",  # space before the colon
        "      - uses: &checkout actions/checkout@v7",  # an anchor is not a SHA
    ],
)
def test_unpinned_actions_fail(text: str) -> None:
    assert len(find_unpinned_actions(text)) == 1


@pytest.mark.parametrize(
    "text",
    [
        "    image: postgres:18",
        "    image: ghcr.io/the-secure-video-call/secure-call-backend:main",  # not allowed here
        "    container: node:22",  # the string form of a job container
        "  postgres: {image: postgres:18}",
        "    image:\n      postgres:18",
        '    "image": postgres:18',
        "    image : postgres:18",
        "          image: tonistiigi/binfmt:latest",  # setup-qemu-action input
        "          driver-opts: image=moby/buildkit:latest",  # setup-buildx-action input
        "    image: ${PG_IMAGE:-postgres:18}",
        "          sbom: generator=docker/buildkit-syft-scanner:stable-1",  # build-push-action
        "          sbom: generator=docker/buildkit-syft-scanner@sha256:abc",  # not a full digest
        "          attests: type=sbom,generator=docker/buildkit-syft-scanner:1",
        "          sbom: true",  # BuildKit's default scanner, by a moving tag
        '          sbom: "true" # quoted, with a comment',
        "          sbom: ${{ inputs.sbom }}",  # cannot be read, so not trusted
        "          attests: type=sbom",
        "          attests: type=provenance,mode=max\n          attests: type=sbom",
    ],
)
def test_unpinned_yaml_images_fail(text: str) -> None:
    assert len(find_unpinned_images_in_yaml(text)) == 1


@pytest.mark.parametrize(
    "text",
    [
        f"          sbom: generator=docker/buildkit-syft-scanner:1.12.1@{DIGEST}",
        f"          attests: type=sbom,generator=docker/buildkit-syft-scanner@{DIGEST}",
        "          sbom: false",
        "          sbom: disabled=true",
        "          provenance: mode=max",
        "          # sbom: true is what we replaced; comments are not configuration",
        "          sboms: true",  # another key
    ],
)
def test_pinned_or_disabled_sbom_scanners_pass(text: str) -> None:
    assert find_unpinned_images_in_yaml(text) == []


def test_pinned_yaml_images_and_container_mappings_pass() -> None:
    yaml_text = "\n".join(
        [
            f"    image: postgres:18@{DIGEST}",
            "    container:",
            f"      image: node:22@{DIGEST}",
            f"          driver-opts: image=moby/buildkit:v0.34.2@{DIGEST}",
        ]
    )

    assert find_unpinned_images_in_yaml(yaml_text) == []


@pytest.mark.parametrize(
    "dockerfile_text",
    [
        PINNED_BASE,
        f"# syntax=docker/dockerfile:1@{DIGEST}\n" + PINNED_BASE,
        f"FROM ghcr.io/astral-sh/uv:0.12.13@{DIGEST} AS uv\n{PINNED_BASE}COPY --from=uv /uv /uv\n",
        f"FROM python@{DIGEST} AS python\nFROM python\n",  # a stage named like an image
        "FROM scratch\n",
        PINNED_BASE + "COPY --from=0 /x /x\n",  # a stage by index
    ],
)
def test_pinned_dockerfiles_pass(dockerfile_text: str) -> None:
    assert find_unpinned_images_in_dockerfile(dockerfile_text) == []


@pytest.mark.parametrize(
    "dockerfile_text",
    [
        "FROM python:3.14-slim\n",
        "from python:3.14-slim\n",
        "FROM --platform=$BUILDPLATFORM python:3.14-slim AS build\n",
        "ARG IMAGE=python:3.14-slim\nFROM ${IMAGE}\n",
        "FROM \\\n  python:3.14-slim\n",
        "# syntax=docker/dockerfile:1\n" + PINNED_BASE,  # the BuildKit frontend runs the build
        PINNED_BASE + "COPY --from=ghcr.io/astral-sh/uv:0.12.13 /uv /bin/uv\n",
        PINNED_BASE + "COPY --link \\\n  --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv\n",
        PINNED_BASE + "RUN --mount=type=bind,from=ghcr.io/astral-sh/uv:latest,target=/u true\n",
        PINNED_BASE + "ONBUILD COPY --from=alpine:3 /x /x\n",
        PINNED_BASE + "COPY --from=later /x /x\n" + f"FROM python@{DIGEST} AS later\n",
    ],
)
def test_unpinned_dockerfiles_fail(dockerfile_text: str) -> None:
    assert len(find_unpinned_images_in_dockerfile(dockerfile_text)) == 1


def make_repository(tmp_path: Path, files: dict[str, str]) -> Path:
    for relative_path, text in files.items():
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return tmp_path


def test_own_images_are_allowed_only_in_the_pi_compose_file(tmp_path: Path) -> None:
    own_image = "    image: ghcr.io/the-secure-video-call/secure-call-backend:main\n"
    repository = make_repository(
        tmp_path,
        {
            "deploy/raspberry-pi/compose.yaml": own_image,
            "deploy/other/compose.yaml": own_image,
        },
    )

    assert find_unpinned_references(repository) == [
        "deploy/other/compose.yaml:1: ghcr.io/the-secure-video-call/secure-call-backend:main"
    ]


def test_local_actions_and_other_container_files_are_scanned(tmp_path: Path) -> None:
    repository = make_repository(
        tmp_path,
        {
            ".github/actions/setup/action.yml": "runs:\n  steps:\n    - uses: actions/cache@v4\n",
            "docker/Containerfile": "FROM alpine:3\n",
            "tools/Dockerfile.dev": "FROM alpine:3\n",
            "docker-compose.override.yml": "services:\n  x:\n    image: redis:8\n",
        },
    )

    problems = find_unpinned_references(repository)

    assert len(problems) == 4
    assert ".github/actions/setup/action.yml:3: actions/cache@v4" in problems


def test_main_reports_each_problem_and_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repository = make_repository(
        tmp_path,
        {
            ".github/workflows/ci.yml": "steps:\n  - uses: actions/checkout@v7\n",
            "Dockerfile": "FROM python:3.14-slim\n",
        },
    )

    exit_code = main([str(repository)])

    output = capsys.readouterr().out
    assert exit_code == 1
    assert ".github/workflows/ci.yml:2: actions/checkout@v7" in output
    assert "Dockerfile:1: python:3.14-slim" in output


def test_main_passes_when_everything_is_pinned(tmp_path: Path) -> None:
    repository = make_repository(
        tmp_path, {".github/workflows/ci.yml": f"steps:\n  - uses: actions/checkout@{SHA}\n"}
    )

    assert main([str(repository)]) == 0


def test_ci_postgres_is_started_from_the_pis_compose_file() -> None:
    # Not a copy of the image or its settings: CI starts the very service the Pi runs, with its
    # TLS and role setup, so the two cannot drift apart.
    ci_text = (ROOT / ".github/workflows/ci.yml").read_text()
    pi_images = re.findall(
        r"image: (postgres:\S+)", (ROOT / "deploy/raspberry-pi/compose.yaml").read_text()
    )

    assert "working-directory: deploy/raspberry-pi" in ci_text
    assert "docker compose up -d --wait postgres" in ci_text
    assert "image: postgres" not in ci_text
    assert len(pi_images) == 1


def test_ci_uses_the_same_uv_as_the_image() -> None:
    dockerfile_uv = re.search(r"ghcr\.io/astral-sh/uv:([\d.]+)@", (ROOT / "Dockerfile").read_text())
    assert dockerfile_uv is not None
    for workflow in ("ci.yml", "claude.yml"):
        workflow_text = (ROOT / ".github/workflows" / workflow).read_text()
        assert f'version: "{dockerfile_uv.group(1)}"' in workflow_text, workflow
