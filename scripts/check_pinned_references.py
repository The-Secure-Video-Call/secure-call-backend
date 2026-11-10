"""Fails when a GitHub Action or a container image is not pinned to an exact, immutable version.

- Every `uses:` in .github/workflows/ must name a full 40-character commit SHA (a tag or branch
  can be moved to other code). Local actions (`./...`) are allowed.
- Every image in a Dockerfile (`FROM`, `COPY --from=`), a compose file or a workflow (`image:`)
  must carry an `@sha256:` digest, except build stages and our own images in OWN_IMAGES.

Usage: python scripts/check_pinned_references.py [REPOSITORY_ROOT]
Prints one line per unpinned reference and exits 1, or exits 0 when everything is pinned.
Standard library only, so CI can run it before anything is installed.
"""

import re
import sys
from pathlib import Path
from typing import NamedTuple

# Images we build ourselves, on purpose referenced by a moving tag: update.sh pulls `main`, and
# the coturn image is built on the Pi from deploy/raspberry-pi/coturn/Dockerfile (pinned there).
OWN_IMAGES = frozenset(
    {
        "ghcr.io/the-secure-video-call/secure-call-backend:main",
        "secure-call-coturn:local",
    }
)

USES_LINE = re.compile(r"^\s*(?:-\s+)?uses:\s*['\"]?(?P<reference>[^'\"\s#]+)")
IMAGE_LINE = re.compile(r"^\s*(?:-\s+)?image:\s*['\"]?(?P<reference>[^'\"\s#]+)")
FROM_LINE = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(?P<reference>\S+)(?:\s+AS\s+(?P<stage>\S+))?",
    re.IGNORECASE,
)
COPY_FROM = re.compile(r"^\s*COPY\s+.*--from=(?P<reference>\S+)", re.IGNORECASE)
FULL_COMMIT_SHA = re.compile(r"@[0-9a-f]{40}$")
IMAGE_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")


class UnpinnedReference(NamedTuple):
    line_number: int
    reference: str


def find_unpinned_actions(workflow_text: str) -> list[UnpinnedReference]:
    unpinned: list[UnpinnedReference] = []
    for line_number, line in enumerate(workflow_text.splitlines(), start=1):
        match = USES_LINE.match(line)
        if match is None:
            continue
        reference = match["reference"]
        if reference.startswith("./") or reference.startswith("docker://"):
            if reference.startswith("docker://") and not IMAGE_DIGEST.search(reference):
                unpinned.append(UnpinnedReference(line_number, reference))
            continue
        if not FULL_COMMIT_SHA.search(reference):
            unpinned.append(UnpinnedReference(line_number, reference))
    return unpinned


def is_pinned_image(reference: str) -> bool:
    return reference in OWN_IMAGES or IMAGE_DIGEST.search(reference) is not None


def find_unpinned_images_in_yaml(yaml_text: str) -> list[UnpinnedReference]:
    unpinned: list[UnpinnedReference] = []
    for line_number, line in enumerate(yaml_text.splitlines(), start=1):
        match = IMAGE_LINE.match(line)
        if match is not None and not is_pinned_image(match["reference"]):
            unpinned.append(UnpinnedReference(line_number, match["reference"]))
    return unpinned


def find_unpinned_images_in_dockerfile(dockerfile_text: str) -> list[UnpinnedReference]:
    unpinned: list[UnpinnedReference] = []
    stage_names: set[str] = set()
    for line_number, line in enumerate(dockerfile_text.splitlines(), start=1):
        from_match = FROM_LINE.match(line)
        if from_match is not None:
            reference = from_match["reference"]
            if reference.lower() not in stage_names and not is_pinned_image(reference):
                unpinned.append(UnpinnedReference(line_number, reference))
            if from_match["stage"]:
                stage_names.add(from_match["stage"].lower())
            continue
        copy_match = COPY_FROM.match(line)
        if copy_match is not None:
            reference = copy_match["reference"]
            if reference.lower() not in stage_names and not is_pinned_image(reference):
                unpinned.append(UnpinnedReference(line_number, reference))
    return unpinned


def find_unpinned_references(repository_root: Path) -> list[str]:
    """Every unpinned reference in the repository, as `path:line: reference` lines."""
    problems: list[str] = []

    def report(path: Path, references: list[UnpinnedReference]) -> None:
        relative_path = path.relative_to(repository_root)
        problems.extend(f"{relative_path}:{ref.line_number}: {ref.reference}" for ref in references)

    workflow_paths = sorted((repository_root / ".github" / "workflows").glob("*.y*ml"))
    for workflow_path in workflow_paths:
        workflow_text = workflow_path.read_text()
        report(workflow_path, find_unpinned_actions(workflow_text))
        report(workflow_path, find_unpinned_images_in_yaml(workflow_text))
    for dockerfile_path in sorted(repository_root.glob("**/Dockerfile")):
        if ".venv" not in dockerfile_path.parts:
            report(dockerfile_path, find_unpinned_images_in_dockerfile(dockerfile_path.read_text()))
    for compose_path in sorted(repository_root.glob("deploy/**/compose.y*ml")):
        report(compose_path, find_unpinned_images_in_yaml(compose_path.read_text()))
    return problems


def main(arguments: list[str]) -> int:
    repository_root = Path(arguments[0] if arguments else ".").resolve()
    problems = find_unpinned_references(repository_root)
    for problem in problems:
        print(f"not pinned: {problem}")
    if problems:
        print(
            f"{len(problems)} reference(s) not pinned. Pin actions to a full commit SHA and "
            "images to an @sha256: digest."
        )
        return 1
    print("All actions and images are pinned.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
