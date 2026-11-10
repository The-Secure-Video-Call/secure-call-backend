"""Fails when a GitHub Action or a container image is not pinned to an exact, immutable version.

- Every `uses:` in workflows and in local action metadata must name a full 40-character commit
  SHA (a tag or branch can be moved to other code). Local actions (`./...`) are allowed, and
  their own `uses:` are checked too.
- Every image must carry an `@sha256:` digest: in Dockerfiles (`# syntax=`, `FROM`,
  `COPY --from=`, `RUN --mount=...from=`, also after `ONBUILD`), in compose files and in
  workflows (`image:`, a scalar `container:`, `image=` options). Build stages and `scratch` are
  allowed, and our own images in OWN_IMAGES only in deploy/raspberry-pi/compose.yaml.

The checks read lines, not YAML, so they are written to fail closed: a `uses`/`image` key is
found anywhere on a line (flow style, quoted keys, a space before the colon), and an empty value
is taken from the next line. A reference it cannot read is reported, never skipped.

Usage: python scripts/check_pinned_references.py [REPOSITORY_ROOT]
Prints one line per unpinned reference and exits 1, or exits 0 when everything is pinned.
Standard library only, so CI can run it before anything is installed.
"""

import re
import sys
from pathlib import Path
from typing import NamedTuple

# Images we build ourselves, on purpose referenced by a moving tag, and only where they are used:
# update.sh pulls `main`, and the coturn image is built on the Pi from a pinned Dockerfile.
OWN_IMAGES_BY_FILE = {
    "deploy/raspberry-pi/compose.yaml": frozenset(
        {
            "ghcr.io/the-secure-video-call/secure-call-backend:main",
            "secure-call-coturn:local",
        }
    )
}

YAML_KEY = re.compile(
    r"""(?:^|[\s{,\[])["']?(?P<key>uses|image|container)["']?\s*:(?!:)\s*(?P<value>.*)$"""
)
IMAGE_OPTION = re.compile(r"""\bimage=(?P<reference>[^\s,'"]+)""")
FULL_COMMIT_SHA_REFERENCE = re.compile(r"^[\w.-]+/[\w.-]+(?:/[^@\s]+)?@[0-9a-f]{40}$")
DIGEST_IMAGE_REFERENCE = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
YAML_MAPPING_KEY = re.compile(r"""^\s*(?:-\s+)?["']?[\w.-]+["']?\s*:(?:\s|$)""")

PARSER_DIRECTIVE = re.compile(r"^#\s*(?P<name>\w+)\s*=\s*(?P<value>\S+)", re.IGNORECASE)
INSTRUCTION = re.compile(r"^\s*(?:ONBUILD\s+)?(?P<name>[A-Za-z]+)\s+(?P<rest>.*)$", re.IGNORECASE)
FROM_ARGUMENTS = re.compile(
    r"^(?:--platform=\S+\s+)?(?P<reference>\S+)(?:\s+AS\s+(?P<stage>\S+))?", re.IGNORECASE
)
COPY_FROM_OPTION = re.compile(r"--from=(?P<reference>\S+)", re.IGNORECASE)
MOUNT_FROM_OPTION = re.compile(r"--mount=\S*?\bfrom=(?P<reference>[^,\s]+)", re.IGNORECASE)


class UnpinnedReference(NamedTuple):
    line_number: int
    reference: str


def clean_scalar(value: str) -> str:
    """The first token of a YAML scalar: no quotes, comment, or flow-style rest."""
    value = value.split(" #", 1)[0].strip()
    value = re.split(r"[,}\]]", value, maxsplit=1)[0].strip()
    return value.strip("'\"")


def yaml_values(yaml_text: str) -> list[tuple[int, str, str]]:
    """(line number, key, value) for every uses/image/container key, empty values resolved."""
    lines = yaml_text.splitlines()
    found: list[tuple[int, str, str]] = []
    for index, line in enumerate(lines):
        if line.lstrip().startswith("#"):
            continue
        match = YAML_KEY.search(line)
        if match is None:
            continue
        value = clean_scalar(match["value"])
        line_number = index + 1
        if value in {"", "|", ">", "|-", ">-"}:
            # The value is on a following line, or this key opens a mapping (container: ...).
            next_line = next(
                (
                    candidate
                    for candidate in lines[index + 1 :]
                    if candidate.strip() and not candidate.lstrip().startswith("#")
                ),
                "",
            )
            if YAML_MAPPING_KEY.match(next_line) and match["key"] == "container":
                continue  # a container mapping: its own `image:` line is checked separately
            value = clean_scalar(next_line)
        found.append((line_number, match["key"], value))
    return found


def is_pinned_action(reference: str) -> bool:
    if reference.startswith("./"):
        return True
    if reference.startswith("docker://"):
        return DIGEST_IMAGE_REFERENCE.match(reference.removeprefix("docker://")) is not None
    return FULL_COMMIT_SHA_REFERENCE.match(reference) is not None


def is_pinned_image(reference: str, own_images: frozenset[str] = frozenset()) -> bool:
    return reference in own_images or DIGEST_IMAGE_REFERENCE.match(reference) is not None


def find_unpinned_actions(workflow_text: str) -> list[UnpinnedReference]:
    return [
        UnpinnedReference(line_number, value or "(no value)")
        for line_number, key, value in yaml_values(workflow_text)
        if key == "uses" and not is_pinned_action(value)
    ]


def find_unpinned_images_in_yaml(
    yaml_text: str, own_images: frozenset[str] = frozenset()
) -> list[UnpinnedReference]:
    unpinned = [
        UnpinnedReference(line_number, value or "(no value)")
        for line_number, key, value in yaml_values(yaml_text)
        if key in {"image", "container"} and not is_pinned_image(value, own_images)
    ]
    for line_number, line in enumerate(yaml_text.splitlines(), start=1):
        for match in IMAGE_OPTION.finditer(line):  # e.g. buildx driver-opts: image=...
            if not is_pinned_image(match["reference"], own_images):
                unpinned.append(UnpinnedReference(line_number, match["reference"]))
    return unpinned


def joined_dockerfile_lines(dockerfile_text: str) -> list[tuple[int, str]]:
    """Instructions with `\\` continuations joined, each with the line number it starts on."""
    joined: list[tuple[int, str]] = []
    current_parts: list[str] = []
    start_line = 0
    for line_number, line in enumerate(dockerfile_text.splitlines(), start=1):
        if not current_parts:
            start_line = line_number
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            current_parts.append(stripped[:-1])
            continue
        current_parts.append(stripped)
        joined.append((start_line, " ".join(part.strip() for part in current_parts)))
        current_parts = []
    if current_parts:
        joined.append((start_line, " ".join(part.strip() for part in current_parts)))
    return joined


def find_unpinned_images_in_dockerfile(dockerfile_text: str) -> list[UnpinnedReference]:
    unpinned: list[UnpinnedReference] = []
    stage_names: set[str] = set()
    stage_count = 0
    seen_instruction = False

    def check_source(line_number: int, reference: str) -> None:
        name = reference.lower()
        if name in stage_names or name == "scratch" or (name.isdigit() and int(name) < stage_count):
            return
        if not is_pinned_image(reference):
            unpinned.append(UnpinnedReference(line_number, reference))

    for line_number, line in joined_dockerfile_lines(dockerfile_text):
        if not seen_instruction:
            directive = PARSER_DIRECTIVE.match(line)
            if directive is not None and directive["name"].lower() == "syntax":
                check_source(line_number, directive["value"])  # the BuildKit frontend image
                continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        instruction = INSTRUCTION.match(line)
        if instruction is None:
            continue
        seen_instruction = True
        name, rest = instruction["name"].upper(), instruction["rest"]
        if name == "FROM":
            from_arguments = FROM_ARGUMENTS.match(rest)
            if from_arguments is None:
                unpinned.append(UnpinnedReference(line_number, rest or "(no image)"))
                continue
            check_source(line_number, from_arguments["reference"])
            if from_arguments["stage"]:
                stage_names.add(from_arguments["stage"].lower())
            stage_count += 1
        elif name in {"COPY", "ADD"}:
            for option in COPY_FROM_OPTION.finditer(rest):
                check_source(line_number, option["reference"])
        elif name == "RUN":
            for option in MOUNT_FROM_OPTION.finditer(rest):
                check_source(line_number, option["reference"])
    return unpinned


def repository_files(repository_root: Path, patterns: list[str]) -> list[Path]:
    skipped_parts = {".venv", "node_modules", ".git"}
    found: set[Path] = set()
    for pattern in patterns:
        found.update(
            path
            for path in repository_root.glob(pattern)
            if path.is_file() and not skipped_parts.intersection(path.parts)
        )
    return sorted(found)


def find_unpinned_references(repository_root: Path) -> list[str]:
    """Every unpinned reference in the repository, as `path:line: reference` lines."""
    problems: list[str] = []

    def report(path: Path, references: list[UnpinnedReference]) -> None:
        relative_path = path.relative_to(repository_root)
        problems.extend(f"{relative_path}:{ref.line_number}: {ref.reference}" for ref in references)

    workflow_like = repository_files(
        repository_root,
        [".github/workflows/*.y*ml", ".github/actions/**/action.y*ml", "action.y*ml"],
    )
    for path in workflow_like:
        text = path.read_text()
        report(path, find_unpinned_actions(text))
        report(path, find_unpinned_images_in_yaml(text))
    dockerfiles = repository_files(
        repository_root, ["**/Dockerfile", "**/Dockerfile.*", "**/*.Dockerfile", "**/Containerfile"]
    )
    for path in dockerfiles:
        report(path, find_unpinned_images_in_dockerfile(path.read_text()))
    compose_files = repository_files(
        repository_root, ["**/compose.y*ml", "**/docker-compose*.y*ml", "**/compose.*.y*ml"]
    )
    for path in compose_files:
        own_images = OWN_IMAGES_BY_FILE.get(
            path.relative_to(repository_root).as_posix(), frozenset()
        )
        report(path, find_unpinned_images_in_yaml(path.read_text(), own_images))
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
