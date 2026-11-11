"""publish-image.yml publishes :main only for an image whose attestation the Pi would accept.

Text checks (the workflow only runs on GitHub): the published image is built without a cache,
only from main, :main moves last, after the attestation is signed and verified with exactly the
flags update.sh uses, and the image scan keeps its settings.
"""

from pathlib import Path

import pytest

from tests.test_update_sh import VERIFY_POLICY_FLAGS

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "publish-image.yml"
WORKFLOW_TEXT = WORKFLOW_PATH.read_text()


def configuration_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if not line.lstrip().startswith("#")]


def find_publish_workflow_problems(workflow_text: str) -> list[str]:
    problems: list[str] = []
    before_publish, separator, publish_job = workflow_text.partition("\n  publish:\n")
    if not separator:
        return ["no publish job"]
    publish_lines = configuration_lines(publish_job)
    scan_lines = configuration_lines(before_publish)

    if "cancel-in-progress: ${{ github.event_name == 'pull_request' }}" not in scan_lines:
        problems.append("a publish on main can be cancelled halfway")
    if (
        "if: github.event_name != 'pull_request' && github.ref == 'refs/heads/main'"
        not in publish_lines
    ):
        problems.append("the publish job can run on another branch")
    if "no-cache: true" not in publish_lines or any(
        line.startswith(("cache-from:", "cache-to:")) for line in publish_lines
    ):
        problems.append("the published image can reuse a build cache")
    if any(line.startswith("tags:") and ":main" in line for line in publish_lines):
        problems.append("the build pushes :main before the attestation is checked")

    publish_text = "\n".join(publish_lines)
    steps_in_order = (
        "uses: actions/attest@",
        'gh attestation verify "oci://',
        "imagetools create --tag",
    )
    positions = [publish_text.find(step) for step in steps_in_order]
    if -1 in positions or positions != sorted(positions):
        problems.append(f"the publish steps are not in the order {steps_in_order}")
    problems.extend(
        f"the verification lacks update.sh's {flag}"
        for flag in VERIFY_POLICY_FLAGS
        if flag not in publish_text
    )
    if "--source-ref refs/heads/not-main" not in publish_text:
        problems.append("no check that a wrong --source-ref is refused")

    for setting in (
        "vuln-type: os,library",
        "severity: HIGH,CRITICAL",
        "ignore-unfixed: true",
        'exit-code: "1"',
        'cache: "false"',
        'TRIVY_DISABLE_TELEMETRY: "true"',
        'TRIVY_SKIP_VERSION_CHECK: "true"',
    ):
        if setting not in scan_lines:
            problems.append(f"the image scan lacks {setting}")
    return problems


def test_publish_workflow_is_as_intended() -> None:
    assert find_publish_workflow_problems(WORKFLOW_TEXT) == []


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        (" && github.ref == 'refs/heads/main'", ""),
        ("${{ github.event_name == 'pull_request' }}", "true"),
        ("          no-cache: true\n", "          cache-from: type=gha\n"),
        ("          no-cache: true\n", ""),
        ("tags: ${{ env.IMAGE }}:sha-${{ github.sha }}", "tags: ${{ env.IMAGE }}:main"),
        ("              --deny-self-hosted-runners \\\n", ""),
        ("--predicate-type https://slsa.dev/provenance/v1", "--predicate-type x"),
        ("refs/heads/not-main", "refs/heads/main"),
        ("imagetools create --tag", "imagetools create -t"),
        ("vuln-type: os,library", "vuln-type: os"),
        ('cache: "false"', 'cache: "true"'),
        ('TRIVY_DISABLE_TELEMETRY: "true"', 'TRIVY_DISABLE_TELEMETRY: "false"'),
    ],
)
def test_weakened_publish_workflow_is_caught(original: str, replacement: str) -> None:
    assert original in WORKFLOW_TEXT
    weakened_text = WORKFLOW_TEXT.replace(original, replacement, 1)

    assert find_publish_workflow_problems(weakened_text) != []


def test_moving_main_before_the_verification_is_caught() -> None:
    move_step_start = WORKFLOW_TEXT.index("      # A single image index as the only source")
    move_step = WORKFLOW_TEXT[move_step_start:]
    attest_step_start = WORKFLOW_TEXT.index("      # A signed SLSA build provenance attestation")
    reordered_text = (
        WORKFLOW_TEXT[:attest_step_start]
        + move_step
        + WORKFLOW_TEXT[attest_step_start:move_step_start]
    )

    assert "the publish steps are not in the order" in " ".join(
        find_publish_workflow_problems(reordered_text)
    )
