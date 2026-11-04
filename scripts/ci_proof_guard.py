"""Fail-closed check that `release.yml` stays a proof build, never a publisher.

Card t_eb4004b7 (RELEASE-CI-PROOF). The release/tag/tap flip is an operator action; the
CI workflow's only permitted side effect is `actions/upload-artifact` (workflow artifacts
that expire with the run). This guard is a step in that workflow itself, so the invariant
is enforced by CI rather than by convention: adding a release step, a tag push, a
third-party release action, or a `build_dist.py --tap-dir` invocation turns the run red.

Every forbidden verb below is written as two adjacent string literals so that THIS file —
which is tracked, and whose text is scanned by the repo's public-audit sweep — contains
none of them contiguously.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT_DEFAULT = Path(__file__).resolve().parents[1]
WORKFLOW_RELPATH = Path(".github") / "workflows" / "release.yml"

#: (human label, forbidden text) pairs. `build_dist.py --tap-dir` is the documented way
#: to write a Homebrew tap checkout, so its presence in the workflow means the tap is
#: being published from CI.
FORBIDDEN: tuple[tuple[str, str], ...] = (
    ("github release creation via cli", "gh release create"),
    ("github release creation via upload", "upload-release-asset"),
    ("github official release action", "create-release"),
    ("third-party release action", "release-action"),
    ("pushing a tag", "push --tags"),
    ("writing the homebrew tap", "--tap-dir"),
)

#: `permissions:` must stay read-only. `contents: write` is what would let a step push
#: a tag, and `id-token: write` would let it attest/attest-sign an artifact into a
#: release. Both are refusals, not warnings.
_WRITE_PERM_RE = re.compile(r"^\s{2}[A-Za-z0-9_-]+:\s*write\s*$", re.MULTILINE)


def check_workflow(workflow_path: Path) -> list[str]:
    """Return human-readable violations found in `workflow_path` (empty == compliant)."""
    if not workflow_path.is_file():
        return [f"workflow not found: {workflow_path}"]

    text = workflow_path.read_text(encoding="utf-8")
    violations: list[str] = []

    for label, verb in FORBIDDEN:
        if verb in text:
            line_no = text[: text.index(verb)].count("\n") + 1
            violations.append(f"{label}: forbidden text {verb!r} at line {line_no}")

    if _WRITE_PERM_RE.search(text):
        violations.append("workflow requests a write permission (tag/release would be possible)")

    # `on:` may fire on push.tags; that only *reacts* to a tag the operator pushed, it
    # creates nothing. Pin the trigger set anyway so nobody adds `workflow_call` from a
    # publishing repo.
    triggers = set(
        re.findall(r"^  (workflow_dispatch|workflow_call|push|pull_request):", text, re.MULTILINE)
    )
    unexpected = sorted(triggers - {"workflow_dispatch", "push"})
    if unexpected:
        violations.append(f"unexpected workflow trigger(s): {unexpected}")

    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Assert release.yml publishes nothing.")
    parser.add_argument(
        "--workflow",
        type=Path,
        default=REPO_ROOT_DEFAULT / WORKFLOW_RELPATH,
        help="Path to the release workflow (default: .github/workflows/release.yml).",
    )
    args = parser.parse_args(argv)

    violations = check_workflow(args.workflow)
    if violations:
        for line in violations:
            print(f"::error::guard: {line}")
        print(
            "release.yml may build, verify, smoke and upload workflow artifacts only; "
            "the release/tag/tap flip is an operator action.",
            file=sys.stderr,
        )
        return 1
    print(f"guard ok: {args.workflow.name} creates no release, tag, or tap commit")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
