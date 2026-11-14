"""GC-P21 G3 evidence: the committed alert proof is real, and carries nothing private.

GC-P17 set the precedent this follows: a proof log is only evidence if something pins it,
because a log that quietly went stale — or was hand-written — proves nothing. So the card's
own command writes the file and the tests here read it back:

    uv run --frozen pytest -q tests/test_gc_p21_alerts_proof.py -vv -rA --no-header \
      | tee docs/internal/go-live-finish/evidence/GC-P21-alerts.log

Deliberately NOT collected by that command: this lives in a separate module, so the run that
*produces* the log never reads the half-written file `tee` is holding open. It is the GATE
(``uv run --frozen pytest -q``) that runs it, against the committed artifact.

The privacy scan is a regex over address-shaped text, not a substring sweep, on purpose: a
proof line carrying ``checkpoint_serial=1046`` or ``threshold=120.0`` is not a private
address, and an earlier draft of this repo's evidence tests failed its own card on exactly
that. The pre-cutover product/tenant spellings are not re-checked here either —
``tests/test_public_audit.py`` scans the contents of every tracked file for them, this file
included.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LOG = REPO_ROOT / "docs" / "internal" / "go-live-finish" / "evidence" / "GC-P21-alerts.log"

#: The three lines the proof module prints, one per accepted behaviour. A log missing one of
#: them did not come from a run that proved that behaviour.
PROOF_MARKERS = (
    "GC-P21 push proof:",
    "GC-P21 stall proof:",
    "GC-P21 skew proof:",
)

#: What each proof line must report to satisfy the card's ACCEPT bullets — the values the
#: card names, read out of the run rather than asserted by me alone.
PROOF_EXPECTATIONS = {
    "GC-P21 push proof:": (
        "push_failed=1",
        "attempts=1",
        "error_class=HttpStatus503",
    ),
    "GC-P21 stall proof:": (
        "strikes=3",
        "checkpoint_stall:critical",
        "unmoved=1",
    ),
    "GC-P21 skew proof:": (
        "skew_seconds=3600.0",
        "warn=True",
        "threshold=120.0",
        "alerts=['clock_skew']",
    ),
}

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
#: The demo device binds loopback and the push transport is a fake, so loopback is the only
#: address this proof can legitimately name. TEST-NET is allowed by hygiene policy in case a
#: future run needs to print a documentation address.
ALLOWED_PREFIXES = ("127.", "192.0.2.", "198.51.100.", "203.0.113.")

#: Text that must never appear in a proof log: a secret, a wire credential header, or the
#: device fields that carry a person's identity. The demo corpus is synthetic by law
#: (`demo_device.py`'s SYNTHETIC-ONLY LAW, pinned by ARM B of tests/test_demo_device.py), so
#: any of these here came from outside the card's OUT list.
FORBIDDEN_TEXT = ("password", "passwd", "cardNo", "employeeNo", "Bearer ", "Authorization")


def _log_text() -> str:
    assert LOG.is_file(), f"the G3 evidence file {LOG.relative_to(REPO_ROOT)} is missing"
    text = LOG.read_text(encoding="utf-8")
    assert text.strip(), "the G3 evidence file is empty"
    return text


def test_evidence_log_reports_all_three_proofs() -> None:
    """The committed log is the three-test run, with every accepted value in it."""
    text = _log_text()
    for marker in PROOF_MARKERS:
        line = next((ln for ln in text.splitlines() if marker in ln), None)
        assert line is not None, f"{marker!r} never appears in the log"
        for expected in PROOF_EXPECTATIONS[marker]:
            assert expected in line, f"{marker} line does not report {expected}: {line}"
    assert "3 passed" in text, "the log is not a clean three-test run"


def test_evidence_log_names_no_private_address_or_identity() -> None:
    """Only loopback/TEST-NET addresses, and no credential or identity-shaped field."""
    text = _log_text()
    addresses = IPV4.findall(text)
    offenders = [ip for ip in addresses if not ip.startswith(ALLOWED_PREFIXES)]
    assert not offenders, f"non-loopback addresses in the log: {offenders}"
    for ip in addresses:
        assert ipaddress.ip_address(ip).version == 4
    for forbidden in FORBIDDEN_TEXT:
        assert forbidden not in text, f"the log carries {forbidden!r}"


def test_evidence_log_is_a_tracked_artifact() -> None:
    """An evidence file nobody commits is a scratch note (GC-P17's lesson)."""
    git = shutil.which("git")
    assert git is not None, "no git on PATH to ask"
    listed = subprocess.run(  # noqa: S603 — fixed argv, no shell, no user input
        [git, "ls-files", "--error-unmatch", str(LOG.relative_to(REPO_ROOT))],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert listed.returncode == 0, (
        f"{LOG.relative_to(REPO_ROOT)} is not committed: {listed.stderr.strip()}"
    )
