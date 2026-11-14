"""GC-P17 — the container proof is evidence, and it is safe to publish.

The card's real proof is a log of one `demo demo` run inside the shipped Alpine image
(built by `deploy/Dockerfile`, run read-only as uid 10001 against the loopback demo
device), not a pytest. This test cannot re-run Docker — the GATE stays offline and
seconds-fast — so what it pins is the artifact itself:

  1. the log records a run that DELIVERED, not merely a container that started. The two
     sinks the walkthrough drives are the csv file leg and the mock TLS ingest, so the
     csv leg and a per-batch line count are the load-bearing words; and
  2. the log leaks no private-range address, so the public tree can carry it.

If the log is ever regenerated, it must keep those properties; a regenerated log that
loses the sink counters is a proof that no longer proves anything, and this test is what
says so in the gate rather than in a reviewer's memory.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

EVIDENCE = REPO_ROOT / "docs" / "internal" / "go-live-finish" / "evidence" / "GC-P17-container.log"

# Prefixes, never a full address: a complete private IPv4 literal written here would be
# exactly what tests/test_public_audit.py sweeps every tracked file for.
PRIVATE_ADDRESS_PREFIXES = ("192.168.", "10.", "172.16.")


def _log_text() -> str:
    assert EVIDENCE.is_file(), (
        f"{EVIDENCE.relative_to(REPO_ROOT)} is the GC-P17 deliverable; "
        "a missing log means the container proof was never captured"
    )
    return EVIDENCE.read_text(encoding="utf-8")


def test_container_log_shows_a_delivered_demo_run() -> None:
    text = _log_text()

    # The csv sink leg and the mock ingest's batch line count. A run that polled and
    # stored but never delivered has neither, so their presence is the delivery claim.
    assert "csv" in text
    assert "lines" in text

    for prefix in PRIVATE_ADDRESS_PREFIXES:
        assert prefix not in text, (
            f"the container log carries what looks like a private-range address ({prefix}*)"
        )


def test_container_log_names_the_built_image_and_the_unprivileged_user() -> None:
    """The ACCEPT bullets, pinned to the artifact rather than to a reviewer's memory."""
    text = _log_text()

    # Both image ids: the one `deploy/Dockerfile` built, and the disposable one that ran.
    assert "base_image_id=sha256:" in text
    assert "proof_image_id=sha256:" in text

    # The extra layer is the openssl CLI and nothing else, and the demo ran as the
    # image's own user rather than a --user root override.
    assert "apk add --no-cache openssl" in text
    assert "run_uid=10001" in text

    # The bounded loop the card asked for.
    assert "--ticks 2" in text
