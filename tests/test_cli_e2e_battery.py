"""Card p1-09, second layer: the invariants that must hold on EVERY scenario box.

Where test_cli_e2e.py asserts what makes each box *different*, this file asserts what no
box may ever do — the whole-corpus pass that turns per-scenario evidence into a
guarantee:

* the read-only promise, checked against what the DEVICE RECEIVED (methods + the
  endpoint registry), not against a config someone could forget to update;
* re-running the same window re-reads the same events (P1 has no store; idempotency is
  by record key, and the CLI's output for a box is a pure function of the box);
* `captured_at` is our read-time stamp and participates in no key (the model card's
  rule, checked on every row of every box through the CLI).

If a new scenario violates one of these, it fails here without this file changing —
that is why the assertions iterate `SCENARIOS` instead of listing names.
"""

from __future__ import annotations

import pytest

from e2e_harness import (
    ALLOWED_PATHS,
    ALLOWED_POST_PATHS,
    GOLDEN_NOW,
    SCENARIOS,
    conn_args,
    install,
)

ALL_SCENARIOS = list(SCENARIOS)


@pytest.fixture
def box(monkeypatch: pytest.MonkeyPatch):
    def _install(name: str):
        return install(SCENARIOS[name], monkeypatch)

    return _install


@pytest.mark.parametrize("name", ALL_SCENARIOS)
def test_no_box_ever_leaves_the_read_only_registry(box, name: str) -> None:
    """Only GETs and the stateless search POSTs, ever, on every endpoint observed.

    DESIGN.md's hard rule, enforced on the wire: for every request the FakeDevice
    actually received, the method is GET or POST and the path+query is in the read-only
    registry (gateclerk.endpoints is the product-side list; ALLOWED_PATHS here is the
    test-side pin — if they drift, this test and the registry test disagree loudly).
    A PUT to a door, a POST to UserInfo (a WRITE), a reboot: any of them fails here even
    if the code never calls them today, because the check is per served request.
    """
    e2e = box(name)
    code, _ = e2e.run_events()
    e2e.run(["users", "list", *conn_args(), "--output", "jsonl"])
    e2e.run(["device", "info", *conn_args(), "--output", "json"])
    e2e.run(["device", "time", *conn_args(), "--output", "json"])
    e2e.run(["device", "capabilities", *conn_args(), "--output", "json"])
    assert code == SCENARIOS[name].expect_exit, (
        f"{name}: events exited {code}, the wire audit below proves nothing"
    )
    for served in e2e.device.served:
        target = f"{served.method} {served.path}"
        assert served.method in {"GET", "POST"}, f"{name}: verb {served.method!r} on {target}"
        assert served.path in ALLOWED_PATHS, f"{name}: unregistered endpoint {target}"
        if served.method == "POST":
            assert served.path in ALLOWED_POST_PATHS, f"{name}: write-shaped POST {target}"


def test_registry_and_harness_allowlists_agree() -> None:
    """The test-side allowlist is not allowed to silently permit MORE than the product.

    If someone adds an endpoint to `gateclerk.endpoints` and forgets the harness, the
    battery still refuses it (a new endpoint must be a reviewed decision — DESIGN.md).
    If someone widens the harness without the registry, this names the drift here
    instead of in a confusing per-scenario failure.
    """
    from gateclerk import endpoints

    # The registry stores bare paths; the wire (and the digest uri=) always carries
    # format=json — `url_path` is the product's own join of the two.
    registered = {ep.url_path for ep in endpoints.REGISTRY.values()}
    extra = ALLOWED_PATHS - registered
    assert not extra, f"harness allows paths the product registry does not know: {sorted(extra)}"


@pytest.mark.parametrize("name", ALL_SCENARIOS)
def test_events_is_a_pure_reread_of_the_box(box, name: str) -> None:
    """Two identical runs print identical bytes (no store, no checkpoint — P1 contract).

    DESIGN.md: re-running the same window re-reads the same events and that is FREE by
    design because the dedupe key is (device_serial, serial_no) — which only works if
    the same window produces the same records. A run that drifts (order, fields, a
    cursor that remembers) breaks the P2 UPSERT assumption, and this catches it on
    every box including the busy/nonce-recovery ones (where retries are allowed to
    change HOW, as long as WHAT stays byte-identical).

    Each run gets a FRESH device install: re-running against the same FakeDevice would
    read from a drained page queue — a harness artifact, not the property under test
    (the property is "same box, same window -> same output", box included).
    """
    e2e_a = box(name)
    code_a, out_a = e2e_a.run_events()
    e2e_b = box(name)
    code_b, out_b = e2e_b.run_events()
    assert code_a == code_b == SCENARIOS[name].expect_exit
    if SCENARIOS[name].expect_exit == 0:
        assert out_a == out_b
    else:
        # The error payload quotes the request body — which carries a fresh uuid4
        # searchID per run (inside escaped JSON, so match the 32-hex token itself).
        # The STABLE part of the contract is the error class and the window it
        # complained about, not the random id; compare everything else.
        import re

        norm = lambda s: re.sub(r"\b[0-9a-f]{32}\b", "X", s)  # noqa: E731
        assert norm(out_a) == norm(out_b)


@pytest.mark.parametrize("name", ALL_SCENARIOS)
def test_captured_at_is_the_pinned_read_stamp_on_every_row(box, name: str) -> None:
    """Every record says WHEN WE READ it — from the CLI's own clock seam, unchanged.

    The goldens pin it byte-wise; this pins it structurally, so a refactor that keeps
    the golden format but re-derives `captured_at` somewhere else (a wall clock, a
    device field) fails here too. And it must never be a device fact: `raw` has no
    captured_at to leak from. (The error box prints no records — nothing to pin.)
    """
    if SCENARIOS[name].expect_exit != 0:
        pytest.skip("error box prints no records")
    e2e = box(name)
    _, out = e2e.run_events()
    rows = e2e.rows(out)
    stamp = GOLDEN_NOW.strftime("%Y-%m-%dT%H:%M:%S") + "+00:00"
    assert rows, "a box with zero records pins nothing"
    for row in rows:
        assert row["captured_at"] == stamp
        assert "captured_at" not in row["raw"]


@pytest.mark.parametrize("name", ALL_SCENARIOS)
def test_every_row_carries_the_idempotency_key_material(box, name: str) -> None:
    """(device_serial, serial_no) is the P2 UPSERT key: present on every printed record.

    The serial comes from deviceInfo on every walk (same MASKED value the recorded
    fixture holds); serial_no is the device's own counter. A row missing either cannot
    be upserted — it would be a payroll duplicate or a hole, discovered at month-end.
    """
    if SCENARIOS[name].expect_exit != 0:
        pytest.skip("error box prints no records")
    e2e = box(name)
    _, out = e2e.run_events()
    rows = e2e.rows(out)
    assert rows
    for row in rows:
        assert row["device_serial"] == "MASKED-SER-1"
        assert isinstance(row["serial_no"], int)


@pytest.mark.parametrize("name", ALL_SCENARIOS)
def test_count_crosscheck_is_advisory_never_fatal(box, name: str) -> None:
    """`--count` compares and reports; it must never change the exit code or lose rows.

    AcsEventTotalNum answered here is exact per box (the harness computes it from the
    fixtures), so the line agrees — but the property under test is that the flag is
    DISPLAY ONLY (DESIGN.md: totalMatches is advisory, never a loop bound): same
    records, same exit code as without it, on every box. Fresh install per run (the
    page queue draining mid-test is a harness artifact, not the property).
    """
    e2e = box(name)
    code_plain, plain = e2e.run_events()
    e2e2 = box(name)
    code_count, with_count = e2e2.run_events("--count")
    assert code_plain == code_count == SCENARIOS[name].expect_exit
    if code_plain == 0:
        assert e2e.rows(plain) == e2e.rows(with_count)
        # the crosscheck line goes to stderr in the real CLI; CliRunner may merge —
        # if it appears on stdout it must be the honest comparison for this box.
        for line in with_count.splitlines():
            if line.startswith("count:"):
                assert "device says" in line
