"""Card p1-09, first layer: every documented scenario box, driven through the FULL CLI.

One parametrized pass per scenario over `tests/fixtures/scenarios/` (the corpus is
documented in tests/fixtures/README.md; the README test below pins corpus == docs):

* `events --format jsonl` is compared byte-for-byte against a committed golden in
  `tests/golden/` — record shape, key order, and the pinned `captured_at` are the
  contract, and the golden diff is the review artifact when it changes.
* `users list --output jsonl` gets the same treatment: the roster half of the
  payroll record (names verbatim, NFD fixture normalized to NFC by the MODEL).
* the box's specific pathology is asserted separately, from what the DEVICE saw
  (served request bodies), not from what the fake served back.

Regenerate goldens deliberately: `GATECLERK_UPDATE_GOLDEN=1 uv run pytest
tests/test_cli_e2e.py`, read `git diff tests/golden`, commit only what you meant to
change.

Offline by construction (tests/conftest.py `netoff` stays autouse; the CLI's client
is rebuilt over FakeDevice's MockTransport — see tests/e2e_harness.py).
"""

from __future__ import annotations

import json
import unicodedata

import pytest

from e2e_harness import (
    EVENT_PATH,
    SCENARIOS,
    check_golden,
    conn_args,
    golden_name,
    install,
)
from gateclerk.model import from_jsonl


@pytest.fixture
def box(monkeypatch: pytest.MonkeyPatch):
    """Install a named scenario as a live E2E (returns the harness object)."""

    def _install(name: str):
        return install(SCENARIOS[name], monkeypatch)

    return _install


# --- goldens: the jsonl contract ---------------------------------------------------------

ALL_SCENARIOS = list(SCENARIOS)


@pytest.mark.parametrize("name", ALL_SCENARIOS)
def test_events_jsonl_matches_golden(box, name: str) -> None:
    """The scenario's whole CLI output for `events` is a committed, diffable contract.

    Skipped for boxes that end in an error payload: that payload quotes the request
    body, which carries a fresh uuid4 searchID per run — a byte golden of random data
    is noise. The error contract for those boxes is pinned structurally instead
    (test_invalid_content_is_terminal_exit_4...).
    """
    if SCENARIOS[name].expect_exit != 0:
        pytest.skip("error-payload output embeds a random searchID; pinned structurally")
    e2e = box(name)
    code, out = e2e.run_events()
    assert code == 0, f"events exited {code}: {out[:800]}"
    check_golden(golden_name("events", SCENARIOS[name]), out)


@pytest.mark.parametrize("name", ALL_SCENARIOS)
def test_events_golden_is_parseable_and_lossless(box, name: str) -> None:
    """A golden that only compares bytes could freeze an unparseable stream.

    So parse it twice: `gateclerk.model.from_jsonl` must accept it, and re-serializing
    the parsed records must reproduce the same lines. The payroll consumer's contract
    and the producer's bytes have to agree from BOTH directions.
    """
    if SCENARIOS[name].expect_exit != 0:
        pytest.skip("no record stream to round-trip on an error box")
    e2e = box(name)
    _, out = e2e.run_events()
    records = from_jsonl(out)
    assert len(records) == len(e2e.rows(out))
    rebuilt = "".join(r.to_json() + "\n" for r in records)
    assert rebuilt == out


@pytest.mark.parametrize("name", ALL_SCENARIOS)
def test_users_jsonl_matches_golden(box, name: str) -> None:
    """The roster half of the record — `valid` window, name verbatim — as a golden too."""
    e2e = box(name)
    code, out = e2e.run(["users", "list", *conn_args(), "--output", "jsonl"])
    assert code == 0, f"users list exited {code}: {out[:800]}"
    check_golden(golden_name("users", SCENARIOS[name]), out)


# --- per-pathology assertions (from the DEVICE's side of the wire) ----------------------


def test_happy_day_walks_one_page_in_order(box) -> None:
    """Attendance mode ON: direction settles from attendanceStatus, order is device order."""
    e2e = box("happy_day")
    code, out = e2e.run_events()
    rows = e2e.rows(out)
    assert code == 0
    assert [r["serial_no"] for r in rows] == list(range(9001, 9013))
    punched = [r for r in rows if r["attendance_status"]]
    assert {r["direction"] for r in punched} == {"in", "out"}
    # DirectionSource.DEVICE: the device's own attendanceStatus settled it (model.py —
    # "device" is the spelling; "none" is site-a's real answer for status-less events).
    assert {r["direction_source"] for r in punched} == {"device"}
    # The +02:00-in-+03:00 stamp (OBSERVED.md): what we used vs what the box claimed.
    assert {r["tz_offset_min"] for r in rows} == {180}
    assert {r["tz_offset_min_device"] for r in rows} == {120}
    assert {r["tz_offset_mismatch"] for r in rows} == {True}
    assert e2e.positions() == [0]  # one page, 0-based cursor (OBSERVED.md)


def test_happy_day_chunked_restarts_cursor_per_chunk_and_keeps_the_edge(box) -> None:
    """Chunking: fresh searchID per chunk, cursor restarts at 0, edge event arrives TWICE.

    The overlap is the documented contract (inclusive device bounds; UPSERT makes the
    duplicate free) — but a chunk walk that silently LOST the edge punch is the payroll
    bug this pins. 13 distinct serials across 14 rows, boundary 9013 from both pages.
    """
    e2e = box("happy_day_chunked")
    code, out = e2e.run_events()
    rows = e2e.rows(out)
    assert code == 0
    conds = e2e.cond()
    ids = [c["searchID"] for c in conds]
    assert len(set(ids)) == 2, "each chunk is its own logical search"
    for sid in set(ids):
        own = [c for c in conds if c["searchID"] == sid]
        assert [c["searchResultPosition"] for c in own] == list(range(len(own)))
    serials = [r["serial_no"] for r in rows]
    assert len(serials) == len(set(serials)) + 1  # exactly one duplicate
    assert serials.count(9013) == 2  # the noon boundary punch, from both pages
    assert set(serials) == set(range(9001, 9014))


def test_naive_time_resolves_identically_to_the_offset_stamped_box(box) -> None:
    """A fw variant with no offset in the string must NOT change the resolved UTC.

    tz_source is site-tz with a None mismatch (nothing claimed) rather than a
    confidently-wrong claim — and the same wall times resolve to the same instants the
    +02:00-stamped spelling would give (both are read in Europe/Bucharest).
    """
    e2e = box("naive_time")
    code, out = e2e.run_events()
    rows = e2e.rows(out)
    assert code == 0 and len(rows) == 4
    assert {r["tz_source"] for r in rows} == {"site-tz"}
    assert {r["tz_offset_min_device"] for r in rows} == {None}
    assert {r["tz_offset_mismatch"] for r in rows} == {None}  # no claim -> None, never False
    assert {r["tz_offset_min"] for r in rows} == {180}
    # The box's System/time is naive too: the CLI reads it without inventing an offset.
    tcode, tout = e2e.run(["device", "time", *conn_args(), "--output", "json"])
    assert tcode == 0
    doc = json.loads(tout)
    assert doc["device_claimed_offset_min"] is None
    assert doc["skew_seconds"] is not None and abs(doc["skew_seconds"]) < 30


def test_dst_day_disambiguates_the_fold_and_flags_the_gap(box) -> None:
    """Bucharest 2026: the autumn fold takes the FIRST occurrence; the spring gap is kept.

    Bucharest falls back 04:00 EEST -> 03:00 EET on 2026-10-25, so wall 03:30 occurs
    TWICE. Two employees stamped naive 03:30 both resolve to the FIRST occurrence
    (+03:00 => 00:30 UTC) and both carry tz_ambiguous — the documented p1-06 rule that
    crediting the second occurrence would hand a worker the repeated hour as time
    worked. The 29 Mar 03:30 string — a minute that did not exist — is kept verbatim
    and flagged nonexistent, never silently shifted.
    """
    e2e = box("dst_day")
    code, out = e2e.run_events()
    rows = {r["serial_no"]: r for r in e2e.rows(out)}
    assert code == 0
    fold = [r for r in rows.values() if r["event_time_local"] == "2026-10-25T03:30:00"]
    assert len(fold) == 2, "the two same-stamped 03:30 punches"
    assert all(r["tz_ambiguous"] for r in fold)
    assert all(r["tz_offset_min"] == 180 for r in fold)  # FIRST occurrence = +03:00
    assert {r["event_time_utc"] for r in fold} == {"2026-10-25T00:30:00+00:00"}
    gap = rows[9202]
    assert gap["tz_nonexistent"] is True
    assert gap["event_time_local"] == "2026-03-29T03:30:00+02:00"  # verbatim, not shifted
    assert rows[9201]["tz_ambiguous"] is False and rows[9201]["tz_nonexistent"] is False
    # After the transition, wall 04:10 exists once: +02:00, no flags.
    after = rows[9208]
    assert (after["tz_offset_min"], after["tz_ambiguous"], after["tz_nonexistent"]) == (
        120,
        False,
        False,
    )


def test_max10_box_pages_six_times_at_the_advertised_cap(box) -> None:
    """A box whose caps say 10 must be walked at 10 — 60 records, 6 pages, no skips."""
    e2e = box("max10_box")
    code, out = e2e.run_events()
    rows = e2e.rows(out)
    assert code == 0 and len(rows) == 60
    assert e2e.max_results_requested() == [10] * 6
    assert e2e.positions() == [0, 10, 20, 30, 40, 50]
    assert len({c["searchID"] for c in e2e.cond()}) == 1


def test_clamped_maxresults_advances_by_returned_count_not_requested(box) -> None:
    """THE payroll-skip bug: device serves 7 of the 30 asked; the cursor follows the 7.

    Advancing by the requested 30 would have asked for position 30, the stuck page
    would re-serve 9701-9707 with MORE forever, and records 9708-9711 would be lost
    with no error anywhere. This asserts the wire positions AND all 11 serials in order.
    """
    e2e = box("clamped_maxresults")
    code, out = e2e.run_events()
    rows = e2e.rows(out)
    assert code == 0
    assert e2e.max_results_requested() == [30, 30]  # we asked the advertised 30 both times
    assert e2e.positions() == [0, 7]  # advanced by the RETURNED 7, not by the requested 30
    assert [r["serial_no"] for r in rows] == list(range(9701, 9712))


def test_ignored_employee_filter_still_yields_exactly_that_employee(box) -> None:
    """The box serves EVERYONE despite employeeNoString (OBSERVED.md): client-side holds.

    Also pins that we never send the bare silently-ignored `employeeNo` key, and that
    the server-side hint we DO send is the suffix-bearing `employeeNoString`.
    """
    e2e = box("ignored_employee_filter")
    code, out = e2e.run_events("--employee-no", "2")
    rows = e2e.rows(out)
    assert code == 0
    assert [r["serial_no"] for r in rows] == [9802, 9803, 9805]
    assert {r["employee_no"] for r in rows} == {"2"}
    conds = e2e.cond()
    assert all(c.get("employeeNoString") == "2" for c in conds)
    assert all("employeeNo" not in c for c in conds)


def test_attendance_absent_marks_every_punch_unknown(box) -> None:
    """site-a's real mode: no attendanceStatus -> unknown/none, kept not dropped.

    This scenario serves the RECORDED masked capture (30 real punches), so the
    assertion runs against device bytes, not a synthetic page.
    """
    e2e = box("attendance_absent")
    code, out = e2e.run_events()
    rows = e2e.rows(out)
    assert code == 0 and len(rows) == 30
    assert {r["direction"] for r in rows} == {"unknown"}
    assert {r["direction_source"] for r in rows} == {"none"}
    assert {r["attendance_status"] for r in rows} == {None}


def test_encrypted_person_data_is_flagged_and_kept_verbatim(box) -> None:
    """A base64 blob in `name` is flagged and handed back untouched — never decoded."""
    e2e = box("encrypted_person_data")
    code, out = e2e.run_events()
    rows = e2e.rows(out)
    assert code == 0
    blob = [r for r in rows if r["encrypted_person_data"]]
    assert len(blob) == 1
    assert blob[0]["name"] == "VGhpc0lzQ0lwaGVyTm90QVBlcnNvbk5hbWU="
    assert blob[0]["raw"]["name"] == blob[0]["name"]  # raw is the device's record, verbatim


def test_unicode_names_are_normalized_to_nfc_with_raw_bytes_kept(box) -> None:
    """The fixture file is NFD on disk; the MODEL composes to NFC and `raw` keeps NFD.

    Composed vs decomposed are different bytes for the same person — an employer
    matching names byte-for-byte would silently split one human into two.
    """
    e2e = box("unicode_names")
    code, out = e2e.run_events()
    rows = e2e.rows(out)
    assert code == 0 and len(rows) == 4
    for row in rows:
        name = row["name"]
        assert name == unicodedata.normalize("NFC", name)
        raw_name = row["raw"]["name"]
        assert unicodedata.normalize("NFD", raw_name) == raw_name
        assert unicodedata.normalize("NFC", raw_name) == name


def test_digest_stale_nonce_recovers_with_one_rechallenge_and_zero_loss(box) -> None:
    """The box retires the nonce mid-session; the client pays the stale="true" once.

    Zero records lost (identical serials to happy_day) and every request AFTER the
    rotation carries the NEW nonce — the recovery is proven on the wire, not just by
    an exit code.
    """
    happy = box("happy_day")
    _, happy_out = happy.run_events()
    e2e = box("digest_stale_nonce")
    code, out = e2e.run_events()
    assert code == 0
    assert e2e.rows(out) == e2e.rows(happy_out)
    assert e2e.device.challenges >= 2  # initial + at least the stale re-challenge
    rotated = "MASKED-NONCE-ROTATED"
    nonces = e2e.auth_nonces()
    assert rotated in nonces
    first_rotated = nonces.index(rotated)
    assert all(n == rotated for n in nonces[first_rotated:]), "stale nonce replayed after rotation"


def test_busy_then_retry_finishes_byte_identical_to_the_healthy_box(box) -> None:
    """Two deviceBusy answers mid-session: backoff, then the same pages, same bytes.

    The OUTPUT comparison against happy_day is the whole point — a retry that
    re-serves a page, skips one, or corrupts order shows up here as a diff.
    """
    happy = box("happy_day")
    _, happy_out = happy.run_events()
    e2e = box("busy_then_retry")
    code, out = e2e.run_events()
    assert code == 0
    assert out == happy_out
    assert len(e2e.sleeps) >= 2, "the busy backoff must have slept through the retry budget"
    assert all(s > 0 for s in e2e.sleeps)


def test_invalid_content_is_terminal_exit_4_with_the_body_quoted_and_zero_rows(box) -> None:
    """statusCode 6 is the terminal class: surface it, never loop on it.

    Retrying this class is how a poller becomes a door-terminal lockout (gotchas
    §7.4), so the CLI must exit 4 naming the payload — and print NO records. The
    event endpoint must not have been hammered either: at most the transport's
    single documented retry.
    """
    e2e = box("invalid_content")
    code, out = e2e.run_events()
    assert code == 4
    payload = json.loads(out.strip().splitlines()[0])
    assert payload["exit_code"] == 4
    assert "Invalid Content" in payload["error"] and "badParameters" in payload["error"]
    # The error line is the ONLY line: zero record rows (records carry serial_no;
    # the error payload carries "error"/"exit_code" and nothing else).
    rows = e2e.rows(out)
    assert [r for r in rows if "serial_no" in r] == []
    assert len(rows) == 1
    event_posts = [s for s in e2e.device.served if s.path == EVENT_PATH]
    assert len(event_posts) <= 2, f"terminal class looped {len(event_posts)} POSTs"


# --- the corpus itself -------------------------------------------------------------------


def test_corpus_matches_the_readme_table() -> None:
    """Every scenario is documented in tests/fixtures/README.md and vice versa.

    The card's definition of done includes a documented corpus; this test is what
    keeps the README true instead of a snapshot someone forgets to update.
    """
    from e2e_harness import SCENARIOS_DIR

    readme = (SCENARIOS_DIR.parent / "README.md").read_text(encoding="utf-8")
    documented = {name for name in SCENARIOS if f"`{name}`" in readme}
    assert documented == set(SCENARIOS), (
        f"undocumented scenarios: {sorted(set(SCENARIOS) - documented)}; "
        f"README rows with no scenario: {sorted(documented - set(SCENARIOS))}"
    )


def test_every_scenario_fixture_is_valid_json_and_wellformed() -> None:
    """A fixture nobody parses until a golden run is a trap; parse the whole corpus here.

    Each event page: envelope key present, counts self-consistent (numOfMatches ==
    len(InfoList)), status one of the three observed spellings (OBSERVED.md). This is
    the check that would have caught a truncated or hand-edited fixture.
    """
    from e2e_harness import _read_json

    for name, sc in SCENARIOS.items():
        for page in sc.events:
            body = _read_json(page)
            env = body.get("AcsEvent")
            assert env is not None, f"{name}/{page.name}: no AcsEvent envelope"
            items = env.get("InfoList")
            assert env["numOfMatches"] == len(items or []), f"{name}/{page.name}: numOfMatches"
            assert env["responseStatusStrg"] in {"OK", "MORE", "NO MATCH"}, name
        for roster in (sc.users, sc.user_count):
            if roster is not None:
                _read_json(roster)  # parses, or this fails with the file name


def test_scenario_event_window_reaches_the_device_with_the_site_offset(box) -> None:
    """--since/--until land in the POST body as site-tz wall time WITH the site offset.

    p1-05b (live P0, OBSERVED.md "Event-window startTime form: offset REQUIRED",
    proof 2026-10-17): a naive `"startTime":"2026-06-15T00:00:00"` gets HTTP 400
    `badJsonContent`/`errorMsg=startTime` from this firmware, so the wire pair must
    be `+03:00`-stamped (June in Bucharest). FakeDevice enforces this too — a naive
    walk now gets the 400 from the fake exactly as from the device.
    """
    e2e = box("happy_day")
    code, _ = e2e.run_events()
    assert code == 0
    assert e2e.window_strings() == [("2026-06-15T00:00:00+03:00", "2026-06-16T00:00:00+03:00")]
