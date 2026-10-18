"""Card p1-06c (run-warning half): ONE stderr summary line per events run.

The per-record `tz_offset_mismatch` column shipped with the p1-06 round (model.py fills
it through `pipeline.event_record_from_device`; `tz_mismatch.py` owns the policy). What
was missing is its visibility: a summer backfill has the flag true on ~100% of records
(OBSERVED.md: site-a stamps +02:00 on a +03:00 Bucharest wall clock) and the operator
sees SILENCE unless they grep the JSONL. This module owns the run-level line only:

* mismatch-true run  -> EXACTLY ONE stderr line, counts exact, stdout bytes identical to
  the same run with the feature off, exit code unchanged (the count-mismatch precedent,
  paging.py: "warn, don't fail");
* zero-mismatch run  -> no line;
* all-None run       -> no line (None is "no device claim": never "wrong", and never a
  mismatch to report — printing one would upgrade absence of evidence to evidence);
* NEVER per-record spam: every mismatched event still produces ONE line, and a
  multi-chunk walk prints one line for the whole run, not one per chunk;
* stdout stays byte-clean: `--format jsonl > out.jsonl` must stay parseable with the
  warning on (the same invariant `--verbose` is pinned on, cli.py). Mutant catcher: move
  the print to stdout and this file goes red three ways — the stderr assertion, the
  stdout byte-identity, and the `from_jsonl` parse.

Every assertion takes stdout AND stderr from the SAME invocation (`run_streams`): the
fake's page queue sticks at its last page, so a second run of a multi-page box can serve
different rows, and a count compared across two runs could pass by accident.

Scenarios are the p1-09 corpus; the exact-count and mixed cases re-serve hand-authored
pages on the same fake (FakeDevice does not filter by window — see e2e_harness.Scenario).
The corpus property at the bottom walks EVERY scenario box and derives the expected
counts from the records the CLI itself printed, so the summary can never drift from what
the run emitted.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest
from typer.testing import CliRunner

import gateclerk.cli as cli_mod
import gateclerk.pipeline as pipeline_mod
from e2e_harness import EVENT_PATH, SCENARIOS, Scenario, conn_args, install
from gateclerk.model import EventRecord, from_jsonl

#: Identifies THE mismatch line. A substring of the payload, not the `warning:` prefix:
#: the naive_time box legitimately prints a *different* warning (p1-05c's window-label
#: fallback), so "exactly one" must mean one of THIS kind, not one warning of any kind.
MISMATCH_MARK = "tz_offset_mismatch=true"

#: Bucharest offsets the authored instants resolve to, spelled out so the arithmetic is
#: visible instead of implied:
#:   +02:00 claim in June     -> site holds +03:00 -> mismatch TRUE   (site-a summer)
#:   +03:00 claim in June     -> site holds +03:00 -> mismatch False  (claim agrees)
#:   +02:00 claim in January  -> site holds +02:00 -> mismatch False  (claim agrees)
#:   +03:00 claim on 26 Oct   -> site holds +02:00 -> mismatch TRUE   (other direction)
#:   naive (no stamp)         -> no claim          -> None            (never False)
JUNE_MISMATCH = "2026-06-15T08:00:00+02:00"
JUNE_AGREES = "2026-06-15T09:00:00+03:00"
JANUARY_AGREES = "2026-01-15T08:00:00+02:00"
OCTOBER_MISMATCH = "2026-10-26T08:00:00+03:00"
NAIVE = "2026-06-15T10:00:00"


@pytest.fixture
def box(monkeypatch: pytest.MonkeyPatch):
    """Install a named scenario as a live E2E (returns the harness object)."""

    def _install(name: str):
        return install(SCENARIOS[name], monkeypatch)

    return _install


# --- one invocation, both streams ---------------------------------------------------------


def invoke_events(e2e, *extra: str) -> tuple[int, str, str]:
    """`gateclerk events --format jsonl` for the box, as (exit, stdout, stderr) — ONE run.

    e2e_harness.E2E.run() keeps only stdout (the goldens compare stdout); this pin needs
    both streams from the same invocation, so it drives CliRunner directly with the same
    argv the harness builds. A non-SystemExit exception is a failure, not a result.
    """
    s: Scenario = e2e.scenario
    result = CliRunner().invoke(
        cli_mod.app,
        [
            "events",
            *conn_args(),
            "--since",
            s.since,
            "--until",
            s.until,
            "--format",
            "jsonl",
            *s.event_args,
            *extra,
        ],
    )
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        raise result.exception
    return result.exit_code, result.stdout or "", result.stderr or ""


def warn_lines(err: str) -> list[str]:
    return [line for line in err.splitlines() if MISMATCH_MARK in line]


# --- fake-page authoring (the window-insensitive box; see module docstring) ---------------


def _page(items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "AcsEvent": {
            "searchID": "p1-06c-warn",
            "totalMatches": len(items),
            "responseStatusStrg": "OK",
            "numOfMatches": len(items),
            "InfoList": items,
        }
    }


def _event(serial: int, wall: str, *, employee: str = "1") -> dict[str, Any]:
    """One major=5 punch stamped `wall` — the offset in the string IS the scenario."""
    return {
        "major": 5,
        "minor": 1,
        "time": wall,
        "cardType": 1,
        "name": f"User {employee}",
        "cardReaderNo": 1,
        "doorNo": 1,
        "employeeNoString": employee,
        "type": 0,
        "serialNo": serial,
        "userType": "normal",
        "currentVerifyMode": "cardOrFaceOrFp",
        "mask": "no",
        "attendanceStatus": "checkIn",
    }


def serve(e2e, *events: dict[str, Any]) -> None:
    """Replace the box's event answer with one OK page of exactly these records."""
    e2e.device.reset_json("POST", EVENT_PATH, _page(list(events)))


# --- (a) mismatch-true run: exactly one line, counts exact, stdout untouched --------------


def test_all_mismatch_run_prints_exactly_one_stderr_line(box) -> None:
    """happy_day is 12 June punches claiming +02:00 in a +03:00 zone: every flag is True.

    The whole line is byte-pinned — it is the sentence an operator reads, and this repo
    pins operator-facing bytes elsewhere (the goldens), so a wording change is a visible
    deliberate diff rather than a silent drift.
    """
    e2e = box("happy_day")
    code, out, err = invoke_events(e2e)
    rows = e2e.rows(out)
    assert code == 0
    assert len(rows) == 12 and all(r["tz_offset_mismatch"] is True for r in rows)
    lines = warn_lines(err)
    assert len(lines) == 1, f"expected exactly one mismatch line, got {len(lines)}: {lines}"
    assert lines[0] == (
        "warning: 12 of 12 events have tz_offset_mismatch=true "
        "(device claims +02:00; site Europe/Bucharest resolves +03:00 at these instants) "
        "— records are correct, site-tz resolution is authoritative"
    )


def test_stdout_bytes_identical_to_the_same_run_with_the_feature_off(box, monkeypatch) -> None:
    """`--format jsonl > out.jsonl` must be byte-identical with the warning on or off.

    The feature is switched off by neutering the emitter on the CLI module — the seam the
    warning hangs on, and the only thing the two runs may differ by. A print that leaked
    even one byte onto stdout breaks the equality; a warning that also stopped printing
    records would break `len(rows)`.
    """
    code_on, out_on, err_on = invoke_events(box("happy_day"))
    assert code_on == 0 and len(warn_lines(err_on)) == 1

    monkeypatch.setattr(cli_mod, "_warn_tz_mismatch", lambda records, **kw: None)
    off_box = box("happy_day")
    code_off, out_off, err_off = invoke_events(off_box)
    assert code_off == 0
    assert warn_lines(err_off) == [], "the disabled seam must print nothing"
    assert out_on == out_off, "stdout bytes moved when only a stderr warning was added"
    assert len(off_box.rows(out_off)) == 12, "the disabled run still printed its records"


def test_a_warning_on_stdout_would_break_the_jsonl_contract(box) -> None:
    """Mutant catcher, second angle: stdout parses as JSONL WITH the warning enabled.

    A print moved to stdout drops a `warning: ...` line inside the stream and `from_jsonl`
    raises — the exact breakage the card names ("stdout stays byte-clean").
    """
    e2e = box("happy_day")
    code, out, err = invoke_events(e2e)
    assert code == 0 and len(warn_lines(err)) == 1
    records = from_jsonl(out)  # raises if any stdout line is not a record
    assert len(records) == 12


def test_table_format_still_warns_once_and_exits_zero(box) -> None:
    """The line is per RUN, not per format: the human table gets it too, stdout intact."""
    e2e = box("happy_day")
    s = e2e.scenario
    result = CliRunner().invoke(
        cli_mod.app,
        [
            "events",
            *conn_args(),
            "--since",
            s.since,
            "--until",
            s.until,
            "--format",
            "table",
        ],
    )
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        raise result.exception
    assert result.exit_code == 0
    assert "serial_no" in (result.stdout or ""), "the table itself still renders on stdout"
    assert len(warn_lines(result.stderr or "")) == 1


def test_multi_chunk_walk_prints_one_line_for_the_whole_run(box) -> None:
    """14 rows across 2 chunks -> ONE line (never per-chunk spam) counting all 14."""
    e2e = box("happy_day_chunked")
    code, out, err = invoke_events(e2e)
    rows = e2e.rows(out)
    assert code == 0
    assert len(rows) == 14, "two chunks incl. the overlapping edge event"
    assert len({r["tz_offset_mismatch"] for r in rows}) == 1 and rows[0]["tz_offset_mismatch"]
    lines = warn_lines(err)
    assert len(lines) == 1, f"one line per RUN, got {len(lines)}: {lines}"
    assert lines[0].startswith("warning: 14 of 14 events have tz_offset_mismatch=true")


# --- exact counts on hand-served pages ----------------------------------------------------


def test_counts_are_exact_and_partial_when_only_some_records_mismatch(box) -> None:
    """2 June +02:00 punches (true) + 1 June +03:00 punch (false) -> '2 of 3', one line."""
    e2e = box("happy_day")
    serve(
        e2e,
        _event(1, JUNE_MISMATCH),
        _event(2, JUNE_MISMATCH, employee="2"),
        _event(3, JUNE_AGREES, employee="3"),
    )
    code, out, err = invoke_events(e2e)
    assert code == 0
    assert [r["tz_offset_mismatch"] for r in e2e.rows(out)] == [True, True, False]
    lines = warn_lines(err)
    assert len(lines) == 1, f"partial mismatch is still ONE line: {lines}"
    assert lines[0].startswith("warning: 2 of 3 events have tz_offset_mismatch=true ")


def test_none_records_count_in_the_total_but_never_as_mismatches(box) -> None:
    """1 true + 1 false + 1 naive(None): the line reads '1 of 3' — None is not a mismatch.

    None rows ride in the TOTAL (they were printed; the denominator is what the run
    emitted) but never raise the mismatch count.
    """
    e2e = box("happy_day")
    serve(
        e2e,
        _event(1, JUNE_MISMATCH),
        _event(2, JUNE_AGREES, employee="2"),
        _event(3, NAIVE, employee="3"),
    )
    code, out, err = invoke_events(e2e)
    rows = e2e.rows(out)
    assert code == 0
    assert [r["tz_offset_mismatch"] for r in rows] == [True, False, None]
    lines = warn_lines(err)
    assert len(lines) == 1
    assert lines[0].startswith("warning: 1 of 3 events have tz_offset_mismatch=true ")


def test_two_claim_pairs_in_one_run_stay_one_line_naming_both(box) -> None:
    """A run whose mismatches go BOTH ways: still ONE line, both pairs named.

    June +02:00-claim resolving +03:00 AND late-October +03:00-claim resolving +02:00 —
    the line must not pick one pair and quietly mislabel the other half.
    """
    e2e = box("happy_day")
    serve(e2e, _event(1, JUNE_MISMATCH), _event(2, OCTOBER_MISMATCH, employee="2"))
    code, out, err = invoke_events(e2e)
    assert code == 0 and len(e2e.rows(out)) == 2
    lines = warn_lines(err)
    assert len(lines) == 1, f"one line for both pairs, got {len(lines)}: {lines}"
    assert lines[0].startswith("warning: 2 of 2 events have tz_offset_mismatch=true ")
    assert "+02:00" in lines[0] and "+03:00" in lines[0]
    assert "Europe/Bucharest" in lines[0]


# --- (b) zero-mismatch run: no line ---------------------------------------------------------


def test_zero_mismatch_run_prints_nothing_about_mismatch(box) -> None:
    """Claims that agree with the site zone (+02:00 in January, +03:00 in June): silence."""
    e2e = box("happy_day")
    serve(e2e, _event(1, JANUARY_AGREES), _event(2, JUNE_AGREES, employee="2"))
    code, out, err = invoke_events(e2e)
    rows = e2e.rows(out)
    assert code == 0 and len(rows) == 2
    assert all(r["tz_offset_mismatch"] is False for r in rows), "the box really agrees"
    assert warn_lines(err) == []


def test_empty_window_prints_no_line(box) -> None:
    """NO MATCH -> zero records -> no line. 'Nobody clocked in' stays a clean zero."""
    e2e = box("happy_day")
    serve(e2e)
    code, out, err = invoke_events(e2e)
    assert code == 0 and out.strip() == ""
    assert warn_lines(err) == []


# --- (c) all-None run: no line --------------------------------------------------------------


def test_all_none_run_prints_nothing(box) -> None:
    """naive_time: every flag is None ("no device claim"), so NOTHING may be claimed.

    'We don't know' rendered as 'something is wrong' is the false alarm this pin keeps
    impossible (tz_mismatch.py's three-valued rule, applied at the run level).
    """
    e2e = box("naive_time")
    code, out, err = invoke_events(e2e)
    rows = e2e.rows(out)
    assert code == 0 and len(rows) == 4
    assert all(r["tz_offset_mismatch"] is None for r in rows)
    assert warn_lines(err) == [], (
        "a None-only run may print the p1-05c label warning, never a mismatch line"
    )


# --- invariants -----------------------------------------------------------------------------


def test_verbose_does_not_duplicate_or_prefix_the_line(box) -> None:
    """With --verbose the request log shares stderr; the mismatch line stays ONE and raw.

    If someone later re-routes the warning through the verbose logger, the `# ` note
    prefix would silently break the `warning:` contract pinned here.
    """
    e2e = box("happy_day")
    code, out, err = invoke_events(e2e, "--verbose")
    assert code == 0
    assert len(e2e.rows(out)) == 12, "verbose must not cost the run a single record"
    assert "AcsEventCond" in err, "the verbose request log itself is still on stderr"
    lines = warn_lines(err)
    assert len(lines) == 1, "verbose must not duplicate the summary"
    assert lines[0].startswith("warning:"), "no logger note prefix may ride in front"


def test_error_run_that_prints_no_records_prints_no_line(box) -> None:
    """invalid_content: exit 4 with zero records — the warning summarizes RECORDS."""
    e2e = box("invalid_content")
    code, out, err = invoke_events(e2e)
    assert code == 4
    assert [r for r in e2e.rows(out) if "serial_no" in r] == []
    assert warn_lines(err) == []


# --- the emitter never crashes the run it reports on (review round 1, required change) -----

#: A claim outside the ±HH:MM ISO form. `EventRecord.from_dict` keeps such a number
#: verbatim (it validates the type, not the range) and `offset_hhmm` refuses it — so the
#: warning is the one place a wild value can turn a report into a crash. Reachable today
#: only through a record that did not come from `TimeResolver` (a rehydrated or
#: hand-assembled record; the resolver itself cannot produce it — a `+99:30` stamp fails
#: `fromisoformat` and lands `unresolved` with no claim at all), which is exactly why the
#: guard must be behaviour and not an assumption about the input.
WILD_CLAIM = 5970  # +99:30 — the widest two-digit hour claim `_TIME_RE`'s shape admits
WILD_USED = -1500  # -25:00 — out of range on the negative side too (both directions)


def _flagged(**over: Any) -> EventRecord:
    """One mismatch-flagged Bucharest record, with `over` on the p1-06 time block.

    Built through `EventRecord.from_dict` — the same door `pipeline` uses — so these pins
    talk to the emitter with a real record, not a stand-in object.
    """
    payload: dict[str, Any] = {
        "site": "site-a",
        "device_serial": "SN-1",
        "serial_no": 1,
        "event_time_utc": "2026-06-15T05:00:00+00:00",
        "event_time_local": "2026-06-15T08:00:00+02:00",
        "tz_offset_min": 180,
        "tz_offset_min_device": 120,
        "tz_source": "site-tz",
        "iana_tz": "Europe/Bucharest",
        "tz_offset_mismatch": True,
    }
    payload.update(over)
    return EventRecord.from_dict(payload)


def test_a_wild_claim_is_labeled_as_raw_minutes_not_raised(capsys) -> None:
    """The single-pair arm interpolates BOTH offsets through the guard.

    Byte-pinned, including the raw-minutes fallback: a "fix" that clamped the value into
    range would print a plausible `+23:59` and hide the fact that the record claims +99:30
    — a cleaner-looking line about a number we never saw.
    """
    cli_mod._warn_tz_mismatch([_flagged(tz_offset_min_device=WILD_CLAIM)])
    assert warn_lines(capsys.readouterr().err) == [
        "warning: 1 of 1 events have tz_offset_mismatch=true "
        f"(device claims {WILD_CLAIM:+d} min; site Europe/Bucharest resolves +03:00 at these "
        "instants) — records are correct, site-tz resolution is authoritative"
    ]


def test_a_wild_site_offset_is_labeled_as_raw_minutes_not_raised(capsys) -> None:
    """Same guard on the OTHER interpolation — the site offset we used."""
    cli_mod._warn_tz_mismatch([_flagged(tz_offset_min=WILD_USED)])
    assert warn_lines(capsys.readouterr().err) == [
        "warning: 1 of 1 events have tz_offset_mismatch=true "
        f"(device claims +02:00; site Europe/Bucharest resolves {WILD_USED:+d} min at these "
        "instants) — records are correct, site-tz resolution is authoritative"
    ]


def test_the_joined_arm_guards_both_offsets_of_every_pair(capsys) -> None:
    """The multi-pair arm has two more interpolations per pair; both are guarded.

    Pair 1 wild on the claim, pair 2 wild on the site offset, so a partial fix that only
    guarded one of the two tokens in the joined f-string is caught here as well.
    """
    cli_mod._warn_tz_mismatch(
        [
            _flagged(tz_offset_min_device=WILD_CLAIM),
            _flagged(serial_no=2, tz_offset_min_device=120, tz_offset_min=WILD_USED),
        ]
    )
    assert warn_lines(capsys.readouterr().err) == [
        "warning: 2 of 2 events have tz_offset_mismatch=true "
        f"(device claims {WILD_CLAIM:+d} min vs site-resolved +03:00; "
        f"device claims +02:00 vs site-resolved {WILD_USED:+d} min; "
        "site Europe/Bucharest at these instants) "
        "— records are correct, site-tz resolution is authoritative"
    ]


def test_a_wild_claim_through_the_cli_still_exits_zero(box, monkeypatch, capsys) -> None:
    """The card's exit-code rule, applied to the warning itself: rc 0, ONE line.

    Injected by wrapping the assembler `pipeline` looks up as a module global, so the
    whole real path runs (walk, render, emitter) and only the record's claimed offset is
    widened to something `offset_hhmm` refuses. Without the guard this run exits 1 — the
    `_Guard` re-raises anything that is not a `GateclerkError`, so a dead guard costs the
    operator a crashed backfill instead of a warning.
    """
    real = pipeline_mod.event_record_from_device

    def widen_claim(*args: Any, **kwargs: Any) -> EventRecord:
        return dataclasses.replace(
            real(*args, **kwargs), tz_offset_min_device=WILD_CLAIM
        )

    monkeypatch.setattr(pipeline_mod, "event_record_from_device", widen_claim)
    e2e = box("happy_day")
    code, out, err = invoke_events(e2e)
    rows = e2e.rows(out)
    assert code == 0, "a warning must never change the exit code — warn, don't fail"
    assert len(rows) == 12 and all(r["tz_offset_mismatch"] is True for r in rows)
    assert all(r["tz_offset_min_device"] == WILD_CLAIM for r in rows), "the injection landed"
    lines = warn_lines(err)
    assert len(lines) == 1, f"12 wild claims are still ONE line, got {len(lines)}: {lines}"
    assert f"{WILD_CLAIM:+d} min" in lines[0]
    assert len(from_jsonl(out)) == 12, "stdout stays parseable with the wild claim on"


# --- the two arms the first round left unpinned (review round 1, non-blocking) --------------


def test_two_site_zones_are_both_named_in_the_one_line(capsys) -> None:
    """The zone list is joined, not silently reduced to the first record's zone.

    Synthetic on purpose: `events` resolves ONE site zone per run, so two names appear
    only when records come from two configs. Either way the line must name every zone it
    saw — asserting one zone and one offset would be wrong about half the records.
    Records share one (claim, site) pair here, which is what keeps the single-pair arm
    (the sentence the card pins) in play while the zone list still has two entries.
    """
    cli_mod._warn_tz_mismatch(
        [
            _flagged(),
            _flagged(serial_no=2, iana_tz="Europe/London"),
        ]
    )
    assert warn_lines(capsys.readouterr().err) == [
        "warning: 2 of 2 events have tz_offset_mismatch=true "
        "(device claims +02:00; site Europe/Bucharest, Europe/London resolves +03:00 at "
        "these instants) — records are correct, site-tz resolution is authoritative"
    ]


def test_the_joined_arm_names_every_pair_and_every_zone(capsys) -> None:
    """Two pairs AND two zones: every one of them named, still ONE line.

    The widest shape of the sentence, pinned byte-for-byte so a future "simplification"
    that drops either list has to be a deliberate diff.
    """
    cli_mod._warn_tz_mismatch(
        [
            _flagged(),
            _flagged(serial_no=2, tz_offset_min=60, iana_tz="Europe/London"),
        ]
    )
    assert warn_lines(capsys.readouterr().err) == [
        "warning: 2 of 2 events have tz_offset_mismatch=true "
        "(device claims +02:00 vs site-resolved +03:00; device claims +02:00 vs "
        "site-resolved +01:00; site Europe/Bucharest, Europe/London at these instants) "
        "— records are correct, site-tz resolution is authoritative"
    ]


def test_a_run_with_no_zone_name_falls_back_to_a_honest_phrase(capsys) -> None:
    """`iana_tz` None (no site zone configured) must not print `site None resolves`."""
    cli_mod._warn_tz_mismatch([_flagged(iana_tz=None)])
    assert warn_lines(capsys.readouterr().err) == [
        "warning: 1 of 1 events have tz_offset_mismatch=true "
        "(device claims +02:00; site the configured site zone resolves +03:00 at these "
        "instants) — records are correct, site-tz resolution is authoritative"
    ]


def test_flag_true_without_offsets_says_so_once_instead_of_printing_blanks(capsys) -> None:
    """A flag whose own columns are missing is an upstream policy bug — named, not blanked.

    Three flagged records still produce ONE line (the early return), and the sentence
    points at the columns instead of inventing offsets for them.
    """
    cli_mod._warn_tz_mismatch(
        [
            _flagged(tz_offset_min_device=None),
            _flagged(serial_no=2, tz_offset_min_device=None),
            _flagged(serial_no=3, tz_offset_min=None),
        ]
    )
    assert warn_lines(capsys.readouterr().err) == [
        "warning: some events have tz_offset_mismatch=true but no offsets to explain it "
        "— see tz_offset_min_device / tz_offset_min in the records"
    ]


# --- corpus property: the line always agrees with the records it summarizes -----------------


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_line_agrees_with_printed_records_on_every_scenario(box, name: str) -> None:
    """For every box: exactly one line iff any printed record is true, counts match stdout.

    The expected counts come from the CLI's own jsonl, not a hand-listed number, so the
    summary cannot drift from what the run emitted — box by box, including the 60-record
    max10 walk (one line for sixty mismatches is the 'no per-record spam' rule).
    """
    if SCENARIOS[name].expect_exit != 0:
        pytest.skip("error box: covered by test_error_run_that_prints_no_records_prints_no_line")
    e2e = box(name)
    code, out, err = invoke_events(e2e)
    rows = e2e.rows(out)
    assert code == 0
    true_n = sum(r["tz_offset_mismatch"] is True for r in rows)
    lines = warn_lines(err)
    if true_n == 0:
        assert lines == [], f"{name}: nothing mismatched, yet a line printed: {lines}"
    else:
        assert len(lines) == 1, f"{name}: expected exactly one line, got {len(lines)}"
        head = f"warning: {true_n} of {len(rows)} events have {MISMATCH_MARK}"
        assert lines[0].startswith(head), f"{name}: {lines[0]!r} does not start {head!r}"
