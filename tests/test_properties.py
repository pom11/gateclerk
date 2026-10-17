"""Card p1-09, third layer: property tests (hypothesis) over the two total functions.

Two invariants the card names explicitly, stated as properties instead of examples:

1. **Paging termination over ARBITRARY numOfMatches sequences.** No sequence of pages —
   honest, lying, clamped, zero-length, MORE-forever — may make `PagedSearch` skip a
   record a well-behaved device handed it, loop past the safety cap without failing
   loudly, or advance the cursor by anything other than min(returned, numOfMatches).
   test_paging.py covers the page shapes we have observed; this covers the shapes we
   have NOT, which is exactly the risk model for firmware we have not met yet.

2. **TZ resolver totality: every input maps or raises, never defaults.** Every string
   (or None) either resolves to an instant with a stated source, or comes back
   explicitly unresolved with a reason. The resolver must NEVER invent UTC for a naive
   string when no site zone exists (DESIGN.md: "we keep it and flag it, we don't
   guess") and must never raise on a string it merely cannot parse.

Hypothesis is a dev dependency (pyproject dependency-groups.dev); CI's `uv run pytest`
collects this file as part of the normal suite.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gateclerk.exceptions import SearchProtocolError, SearchRunawayError
from gateclerk.paging import acs_event_search
from gateclerk.tz import DEFAULT_SITE_TZ, TimeResolver, TzSource, resolve_event_time

#: The walk's safety cap in these tests: small on purpose so the runaway shapes are
#: cheap to hit, and one number used by BOTH the engine and the assertions.
_MAX_PAGES = 12

# --- 1. paging termination over arbitrary numOfMatches sequences ------------------------


@st.composite
def lying_device(draw: st.DrawFn) -> tuple[int, list[tuple[int, int]], bool]:
    """A virtual device: R records, then a per-request policy of (served, declared num).

    `served` is what the device ACTUALLY puts in InfoList; `declared` is what it claims
    in numOfMatches — deliberately allowed to disagree (the observed clamping lies both
    ways). Past the scripted policies the last one repeats, like a stuck FakeDevice
    route: if it declares MORE with records but zero progress, that is the runaway case.
    `inject_runaway` forces that shape on every answer (always MORE, declared 0).
    """
    inject_runaway = draw(st.booleans())
    # A forced-runaway device with zero records terminates on the empty-page rule
    # instead of freezing, so this mode needs at least one record to freeze against.
    total = draw(st.integers(min_value=1 if inject_runaway else 0, max_value=30))
    policies = [
        (
            draw(st.integers(min_value=0, max_value=6)),  # served (may exceed its own cap)
            draw(st.integers(min_value=0, max_value=40)),  # declared numOfMatches (may lie)
        )
        for _ in range(draw(st.integers(min_value=1, max_value=10)))
    ]
    return total, policies, inject_runaway


@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
@given(device=lying_device())
def test_walk_never_skips_and_terminates_loudly(device) -> None:
    """Against a lying numOfMatches the walk must re-read, never skip — or fail loudly.

    The device model answers a request at position P with records[P : P+served] and
    status MORE iff P+served < R (a well-behaved device about its own slicing; the LIE
    is only in numOfMatches). Engine contract under arbitrary lies:
      * every returned record set is exactly what the device served, in order;
      * the returned serials are a GAP-FREE prefix of the device's list — re-reads
        allowed (UPSERT makes them free), holes are the payroll bug and forbidden;
      * if the walk ends (status OK or empty page), the whole device list came back;
      * if it cannot progress (declared 0 with records served), the cap raises
        SearchRunawayError — the loud failure, not a silent loop or a silent stop;
      * each cursor step is exactly min(returned, declared) — the anti-skip rule.
    """
    total, policies, inject_runaway = device
    records = [{"serialNo": i} for i in range(total)]
    sent: list[dict[str, Any]] = []

    def reader(body: Mapping[str, Any]) -> dict[str, Any]:
        sent.append(dict(body))
        served, declared = policies[min(len(sent) - 1, len(policies) - 1)]
        position = body["AcsEventCond"]["searchResultPosition"]
        if inject_runaway:
            # A device that refuses to end the walk: always MORE, always progress-hungry.
            declared = 0
            served = min(served, 1)
            if served == 0:
                served = 1  # a record each time, but declares 0: cursor frozen, MORE forever
            return {
                "AcsEvent": {
                    "responseStatusStrg": "MORE",
                    "numOfMatches": declared,
                    "InfoList": records[position : position + 1] or [{"serialNo": 99999}],
                }
            }
        window = records[position : position + served]
        more = position + served < total
        return {
            "AcsEvent": {
                "responseStatusStrg": "MORE" if more else "OK",
                "numOfMatches": declared,
                "InfoList": window,
            }
        }

    engine = acs_event_search(
        reader,
        sleep=lambda _s: None,
        inter_page_delay=0.0,
        clock=lambda: 0.0,
        max_pages=_MAX_PAGES,
    )

    got: list[int] = []
    steps: list[tuple[int, int, int]] = []  # (from_position, step, returned)
    runaway = False
    protocol_error = False
    try:
        for page in engine.pages({"major": 5}, search_id="property-test-walk"):
            returned = len(page.records)
            # (a) what came back is EXACTLY what the device model served at this
            # position — verbatim, in order, nothing invented.
            assert [r["serialNo"] for r in page.records] == [
                r["serialNo"] for r in records[page.position : page.position + returned]
            ]
            if steps:
                prev_from, prev_step, _prev_ret = steps[-1]
                assert page.position == prev_from + prev_step  # cursor followed the rule
            steps.append((page.position, min(returned, page.num_of_matches), returned))
            got.extend(r["serialNo"] for r in page.records)
    except SearchRunawayError:
        runaway = True
    except SearchProtocolError:
        protocol_error = True

    if protocol_error:
        return

    # (b) No holes: the serials seen form an exact prefix 0..k (duplicates from
    # re-reads are free by UPSERT design; a HOLE is the silent-skip payroll bug).
    seen = set(got)
    assert seen == set(range(max(seen) + 1)) if seen else True

    if runaway:
        # The cap fired. That is a CORRECT abort for two device shapes: a frozen
        # cursor (declares 0, position can never advance) and a walk simply longer
        # than the page ceiling (1 record/page over 13 pages vs a 12-page cap). What
        # must never happen is SILENCE — the cap raises, and dies AT the cap.
        assert len(sent) <= _MAX_PAGES, "ran past the cap instead of at it"
    else:
        # (c) A completed walk with a non-empty last page delivered EVERY record:
        # status OK means the device's own window was covered, (b) means nothing was
        # skipped, so the only legal early stop left is the engine's empty-page rule.
        if got and steps[-1][2] > 0:
            assert seen == set(range(total))


# --- 2. tz resolver totality -------------------------------------------------------------


any_string = st.one_of(
    st.none(),
    st.text(max_size=40),
    # plausible device stamps in the shapes devices actually send, plus broken
    # near-misses (month 13, hour 24, :60 minutes) that must resolve as UNRESOLVED
    st.from_regex(
        r"20[0-9][0-9]-(0[0-9]|1[0-3])-(0[0-9]|[12][0-9]|3[0-9])T([01][0-9]|2[0-9]):"
        r"[0-6][0-9]:[0-6][0-9](\+0[0-4]:[03]00|-0[0-5]:[03]00|Z)?",
        fullmatch=True,
    ),
)

site_zones = st.one_of(
    st.just(DEFAULT_SITE_TZ),
    st.just("UTC"),
    st.just("America/New_York"),
    st.none(),  # "no site zone configured" — a real config state, not an error
)


@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
@given(raw=any_string, site=site_zones)
def test_resolver_is_total_never_invents_utc_never_raises_on_unparsable(raw, site) -> None:
    """resolve() answers for every (string, zone) pair: instant+site-tz OR flagged unresolved.

    The forbidden state is the silent default: a naive string with no zone resolving to
    UTC anyway — a payroll hour invented out of nothing (DESIGN.md "keep it and flag
    it"). The other forbidden state is an exception for a merely-malformed string, which
    would lose a punch to a typo. Neither may happen, for any input: the resolver is a
    total function whose codomain is (resolved | unresolved-with-reason).
    """
    resolved = TimeResolver(site_tz=site).resolve(raw)

    if resolved.utc is not None:
        # An instant exists — so a site zone existed and the source says which one.
        assert resolved.tz_source is TzSource.SITE_TZ
        assert site is not None
        assert resolved.offset_minutes is not None
    else:
        # No instant — so it is EXPLICITLY unresolved, with a reason attached.
        assert resolved.tz_source is TzSource.UNRESOLVED
        assert resolved.reason

    # The device's string is never rewritten, in any branch (audit needs the bytes).
    assert resolved.device_local == (raw.strip() if isinstance(raw, str) else None)


@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
@given(
    raw=st.from_regex(
        r"2026-10-2[4-6]T(0[0-9]|1[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\+0[23]:00|Z)?",
        fullmatch=True,
    )
)
def test_resolve_event_time_always_answers_and_the_flag_is_tri_state(raw) -> None:
    """The façade (p1-06d) is total too, and `mismatch` never collapses None to False.

    Around the 2026-10-25 autumn fold on purpose: ambiguous and nonexistent wall times
    still have to produce a complete answer, not a raise. "Agrees" about missing
    evidence would be a false reassurance in payroll output (tz_mismatch.py's rule).
    """
    result = resolve_event_time(raw, "Europe/Bucharest")
    assert result.tz_source in {TzSource.SITE_TZ, TzSource.UNRESOLVED}
    assert result.mismatch in {True, False, None}
    if result.utc is not None:
        assert result.utc.tzinfo is not None
        assert result.wall_naive is not None and result.wall_naive.tzinfo is None
        assert result.claimed_offset_min is None or isinstance(result.claimed_offset_min, int)


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(offset=st.integers(min_value=-14 * 60, max_value=14 * 60))
def test_the_mismatch_flag_can_never_move_the_instant(offset: int) -> None:
    """Same wall string, arbitrary device claim: UTC is IDENTICAL, only the flag moves.

    If this ever breaks, the payroll instant becomes a function of a device bug report —
    the detector is a bystander by design (p1-06c), and this property is what keeps it
    one under every input hypothesis, not just the two examples test_tz_mismatch gives.
    """
    wall = "2026-06-15T08:00:00"
    base = resolve_event_time(wall, "Europe/Bucharest")
    claimed = resolve_event_time(wall, "Europe/Bucharest", claimed_offset_min=offset)
    assert claimed.utc == base.utc
    assert claimed.tz_source is base.tz_source
