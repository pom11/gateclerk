"""Card GC-P15: a serial reset is still detected when the poll window comes back empty.

BINDING SPEC: docs/P2-SITE-AGENT.md §2a request math + the R1 rule ("no punch may be
lost silently"). A terminal that is factory-reset or replaced restarts `serialNo` near
1. Until now the ONLY place that decision lived was inside the per-chunk loop of
`tick()`: with no chunk, no decision — so a replacement unit that had produced nothing
the narrow poll asks for was never even asked, its events stayed unreachable, and the
checkpoint sat at the dead generation's serial forever.

The pins below are the card's four DoD cases plus the ACCEPT clauses and MUST-NOT-CHANGE
clauses those four do not reach on their own:

(1) a quiet tick + a replacement generation below the checkpoint opens epoch 1 and the
    first punch of the new generation is stored under it, not skipped;
(2) a quiet tick whose newest serial is at or above the checkpoint rewinds nothing and
    pays no `deviceInfo` read (suspicion is what earns that request, not the probe);
(3) the wider read costs at most one page per hour, only after a quiet tick, and never
    on a tick that stored records;
(4) a probe that raises leaves the tick `ok` and the checkpoint untouched;
(5) a below-checkpoint drop with no evidence (same firmware, small drop) is a glitch:
    no rewind, and the warning is said ONCE rather than every hour;
(6) a `deviceInfo` serial that moved is still refused — the identity guard was NOT
    softened into a warn just because the quiet arm is new;
(7) a lower serial stamped AT the checkpoint instant is not a new generation (the
    strict-later guard is the only thing holding that epoch shut);
(8) the probe's own window bounds are asserted on the wire — it never reads back below
    the checkpoint, and a floor it cannot place costs no request at all (fail closed).

WHY A TRANSPORT SHIM (`_MajorFilteringTransport`) — read this before "fixing" it.
The shared `FakeDevice` answers the event store with WINDOW arithmetic only and
deliberately does NOT simulate the server-side `major`/`minor` filters
(fakedevice.py, `_event_store_response`: "major/minor are NOT simulated server-side ...
we never trust a server filter we have not probed"). That is the right default for a
box whose filter behaviour is unknown, but it makes the card's own scenario
unreachable: the narrow poll asks `major=5` (punches) and the probe asks `major=0`
(everything), so on a filter-blind fake both reads see the same rows and a quiet tick
can never hide the evidence the probe finds. The card's premise is precisely a device
that DOES honour the filter it advertised — the arm OBSERVED.md's "Server-side filter
truth" section contrasts with the silently-ignored one. So the shim re-filters the
store's answer by the `major` the request asked for, which is what a honouring box
returns, and leaves every other request byte-identical. Everything above it —
`IsapiClient`, digest auth, the paging engine, `store_events`, the checkpoint CAS — is
production code under test, unchanged. The probe request is additionally identifiable
by `timeReverseOrder: true` + `maxResults: 1`, which is what cases (3) and (4) count.

Offline by construction: FakeDevice behind the real IsapiClient, tmp sqlite, injected
wall + monotonic clocks, no socket. The harness and the device seeds are P2-03's own,
imported rather than re-derived, so the scenario cannot drift from the scheduler's
truth. No real host or serial appears (fixtures carry MASKED-SER-1).
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from fakedevice import FakeDevice
from gateclerk import agent_loop
from gateclerk.agent_loop import RESET_PROBE_INTERVAL_S, RESET_PROBE_WINDOW_S
from gateclerk.agent_store import read_checkpoint
from gateclerk.exceptions import IsapiError
from test_p2_03_scheduler import (
    CADENCE_S,
    DEVICE_FW,
    DEVICE_FW_UPGRADED,
    DEVICE_INFO_PATH,
    EVENT_PATH,
    RECORDED,
    LoopHarness,
    _set_firmware,
    device_event,
    seed_events,
    seeded_device,
)

#: The gap that makes the tick quiet: longer than `RESET_PROBE_INTERVAL_S`, so the
#: hourly budget has expired and the wider read is due.
QUIET_S = RESET_PROBE_INTERVAL_S + 120

#: The event POST as httpx routes it: `url.path` never carries the query string.
_EVENT_ROUTE = EVENT_PATH.split("?")[0]

SERIAL = "MASKED-SER-1"


# --- the filter-honest device arm (see the module docstring) -----------------------------


class _MajorFilteringTransport(httpx.BaseTransport):
    """Wrap a FakeDevice transport so the event store honours the requested `major`.

    `major: 0` is the ISAPI "every major" ask (the loop's own `include_noise` walk uses
    it), so only a non-zero `major` narrows the answer. `fail_reverse_reads` models the
    probe request itself failing — the one arm of the card that must bend, never break.
    """

    def __init__(self, inner: httpx.BaseTransport, *, fail_reverse_reads: bool = False) -> None:
        self._inner = inner
        self._fail_reverse = fail_reverse_reads
        #: Rows the `major` filter swallowed on a narrow read. Test 1 asserts this is
        #: non-zero: a shim that silently stopped filtering would leave the probe with
        #: nothing to find and the tick would still pass, answered by the IN-WINDOW
        #: branch instead — the exact false green this file's premise has to defend.
        self.hidden_rows = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        response = self._inner.handle_request(request)
        # `url.path` carries NO query string on httpx, so the route is compared bare
        # (and `AcsEventTotalNum` is not this route — endswith would catch it too).
        if request.url.path != _EVENT_ROUTE:
            return response
        try:
            payload = json.loads(request.content)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return response
        cond = payload.get("AcsEventCond") if isinstance(payload, dict) else None
        if not isinstance(cond, dict):
            return response
        if self._fail_reverse and cond.get("timeReverseOrder") is True:
            # A dead probe read: the same shape `add_raw` raises for a transport error.
            raise httpx.ConnectError("probe read refused (test-injected transport failure)")
        major = cond.get("major") or 0
        if not major:
            return response
        body = json.loads(response.content)
        envelope = body.get("AcsEvent")
        if not isinstance(envelope, dict) or "InfoList" not in envelope:
            return response
        rows = [r for r in envelope["InfoList"] if r.get("major") == major]
        self.hidden_rows += len(envelope["InfoList"]) - len(rows)
        if not rows:
            # The recorded empty-window shape: "NO MATCH" with the space, no InfoList.
            envelope = {
                "searchID": envelope.get("searchID", ""),
                "responseStatusStrg": "NO MATCH",
                "numOfMatches": 0,
                "totalMatches": 0,
            }
        else:
            envelope.update(
                {"numOfMatches": len(rows), "totalMatches": len(rows), "InfoList": rows}
            )
        return httpx.Response(200, json={"AcsEvent": envelope})


def filter_honest(device: FakeDevice, *, fail_reverse_reads: bool = False) -> FakeDevice:
    """Install the honour-the-filter arm on `device` (module docstring: why)."""
    # The client takes any httpx transport; FakeDevice's attribute is typed to the
    # MockTransport it builds itself, so the seam needs the ignore, not a cast.
    device.transport = _MajorFilteringTransport(  # type: ignore[assignment]
        device.transport, fail_reverse_reads=fail_reverse_reads
    )
    return device


def wipe_log(device: FakeDevice) -> None:
    """The device's event ring is EMPTY — what a factory reset / swap actually does.

    Same store seam `test_p2_03_scheduler.py:869` uses for the "the device lost the
    high serial" glitch. Without the wipe the old generation's own punches still sit
    inside the overlap window, so the tick is not quiet and the probe is never asked.
    """
    device._event_store = []


def noise_event(serial: int, wall: str) -> dict[str, Any]:
    """One `major=3` heartbeat: a real serialNo and a real device stamp, NOT a punch.

    This is what a replacement terminal keeps producing while nobody badged in yet: the
    narrow poll (major=5) sees nothing, so the tick is quiet, and only a `major=0` read
    can show that the device's counter restarted.
    """
    return {**device_event(serial, wall), "major": 3}


def quiet_replacement(
    tmp_path: Path,
    *,
    new_serials: list[tuple[int, str]],
    upgraded: bool = True,
    fail_reverse_reads: bool = False,
) -> LoopHarness:
    """Run to the state the card is about: epoch 0 at serial 100, then a swap.

    Tick 1 reads the old generation (serials 1..3 and 100) and stores it; the log is
    then wiped and refilled with the replacement generation's heartbeats, and the clock
    moves past the probe interval. The harness is returned JUST before the quiet tick,
    which the caller takes and asserts on.
    """
    device = filter_honest(
        seeded_device(), fail_reverse_reads=fail_reverse_reads
    )  # the honest-filter arm, module docstring
    seed_events(
        device,
        [
            device_event(1, "2026-10-19T09:51:00"),
            device_event(2, "2026-10-19T09:52:00"),
            device_event(3, "2026-10-19T09:53:00"),
            device_event(100, "2026-10-19T09:55:00"),
        ],
    )
    h = LoopHarness(tmp_path, device)
    first = h.tick()
    assert first.ok and first.serial_reset is None
    cp = read_checkpoint(h.conn, SERIAL)
    assert cp is not None and (cp.checkpoint_serial, cp.serial_epoch) == (100, 0)

    if upgraded:
        _set_firmware(device, DEVICE_FW_UPGRADED)
    wipe_log(device)
    seed_events(device, [noise_event(serial, wall) for serial, wall in new_serials])
    h.clock.advance(QUIET_S)
    h.monotonic.advance(QUIET_S)
    return h


def _shim(device: FakeDevice) -> _MajorFilteringTransport:
    """The installed arm, or a loud failure: a quietly-missing shim is a false green."""
    transport = device.transport
    assert isinstance(transport, _MajorFilteringTransport), (
        "the honour-the-filter arm is not installed, so the narrow poll sees what the "
        "probe sees and the quiet-tick assertions would pass off the in-window branch"
    )
    return transport


def probe_reads(device: FakeDevice) -> list[dict[str, Any]]:
    """The event POSTs that are probe reads: newest-first, one row asked for."""
    out = []
    for served in device.served:
        if served.method != "POST" or not served.body or b"timeReverseOrder" not in served.body:
            continue
        cond = json.loads(served.body).get("AcsEventCond", {})
        if isinstance(cond, dict) and cond.get("timeReverseOrder") is True:
            out.append(cond)
    return out


def narrow_reads(device: FakeDevice) -> list[dict[str, Any]]:
    """The event POSTs that are the narrow poll: the oldest-first window walk."""
    out = []
    for served in device.served:
        if served.method != "POST" or not served.body or b"timeReverseOrder" in served.body:
            continue
        cond = json.loads(served.body).get("AcsEventCond", {})
        if isinstance(cond, dict) and "startTime" in cond:
            out.append(cond)
    return out


def device_info_reads(device: FakeDevice) -> int:
    """Authenticated `deviceInfo` GETs — the request `_reset_evidence` pays on suspicion."""
    return sum(1 for s in device.served if s.path == DEVICE_INFO_PATH and s.had_auth)


# --- DoD (1): the quiet replacement opens epoch 1 and its punches get stored -------------


def test_quiet_replacement_is_detected_one_hour_after_the_last_tick(tmp_path: Path) -> None:
    """The card's R1 case: silence must not be read as "nothing happened".

    The narrow poll comes back empty (the ring was wiped; the new generation has only
    heartbeats so far), so the per-chunk reset branch never runs. The wider read is
    what notices that serialNo restarted, and the rewind it opens is what lets the
    next tick store the replacement's first punch instead of skipping it.
    """
    h = quiet_replacement(
        tmp_path, new_serials=[(1, "2026-10-19T09:57:00"), (3, "2026-10-19T10:08:00")]
    )
    assert narrow_reads(h.device)  # the poll ran and came back empty
    quiet = h.tick()

    assert quiet.ok, quiet.error
    assert quiet.records == 0 and quiet.inserted == 0  # the tick really was quiet
    # The evidence lived ONLY behind the narrow poll's filter: the poll was blind to it
    # (rows hidden) and the newest-first read is what found it. Without this pin the
    # test could be answered by the pre-existing in-window branch and prove nothing here.
    assert _shim(h.device).hidden_rows > 0
    assert len(probe_reads(h.device)) == 1
    assert quiet.serial_reset is not None
    assert (quiet.serial_reset.old_serial, quiet.serial_reset.new_serial) == (100, 3)
    assert quiet.serial_reset.old_firmware == DEVICE_FW
    assert quiet.serial_reset.new_firmware == DEVICE_FW_UPGRADED
    assert quiet.advanced is True
    cp = read_checkpoint(h.conn, SERIAL)
    assert cp is not None and (cp.checkpoint_serial, cp.serial_epoch) == (3, 1)
    assert cp.firmware == DEVICE_FW_UPGRADED

    # The replacement's first punch: stored under the NEW epoch, not skipped.
    seed_events(h.device, [device_event(4, "2026-10-19T10:12:00")])
    h.clock.advance(CADENCE_S)
    h.monotonic.advance(CADENCE_S)
    after = h.tick()

    assert after.ok and after.inserted == 1 and after.serial_reset is None
    rows = h.conn.execute(
        "SELECT serial_epoch, serial_no FROM events ORDER BY serial_epoch, serial_no"
    ).fetchall()
    assert [(r["serial_epoch"], r["serial_no"]) for r in rows] == [
        (0, 1),
        (0, 2),
        (0, 3),
        (0, 100),
        (1, 4),
    ]
    stored = json.loads(
        h.conn.execute(
            "SELECT jsonl FROM events WHERE serial_epoch = 1 AND serial_no = 4"
        ).fetchone()["jsonl"]
    )
    assert stored["event_time_local"].startswith("2026-10-19T10:12")


# --- DoD (2): a quiet tick with nothing below the checkpoint rewinds nothing -------------


def test_quiet_tick_without_a_reset_does_not_rewind(tmp_path: Path) -> None:
    """Silence + a healthy counter must be a no-op — no epoch, no firmware read.

    The replacement-generation serials here are ABOVE the checkpoint (a device that
    kept counting, it just had no punches to report), which is not evidence of
    anything. The probe's cost is the one page; `deviceInfo` stays un-read because
    suspicion, not curiosity, is what pays for it.
    """
    h = quiet_replacement(
        tmp_path,
        new_serials=[
            (101, "2026-10-19T09:57:00"),
            (102, "2026-10-19T10:00:00"),
            (103, "2026-10-19T10:08:00"),
        ],
        upgraded=False,
    )
    quiet = h.tick()

    assert quiet.ok and quiet.records == 0
    assert quiet.serial_reset is None and quiet.advanced is False
    cp = read_checkpoint(h.conn, SERIAL)
    assert cp is not None and (cp.checkpoint_serial, cp.serial_epoch) == (100, 0)
    assert cp.firmware == DEVICE_FW
    assert device_info_reads(h.device) == 1  # only the bootstrap identity read
    assert h.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 4


# --- DoD (3): the wider read costs at most one page per hour -----------------------------


def test_quiet_probe_runs_at_most_once_per_hour(tmp_path: Path) -> None:
    """Quiet ticks at 5 min, 5 min and an hour later: two probes, never three.

    The narrow poll still runs every tick (that is how punches arrive); only the extra
    newest-first page is rate-limited, and it must be ONE request — a page of one row,
    not a cursor walk over the retained week. The tick at the end found a punch, so it
    owes no probe even though the hour had expired.
    """
    h = quiet_replacement(tmp_path, new_serials=[(101, "2026-10-19T10:08:00")], upgraded=False)
    base = len(h.device.served)

    first = h.tick()  # probe due: the interval has never been paid for
    h.clock.advance(CADENCE_S)
    h.monotonic.advance(CADENCE_S)
    second = h.tick()  # minutes later: NO second probe
    h.clock.advance(QUIET_S)
    h.monotonic.advance(QUIET_S)
    third = h.tick()  # the hour expired: probe again

    assert [r.ok for r in (first, second, third)] == [True, True, True]
    assert [r.records for r in (first, second, third)] == [0, 0, 0]
    probes = probe_reads(h.device)
    assert len(probes) == 2, probes
    # Each probe is exactly one page of one row, newest-first, over the retained window.
    for cond in probes:
        assert cond["maxResults"] == 1
        assert cond["major"] == 0
    # The narrow poll still runs every tick — one window POST each (the setup tick plus
    # these three = four), and the ONLY requests on top of the polls are the two probes:
    # five event POSTs after the setup tick, of which exactly two are probe-shaped.
    assert len(narrow_reads(h.device)) == 4
    assert len(h.event_conditions(base)) == 5
    assert len(h.event_conditions(base)) - len(probes) == 3
    cp = read_checkpoint(h.conn, SERIAL)
    assert cp is not None and (cp.checkpoint_serial, cp.serial_epoch) == (100, 0)

    # And a tick that FOUND records owes no probe at all — the reset question was
    # already answered in-window. The budget has expired again here, so the only thing
    # holding the count is `counts.records == 0`.
    seed_events(h.device, [device_event(104, "2026-10-19T12:30:00")])
    h.clock.advance(QUIET_S)
    h.monotonic.advance(QUIET_S)
    busy = h.tick()

    assert busy.ok and busy.records == 1 and busy.inserted == 1
    assert len(probe_reads(h.device)) == 2, "a tick that stored records owes no probe"
    cp = read_checkpoint(h.conn, SERIAL)
    assert cp is not None and (cp.checkpoint_serial, cp.serial_epoch) == (104, 0)


# --- DoD (4): a probe that raises must not fail the tick or move the checkpoint ----------


def test_failed_quiet_probe_does_not_fail_the_tick(tmp_path: Path) -> None:
    """The alert path bends, never breaks: a dead probe read is "no evidence".

    Same scenario as DoD (1) — a real reset is waiting to be found — except the
    newest-first read itself dies. The tick still reports ok (the narrow poll DID
    complete), the checkpoint stays on the dead generation, and the operator hears
    about it through `warn`, the same channel the ring-floor probe uses.
    """
    h = quiet_replacement(
        tmp_path,
        new_serials=[(1, "2026-10-19T09:57:00"), (3, "2026-10-19T10:08:00")],
        fail_reverse_reads=True,
    )
    quiet = h.tick()

    assert quiet.ok, quiet.error
    assert quiet.exception is None and quiet.serial_reset is None
    assert quiet.records == 0
    cp = read_checkpoint(h.conn, SERIAL)
    assert cp is not None and (cp.checkpoint_serial, cp.serial_epoch) == (100, 0)
    assert cp.firmware == DEVICE_FW
    assert any("reset probe" in w and "failed" in w for w in h.warns), h.warns
    # The probe is a probe: it read nothing that could have moved anything.
    assert h.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 4


# --- ACCEPT: a drop WITHOUT evidence is a glitch, and is said once -----------------------


def test_quiet_probe_without_evidence_warns_once_and_never_rewinds(tmp_path: Path) -> None:
    """The card's own refusal arm: serial below, firmware unchanged, drop below floor.

    `RESET_MIN_SERIAL_DROP` exists because a few counts of jitter is not a hardware
    swap. On a quiet tick the in-window path's `CheckpointRegressionError` is the wrong
    answer (there is no chunk to refuse, and a failed tick would mask the poll's own
    truth), so the quiet probe warns once and leaves the checkpoint alone — and says
    nothing more at the NEXT probe, because a permanently glitchy counter is not an
    hourly alarm.
    """
    h = quiet_replacement(tmp_path, new_serials=[(50, "2026-10-19T10:08:00")], upgraded=False)
    quiet = h.tick()

    assert quiet.ok and quiet.serial_reset is None and quiet.advanced is False
    cp = read_checkpoint(h.conn, SERIAL)
    assert cp is not None and (cp.checkpoint_serial, cp.serial_epoch) == (100, 0)
    refused = [w for w in h.warns if "without reset evidence" in w]
    assert len(refused) == 1, h.warns

    # The same glitch an hour later: probed again (the budget allows it), still no
    # rewind, and NOT a second warning line.
    h.clock.advance(QUIET_S)
    h.monotonic.advance(QUIET_S)
    later = h.tick()
    assert later.ok and later.serial_reset is None
    assert len(probe_reads(h.device)) == 2
    assert [w for w in h.warns if "without reset evidence" in w] == refused
    cp = read_checkpoint(h.conn, SERIAL)
    assert cp is not None and (cp.checkpoint_serial, cp.serial_epoch) == (100, 0)


# --- the shape the probe must NOT become --------------------------------------------------


def _set_serial(device: FakeDevice, serial: str) -> None:
    """Re-serve `deviceInfo` with a different `serialNumber` (a swapped identity)."""
    xml = (
        (RECORDED / "device_info.xml")
        .read_text()
        .replace(
            "<serialNumber>MASKED-SER-1</serialNumber>", f"<serialNumber>{serial}</serialNumber>"
        )
    )
    assert f"<serialNumber>{serial}</serialNumber>" in xml
    device.reset(
        "GET",
        DEVICE_INFO_PATH,
        httpx.Response(200, text=xml, headers={"Content-Type": "application/xml"}),
    )


def test_quiet_probe_still_refuses_a_changed_device_identity(tmp_path: Path) -> None:
    """The card's MUST-NOT-CHANGE clause, applied to the new path.

    A `deviceInfo` serial that moved is a different terminal, not a restarted counter:
    stamping the new generation's punches under the old identity would corrupt every
    downstream join, so the refusal stands and the tick fails loudly with the checkpoint
    untouched — the in-window branch's behaviour, deliberately NOT softened into a warn.
    Only the probe's own READ is bend-not-break; the evidence read is a decision.
    """
    h = quiet_replacement(tmp_path, new_serials=[(1, "2026-10-19T10:08:00")])
    _set_serial(h.device, "MASKED-SER-2")

    quiet = h.tick()

    assert not quiet.ok and quiet.serial_reset is None
    assert quiet.exception is not None and "identity change" in quiet.error
    cp = read_checkpoint(h.conn, SERIAL)
    assert cp is not None and (cp.checkpoint_serial, cp.serial_epoch) == (100, 0)
    assert h.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 4


def test_quiet_probe_ignores_a_record_stamped_at_the_checkpoint_instant(
    tmp_path: Path,
) -> None:
    """Same instant, lower serial: NOT a new generation (the window floor is inclusive).

    The probe window starts AT the checkpoint stamp and this firmware's bounds are
    inclusive on both ends, so the checkpoint's own instant can come back. `_is_after_
    checkpoint` — strictly later, never merely equal — is the guard, and here it is the
    ONLY thing between this tick and an epoch that must not open: the firmware really
    did change, so `_reset_evidence` would have blessed the rewind.
    """
    h = quiet_replacement(tmp_path, new_serials=[(1, "2026-10-19T09:55:00")])
    quiet = h.tick()

    assert quiet.ok and quiet.serial_reset is None and quiet.advanced is False
    assert len(probe_reads(h.device)) == 1, "the read really happened"
    cp = read_checkpoint(h.conn, SERIAL)
    assert cp is not None and (cp.checkpoint_serial, cp.serial_epoch) == (100, 0)
    # Refused before the evidence read: no `deviceInfo` was paid for a non-candidate.
    assert device_info_reads(h.device) == 1


def test_an_unplaceable_checkpoint_stamp_probes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail closed: a floor that cannot be placed must not widen the read.

    The card's snippet swallowed the parse error and kept the 7-day ring bound — i.e. it
    answered "where does the old generation end?" by reading everything the ring holds,
    and warned about it every probe hour forever. There is no honest window in that
    shape, so the probe declines: no request, no rewind, one warning per probe. The
    injection fails only the probe's own call — `_parse_stamp` runs first for the poll's
    window floor, and the narrow walk must still complete.
    """
    h = quiet_replacement(tmp_path, new_serials=[(1, "2026-10-19T10:08:00")])
    real = agent_loop._parse_stamp
    calls = itertools.count()

    def flaky(stamp: str, *, site_tz: Any) -> Any:
        if next(calls) == 1:  # the poll's floor landed; the probe's does not
            raise IsapiError("injected: the checkpoint stamp cannot be placed")
        return real(stamp, site_tz=site_tz)

    monkeypatch.setattr(agent_loop, "_parse_stamp", flaky)
    quiet = h.tick()

    assert quiet.ok, quiet.error  # the narrow walk's own truth still stands
    assert quiet.serial_reset is None and quiet.advanced is False
    assert probe_reads(h.device) == [], "an unplaceable floor must not cost a request"
    assert any("cannot place checkpoint" in w for w in h.warns), h.warns
    cp = read_checkpoint(h.conn, SERIAL)
    assert cp is not None and (cp.checkpoint_serial, cp.serial_epoch) == (100, 0)


def test_probe_window_never_reads_back_before_the_checkpoint(tmp_path: Path) -> None:
    """A reset older than the probe window cannot be proven; the ring is not a promise.

    The probe asks for `[max(now - RESET_PROBE_WINDOW_S, checkpoint_time), now]`:
    reading below the checkpoint would re-serve events the store already has and could
    not prove a new generation anyway (`_is_after_checkpoint` refuses them). The bound
    is asserted on the wire, not in a helper.
    """
    h = quiet_replacement(tmp_path, new_serials=[(101, "2026-10-19T10:08:00")], upgraded=False)
    assert h.tick().ok
    probes = probe_reads(h.device)
    assert len(probes) == 1
    cond = probes[0]
    assert cond["startTime"].startswith("2026-10-19T09:55")  # the checkpoint's stamp
    assert cond["endTime"].startswith("2026-10-19T11:02")  # `now`, quiet + 2 min
    assert RESET_PROBE_WINDOW_S > QUIET_S  # the window is wide; the CHECKPOINT is the floor
