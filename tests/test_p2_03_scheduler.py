"""Card P2-03: the scheduler loop — 5 min cadence / 5 min overlap, ONE long-lived client.

BINDING SPEC: docs/P2-SITE-AGENT.md §2a (DECIDED 2026-10-19: 5 min / 5 min, one
long-lived `IsapiClient` per device across cycles so digest state amortizes against the
~190-request nonce use-cap) + §1 seams 2/3/7/9. Device truth: docs/OBSERVED.md. The
loop reuses P1 (paging's `iter_event_windows` cursor rules, pipeline's assembly +
capability discovery + claimed-offset read, transport's digest/circuit machinery) and
P2-02's store (`store_events` / `advance_checkpoint` / `read_checkpoint`); it owns only
`src/gateclerk/agent_loop.py`.

The five DoD cases, 1:1 to test names below:

(1) three ticks over a fake with events spread across an overlap window store every
    event EXACTLY once (the UPSERT guard holds: re-read rows keep revision 1, i.e. the
    overlap re-read is FREE, not a rewrite) and the checkpoint advances by the
    completed chunks' max only.
(2) a failed tick leaves the checkpoint UNMOVED and a retry heals (both shapes: a
    broken device mid-life, and a deleted row healed by the overlap re-poll).
(3) overlap math pinned on the wire: the request body's lower bound is exactly
    `checkpoint_time - overlap_s` in site-wall digits, LABELLED with the device's
    claimed offset (seam 7 — never site-labeled silently; the silent fallback is
    pinned separately as the *warned* shape).
(4) client reuse: N ticks, ONE authenticated session — exactly one unauthenticated
    handshake across the whole run (counted via FakeDevice.served `had_auth`, the
    card's own accounting), zero digest recoveries.
(5) clock injection: no real sleeps — `run_forever` records injected `sleep` calls and
    every time seam is an explicit argument (stdlib defaults pinned by signature, so
    the seam exists rather than being absent).

Plus the loop-shape pins the card names: circuit-open skips the device with ZERO
requests (no hammering, OBSERVED.md lockout accounting), the cold-start window, and
the SIGTERM-safe single-UPSERT checkpoint (P2-02 pins the mechanism; here the loop is
pinned to store + advance after EACH COMPLETED chunk — never around a failure, never
in a batch that a kill could halve).

Offline by construction: FakeDevice behind the real IsapiClient, tmp sqlite files,
injected clocks; conftest.netoff would still kill a socket and none is opened. No real
host or serial appears (fixtures carry MASKED-SER-1 and TEST-NET 192.0.2.x).
"""

from __future__ import annotations

import inspect
import json
import re
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import httpx

from fakedevice import BASE_URL, FakeDevice, invalid_content
from gateclerk.agent_db import connect
from gateclerk.agent_store import read_checkpoint
from gateclerk.config import SiteConfig
from gateclerk.exceptions import IsapiBadContent
from gateclerk.isapi_transport import IsapiClient
from gateclerk.paging import PagingLimits

RECORDED = Path(__file__).parent / "fixtures" / "recorded" / "site-a-ds-k1t341amf-s"
SCENARIOS = Path(__file__).parent / "fixtures" / "scenarios"

SITE = "site-a"
PASSWORD = "fakepw"  # hygiene placeholder (tests/test_repo_hygiene.py)
SITE_TZ = "Europe/Bucharest"
#: site-a claims +02:00 year-round inside a +03:00 summer (OBSERVED.md "time/offset bug").
DEVICE_CLAIM_MIN = 120

DEVICE_INFO_PATH = "/ISAPI/System/deviceInfo?format=json"
SYSTEM_TIME_PATH = "/ISAPI/System/time?format=json"
ACS_CAPS_PATH = "/ISAPI/AccessControl/AcsEvent/capabilities?format=json"
AC_CAPS_PATH = "/ISAPI/AccessControl/capabilities?format=json"
EVENT_PATH = "/ISAPI/AccessControl/AcsEvent?format=json"

CADENCE_S = 300
OVERLAP_S = 300

#: The pinned run date: 2026-10-19 is Bucharest SUMMER (+03:00, still inside EU DST), so
#: the site label (+03:00) and the device's +02:00 claim genuinely disagree — the exact
#: shape the A/B of OBSERVED.md proved the device does arithmetic on.
T0 = datetime(2026, 10, 19, 10, 0, 0, tzinfo=ZoneInfo(SITE_TZ))


# --- the harness -----------------------------------------------------------------------


class FakeClock:
    """An injected wall clock: `clock()` reads it, `advance(s)` moves it. Never real."""

    def __init__(self, start: datetime = T0) -> None:
        self.current = start

    def __call__(self) -> datetime:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += timedelta(seconds=seconds)


class FakeMonotonic:
    """The transport/pacing monotonic seam, in the same fake-time universe."""

    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def device_event(serial: int, wall: str) -> dict[str, Any]:
    """One stored event stamped site-a-style: ITS wall digits + ITS claimed +02:00.

    The fields are the RECORDED page's granted pass (`events_major5_page1.json`: minor 75,
    `employeeNoString`, `currentVerifyMode: cardOrFaceOrFp`), not a bare code. GC-P01 makes
    `queue_new_events` carry only punch candidates, and an event a working site polls IS a
    pass; a fake stamped `minor: 0` with no verify mode classifies as `unknown_code`, so it
    is stored and — correctly — never queued, which would leave every queue/drain assertion
    here reasoning about data the classifier refuses to call a punch.
    """
    return {
        "serialNo": serial,
        "employeeNoString": "1",
        "name": "User E1",
        "major": 5,
        "minor": 75,
        "time": f"{wall}+02:00",
        "cardType": 1,
        "cardReaderNo": 1,
        "doorNo": 1,
        "type": 0,
        "userType": "normal",
        "currentVerifyMode": "cardOrFaceOrFp",
        "mask": "no",
    }


def system_time_body_at(moment: datetime) -> str:
    """The recorded `System/time` body with its wall digits at `moment`, claimed stamp kept.

    THE DEVICE CLOCK, DERIVED — not frozen. The recorded body carries a 2026-10-15 probe
    snapshot (`localTime 2026-10-15T16:39:32+02:00`). Served verbatim to a run whose injected
    clock is `T0` — or `T0` plus days, which the ring-floor cases do — the fake is a terminal
    whose RTC sits days off the agent's. Nothing read that reading until GC-P04 wired the tick's
    `Skew` into P2-05's warning channel, at which point every such test woke up holding a
    `clock_skew` warning it never claimed to be about. A real RTC keeps counting, so the honest
    fixture DERIVES the reading from the scenario clock; `e2e_harness._fresh_wall` already does
    exactly this for the goldens, for the same stated reason ("no golden ages; skew measures the
    clock, not fixture rot from a 2026-10-15 probe snapshot").

    Only the digits move. The `<localTime>` *suffix* — the +02:00 stamp OBSERVED.md proves is
    wrong inside +03:00 summer — survives verbatim, because that stamp, not the reading, is what
    defines this scenario and what every window-label assertion here depends on.
    """
    text = (RECORDED / "system_time.xml").read_text()
    wall = moment.astimezone(ZoneInfo(SITE_TZ)).strftime("%Y-%m-%dT%H:%M:%S")
    stamped, hits = re.subn(
        r"<localTime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}([^<]*)</localTime>",
        lambda m: f"<localTime>{wall}{m.group(1)}</localTime>",
        text,
        count=1,
    )
    assert hits == 1, (
        "the recorded System/time body lost its <localTime> element: the seam below would "
        "stamp nothing and every clock-sensitive test here would silently stop testing"
    )
    return stamped


def seeded_device(**over: Any) -> FakeDevice:
    """A FakeDevice answering the loop's bootstrap GETs with the RECORDED site-a bodies.

    Its RTC is derived from the scenario clock (`T0`) by `system_time_body_at`, so a default
    seeded box is a device whose clock is RIGHT — which is what every scheduler/agent test
    here assumes unless it is specifically about a skewed clock (then: `reset` the
    `System/time` route to your own body, the way GC-P04's skew tests do).
    """
    device = FakeDevice(password=PASSWORD)
    device.claimed_offset_min = over.pop("claimed", DEVICE_CLAIM_MIN)
    assert not over, f"unknown seed knobs: {sorted(over)}"
    device.xml_ok("GET", DEVICE_INFO_PATH, (RECORDED / "device_info.xml").read_text())
    device.xml_ok("GET", SYSTEM_TIME_PATH, system_time_body_at(T0))
    device.add(
        "GET",
        ACS_CAPS_PATH,
        httpx.Response(200, content=(RECORDED / "acs_capabilities.json").read_bytes()),
    )
    device.add(
        "GET",
        AC_CAPS_PATH,
        httpx.Response(
            200,
            content=(
                SCENARIOS.parent / "synthetic" / "access_control_capabilities.json"
            ).read_bytes(),
        ),
    )
    return device


def seed_events(device: FakeDevice, events: list[dict[str, Any]]) -> None:
    device.add_events(*events)


class LoopHarness:
    """One device fake + one connection + ONE client shared by every tick of the run."""

    def __init__(
        self,
        tmp_path: Path,
        device: FakeDevice,
        *,
        clock: FakeClock | None = None,
        monotonic: FakeMonotonic | None = None,
        client_password: str | None = None,
        limits: PagingLimits | None = None,
        warn_sink: list[str] | None = None,
    ) -> None:
        from gateclerk.agent_loop import DeviceLoop
        from gateclerk.capabilities import capability_cache

        # The capability cache is PROCESS state (p1-04); a stale entry from another
        # test would answer this walk's caps without the fake ever being asked —
        # the same clearing e2e_harness.install does.
        capability_cache().clear()
        self.device = device
        self.clock = clock or FakeClock()
        self.monotonic = monotonic or FakeMonotonic()
        self.warns: list[str] = warn_sink if warn_sink is not None else []
        self.sleeps: list[float] = []
        self.conn = connect(tmp_path / "agent.sqlite3")
        self.client = IsapiClient(
            BASE_URL,
            "admin",
            PASSWORD if client_password is None else client_password,
            transport=device.transport,
            sleep=self.sleeps.append,
            now=self.monotonic,
        )
        self.loop = DeviceLoop(
            client=self.client,
            conn=self.conn,
            site=SITE,
            site_tz=SITE_TZ,
            cadence_s=CADENCE_S,
            overlap_s=OVERLAP_S,
            limits=limits,
            inter_page_delay=0.0,
            now=self.clock,
            monotonic=self.monotonic,
            warn=self.warns.append,
        )

    def tick(self) -> Any:
        """One tick at the current fake time (the clock is advanced by the test)."""
        return self.loop.tick()

    def ticks(self, n: int, step_s: float = CADENCE_S) -> list[Any]:
        out = []
        for _ in range(n):
            out.append(self.tick())
            self.clock.advance(step_s)
            self.monotonic.advance(step_s)
        return out

    # -- device-side accounting (the card's pin: FakeDevice.served with had_auth) ------

    def event_conditions(self, since_index: int = 0) -> list[dict[str, Any]]:
        """AcsEventCond of every event POST served at index >= since_index."""
        out = []
        for served in self.device.served[since_index:]:
            if served.path != EVENT_PATH or not served.body:
                continue
            try:
                body = json.loads(served.body)
            except json.JSONDecodeError:
                continue
            cond = body.get("AcsEventCond") if isinstance(body, dict) else None
            if isinstance(cond, dict):
                out.append(cond)
        return out

    def unauthenticated_handshakes(self) -> int:
        return sum(1 for s in self.device.served if not s.had_auth)

    def stored_rows(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT serial_no, revision, device_serial, jsonl FROM events ORDER BY serial_no"
        ).fetchall()


# --- DoD (1): three ticks, each event exactly once, checkpoint by completed max --------


def test_three_ticks_store_every_event_exactly_once_and_checkpoint_advances_by_completed_max(
    tmp_path: Path,
) -> None:
    """The overlap window must re-read FREE and the checkpoint must chase completed max.

    Events land every ~3 min across the tick boundaries, so ticks 2 and 3 re-read a
    chunk of already-stored rows: the P2-02 UPSERT guard (`jsonl IS NOT excluded.jsonl`)
    makes that a zero-write conflict, so `revision` stays 1 on every row — a loop that
    rewrote identical bytes would show revision > 1 (the mutation this pin catches).
    """
    device = seeded_device()
    # site-wall digits (the fake filters on the digits); serials count up device-wide.
    seed_events(
        device,
        [
            device_event(100, "2026-10-19T09:52:00"),
            device_event(101, "2026-10-19T09:55:00"),
            device_event(102, "2026-10-19T09:58:00"),
            device_event(103, "2026-10-19T10:01:00"),
            device_event(104, "2026-10-19T10:04:00"),
            device_event(105, "2026-10-19T10:07:00"),
            device_event(106, "2026-10-19T10:10:00"),
            device_event(107, "2026-10-19T10:13:00"),  # arrives in a later tick only
        ],
    )
    h = LoopHarness(tmp_path, device)

    r1, r2, r3 = h.ticks(3)
    assert (r1.ok, r2.ok, r3.ok) == (True, True, True)
    # tick1 cold-start window [09:50,10:00] -> 100..102; tick2 [09:53,10:05] re-reads
    # 101..102 free and adds 103,104; tick3 [09:59,10:10] re-reads 103,104 and adds
    # 105,106. (The counts make the card's "store each exactly once" numeric.)
    assert (r1.inserted, r1.unchanged) == (3, 0)
    assert (r2.inserted, r2.unchanged) == (2, 2)
    assert (r3.inserted, r3.unchanged) == (2, 2)

    rows = h.stored_rows()
    assert [r["serial_no"] for r in rows] == [100, 101, 102, 103, 104, 105, 106]
    assert all(r["revision"] == 1 for r in rows), (
        "the overlap re-read must be a FREE conflict (zero write, zero revision bump)"
    )
    assert all(r["device_serial"] == "MASKED-SER-1" for r in rows)

    # Checkpoint: completed max only — 102 after tick1, 104 after tick2, 106 after
    # tick3; the still-uncovered 107 must NOT appear (no premature advance).
    cp = read_checkpoint(h.conn, "MASKED-SER-1")
    assert cp is not None and cp.checkpoint_serial == 106
    assert cp.checkpoint_time == "2026-10-19T10:10:00+02:00"  # device-local, verbatim
    assert (r1.checkpoint_serial, r2.checkpoint_serial, r3.checkpoint_serial) == (102, 104, 106)
    assert (r1.advanced, r2.advanced, r3.advanced) == (True, True, True)


# --- DoD (2): failed tick = checkpoint unmoved; retry heals -----------------------------


def test_failed_tick_leaves_checkpoint_unmoved_and_retry_heals(tmp_path: Path) -> None:
    """A broken device must not move the checkpoint, and the overlap must heal the gap.

    Shape: ticks at 10:00 and 10:05 find nothing yet (events start at 10:10). The
    events endpoint then answers the recorded terminal `Invalid Content` and STAYS
    there (reset_raw repeats the last item): the 10:10 tick fails, the checkpoint row
    never moves, and no partial write exists. Clearing the fault and re-ticking heals
    everything from `checkpoint_time - overlap` — the failed range is re-read, nothing
    is skipped.
    """
    device = seeded_device()
    seed_events(
        device,
        [device_event(120 + i, f"2026-10-19T10:{10 + 2 * i:02d}:00") for i in range(8)],
    )
    h = LoopHarness(tmp_path, device)

    r1 = h.tick()  # window [09:50,10:00] -> nothing yet
    assert r1.ok and r1.inserted == 0
    assert read_checkpoint(h.conn, "MASKED-SER-1") is None  # empty chunk = no advance

    h.clock.advance(CADENCE_S)  # 10:05, still before the first event
    r2 = h.tick()  # window [09:50,10:05] -> still nothing (events start 10:10)
    assert r2.ok and r2.inserted == 0

    device.reset_raw("POST", EVENT_PATH, invalid_content())
    h.clock.advance(CADENCE_S)  # 10:10 — events 10:10.. are in-window and unreachable
    r3 = h.tick()
    assert not r3.ok and r3.error is not None
    assert "Invalid Content" in r3.error
    assert read_checkpoint(h.conn, "MASKED-SER-1") is None
    # Nothing half-walked is in the store: the failed chunk never reached a store+advance.
    assert [r["serial_no"] for r in h.stored_rows()] == []

    # Heal: same client, same loop, fault removed. No checkpoint exists yet, so the
    # cold floor (now - cadence - overlap) still reaches back over the failed range,
    # and consecutive ticks walk the backlog forward exactly like normal operation:
    # 10:15 sees 10:10..10:14, 10:20 sees to 10:20, 10:25 closes out 10:22/10:24.
    device.raw[f"POST {EVENT_PATH}"] = []
    r4 = h.tick()  # still 10:10 -> [10:00,10:10] catches only serial 120
    assert r4.ok, r4.error
    h.clock.advance(CADENCE_S)
    r5 = h.tick()  # 10:15 -> floor 10:05 -> through 10:14
    assert r5.ok, r5.error
    h.clock.advance(CADENCE_S)
    r6 = h.tick()  # 10:20 -> through 10:20
    assert r6.ok, r6.error
    h.clock.advance(CADENCE_S)
    r7 = h.tick()  # 10:25 -> through 10:24: everything healed
    assert r7.ok, r7.error
    assert [r["serial_no"] for r in h.stored_rows()] == list(range(120, 128))
    cp = read_checkpoint(h.conn, "MASKED-SER-1")
    assert cp is not None and cp.checkpoint_serial == 127


def test_deleted_row_is_healed_by_the_overlap_re_poll_without_moving_the_checkpoint(
    tmp_path: Path,
) -> None:
    """The crash-shape healer (P2-02's "overlap heals", driven through the real loop).

    A committed row vanishes (WAL-tail loss on a kill — the scenario agent_db's
    synchronous=NORMAL choice tolerates). The checkpoint is ahead of it, so only the
    overlap re-read can restore it: after the next tick the row is back byte-identical,
    the checkpoint did NOT move (equal serial = quiet no-op), and the re-store of the
    SURVIVING rows was free (revision stays 1; only the healed row counts inserted).

    The deleted row sits INSIDE the overlap floor (checkpoint_time - overlap): what
    falls behind the floor is, by design, outside the heal horizon — the checkpoint is
    the promise "everything at or below is durable", and widening the horizon silently
    would be the same lie in the other direction.
    """
    device = seeded_device()
    walls = ["09:50", "09:52", "09:54", "09:56", "09:58", "10:00"]
    seed_events(
        device,
        [device_event(130 + i, f"2026-10-19T{w}:00") for i, w in enumerate(walls)],
    )
    h = LoopHarness(tmp_path, device)
    r1 = h.tick()
    assert r1.ok and r1.inserted == 6  # 09:50..10:00 all inside the cold window
    cp1 = read_checkpoint(h.conn, "MASKED-SER-1")
    assert cp1 is not None and cp1.checkpoint_serial == 135
    assert cp1.checkpoint_time == "2026-10-19T10:00:00+02:00"

    lost = h.conn.execute("SELECT jsonl FROM events WHERE serial_no = 134").fetchone()
    h.conn.execute("DELETE FROM events WHERE serial_no = 134")
    remaining = h.conn.execute("SELECT COUNT(*) c FROM events WHERE serial_no = 134").fetchone()[
        "c"
    ]
    assert remaining == 0

    h.clock.advance(CADENCE_S)
    r2 = h.tick()  # 10:05, floor = 10:00 - 300 s = 09:55 -> 133(09:56),134(09:58),135(10:00)
    assert r2.ok
    row = h.conn.execute("SELECT jsonl, revision FROM events WHERE serial_no = 134").fetchone()
    assert row is not None and row["revision"] == 1
    # The healed line is the lost one EXCEPT captured_at: the row was gone, so this
    # re-poll IS its first contact in the store now (the surviving rows keep theirs).
    healed = json.loads(row["jsonl"])
    original = json.loads(lost["jsonl"])
    healed.pop("captured_at"), original.pop("captured_at")
    assert healed == original
    assert (r2.inserted, r2.unchanged) == (1, 2)  # the healed row + two FREE re-reads
    cp2 = read_checkpoint(h.conn, "MASKED-SER-1")
    assert cp2 is not None and cp2.checkpoint_serial == 135  # unmoved (equal = no-op)
    assert not r2.advanced  # the loop reports the quiet tick honestly


# --- DoD (3): overlap math + device-claimed label, pinned on the wire -------------------


def test_overlap_lower_bound_lands_on_the_wire_device_claim_labelled(tmp_path: Path) -> None:
    """`checkpoint_time - overlap_s` in site-wall digits, relabelled +02:00 (seam 7).

    Pinning `FakeDevice.served` bodies is the card's requirement; and because the fake
    filters by the device's ARITHMETIC (fakedevice.py), a site-labelled (+03:00) bound
    would not merely print differently here — it would ANSWER A SHIFTED WINDOW.
    """
    device = seeded_device()
    seed_events(
        device,
        [
            device_event(140, "2026-10-19T09:58:00"),
            device_event(141, "2026-10-19T10:01:00"),
        ],
    )
    h = LoopHarness(tmp_path, device)

    r1 = h.tick()  # cold start [09:50,10:00]: covers 09:58
    assert r1.ok
    cold = h.event_conditions()[0]
    # The cold-start lower bound is one (cadence + overlap) back, same claimed label.
    assert cold["startTime"] == "2026-10-19T09:50:00+02:00"
    assert cold["endTime"] == "2026-10-19T10:00:00+02:00"
    assert cold["major"] == 5  # noise excluded by default (OBSERVED.md census)
    assert "picEnable" not in cold
    assert r1.window_label == "device-claimed +02:00"
    assert h.warns == []  # a known claim must never trigger the fallback warning

    mark = len(h.device.served)
    h.clock.advance(CADENCE_S)  # now 10:05; checkpoint_time is 09:58 device wall
    r2 = h.tick()
    assert r2.ok
    conds = h.event_conditions(since_index=mark)
    assert conds, "the second tick must have searched"
    # 09:58 (device-local stamp of serial 140) minus 300 s overlap = 09:53, and the
    # digits go out labelled with the device's CLAIMED +02:00, not the site's +03:00.
    assert conds[0]["startTime"] == "2026-10-19T09:53:00+02:00"
    assert conds[0]["endTime"] == "2026-10-19T10:05:00+02:00"
    assert r2.window_label == "device-claimed +02:00"


def test_unreadable_device_claim_falls_back_to_site_label_with_a_warning(
    tmp_path: Path,
) -> None:
    """Seam 7's only allowed deviation: the p1-05c *warned* site-labelled fallback.

    The naive System/time box (scenarios/naive_time) carries no offset to claim, so
    the loop must (a) warn every tick, (b) send the site-labelled pair, and (c) never
    invent an offset. Silent site-labelling is the payroll bug OBSERVED.md's A/B
    proved; a silently invented offset is its twin.
    """
    device = seeded_device()
    naive = (SCENARIOS / "naive_time" / "system_time.xml").read_text()
    device.reset("GET", SYSTEM_TIME_PATH, httpx.Response(200, text=naive))
    seed_events(device, [device_event(150, "2026-10-19T09:58:00")])
    h = LoopHarness(tmp_path, device)

    r = h.tick()
    assert r.ok
    cond = h.event_conditions()[0]
    assert cond["startTime"].endswith("+03:00"), "no claim readable -> the site label is honest"
    assert r.window_label == "site (fallback)"
    assert len(h.warns) == 1 and "window labeled" in h.warns[0]


# --- DoD (4): ONE long-lived client, ONE authenticated session --------------------------


def test_many_ticks_reuse_one_client_and_pay_exactly_one_handshake(tmp_path: Path) -> None:
    """The §2a amortization, counted the way the card dictates (`had_auth` accounting).

    One IsapiClient is built (the harness builds it once; the loop never rebuilds it),
    so across all four ticks the device sees exactly ONE unauthenticated request — the
    bootstrap GET that pays the first challenge. A loop that rebuilt the client per
    tick would pay an extra handshake per tick and hit the ~190-request nonce cap far
    sooner (spec §2a: "rebuilding the client per poll ... hits the cap ~3x faster").
    """
    device = seeded_device()
    seed_events(
        device,
        [device_event(160 + i, f"2026-10-19T09:{50 + i * 2:02d}:00") for i in range(5)],
    )
    h = LoopHarness(tmp_path, device)

    results = h.ticks(4)
    assert all(r.ok for r in results)
    assert h.unauthenticated_handshakes() == 1
    assert device.challenges == 1
    assert h.client.auth_recoveries == 0
    # And every later request still carries a valid digest (the session is real).
    assert all(s.had_auth for s in h.device.served[1:])


# --- DoD (5): clock injection = no real sleeps ------------------------------------------


def test_run_forever_uses_injected_clock_and_sleep_and_never_really_sleeps(
    tmp_path: Path,
) -> None:
    """`run_forever(loop, sleep=..., max_ticks=...)` is the scheduler seam, not a sleep loop.

    The card bans `time.sleep` from tests and demands an injected clock; this pins both
    directions of that contract: the seam's STDLIB default exists (so the product
    really sleeps between ticks), and every injected run does not (the whole test
    finishes in milliseconds — a 5-min cadence would not if injection were ignored).
    """
    from gateclerk.agent_loop import DeviceLoop, run_forever

    device = seeded_device()
    seed_events(device, [device_event(170, "2026-10-19T09:58:00")])
    h = LoopHarness(tmp_path, device)

    slept: list[float] = []
    results = run_forever(h.loop, sleep=slept.append, max_ticks=3)

    assert len(results) == 3 and all(r.ok for r in results)
    assert slept == [float(CADENCE_S)] * 2  # sleeps BETWEEN ticks, never after the last
    assert h.clock.current == T0  # run_forever never touches the wall clock itself

    # The seams are explicit parameters with stdlib defaults — the injection point
    # exists rather than being an absent hook (a mutation deleting one breaks these
    # signature lines before any behaviour test runs).
    sig = inspect.signature(DeviceLoop.__init__)
    assert sig.parameters["now"].default is not inspect.Parameter.empty
    assert sig.parameters["monotonic"].default is time.monotonic
    assert inspect.signature(run_forever).parameters["sleep"].default is time.sleep


# --- circuit-open: skip, never hammer (spec §1 seam 9 / §2c) -----------------------------


def test_open_circuit_skips_the_device_with_zero_requests_and_close_reopens(
    tmp_path: Path,
) -> None:
    """Terminal auth failure parks the device loop; a skip costs the device NOTHING.

    With the wrong password the transport opens its circuit (lockout accounting,
    OBSERVED.md). The loop must then return a skipped result WITHOUT sending a single
    request — the "no hammering while parked" clause — and resume attempts once the
    circuit's own unlock window passes (the acked slow-re-probe policy is P2-05's).
    """
    device = seeded_device()
    seed_events(device, [device_event(180, "2026-10-19T09:58:00")])
    h = LoopHarness(tmp_path, device, client_password="wrong-password")

    r1 = h.tick()
    assert not r1.ok and not r1.skipped
    assert h.client.circuit_open()

    mark = len(h.device.served)
    r2 = h.tick()
    assert r2.skipped and not r2.ok and r2.circuit_open
    assert len(h.device.served) == mark, "a skipped tick must not touch the device"
    assert read_checkpoint(h.conn, "MASKED-SER-1") is None  # nothing ever advanced

    # Wait the circuit out through the injected monotonic (no real waiting); the loop
    # then attempts again — one request pair, not a retry storm.
    mark = len(h.device.served)
    h.monotonic.advance(400)
    r3 = h.tick()
    assert not r3.ok and not r3.skipped
    assert len(h.device.served) > mark


# --- cold start: first tick has no checkpoint; window = (cadence + overlap) back ---------


def test_cold_start_reads_back_one_cadence_plus_overlap_and_bootstraps_state(
    tmp_path: Path,
) -> None:
    """No checkpoint row: the first window reaches [now - (cadence + overlap), now].

    The design decision this pins (documented in agent_loop): a fresh install reads one
    cadence back plus the overlap margin — a full-history backfill belongs to the CLI
    (`gateclerk events`), not to a systemd unit's first 5 minutes. Identity, capabilities
    and the claimed offset are read once here and amortized over the client's life.
    """
    device = seeded_device()
    seed_events(
        device,
        [
            device_event(190, "2026-10-19T09:00:00"),  # behind the cold-start floor
            device_event(191, "2026-10-19T09:59:00"),
        ],
    )
    h = LoopHarness(tmp_path, device)

    r = h.tick()
    assert r.ok
    cond = h.event_conditions()[0]
    assert cond["startTime"] == "2026-10-19T09:50:00+02:00"
    assert [row["serial_no"] for row in h.stored_rows()] == [191]
    cp = read_checkpoint(h.conn, "MASKED-SER-1")
    assert cp is not None and cp.checkpoint_serial == 191
    assert r.device_serial == "MASKED-SER-1"
    # Bootstrap reads: deviceInfo once, System/time once (caps too, once each). The
    # FIRST GET pays the digest challenge, so its 401-replay lands in `served` twice
    # under the same path — count AUTHENTICATED requests, the logical read count.
    authed = [f"{s.method} {s.path}" for s in h.device.served if s.had_auth]
    assert authed.count(f"GET {DEVICE_INFO_PATH}") == 1
    assert authed.count(f"GET {SYSTEM_TIME_PATH}") == 1


def test_second_tick_does_not_re_read_identity_or_claim(tmp_path: Path) -> None:
    """Long-lived client = long-lived device state: one bootstrap for the whole run.

    Re-reading deviceInfo/System/time every tick would multiply requests against the
    ~190-use nonce cap (spec §2a request math: ~1 POST per cycle is the target).
    """
    device = seeded_device()
    seed_events(device, [device_event(200, "2026-10-19T09:58:00")])
    h = LoopHarness(tmp_path, device)
    h.ticks(3)
    # Authenticated requests only: the first GET of the session pays the digest
    # challenge once (unauth attempt + replay); every LATER tick re-reads nothing.
    get_paths = [s.path for s in h.device.served if s.method == "GET" and s.had_auth]
    assert get_paths.count(SYSTEM_TIME_PATH) == 1
    assert get_paths.count(DEVICE_INFO_PATH) == 1


# --- result object: what P2-05 alerts on --------------------------------------------------


def test_tick_result_surfaces_the_failure_for_p2_05_without_raising(tmp_path: Path) -> None:
    """A failed tick RETURNS a result; it never raises into the scheduler (P2-05 reads)."""
    device = seeded_device()
    device.reset_raw("POST", EVENT_PATH, invalid_content())
    h = LoopHarness(tmp_path, device)

    r = h.tick()
    assert not r.ok and r.skipped is False
    assert r.exception is not None and "IsapiBadContent" in r.error
    assert r.error and "Invalid Content" in r.error
    assert r.pages == 0 and r.records == 0 and r.stored == 0
    # The typed exception class survives in the message (prefix) for alert routing:
    # auth vs device vs walk is P2-05's first routing decision (spec §2c).
    assert isinstance(r.exception, IsapiBadContent)


# --- build seam: config -> loop, refs-only credentials (P2-01 helpers) --------------------


def test_build_device_loop_uses_site_config_and_env_password(tmp_path: Path, monkeypatch) -> None:
    """`build_device_loop(site=SiteConfig)` wires host/port/cadence/overlap/tz/db-path.

    The credential comes through P1's resolver (env rung here — the refs-only rule of
    spec §2d: configs carry NAMES, never values). Building opens no socket; the
    autouse offline guard would kill the test if it did.
    """
    from gateclerk.agent_loop import build_device_loop

    monkeypatch.setenv("GATECLERK_192_0_2_10_PASSWORD", PASSWORD)
    site = SiteConfig(
        name=SITE,
        host="192.0.2.10",
        iana_tz=SITE_TZ,
        device_tz=SITE_TZ,
        cadence_s=120,
        overlap_s=60,
        db_path=str(tmp_path / "built.sqlite3"),
    )
    loop = build_device_loop(site)
    try:
        assert loop.site_tz == SITE_TZ and loop.device_tz == SITE_TZ
        assert (loop.cadence_s, loop.overlap_s) == (120, 60)
        assert loop.device_serial is None  # nothing read until the first tick
    finally:
        loop.close()
    # The db file was created by the build (P2-01's resolved-path seam, honoured).
    assert (tmp_path / "built.sqlite3").exists()


# --- serialNo reset after a firmware upgrade / log clear (card t_fbd85a10) ----------------

DEVICE_FW = "V3.2.30"
DEVICE_FW_UPGRADED = "V4.13.0"


def _set_firmware(device: FakeDevice, version: str) -> None:
    """Re-serve deviceInfo with a different firmwareVersion (same masked identity)."""
    xml = (
        (RECORDED / "device_info.xml")
        .read_text()
        .replace(
            f"<firmwareVersion>{DEVICE_FW}</firmwareVersion>",
            f"<firmwareVersion>{version}</firmwareVersion>",
        )
    )
    assert f"<firmwareVersion>{version}</firmwareVersion>" in xml
    device.reset(
        "GET",
        DEVICE_INFO_PATH,
        httpx.Response(200, text=xml, headers={"Content-Type": "application/xml"}),
    )


def test_serial_reset_stores_new_punches_in_a_new_epoch_and_alerts_once(
    tmp_path: Path,
) -> None:
    """Firmware upgrade + newest serial below the checkpoint = one confirmed reset.

    The old generation keeps serials 1, 2, 3 and 100; the post-reset punches reuse
    serials 1..3 at LATER times. They must land as new rows (never merge into the old
    ones), the checkpoint must open epoch 1 (the only legal rewind), and the tick must
    carry the one alert evidence. The next overlap tick must stay quiet.
    """
    device = seeded_device()
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
    r1 = h.tick()
    assert r1.ok and r1.serial_reset is None
    cp = read_checkpoint(h.conn, "MASKED-SER-1")
    assert cp is not None and (cp.checkpoint_serial, cp.serial_epoch) == (100, 0)
    assert cp.firmware == DEVICE_FW

    # The upgrade resets the event counter; new punches reuse serial 1..3 at later times.
    _set_firmware(device, DEVICE_FW_UPGRADED)
    seed_events(
        device,
        [
            device_event(1, "2026-10-19T10:02:00"),
            device_event(2, "2026-10-19T10:05:00"),
            device_event(3, "2026-10-19T10:08:00"),
        ],
    )
    h.clock.advance(600)
    h.monotonic.advance(600)
    r2 = h.tick()

    assert r2.ok and r2.inserted == 3
    assert r2.serial_reset is not None
    assert (r2.serial_reset.old_serial, r2.serial_reset.new_serial) == (100, 3)
    assert r2.serial_reset.old_firmware == DEVICE_FW
    assert r2.serial_reset.new_firmware == DEVICE_FW_UPGRADED
    cp = read_checkpoint(h.conn, "MASKED-SER-1")
    assert cp is not None
    assert (cp.checkpoint_serial, cp.serial_epoch) == (3, 1)
    assert cp.firmware == DEVICE_FW_UPGRADED

    rows = h.conn.execute(
        "SELECT serial_epoch, serial_no, jsonl FROM events ORDER BY serial_epoch, serial_no"
    ).fetchall()
    assert [(r["serial_epoch"], r["serial_no"]) for r in rows] == [
        (0, 1),
        (0, 2),
        (0, 3),
        (0, 100),
        (1, 1),
        (1, 2),
        (1, 3),
    ]
    old_one = json.loads(
        h.conn.execute(
            "SELECT jsonl FROM events WHERE serial_epoch = 0 AND serial_no = 1"
        ).fetchone()["jsonl"]
    )
    new_one = json.loads(
        h.conn.execute(
            "SELECT jsonl FROM events WHERE serial_epoch = 1 AND serial_no = 1"
        ).fetchone()["jsonl"]
    )
    assert old_one["event_time_local"].startswith("2026-10-19T09:51")
    assert new_one["event_time_local"].startswith("2026-10-19T10:02")

    # A later overlap re-read is free, opens no new epoch and raises no second alert.
    h.clock.advance(CADENCE_S)
    h.monotonic.advance(CADENCE_S)
    r3 = h.tick()
    assert r3.ok and r3.serial_reset is None and r3.inserted == 0
    cp = read_checkpoint(h.conn, "MASKED-SER-1")
    assert cp is not None and (cp.checkpoint_serial, cp.serial_epoch) == (3, 1)
    assert h.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 7


def test_repoll_overlap_without_reset_is_not_a_reset(tmp_path: Path) -> None:
    """Overlap re-reads (and a quiet tick) must never open an epoch or read deviceInfo."""
    device = seeded_device()
    seed_events(
        device,
        [
            device_event(100, "2026-10-19T09:52:00"),
            device_event(101, "2026-10-19T09:55:00"),
            device_event(102, "2026-10-19T09:58:00"),
            device_event(103, "2026-10-19T10:01:00"),
        ],
    )
    h = LoopHarness(tmp_path, device)
    results = h.ticks(3)
    assert all(r.ok for r in results)
    assert all(r.serial_reset is None for r in results)
    cp = read_checkpoint(h.conn, "MASKED-SER-1")
    assert cp is not None and cp.serial_epoch == 0
    # No suspicious tick, so the one-time bootstrap identity read is the only one.
    authed_gets = [s.path for s in h.device.served if s.method == "GET" and s.had_auth]
    assert authed_gets.count(DEVICE_INFO_PATH) == 1


def test_a_lower_serial_without_reset_evidence_fails_without_rewind_or_merge(
    tmp_path: Path,
) -> None:
    """A glitch (same firmware, small drop) must NOT rewind; nothing collides/merges."""
    device = seeded_device()
    seed_events(device, [device_event(100, "2026-10-19T09:55:00")])
    h = LoopHarness(tmp_path, device)
    assert h.tick().ok
    cp = read_checkpoint(h.conn, "MASKED-SER-1")
    assert cp is not None and cp.checkpoint_serial == 100

    # The device loses the high serial (a glitch, not a reset): same firmware, and the
    # drop (100 -> 50) is below the far-below floor.
    device._event_store = [e for e in (device._event_store or []) if e["serialNo"] != 100]
    seed_events(device, [device_event(50, "2026-10-19T10:02:00")])
    h.clock.advance(600)
    h.monotonic.advance(600)
    r = h.tick()

    assert not r.ok and r.serial_reset is None
    assert r.exception is not None and "CheckpointRegressionError" in r.error
    cp = read_checkpoint(h.conn, "MASKED-SER-1")
    assert cp is not None and (cp.checkpoint_serial, cp.serial_epoch) == (100, 0)
    rows = h.conn.execute("SELECT serial_no FROM events ORDER BY serial_no").fetchall()
    assert [row["serial_no"] for row in rows] == [100]
