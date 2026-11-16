"""Card P2-05: alerts + park-on-bad-creds (acked 30-min re-probe; lockout on-site; nonce=info).

BINDING SPEC: docs/internal/P2-SITE-AGENT.md §2c (DECIDED verbatim 2026-10-19):

* terminal 401 WITH challenge (wrong/rotated creds) -> CRITICAL + the device loop
  PARKS: no automatic re-probe; slow re-probe every 30 min ONLY after operator ack;
* 401 body ``lockStatus=lock`` -> CRITICAL + operator on site (the transport circuit
  already waits out ``unlockTime`` — never present creds while locked);
* nonce recoveries -> NOT an alert: an info counter line only;
* clock skew over threshold -> warning;
* checkpoint stall -> CRITICAL only on evidence of loss: k consecutive non-auth
  failed polls with a stale checkpoint, or our store's oldest serialNo rising
  (stored history disappeared — not ring-rollover; that is card t_ed9c7e92).

The lockout-safety invariant the card pins hardest: an UNACKED parked device must be
touched NEVER AGAIN — not at the cadence, not after a restart, not "just one probe".
Every "zero requests" assertion below counts ``FakeDevice.served`` (the card's own
accounting, as in P2-03) and the ``had_auth`` flag (the "never present creds" half).

Offline by construction: FakeDevice behind the real ``IsapiClient``, tmp sqlite files,
tmp park dirs, injected clocks; no socket is opened and none is needed. No real host,
serial or secret appears (fixtures carry MASKED-SER-1 and TEST-NET 192.0.2.x).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from fakedevice import BASE_URL, RETIRE_ENVELOPE_ONLY, FakeDevice
from gateclerk.agent_db import connect
from gateclerk.agent_store import check_db_watermark
from gateclerk.exceptions import IsapiAuthError, IsapiBadContent
from gateclerk.isapi_transport import IsapiClient
from gateclerk.tz import DeviceTime, compute_skew
from test_p2_03_scheduler import (
    CADENCE_S,
    EVENT_PATH,
    OVERLAP_S,
    SITE,
    SITE_TZ,
    T0,
    FakeClock,
    FakeMonotonic,
    device_event,
    seed_events,
    seeded_device,
)

DEVICE_INFO_PATH = "/ISAPI/System/deviceInfo?format=json"

PASSWORD_OK = "fakepw"  # FakeDevice's default (hygiene placeholder, S107 tests policy)
PASSWORD_BAD = "fakepw-rotated"

#: §2c's slow-re-probe period, written out here as a literal on purpose: the tests
#: must not go green just because the module and the test import the same constant.
REPROBE_S = 1800

#: The transport circuit for the lockout scenario: unlockTime 1800 (the fake says so)
#: + margin 10 (isapi_transport.DEFAULT_CIRCUIT_MARGIN_SECONDS).
CIRCUIT_UNTIL_S = 1810.0


# --- the harness -------------------------------------------------------------------------


class PolicyHarness:
    """Fake device + loop (P2-03, untouched) + the P2-05 policy over a tmp park dir.

    The loop is driven exclusively through ``guarded_tick`` — the P2-05 gate P2-07's
    CLI will wrap (a parked device is never handed a tick at all). Clocks are fake;
    ``walk`` advances both clocks per cadence step exactly like P2-03's harness.
    """

    def __init__(
        self,
        tmp_path: Path,
        device: FakeDevice,
        *,
        client_password: str = PASSWORD_BAD,
    ) -> None:
        from gateclerk.agent_alert import AlertPolicy, guarded_tick
        from gateclerk.capabilities import capability_cache

        capability_cache().clear()  # process-global p1-04 cache — same clear as P2-03
        self.device = device
        self.clock = FakeClock()
        self.monotonic = FakeMonotonic()
        self.sleeps: list[float] = []
        self.conn: sqlite3.Connection = connect(tmp_path / "agent.sqlite3")
        self.client = IsapiClient(
            BASE_URL,
            "admin",
            client_password,
            transport=device.transport,
            sleep=self.sleeps.append,
            now=self.monotonic,
        )
        from gateclerk.agent_loop import DeviceLoop

        self.loop = DeviceLoop(
            client=self.client,
            conn=self.conn,
            site=SITE,
            site_tz=SITE_TZ,
            cadence_s=CADENCE_S,
            overlap_s=OVERLAP_S,
            inter_page_delay=0.0,
            now=self.clock,
            monotonic=self.monotonic,
            warn=lambda text: None,
        )
        self.park_dir = tmp_path / "park"
        self.alerts: list[Any] = []
        self.policy = AlertPolicy(
            site=SITE,
            conn=self.conn,
            cadence_s=CADENCE_S,
            now=self.clock,
            sink=self.alerts.append,
            park_dir=self.park_dir,
        )
        self._guarded_tick = guarded_tick

    # -- driving ------------------------------------------------------------------------

    def tick(self) -> Any:
        """One gated tick at the current fake time (None when the park blocks it)."""
        return self._guarded_tick(self.policy, self.loop)

    def walk(self, n: int, step_s: float = CADENCE_S) -> list[Any]:
        out = []
        for _ in range(n):
            out.append(self.tick())
            self.clock.advance(step_s)
            self.monotonic.advance(step_s)
        return out

    def tick_at(self, minutes: float) -> Any:
        """Advance BOTH clocks to T0 + minutes (exactly) and tick there.

        Explicit instants instead of step-arithmetic: the 30-min re-probe grid is
        what the test pins, so the timeline reads as minutes, not as loop counts.
        """
        target = minutes * 60.0
        delta = target - self.monotonic.t
        assert delta >= 0, "the fake clock only moves forward"
        self.clock.advance(delta)
        self.monotonic.advance(delta)
        return self.tick()

    # -- accounting ---------------------------------------------------------------------

    def served_count(self) -> int:
        return len(self.device.served)

    def creds_presented(self) -> int:
        """Requests that carried an Authorization header — the card's 'presented creds'."""
        return sum(1 for s in self.device.served if s.had_auth)

    def kinds(self) -> list[str]:
        return [a.kind for a in self.alerts]

    def levels(self) -> list[str]:
        return [a.level for a in self.alerts]


def locked_401() -> httpx.Response:
    """The DESIGN.md lockout shape: 401 + challenge + userCheck lockStatus=locked.

    Same fixture the transport suite uses (test_isapi_transport.py lockout tests):
    ``unlockTime=1800`` is machine-readable truth the circuit must wait out.
    """
    return httpx.Response(
        401,
        headers={
            "WWW-Authenticate": (
                'Digest qop="auth", realm="DS-39DED0D1", nonce="MASKED-NONCE", stale="false"'
            ),
            "Server": "webs",
        },
        content=b"<userCheck><statusValue>401</statusValue>"
        b"<lockStatus>locked</lockStatus><unlockTime>1800</unlockTime></userCheck>",
    )


# --- DoD (1): wrong-creds terminal 401 -> critical + parked + ZERO further requests ------


def test_wrong_creds_fire_critical_park_the_device_and_freeze_all_requests(
    tmp_path: Path,
) -> None:
    """The §2c first clause, end to end: one failing tick, then the loop never touches
    the device again — the served count is FROZEN until an operator acks.

    The failing tick itself costs the two digest requests (unauthenticated + httpx's
    one replay). After the park, `guarded_tick` must refuse to hand the loop a tick at
    ALL: served_count stays at exactly the failing tick's count across the cadence.
    """
    h = PolicyHarness(tmp_path, seeded_device())
    first = h.tick()

    assert first is not None and first.ok is False
    assert isinstance(first.exception, IsapiAuthError)
    assert first.exception.locked is False  # wrong creds, not a lockout
    assert h.kinds() == ["auth_terminal"]
    assert h.levels() == ["critical"]
    parked = h.policy.parked(SITE, "pending")  # serial unknown: pre-bootstrap failure
    assert parked is not None and parked.parked_at is not None
    assert parked.acked_at is None

    frozen = h.served_count()
    assert frozen >= 1
    results = h.walk(10)  # 10 cadence steps = 50 fake minutes
    assert all(r is None for r in results), "a parked device is never handed a tick"
    assert h.served_count() == frozen, "served count FROZEN — no automatic re-probe"
    assert h.kinds() == ["auth_terminal"], "the re-fire would be alert spam; park once"


def test_park_survives_a_restart_and_still_touches_nothing(tmp_path: Path) -> None:
    """The lockout-safety invariant is a DISK fact, not a memory (Restart=always).

    Scenario: parked, then the systemd unit restarts (fresh policy + fresh loop +
    fresh client — the transport circuit is in-memory and would otherwise forget).
    The unacked park read back from disk must still block every attempt.
    """
    device = seeded_device()
    h = PolicyHarness(tmp_path, device)
    h.tick()
    frozen = h.served_count()

    # "Restart": a brand-new policy over the same park dir + a brand-new loop/client.
    from gateclerk.agent_alert import AlertPolicy, guarded_tick
    from gateclerk.agent_loop import DeviceLoop

    clock2, mono2 = FakeClock(), FakeMonotonic()
    client2 = IsapiClient(BASE_URL, "admin", PASSWORD_BAD, transport=device.transport, now=mono2)
    loop2 = DeviceLoop(
        client=client2,
        conn=connect(tmp_path / "agent.sqlite3"),
        site=SITE,
        site_tz=SITE_TZ,
        cadence_s=CADENCE_S,
        overlap_s=OVERLAP_S,
        inter_page_delay=0.0,
        now=clock2,
        monotonic=mono2,
        warn=lambda text: None,
    )
    policy2 = AlertPolicy(
        site=SITE,
        conn=loop2.conn,
        cadence_s=CADENCE_S,
        now=clock2,
        sink=lambda a: None,
        park_dir=tmp_path / "park",
    )
    for _ in range(6):
        assert guarded_tick(policy2, loop2) is None
        clock2.advance(CADENCE_S)
        mono2.advance(CADENCE_S)
    assert len(device.served) == frozen, "restart must not launder a park"


# --- DoD (2): ack -> re-probe at +30 min, then every 30; success un-parks -----------------


def test_ack_opens_a_30_minute_re_probe_grid_and_a_success_un_parks(tmp_path: Path) -> None:
    """Parked+acked attempts ONLY on the 30-min grid; a good tick lifts the park.

    Timeline (injected clock): terminal 401 parks at T; ack at T; T+30 min the fake
    is still wrong -> another critical but no re-park spam; T+60 min the credentials
    were fixed (device-side password rotated back) -> success un-parks; from then on
    the ordinary cadence governs again (a tick between grid slots that used to be
    refused now runs).
    """
    device = seeded_device()
    seed_events(device, [device_event(101, "2026-10-19T10:01:00")])
    h = PolicyHarness(tmp_path, device)
    assert h.tick() is not None
    assert h.kinds() == ["auth_terminal"]
    frozen = h.served_count()

    acked = h.policy.ack(SITE)
    assert acked == 1

    # Off-grid minutes before the first re-probe stays due: still fully blocked.
    for minute in (5, 10, 15, 20, 25):
        assert h.tick_at(minute) is None
        assert h.served_count() == frozen

    # +30 min from the ack: the grid opens exactly one attempt, and it fails again.
    assert h.tick_at(30) is not None
    assert h.served_count() > frozen, "acked: the slow re-probe must actually try"
    assert h.kinds().count("auth_terminal") == 1, "a failed re-probe does not re-page"
    assert h.policy.parked(SITE, "pending") is not None
    frozen2 = h.served_count()

    # Off-grid again: the failed attempt re-armed the grid from NOW (+30 min), so
    # the minutes between stay closed.
    for minute in (35, 40, 45, 50, 55):
        assert h.tick_at(minute) is None
        assert h.served_count() == frozen2

    # Credentials fixed: the agent's client is long-lived (spec §2a), so the
    # self-heal shape is the DEVICE-side secret being provisioned back to what the
    # agent holds. The +60 min grid slot succeeds and un-parks.
    device.password = PASSWORD_BAD
    assert h.tick_at(60) is not None
    assert h.policy.parked(SITE, "pending") is None
    serial = h.loop.device_serial
    assert serial is not None and h.policy.parked(SITE, serial) is None

    # Un-parked: the very next CADENCE minute (not a 30-min slot) runs immediately.
    before = h.served_count()
    assert h.tick_at(65) is not None
    assert h.served_count() > before
    assert h.kinds().count("auth_terminal") == 1


def test_ack_on_a_never_parked_device_is_a_no_op(tmp_path: Path) -> None:
    h = PolicyHarness(tmp_path, seeded_device())
    assert h.policy.ack(SITE) == 0, "nothing parked -> nothing acked (typo-safe)"


# --- DoD (3): unacked forever = ZERO probes across days -----------------------------------


def test_unacked_park_never_probes_again_across_days(tmp_path: Path) -> None:
    """The card's hardest pin: no ack -> no attempts at all, not even after days.

    3 days at the 5-min cadence = 864 gated ticks; every one must return None and the
    fake's served count must be the frozen failing-tick count. If the gate ever let a
    single tick through, the served count moves and this test dies — which is the
    lockout the whole policy exists to prevent.
    """
    h = PolicyHarness(tmp_path, seeded_device())
    h.tick()
    frozen = h.served_count()
    creds = h.creds_presented()

    for _ in range(3 * 288):  # 3 days at cadence 300 s
        assert h.tick() is None
        h.clock.advance(CADENCE_S)
        h.monotonic.advance(CADENCE_S)

    assert h.served_count() == frozen
    assert h.creds_presented() == creds, "not one more credential presented"
    assert h.policy.parked(SITE, "pending") is not None
    # and the alert was exactly ONE critical (no daily nag)
    assert h.kinds() == ["auth_terminal"]


# --- DoD (4): lockStatus=lock -> critical on-site + circuit honors unlockTime -------------


def test_lockout_body_fires_critical_on_site_and_creds_wait_out_unlock_time(
    tmp_path: Path,
) -> None:
    """§2c second clause: the DEVICE said locked -> critical + on-site, and the agent
    presents NOTHING (not even an unauthenticated knock) until the circuit's unlock
    window passed — pinned on the served timeline, the card's own accounting.

    The account lock here is the door-terminal kind (someone typed the wrong password
    at the door); our credentials are fine, so the loop resumes once the device's own
    `unlockTime` has passed — no park, no ack (the circuit is the wait, per spec).
    """
    device = seeded_device()
    # The lockout answers the first TWO requests regardless of Authorization (raw
    # queue, as the transport suite does it — the challenge plus httpx's one
    # replay); after that the box is normal again.
    device.add_raw("GET", DEVICE_INFO_PATH, locked_401(), locked_401())
    seed_events(device, [device_event(7, "2026-10-19T10:02:00")])
    h = PolicyHarness(tmp_path, device, client_password=PASSWORD_OK)

    first = h.tick()
    assert first is not None and first.ok is False
    exc = first.exception
    assert isinstance(exc, IsapiAuthError) and exc.locked is True and exc.unlock_time == 1800
    assert h.kinds() == ["device_locked"]
    assert h.levels() == ["critical"]
    # No park: the circuit IS the wait for a lockout (spec: "circuit already waits
    # out unlockTime"); acking a lockout would be meaningless.
    assert h.policy.parked(SITE, "pending") is None

    served_after_fail = h.served_count()
    creds_after_fail = h.creds_presented()
    assert creds_after_fail == 1, "only httpx's single in-flight replay ever carried creds"

    # Inside the unlock window (circuit until unlockTime 1800 + margin 10 = t=1810):
    # every gated tick is a zero-request circuit-open skip. No request at ALL leaves
    # the process — the served timeline is FROZEN (the card's "pin served timeline").
    for _ in range(6):  # steps land at t=300..1800, all < 1810
        h.clock.advance(CADENCE_S)
        h.monotonic.advance(CADENCE_S)
        skipped = h.tick()
        assert skipped is not None and skipped.skipped is True, (
            "not parked -> the loop still ticks, and the CIRCUIT makes it a skip"
        )
    assert h.monotonic.t == 1800.0 < CIRCUIT_UNTIL_S
    assert h.served_count() == served_after_fail, "ZERO requests while the circuit is open"
    assert h.creds_presented() == creds_after_fail

    # Past unlockTime+margin (circuit until t=1810): the next tick (t=2100) touches
    # the box again — and THIS is the first credential the fake ever accepts.
    h.clock.advance(CADENCE_S)
    h.monotonic.advance(CADENCE_S)
    resumed = h.tick()
    assert resumed is not None and resumed.ok is True
    assert h.served_count() > served_after_fail
    assert h.creds_presented() > creds_after_fail, (
        "creds are presented ONLY after the unlock window (frozen until now)"
    )
    assert h.kinds().count("device_locked") == 1


def test_circuit_open_skip_alerts_nothing_extra(tmp_path: Path) -> None:
    """A circuit-open skip is the transport already enforcing a prior page — silence."""
    device = seeded_device()
    device.add_raw("GET", DEVICE_INFO_PATH, locked_401(), locked_401())
    h = PolicyHarness(tmp_path, device, client_password=PASSWORD_OK)
    h.tick()  # fires the single device_locked page
    h.alerts.clear()
    skipped = h.tick()
    assert skipped is not None and skipped.skipped is True
    assert h.alerts == [], "the skip is enforcement, not a new incident"


# --- DoD (5): nonce recoveries = info counter ONLY ----------------------------------------


def test_nonce_recoveries_land_in_the_info_counter_and_never_alert(tmp_path: Path) -> None:
    """§2c third clause: retirement recovery is ROUTINE at cadence (spec §2a math).

    The fake retires the nonce every 1 authorized request in the envelope-only shape
    (the one the transport's own recovery arm answers), so a healthy walk spends
    recoveries while still succeeding. The policy's counter must move; the alert sink
    must NOT be callable-not-once.
    """
    device = seeded_device()
    device.retire_after = 1
    device.retire_shape = RETIRE_ENVELOPE_ONLY
    seed_events(device, [device_event(500, "2026-10-19T10:03:00")])
    h = PolicyHarness(tmp_path, device, client_password=PASSWORD_OK)

    result = h.tick()
    assert result is not None and result.ok is True
    assert h.client.auth_recoveries >= 1, "the walk genuinely spent recoveries"

    h.policy.observe_recoveries(h.client.auth_recoveries)
    assert h.policy.counters["auth_recoveries"] == h.client.auth_recoveries
    assert h.alerts == [], "a recovery is a metric line, not an alert"
    # a repeat observation of the same total does not double-count
    h.policy.observe_recoveries(h.client.auth_recoveries)
    assert h.policy.counters["auth_recoveries"] == h.client.auth_recoveries


# --- DoD (6): skew over threshold -> warning; under -> silence -----------------------------


def _skew(seconds: float) -> Any:
    """A real `tz.compute_skew` result: device wall is our site wall ± `seconds`."""
    from zoneinfo import ZoneInfo

    our_now = T0
    device_wall = (our_now.astimezone(ZoneInfo(SITE_TZ)) + timedelta(seconds=seconds)).replace(
        tzinfo=None
    )
    return compute_skew(
        DeviceTime(
            local_time_raw=device_wall.isoformat(),
            naive_local=device_wall,
            claimed_offset_minutes=120,
        ),
        our_now=our_now,
        site_tz=SITE_TZ,
    )


def test_skew_over_threshold_warns_under_is_silent(tmp_path: Path) -> None:
    h = PolicyHarness(tmp_path, seeded_device())

    over = _skew(3600.0)  # 1 h: far past the 120 s SKEW_WARN_SECONDS carry-over
    assert over.warn is True
    fired = h.policy.observe_skew(over)
    assert [a.kind for a in fired] == ["clock_skew"]
    assert [a.level for a in fired] == ["warning"]
    # Still over, observed again: the episode is open -> silence (no nag).
    assert h.policy.observe_skew(over) == []

    under = _skew(60.0)
    assert under.warn is False
    assert h.policy.observe_skew(under) == [], "under threshold is silence"
    # A healed drift that starts over again IS a new incident -> fresh warning.
    assert [a.kind for a in h.policy.observe_skew(over)] == ["clock_skew"]
    assert [a.kind for a in h.alerts].count("clock_skew") == 2


# --- DoD (7): stall = EVIDENCE OF LOSS (failing poll / serial floor), never silence ---


def test_checkpoint_stall_is_quiet_on_a_quiet_device(tmp_path: Path) -> None:
    """STALL-ALERT-FALSE: a checkpoint only moves on major=5 punches, so a quiet
    door (night/lunch) looks frozen while every poll SUCCEEDS and returns nothing
    newer. That is silence, not a stall — no alert however old the checkpoint gets.
    """
    device = seeded_device()
    seed_events(device, [device_event(60, "2026-10-19T09:58:00")])
    h = PolicyHarness(tmp_path, device, client_password=PASSWORD_OK)

    first = h.tick()
    assert first is not None and first.ok is True
    serial = first.device_serial
    assert serial is not None
    assert h.policy.check_stall(serial) is None, "a fresh checkpoint is quiet"

    # Four quiet cadences: every poll succeeds, every poll is a FREE overlap re-read
    # (advanced=False). The checkpoint is now older than k=3 cadences.
    for _ in range(4):
        h.clock.advance(CADENCE_S)
        h.monotonic.advance(CADENCE_S)
        quiet = h.tick()
        assert quiet is not None and quiet.ok is True and quiet.advanced is False
        assert h.policy.check_stall(serial) is None, "a successful quiet poll is not a stall"

    assert h.alerts == []
    assert h.policy.counters["checkpoint_stall"] == 0


def test_checkpoint_stall_pages_once_after_k_failed_polls(tmp_path: Path) -> None:
    """A stale checkpoint needs STALL_STRIKES consecutive non-auth failed polls.

    One failed poll below the threshold does not page; the third consecutive failure
    fires exactly one CRITICAL. Skipped ticks and auth failures neither count nor
    reset the streak (they have their own channels and prove nothing about the walk).
    """
    device = seeded_device()
    seed_events(device, [device_event(60, "2026-10-19T09:58:00")])
    h = PolicyHarness(tmp_path, device, client_password=PASSWORD_OK)
    first = h.tick()
    serial = first.device_serial
    assert serial is not None
    assert h.policy.check_stall(serial) is None

    # Break the event walk AFTER bootstrap, so the tick still knows its serial.
    device.reset_raw("POST", EVENT_PATH, _bad_content())
    h.clock.advance(3 * CADENCE_S)  # age is now exactly k*cadence: not OVER yet
    h.monotonic.advance(3 * CADENCE_S)
    failed = h.tick()
    assert failed is not None and failed.ok is False and failed.device_serial == serial
    assert isinstance(failed.exception, IsapiBadContent)
    assert h.policy.check_stall(serial) is None, "one failure below k does not page"

    # A circuit-open skip and an auth failure are neither counted nor resetting.
    h.policy.handle_tick(
        SimpleNamespace(ok=False, skipped=True, device_serial=serial, exception=None)
    )
    h.policy.handle_tick(
        SimpleNamespace(
            ok=False,
            skipped=False,
            device_serial=serial,
            exception=IsapiAuthError("locked", lock_status="locked"),
        )
    )
    assert h.policy._failed_streak[serial] == 1, "skip/auth leave the streak untouched"

    h.clock.advance(1)
    h.monotonic.advance(1)
    failed = h.tick()
    assert failed is not None and failed.ok is False
    assert h.policy.check_stall(serial) is None, "two failures are still below k"

    h.clock.advance(1)
    h.monotonic.advance(1)
    failed = h.tick()
    assert failed is not None and failed.ok is False
    fired = h.policy.check_stall(serial)
    assert fired is not None and fired.kind == "checkpoint_stall"
    assert fired.level == "critical"
    assert h.kinds().count("checkpoint_stall") == 1, "exactly one page for this episode"
    assert "3 consecutive polls FAILED" in fired.note
    assert h.policy.check_stall(serial) is None, "one page per stall episode, not per check"

    # Heal the walk and move the checkpoint: the episode closes, so a later stall can
    # page fresh instead of being swallowed by the old key.
    device.raw.pop(f"POST {EVENT_PATH}", None)
    device.add_events(device_event(61, "2026-10-19T10:15:00"))
    healed = h.tick()
    assert healed is not None and healed.ok is True and healed.advanced is True
    assert h.policy.check_stall(serial) is None


def test_checkpoint_stall_ok_poll_resets_the_failure_streak(tmp_path: Path) -> None:
    """Any ok poll between failures resets the streak, so two isolated errors on a
    quiet night do not accumulate into a CRITICAL page.
    """
    device = seeded_device()
    seed_events(device, [device_event(60, "2026-10-19T09:58:00")])
    h = PolicyHarness(tmp_path, device, client_password=PASSWORD_OK)
    first = h.tick()
    serial = first.device_serial
    assert serial is not None

    # Four quiet ok polls: checkpoint is now older than k cadence on success alone.
    for _ in range(4):
        h.clock.advance(CADENCE_S)
        h.monotonic.advance(CADENCE_S)
        quiet = h.tick()
        assert quiet is not None and quiet.ok is True and quiet.advanced is False

    device.reset_raw("POST", EVENT_PATH, _bad_content())
    for _ in range(2):
        h.clock.advance(CADENCE_S)
        h.monotonic.advance(CADENCE_S)
        failed = h.tick()
        assert failed is not None and failed.ok is False
    assert h.policy.check_stall(serial) is None, "two failures below k do not page"

    # An ok poll in between (still no new events) resets the streak to zero.
    device.raw.pop(f"POST {EVENT_PATH}", None)
    h.clock.advance(CADENCE_S)
    h.monotonic.advance(CADENCE_S)
    quiet = h.tick()
    assert quiet is not None and quiet.ok is True and quiet.advanced is False
    assert h.policy._failed_streak[serial] == 0

    device.reset_raw("POST", EVENT_PATH, _bad_content())
    for _ in range(2):
        h.clock.advance(CADENCE_S)
        h.monotonic.advance(CADENCE_S)
        failed = h.tick()
        assert failed is not None and failed.ok is False
    assert h.policy.check_stall(serial) is None, "the reset forced a fresh k-streak"

    h.clock.advance(CADENCE_S)
    h.monotonic.advance(CADENCE_S)
    failed = h.tick()
    assert failed is not None and failed.ok is False
    fired = h.policy.check_stall(serial)
    assert fired is not None and fired.kind == "checkpoint_stall"
    assert h.kinds().count("checkpoint_stall") == 1


def test_checkpoint_stall_fires_when_stored_history_disappears(tmp_path: Path) -> None:
    """Serial-floor arm: our keep-everything store's MIN(serial_no) rising means
    stored history disappeared. This is NOT ring-rollover detection — real
    ring-rollover detection does not exist yet (card t_ed9c7e92); DESIGN.md:411
    records the intended device-side probe: "the agent must record oldest-serialNo
    per poll (a monotonic increase of the minimum = rolling started = punches are
    being lost)".
    """
    device = seeded_device()
    seed_events(
        device,
        [
            device_event(60, "2026-10-19T09:58:00"),
            device_event(61, "2026-10-19T09:59:00"),
            device_event(62, "2026-10-19T10:00:00"),
        ],
    )
    h = PolicyHarness(tmp_path, device, client_password=PASSWORD_OK)
    first = h.tick()
    serial = first.device_serial
    assert serial is not None
    assert h.policy.check_stall(serial) is None, "first check records the floor baseline"

    # The store floor moves from 60 to 61 while the checkpoint stays fresh: rows the
    # agent had kept are gone. This arm reports that fact, not device ring loss.
    h.conn.execute("DELETE FROM events WHERE device_serial = ? AND serial_no < ?", (serial, 61))
    fired = h.policy.check_stall(serial)
    assert fired is not None and fired.kind == "checkpoint_stall"
    assert fired.level == "critical"
    assert "oldest stored serialNo rose 60 -> 61" in fired.note
    assert "stored history disappeared" in fired.note
    assert "not ring-rollover detection" in fired.note
    assert h.policy.check_stall(serial) is None, "a flat floor does not nag"

    # A second rise is a NEW stored-history incident (fresh page).
    h.conn.execute("DELETE FROM events WHERE device_serial = ? AND serial_no < ?", (serial, 62))
    again = h.policy.check_stall(serial)
    assert again is not None and "61 -> 62" in again.note
    assert h.kinds().count("checkpoint_stall") == 2


def test_stall_is_quiet_for_a_device_that_never_advanced(tmp_path: Path) -> None:
    """No checkpoint row = a fresh install, not a stalled one (nothing to be stale)."""
    h = PolicyHarness(tmp_path, seeded_device())
    assert h.policy.check_stall("NEVER-SEEN-SERIAL") is None


# --- the two side channels the seams already expose: watermark + non-auth silence ----------


def test_db_watermark_over_fires_a_warning(tmp_path: Path) -> None:
    h = PolicyHarness(tmp_path, seeded_device())
    under = check_db_watermark(tmp_path / "agent.sqlite3", warn_bytes=10**12)
    assert h.policy.observe_watermark(under) == []
    over = check_db_watermark(tmp_path / "agent.sqlite3", warn_bytes=10)
    fired = h.policy.observe_watermark(over)
    assert [a.kind for a in fired] == ["db_watermark"] and fired[0].level == "warning"
    assert h.policy.observe_watermark(over) == [], "one page per watermark episode"
    assert h.policy.observe_watermark(under) == []
    assert h.policy.observe_watermark(over), "back under closes the episode: re-over re-fires"


def test_non_auth_tick_failure_alerts_nothing(tmp_path: Path) -> None:
    """§2c keeps the channels separate: a broken page heals via the overlap (P2-03) —
    a metric, not a page. Only the auth/stall/skew classes alert."""
    device = seeded_device()

    device.reset_raw("GET", DEVICE_INFO_PATH, *([_bad_content()] * 12))
    h = PolicyHarness(tmp_path, device, client_password=PASSWORD_OK)
    result = h.tick()
    assert result is not None and result.ok is False
    assert isinstance(result.exception, IsapiBadContent)
    assert h.alerts == []
    assert h.policy.counters["tick_failures"] == 1


def _bad_content() -> httpx.Response:
    return httpx.Response(
        400,
        content=b'{"statusCode":6,"statusString":"Bad Content","subStatusCode":"badContent"}',
        headers={"Content-Type": "application/json"},
    )


# --- sink discipline: never leak host / Authorization / payload ----------------------------


def test_alert_lines_never_carry_host_authorization_or_payload(tmp_path: Path, capsys) -> None:
    """The card's log rule: the sink may see the SITE LABEL, the serial, the kind and
    a human phrase — never Authorization, never a host (even TEST-NET), never a
    payload body. The transport's own exception strings DO embed base_url on transport
    failures, so this scan is a real pin, not a tautology."""
    h = PolicyHarness(tmp_path, seeded_device())
    h.tick()  # wrong creds: the exception message could have carried wire detail
    h.policy.observe_skew(_skew(3600.0))
    assert h.alerts, "the scenarios above fired alerts to scan"

    # The sink default is a stderr line — prove THAT line passes the same scan.
    from gateclerk.agent_alert import AlertPolicy, default_sink

    stderr_policy = AlertPolicy(site=SITE, cadence_s=CADENCE_S, now=FakeClock())
    assert stderr_policy.sink is default_sink
    stderr_policy.observe_skew(_skew(7200.0))
    err = capsys.readouterr().err

    corpus = "\n".join([json.dumps(a.as_dict(), sort_keys=True) for a in h.alerts] + [err])
    # Positive control: without an alert ACTUALLY in the corpus, every "not in"
    # below would pass on an empty scan (the tautological-filter lesson).
    assert "terminal 401" in corpus and "clock skew" in corpus
    # The `http_status` / `on device_info` / `statusCode` trio is what transport 401
    # detail strings carry ("unauthorized on device_info http_status=401
    # lockStatus=...") — a note authored from str(exc) would leak the endpoint and
    # the envelope fields even where no host appears. The scan is built to catch
    # that mutation, not only the host leak.
    for needle in (
        "192.0.2",
        "Authorization",
        "Digest",
        "fakepw",
        BASE_URL,
        "password",
        "http_status",
        "on device_info",
        "statusCode",
    ):
        assert needle not in corpus, f"alert surface leaked {needle!r}"
    assert "site-a" in corpus, "the site label is the ONE identity the surface carries"


def test_alert_shape_is_structured(tmp_path: Path) -> None:
    h = PolicyHarness(tmp_path, seeded_device())
    h.tick()
    a = h.alerts[0]
    assert a.level == "critical" and a.kind == "auth_terminal" and a.site == SITE
    assert a.device_serial is None  # failed pre-bootstrap: no serial to name
    parsed = datetime.fromisoformat(a.at)
    assert parsed == T0, "the alert stamp is the injected clock, verbatim"


# --- guards: the policy refuses to act on state that is not its own -----------------------


def test_in_memory_policy_parks_and_acks_without_a_dir(tmp_path: Path) -> None:
    """The dict-sink / no-park_dir shape the card allows for tests must behave the
    same as the on-disk one for the pure logic (it just cannot survive restart)."""
    from gateclerk.agent_alert import AlertPolicy

    events: list[Any] = []
    policy = AlertPolicy(site=SITE, cadence_s=CADENCE_S, now=FakeClock(), sink=events.append)
    assert policy.park_dir is None
    policy._park("pending", serial_for_record=None)  # same path handle_tick takes
    state = policy.parked(SITE)
    assert state is not None and state.acked_at is None
    allowed, reason = policy.attempt_allowed(None)
    assert not allowed and "unacked" in reason
    assert policy.ack(SITE) == 1
    reopened = policy.parked(SITE)
    assert reopened is not None and reopened.acked_at is not None
    assert policy.ack(SITE) == 0, "re-ack of an open park counts nothing"
    assert policy.ack(SITE, "no-such-serial") == 0, "serial filter: other parks are left alone"


def test_foreign_site_park_file_is_refused_not_acted_on(tmp_path: Path) -> None:
    """One park dir cannot silently cross-wire two units (spec §2d: unit-per-site):
    a park record naming a different site raises instead of being acked or read."""
    import json as _json

    from gateclerk.agent_alert import AlertPolicy

    (tmp_path / "park").mkdir()
    stranger = tmp_path / "park" / f"park-{SITE}__OTHER.json"
    stranger.write_text(
        _json.dumps(
            {
                "version": 1,
                "site": "site-B",  # foreign: this policy's site is site-a
                "device_serial": "OTHER",
                "parked_at": T0.isoformat(),
                "acked_at": None,
                "next_attempt_at": None,
            }
        ),
        encoding="utf-8",
    )
    policy = AlertPolicy(
        site=SITE,
        cadence_s=CADENCE_S,
        now=FakeClock(),
        sink=lambda a: None,
        park_dir=tmp_path / "park",
    )
    with pytest.raises(ValueError, match="foreign site"):
        policy.ack(SITE)
    # A direct read of a key whose file is foreign must raise the same way, not act.
    with pytest.raises(ValueError, match="not site"):
        policy.parked(SITE, "OTHER")
    # (the file names itself park-site-a__OTHER so this policy's prefix glob sees it)


def test_wrong_site_cannot_read_or_clear_a_park(tmp_path: Path) -> None:
    h = PolicyHarness(tmp_path, seeded_device())
    h.tick()
    assert h.policy.parked("typo-site", "pending") is None
    assert h.policy.ack("typo-site") == 0
    assert h.policy.parked(SITE, "pending") is not None, "the real park is untouched"


def test_policy_refuses_cadence_zero(tmp_path: Path) -> None:
    from gateclerk.agent_alert import AlertPolicy

    with pytest.raises(ValueError, match="cadence_s"):
        AlertPolicy(site=SITE, cadence_s=0, now=FakeClock(), sink=lambda a: None)


def test_stall_check_is_none_without_a_connection() -> None:
    from gateclerk.agent_alert import AlertPolicy

    policy = AlertPolicy(site=SITE, cadence_s=CADENCE_S, now=FakeClock(), sink=lambda a: None)
    assert policy.check_stall("ANY") is None, "no conn = no store to consult, not an alert"


def test_confirmed_serial_reset_pages_once_and_names_both_serials(tmp_path: Path) -> None:
    """The loop's confirmed reset is one critical page, not a per-tick nag."""
    from gateclerk.agent_alert import AlertPolicy
    from gateclerk.agent_loop import SerialReset, TickResult

    events: list[Any] = []
    policy = AlertPolicy(
        site=SITE,
        cadence_s=CADENCE_S,
        now=FakeClock(),
        sink=events.append,
        park_dir=tmp_path / "park",
    )
    reset = SerialReset(
        old_serial=5742,
        new_serial=3,
        old_firmware="V3.2.30",
        new_firmware="V4.13.0",
    )
    first = policy.handle_tick(
        TickResult(device_serial="MASKED-SER-1", ok=True, serial_reset=reset)
    )
    assert len(first) == 1
    alert = first[0]
    assert alert.level == "critical" and alert.kind == "serial_reset"
    assert "5742" in alert.note and " 3 " in alert.note
    assert "V3.2.30" in alert.note and "V4.13.0" in alert.note
    assert len(events) == 1 and policy.counters["serial_reset"] == 1

    # The same episode re-confirmed (e.g. a kill before the checkpoint rewind) is silent.
    again = policy.handle_tick(
        TickResult(device_serial="MASKED-SER-1", ok=True, serial_reset=reset)
    )
    assert again == [] and len(events) == 1
