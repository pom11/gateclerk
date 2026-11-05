"""The P2 site agent's health surface: state collector + text/JSON builder (no server).

Card P2-06 (docs/P2-SITE-AGENT.md §2e, DECIDED 2026-10-19: carry over ALL listed P1
observables; minimal vocabulary; no dashboard). The spec's `/healthz` line — ok/degraded
+ agent version + per-device `last_poll_ok_age_s` + circuit state + dead-letter depth,
NO secrets and no hosts beyond the site label — is exactly what `healthz_text` renders.
Serving it (systemd + socat, or a thin stdlib wrapper) is P2-07's; this module never
binds a socket, and its tests never open one.

**State: the db is the state, the process owns the counters.** Every gauge below has a
home that already exists — no new schema, no sidecar file, no invented concept:

* per-tick facts come from P2-03's `TickResult` (pages, stored, window label,
  termination) — the collector records the numbers the loop already reported, it
  does not re-walk anything;
* auth counters come from the exception a failed tick CARRIES (`TickResult.exception`
  is a typed `IsapiAuthError` — the transport's own terminal 401 verdict, `locked`
  included) and from `IsapiClient.auth_recoveries` / `circuit_open()` read live;
* store facts (mismatched-record count, oldest serial, events/day) are plain reads
  over P2-02's tables (`events`, `checkpoint`); `db_size_bytes` is P2-02's own helper;
* push facts: `dead_letter_depth` is P2-04's own `dead_letter_depth(conn)`; the
  cumulative push_ok/push_failed come from parsing `drain`'s OWN log line — wire
  `drain(..., log=collector.observe_push_log)` and the counters follow the drain
  verbatim, with no second bookkeeping of queue rows anywhere.

What genuinely lives only in the running process (the transport's circuit, the once-
per-run warning policy, "when did this process last see a successful poll") is held by
`AgentHealthCollector`, the object the agent process constructs once. The collector is
also the agent-side **state collector** the card names: it is the seam through which
the `tz_offset_mismatch` once-per-run warning (delegated to `cli._warn_tz_mismatch`,
reused not forked, p1-12's mapping policy included), the clock-skew warning (spec §2c:
a WARNING, never a degraded trigger) and the drain counters are observed. `collect()`
issues zero device requests and zero db writes (both pinned by test) — a health poll
that perturbs the loop it reports on is how /healthz checks become incidents. The
mismatch warning runs its policy ONCE per device per process (p1-06c once-per-run
semantics; the metric then carries 0/1, never a per-poll spam count).

For a separate reader process (P2-07's socat shape), the snapshot round-trips through
JSON (`snapshot_to_json` / `snapshot_from_dict`) — that is the "small json sidecar"
option of the card, implemented as a format, not a second source of truth.

**Vocabulary is the contract** (§2e, pinned by test to the card's list — 18 names,
snake_case, exact): `auth_recoveries`, `auth_terminal_failures`, `device_locked_events`,
`circuit_open_gauge`, `tz_offset_mismatch_records` + `tz_offset_mismatch_warnings`
(the per-record flag, pipeline.py:463, and the p1-06c once-per-run warning),
`site_labeled_windows` (the p1-05c risky fallback — should be ~0; it is the §5 rollout
gate's evidence), `device_clock_skew_seconds`, `pages_fetched`, `records_stored`,
`search_termination`, `checkpoint_serial`, `oldest_serial`, `events_per_day`,
`push_ok`, `push_failed`, `dead_letter_depth`, `db_size_bytes`. Four are site-level
(`SNAPSHOT_ONLY_NAMES` — one db, one pusher per agent process); fourteen are per
device. Every metric line carries value AND source (`name value  # where it is
computed`) so `/metrics` doubles as the documentation of its own vocabulary.

**degraded = any device circuit open, or a checkpoint older than the caller's stall
threshold** (spec §2c's health field). The threshold reports age only; P2-05 pages
only on evidence of loss (consecutive failed polls, or stored history disappearing),
never on a quiet door's silence. Nothing else flips it: recoveries are info (§2a),
skew is a warning (§2c); and this module raises no alert, sends no page and opens no
socket — routing is P2-05's.
"""

from __future__ import annotations

import io
import json
import sqlite3
import time
from collections.abc import Callable, Mapping
from contextlib import redirect_stderr
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from gateclerk import __version__
from gateclerk.agent_push import dead_letter_depth
from gateclerk.agent_store import db_size_bytes
from gateclerk.exceptions import IsapiAuthError
from gateclerk.model import EventRecord
from gateclerk.tz import Skew

__all__ = [
    "DEVICE_METRIC_NAMES",
    "FALLBACK_MARKER",
    "METRIC_NAMES",
    "MISMATCH_MARKER",
    "SITE_LABELLED",
    "SNAPSHOT_ONLY_NAMES",
    "AgentHealthCollector",
    "DeviceHealth",
    "DeviceStats",
    "HealthSnapshot",
    "MetricLine",
    "device_health",
    "healthz_text",
    "metrics_text",
    "snapshot_from_dict",
    "snapshot_to_json",
]

#: The p1-05c fallback label, verbatim from `DeviceLoop._label` / pipeline's walk line
#: (ONE shared string, so the loop's output and this counter can never disagree).
SITE_LABELLED = "site (fallback)"

#: Substrings identifying each warning family on the shared warn stream — same
#: discriminator style as tests/test_p1_12_device_tz.py (a payload substring, never the
#: `warning:` prefix, because the two families legitimately share one stderr line).
MISMATCH_MARKER = "tz_offset_mismatch=true"
FALLBACK_MARKER = "device arithmetic may shift boundaries"

#: The store/push gauges that belong to the process (one db, one pusher), not to a
#: device. The other fourteen names render per device.
SNAPSHOT_ONLY_NAMES: tuple[str, ...] = (
    "db_size_bytes",
    "dead_letter_depth",
    "push_failed",
    "push_ok",
)

#: The card's §2e vocabulary, exact snake_case, sorted — the set-equality test is the
#: contract pin (docs/P2-SITE-AGENT.md §2e). One line each, value + source, below.
METRIC_NAMES: tuple[str, ...] = (
    "auth_recoveries",
    "auth_terminal_failures",
    "circuit_open_gauge",
    "checkpoint_serial",
    "db_size_bytes",
    "dead_letter_depth",
    "device_clock_skew_seconds",
    "device_locked_events",
    "events_per_day",
    "oldest_serial",
    "pages_fetched",
    "push_failed",
    "push_ok",
    "records_stored",
    "search_termination",
    "site_labeled_windows",
    "tz_offset_mismatch_records",
    "tz_offset_mismatch_warnings",
)

DEVICE_METRIC_NAMES: tuple[str, ...] = tuple(
    n for n in METRIC_NAMES if n not in SNAPSHOT_ONLY_NAMES
)


# --- the emitted shapes -----------------------------------------------------------------


def _parse_jsonl(line: str) -> EventRecord | None:
    """One stored contract line -> `EventRecord`, or None if it will not parse.

    A corrupt row is data, not a health crash: the health surface must keep serving
    even when one row is junk (the same posture p1-06b took for unknown payload keys).
    """
    try:
        return EventRecord.from_dict(json.loads(line))
    except Exception:  # the row shape is the store's; a bad one skips, never kills
        return None


@dataclass(frozen=True, slots=True)
class MetricLine:
    """One metric: name, value, and WHERE it is computed (the card's "value + source").

    Values are plain JSON scalars only — a snapshot must survive the JSON round trip
    unchanged (the separate-reader shape P2-07's socat needs).
    """

    name: str
    value: int | float | str | None
    source: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "value": self.value, "source": self.source}

    @staticmethod
    def from_dict(payload: Mapping[str, Any]) -> MetricLine:
        return MetricLine(
            name=str(payload["name"]),
            value=payload["value"],
            source=str(payload["source"]),
        )

    def render(self) -> str:
        value = "null" if self.value is None else str(self.value)
        return f"{self.name} {value}  # {self.source}"


@dataclass(frozen=True, slots=True)
class DeviceHealth:
    """One device's block: the spec's healthz facts + the fourteen device metrics."""

    device_serial: str
    circuit_open: bool
    circuit_parked_s: float
    checkpoint_serial: int | None
    checkpoint_age_s: float | None
    last_poll_ok_age_s: float | None
    metrics: tuple[MetricLine, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_serial": self.device_serial,
            "circuit_open": self.circuit_open,
            "circuit_parked_s": self.circuit_parked_s,
            "checkpoint_serial": self.checkpoint_serial,
            "checkpoint_age_s": self.checkpoint_age_s,
            "last_poll_ok_age_s": self.last_poll_ok_age_s,
            "metrics": [m.to_dict() for m in self.metrics],
        }

    @staticmethod
    def from_dict(payload: Mapping[str, Any]) -> DeviceHealth:
        return DeviceHealth(
            device_serial=str(payload["device_serial"]),
            circuit_open=bool(payload["circuit_open"]),
            circuit_parked_s=float(payload["circuit_parked_s"]),
            checkpoint_serial=payload["checkpoint_serial"],
            checkpoint_age_s=payload["checkpoint_age_s"],
            last_poll_ok_age_s=payload["last_poll_ok_age_s"],
            metrics=tuple(MetricLine.from_dict(m) for m in payload["metrics"]),
        )


@dataclass(frozen=True, slots=True)
class HealthSnapshot:
    """Everything the health surface says at one instant (JSON round-trips; == holds)."""

    site: str
    agent_version: str
    status: str  # "ok" | "degraded"
    reasons: tuple[str, ...]
    #: Threshold the health surface reports. The paging semantics live in
    #: AlertPolicy.check_stall: "stall" now means EVIDENCE OF LOSS (a streak of
    #: failed polls, or stored history disappearing), never the mere silence of a
    #: quiet door. A rising oldest serial is our own store's floor, not the device's
    #: ring; real ring-rollover detection is card t_ed9c7e92.
    checkpoint_stall_s: float
    devices: tuple[DeviceHealth, ...]
    site_metrics: tuple[MetricLine, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "site": self.site,
            "agent_version": self.agent_version,
            "status": self.status,
            "reasons": list(self.reasons),
            "checkpoint_stall_s": self.checkpoint_stall_s,
            "devices": [d.to_dict() for d in self.devices],
            "site_metrics": [m.to_dict() for m in self.site_metrics],
        }

    @staticmethod
    def from_dict(payload: Mapping[str, Any]) -> HealthSnapshot:
        return HealthSnapshot(
            site=str(payload["site"]),
            agent_version=str(payload["agent_version"]),
            status=str(payload["status"]),
            reasons=tuple(str(r) for r in payload["reasons"]),
            checkpoint_stall_s=float(payload["checkpoint_stall_s"]),
            devices=tuple(DeviceHealth.from_dict(d) for d in payload["devices"]),
            site_metrics=tuple(MetricLine.from_dict(m) for m in payload["site_metrics"]),
        )


# --- per-device process state (the collector owns it; the db owns the rest) --------------


@dataclass(slots=True)
class DeviceStats:
    """What the PROCESS remembers. Nothing here is re-derivable from the db alone:
    the circuit, the poll heartbeat and the drain counters are runtime facts. The
    collector also keeps one instance of this for SITE-level push counters (one
    pusher per agent process, spec §2d) — `push_ok`/`push_failed` live there.

    `mismatch_warnings` is None until the p1-06c policy has run once for this device
    in this process, then sticks at 0/1 (once-per-RUN semantics: the agent's run is
    its life, so the warning line — and its count — happen once, never per poll).
    """

    pages_fetched: int = 0
    records_stored: int = 0
    site_labeled_windows: int = 0
    auth_terminal_failures: int = 0
    device_locked_events: int = 0
    push_ok: int = 0
    push_failed: int = 0
    skew_seconds: float | None = None
    skew_warned: bool = False
    mismatch_warnings: int | None = None
    last_poll_ok_monotonic: float | None = None
    park_observed_monotonic: float | None = None
    last_termination: str | None = None


# --- the collector ------------------------------------------------------------------------


def _stderr_warn(text: str) -> None:
    """Default warn sink — same precedent as agent_loop._default_warn (rich stderr)."""
    from gateclerk.output import make_console  # local: keeps the module import cheap

    make_console(stderr=True).print(text, markup=False)


class AgentHealthCollector:
    """The agent-side state collector: observe the loop's facts, render the health text.

    Constructed once per agent process (per site). `observe_tick` wraps every
    `DeviceLoop.tick()` (it returns the tick unchanged — a decorator, not a consumer);
    `observe_push_log` wires to `drain(log=...)`; `observe_skew` stores the
    `tz.compute_skew` gauge the caller read; `observe_warn` is the process's warning
    funnel (it OBSERVES only — the emitter already printed the line; re-emitting would
    double every warning, and the site_labeled counter deliberately comes from the
    loop's result label rather than this stream so the two cannot double-count).

    `collect()` builds the snapshot from injected live clients and the store: no
    device call, no db write (both pinned by test — health must not perturb the agent).
    """

    def __init__(
        self,
        *,
        site: str,
        conn: sqlite3.Connection,
        db_path: str,
        checkpoint_stall_s: float,
        tz_mapping_declared: bool,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        monotonic: Callable[[], float] = time.monotonic,
        warn: Callable[[str], None] = _stderr_warn,
    ) -> None:
        if checkpoint_stall_s <= 0:
            raise ValueError(
                f"checkpoint_stall_s {checkpoint_stall_s} must be > 0 — a threshold of"
                " zero or less degrades every snapshot by construction"
            )
        self.site = site
        self._conn = conn
        self._db_path = db_path
        self.checkpoint_stall_s = checkpoint_stall_s
        self.tz_mapping_declared = tz_mapping_declared
        self._now = now
        self._monotonic = monotonic
        self._warn = warn
        # The p1-06c/p1-12 warning policy, REUSED not forked: the collector delegates
        # to the CLI's own function and captures what it prints (the function builds
        # its stderr console at call time, so `redirect_stderr` sees exactly the line
        # an operator would have seen). The anti-fork pin is the test's
        # `collector.mismatch_policy is cli._warn_tz_mismatch`.
        from gateclerk.cli_shared import _warn_tz_mismatch  # lazy: cli_shared pulls typer + rich

        self.mismatch_policy = _warn_tz_mismatch
        self._stats: dict[str, DeviceStats] = {}
        # push state is a SITE-level gauge (one pusher per agent process, spec §2d):
        # its own bucket, deliberately outside the per-device map so `collect()` can
        # never mistake it for a device.
        self._push = DeviceStats()

    # -- observation seams (the agent process calls these; they never raise) ----------

    def stats(self, device_serial: str) -> DeviceStats:
        return self._stats.setdefault(device_serial, DeviceStats())

    def observe_tick(self, result: Any, *, device_serial: str, client: Any) -> Any:
        """Record one `TickResult` (P2-03) and hand it back untouched.

        `device_serial` is the serial the CALLER's loop owns (from config/`DeviceLoop`
        — a pre-bootstrap failure tick carries `device_serial=None`, and "which device
        is this" is wiring the caller knows, not something to guess). When the result
        DID carry a serial it must agree — a disagreement is two loops sharing one
        collector, a wiring bug loud is better than a counter silently split.

        The counters read exactly what the loop reported — never a re-walk. The auth
        counters read the exception the failed tick CARRIES (`IsapiAuthError` is the
        transport's own terminal-401 verdict; `.locked` is the 401 body's lockStatus),
        so `auth_terminal_failures` counts terminal 401s the agent actually observed,
        and a circuit-open skip adds nothing on top of the failure that opened it.
        """
        del client  # the tick already carries the loop's verdict; live state is read at build
        result_serial = getattr(result, "device_serial", None)
        if result_serial is not None and result_serial != device_serial:
            raise ValueError(
                f"tick reported {result_serial!r} but collector was told {device_serial!r}"
                " — one collector per device loop, wire observe_tick per loop"
            )
        stats = self.stats(device_serial)
        if getattr(result, "ok", False):
            stats.pages_fetched += int(result.pages)
            stats.records_stored += int(result.stored)
            if getattr(result, "termination", None):
                stats.last_termination = result.termination
            if result.window_label == SITE_LABELLED:
                # p1-05c: the risky fallback is counted per ok tick — the §5 rollout
                # gate needs "site_labeled_windows 0" as EVIDENCE, so the count comes
                # from the loop's own label (the shared constant), not a re-read.
                stats.site_labeled_windows += 1
            stats.last_poll_ok_monotonic = self._monotonic()
            stats.park_observed_monotonic = None  # ticking again = not parked
        elif getattr(result, "circuit_open", False):
            # The parked gauge's age anchor: first moment THIS process saw it parked.
            # `is None` (not `or`): a legit anchor of 0.0 (fresh monotonic) is falsy.
            if stats.park_observed_monotonic is None:
                stats.park_observed_monotonic = self._monotonic()
        exc = getattr(result, "exception", None)
        if isinstance(exc, IsapiAuthError):
            stats.auth_terminal_failures += 1
            if exc.locked:
                stats.device_locked_events += 1
        return result

    def observe_push_log(self, line: str) -> None:
        """Accumulate `drain`'s own log counters (agent_push's drain log is the source).

        Wired as `drain(..., log=collector.observe_push_log)`: the numbers are the
        ones the drain printed for its rows, so health can never disagree with the
        queue. A line that does not parse is ignored — a health counter must not be
        able to break (or crash) a drain.
        """
        before, sep, rest = line.partition("push drain: ")
        if not sep or before.strip():
            return
        try:
            fields = dict(token.split("=", 1) for token in rest.split() if "=" in token)
            sent = int(fields["sent"])
            retried = int(fields["retried"])
            dead = int(fields["dead_lettered"])
        except (KeyError, ValueError):
            return
        self._push.push_ok += sent
        self._push.push_failed += retried + dead

    def observe_warn(self, text: str) -> None:
        """Observe the process's warning stream WITHOUT re-emitting it.

        Exists so the wiring is explicit (P2-07 routes every warning line through the
        collector) and so the no-leak pin has a chokepoint: nothing observed here ever
        reaches the health text (the emitted surfaces are metric lines only).
        """
        del text
        return None

    def observe_skew(self, device_serial: str, skew: Skew) -> None:
        """Store the `tz.compute_skew` gauge; spec §2c keeps it a WARNING channel.

        Over-threshold warns ONCE per process (the loop's precedent: a repeating
        warning line is noise that trains operators out of reading warnings). Skew
        NEVER feeds the degraded rule — that rule is circuit-open / stall, nothing
        else (card RULES).
        """
        stats = self.stats(device_serial)
        stats.skew_seconds = skew.skew_seconds
        if skew.warn and not stats.skew_warned:
            stats.skew_warned = True
            message = skew.message
            if message is not None:
                self._warn(message)

    # -- the read side -------------------------------------------------------------------

    def collect(self, *, clients: Mapping[str, Any], ticks: Mapping[str, Any]) -> HealthSnapshot:
        """Build the snapshot: store reads + live client gauges + process memory.

        `clients` maps device serial -> live `IsapiClient` (for `auth_recoveries` and
        `circuit_open()` — the transport's OWN numbers, read not re-derived); `ticks`
        maps serial -> the last `TickResult`. No device call is made (the clients are
        only asked for local state) and no db write happens — both pinned by test.
        """
        now = self._now()
        devices: list[DeviceHealth] = []
        reasons: list[str] = []
        for serial in sorted(set(clients) | set(ticks) | set(self._stats)):
            stats = self.stats(serial)
            if stats.mismatch_warnings is None:
                # once-per-process policy (p1-06c): runs on the FIRST collect for this
                # device, then sticks at 0/1 — healthz polls never re-warn.
                stats.mismatch_warnings = self._run_mismatch_policy(serial)
            health = device_health(
                conn=self._conn,
                device_serial=serial,
                stats=stats,
                client=clients.get(serial),
                last_tick=ticks.get(serial),
                now=now,
                monotonic=self._monotonic,
            )
            devices.append(health)
            if health.circuit_open:
                reasons.append(
                    f"device {serial}: auth circuit open — parked {health.circuit_parked_s:.0f}s"
                    " (terminal 401; P2-05 alert channel)"
                )
            if health.checkpoint_age_s is not None and (
                health.checkpoint_age_s > self.checkpoint_stall_s
            ):
                reasons.append(
                    f"device {serial}: checkpoint stalled {health.checkpoint_age_s:.0f}s"
                    f" > {self.checkpoint_stall_s:.0f}s threshold (age only — P2-05 "
                    "pages on failed-poll evidence, not silence)"
                )

        site_metrics = (
            MetricLine(
                "db_size_bytes",
                db_size_bytes(self._db_path),
                "agent_store.db_size_bytes (main db file)",
            ),
            MetricLine(
                "dead_letter_depth",
                dead_letter_depth(self._conn),
                "agent_push.dead_letter_depth (COUNT(*) dead_letter rows)",
            ),
            MetricLine(
                "push_failed",
                self._push.push_failed,
                "drain log 'retried+dead_lettered', cumulative (AgentHealthCollector)",
            ),
            MetricLine(
                "push_ok",
                self._push.push_ok,
                "drain log 'sent', cumulative (AgentHealthCollector)",
            ),
        )
        return HealthSnapshot(
            site=self.site,
            agent_version=__version__,
            status="degraded" if reasons else "ok",
            reasons=tuple(reasons),
            checkpoint_stall_s=self.checkpoint_stall_s,
            devices=tuple(devices),
            site_metrics=site_metrics,
        )

    # -- internals ------------------------------------------------------------------------

    def mismatch_records(self, device_serial: str) -> list[EventRecord]:
        """Stored lines -> `EventRecord`, `from_dict` verbatim (never re-derived).

        p1-12's rule for the summary line applies to this metric too: the policy's
        input is READ OFF the store (`jsonl` is the frozen contract line), so the
        warning can never disagree with the records it summarizes. A line that will
        not parse is skipped — the health surface must not die on one corrupt row.
        """
        rows = self._conn.execute(
            "SELECT jsonl FROM events WHERE device_serial = ? ORDER BY serial_no",
            (device_serial,),
        ).fetchall()
        out: list[EventRecord] = []
        for row in rows:
            record = _parse_jsonl(row["jsonl"])
            if record is not None:
                out.append(record)
        return out

    def _run_mismatch_policy(self, device_serial: str) -> int:
        """Delegate to `cli._warn_tz_mismatch`, capture its stderr line(s), count them.

        Returns 0 or 1 (the policy prints at most one summary line per call). The line
        also goes through the process warn sink, so journalctl keeps what the CLI
        operator would have seen.
        """
        records = self.mismatch_records(device_serial)
        if not records:
            return 0
        buffer = io.StringIO()
        try:
            with redirect_stderr(buffer):
                self.mismatch_policy(records, mapping_declared=self.tz_mapping_declared)
        except Exception:  # the policy must not break a health poll
            return 0
        emitted = [line for line in buffer.getvalue().splitlines() if MISMATCH_MARKER in line]
        for line in emitted:
            self._warn(line)
        return len(emitted)


# --- the pure builder (tests call this directly; the collector delegates) ------------------


def device_health(
    *,
    conn: sqlite3.Connection,
    device_serial: str,
    stats: DeviceStats,
    client: Any,
    last_tick: Any,
    now: datetime,
    monotonic: Callable[[], float],
) -> DeviceHealth:
    """One device block: the db's facts + the live transport gauges, as plain data.

    Read-only (no device request, no db write) and side-effect free: same inputs ->
    same block, so the test can call it twice and pin equality. Clock math is split
    deliberately: `now` (wall) ages the checkpoint row (its stamp is wall), `monotonic`
    ages the poll heartbeat and the parked gauge (process facts — a wall-clock step
    must not make the agent look stalled or freshly-polled).
    """
    checkpoint = conn.execute(
        "SELECT checkpoint_serial, checkpoint_time, updated_at FROM checkpoint"
        " WHERE device_serial = ?",
        (device_serial,),
    ).fetchone()
    checkpoint_serial = checkpoint["checkpoint_serial"] if checkpoint is not None else None
    checkpoint_age_s = _checkpoint_age_s(checkpoint, now)

    circuit_open = bool(client.circuit_open()) if client is not None else False
    parked = 0.0
    if circuit_open and stats.park_observed_monotonic is not None:
        parked = max(0.0, monotonic() - stats.park_observed_monotonic)
    last_poll_ok_age_s = None
    if stats.last_poll_ok_monotonic is not None:
        last_poll_ok_age_s = max(0.0, monotonic() - stats.last_poll_ok_monotonic)

    mismatch = conn.execute(
        "SELECT COUNT(*) c FROM events WHERE device_serial = ? AND tz_offset_mismatch = 1",
        (device_serial,),
    ).fetchone()["c"]
    oldest = conn.execute(
        "SELECT MIN(serial_no) m FROM events WHERE device_serial = ?",
        (device_serial,),
    ).fetchone()["m"]
    termination = getattr(last_tick, "termination", None) or stats.last_termination

    metrics = (
        MetricLine(
            "auth_recoveries",
            int(getattr(client, "auth_recoveries", 0)) if client is not None else 0,
            "IsapiClient.auth_recoveries",
        ),
        MetricLine(
            "auth_terminal_failures",
            stats.auth_terminal_failures,
            "terminal IsapiAuthError on an observed tick (AgentHealthCollector.observe_tick)",
        ),
        MetricLine(
            "circuit_open_gauge",
            1 if circuit_open else 0,
            "IsapiClient.circuit_open() at snapshot build",
        ),
        MetricLine(
            "checkpoint_serial",
            checkpoint_serial,
            "agent_store.read_checkpoint (checkpoint table row)",
        ),
        MetricLine(
            "device_clock_skew_seconds",
            stats.skew_seconds,
            "tz.compute_skew over GET System/time (AgentHealthCollector, once per process)",
        ),
        MetricLine(
            "device_locked_events",
            stats.device_locked_events,
            "IsapiAuthError.locked on an observed tick (AgentHealthCollector.observe_tick)",
        ),
        MetricLine(
            "events_per_day",
            _events_per_day(conn, device_serial, now),
            "COUNT(events) / (now - first event_time_utc) over the store",
        ),
        MetricLine(
            "oldest_serial",
            oldest,
            "AgentHealthCollector observation, else MIN(events.serial_no)",
        ),
        MetricLine(
            "pages_fetched",
            stats.pages_fetched,
            "TickResult.pages (SearchSummary.pages, paging.py:351)",
        ),
        MetricLine(
            "records_stored",
            stats.records_stored,
            "TickResult.stored (agent_store UPSERT outcomes)",
        ),
        MetricLine(
            "search_termination",
            termination,
            "TickResult.termination (SearchSummary.termination of the last completed chunk)",
        ),
        MetricLine(
            "site_labeled_windows",
            stats.site_labeled_windows,
            "TickResult.window_label == the p1-05c fallback label, per ok tick",
        ),
        MetricLine(
            "tz_offset_mismatch_records",
            mismatch,
            "COUNT events WHERE tz_offset_mismatch = 1",
        ),
        MetricLine(
            "tz_offset_mismatch_warnings",
            stats.mismatch_warnings,
            "p1-06c once-per-run policy (cli._warn_tz_mismatch), once per process",
        ),
    )
    return DeviceHealth(
        device_serial=device_serial,
        circuit_open=circuit_open,
        circuit_parked_s=parked,
        checkpoint_serial=checkpoint_serial,
        checkpoint_age_s=checkpoint_age_s,
        last_poll_ok_age_s=last_poll_ok_age_s,
        metrics=tuple(sorted(metrics, key=lambda m: m.name)),
    )


def healthz_text(snapshot: HealthSnapshot) -> str:
    """The /healthz body: the spec §2e summary + one block per device (pinned format)."""
    lines = [
        f"status: {snapshot.status}",
        f"site: {snapshot.site}",
        f"agent_version: {snapshot.agent_version}",
        f"devices: {len(snapshot.devices)}",
    ]
    depth = next((m for m in snapshot.site_metrics if m.name == "dead_letter_depth"), None)
    lines.append(f"dead_letter_depth: {_fmt(depth.value if depth else None)}")
    ages = [d.last_poll_ok_age_s for d in snapshot.devices if d.last_poll_ok_age_s is not None]
    lines.append(f"last_poll_ok_age_s: {f'{max(ages):.1f}' if ages else 'null'}")
    for device in snapshot.devices:
        lines.append(f"device: {device.device_serial}")
        lines.append(f"  circuit_open: {'true' if device.circuit_open else 'false'}")
        lines.append(f"  circuit_parked_s: {device.circuit_parked_s:.1f}")
        lines.append(f"  checkpoint_serial: {_fmt(device.checkpoint_serial)}")
        lines.append(f"  checkpoint_age_s: {_fmt_age(device.checkpoint_age_s)}")
        lines.append(f"  last_poll_ok_age_s: {_fmt_age(device.last_poll_ok_age_s)}")
        lines.extend(f"  {m.render()}" for m in device.metrics)
    return "\n".join(lines) + "\n"


def metrics_text(snapshot: HealthSnapshot) -> str:
    """The /metrics body: `name value  # source`, one line per emitted metric.

    Site-level names first (sorted), then one commented block per device. Full sorted
    set equality against the §2e vocabulary is pinned over this exact rendering.
    """
    lines = [m.render() for m in sorted(snapshot.site_metrics, key=lambda m: m.name)]
    for device in snapshot.devices:
        lines.append(f"# device: {device.device_serial}")
        lines.extend(m.render() for m in device.metrics)
    return "\n".join(lines) + "\n"


def snapshot_to_json(snapshot: HealthSnapshot) -> str:
    """The sidecar write: JSON for a separate reader process (P2-07's socat shape)."""
    return json.dumps(snapshot.to_dict(), indent=2, sort_keys=True)


def snapshot_from_dict(payload: Mapping[str, Any]) -> HealthSnapshot:
    """The sidecar read: rebuild a snapshot from parsed JSON (equality holds)."""
    return HealthSnapshot.from_dict(payload)


# --- helpers -------------------------------------------------------------------------------


def _fmt(value: Any) -> str:
    return "null" if value is None else str(value)


def _fmt_age(value: float | None) -> str:
    return "null" if value is None else f"{value:.1f}"


def _parse_utc(stamp: str) -> datetime | None:
    """An ISO stamp written by agent_store (UTC, second resolution) -> aware datetime."""
    try:
        parsed = datetime.fromisoformat(stamp)
    except ValueError:
        return None
    if parsed.tzinfo is None:  # a naive stamp is corruption to us, not UTC-by-assumption
        return None
    return parsed


def _checkpoint_age_s(checkpoint: Any, now: datetime) -> float | None:
    if checkpoint is None:
        return None
    stamp = _parse_utc(checkpoint["updated_at"])
    if stamp is None:
        return None
    return max(0.0, (now - stamp).total_seconds())


def _events_per_day(conn: sqlite3.Connection, device_serial: str, now: datetime) -> float | None:
    row = conn.execute(
        "SELECT COUNT(*) c, MIN(event_time_utc) first FROM events WHERE device_serial = ?",
        (device_serial,),
    ).fetchone()
    if not row["c"] or row["first"] is None:
        return None
    first = _parse_utc(row["first"])
    if first is None:
        return None
    span = (now - first).total_seconds()
    if span <= 0:
        # The very first store in a brand-new db at the same instant as the clock: no
        # rate is definable. None is honest; 0 would be a lie and inf breaks the JSON.
        return None
    return row["c"] * 86400.0 / span
