"""Alert semantics + park-on-bad-creds for the P2 site agent (card P2-05).

BINDING SPEC: docs/P2-SITE-AGENT.md §2c (DECIDED verbatim 2026-10-19):

* terminal 401 WITH a challenge (wrong/rotated creds) -> CRITICAL, and the device
  loop PARKS: no automatic re-probe; a slow re-probe every 30 min ONLY after
  operator acknowledgement;
* 401 body ``lockStatus=lock`` -> CRITICAL + operator on site (the transport circuit
  already waits out ``unlockTime`` — creds are never presented while locked,
  FINDINGS-t_a3521d8a F3);
* nonce recoveries -> NOT an alert: an info counter line only (spec §2a: retirement
  is routine at any minutes-scale cadence; OBSERVED.md "Digest nonce use-cap");
* clock skew over threshold -> warning;
* checkpoint stall -> CRITICAL only on EVIDENCE OF LOSS, never on silence. A
  checkpoint older than k*cadence while polls succeed and return nothing newer is
  a quiet door (night/lunch), not an outage: the checkpoint only moves on major=5
  punches. The page fires when that stale checkpoint coincides with a FAILING poll,
  or when the oldest serialNo rises — DESIGN.md OQ4's ring-floor signal,
  "a monotonic increase of the minimum = rolling started = punches are being lost"
  (OBSERVED.md "Retention / gaps").

The invariant that outranks everything else here — the lockout-safety one the card
pins hardest — is that an UNACKED parked device is touched NEVER again: not at the
cadence, not after a process restart (``Restart=always``), not "just one probe".
The park therefore lives on disk (or in an injected store), not in memory: the
transport circuit is process state and dies with the unit; a park that died with it
would re-feed wrong credentials into the device's lockout accounting every five
minutes (OBSERVED.md "lockout accounting").

Design seam, per the card: the loop (P2-03) and the transport circuit are read,
never edited. The policy consumes ``TickResult`` objects + ``IsapiClient`` counters
through ``handle_tick``/``observe_*``, and P2-07's CLI wraps the scheduler in
``guarded_tick`` — the only gate that decides whether a device gets a tick at all.

Logging rule (card): the sink line may carry the site label, the device serial, the
kind, and a human phrase — never Authorization, never payload bodies, never hosts
beyond the site label. That last one is not paranoia: the transport's own exception
strings embed the base URL (isapi_transport.py: ``request to {base_url} failed``),
so alert notes are authored from safe pieces here and NEVER from ``str(exc)``.
``tests/test_p2_05_alerts.py`` scans the whole alert surface for the leak.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from gateclerk.agent_store import WatermarkCheck, read_checkpoint, read_oldest_serial
from gateclerk.exceptions import GateClerkError, IsapiAuthError
from gateclerk.tz import Skew

__all__ = [
    "REPROBE_AFTER_S",
    "STALL_STRIKES",
    "Alert",
    "AlertPolicy",
    "ParkState",
    "default_sink",
    "guarded_tick",
]

# --- the vocabulary (§2c classes; snake_case names carry §2e's metric names) -------------

LEVEL_CRITICAL = "critical"
LEVEL_WARNING = "warning"

#: terminal 401 WITH a challenge — wrong or rotated credentials. Critical + parked.
KIND_AUTH_TERMINAL = "auth_terminal"
#: 401 body ``lockStatus=lock`` — the account is locked at the door. Critical + on-site.
KIND_DEVICE_LOCKED = "device_locked"
#: device clock past ``tz.SKEW_WARN_SECONDS`` (DESIGN.md "Time handling": log, never fix).
KIND_CLOCK_SKEW = "clock_skew"
#: checkpoint stale AND evidence of loss (a failing poll or a rising serial floor),
#: never mere silence — the ring may be rolling (DESIGN.md OQ4).
KIND_CHECKPOINT_STALL = "checkpoint_stall"
#: db past the §2b keep-everything watermark.
KIND_DB_WATERMARK = "db_watermark"

#: §2c verbatim: "slow re-probe e.g. every 30 min only after operator
#: acknowledgement". 30 minutes, as seconds.
REPROBE_AFTER_S = 1800

#: Stall threshold k (§2c "checkpoint stall ... over k*cadence"), default 3.
#: There is NO config key for it (config.py ``SiteConfig._KNOWN_KEYS`` does not carry
#: a stall multiplier — adding one there is out of this card's ownership), so per
#: the card this is a module constant with the spec pointer. If P2-06 grows the key,
#: the caller passes ``stall_strikes=`` from config and nothing else changes.
STALL_STRIKES = 3

#: The park record for a failure that happened BEFORE the serial was ever read
#: (bootstrap died on the very first GET — there is no serial to name).
PENDING_SERIAL = "pending"

_SAFE = str.maketrans(dict.fromkeys('\\/:*?"<>| \t\n', "_"))


def _safe_name(text: str) -> str:
    """Filesystem-safe form of a site/serial label (labels may carry anything)."""
    return (text or "_").translate(_SAFE) or "_"


def _iso(moment: datetime) -> str:
    if moment.tzinfo is None:
        raise ValueError("alert timestamps must be tz-aware (payroll data; pyproject DTZ)")
    return moment.astimezone(UTC).isoformat(timespec="seconds")


def _parse_iso(text: str) -> datetime:
    moment = datetime.fromisoformat(text)
    if moment.tzinfo is None:  # a naive stamp on disk is a bug, not a timezone choice
        raise ValueError(f"park/checkpoint timestamp {text!r} is not tz-aware")
    return moment


@dataclass(frozen=True, slots=True)
class Alert:
    """One alert record — what goes to the sink, and nothing else.

    Deliberately small and safe: the notes are authored HERE from safe pieces (kind,
    site label, serial, numbers), never from transport exception strings, which embed
    the device host (module docstring). P2-06 may add the metric-counter increment
    beside the sink line once the §2e vocabulary ships; the Alert shape is what both
    surfaces share.
    """

    level: str  # LEVEL_CRITICAL | LEVEL_WARNING
    kind: str  # KIND_* — the stable machine name (a metric identity, §2e)
    site: str
    device_serial: str | None
    at: str  # tz-aware ISO, from the injected clock — never a wall-clock surprise
    note: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "kind": self.kind,
            "site": self.site,
            "device_serial": self.device_serial,
            "at": self.at,
            "note": self.note,
        }


def default_sink(alert: Alert) -> None:
    """The stdlib default: one stderr line, p1-05c ``_default_warn`` precedent.

    ``markup=False`` because notes and serials are data (rich markup injection is
    the same class of bug the CLI guards elsewhere). No colors, no frames: this line
    lands in a journald unit log next to systemd's own.
    """
    from gateclerk.output import make_console  # local: keeps the module import cheap

    console = make_console(stderr=True)
    serial = alert.device_serial if alert.device_serial else "-"
    console.print(
        f"GATECLERK ALERT {alert.level} site={alert.site} device={serial} "
        f"kind={alert.kind}: {alert.note}",
        markup=False,
    )


@dataclass(frozen=True, slots=True)
class ParkState:
    """One parked device: when it parked, whether an operator acked, and the grid.

    ``next_attempt_at`` is None while unacked — the unacked state means *no
    schedule at all*, not "a very long schedule", because a clock that "forgot" to
    be unacked would re-present dead credentials to a lockout-counting device.
    """

    site: str
    device_serial: str
    parked_at: datetime
    acked_at: datetime | None
    next_attempt_at: datetime | None


class AlertPolicy:
    """Per-process alert + park policy for ONE site (one unit, one agent — §2d).

    Everything time-shaped reads the injected ``now`` (tests drive days; the unit
    reaches the same seams via P2-07). The park store is a directory of small JSON
    files when ``park_dir`` is given — the on-disk state is what survives the
    systemd restart that the lockout invariant depends on — and an in-memory dict
    otherwise (tests of the pure logic). ``conn`` is only needed by ``check_stall``.
    """

    def __init__(
        self,
        *,
        site: str,
        cadence_s: int,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        sink: Callable[[Alert], None] = default_sink,
        conn: Any | None = None,
        park_dir: Path | str | None = None,
        reprobe_after_s: int = REPROBE_AFTER_S,
        stall_strikes: int = STALL_STRIKES,
    ) -> None:
        if cadence_s <= 0:
            raise ValueError(f"cadence_s {cadence_s} must be > 0 (config validated this)")
        self.site = site
        self.cadence_s = cadence_s
        self.now = now
        self.sink = sink
        self.conn = conn
        self.park_dir = Path(park_dir) if park_dir is not None else None
        self.reprobe_after_s = reprobe_after_s
        self.stall_strikes = stall_strikes
        #: §2e-style info counters. Everything here is a metric line, never an alert
        #: (nonce recoveries explicitly so — spec §2c).
        self.counters: dict[str, int] = {
            "ticks_ok": 0,
            "tick_failures": 0,
            "circuit_open_skips": 0,
            "auth_recoveries": 0,
            "auth_terminal": 0,
            "device_locked": 0,
            "clock_skew": 0,
            #: Evidence-of-loss only: a failing poll or a rising serial floor. A quiet
            #: door whose polls succeed is not a stall (card STALL-ALERT-FALSE).
            "checkpoint_stall": 0,
            "db_watermark": 0,
        }
        self._mem_parks: dict[str, dict[str, Any]] = {}
        # Last observed poll shape per device: "ok" | "failed" | "auth" | "skipped".
        # Only "failed" (a non-auth walk failure) is stall evidence; auth has its own
        # critical channel and a circuit-open skip touched nothing at all.
        self._last_poll_status: dict[str, str] = {}
        # Store floor per device across checks (the OBSERVED oldest-serialNo signal).
        self._oldest_serial_seen: dict[str, int | None] = {}
        # Episode guards: each of these alert kinds pages ONCE per incident, never
        # once per tick — an alert that fires every 5 minutes is an alert nobody reads.
        self._locked_open = False
        self._skew_open = False
        self._watermark_open = False
        self._stall_open_at: dict[str, str] = {}  # serial -> checkpoint updated_at seen

    # --- park store ---------------------------------------------------------------------

    def _park_path(self, device_key: str) -> Path:
        if self.park_dir is None:  # pragma: no cover - every caller gates on park_dir
            raise GateClerkError("park path requested on an in-memory policy (no park_dir)")
        return self.park_dir / f"park-{_safe_name(self.site)}__{_safe_name(device_key)}.json"

    def _read_park(self, device_key: str) -> dict[str, Any] | None:
        if self.park_dir is None:
            return self._mem_parks.get(device_key)
        try:
            raw = self._park_path(device_key).read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        data = json.loads(raw)
        if not isinstance(data, dict) or data.get("site") != self.site:
            raise ValueError(
                f"park file {self._park_path(device_key)!r} is not site {self.site!r} — "
                "park dirs are per-unit state; refuse to act on someone else's park"
            )
        return data

    def _write_park(self, device_key: str, record: dict[str, Any] | None) -> None:
        if self.park_dir is None:
            if record is None:
                self._mem_parks.pop(device_key, None)
            else:
                self._mem_parks[device_key] = record
            return
        self.park_dir.mkdir(parents=True, exist_ok=True)
        path = self._park_path(device_key)
        if record is None:
            path.unlink(missing_ok=True)
            return
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
        tmp.replace(path)  # atomic: a kill between write and rename cannot halve a park

    def _device_keys(self, device_serial: str | None) -> tuple[str, ...]:
        """A tick can hit BOTH parks: the pre-bootstrap `pending` one and, once the
        serial is known, the device-named one. Either one blocks the device."""
        return (PENDING_SERIAL,) if device_serial is None else (PENDING_SERIAL, device_serial)

    def parked(self, site: str, device_serial: str = PENDING_SERIAL) -> ParkState | None:
        """The park state for one device key, or None when not parked.

        Takes the site explicitly (typo'd site cannot clear or read another unit's
        park; the file name carries both labels).
        """
        if site != self.site:
            return None
        record = self._read_park(device_serial)
        if record is None:
            return None
        return ParkState(
            site=self.site,
            device_serial=record["device_serial"],
            parked_at=_parse_iso(record["parked_at"]),
            acked_at=None if record["acked_at"] is None else _parse_iso(record["acked_at"]),
            next_attempt_at=(
                None if record["next_attempt_at"] is None else _parse_iso(record["next_attempt_at"])
            ),
        )

    def _park(self, device_key: str, *, serial_for_record: str | None) -> ParkState:
        now = self.now()
        record = {
            "version": 1,
            "site": self.site,
            "device_serial": serial_for_record or PENDING_SERIAL,
            "parked_at": _iso(now),
            "acked_at": None,
            # No schedule while unacked (class docstring): the operator decides IF
            # the device is ever knocked on again, the grid decides WHEN.
            "next_attempt_at": None,
        }
        self._write_park(device_key, record)
        return ParkState(
            site=self.site,
            device_serial=record["device_serial"],
            parked_at=now,
            acked_at=None,
            next_attempt_at=None,
        )

    def _park_records(self) -> list[dict[str, Any]]:
        """Every park record of THIS site (site-wide ack + tests iterate these)."""
        if self.park_dir is None:
            return list(self._mem_parks.values())
        out: list[dict[str, Any]] = []
        if not self.park_dir.is_dir():
            return out
        for path in sorted(self.park_dir.glob(f"park-{_safe_name(self.site)}__*.json")):
            record = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(record, dict) or record.get("site") != self.site:
                raise ValueError(
                    f"park file {path!r} carries a foreign site — park dirs are per-unit "
                    "state; refuse to act on someone else's park"
                )
            out.append(record)
        return out

    def ack(self, site: str, device_serial: str | None = None) -> int:
        """Operator acknowledgement (P2-07 wires `gateclerk agent ack`).

        Returns how many parks the ack opened (0 for a typo — an ack that cannot
        find a park must not look like it cleared one). ``device_serial=None`` acks
        every park of this site (the operator saw the page; they know their site).
        From here the re-probe grid starts: one attempt per ``reprobe_after_s``,
        first at ``ack + reprobe_after_s`` (never immediately — an ack is permission
        to schedule, not a request to hammer the moment the key is pressed).
        """
        if site != self.site:
            return 0
        count = 0
        now = self.now()
        stamp = _iso(now)
        due = _iso(now + timedelta(seconds=self.reprobe_after_s))
        for record in self._park_records():
            if device_serial is not None and record["device_serial"] != device_serial:
                continue
            if record.get("acked_at") is not None:
                continue  # already open; re-acking must not push the grid out
            record["acked_at"] = stamp
            record["next_attempt_at"] = due
            self._write_park(record["device_serial"], record)
            count += 1
        return count

    def _unpark(self, device_serial: str | None) -> None:
        for key in self._device_keys(device_serial):
            if self._read_park(key) is not None:
                self._write_park(key, None)

    def _note_attempt(self, device_serial: str | None) -> None:
        """A gated attempt happened under a park: re-arm the grid from NOW.

        Measured from the attempt, not from the last scheduled slot, so a failed
        re-probe cannot immediately justify another one (the cadence loop calls
        every 5 min; without this the device would be knocked at every slot that
        has ever come due).
        """
        for key in self._device_keys(device_serial):
            record = self._read_park(key)
            if record is None or record.get("next_attempt_at") is None:
                continue  # unacked parks have no grid to re-arm
            record["next_attempt_at"] = _iso(self.now() + timedelta(seconds=self.reprobe_after_s))
            self._write_park(key, record)

    # --- the gate -----------------------------------------------------------------------

    def attempt_allowed(self, device_serial: str | None) -> tuple[bool, str]:
        """May the device be touched RIGHT NOW? The lockout-safety gate.

        (allowed, reason): the reason is for the caller's log/metrics, never a
        device-facing string. Unacked park -> never allowed (hard); acked park ->
        allowed only on the 30-min grid.
        """
        for key in self._device_keys(device_serial):
            record = self._read_park(key)
            if record is None:
                continue
            if record.get("acked_at") is None:
                return False, f"parked unacked ({key}) — operator ack required"
            nxt = record.get("next_attempt_at")
            if nxt is not None and self.now() < _parse_iso(nxt):
                return False, f"parked+acked, re-probe not due ({key})"
        return True, "allowed"

    # --- the result object (P2-03 TickResult) -------------------------------------------

    def handle_tick(self, result: Any, *, attempted: bool = False) -> list[Alert]:
        """Read one ``TickResult`` and decide what it means (§2c channels, separate).

        Never raises: an alert policy that can take the agent down has become the
        outage. Returns the alerts it fired (empty for the silent classes). With
        ``attempted=True`` the caller says "this tick went out under the gate" — a
        parked device that is still parked after the attempt gets its grid re-armed.

        The two skipped shapes are SILENCE, by design:
        * ``skipped=True`` (circuit open): the transport enforcing a page this policy
          already fired — re-alerting it would be nagging;
        * a failed tick that is NOT an auth failure: the overlap heals it (P2-03),
          it is a metric (``tick_failures``), not a page (§2c separates the
          channels on purpose).
        """
        fired: list[Alert] = []
        serial = getattr(result, "device_serial", None)
        if attempted:
            # The grid is consumed by the ATTEMPT, whatever it found: an acked park
            # means exactly one knock per re-probe period, not "one knock per
            # auth-shaped failure" (a transient busy in between must not reopen the
            # cadence door for the rest of the episode). On a good tick the park
            # lifts below anyway; the re-arm is then dead weight, not a bug.
            self._note_attempt(serial)
        if getattr(result, "ok", False):
            self.counters["ticks_ok"] += 1
            self._locked_open = False
            if serial is not None:
                self._last_poll_status[serial] = "ok"
            # A good tick IS the proof the credentials work again — the park (any
            # shape) lifts. §2c's rationale for the slow re-probe over park-forever:
            # "a transient creds rotation self-heals without a site visit".
            self._unpark(serial)
            return fired

        if getattr(result, "skipped", False):
            self.counters["circuit_open_skips"] += 1
            if serial is not None:
                self._last_poll_status[serial] = "skipped"
            return fired

        self.counters["tick_failures"] += 1
        exc = getattr(result, "exception", None)
        if serial is not None:
            self._last_poll_status[serial] = "auth" if isinstance(exc, IsapiAuthError) else "failed"
        if isinstance(exc, IsapiAuthError):
            if exc.locked:
                if not self._locked_open:
                    self._locked_open = True
                    fired.append(
                        self._fire(
                            LEVEL_CRITICAL,
                            KIND_DEVICE_LOCKED,
                            serial,
                            "device says the account is LOCKED (lockStatus=lock); the "
                            "transport circuit waits out the device's own unlockTime "
                            "and presents nothing meanwhile — operator on site required",
                        )
                    )
                # No park here on purpose: the circuit IS the wait (§2c: "circuit
                # already waits out unlockTime"); an ack could not shorten it.
            else:
                if self._read_park(PENDING_SERIAL) is None and (
                    serial is None or self._read_park(serial) is None
                ):
                    fired.append(
                        self._fire(
                            LEVEL_CRITICAL,
                            KIND_AUTH_TERMINAL,
                            serial,
                            "terminal 401 with a challenge — credentials wrong or "
                            "rotated; the device loop is PARKED (no re-probe until "
                            "`gateclerk agent ack`)",
                        )
                    )
                    self._park(
                        PENDING_SERIAL if serial is None else serial, serial_for_record=serial
                    )
            return fired

        return fired

    # --- the info channels (counters; NEVER alerts) --------------------------------------

    def observe_recoveries(self, total: int) -> None:
        """`IsapiClient.auth_recoveries` — spec §2c: routine, an info line only.

        Monotone max, so feeding an older total (a re-read of a shared client) can
        never lower the counter — it is a *total spent*, like the transport's own.
        """
        self.counters["auth_recoveries"] = max(self.counters["auth_recoveries"], int(total))

    # --- the warning channel: clock skew --------------------------------------------------

    def observe_skew(self, skew: Skew) -> list[Alert]:
        """`tz.compute_skew` result -> warning over threshold, silence under.

        One page per incident: the device clock drifts or it does not; re-firing
        every tick is noise. A non-warn observation closes the episode.
        """
        if not skew.warn:
            self._skew_open = False
            return []
        if self._skew_open:
            return []
        self._skew_open = True
        seconds = skew.skew_seconds if skew.skew_seconds is not None else 0.0
        return [
            self._fire(
                LEVEL_WARNING,
                KIND_CLOCK_SKEW,
                None,
                f"device clock skew {seconds:+.1f}s exceeds {skew.warn_seconds:.0f}s; "
                "not correcting it — device time is an owner-side write (DESIGN.md)",
            )
        ]

    # --- the critical channel: checkpoint stall (DESIGN.md OQ4) ----------------------------

    def check_stall(self, device_serial: str) -> Alert | None:
        """Checkpoint age becomes a stall ONLY with evidence of loss, never silence.

        The health/alert field stays, but its meaning changed with STALL-ALERT-FALSE:
        a stall is EVIDENCE OF LOSS, not "the checkpoint has not moved". A checkpoint
        that stops moving while polls SUCCEED and the device returns nothing newer is
        a quiet door (night/lunch) — the checkpoint only moves on major=5 punches, so
        age alone is silence and must not page. Two shapes are evidence:

        * a stale checkpoint AND the last poll failed (no successful poll is proving
          the device has nothing newer);
        * the oldest serialNo rose since the previous check — DESIGN.md OQ4,
          "a monotonic increase of the minimum = rolling started = punches are being
          lost" (OBSERVED.md "Retention / gaps"). This store keeps everything, so its
          floor can only rise when already-stored history disappears: the same loss
          event seen from the near side.

        One page per incident: the frozen ``updated_at`` plus the evidence shape is
        the episode key; a further rise of the floor is a new incident. Silence for
        a device with NO checkpoint row: a fresh install is not a stalled one
        (P2-03's cold-start floor governs), and inventing an alert for the state
        every first boot passes through would train operators to ignore the one that
        matters.
        """
        if self.conn is None:
            return None
        checkpoint = read_checkpoint(self.conn, device_serial)
        if checkpoint is None:
            return None
        updated = _parse_iso(checkpoint.updated_at)
        threshold = timedelta(seconds=self.stall_strikes * self.cadence_s)
        age = (self.now() - updated).total_seconds()
        stale = self.now() - updated > threshold

        oldest = read_oldest_serial(self.conn, device_serial)
        previous_oldest = self._oldest_serial_seen.get(device_serial)
        self._oldest_serial_seen[device_serial] = oldest
        floor_moved = (
            oldest is not None and previous_oldest is not None and oldest > previous_oldest
        )

        failing = self._last_poll_status.get(device_serial) == "failed"
        if not (stale and failing) and not floor_moved:
            if not stale:
                # The checkpoint moved (or healed): close the episode so a LATER
                # stall is a new incident and pages fresh.
                self._stall_open_at.pop(device_serial, None)
            return None

        evidence = f"floor:{previous_oldest}->{oldest}" if floor_moved else "failing-poll"
        episode = f"{checkpoint.updated_at}|{evidence}"
        if self._stall_open_at.get(device_serial) == episode:
            return None  # already paged for exactly this incident
        self._stall_open_at[device_serial] = episode
        if floor_moved:
            note = (
                f"oldest serialNo rose {previous_oldest} -> {oldest} — the event-ring "
                "floor moved past stored history, so punches in that gap are LOST "
                "(OBSERVED.md 'Retention / gaps': a monotonic increase of the minimum "
                "= rolling started)"
            )
        else:
            note = (
                f"checkpoint unmoved for {age:.0f}s (k={self.stall_strikes} x cadence "
                f"{self.cadence_s}s) and the last poll FAILED — no successful poll is "
                f"proving the device has nothing newer, so punches may be lost "
                f"(last serial {checkpoint.checkpoint_serial})"
            )
        return self._fire(LEVEL_CRITICAL, KIND_CHECKPOINT_STALL, device_serial, note)

    # --- the warning channel: db watermark (§2b) --------------------------------------------

    def observe_watermark(self, check: WatermarkCheck) -> list[Alert]:
        """§2b: keep-everything store past the operator's watermark -> warning once."""
        if not check.warn:
            self._watermark_open = False
            return []
        if self._watermark_open:
            return []
        self._watermark_open = True
        return [
            self._fire(
                LEVEL_WARNING,
                KIND_DB_WATERMARK,
                None,
                f"agent db {check.size_bytes} bytes over watermark {check.warn_bytes} "
                "(keep-everything store — spec §2b)",
            )
        ]

    # --- internals --------------------------------------------------------------------------

    def _fire(self, level: str, kind: str, serial: str | None, note: str) -> Alert:
        alert = Alert(
            level=level,
            kind=kind,
            site=self.site,
            device_serial=serial,
            at=_iso(self.now()),
            note=note,
        )
        self.counters[kind] = self.counters.get(kind, 0) + 1
        self.sink(alert)
        return alert


@dataclass(frozen=True, slots=True)
class _GateNote:  # pragma: no cover - documentation carrier, not constructed in tests
    """Keeps the gate vocabulary in one place for P2-06 (healthz shows the reason)."""

    reason: str = ""


def guarded_tick(policy: AlertPolicy, loop: Any) -> Any:
    """The only way a P2 device should be ticked once this policy exists.

    P2-07's ``gateclerk agent run`` wraps the scheduler in this; tests call it
    directly. It is a thin, explicit seam (rather than a DeviceLoop monkey-patch)
    because the gate must hold at the ONE place the unit decides to knock on a
    device — and the park state is policy, not loop, business (P2-03 shipped
    untouched; the card's rule).

    Returns the ``TickResult``, or None when the gate refused the tick (the device
    was not touched at all — the served-count-frozen property the tests pin). A
    refused tick does NOT count as a tick failure: it is the policy working.
    """
    allowed, _reason = policy.attempt_allowed(loop.device_serial)
    if not allowed:
        return None
    result = loop.tick()
    policy.handle_tick(result, attempted=True)
    return result
