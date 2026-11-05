"""The P2 site agent's scheduler loop: 5 min cadence, 5 min overlap, one client.

Card P2-03 (docs/P2-SITE-AGENT.md §2a, DECIDED 2026-10-19; §1 seams 2/3/7/9). Device
truth: docs/OBSERVED.md. This module *orchestrates* — every hard rule lives in the P1
module that owns it and is reused untouched (seam 6, "reuse, do not fork"):

* `paging.iter_event_windows` — the p1-05c walk: chunking, the 0-based cursor, the
  advance-by-`numOfMatches` rule, `NO MATCH`-with-space termination, the runaway cap.
  `ChunkResult.max_serial_no` exists only for COMPLETED chunks (paging.py:612-615),
  which is what makes the checkpoint rule below enforceable.
* `pipeline.event_record_from_device` — the p1-07 assembly contract (27-key record,
  classification verdict, tz provenance verbatim from p1-06).
* `pipeline.read_device_identity` / `read_capabilities` / `device_window_labels` — the
  once-per-client bootstrap: the serial is half the store key, the caps clamp paging,
  and the device's claimed offset labels every window (seam 7: device-claimed labels
  or the WARNED site fallback, never silent, never naive).
* `isapi_transport.IsapiClient` — digest session, busy backoff, the 401 circuit. ONE
  client per device, kept alive across ticks (spec §2a: rebuilding per poll pays an
  extra handshake per cycle and hits the ~190-request nonce use-cap far sooner; OBSERVED.md).
* `agent_store` (P2-02) — `store_events` UPSERT (the overlap re-read is FREE),
  `advance_checkpoint` (completed-only, one UPSERT, never regresses), `read_checkpoint`.

The loop shape (card-pinned):

    window = [checkpoint_time - overlap_s, now]           (no checkpoint yet:
                                                           [now - (cadence+overlap), now])
    walk it through iter_event_windows, chunk by chunk;
    per COMPLETED chunk: store its records, THEN advance the checkpoint by the
    chunk's max serial + that record's device-local time.

The store-then-advance order per chunk is deliberate three ways: the checkpoint never
covers an unstored event (advance runs only after that chunk's `store_events`
committed); a kill between chunks leaves only fully-stored serials checkpointed
(advance itself is one UPSERT — P2-02 — so SIGTERM cannot halve it); and the overlap
makes every loss window healable, which is the whole P2-02 idempotency argument.

A failed tick is DATA, not an exception: `tick()` returns a `TickResult` carrying the
typed exception and a message for P2-05 to alert on (spec §2c keeps the channels
separate), and the checkpoint stays exactly where it was. A circuit the transport
opened (terminal 401 — lockout accounting, OBSERVED.md) parks the device: a skipped
tick sends ZERO requests, no hammering (seam 9).

Times are injected (`now` wall clock, `monotonic` for the transport/pacing seams):
tests drive whole days without a single real sleep, and the agent's systemd unit
reaches the same cadence through `run_forever(sleep=...)`.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from gateclerk.agent_db import connect
from gateclerk.agent_push import Transport as PushTransport
from gateclerk.agent_push import device_users_line
from gateclerk.agent_store import Checkpoint, advance_checkpoint, read_checkpoint, store_events
from gateclerk.config import DeviceTarget, resolve_credentials
from gateclerk.exceptions import IsapiError
from gateclerk.isapi_transport import IsapiClient
from gateclerk.paging import (
    DEFAULT_CHUNK,
    DEFAULT_INTER_PAGE_DELAY,
    ChunkResult,
    PagingLimits,
    iter_event_windows,
    oldest_serial_in_window,
)
from gateclerk.pipeline import (
    NOISE_MAJOR,
    device_window_labels,
    event_record_from_device,
    paging_limits_from_caps,
    read_capabilities,
)
from gateclerk.sinks import IMPLICIT_SINK_NAME, SinkSpec
from gateclerk.tz import TimeResolver, offset_hhmm

__all__ = [
    "DEFAULT_DEVICE_USERS_INTERVAL_S",
    "DeviceLoop",
    "DeviceUsersResult",
    "TickResult",
    "build_device_loop",
    "run_forever",
]

#: The cold-start floor for a device that has never checkpointed (design decision,
#: pinned by test): one cadence back plus the overlap margin. A fresh install reads
#: ~10 minutes of history — a full-history backfill is `gateclerk events`' job (CLI,
#: operator-invoked), not a systemd unit's first five minutes. The overlap margin on
#: top means the first window and the second one still overlap like every later pair.
_COLD_START_BACK = "cadence + overlap"


@dataclass(frozen=True, slots=True)
class TickResult:
    """What one tick did — the object P2-05 reads to decide whether to alert.

    `ok=False` comes in two shapes the alert policy separates (spec §2c): `skipped=True`
    (the circuit is open — the transport already decided a human must look at the
    credential; the device was NOT touched) and `skipped=False` with `exception` set
    (the walk failed — checkpoint unmoved, overlap will heal it).
    """

    device_serial: str | None
    ok: bool
    #: True only for a circuit-open skip: zero requests went out.
    skipped: bool = False
    #: The client's circuit state at tick start (the "parked" gauge for /healthz).
    circuit_open: bool = False
    error: str | None = None
    exception: Exception | None = None
    #: Window bookkeeping for metrics (spec §2e vocabulary).
    window_label: str = ""
    pages: int = 0
    records: int = 0
    #: Store outcomes across this tick's chunks ("free" overlap re-reads are `unchanged`).
    stored: int = 0
    inserted: int = 0
    refreshed: int = 0
    unchanged: int = 0
    #: The checkpoint after this tick (None when nothing ever advanced), and whether
    #: THIS tick moved it (a quiet tick re-reports the serial without churning).
    checkpoint_serial: int | None = None
    #: The checkpoint as it stood BEFORE this tick's first advance. The ring-floor
    #: probe (card t_ed9c7e92) must compare the device's oldest retained event with
    #: THIS serial: comparing with `checkpoint_serial` above would compare against a
    #: serial this very tick just walked, which no retained event can exceed.
    checkpoint_serial_before: int | None = None
    checkpoint_time_before: str | None = None
    advanced: bool = False
    #: Normalized termination of the LAST completed chunk's SearchSummary
    #: (paging.py:351) — the §2e `search_termination` observable: P2-06 reports it,
    #: so the loop hands it over instead of the health module re-walking anything.
    termination: str | None = None


def _default_warn(text: str) -> None:
    """The p1-05c precedent: a fallback warning goes to stderr, visibly, unasked."""
    from gateclerk.output import make_console  # local: keeps the module import cheap

    make_console(stderr=True).print(text, markup=False)


#: Task 15: the roster leg's cadence — "also push device-user list hourly" (card).
#: Deliberately decoupled from `cadence_s`: the punches poll every 5 min against the
#: ~190-use nonce budget, and a per-tick `UserInfo/Search` walk (paged, ~20/page per
#: OBSERVED.md) would spend that budget re-reading a list that only changes when
#: someone is enrolled. Hourly bounds the cost and still bounds the staleness of BC's
#: Nelegati view at one hour.
DEFAULT_DEVICE_USERS_INTERVAL_S = 3600


@dataclass(frozen=True, slots=True)
class SinkDelivery:
    """One sink's half of one roster push (SINKS-WIRING).

    Exists so the fan-out can report per-destination truth while `DeviceUsersResult` keeps
    the single-destination shape Task 15 shipped: a roster that reached the archive but not
    the ingest is a state an operator has to be able to see, and one blended status cannot
    say it. `error` is the exception CLASS plus a redacted message — never a payload, never
    a header (the bearer lives in the transport).
    """

    sink_name: str
    ok: bool
    status: int | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class DeviceUsersResult:
    """One roster push attempt (Task 15). Returned as DATA, like TickResult.

    A roster is RE-DERIVABLE from the device at any time; a punch is not. That asymmetry
    is why this leg deliberately does NOT go through `push_queue`/`dead_letter` (whose
    `event_id` is an FK to a stored event — a roster row has no event to point at) and
    why a failure is a warning plus a retry at the NEXT hourly slot, never a dead-letter.
    That law is now per sink too (SINKS-WIRING): one sink refusing the roster can never
    move a roster row into the queue tables.

    `ok`/`status` are Task 15's single-target shape and keep their meaning: `ok` is now
    "every sink that should have taken it did" and `status` is the first leg's answer (the
    site's own ingest), so pre-sinks readers see exactly what they saw before. `per_sink`
    is the fan-out's truth, in the config's declaration order.
    """

    ok: bool
    status: int | None
    users: int
    error: str | None = None
    per_sink: tuple[SinkDelivery, ...] = ()


class DeviceLoop:
    """One device, one long-lived client, one tick function.

    Constructed once per process (per `gateclerk-agent@<site>` unit, per device);
    `tick()` is safe to call on a timer, from tests, or from `run_forever`. All
    device state (identity, capabilities, claimed offset) is read lazily on the first
    tick that needs it and kept for the client's life — the amortization the cadence
    decision (§2a) is built on. Re-reading them per tick is the bug that pin avoids.
    """

    def __init__(
        self,
        *,
        client: IsapiClient,
        conn: Any,
        site: str,
        site_tz: str | None,
        device_tz: str | None = None,
        cadence_s: int,
        overlap_s: int,
        limits: PagingLimits | None = None,
        page_size: int | None = None,
        inter_page_delay: float = DEFAULT_INTER_PAGE_DELAY,
        chunk: str = DEFAULT_CHUNK,
        include_noise: bool = False,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        warn: Callable[[str], None] = _default_warn,
        push_target: str | None = None,
        push_transport: PushTransport | None = None,
        device_users_interval_s: int = DEFAULT_DEVICE_USERS_INTERVAL_S,
        device_code: str | None = None,
        roster: Callable[[], Any] | None = None,
        sinks: Sequence[SinkSpec] = (),
        sink_transports: Mapping[str, PushTransport] | None = None,
        sink_writers: Mapping[str, Any] | None = None,
    ) -> None:
        if cadence_s <= 0:
            raise ValueError(f"cadence_s {cadence_s} must be > 0 (config validated this)")
        if overlap_s < 0:
            raise ValueError(f"overlap_s {overlap_s} must be >= 0 (config validated this)")
        if device_users_interval_s <= 0:
            raise ValueError(
                f"device_users_interval_s {device_users_interval_s} must be > 0 "
                "(0 would roster on every tick — the nonce budget says otherwise)"
            )
        self.client = client
        self.conn = conn
        self.site = site
        self.site_tz = site_tz
        #: p1-12 owner decision carried into the agent: a declared `device_tz` is
        #: authoritative for RECORD resolution (the digits' real zone); the claimed
        #: offset keeps travelling as `tz_offset_min_device` provenance. Windows are
        #: still built in `site_tz` — site wall is the payroll truth (spec §2d).
        self.device_tz = device_tz
        self.cadence_s = cadence_s
        self.overlap_s = overlap_s
        self._limits = limits
        self._page_size = page_size
        self._inter_page_delay = inter_page_delay
        self._chunk = chunk
        self._include_noise = include_noise
        self._now = now
        self._monotonic = monotonic
        self._sleep = sleep
        self._warn = warn
        # --- Task 15: the hourly device-users leg (module doc; DeviceUsersResult doc) ----
        # None target = the site does not push at all (§3: no invented default), and both
        # roster methods are then honest no-ops rather than crashes.
        self.push_target = push_target
        self._push_transport = push_transport
        self.device_users_interval_s = device_users_interval_s
        #: BC page-70602 device code when the site declares one; otherwise the roster
        #: names the device by serial and the function resolves serial -> code.
        self.device_code = device_code
        #: Injectable so tests never walk a real `UserInfo/Search`; the default walks
        #: the loop's own long-lived client through the p1-05 paging engine (one client,
        #: spec §2a — the roster does not get a second session).
        self._roster = roster
        self._last_roster_push_at: datetime | None = None
        # --- SINKS-WIRING: the roster fan-out ------------------------------------------------
        #: The site's sinks (SINKS-CORE's specs). EMPTY for the pre-sinks shape, which is the
        #: upgrade-inert case: `push_target` + `push_transport` alone still roster exactly as
        #: Task 15 shipped them, through the single legacy path below.
        self.sinks = tuple(sinks)
        #: Per-sink transports for the https legs (injected; keyed by sink NAME).
        self._sink_transports: dict[str, PushTransport] = dict(sink_transports or {})
        #: Per-sink file writers for the csv/jsonl legs. A writer is not a `Transport` in the
        #: roster's sense (the roster row goes to a companion table, not the punch stream), so
        #: it is a separate seam rather than a value crammed into `_sink_transports`.
        self._sink_writers: dict[str, Any] = dict(sink_writers or {})
        # Bootstrap state: read once per client, never per tick (spec §2a math).
        self.device_serial: str | None = None
        self._caps: Any = None
        self._claim: int | None = None
        self._claim_note: str | None = None
        self._bootstrapped = False

    # --- the tick -----------------------------------------------------------------------

    def tick(self) -> TickResult:
        """One poll cycle: window -> walk -> store -> checkpoint. Never raises.

        The two refusal paths are the card's, both returned as data:

        * circuit open at tick start -> `skipped` result, ZERO requests (seam 9's
          "never hammer" while the transport is parked on a terminal 401);
        * anything the walk/transport/store raises mid-tick -> failed result carrying
          the typed exception, checkpoint UNMOVED (advance only ever runs on a
          COMPLETED chunk that has already been stored).
        """
        if self.client.circuit_open():
            return TickResult(
                device_serial=self.device_serial,
                ok=False,
                skipped=True,
                circuit_open=True,
                error="auth circuit open — device parked, no request sent (P2-05 alert channel)",
            )
        since, until = None, None
        before: Checkpoint | None = None
        try:
            self._ensure_device_state()
            if self.device_serial is None:  # pragma: no cover - _ensure raises otherwise
                raise IsapiError("bootstrap completed without a device serial")
            # Capture the checkpoint BEFORE the per-chunk advances below. The ring-floor
            # probe (card t_ed9c7e92) compares the device's oldest retained event with
            # this value: after the walk there is nothing retained above the advanced
            # checkpoint by construction, so using the post-tick serial would make the
            # arm dead (and a late arrival would look like loss).
            before = read_checkpoint(self.conn, self.device_serial)
            since, until = self._window()
            counts = _WalkCounts()
            advanced = False
            checkpoint_serial: int | None = None
            for chunk_result in self._walk(since, until):
                records = self._assemble(chunk_result)
                stored, inserted, refreshed, unchanged = self._store_chunk(records)
                counts.absorb(chunk_result, stored, inserted, refreshed, unchanged, len(records))
                advance = advance_checkpoint(
                    self.conn,
                    self.device_serial,
                    chunk_result.max_serial_no,
                    completed=True,  # a yielded chunk IS completed (paging.py:612-615)
                    checkpoint_time=_device_time_of(chunk_result),
                    now=self._now(),
                )
                advanced = advanced or advance.advanced
                if advance.checkpoint_serial is not None:
                    # Explicit None check: serial 0 is legitimate (serialNo counts up
                    # from 0; agent_store only refuses negatives) — `or` would drop it.
                    checkpoint_serial = advance.checkpoint_serial
            checkpoint = read_checkpoint(self.conn, self.device_serial)
            return TickResult(
                device_serial=self.device_serial,
                ok=True,
                window_label=self._label(),
                pages=counts.pages,
                records=counts.records,
                stored=counts.stored,
                inserted=counts.inserted,
                refreshed=counts.refreshed,
                unchanged=counts.unchanged,
                checkpoint_serial=(
                    checkpoint_serial
                    if checkpoint_serial is not None
                    else (checkpoint.checkpoint_serial if checkpoint else None)
                ),
                checkpoint_serial_before=(before.checkpoint_serial if before else None),
                checkpoint_time_before=(before.checkpoint_time if before else None),
                advanced=advanced,
                termination=counts.termination,
            )
        except Exception as exc:
            return self._failure(exc, since=since, until=until)

    def probe_ring_floor(self, since_stamp: str) -> int | None:
        """One read-only AcsEvent page: the oldest event of ANY major still retained.

        The device ring is shared by punches and the 1/min major=3 noise, and serialNo
        is device-wide. The signal is therefore the oldest retained event of ANY major
        in the *unread* window that starts at the pre-advance checkpoint time: a floor
        above ``checkpoint_serial + 1`` means events after that checkpoint were evicted
        before this agent read them, so punches in that serial range may be lost. A
        punch-only floor would miss the case where the evicted rows were noise and the
        ring moved while the agent was down.

        Window: ``[the pre-advance checkpoint's device-local stamp, now]``. The caller
        captures that checkpoint before the tick walks and advances it; passing the
        post-tick one would make the comparison dead by construction. The device
        answers oldest-first, so ``maxResults=1`` is the floor with one POST (no cursor
        walk). A floor AT the checkpoint (or one serial past it: the next event, which
        the walk may just have read) proves nothing was evicted.

        Deliberately silent on failure: the alert path must bend, never break — a failed
        probe is "no evidence this incident", and the failing-poll arm still speaks.
        The caller decides when it is worth asking. A parked/skipped device is never
        asked because only an ok tick offers this callable.
        """
        if self.device_serial is None or self.conn is None:
            return None
        try:
            # The checkpoint stamp is device wall digits; p1-05c's TimeResolver
            # localizes them in the SITE zone (the claim may be the known +02/+03
            # lie), exactly like the poll's own window floor.
            since = _parse_stamp(since_stamp, site_tz=self.site_tz)
            until = self._now()
            if until.tzinfo is None or since >= until:
                return None
            limits = self._limits or (
                paging_limits_from_caps(self._caps) if self._caps is not None else PagingLimits()
            )
            oldest = oldest_serial_in_window(
                _search_reader(self.client),
                since=since,
                until=until,
                site_tz=self.site_tz,
                device_offset_min=self._claim,
                major=0,
                limits=limits,
                inter_page_delay=self._inter_page_delay,
                sleep=self._sleep,
                clock=self._monotonic,
            )
        except Exception as exc:  # the alert path must never raise
            self._warn(
                f"warning: device ring-floor probe failed ({type(exc).__name__}); "
                "checkpoint_stall has no device-floor evidence this incident"
            )
            return None
        return None if oldest is None else oldest.serial_no

    def close(self) -> None:
        """Release the client's socket pool and the db connection (unit shutdown)."""
        self.client.close()
        self.conn.close()

    # --- the hourly device-users leg (Task 15) ------------------------------------------------

    def push_device_users_if_due(self) -> DeviceUsersResult | None:
        """The loop's roster leg: push when the hour is up, otherwise a no-op (None).

        The clock is the loop's injected wall clock (same instant the windows are built
        from), so a test drives whole days without sleeping. `tick()` never calls this:
        the roster cadence (§2a's nonce-budget argument) is a separate hour-clock from
        the 5-minute punch cadence, and only `run_forever`'s per-cycle step — or an
        operator's explicit call — pulls it.

        The clock gates the WHOLE fan-out, not each sink: one hour-clock per loop is the
        request-budget promise (an hourly roster to N sinks is still one roster walk), so a
        call inside the hour is a no-op for EVERY sink.
        """
        if not self._roster_wired():
            return None
        moment = self._now()
        if self._last_roster_push_at is not None:
            elapsed = (moment - self._last_roster_push_at).total_seconds()
            if elapsed < self.device_users_interval_s:
                return None
        return self.push_device_users()

    def _roster_wired(self) -> bool:
        """Can this loop roster at all? (Both Task 15's shape and the fan-out's.)

        The pre-sinks shape needs a target AND a transport; the sink shape needs at least one
        sink the loop can actually reach (a transport for an https sink, a writer for a file
        sink). Anything else returns False so both roster methods are honest no-ops rather
        than crashes — a loop with no way to deliver must not burn its hour-clock pretending.
        """
        if self.sinks:
            return any(
                self._sink_transport_for(sink) is not None
                or self._sink_writers.get(sink.name) is not None
                for sink in self.sinks
                if sink.accepts_roster
            )
        return self.push_target is not None and self._push_transport is not None

    def push_device_users(self) -> DeviceUsersResult | None:
        """One roster push over the site's authenticated push channel; None if not wired.

        Deliberately NOT the queue: `push_queue.event_id` is an FK to a stored event and
        a roster is not an event (module's DeviceUsersResult docstring for the full
        asymmetry). Failure is warn-and-retry-next-hour — a roster the ingest never got
        is refreshed by the next hour's walk, while a punch that never got there is a
        payroll row nobody else can re-derive, which is why only punches dead-letter.
        SINKS-WIRING moves that law nowhere: a roster still cannot enter the queue tables,
        it simply reaches N destinations instead of one.

        Never raises: like `tick()`, everything that can go wrong comes back as data.
        The warning line carries the exception CLASS and a redacted message, never any
        header — the bearer lives in the transport and this module never sees its value.

        The fan-out walks the sinks in config order and delivers to each one that accepts
        rosters, so a file sink gets the roster even while the ingest 502s (per-sink
        warn-and-retry, DoD (d)); `ok` is the AND across the legs and `status` is the first
        leg's answer, keeping Task 15's shape for a single-destination site.
        """
        if not self._roster_wired():
            return None
        # Mark the attempt (not the success) as the clock anchor: a failing ingest must
        # not be re-hit every tick by a loop that treats "never succeeded" as "always
        # due" — the hourly bound is a request-budget promise, not a success promise.
        self._last_roster_push_at = self._now()
        try:
            users = self._read_roster()
            line = device_users_line(
                device_code=self.device_code or self._device_identity(),
                users=users,
            )
        except Exception as exc:  # the leg converts everything to data, like tick()
            self._warn(
                f"warning: device-users roster push failed ({type(exc).__name__}); "
                f"site={self.site} next attempt in {self.device_users_interval_s}s"
            )
            return DeviceUsersResult(
                ok=False,
                status=None,
                users=0,
                error=f"{type(exc).__name__}: {exc}",
            )
        if not self.sinks:
            return self._roster_legacy(line, users=len(users))
        return self._roster_fanout(line, users=len(users))

    def _roster_legacy(self, line: str, *, users: int) -> DeviceUsersResult:
        """Task 15's single-destination roster, unchanged in shape and in its warn text.

        The one remaining path for a site that declares `push_target` and no sinks, so the
        upgrade-inert assertions (status, warn wording, keychain hint) keep applying
        verbatim — the fan-out below reuses this for the implicit sink's own leg.
        """
        if self.push_target is None or self._push_transport is None:  # wiring bug, not config
            raise RuntimeError(
                f"site {self.site}: the legacy roster leg needs a push_target and its "
                "transport — reach here only from the no-sinks path of push_device_users"
            )
        try:
            status = self._push_transport(self.push_target, line)
        except Exception as exc:
            self._warn(
                f"warning: device-users roster push failed ({type(exc).__name__}); "
                f"site={self.site} next attempt in {self.device_users_interval_s}s"
            )
            return DeviceUsersResult(
                ok=False,
                status=None,
                users=users,
                error=f"{type(exc).__name__}: {exc}",
                per_sink=(
                    SinkDelivery(
                        sink_name=IMPLICIT_SINK_NAME,
                        ok=False,
                        error=f"{type(exc).__name__}: {exc}",
                    ),
                ),
            )
        result = DeviceUsersResult(
            ok=200 <= status < 300,
            status=status,
            users=users,
            per_sink=(
                SinkDelivery(sink_name=IMPLICIT_SINK_NAME, ok=200 <= status < 300, status=status),
            ),
        )
        if not result.ok:
            # A 401/403 here is the same keychain-shaped problem a 401 on punches is;
            # naming the keychain item turns journald into the fix instruction.
            hint = (
                f" check the ingest token keychain item gateclerk-ingest-{self.site}."
                if status in (401, 403)
                else ""
            )
            self._warn(
                f"warning: device-users roster push answered HTTP {status}; "
                f"site={self.site} users={result.users}{hint}"
            )
        return result

    def _roster_fanout(self, line: str, *, users: int) -> DeviceUsersResult:
        """Deliver one roster line to every sink that accepts it — independently, loudly.

        Per-sink isolation is the point (DoD (d)): each leg is wrapped, so a sink that raises
        or answers 5xx warns with ITS name and ITS status and cannot stop the next sink's
        write. A file sink's roster row goes to its companion table (`write_roster`), a
        jsonl sink's is the line verbatim, and the https leg is byte-identical to Task 15's —
        one roster, N destinations, one wire shape.
        """
        moment = self._now()
        deliveries: list[SinkDelivery] = []
        for sink in self.sinks:
            if not sink.accepts_roster:
                continue
            try:
                deliveries.append(self._roster_one(sink, line, moment=moment))
            except Exception as exc:  # a broken sink must not stop the others
                self._warn(
                    f"warning: device-users roster sink={sink.name} failed "
                    f"({type(exc).__name__}); site={self.site} next attempt in "
                    f"{self.device_users_interval_s}s"
                )
                deliveries.append(
                    SinkDelivery(
                        sink_name=sink.name,
                        ok=False,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                )
        if not deliveries:
            # Nothing accepted the roster (every sink opted out, or none is reachable): the
            # honest answer is not-ok, not an empty success.
            return DeviceUsersResult(ok=False, status=None, users=users, per_sink=())
        first = deliveries[0]
        return DeviceUsersResult(
            ok=all(d.ok for d in deliveries),
            status=first.status,
            users=users,
            per_sink=tuple(deliveries),
        )

    def _roster_one(self, sink: SinkSpec, line: str, *, moment: datetime) -> SinkDelivery:
        """One sink's roster leg (raises are the caller's to fold into a delivery)."""
        writer = self._sink_writers.get(sink.name)
        if writer is not None:
            from gateclerk.sink_writers import roster_stamp  # local: sink_writers owns the stamp

            if sink.type == "csv":
                body = writer.render_roster(
                    line,
                    {"sink_name": sink.name, "enqueued_at": roster_stamp(moment)},
                )
                status = writer.write_roster(body, moment=moment)
            else:
                status = writer.write_line(line, moment=moment)
            ok = 200 <= status < 300
            if not ok:
                self._warn(
                    f"warning: device-users roster sink={sink.name} answered HTTP {status}; "
                    f"site={self.site}"
                )
            return SinkDelivery(sink_name=sink.name, ok=ok, status=status)
        transport = self._sink_transport_for(sink)
        if transport is None:
            raise IsapiError(
                f"sink {sink.name!r} ({sink.type}) has no transport or writer wired: the "
                "agent builds one from the sink spec, so a loop that reaches this line was "
                "constructed without the sink's delivery seam"
            )
        status = transport(sink.ref, line)
        ok = 200 <= status < 300
        if not ok:
            hint = (
                f" check the ingest token keychain item gateclerk-ingest-{self.site}."
                if status in (401, 403)
                else ""
            )
            self._warn(
                f"warning: device-users roster push answered HTTP {status}; "
                f"sink={sink.name} site={self.site}{hint}"
            )
        return SinkDelivery(sink_name=sink.name, ok=ok, status=status)

    def _sink_transport_for(self, sink: SinkSpec) -> PushTransport | None:
        """The injected transport for one https sink, or the site's shared one.

        Keyed by sink NAME (the identity): two sinks aimed at one ref are two delivery
        obligations and must not silently share one leg's outcome. A file sink has no
        transport here by design — its writer is the delivery seam.
        """
        injected = self._sink_transports.get(sink.name)
        if injected is not None:
            return injected
        if sink.type == "https" and sink.ref == self.push_target:
            return self._push_transport
        return None

    def _device_identity(self) -> str:
        """What the roster names the device with when no `device_code` is configured.

        The function resolves serial -> code through `gateclerkDevices` and accepts either,
        so the loop's own serial (read once per client, bootstrap) is legal and free. An
        un-bootstrapped loop has nothing honest to name — refusing (via the exception
        path of `push_device_users`) beats sending an empty `deviceCode`, which the
        function answers 400 `invalid_user_line` for.
        """
        if self.device_serial:
            return self.device_serial
        raise IsapiError(
            "cannot roster before the device serial is known: run a tick first (the "
            "bootstrap reads deviceInfo once per client) or configure device_code"
        )

    def _read_roster(self) -> list[Any]:
        """The device-user list, through the loop's ONE client (injectable seam).

        Default: p1-05's `iter_users` over `UserInfo/Search` on the existing digest
        session (a second client would double the session/nonce cost spec §2a exists to
        avoid), mapped through p1-07's `user_record_from_device` — which is where the
        device `password` hash is stripped, so the roster leg inherits the redaction
        rather than re-implementing it (seam 6: reuse, do not fork).
        """
        if self._roster is not None:
            return list(self._roster())
        from gateclerk.paging import PagingLimits, iter_users
        from gateclerk.pipeline import user_record_from_device

        limits = self._limits or (
            paging_limits_from_caps(self._caps) if self._caps is not None else PagingLimits()
        )
        reader = _search_reader(self.client, "user_info_search")
        return [user_record_from_device(raw) for raw in iter_users(reader, limits=limits)]

    # --- internals ----------------------------------------------------------------------

    def _failure(self, exc: Exception, *, since: Any, until: Any) -> TickResult:
        checkpoint = read_checkpoint(self.conn, self.device_serial) if self.device_serial else None
        circuit_open = self.client.circuit_open()
        # The transport already opened the circuit on a terminal 401 (lockout
        # accounting — OBSERVED.md); the loop neither hides that nor adds retries.
        message = f"{type(exc).__name__}: {exc}"
        return TickResult(
            device_serial=self.device_serial,
            ok=False,
            circuit_open=circuit_open,
            error=message,
            exception=exc,
            window_label=self._label(),
            checkpoint_serial=checkpoint.checkpoint_serial if checkpoint else None,
        )

    def _ensure_device_state(self) -> None:
        """The once-per-client bootstrap: identity, caps, claimed window label.

        `read_capabilities` (pipeline → p1-04 discover) does its OWN deviceInfo read
        for the cache key and carries the serial on the result — so the serial comes
        from there rather than a second `read_device_identity` GET: every request
        counts against the ~190-use nonce cap (spec §2a math). A blank serial is
        refused (the store key cannot be honoured; pipeline's own rule). The claimed
        offset is read exactly once per client (device_window_labels' rule: re-reads
        spend requests against the cap for an answer that does not change).
        """
        if self._bootstrapped:
            return
        caps = read_capabilities(self.client)
        if not caps.serial:
            raise IsapiError(
                "deviceInfo carried no serialNumber — the store key (device_serial, "
                "serial_no) cannot be honoured; refusing to store records with a blank serial"
            )
        labels = device_window_labels(self.client)
        self.device_serial = caps.serial
        self._caps = caps
        self._claim = labels.claimed_offset_min
        self._claim_note = labels.note
        self._bootstrapped = True

    def _window(self) -> tuple[datetime, datetime]:
        """`[checkpoint_time - overlap_s, now]`, or the cold-start floor (module doc).

        `checkpoint_time` is the device-local stamp the last advance carried verbatim
        (DESIGN.md's `last_event_time_local`). An offset-bearing stamp parses to an
        INSTANT and the overlap subtracts from the instant — the site-wall relabeling
        for the wire happens inside `window_for_device`, exactly as for the CLI's
        --since. A naive stamp (a box that stamps no offset) is read as site wall, the
        CLI's own rule for naive input.
        """
        if self.device_serial is None:  # pragma: no cover - tick() checks first
            raise IsapiError("window built before the device serial was read")
        now = self._now()
        if now.tzinfo is None:
            raise IsapiError("the loop's clock must return a tz-aware datetime (payroll data)")
        checkpoint = read_checkpoint(self.conn, self.device_serial)
        lower = _checkpoint_floor(
            checkpoint,
            cadence_s=self.cadence_s,
            overlap_s=self.overlap_s,
            now=now,
            site_tz=self.site_tz,
        )
        return lower, now

    def _walk(self, since: datetime, until: datetime) -> Any:
        """The P1 walk, with the P1 labels (seam 7). Yields COMPLETED chunks only."""
        if self._claim is None and self._claim_note is not None:
            # The p1-05c fallback: site-labeled digits are a KNOWN-RISKY shape; say it
            # every tick (the agent's "run" is its life, and a silent warning line is
            # no line at all). Never an invented offset, never naive.
            self._warn(
                f"warning: window labeled {until.isoformat()[-6:]}; device arithmetic "
                f"may shift boundaries — device time unreadable ({self._claim_note}). "
                "Events near a window edge may be silently missing (OBSERVED.md)."
            )
        limits = self._limits or (
            paging_limits_from_caps(self._caps) if self._caps is not None else PagingLimits()
        )
        return iter_event_windows(
            _search_reader(self.client),
            since=since,
            until=until,
            chunk=self._chunk,
            site_tz=self.site_tz,
            device_offset_min=self._claim,
            limits=limits,
            page_size=self._page_size,
            inter_page_delay=self._inter_page_delay,
            sleep=self._sleep,
            clock=self._monotonic,
            major=0 if self._include_noise else 5,
            minor=0,
        )

    def _assemble(self, chunk_result: ChunkResult) -> list[Any]:
        """Raw chunk records -> 27-key EventRecords, noise dropped client-side.

        Same double-filter rule as `pipeline.fetch_events`: `major=5` goes to the
        device AND `major==3` is dropped here, because OBSERVED.md's filter-truth
        section proves this firmware silently ignores server filters it has not
        advertised — a heartbeat stream must not slip back in through that hole.
        """
        resolve_tz = self.device_tz or self.site_tz
        records = []
        for raw in chunk_result.records:
            record = event_record_from_device(
                raw,
                site=self.site,
                device_serial=self.device_serial or "",
                site_tz=resolve_tz,
                capabilities=self._caps,
                captured_at=self._now(),
            )
            if record.major == NOISE_MAJOR and not self._include_noise:
                continue
            records.append(record)
        return records

    def _store_chunk(self, records: list[Any]) -> tuple[int, int, int, int]:
        """Store one completed chunk; return (stored, inserted, refreshed, unchanged).

        `unchanged` is the card's "overlap re-read was FREE" counter. The
        compare-before-write exists because the overlap re-fetch produces records that
        are byte-identical to the stored rows EXCEPT `captured_at` — stamped when THIS
        process saw the event — and the frozen 27-key contract puts `captured_at`
        inside the jsonl line. Blindly re-storing would flip the P2-02 guard true on
        every overlap poll: a revision bump every 5 minutes, the "store that lies
        about which records were ever corrected" agent_store exists to refuse. A row
        whose content GENUINELY differs (tz remap via p1-12 `device_tz`, a firmware
        change altering `raw`, a first-seen row) still goes through the UPSERT and
        refreshes; the SQL guard remains the backstop for anything this misses.
        """
        if self.device_serial is None:  # pragma: no cover - tick() checked before any chunk
            raise IsapiError("chunk stored before the device serial was read")
        if not records:
            return 0, 0, 0, 0
        fresh = []
        skipped = 0
        for record in records:
            # Static SQL, indexed point lookup (events_key covers both columns): the
            # overlap pages are ~10-20 rows (§2a math), so a per-row probe beats any
            # dynamic IN-list (and any reason for ruff's S608 to exist here).
            row = (
                self.conn.execute(
                    "SELECT jsonl FROM events WHERE device_serial = ? AND serial_no = ?",
                    (self.device_serial, record.serial_no),
                ).fetchone()
                if record.serial_no is not None
                else None
            )
            stored = row["jsonl"] if row is not None else None
            if stored is not None and _is_free_reread(stored, record):
                skipped += 1  # identical bytes already durable (first-seen stamp kept)
                continue
            fresh.append(record)
        result = store_events(self.conn, fresh, now=self._now())
        unchanged = skipped + result.unchanged
        stored_count = result.inserted + result.refreshed + unchanged
        return stored_count, result.inserted, result.refreshed, unchanged

    def _label(self) -> str:
        """The same label vocabulary pipeline.fetch_events logs (metrics, spec §2e)."""
        if self._claim is None:
            return "site (fallback)"
        return f"device-claimed {offset_hhmm(self._claim)}"


@dataclass
class _WalkCounts:
    """Tick-wide roll-up of the per-chunk walk + store results (metrics §2e)."""

    pages: int = 0
    records: int = 0
    stored: int = 0
    inserted: int = 0
    refreshed: int = 0
    unchanged: int = 0
    #: Termination of the LAST completed chunk — the §2e `search_termination` value.
    termination: str | None = None

    def absorb(
        self,
        chunk: ChunkResult,
        stored: int,
        inserted: int,
        refreshed: int,
        unchanged: int,
        n_records: int,
    ) -> None:
        self.pages += chunk.pages
        self.records += n_records
        self.stored += stored
        self.inserted += inserted
        self.refreshed += refreshed
        self.unchanged += unchanged
        self.termination = chunk.termination  # last completed chunk wins


def _search_reader(client: Any, endpoint: str = "acs_event_search") -> Any:
    """paging's PageReader over the client (same shape pipeline._search_reader uses).

    Kept local rather than imported from pipeline because the engine contract here is
    one lambda; pipeline owns the registry assertion in its own reader for the CLI, and
    `iter_event_windows` only ever POSTs the AcsEvent search POST in the registry.
    Task 15 passes `user_info_search` for the roster walk — the SAME client, the
    registry name of the other endpoint (endpoints.py owns both shapes).
    """

    def read(body: Mapping[str, Any]) -> dict[str, Any]:
        return client.search(endpoint, body)

    return read


def _is_free_reread(stored_jsonl: str, record: Any) -> bool:
    """True when the stored line IS this record — the overlap re-read, free by design.

    Compares the two contract dicts with `captured_at` removed from both: that field
    is when THIS process first saw the event, so a re-fetch legitimately differs on it
    while the device truth (every other key) is identical. Keeping the stored row's
    original first-seen stamp is the point: `stored_at`/`captured_at` stay honest
    "first contact" values (agent_store's own rule). Any other difference — tz fields
    after a p1-12 remap, `raw` after a fw change, an employee_no the classifier reads
    differently — makes this False and the UPSERT refreshes the row.

    A stored line that will not parse is treated as a real difference (go through the
    UPSERT; the SQL guard is the backstop, and a loud revision bump for a corrupt row
    is better than silently keeping it).
    """
    try:
        stored = json.loads(stored_jsonl)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False
    if not isinstance(stored, dict):
        return False
    fresh = record.to_dict()
    return {k: v for k, v in stored.items() if k != "captured_at"} == {
        k: v for k, v in fresh.items() if k != "captured_at"
    }


def _device_time_of(chunk_result: ChunkResult) -> str | None:
    """The device-local stamp of the record that carries the chunk's max serial.

    DESIGN.md's checkpoint tuple is `(last_serial_no, last_event_time_local)` — the
    time travels VERBATIM from the device record (its claimed offset included), never
    re-derived: the next tick's window floor parses exactly this string, and the
    fake/device round-trip (tests/test_p2_03_scheduler.py, DoD 3) pins that pairing.
    """
    if chunk_result.max_serial_no is None:
        return None
    for raw in chunk_result.records:
        serial = raw.get("serialNo")
        if isinstance(serial, int) and serial == chunk_result.max_serial_no:
            value = raw.get("time")
            if isinstance(value, str) and value.strip():
                return value.strip()
            return None
    return None


def _checkpoint_floor(
    checkpoint: Checkpoint | None,
    *,
    cadence_s: int,
    overlap_s: int,
    now: datetime,
    site_tz: str | None,
) -> datetime:
    """Window lower bound: `checkpoint_time - overlap`, or the cold-start floor.

    Cold start (no checkpoint row, or a row whose time was never carried) reads back
    `cadence + overlap`: two adjacent windows still overlap (the seam-3 invariant),
    and a fresh install's first tick sees roughly "the last poll's worth" of events.
    Full backfill stays the CLI's job (module doc).
    """
    if checkpoint is None or not checkpoint.checkpoint_time:
        return now - timedelta(seconds=cadence_s + overlap_s)
    return _parse_stamp(checkpoint.checkpoint_time, site_tz=site_tz) - timedelta(seconds=overlap_s)


def _parse_stamp(stamp: str, *, site_tz: str | None) -> datetime:
    """A checkpoint_time stamp -> an INSTANT, through P1's event-time policy.

    `TimeResolver` (p1-06) is reused, not `parse_user_timestamp`, and the difference
    is the whole p1-05c lesson: `parse_user_timestamp` would HONOUR the stamp's
    trailing +02:00 — the claim OBSERVED.md proves site-a stamps wrong — and shift the
    window floor by an hour, silently. `TimeResolver.resolve` treats the wall DIGITS
    as the truth and localizes them in the site zone (the claimed offset travels on
    as provenance only), exactly as every event `time` is resolved. A naive stamp (the
    `naive_time` box) localizes the same way; an unparseable stamp is corruption (or
    a firmware that changed time formats mid-history): the tick fails loudly, the
    checkpoint is untouched, and the overlap keeps every window in between healable.
    """
    resolved = TimeResolver(site_tz=site_tz).resolve(stamp)
    if resolved.utc is None:
        raise IsapiError(
            f"checkpoint_time {stamp!r} cannot become a window floor: "
            f"{resolved.reason or 'unresolvable'} — refusing to guess the overlap floor"
        )
    return resolved.utc


def run_forever(
    loop: DeviceLoop,
    *,
    sleep: Callable[[float], None] = time.sleep,
    max_ticks: int | None = None,
) -> list[TickResult]:
    """The scheduler seam: tick, roster-if-due, sleep(cadence), repeat. No clock touch.

    The systemd unit runs this (or P2-07's CLI wrapper does); tests hand it a recorder
    and a tick cap and finish in milliseconds. A failed tick does NOT stop the loop —
    the overlap heals it on the next one, and the alerting decision is P2-05's reading
    of the returned results, not an exception that kills the unit.

    Task 15: each cycle also pulls the loop's hourly roster step. It is a no-op (None)
    for a loop with no push wiring and for every cycle before the hour is up, so an
    unconfigured site's behaviour is byte-identical to before; when it does run, the
    `DeviceUsersResult` is deliberately not collected into the TickResult list — the
    roster leg reports through `warn` (journald) and BC's own Nelegati view, not
    through the punch metrics P2-05/P2-06 read.
    """
    results: list[TickResult] = []
    ticks = 0
    while max_ticks is None or ticks < max_ticks:
        results.append(loop.tick())
        loop.push_device_users_if_due()
        ticks += 1
        if max_ticks is not None and ticks >= max_ticks:
            break
        sleep(float(loop.cadence_s))
    return results


def build_device_loop(
    site: Any,
    *,
    conn: Any | None = None,
    client: IsapiClient | None = None,
    now: Callable[[], datetime] | None = None,
    monotonic: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
    warn: Callable[[str], None] | None = None,
    env: Mapping[str, str] | None = None,
    keychain: Any = None,
    push_transport: PushTransport | None = None,
) -> DeviceLoop:
    """Wire one `SiteConfig` (P2-01's schema) into a running loop. No socket opens here.

    The credential arrives through P1's resolver (flag>env>keychain; spec §2d: the
    config carries refs only, values resolve per host — `GATECLERK_<HOST>_PASSWORD` or
    the keychain item on a macOS box, systemd `LoadCredential=` on an agent host).
    `db_path_resolved` is P2-01's derived `./gateclerk-<site>.sqlite3` when unset.

    Task 15: when the site declares a `push_target`, the loop also gets the hourly
    roster leg wired — the target as configured (never defaulted), the injected
    transport (the bearer lives THERE, per site; this function never sees a token),
    and the optional `device_code` the BC registry knows the device by.
    """
    db = conn if conn is not None else connect(site.db_path_resolved)
    if client is None:
        creds = resolve_credentials(
            DeviceTarget(
                host=site.host,
                port=site.port,
                site=site.name,
                keychain_service=site.keychain_service,
                config_user=site.isapi_user,
            ),
            env=env,
            keychain=keychain,
        )
        client = IsapiClient(
            f"http://{site.host}:{site.port}",
            creds.user,
            creds.password.reveal(),
            read_timeout=site.timeout_s,
        )
    kwargs: dict[str, Any] = {}
    if now is not None:
        kwargs["now"] = now
    if monotonic is not None:
        kwargs["monotonic"] = monotonic
    if sleep is not None:
        kwargs["sleep"] = sleep
    if warn is not None:
        kwargs["warn"] = warn
    if getattr(site, "push_target", None) is not None:
        kwargs["push_target"] = site.push_target
        kwargs["push_transport"] = push_transport
        kwargs["device_code"] = getattr(site, "device_code", None)
    return DeviceLoop(
        client=client,
        conn=db,
        site=site.name,
        site_tz=site.iana_tz,
        device_tz=site.device_tz,
        cadence_s=site.cadence_s,
        overlap_s=site.overlap_s,
        inter_page_delay=site.page_delay_ms / 1000.0,
        **kwargs,
    )
