"""The P2 agent's own commands: `gateclerk agent run | ack | deadletter` (card P2-07b).

Thin wiring, deliberately. Every rule in here belongs to the module that shipped it and is
*imported*, not re-expressed: the cadence and the walk (P2-03 `agent_loop`), the UPSERT and
the checkpoint (P2-02 `agent_store`), the queue, the backoff and the dead letter (P2-04
`agent_push`), the park and the re-probe grid (P2-05 `agent_alert`), the health vocabulary
(P2-06 `agent_health`), and the site block / credential rungs (P2-01 `config`). What this
module owns is the ORDER of one pass and the seams a caller needs to drive it
deterministically:

    gate (P2-05) -> tick (P2-03: window -> walk -> store -> checkpoint)
                 -> health observe (P2-06) -> watermark (P2-05 + P2-02)
                 -> queue (below) -> drain (P2-04) -> health snapshot export (P2-06)

`cli.py` gains the `agent` subcommand group and nothing else — existing command bodies are
untouched (the card's rule) — and every piece of logic that would otherwise sit in a command
body lives here, importable and testable without the CLI.

THE CLOCK SEAM (the thing that wedged the last attempt — decided here, not re-derived)
--------------------------------------------------------------------------------------
One clock, injected once, threaded everywhere: `_now()` is the module-level indirection the
CLI falls back to (the same shape `cli._now()` is, so freezing the agent's clock is one
monkeypatch), and `build_site_agent(now=...)` hands the SAME callable to every
`build_device_loop`, to `AlertPolicy`, to `AgentHealthCollector` and to `SiteAgent`, which
passes its own reading of it to `queue_new_events` and to `drain` as `now`. So `--once` is
fully deterministic against `FakeDevice`: seed events whose wall digits are COMPUTED from
that injected now through the fake's `claimed_offset_min` (wall = UTC + claimed), and the
window the loop builds is the window the fake's arithmetic answers. No test sleeps and no
test opens a socket.

What the queue step is, and why it is here
------------------------------------------
P2-04's `drain` pushes what is *queued*, and nothing in the shipped code queued what the
poll *stored*. `queue_new_events` closes that gap without editing P2-04. The dead-letter
exclusion in its query is load-bearing, not tidy: a dead-lettered row's queue buffer was
deleted *because* the 24 h bound expired, so a naive "not in push_queue" query would
re-enqueue it on the next pass and restart the failure clock on a poison event forever (§2b:
a dead letter leaves the table only through the owner's `agent deadletter delete`).

The health snapshot export
--------------------------
P2-06 ships the collector and the JSON round trip and names this card as the writer
(`snapshot_to_json`: "the sidecar write ... P2-07's socat reads state written by the agent
loop"). `run` therefore writes `<state dir>/health/agent.json` by atomic replace after every
pass, so a separate reader process sees either the old snapshot or the new one, never half
of either. It is a COPY of the truth and never a second source: the db is the state (P2-06's
rule); the file is its export format. A write failure warns and does not stop the poll — an
instrument panel must not be able to park a door agent.

Security: no credential value is stored on this module, printed, or put in a report; no
endpoint is invented (targets come from sites.toml — §3). Since Task 15 the real ingest
transport ships: an `https://` push target wires `agent_push.https_transport` for the
site (bearer from the keychain item `gateclerk-ingest-<site>`), so the value lives only in
the transport's `Secret` and never in this module, a report, or a log line.
"""

from __future__ import annotations

import json
import os
import random
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Any

from gateclerk import agent_push
from gateclerk.agent_alert import (
    PENDING_SERIAL,
    STALL_STRIKES,
    Alert,
    AlertPolicy,
    default_sink,
    guarded_tick,
)
from gateclerk.agent_db import connect
from gateclerk.agent_health import AgentHealthCollector, snapshot_to_json
from gateclerk.agent_loop import DeviceLoop, TickResult, build_device_loop
from gateclerk.agent_store import check_db_watermark
from gateclerk.config import (
    PUSH_TARGET_SCHEMES,
    ConfigError,
    DeviceTarget,
    SiteConfig,
    credential_provider,
    credential_ref,
    resolve_credentials,
)
from gateclerk.isapi_transport import IsapiClient
from gateclerk.sinks import IMPLICIT_SINK_NAME, SinkSpec

__all__ = [
    "HEALTH_DIR_NAME",
    "HEALTH_FILE_NAME",
    "PARK_DIR_NAME",
    "PUSH_LEDGER_FILE_NAME",
    "PushLedger",
    "SiteAgent",
    "SiteRunReport",
    "SiteTickReport",
    "build_site_agent",
    "discard_dead_letter",
    "flag_rung_password",
    "queue_new_events",
    "resolve_db_path",
    "resolve_state_root",
]

#: P2-05's park dir name under the state dir. On disk, not in memory: the unacked park is
#: what survives the `Restart=always` restart (deploy/README.md step 4).
PARK_DIR_NAME = "park"
#: The §2e health snapshot dir under the state dir (the socat reader's file).
HEALTH_DIR_NAME = "health"
HEALTH_FILE_NAME = "agent.json"
#: systemd exposes `LoadCredential=<name>:<path>` as this env var pointing at a dir of files.
CREDENTIALS_DIRECTORY_ENV = "CREDENTIALS_DIRECTORY"

#: Minimum wall-clock gap since the last known successful poll before the ring-floor
#: probe is worth ONE request (card t_ed9c7e92). The observed ring is ~10k events with
#: the site's 1/min major=3 noise, i.e. ~1,440 events/day and ~7 days of retention
#: (OBSERVED.md: 10,199 events, earliest serial 27). A gap shorter than a day therefore
#: leaves >6 days before any event after the checkpoint can be evicted, so the answer
#: cannot show loss: spending the POST would only cost nonce budget. A normal 5-minute
#: poll and a short restart never probe; a quiet week of SUCCESSFUL polls never probes
#: either, because the gap is the time since the last success, not since the last punch.
RING_PROBE_MIN_GAP_S = 24 * 60 * 60


def _now() -> datetime:
    """The agent's wall clock as ONE module-level name — the test/ops freeze seam.

    `cli._now()` is the same pattern for the same reason: a clock a test can pin without
    reaching into any object. Everything time-shaped in a pass reads through the callable
    `build_site_agent` was handed, whose default is this function.
    """
    return datetime.now(UTC)


# --- the queue seam the poller owns ---------------------------------------------------------


#: The poller's own record of what it has already pushed (see `PushLedger`).
PUSH_LEDGER_FILE_NAME = "push-ledger.jsonl"


class PushLedger:
    """Which events this site's poller has already pushed (or the owner discarded), on disk.

    Why this exists at all: P2-04's `drain` DELETEs the queue row on success and keeps no
    "sent" marker — correct for the pusher (the store is the truth, the queue is a buffer) —
    and P2-03's `TickResult` reports counts, not rowids. Neither module is wrong; together
    they leave the POLLER unable to answer "has this event already left the building?", so a
    fresh `agent run` process would re-queue and re-push the ENTIRE store on every restart
    (and re-push a payload the owner just deleted with `agent deadletter delete`). The ledger
    is the poller's own bookkeeping, and it follows the fleet's existing precedent for exactly
    this problem — P2-05's park: a small append-only file under the site's state dir, never
    a db schema change (the schema belongs to P2-04's forward-only MIGRATIONS, untouched).

    It is a CACHE of observed outcomes, never an authority: the db stays the truth, and the
    ingest's idempotency key (DESIGN.md "Event model") stays the final dedupe authority. A
    lost or stale ledger line means at worst one re-push, which the UPSERT makes harmless.
    """

    def __init__(
        self,
        path: Path,
        *,
        warn: Callable[[str], None] | None = None,
    ) -> None:
        self.path = Path(path)
        # Resolved at call time, like the SiteAgent clock: a test that monkeypatches the
        # module-level warn after construction still sees the ledger's lines.
        self._warn = warn
        # (endpoint, sink name) -> event ids, lazy. The sink half is SINKS-WIRING: with N
        # sinks per site, "already pushed" is a fact ABOUT A SINK (the other sinks have
        # their own backlog), and one bucket per endpoint would let a successful https leg
        # mark the same event as done for the csv archive that has not seen it yet.
        self._known: dict[tuple[str, str | None], set[int]] | None = None

    def known(self, sink_name: str = IMPLICIT_SINK_NAME, *, endpoint: str) -> set[int]:
        """Event ids already `sent` or `gone` for this (endpoint, sink) — a copy, loads once.

        A line written BEFORE sinks existed carries no `s`, and is read as belonging to this
        endpoint for EVERY sink aimed at it. That is the upgrade-inert half of the keying:
        such a line is evidence that the endpoint has seen the event, which is exactly what
        a sink pointing at that endpoint needs, and it is what keeps upgrade day from
        re-pushing the whole store at a site that replaced `push_target` with a sink at the
        same URL. The sink half only ever makes the exclusion narrower for lines written
        WITH a sink name.
        """
        if self._known is None:
            self._known = self._load()
        out = set(self._known.get((endpoint, sink_name), ()))
        # `set()` default, NOT `()`: `|=` onto a set accepts any iterable, but the tuple
        # default blew up on the first legacy-line lookup (found by tests/test_p2_07b).
        out |= self._known.get((endpoint, None), set())
        return out

    def _bucket(self, endpoint: str, sink_name: str) -> set[int]:
        known = self._known if self._known is not None else self._load()
        self._known = known
        return known.setdefault((endpoint, sink_name), set())

    def _load(self) -> dict[tuple[str, str | None], set[int]]:
        out: dict[tuple[str, str | None], set[int]] = {}
        if not self.path.exists():
            return out
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                # `s` is SINKS-WIRING's sink name; its ABSENCE is a pre-sinks line and keys
                # the bucket to None (read as "every sink on this endpoint" by `known`).
                sink_name = record.get("s")
                if sink_name is not None and not isinstance(sink_name, str):
                    raise TypeError(f"sink name {sink_name!r} is not a string")
                out.setdefault((record["t"], sink_name), set()).add(int(record["e"]))
            except (ValueError, KeyError, TypeError):
                # A torn final line (killed mid-append) or corruption must not stop a poll:
                # the worst case is one re-push the UPSERT absorbs. Warn, skip, continue.
                (self._warn or _stderr_warn)(
                    f"push ledger: skipping unreadable line in {self.path}"
                )
        return out

    def append(
        self,
        event_ids: Sequence[int],
        *,
        endpoint: str,
        sink_name: str = IMPLICIT_SINK_NAME,
        kind: str = "sent",
    ) -> None:
        """Record what just happened for these events. Append-only: small lines, atomic enough.

        One writer per site (the unit is per-site), so appends cannot interleave with each
        other; a concurrent CLI `deadletter delete` appends its own line (O_APPEND keeps
        single small lines intact on a local filesystem — and a torn line loads as skipped).

        The line gains `s` (the sink) and keeps `e`/`t`/`k` exactly as before: an older
        reader of a newer ledger sees precisely what it saw before, which is the direction
        of compatibility that matters on upgrade day (the file is on disk, not in a schema).
        `sink_name` defaults to the implicit legacy sink so a pre-sinks caller keeps
        compiling and writes a line a pre-sinks reader still understands.
        """
        if not event_ids:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            for event_id in event_ids:
                handle.write(
                    json.dumps({"e": int(event_id), "t": endpoint, "k": kind, "s": sink_name})
                    + "\n"
                )
        self._bucket(endpoint, sink_name).update(int(e) for e in event_ids)

    def apply_exclusion(
        self, conn: Any, sink_name: str = IMPLICIT_SINK_NAME, *, endpoint: str
    ) -> None:
        """Expose `known(sink_name, endpoint=...)` to SQL as a TEMP table (dies with it).

        The exclusion has to happen INSIDE the candidate query: without it, a store whose
        first N events are all ledger-known would return N candidates, filter to zero, and
        never reach the unsent rows behind them. A TEMP table keeps the db FILE untouched —
        P2-04's schema and forward-only migration guard never see this state.
        """
        conn.execute("DROP TABLE IF EXISTS temp.agent_push_ledger")
        conn.execute("CREATE TEMP TABLE agent_push_ledger (event_id INTEGER NOT NULL PRIMARY KEY)")
        known = self.known(sink_name, endpoint=endpoint)
        if known:
            conn.executemany(
                "INSERT OR IGNORE INTO temp.agent_push_ledger VALUES (?)",
                ((event_id,) for event_id in sorted(known)),
            )


def _reset_ledger_table(conn: Any) -> None:
    """Empty ledger table for a connection that has no PushLedger (`queue_new_events` needs
    the temp table to exist whether or not a poller is the caller)."""
    conn.execute("DROP TABLE IF EXISTS temp.agent_push_ledger")
    conn.execute("CREATE TEMP TABLE agent_push_ledger (event_id INTEGER NOT NULL PRIMARY KEY)")


def discard_dead_letter(
    conn: Any, dead_letter_id: int, *, ledger: PushLedger, sink_name: str | None = None
) -> bool:
    """The owner's `deadletter delete` path, ledger-armed: delete ONE row, remember it gone.

    Why this exists beside `agent_push.delete_dead_letter` (which stays exactly as shipped):
    deleting a dead letter removes its `dead_letter` exclusion, so the next pass's
    `queue_new_events` would see the event row — still in the store, now unexcluded — and
    re-queue and RE-PUSH the very payload the owner just discarded. That would violate §2b
    from the other side: "deleted only by the owner's command" has to mean gone, not
    "re-pushed next tick". Recording the id as `gone` in the ledger keeps the exclusion
    without touching the schema or the pusher.

    `sink_name` defaults to the row's OWN sink (read from the row being deleted): the owner
    deleted this sink's copy of the event, and the other sinks still have their own backlog
    to serve. A caller may pass one explicitly only to record the delete against a different
    sink, which no shipped command does.
    """
    row = conn.execute(
        "SELECT event_id, endpoint, sink_name FROM dead_letter WHERE id = ?", (dead_letter_id,)
    ).fetchone()
    if row is None:
        return False
    if not agent_push.delete_dead_letter(conn, dead_letter_id):
        return False
    ledger.append(
        [row["event_id"]],
        endpoint=row["endpoint"],
        sink_name=sink_name or row["sink_name"] or IMPLICIT_SINK_NAME,
        kind="gone",
    )
    return True


def queue_new_events(
    conn: Any,
    *,
    endpoint: str,
    now: datetime,
    limit: int = agent_push.DEFAULT_PUSH_BATCH_LIMIT,
    ledger: PushLedger | None = None,
    sink_name: str = IMPLICIT_SINK_NAME,
) -> tuple[int, ...]:
    """Queue every stored event that has no send buffer for this sink; return queue ids.

    The missing link between P2-02's store and P2-04's drain (module docstring). It lives
    here rather than in `agent_push` because it is not a push rule — the pusher stays exactly
    as shipped. `limit` bounds one pass (P2-04's batch cap): a first-ever pass over a
    year-old store must not build an unbounded queue in one transaction; the rest is still
    there, due, on the next pass.

    `sink_name` (SINKS-WIRING) is which sink this pass is queueing FOR: every exclusion is
    per (event, sink), because an event the ingest has already accepted still has to reach
    the csv archive that has never seen it. It defaults to the implicit legacy sink, so the
    pre-sinks call shape (`endpoint=site.push_target`, no sink) is unchanged.

    Three exclusions, all load-bearing:
    * `push_queue` — this sink already has a buffer for the event (plus, for the legacy sink
      only, any `legacy+<n>` row: see the note on `legacy_wild` below);
    * `dead_letter` — a dead-lettered row's queue buffer was DELETED *because* the 24 h
      bound expired; re-queuing it would re-push a poison payload every tick forever, which
      is the opposite of §2b ("a dead letter leaves the table only through the owner's
      command");
    * the ledger's TEMP table — what THIS poller already pushed for this sink (see
      `PushLedger`). Without it, every process restart re-queues and re-pushes the whole
      store. The exclusion is inside the query (not a post-filter) so a store whose oldest N
      rows are all known still reaches the unsent rows behind them.
    """
    if ledger is not None:
        ledger.apply_exclusion(conn, sink_name, endpoint=endpoint)
    else:
        _reset_ledger_table(conn)
    # The `legacy+<n>` arm of each clause is dead for a named sink: those rows are what the
    # v5/v6 migration mints when a pre-upgrade event had been buffered against two targets
    # (the operator moved `push_target` mid-backlog) — the oldest keeps `legacy`, the rest get
    # `legacy+<id>`. They carry a `+`, which config's identifier rule rejects, so no configured
    # sink can ever drain them; for the IMPLICIT sink they are the same push's history and
    # re-queueing would re-push a punch the legacy target already took. A newly configured sink
    # has genuinely never seen the event, so excluding it there would be silent loss, not
    # dedupe. The gate is a BOUND 0/1 — the query text stays a literal.
    legacy_wild = 1 if sink_name == IMPLICIT_SINK_NAME else 0
    rows = conn.execute(
        """
        SELECT e.id AS id
          FROM events AS e
         WHERE NOT EXISTS (
                 SELECT 1 FROM push_queue AS q
                  WHERE q.event_id = e.id AND q.endpoint = ?
                    AND (q.sink_name = ? OR (? = 1 AND substr(q.sink_name, 1, 7) = 'legacy+')))
           AND NOT EXISTS (
                 SELECT 1 FROM dead_letter AS d
                  WHERE d.event_id = e.id AND d.endpoint = ?
                    AND (d.sink_name = ? OR (? = 1 AND substr(d.sink_name, 1, 7) = 'legacy+')))
           AND NOT EXISTS (
                 SELECT 1 FROM temp.agent_push_ledger AS l
                  WHERE l.event_id = e.id)
         ORDER BY e.id
         LIMIT ?
        """,
        (
            endpoint,
            sink_name,
            legacy_wild,
            endpoint,
            sink_name,
            legacy_wild,
            max(1, int(limit)),
        ),
    ).fetchall()
    ids = [row["id"] for row in rows]
    if not ids:
        return ()
    return agent_push.enqueue_events(conn, ids, endpoint=endpoint, now=now, sink_name=sink_name)


# --- the reports `agent run` prints ---------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SiteTickReport:
    """One pass over the site, as data. Nothing here carries a host, a payload or a secret.

    `refused` counts GATE refusals — devices the park kept at ZERO requests, i.e. the
    lockout-safety gate working, not a failure.
    """

    at: str
    ticks_ok: int = 0
    ticks_failed: int = 0
    ticks_refused: int = 0
    records_stored: int = 0
    inserted: int = 0
    refreshed: int = 0
    unchanged: int = 0
    checkpoint_serial: int | None = None
    alerts: tuple[str, ...] = ()
    queued: int = 0
    pushed: int = 0
    push_failed: int = 0
    dead_lettered: int = 0
    parked: tuple[str, ...] = ()
    #: Per-sink counters for this pass (SINKS-WIRING): sink name -> `pushed`/`push_failed`/
    #: `dead_lettered`/`queued`. The scalars above stay the SUM across sinks (so every
    #: existing reader keeps its meaning), but one blended number would hide "the ingest leg
    #: failed while the archive succeeded" — the outage an operator has to see. Counters
    #: only: never a payload, a host, or a token.
    sinks: Mapping[str, Mapping[str, int]] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "at": self.at,
            "ticks_ok": self.ticks_ok,
            "ticks_failed": self.ticks_failed,
            "ticks_refused": self.ticks_refused,
            "records_stored": self.records_stored,
            "inserted": self.inserted,
            "refreshed": self.refreshed,
            "unchanged": self.unchanged,
            "checkpoint_serial": self.checkpoint_serial,
            "alerts": list(self.alerts),
            "queued": self.queued,
            "pushed": self.pushed,
            "push_failed": self.push_failed,
            "dead_lettered": self.dead_lettered,
            "parked": list(self.parked),
        }
        # Emitted whenever the pass touched any sink (including the implicit legacy one), so
        # a single-sink site's JSON has the same shape as an N-sink site's and a reader never
        # has to special-case the legacy form.
        if self.sinks:
            out["sinks"] = {name: dict(counts) for name, counts in self.sinks.items()}
        return out


@dataclass(frozen=True, slots=True)
class SiteRunReport:
    """The whole run: every pass's report plus the counters the operator reads once.

    `parked` and `circuit_open` are what `agent run` maps onto its exit code: a site in either
    state needs a human (the park exists because of a terminal 401, and the circuit is the
    transport refusing to present credentials again). A plain tick failure is NOT here — the
    overlap heals those (P2-03), and exiting on one would turn a transient 503 into a
    `Restart=always` crash loop against a door controller.
    """

    site: str
    db_path: str
    ticks: int
    tick_reports: tuple[SiteTickReport, ...] = ()
    counters: Mapping[str, int] = field(default_factory=dict)
    push_target: str | None = None
    parked: tuple[str, ...] = ()
    circuit_open: tuple[str, ...] = ()
    #: An unacked park or an open circuit somewhere on the site: `agent run --once` maps this
    #: onto exit 3 (a smoke test of a site that needs a human must not report success). The
    #: continuous unit form never reaches the mapping — `run()` does not return — so a park
    #: cannot become a `Restart=always` crash loop.
    needs_human: bool = False

    @property
    def pushed(self) -> int:
        return sum(report.pushed for report in self.tick_reports)

    @property
    def push_failed(self) -> int:
        return sum(report.push_failed for report in self.tick_reports)

    @property
    def dead_lettered(self) -> int:
        return sum(report.dead_lettered for report in self.tick_reports)

    def as_dict(self) -> dict[str, Any]:
        return {
            "site": self.site,
            "db_path": self.db_path,
            "ticks": self.ticks,
            "tick_reports": [report.as_dict() for report in self.tick_reports],
            "counters": dict(self.counters),
            "push_target": self.push_target,
            "parked": list(self.parked),
            "circuit_open": list(self.circuit_open),
            "needs_human": self.needs_human,
            # Run totals as well as the per-pass detail: `--output json | jq .pushed` is the
            # operator's one-line question ("did this run push anything"), and answering it
            # should not require summing an array in the shell.
            "pushed": self.pushed,
            "push_failed": self.push_failed,
            "dead_lettered": self.dead_lettered,
        }


# --- the agent: one site, its devices, the gate, the pusher ---------------------------------


class SiteAgent:
    """One site: N device loops (P2-03) behind the park gate (P2-05), plus queue + drain.

    Two things, and only two, are owned here: the ORDER of the pass (module docstring — the
    checkpoint must never cover an unstored event, and the pusher must never see an unsent
    punch), and the fact that a refused tick sends ZERO requests (`guarded_tick` returns
    None; the loop is never entered).

    Clock, sleep, monotonic, env, client factory and push transport are injected for the same
    reason the rest of the codebase injects them: a test that sleeps 300 s is not a test, and
    a suite that opens a socket to a door controller is worse than no suite.
    """

    def __init__(
        self,
        *,
        site: SiteConfig,
        loops: Sequence[DeviceLoop],
        policy: AlertPolicy,
        conn: Any,
        db_path: str,
        collector: AgentHealthCollector | None = None,
        health_path: Path | None = None,
        push_transport: agent_push.Transport | None = None,
        ledger: PushLedger | None = None,
        sink_transports: Mapping[str, agent_push.Transport] | None = None,
        now: Callable[[], datetime] | None = None,
        sleep: Callable[[float], None] | None = None,
        monotonic: Callable[[], float] | None = None,
        warn: Callable[[str], None] | None = None,
    ) -> None:
        if not loops:
            raise ValueError("SiteAgent needs at least one device loop")
        self.site = site
        self.loops = tuple(loops)
        self.policy = policy
        self.conn = conn
        # The db THIS agent opened (state-root resolved). The watermark reads this exact
        # file rather than `site.db_path_resolved`: the config value is relative to CWD, and
        # a relocated store must not have the wrong file stat'd (a stat of a file that is not
        # ours would silently report "no watermark" for a store that has one).
        self._db_path = db_path
        self.collector = collector
        self.health_path = health_path
        # None means "read the module-level `_now` at call time" — deliberately NOT a bound
        # default of `_now`: a late read is what lets a test freeze the agent's clock with one
        # monkeypatch of `agent_cli._now` (the same trick `cli._now` is for). An injected
        # callable wins over it and is what `build_site_agent` threads to every seam.
        self._clock = now
        self._sleep = sleep
        self._monotonic = monotonic if monotonic is not None else time.monotonic
        self._warn = warn if warn is not None else _stderr_warn
        self.push_target = site.push_target
        self._push_transport = push_transport
        # --- SINKS-WIRING: the fan-out ------------------------------------------------------
        # `event_sinks` is `effective_sinks` minus the alert-only `mnotify` route: a site
        # with `[[site.sink]]` blocks gets those, a site with only `push_target` gets the
        # single implicit `legacy` sink aimed at exactly that ref, and a site with neither
        # is the pusher being off. Nothing below branches on "is this the legacy case" —
        # the legacy site is one sink in a list of one, which is why the pre-sinks
        # behaviour is unchanged rather than duplicated.
        self.sinks: tuple[SinkSpec, ...] = site.event_sinks
        #: Injected per-sink transports (tests, owner-wired); an injected one always wins over
        #: what `_sink_transport` would build. Keyed by sink NAME — the identity — never by
        #: ref, because two sinks may share one ref and must not share one transport object.
        self._sink_transports: dict[str, agent_push.Transport] = dict(sink_transports or {})
        #: Lazily built transports, keyed by name (the same cache `build_site_agent` avoids
        #: by building once: every `security` invocation can be a macOS ACL prompt).
        self._built_sink_transports: dict[str, agent_push.Transport] = {}
        if not self.sinks:
            # Absence is loud, mirroring the push_target-absent law Task 15 states for a
            # missing bearer: an operator who removed the last sink (or never wrote one)
            # learns it from this line at startup, not from a payroll gap in three months.
            # This is a warn, not a refusal — §3 forbids defaulting an endpoint, and "no
            # push" is a legitimate configuration the operator is entitled to choose.
            self._warn(
                f"warning: site {self.site.name!r} has no event sinks: neither push_target "
                "nor a non-alert [[site.sink]] is declared, so nothing this site polls will "
                "be pushed. Queued events stay queued (and nothing gets queued)."
            )
        # The poller's sent/gone ledger (class docstring on `PushLedger`). None means "no
        # ledger" — the pure-API shape tests use when they want the raw P2-04 behaviour.
        self.ledger = ledger
        if self.push_target is not None and not self.push_target.startswith(PUSH_TARGET_SCHEMES):
            # config validates this too; the second wall exists because SiteAgent is also the
            # seam a test (or a future caller) can hand a target to directly (§3).
            raise ConfigError(f"push_target {self.push_target!r} has an unacceptable scheme")
        #: device key (serial, or `pending` before bootstrap) -> that loop's last TickResult.
        self._last_tick: dict[str, Any] = {}
        #: Device serial -> wall-clock instant of the last SUCCESSFUL poll. Seeded from
        #: the health snapshot this agent already writes, so a restart remembers its
        #: last-known-good without a schema change (card t_ed9c7e92). The ring-floor
        #: probe's gate is the time since this instant, never the checkpoint's age:
        #: that is what distinguishes an outage from a quiet door.
        self._last_ok_at: dict[str, datetime] = self._last_ok_from_health()
        self._cycle_started = time.monotonic()

    # --- one pass -------------------------------------------------------------------------

    def now(self) -> datetime:
        """The pass's instant, resolved at CALL time through the injected seam.

        Resolving here rather than binding `self.now = _now` is what keeps the module-level
        indirection useful: a test may freeze `agent_cli._now` after building the agent and
        still move the whole pass (the same reason `cli._now` is a function).
        """
        return self._clock() if self._clock is not None else _now()

    def tick(self) -> SiteTickReport:
        """Gate every device, tick the allowed ones, queue, drain, export health.

        Never raises for a device failure: `DeviceLoop.tick` returns those as data (the
        checkpoint stays put and the overlap heals them) and the alert policy is explicitly
        never-raise. `drain` is a per-row failure model too, so a down ingest lands in
        `push_failed` rather than in an exception that takes the poll down with it.
        """
        moment = self.now()
        report = _TickBuilder()
        for loop in self.loops:
            result = guarded_tick(self.policy, loop)
            if result is None:
                report.refused += 1
                continue
            report.absorb(result)
            key = loop.device_serial or PENDING_SERIAL
            self._last_tick[key] = result
            # GC-P04: the clock channel, fed by the reading GC-P03 already refreshes. Both
            # surfaces get the SAME Skew object — the policy's one-warning-per-episode rule
            # (§2c) and the collector's §2e gauge — and this sits ahead of the ok/fail split
            # on purpose: a terminal can be reachable enough to answer System/time and still
            # fail the event walk, and an RTC an hour off corrupts R1's payroll scan either
            # way. Neither observer raises; neither writes to the device.
            if result.clock_skew is not None:
                report.alerts.extend(self.policy.observe_skew(result.clock_skew))
                if self.collector is not None:
                    self.collector.observe_skew(key, result.clock_skew)
            if self.collector is not None:
                self.collector.observe_tick(result, device_serial=key, client=loop.client)
            # The nonce-recovery total is the transport's OWN counter (an info line, never an
            # alert — §2c), and a stalled checkpoint is P2-05's reading of P2-02's row.
            recoveries = getattr(loop.client, "auth_recoveries", None)
            if isinstance(recoveries, int):
                self.policy.observe_recoveries(recoveries)
            if loop.device_serial:
                # The ring-floor probe is a READ on the same device: spend it ONLY at
                # the first ok tick after a gap long enough for the ~7-day ring to have
                # evicted events after the checkpoint. A skipped tick (circuit
                # open/park) presents ZERO requests; a failed walk already has the
                # failed-poll arm and offers no probe. The checkpoint passed for the
                # comparison is the PRE-tick one (the walk just advanced it).
                gap_s = self._last_ok_gap(loop.device_serial, moment) if result.ok else None
                ring_probe = None
                if (
                    gap_s is not None
                    and gap_s >= RING_PROBE_MIN_GAP_S
                    and result.checkpoint_serial_before is not None
                    and result.checkpoint_time_before
                ):
                    checkpoint_time = result.checkpoint_time_before
                    ring_probe = partial(loop.probe_ring_floor, checkpoint_time)
                stall = self.policy.check_stall(
                    loop.device_serial,
                    ring_probe=ring_probe,
                    checkpoint_serial_before=result.checkpoint_serial_before,
                    gap_s=gap_s,
                )
                if result.ok:
                    self._last_ok_at[loop.device_serial] = moment
                if stall is not None:
                    report.alerts.append(stall)
            # Task 15's hourly roster step, pulled per cycle: a no-op (None) until the
            # hour is up, and ONLY reached for a loop that actually ticked — a parked
            # device above got `guarded_tick` -> None and must still see ZERO requests
            # (§1.9). The DeviceUsersResult is deliberately dropped: the roster leg
            # reports through `warn` (the collector observes the funnel) and BC's own
            # Nelegati view, never through the punch counters P2-05/P2-06 read.
            loop.push_device_users_if_due()
        report.alerts.extend(self._observe_watermark())
        # The pusher is on when the site HAS sinks. For a pre-sinks site that is the single
        # implicit legacy sink aimed at `push_target`, so this is the same condition the
        # card shipped (`push_target is not None`) — just expressed through the one property
        # that knows both forms.
        if self.sinks:
            self._push(moment, report)
        report.parked = self.parked_keys()
        self._write_health()
        return report.build(moment)

    def run(self, *, once: bool = False, max_ticks: int | None = None) -> SiteRunReport:
        """One tick (`--once`), or the §2a cadence loop: all devices, sleep, repeat.

        `once` is the smoke-test shape every deploy step wants (CI, and "does this config
        work before I enable the unit"). It must NOT go in the unit: one tick then exit,
        under `Restart=always`, becomes a five-second poll of a door controller — the
        hammering §1.9 forbids.

        The loop is written here rather than delegated to `run_forever` because a site has N
        devices and ONE sleep per cycle: the pass above is all devices, and the sleep is
        `cadence - elapsed`, floored at zero. The cadence NUMBER stays the loop's (§2a) —
        this only reuses it — and the injected sleep keeps the whole loop testable in
        milliseconds.
        """
        reports: list[SiteTickReport] = []
        sleep = self._sleep if self._sleep is not None else time.sleep
        ticks = 0
        try:
            while max_ticks is None or ticks < max_ticks:
                self._cycle_started = time.monotonic()
                reports.append(self.tick())
                ticks += 1
                if once or (max_ticks is not None and ticks >= max_ticks):
                    break
                sleep(self._cycle_delay())
        except BaseException:
            # A raise here is a BUG, not a device failure (`tick()` absorbs those). The
            # counters go out before the traceback so journald keeps them, and
            # `Restart=always` brings the process back.
            _abort_line(
                f"agent run aborted site={self.site.name} after {ticks} tick(s); "
                f"counters={self.policy.counters}"
            )
            raise
        return SiteRunReport(
            site=self.site.name,
            db_path=self._db_path,
            ticks=ticks,
            tick_reports=tuple(reports),
            counters=dict(self.policy.counters),
            push_target=self.push_target,
            parked=self.parked_keys(),
            circuit_open=self.open_circuits(),
            needs_human=self.needs_human(),
        )

    def needs_human(self) -> bool:
        """Is the site in a state that only an operator can end? (exit-3 input, §2c)

        Two states qualify, both read live from their owners — an UNACKED park (the policy
        will not let anyone knock until `agent ack`) and an open transport circuit (the
        client will not present credentials again). An ACKED park waiting for its re-probe
        slot is deliberately NOT here: the human already acted, and a run that refused the
        device while correctly waiting out the grid must not read as "needs a human".
        """
        if self.open_circuits():
            return True
        return any(
            state is not None and state.acked_at is None
            for state in (self.policy.parked(self.site.name, key) for key in self.parked_keys())
        )

    def open_circuits(self) -> tuple[str, ...]:
        """Device keys whose transport circuit is open right now (the transport's own verdict).

        Read live, never inferred from counters: `IsapiClient.circuit_open()` is the one
        statement of "this device answered a terminal 401 and credentials must not be presented
        again", which is also what P2-06 reports as `circuit_open_gauge`.
        """
        return tuple(
            key
            for key, client in (
                (loop.device_serial or PENDING_SERIAL, loop.client) for loop in self.loops
            )
            if client.circuit_open()
        )

    def close(self) -> None:
        """Release the alert worker, every device client and the db (SIGTERM path).

        The mnotify sink is drained for its own bounded time so `--once` and a SIGTERM
        both give an accepted page a chance to finish; a still-running page only warns
        (the local evidence line was already written before it was queued).
        """
        close_sink = getattr(getattr(self.policy, "sink", None), "close", None)
        if callable(close_sink):
            close_sink()
        for loop in self.loops:
            loop.client.close()
        self.conn.close()

    def parked_keys(self) -> tuple[str, ...]:
        """Which device keys the park is holding, through P2-05's own `parked()`.

        Consulted for both keys `attempt_allowed` consults (the pre-bootstrap `pending` key
        and the device key), so the gauge cannot disagree with the gate.
        """
        keys: list[str] = []
        for loop in self.loops:
            for candidate in (PENDING_SERIAL, loop.device_serial):
                if candidate is None or candidate in keys:
                    continue
                if self.policy.parked(self.site.name, candidate) is not None:
                    keys.append(candidate)
        return tuple(keys)

    # --- internals ------------------------------------------------------------------------

    def _cycle_delay(self) -> float:
        """Seconds to the next pass: the configured cadence minus what this pass took."""
        cadence = float(max(loop.cadence_s for loop in self.loops))
        return max(0.0, cadence - (time.monotonic() - self._cycle_started))

    # --- the fan-out: one queue step, one drain per sink ------------------------------------

    def _sink_transport(self, sink: SinkSpec) -> agent_push.Transport:
        """The transport one sink drains through — built from the sink's own config alone.

        Resolution order: an injected one (tests, owner-wired) wins; then a cached lazily
        built one; then build it here:

        * `csv` / `jsonl` -> a `FileSinkWriter` for that spec. No injected transport is
          needed for a file sink at all, which is the point: a site that configures an
          archive gets an archive written, and a csv sink that silently never wrote would be
          payroll loss discovered at audit time.
        * `https` with the site's shared transport available -> that object (the T15 leg,
          unchanged: same client, same bearer, same wire bytes). A site that declared sinks
          has no `push_target`, so the shared transport is the one `build_site_agent` built
          from the first https sink or that the caller injected.
        * `https` otherwise (per-sink token refs/headers, or no shared transport) ->
          `sink_writers.build_https_sink_transport`, which is Task 15's transport addressed
          from THIS sink's token ref.

        Built lazily for the same reason the bearer is resolved lazily: every `security`
        invocation can be a macOS ACL prompt, and a sink with nothing queued has no reason to
        ask. The result is cached per name so one sink never builds two.
        """
        injected = self._sink_transports.get(sink.name)
        if injected is not None:
            return injected
        built = self._built_sink_transports.get(sink.name)
        if built is not None:
            return built
        if sink.type in ("csv", "jsonl"):
            from gateclerk.sink_writers import FileSinkWriter

            # The agent's OWN clock stamps the rotation: a frozen test clock must freeze the
            # file name (the rotation stamp is part of what a deterministic run controls), and
            # in production the two clocks are the same object anyway.
            transport: agent_push.Transport = FileSinkWriter(sink, now=self.now)
        elif sink.type == "https":
            if sink.ref.startswith("stub://"):
                # `stub://` stays lazy and per-sink, exactly as the pre-sinks card had it:
                # the path is resolved at call time by `stub_transport`, which is what keeps a
                # `push_target = stub://` site byte-identical at upgrade (its implicit sink IS
                # an https sink with a stub ref). It also cannot be shared: two stub sinks are
                # two different files.
                transport = agent_push.stub_transport(sink.ref)
            else:
                shared = self._push_transport
                needs_own_wiring = bool(sink.token_env or sink.token_keychain or sink.headers)
                if shared is not None and not needs_own_wiring:
                    transport = shared
                else:
                    from gateclerk.sink_writers import build_https_sink_transport

                    transport = build_https_sink_transport(self.site.name, sink)
        else:
            raise ConfigError(
                f"sink {sink.name!r} has type {sink.type!r}, which this repo cannot send to: "
                "the registry knows https, csv and jsonl (a new type needs a writer in "
                "gateclerk.sink_writers, never a silent skip)"
            )
        self._built_sink_transports[sink.name] = transport
        return transport

    def _push(self, moment: datetime, report: _TickBuilder) -> None:
        """Queue once, then drain EVERY sink independently — one pass, N backoffs.

        The order is the card's law: for each sink, queue the events that sink has not seen
        (per-(event, sink) exclusions) and drain what is due for that sink. Each `drain` call
        is its own transaction batch with its own ladder and its own 24 h bound, so a sink at
        its batch cap stops claiming only ITS rows and an https outage never starves a file
        sink (DoD (a)); a poison row dead-letters in the one sink that could not take it and
        survives every other sink's success (DoD (b)).

        One sink's whole step is wrapped, so an exception escaping it — a transport blowing up
        outside its contract, a writer wired wrong — becomes a loud per-sink warn and the
        remaining sinks still get their drain in the SAME pass. That is not papering over a
        bug: the alternative is one mis-configured sink stopping the delivery of payroll data
        to every other destination the operator declared.
        """
        for sink in self.sinks:
            try:
                self._push_one(sink, moment, report)
            except Exception as exc:  # a broken sink must not stop the others
                self._warn(
                    f"warning: sink {sink.name!r} pass failed "
                    f"({type(exc).__name__}: {exc}); the site's other sinks are unaffected"
                )

    def _push_one(self, sink: SinkSpec, moment: datetime, report: _TickBuilder) -> None:
        """One sink's half of the pass: queue step, bearer gate, drain, ledger, counters."""
        target = sink.ref
        transport = self._sink_transport(sink)
        queued = len(
            queue_new_events(
                self.conn,
                endpoint=target,
                now=moment,
                ledger=self.ledger,
                sink_name=sink.name,
            )
        )
        report.sink_counts(sink.name, queued=queued)
        # Task 15: a bearer transport with no token skips THIS cycle's drain, loudly — and
        # the same law now applies per sink, because a sink whose token ref is wrong would
        # otherwise burn its whole backlog into dead letters for an install-time mistake.
        pending = queued or agent_push.queue_depth(self.conn, sink_name=sink.name)
        probe = getattr(transport, "token_available", None)
        if pending and probe is not None and not probe():
            self._warn(
                f"warning: sink {sink.name!r} at target {target!r} has no ingest bearer "
                f"token for site {self.site.name!r}: set "
                f"{agent_push.ingest_token_env_var(self.site.name)} (or the sink's own "
                f"token_env / token_keychain) or add the keychain item with security "
                f"add-generic-password -U -s gateclerk-ingest-{self.site.name} -a "
                f"{self.site.name} -w. Queued events stay queued until then (no attempts "
                "burned, no dead-letters)."
            )
            return
        result = agent_push.drain(
            self.conn,
            endpoint=target,
            transport=transport,
            now=moment,
            rng=random.random,
            dead_letter_after_s=self.site.push_dead_letter_after_s,
            log=self._observe_push,
            sink_name=sink.name,
        )
        report.sink_push_result(
            sink.name,
            pushed=result.push_ok,
            failed=result.push_failed,
            dead_lettered=len(result.dead_lettered),
        )
        self._warn_file_sink_failures(sink, result)
        # Record what left the building (PushLedger docstring), for THIS sink. Only successes
        # need a line: a row the drain dead-lettered stays excluded through the `dead_letter`
        # arm of the queue query until the owner's `delete` records it as `gone`.
        if self.ledger is not None:
            self.ledger.append(result.sent, endpoint=target, sink_name=sink.name, kind="sent")

    def _warn_file_sink_failures(self, sink: SinkSpec, result: agent_push.DrainResult) -> None:
        """A file sink that could not write says so, naming the sink and the failure class.

        `drain`'s own log line counts rows (the health parser partitions on it) but carries no
        reason, and for an https sink the reason is in the row's `HttpStatus503`-style class
        that an operator reads off the dead-letter table. A file sink's failure is different:
        the usual cause is a path the site cannot write (a data directory on an unmounted
        volume, a permission change, `path` pointing at a directory), and every row of the
        backlog fails the SAME way, so a silent retry loop looks like a healthy agent that
        simply never delivers. Name the sink, name the class, keep the rows queued.
        """
        if sink.type not in ("csv", "jsonl") or result.push_failed == 0:
            return
        classes: list[str] = []
        for row in agent_push.pending_rows(self.conn, sink_name=sink.name):
            if row.last_error_class and row.last_error_class not in classes:
                classes.append(row.last_error_class)
        for row in agent_push.dead_letter_rows(self.conn, sink_name=sink.name):
            if row.error_class not in classes:
                classes.append(row.error_class)
        named = ", ".join(classes) if classes else "unknown"
        self._warn(
            f"warning: sink {sink.name!r} ({sink.type}) could not write to {sink.ref!r}: "
            f"{result.push_failed} row(s) failed ({named}); the rows stay queued and will be "
            "retried on the sink's own backoff ladder"
        )

    def _observe_push(self, line: str) -> None:
        """drain's OWN log line, routed to the health collector (its push counters parse it)."""
        if self.collector is not None:
            self.collector.observe_push_log(line)

    def _observe_watermark(self) -> list[Alert]:
        """§2b's keep-everything watermark: a stat over the db file, not a device request."""
        try:
            check = check_db_watermark(self._db_path, self.site.db_warn_bytes)
        except OSError:  # pragma: no cover - a missing file is the fresh-install case
            return []
        return self.policy.observe_watermark(check)

    def _last_ok_gap(self, device_serial: str, now: datetime) -> float | None:
        """Seconds since the last known successful poll, or None when never known."""
        last = self._last_ok_at.get(device_serial)
        if last is None:
            return None
        return max(0.0, (now - last).total_seconds())

    def _last_ok_from_health(self) -> dict[str, datetime]:
        """Seed last-known-good across restarts from the snapshot the agent writes.

        The snapshot carries `last_poll_ok_age_s` (process monotonic) and is replaced
        atomically after every pass, so its FILE MTIME is the instant the last pass
        finished: mtime minus that age is the wall-clock instant of the last successful
        poll, even when the last pass failed. No new column, no second state file, and
        a missing/corrupt snapshot simply means "unknown" — which spends no request.
        """
        if self.health_path is None:
            return {}
        try:
            payload = json.loads(self.health_path.read_text(encoding="utf-8"))
            written = datetime.fromtimestamp(self.health_path.stat().st_mtime, tz=UTC)
        except (OSError, ValueError, TypeError):
            return {}
        devices = payload.get("devices") if isinstance(payload, dict) else None
        if not isinstance(devices, list):
            return {}
        seeded: dict[str, datetime] = {}
        for device in devices:
            if not isinstance(device, dict):
                continue
            serial = device.get("device_serial")
            age = device.get("last_poll_ok_age_s")
            if (
                isinstance(serial, str)
                and isinstance(age, (int, float))
                and not isinstance(age, bool)
                and age >= 0
            ):
                seeded[serial] = written - timedelta(seconds=float(age))
        return seeded

    def _write_health(self) -> None:
        """Export the §2e snapshot for a separate reader process (P2-06's sidecar contract).

        Atomic: temp file + `Path.replace` (agent_alert's park-write precedent) — a
        concurrent reader never sees a half-written snapshot. Only `OSError` is absorbed —
        a health export must not be able to stop or crash the poll it reports on, and any
        other exception is a real bug worth the unit's loud restart.
        """
        if self.collector is None or self.health_path is None:
            return
        try:
            clients = {(loop.device_serial or PENDING_SERIAL): loop.client for loop in self.loops}
            snapshot = self.collector.collect(clients=clients, ticks=dict(self._last_tick))
            text = snapshot_to_json(snapshot)
            self.health_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.health_path.parent / f"{self.health_path.name}.tmp"
            tmp.write_text(text, encoding="utf-8")
            tmp.replace(self.health_path)  # agent_alert's precedent: Path.replace is atomic
        except OSError as exc:
            self._warn(
                f"warning: health snapshot not written ({type(exc).__name__}: {exc}) — "
                "the poll continues; /healthz reads the previous snapshot"
            )


class _TickBuilder:
    """Mutable accumulator for one pass (`SiteTickReport` is the frozen result)."""

    def __init__(self) -> None:
        self.ticks_ok = 0
        self.ticks_failed = 0
        self.refused = 0
        self.records = 0
        self.inserted = 0
        self.refreshed = 0
        self.unchanged = 0
        self.checkpoint_serial: int | None = None
        self.alerts: list[Alert] = []
        self.queued = 0
        self.pushed = 0
        self.push_failed = 0
        self.dead_lettered = 0
        self.parked: tuple[str, ...] = ()
        #: sink name -> counters, in insertion order (the config's declaration order, because
        #: the fan-out walks the sinks in that order). Counters only, never content.
        self.sink_counters: dict[str, dict[str, int]] = {}

    def sink_counts(self, sink_name: str, *, queued: int) -> None:
        """Record the queue step for one sink (created on first sight, order = config's)."""
        self.queued += queued
        self.sink_counters.setdefault(sink_name, {}).update(queued=queued)

    def sink_push_result(
        self, sink_name: str, *, pushed: int, failed: int, dead_lettered: int
    ) -> None:
        """Record one sink's drain, and keep the site totals as the SUM across sinks.

        The scalars are what every pre-sinks reader already reads (`report.pushed`), so they
        must stay the total; the per-sink map is what makes "which leg failed" answerable
        without guessing.
        """
        counters = self.sink_counters.setdefault(sink_name, {"queued": 0})
        counters.update(pushed=pushed, push_failed=failed, dead_lettered=dead_lettered)
        self.pushed += pushed
        self.push_failed += failed
        self.dead_lettered += dead_lettered

    def absorb(self, result: TickResult) -> None:
        if result.ok:
            self.ticks_ok += 1
        else:
            self.ticks_failed += 1
        self.records += result.records
        self.inserted += result.inserted
        self.refreshed += result.refreshed
        self.unchanged += result.unchanged
        if result.checkpoint_serial is not None:
            self.checkpoint_serial = result.checkpoint_serial

    def build(self, moment: datetime) -> SiteTickReport:
        return SiteTickReport(
            at=moment.astimezone(UTC).isoformat(timespec="seconds"),
            ticks_ok=self.ticks_ok,
            ticks_failed=self.ticks_failed,
            ticks_refused=self.refused,
            records_stored=self.records,
            inserted=self.inserted,
            refreshed=self.refreshed,
            unchanged=self.unchanged,
            checkpoint_serial=self.checkpoint_serial,
            alerts=tuple(f"{alert.level}:{alert.kind}" for alert in self.alerts),
            queued=self.queued,
            pushed=self.pushed,
            push_failed=self.push_failed,
            dead_lettered=self.dead_lettered,
            parked=self.parked,
            sinks={name: dict(counts) for name, counts in self.sink_counters.items()},
        )


# --- the paths every agent command resolves the same way ------------------------------------


def resolve_db_path(site: SiteConfig, state_root: Path | str | None) -> str:
    """The site's sqlite path, resolved exactly the way `agent run` resolves it.

    Shared by `ack` and `deadletter` so a command that READS the store cannot disagree with
    the command that WROTE it. P2-01 owns the derivation of the site-derived name
    (`db_path_resolved`); this only applies the state root to a relative path.

    `--state-root` may name either the site's own directory (what `service install` renders
    into the unit) or the PARENT that holds one directory per site (what an operator passes
    to a multi-site `doctor`/`status`). Prefer `<root>/<site>` only when it exists AND the
    flat `<root>/<db_path>` does not: this same function is the writer's path too, so a
    flat-layout site that happens to have a stale `<root>/<site>/` directory must keep
    writing its flat store rather than silently opening an empty one. A root already named
    for the site never descends a second level.
    """
    db_path = Path(site.db_path_resolved)
    if state_root is not None and not db_path.is_absolute():
        root = Path(state_root)
        per_site = root / site.name
        if root.name != site.name and per_site.is_dir() and not (root / db_path).exists():
            root = per_site
        return str(root / db_path)
    return str(db_path)


def resolve_state_root(site: SiteConfig, state_root: Path | str | None) -> Path:
    """The site's ONE writable directory — where the store, `park/` and `health/` live.

    It is the store's own parent, which is what makes the three commands agree: with
    `--state-root` the relative `db_path` (including the derived
    `./gateclerk-<site>.sqlite3`) belongs to that root and not to whatever cwd the process
    started in, and without it the store's parent is the state root by definition. That is
    also the unit's `ReadWritePaths=<STATE_ROOT>/<SITE>` (deploy/README.md step 1).
    """
    return Path(resolve_db_path(site, state_root)).parent


# --- the composition (no socket opens, no credential values kept) ----------------------------


def _alert_sink_for(site: SiteConfig, *, warn: Callable[[str], None]) -> Callable[[Alert], None]:
    """The site's alert route: its one `mnotify` sink, else P2-05's stderr default.

    `mnotify` is an ADDITIONAL page, not a replacement for the local line: the sink writes
    `default_sink`'s line immediately on the alert thread, then queues the mail to one
    daemon worker (so a mail outage cannot stall polling). A delivery failure only warns —
    the line is never written twice (agent_mnotify's fallback law). `SiteAgent.close`
    drains accepted pages for a bounded time at exit.
    """
    spec = site.alert_sink
    if spec is None or not spec.to:
        return default_sink
    from gateclerk.agent_mnotify import MNOTIFY_TIMEOUT_S, MnotifySink

    return MnotifySink(
        to=spec.to,
        timeout_s=spec.timeout_s if spec.timeout_s is not None else MNOTIFY_TIMEOUT_S,
        warn=warn,
    )


def build_site_agent(
    site: SiteConfig,
    *,
    state_root: Path | str | None = None,
    env: Mapping[str, str] | None = None,
    keychain: Any = None,
    now: Callable[[], datetime] | None = None,
    sleep: Callable[[float], None] | None = None,
    monotonic: Callable[[], float] | None = None,
    warn: Callable[[str], None] | None = None,
    sink: Callable[[Alert], None] | None = None,
    client_factory: Callable[[str, str, str], IsapiClient] | None = None,
    push_transport: agent_push.Transport | None = None,
    sink_transports: Mapping[str, agent_push.Transport] | None = None,
    park_dir: Path | str | None = None,
    credentials_dir: Path | str | None = None,
    password: str | None = None,
    health: bool = True,
) -> SiteAgent:
    """Wire one `SiteConfig` into a runnable agent. Opens no socket; stores nothing yet.

    The state dir is created when missing: `Restart=always` means "starts on a fresh box" is
    a normal case, and sqlite cannot create a file in a directory that is not there. The park
    dir defaults to `<state dir>/park` — beside the store, inside the unit's single writable
    path, on disk because an unacked park must survive the restart (P2-05's lockout argument).

    `credentials_dir` / `password` are the two entry points P1's resolver does not have:
    systemd `LoadCredential=` delivers a FILE, which is neither a flag, an env var nor a
    keychain item. Its contents enter as the resolver's FLAG rung (`flag_rung_password`), so
    precedence stays flag > env > keychain exactly as p1-02 shipped it and `config.py` gains
    no fourth rung. Where no credentials directory exists — a dev box, a launchd job, a smoke
    test — the env and keychain rungs get their normal turn.

    One clock, one warn stream, one alert sink: `now` goes to every loop, the policy and the
    collector (module docstring), `warn` is the single stderr funnel the collector also
    observes, and `sink` defaults to P2-05's own journald sink.
    """
    # Task 15: an `https://` target now HAS a transport in this repo — the bearer ingest
    # leg (`agent_push.https_transport`, keychain item `gateclerk-ingest-<site>`). What the
    # old refusal protected against stays protected against: an agent that polls all day
    # while silently not pushing. The transport is wired here (when the caller did not
    # inject one) and its lazy token resolution means a missing keychain item fails every
    # push with a loud error class instead of a silent zero — plus the warn line below,
    # so the missing install step names itself at startup rather than at dead-letter time.
    if (
        site.push_target is not None
        and push_transport is None
        and not site.push_target.startswith(("stub://", "https://"))
    ):
        raise ConfigError(
            f"push_target {site.push_target!r} has no transport: this repo serves "
            "`stub://` and `https://` only and never invents an endpoint "
            "(docs/P2-SITE-AGENT.md §3). Unset push_target, or aim it at one of those."
        )
    db_path = resolve_db_path(site, state_root)
    root = Path(db_path).parent
    root.mkdir(parents=True, exist_ok=True)
    parks = Path(park_dir) if park_dir is not None else root / PARK_DIR_NAME
    clock = now if now is not None else _now
    base_warn = warn if warn is not None else _stderr_warn

    conn = connect(db_path)
    ledger = PushLedger(
        root / PUSH_LEDGER_FILE_NAME,
        warn=warn if warn is not None else _stderr_warn,
    )
    collector: AgentHealthCollector | None = AgentHealthCollector(
        site=site.name,
        conn=conn,
        db_path=db_path,
        # §2c's stall threshold is k*cadence; k (STALL_STRIKES) is P2-05's decision and the
        # cadence is config's, so the collector gets the arithmetic, not a new number.
        checkpoint_stall_s=float(STALL_STRIKES * site.cadence_s),
        tz_mapping_declared=site.device_tz is not None,
        now=clock,
        monotonic=monotonic if monotonic is not None else time.monotonic,
        # The collector's own warn line is emitted by the funnel below, never by itself.
        warn=lambda text: None,
    )

    def funnel(text: str) -> None:
        """One warn stream: the collector OBSERVES it, the emitter still PRINTS it (once)."""
        collector.observe_warn(text)
        base_warn(text)

    loops: list[DeviceLoop] = []
    # Task 15: the site's push transport, built ONCE here and shared by every leg — the
    # punches (SiteAgent._push) and the hourly roster (DeviceLoop) hit the SAME endpoint
    # with the SAME bearer, and one httpx.Client means one connection pool. An injected
    # `push_transport` (tests, owner-wired) always wins. The token is resolved lazily
    # inside the transport — deliberately NOT probed here: every `security` invocation can
    # raise a macOS ACL prompt (KeychainReader's own rule about the second call), and an
    # agent that has queued nothing yet has no reason to ask. A missing token surfaces at
    # the first push instead, as a warning naming the keychain item (§3, SiteAgent._push).
    ingest_transport = push_transport
    if (
        ingest_transport is None
        and site.push_target is not None
        and site.push_target.startswith("https://")
    ):
        ingest_transport = agent_push.https_transport(site.name, env=env, keychain=keychain)
    # `stub://` stays lazy inside SiteAgent._push: the path is resolved per call,
    # matching the shipped P2-04 behaviour byte-for-byte.
    for host in _site_hosts(site):
        client = _client_for_host(
            site,
            host,
            env=env,
            keychain=keychain,
            client_factory=client_factory,
            credentials_dir=credentials_dir,
            password=password,
        )
        loops.append(
            build_device_loop(
                _site_for_host(site, host),
                conn=conn,
                client=client,
                now=clock,
                monotonic=monotonic,
                sleep=sleep,
                warn=funnel,
                push_transport=ingest_transport,
            )
        )
    policy = AlertPolicy(
        site=site.name,
        cadence_s=site.cadence_s,
        now=clock,
        conn=conn,
        park_dir=parks,
        sink=sink if sink is not None else _alert_sink_for(site, warn=funnel),
    )
    return SiteAgent(
        site=site,
        loops=loops,
        policy=policy,
        conn=conn,
        db_path=db_path,
        collector=collector,
        health_path=(root / HEALTH_DIR_NAME / HEALTH_FILE_NAME if health else None),
        # The SAME transport object the loops roster through (one client, one bearer);
        # `stub://` sites keep it None and _push keeps resolving the stub lazily.
        push_transport=ingest_transport,
        # SINKS-WIRING's `SiteAgent` seam, passed through: an injected per-sink transport
        # always wins over what `_sink_transport` would build (tests and the demo wire the
        # https leg to a loopback target; production passes nothing and behaviour is
        # unchanged). Keyed by sink NAME — the identity — never by ref.
        sink_transports=sink_transports,
        ledger=ledger,
        now=clock,
        sleep=sleep,
        monotonic=monotonic,
        warn=funnel,
    )


def _site_hosts(site: SiteConfig) -> tuple[str, ...]:
    """This site's device hosts — exactly one today (P2-01's schema has one `host` per
    block, and `parse_sites` refuses two blocks with the same name). The list is written for
    the day the schema grows a device list (spec §2d's "one entry per device")."""
    return (site.host,)


def _site_for_host(site: SiteConfig, host: str) -> SiteConfig:
    """The site view for one device host (identical today; the seam for a device list)."""
    if host == site.host:
        return site
    from dataclasses import replace

    return replace(site, host=host)


# --- the credential seam systemd's LoadCredential= needs ------------------------------------


def credential_file_value(
    site: str,
    host: str,
    *,
    credentials_dir: Path | str | None = None,
    env: Mapping[str, str] | None = None,
) -> str:
    """Read `$CREDENTIALS_DIRECTORY/gateclerk-<site>-<host>` (one systemd LoadCredential=).

    The trailing newline is trimmed: a digest password carrying a newline authenticates as a
    DIFFERENT password, so trimming is a correctness rule, not tidiness. A missing file is an
    error, never a fall-through: a unit that was given a credentials directory and has no
    matching file is a broken install, and quietly dropping to the keychain on a headless
    Linux box turns a loud config error into a mystery 401 — and a 401 is what burns the
    device's lockout budget (OBSERVED.md "lockout accounting").
    """
    environ: Mapping[str, str] = os.environ if env is None else env
    directory = (
        credentials_dir if credentials_dir is not None else environ.get(CREDENTIALS_DIRECTORY_ENV)
    )
    if not directory:
        raise ConfigError(
            "nothing to read a credential from: pass --credentials-dir or run under a unit "
            f"that sets ${CREDENTIALS_DIRECTORY_ENV} (otherwise use the env or keychain rung)"
        )
    name = credential_ref(site, host)
    try:
        return (Path(directory) / name).read_text(encoding="utf-8").rstrip("\r\n")
    except OSError as exc:
        raise ConfigError(
            f"credential reference {name!r} is not readable under {directory!r} "
            f"({type(exc).__name__}): the unit's LoadCredential= line and the source file "
            "must agree (deploy/README.md step 3)"
        ) from exc


def flag_rung_password(
    site: str,
    host: str,
    *,
    password: str | None = None,
    credentials_dir: Path | str | None = None,
    env: Mapping[str, str] | None = None,
) -> str | None:
    """The password as p1-02's FLAG rung, or None when nothing agent-specific supplies it.

    In order: `--password` verbatim (the flag already outranks env and keychain inside
    `resolve_credentials`, so the agent invents no precedence); else a credentials directory
    (flag or systemd's env) -> the reference file's contents; else None, so the env rung
    (`GATECLERK_<HOST>_PASSWORD`) and the keychain rung get their normal turn. `resolve_
    credentials` stays the only place precedence is decided.
    """
    if password is not None:
        return password
    environ: Mapping[str, str] = os.environ if env is None else env
    if credentials_dir is None and not environ.get(CREDENTIALS_DIRECTORY_ENV):
        return None
    return credential_file_value(site, host, credentials_dir=credentials_dir, env=environ)


def _client_for_host(
    site: SiteConfig,
    host: str,
    *,
    env: Mapping[str, str] | None,
    keychain: Any,
    client_factory: Callable[[str, str, str], IsapiClient] | None,
    credentials_dir: Path | str | None = None,
    password: str | None = None,
) -> IsapiClient:
    """Build one device's long-lived client, from a provider unless a factory was injected.

    `build_device_loop` would do both, but building here is what lets the caller inject a
    transport (the offline test path, and any owner-wired transport) without reaching into the
    loop. The default path hands the transport a re-readable provider (the Slice-2 seam), so
    a credential rotated while the agent runs is picked up at nonce retirement or circuit
    expiry — the §2c self-heal. An injected `client_factory` keeps receiving the eager
    (base, user, secret) triple, so every already-wired test and owner transport is untouched.
    The plaintext is never kept on this module, printed, or returned.
    """
    flag_password = flag_rung_password(
        site.name,
        host,
        password=password,
        credentials_dir=credentials_dir,
        env=env,
    )
    target = DeviceTarget(
        host=host,
        port=site.port,
        site=site.name,
        keychain_service=site.keychain_service,
        config_user=site.isapi_user,
    )
    base_url = f"http://{host}:{site.port}"
    if client_factory is not None:
        creds = resolve_credentials(
            target,
            password=flag_password,
            env=env,
            keychain=keychain,
        )
        return client_factory(base_url, creds.user, creds.password.reveal())
    return IsapiClient(
        base_url,
        "",
        "",
        credentials=credential_provider(
            target,
            password=flag_password,
            env=env,
            keychain=keychain,
        ),
        read_timeout=site.timeout_s,
    )


# --- stderr (the same channel P2-05's default sink and P2-03's warn use) --------------------


def _stderr_warn(text: str) -> None:
    """The p1-05c precedent: a warning goes to stderr, visibly, unasked."""
    from gateclerk.output import make_console  # local: keeps the module import cheap

    make_console(stderr=True).print(text, markup=False)


def _abort_line(text: str) -> None:
    """One stderr line for an abort that is about to re-raise, so journald keeps the why.

    The exception is NOT printed here: a transport exception's text embeds the base_url, and
    the traceback reaches stderr by the usual Python route anyway. What is printed is integers
    and the site label — safe by construction.
    """
    from gateclerk.output import make_console

    make_console(stderr=True).print(text, markup=False)
