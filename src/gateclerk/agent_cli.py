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
endpoint is invented (an `https://` push target is refused with the reason, because P2-04
ships only the `stub://` ingest — §3); device hosts come from sites.toml, never from here.
"""

from __future__ import annotations

import os
import random
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
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
    credential_ref,
    resolve_credentials,
)
from gateclerk.isapi_transport import IsapiClient

__all__ = [
    "HEALTH_DIR_NAME",
    "HEALTH_FILE_NAME",
    "PARK_DIR_NAME",
    "SiteAgent",
    "SiteRunReport",
    "SiteTickReport",
    "build_site_agent",
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


def _now() -> datetime:
    """The agent's wall clock as ONE module-level name — the test/ops freeze seam.

    `cli._now()` is the same pattern for the same reason: a clock a test can pin without
    reaching into any object. Everything time-shaped in a pass reads through the callable
    `build_site_agent` was handed, whose default is this function.
    """
    return datetime.now(UTC)


# --- the queue seam the poller owns ---------------------------------------------------------


def queue_new_events(
    conn: Any,
    *,
    endpoint: str,
    now: datetime,
    limit: int = agent_push.DEFAULT_PUSH_BATCH_LIMIT,
) -> tuple[int, ...]:
    """Queue every stored event that has no send buffer for `endpoint`; return queue ids.

    The missing link between P2-02's store and P2-04's drain (module docstring). It lives
    here rather than in `agent_push` because it is not a push rule — the pusher stays exactly
    as shipped. `limit` bounds one pass (P2-04's batch cap): a first-ever pass over a
    year-old store must not build an unbounded queue in one transaction; the rest is still
    there, due, on the next pass.
    """
    rows = conn.execute(
        """
        SELECT e.id AS id
          FROM events AS e
         WHERE NOT EXISTS (
                 SELECT 1 FROM push_queue AS q
                  WHERE q.event_id = e.id AND q.endpoint = ?)
           AND NOT EXISTS (
                 SELECT 1 FROM dead_letter AS d
                  WHERE d.event_id = e.id AND d.endpoint = ?)
         ORDER BY e.id
         LIMIT ?
        """,
        (endpoint, endpoint, max(1, int(limit))),
    ).fetchall()
    ids = [row["id"] for row in rows]
    if not ids:
        return ()
    return agent_push.enqueue_events(conn, ids, endpoint=endpoint, now=now)


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

    def as_dict(self) -> dict[str, Any]:
        return {
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


@dataclass(frozen=True, slots=True)
class SiteRunReport:
    """The whole run: every pass's report plus the counters the operator reads once."""

    site: str
    db_path: str
    ticks: int
    tick_reports: tuple[SiteTickReport, ...] = ()
    counters: Mapping[str, int] = field(default_factory=dict)
    push_target: str | None = None
    parked: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "site": self.site,
            "db_path": self.db_path,
            "ticks": self.ticks,
            "tick_reports": [report.as_dict() for report in self.tick_reports],
            "counters": dict(self.counters),
            "push_target": self.push_target,
            "parked": list(self.parked),
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
        collector: AgentHealthCollector | None = None,
        health_path: Path | None = None,
        push_transport: agent_push.Transport | None = None,
        now: Callable[[], datetime] = _now,
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
        self.collector = collector
        self.health_path = health_path
        self.now = now
        self._sleep = sleep
        self._monotonic = monotonic if monotonic is not None else time.monotonic
        self._warn = warn if warn is not None else _stderr_warn
        self.push_target = site.push_target
        self._push_transport = push_transport
        if self.push_target is not None and not self.push_target.startswith(PUSH_TARGET_SCHEMES):
            # config validates this too; the second wall exists because SiteAgent is also the
            # seam a test (or a future caller) can hand a target to directly (§3).
            raise ConfigError(f"push_target {self.push_target!r} has an unacceptable scheme")
        #: device key (serial, or `pending` before bootstrap) -> that loop's last TickResult.
        self._last_tick: dict[str, Any] = {}
        self._cycle_started = time.monotonic()

    # --- one pass -------------------------------------------------------------------------

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
            if self.collector is not None:
                self.collector.observe_tick(result, device_serial=key, client=loop.client)
            # The nonce-recovery total is the transport's OWN counter (an info line, never an
            # alert — §2c), and a stalled checkpoint is P2-05's reading of P2-02's row.
            recoveries = getattr(loop.client, "auth_recoveries", None)
            if isinstance(recoveries, int):
                self.policy.observe_recoveries(recoveries)
            if loop.device_serial:
                stall = self.policy.check_stall(loop.device_serial)
                if stall is not None:
                    report.alerts.append(stall)
        report.alerts.extend(self._observe_watermark())
        if self.push_target is not None:
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
            db_path=self.site.db_path_resolved,
            ticks=ticks,
            tick_reports=tuple(reports),
            counters=dict(self.policy.counters),
            push_target=self.push_target,
            parked=self.parked_keys(),
        )

    def close(self) -> None:
        """Release every device client and the db (the unit's SIGTERM path)."""
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

    def _push(self, moment: datetime, report: _TickBuilder) -> None:
        target = self.push_target
        if target is None:  # tick() only calls this when a target is configured
            return
        transport = self._push_transport
        if transport is None:
            if target.startswith("stub://"):
                transport = agent_push.stub_transport(target)
            else:
                raise ConfigError(
                    f"push_target {target!r} needs a transport the owner wires: this repo "
                    "ships only the `stub://` ingest and never invents an endpoint "
                    "(docs/P2-SITE-AGENT.md §3). Unset push_target, or aim it at a stub."
                )
        report.queued = len(queue_new_events(self.conn, endpoint=target, now=moment))
        result = agent_push.drain(
            self.conn,
            endpoint=target,
            transport=transport,
            now=moment,
            rng=random.random,
            dead_letter_after_s=self.site.push_dead_letter_after_s,
            log=self._observe_push,
        )
        report.pushed = result.push_ok
        report.push_failed = result.push_failed
        report.dead_lettered = len(result.dead_lettered)

    def _observe_push(self, line: str) -> None:
        """drain's OWN log line, routed to the health collector (its push counters parse it)."""
        if self.collector is not None:
            self.collector.observe_push_log(line)

    def _observe_watermark(self) -> list[Alert]:
        """§2b's keep-everything watermark: a stat over the db file, not a device request."""
        try:
            check = check_db_watermark(self.site.db_path_resolved, self.site.db_warn_bytes)
        except OSError:  # pragma: no cover - a missing file is the fresh-install case
            return []
        return self.policy.observe_watermark(check)

    def _write_health(self) -> None:
        """Export the §2e snapshot for a separate reader process (P2-06's sidecar contract).

        Atomic: temp file + `os.replace`, so a concurrent reader never sees a half-written
        snapshot. Only `OSError` is absorbed — a health export must not be able to stop or
        crash the poll it reports on, and any other exception is a real bug worth the unit's
        loud restart.
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
            os.replace(tmp, self.health_path)
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
        )


# --- the paths every agent command resolves the same way ------------------------------------


def resolve_db_path(site: SiteConfig, state_root: Path | str | None) -> str:
    """The site's sqlite path, resolved exactly the way `agent run` resolves it.

    Shared by `ack` and `deadletter` so a command that READS the store cannot disagree with
    the command that WROTE it. P2-01 owns the derivation of the site-derived name
    (`db_path_resolved`); this only applies the state root to a relative path.
    """
    db_path = Path(site.db_path_resolved)
    if state_root is not None and not db_path.is_absolute():
        return str(Path(state_root) / db_path)
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
    db_path = resolve_db_path(site, state_root)
    root = Path(db_path).parent
    root.mkdir(parents=True, exist_ok=True)
    parks = Path(park_dir) if park_dir is not None else root / PARK_DIR_NAME
    clock = now if now is not None else _now
    base_warn = warn if warn is not None else _stderr_warn

    conn = connect(db_path)
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
            )
        )
    policy = AlertPolicy(
        site=site.name,
        cadence_s=site.cadence_s,
        now=clock,
        conn=conn,
        park_dir=parks,
        sink=sink if sink is not None else default_sink,
    )
    return SiteAgent(
        site=site,
        loops=loops,
        policy=policy,
        conn=conn,
        collector=collector,
        health_path=(root / HEALTH_DIR_NAME / HEALTH_FILE_NAME if health else None),
        push_transport=push_transport,
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
    directory = credentials_dir if credentials_dir is not None else environ.get(
        CREDENTIALS_DIRECTORY_ENV
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
    """Resolve the credential for one device and build its long-lived client.

    `build_device_loop` would do both, but resolving here is what lets the caller inject a
    transport (the offline test path, and any owner-wired transport) without reaching into the
    loop. The plaintext goes straight into the client's digest construction — the transport's
    own rule — and is never kept on this module, printed, or returned.
    """
    flag_password = flag_rung_password(
        site.name,
        host,
        password=password,
        credentials_dir=credentials_dir,
        env=env,
    )
    creds = resolve_credentials(
        DeviceTarget(
            host=host,
            port=site.port,
            site=site.name,
            keychain_service=site.keychain_service,
            config_user=site.isapi_user,
        ),
        password=flag_password,
        env=env,
        keychain=keychain,
    )
    factory = client_factory or (
        lambda base, user, secret: IsapiClient(
            base, user, secret, read_timeout=site.timeout_s
        )
    )
    return factory(f"http://{host}:{site.port}", creds.user, creds.password.reveal())


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
