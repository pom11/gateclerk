"""The facts behind `gateclerk status` — the rules, kept typer-free and importable.

CLI-STATUS (parent CLI-VERBS-HELP). This module answers "is this site healthy" from
ONE place so the CLI surface (`gateclerk.status_cmds`) stays resolve -> collect -> render
and a test can ask the question without constructing a Click object. It follows the
`sink_cli.py` precedent: rules live in the typer-free domain module, the cmd module is
the surface, and `gateclerk.cli` is imported by nobody here (tests/test_cli_structure.py
enforces the direction).

The three laws this module exists to hold

1. ZERO WRITES, ZERO DEVICE CALLS. `status` is the first command a new operator learns
   and the one CI runs on every deploy, so it must be safe to run ANYWHERE: not on the
   agent box (no db write — the store is opened `PRAGMA query_only=ON`, the same honest
   statement `sink_cmds._sink_store` makes), never against the ingest (no probe, no
   POST), never against the device (the device line is CACHE-ONLY — see `_device_section`).
   A status screen that hammers a door controller is how health checks become incidents
   (docs/P2-SITE-AGENT.md §2e made the same argument about /healthz).

2. THE DB IS THE STATE. Every number is read from a table or a file the agent already
   writes: per-sink pending/dead-letter counts from `push_queue`/`dead_letter` via
   `sink_cli.sink_rows` (per-sink rows automatically once SINKS-WIRING merged — no new
   schema, the card's law), db size via `agent_store.db_size_bytes`, the last-drain age
   from the §2e health snapshot's mtime (the agent writes it after every tick, which
   includes the drain), the last-push verdict from the dead-letter/queue rows' OWN
   `error_class` columns. Nothing is re-derived, nothing is invented.

3. REFERENCES AND CLASS NAMES ONLY, NEVER VALUES OR PAYLOADS. The dead-letter `payload`
   column carries employee names — this module never selects it. The only push text
   shown is the `error_class` column (an exception class name or `HttpStatus<code>`,
   minted by `agent_push._error_class`, credential-free by construction) and token
   REFERENCES (`sink_cli.token_ref_text` prints names, never values). The redact law's
   sweep lives in tests/test_cli_status.py.

Graceful degradation is a rule, not a courtesy
----------------------------------------------
`status` may run on a laptop where the state dir was never populated, and the SERVICE
card's pidfile convention is not merged yet. "Cannot know" renders as `warn`, never as
`fail`: a fail must be EVIDENCE (a stale pidfile, a failed cached probe, dead-letter
rows, a snapshot that stopped moving), not an absence. The one deliberate exception to
"absence is not evidence": a state dir that HAS a store but a health snapshot older
than the staleness bound IS evidence the agent stopped polling, and that fails —
catching exactly that is the screen's reason to exist.

Exit codes (docs/CLI-CONVENTIONS.md; the shipped p1-08 contract, not a new numbering)
--------------------------------------------------------------------------------------
Each failing section carries one of the documented codes; the screen exits with the
worst, in this precedence — root causes first, because when the config is broken every
other line is noise:

  2  config / credential class — the store cannot be opened at all, or the agent loop
     is demonstrably dead (stale pidfile) / has stopped polling (snapshot stale past
     the bound): "the install needs an operator", the same merged class `creds test`
     and `sink test` already use.
  3  terminal auth — the health snapshot says a device circuit is open (the transport
     stopped to protect the account; a human must verify the credential).
  4  device / protocol — a FRESH cached device probe came back failed.
  6  push lane — dead-letter rows exist for any sink. This is the code CLI-VERBS-HELP
     reserved for the push lane and documented as "no command emits it yet"; CLI-STATUS
     is the deliberate first emitter (the pin that held 6 unwired — `agent run`'s
     parked/circuit-open mapping to 3 — is untouched and stays green).

`warn` changes no exit code. `--check` changes only rendering (compact, one jsonl row
per site), never the exit mapping: the codes are the convention, not a CI mode.
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

from gateclerk import sink_cli
from gateclerk.exceptions import ConfigError

__all__ = [
    "DEVICE_PROBE_MAX_AGE_S",
    "PIDFILE_NAME",
    "PROBE_CACHE_PARTS",
    "SINK_COLUMNS",
    "SNAPSHOT_STALE_MULTIPLE",
    "STATUS_COLUMNS",
    "Verdict",
    "collect_site_status",
    "exit_code_for_sites",
]

#: A cached device probe counts as current for this many seconds only (the card's
#: number). The reason the line says `run: gateclerk doctor` rather than lying: an
#: hour-old "reachable" is not a fact, it is a memory.
DEVICE_PROBE_MAX_AGE_S = 60

#: The pidfile the SERVICE card's unit will drop in the site's state dir. NOT shipped
#: yet (CLI-SERVICE-CMD is its own card) — its absence is exactly why the agent line
#: degrades to snapshot evidence instead of failing. The constant lives here so the
#: future writer and this reader cannot drift.
PIDFILE_NAME = "agent.pid"

#: Where a device-probe result is cached, under the site's state dir. `status` only
#: READS this file; `gateclerk doctor` (CLI-DOCTOR, unmerged) is the sanctioned writer.
#: The shape mirrors the health snapshot's contract: whoever writes it fresh owns the
#: line, and `status` refuses to age it past DEVICE_PROBE_MAX_AGE_S.
PROBE_CACHE_PARTS = ("status", "device-probe.json")

#: Snapshot staleness bound = max(600 s, cadence_s * this). 600 s floors at two missed
#: 5-min ticks (the shipped §2a cadence) so a single slow tick never reads as dead;
#: 3x the site's own cadence is the general rule for a site that configured otherwise.
SNAPSHOT_STALE_MULTIPLE = 3.0

#: The per-sink columns, straight from `sink_cli` — one source for the sink vocabulary.
SINK_COLUMNS = sink_cli.SINK_COLUMNS

#: The table view, in order. One row per site; the per-sink detail is folded compactly
#: into `sinks` (the json form carries it unfolded — see `collect_site_status`).
STATUS_COLUMNS: tuple[str, ...] = (
    "site",
    "verdict",
    "state",
    "db",
    "drain",
    "agent",
    "sinks",
    "last_push",
    "roster",
    "device",
    "notes",
)


class Verdict:
    """The three states a section (or a whole site) can be in. Plain strings: they are
    part of the machine-output contract, so they are frozen here once."""

    OK = "ok"
    WARN = "warn"
    FAIL = "fail"

    _RANK: ClassVar[dict[str, int]] = {OK: 0, WARN: 1, FAIL: 2}

    @classmethod
    def worst_of(cls, verdicts: Any) -> str:
        """The worst of a collection of verdict strings; unknown spellings rank as ok."""
        worst = cls.OK
        for verdict in verdicts:
            if cls._RANK.get(verdict, 0) > cls._RANK[worst]:
                worst = verdict
        return worst


#: Precedence for the screen's exit code — earliest wins (root cause first).
#: 1 is never returned by design (cli_conventions), 5 (runaway paging) cannot be a
#: status section because status pages nothing.
_EXIT_PRECEDENCE: tuple[int, ...] = (2, 3, 4, 6)


# --- small readers (each degrades to None, never raises, on a missing file) ----------------


def _age_s(moment: datetime | None, now: datetime) -> float | None:
    """Seconds between a stamp and `now`; None for a stamp we cannot trust."""
    if moment is None:
        return None
    return max(0.0, (now - moment).total_seconds())


def _mtime_age(path: Path, now: datetime) -> float | None:
    """Age of a file's mtime; None when the file cannot be stat'd."""
    try:
        stamp = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    except OSError:
        return None
    return _age_s(stamp, now)


def _parse_iso(text: str) -> datetime | None:
    """An ISO stamp back to aware-datetime, or None. A naive stamp is NOT trusted
    (every writer in this repo stamps tz-aware; a naive one is a bug, and guessing
    its zone on a 60-second cache window is how a stale probe reads as fresh)."""
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _pid_alive(pid: int) -> bool:
    """Does `pid` exist? `os.kill(pid, 0)` sends NO signal — it is the POSIX existence
    probe, not a write to the process. PermissionError means it exists but is not
    ours; ProcessLookupError means it does not."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _read_json_object(path: Path) -> dict[str, Any] | None:
    """A JSON object from disk, or None for missing / unparseable / not-an-object.
    A snapshot or probe cache we cannot read is "cannot know", never "broken"."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _fmt_age(age: float | None) -> str:
    return "unknown" if age is None else f"{age:.0f}s"


# --- the per-site collection ------------------------------------------------------------------


def collect_site_status(
    site: Any,
    *,
    state_root: str | Path | None,
    now: datetime,
) -> dict[str, Any]:
    """One site's full status row: plain data, no rendering, zero side effects.

    `site` is a validated `config.SiteConfig` — validation already happened at parse
    (a block that fails it raises before this function can run, and the CLI maps that
    onto exit 2). `state_root` is the CLI's `--state-root`; paths resolve EXACTLY as
    `agent run` resolves them (`agent_cli.resolve_db_path` / `resolve_state_root`), so
    this screen can never describe a directory the unit does not use.

    Returns one flat row for the renderer plus `_sections` (each
    `{"state": ok|warn|fail, "text": str, "exit": int|None}`) for the exit-code rule
    and for tests that want per-section detail.
    """
    from gateclerk import agent_cli  # lazy: the heavy agent stack — sink_cmds' precedent

    db_path = Path(agent_cli.resolve_db_path(site, state_root))
    state_dir = agent_cli.resolve_state_root(site, state_root)
    snapshot_path = state_dir / agent_cli.HEALTH_DIR_NAME / agent_cli.HEALTH_FILE_NAME

    store, store_error = _open_store(db_path)
    try:
        return _collect_with_store(
            site,
            db_path=db_path,
            state_dir=state_dir,
            snapshot_path=snapshot_path,
            conn=store,
            store_error=store_error,
            now=now,
        )
    finally:
        if store is not None:
            store.close()  # sink_cmds' law: a read opens, the command closes


def _collect_with_store(
    site: Any,
    *,
    db_path: Path,
    state_dir: Path,
    snapshot_path: Path,
    conn: sqlite3.Connection | None,
    store_error: str | None,
    now: datetime,
) -> dict[str, Any]:
    """The sections, built once the store is open (or its refusal is known). Split from
    `collect_site_status` only so the connection has exactly one owner with a finally."""
    snapshot = _read_json_object(snapshot_path)
    snapshot_age = _mtime_age(snapshot_path, now)

    sections: dict[str, dict[str, Any]] = {}
    sections["config"] = _config_section(site)
    sections["db"] = (
        {"state": Verdict.FAIL, "text": f"store unopenable: {store_error}", "exit": 2}
        if store_error
        else {"state": Verdict.OK, "text": _db_text(db_path), "exit": None}
    )
    sections["drain"] = _drain_section(conn, snapshot_age, now)
    sections["agent"] = _agent_section(state_dir, db_path, snapshot, snapshot_age, site)
    sink_rows, sink_fail = _sinks_section(site, conn)
    sections["sinks"] = sink_fail or {
        "state": Verdict.OK,
        "text": _fold_sinks(sink_rows),
        "exit": None,
    }
    sections["last_push"] = _last_push_section(conn, snapshot)
    sections["roster"] = _roster_section(site, now)
    sections["device"] = _device_section(state_dir, now)

    verdict = Verdict.worst_of(section["state"] for section in sections.values())
    codes = {section["exit"] for section in sections.values() if section["exit"] is not None}
    exit_code = next((code for code in _EXIT_PRECEDENCE if code in codes), 0)
    # `notes` is where a WARN that no column can carry still reaches the operator —
    # the config note (device_code) included, which is the one thing on this screen
    # whose fix line an operator has to be able to read.
    notes = "; ".join(
        section["text"]
        for section in sections.values()
        if section["state"] == Verdict.WARN and section["text"]
    )
    return {
        "site": site.name,
        "verdict": verdict,
        "state": str(state_dir),
        "db": sections["db"]["text"],
        "drain": sections["drain"]["text"],
        "agent": sections["agent"]["text"],
        "sinks": _fold_sinks(sink_rows),
        "last_push": sections["last_push"]["text"],
        "roster": sections["roster"]["text"],
        "device": sections["device"]["text"],
        "notes": notes or "-",
        "exit_code": exit_code,
        # the unfolded detail rides on every row: `-o json` emits WHOLE records (the
        # shared renderer's law), and the table view selects its columns via
        # STATUS_COLUMNS, so the extra keys are invisible there but a script gets the
        # per-sink counts and the per-section verdicts without parsing prose.
        "sink_rows": sink_rows,
        "sections": {
            name: {"state": section["state"], "exit": section["exit"], "text": section["text"]}
            for name, section in sections.items()
        },
    }


def exit_code_for_sites(rows: list[dict[str, Any]]) -> int:
    """The screen's exit code: the worst section across every shown site.

    Root causes first (2 before 3 before 4 before 6): when the config itself is broken
    every other line is noise, and an operator (or CI) reading ONE number has to get
    the number they can act on.
    """
    codes = {int(row["exit_code"]) for row in rows if row.get("exit_code")}
    for code in _EXIT_PRECEDENCE:
        if code in codes:
            return code
    return 0


# --- sections ---------------------------------------------------------------------------------


def _open_store(db_path: Path) -> tuple[sqlite3.Connection | None, str | None]:
    """Open the site's store READ-ONLY: `(conn, None)`, `(None, None)` when no store
    exists yet, or `(None, refusal)` when a file is there but cannot be read.

    `PRAGMA query_only=ON` is `sink_cmds._sink_store`'s law, restated here only because
    that helper lives on the sink command surface and a domain module must not import
    a cmd module (the one-way rule tests/test_cli_structure.py pins). A store that has
    never been created is "no state here yet" — not an error — and the caller reads
    zero counts, exactly like `sink list` does.

    The `sqlite_master` probe is the difference between "no store" and "not a
    database": a file that is not sqlite (or is truncated mid-write) fails HERE and
    the operator sees the failure on the db line, not a blank site.
    """
    if not db_path.exists():
        return None, None
    try:
        conn = sqlite3.connect(str(db_path))
        conn.execute("PRAGMA query_only=ON")
        conn.row_factory = sqlite3.Row
        conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
    except sqlite3.Error as exc:
        return None, str(exc)
    return conn, None


def _db_text(db_path: Path) -> str:
    from gateclerk.agent_store import db_size_bytes  # lazy, same stack as the paths

    size = db_size_bytes(db_path)
    return "no store yet" if size == 0 else f"{size} B"


def _drain_section(
    conn: sqlite3.Connection | None, snapshot_age: float | None, now: datetime
) -> dict[str, Any]:
    """Age since the last drain. The §2e snapshot is written after every tick and a
    tick includes the drain pass (agent_cli's SiteAgent.run order), so the snapshot's
    mtime IS the last-drain stamp. A queue with a real attempted-at stamp overrides it
    with the fresher FACT (a drain that only found due-rows attempted sends after it)."""
    if conn is not None:
        try:
            row = conn.execute("SELECT MAX(last_attempt_at) t FROM push_queue").fetchone()
            attempted = _parse_iso(str(row["t"] or ""))
            attempted_age = _age_s(attempted, now)
            if attempted_age is not None:
                return {
                    "state": Verdict.OK,
                    "text": f"last drain attempt {_fmt_age(attempted_age)} ago",
                    "exit": None,
                }
        except sqlite3.Error:
            pass  # the db line already says the store is unreadable; no second line
    if snapshot_age is not None:
        return {
            "state": Verdict.OK,
            "text": f"last tick {_fmt_age(snapshot_age)} ago (health snapshot)",
            "exit": None,
        }
    return {"state": Verdict.WARN, "text": "unknown (no drain evidence here)", "exit": None}


def _agent_section(
    state_dir: Path,
    db_path: Path,
    snapshot: dict[str, Any] | None,
    snapshot_age: float | None,
    site: Any,
) -> dict[str, Any]:
    """The agent loop, in evidence order:

    1. the SERVICE card's pidfile (CLI-SERVICE-CMD, unmerged): live pid -> running;
       a pidfile whose pid is gone -> FAIL exit 2 (that IS a false-alive failure);
       no pidfile at all -> degrade, do NOT fail (absence is not evidence yet);
    2. the §2e health snapshot: a circuit-open device is terminal-auth FAIL exit 3
       (the transport stopped to protect the account — same fact `agent run` reports
       as 3, pinned by its own test; here it is one line, not an exit from the loop);
       fresh snapshot -> ok; a snapshot that stopped moving past the bound while a
       store exists -> FAIL exit 2 (the ring is rolling — spec §2c calls a checkpoint
       stall critical and this screen is where an operator meets it).
    """
    pidfile = state_dir / PIDFILE_NAME
    if pidfile.exists():
        raw = ""
        with contextlib.suppress(OSError):
            raw = pidfile.read_text(encoding="utf-8").strip()
        if raw.isdigit() and int(raw) > 0:
            pid = int(raw)
            if _pid_alive(pid):
                return {"state": Verdict.OK, "text": f"running (pid {pid})", "exit": None}
            return {
                "state": Verdict.FAIL,
                "text": f"not running (stale pidfile says pid {pid})",
                "exit": 2,
            }
        return {
            "state": Verdict.WARN,
            "text": f"pidfile unreadable ({raw[:24]!r}) — agent state unknown",
            "exit": None,
        }

    devices = snapshot.get("devices", []) if isinstance(snapshot, dict) else []
    circuit_open = any(
        isinstance(device, dict) and device.get("circuit_open") for device in devices
    )
    if circuit_open:
        return {
            "state": Verdict.FAIL,
            "text": (
                f"device circuit OPEN (last tick {_fmt_age(snapshot_age)} ago) — "
                "verify the credential: gateclerk creds test"
            ),
            "exit": 3,
        }
    if snapshot_age is None:
        if db_path.exists():
            return {
                "state": Verdict.WARN,
                "text": "unknown (no pidfile yet, no health snapshot)",
                "exit": None,
            }
        return {"state": Verdict.WARN, "text": "unknown (nothing set up here yet)", "exit": None}

    stale_after = max(600.0, float(site.cadence_s) * SNAPSHOT_STALE_MULTIPLE)
    if snapshot_age <= stale_after:
        return {
            "state": Verdict.OK,
            "text": f"last tick {_fmt_age(snapshot_age)} ago",
            "exit": None,
        }
    if db_path.exists():
        return {
            "state": Verdict.FAIL,
            "text": (
                f"NOT POLLING (last tick {_fmt_age(snapshot_age)} ago, stale past "
                f"{stale_after:.0f}s) — the event ring rolls while this site sleeps"
            ),
            "exit": 2,
        }
    return {
        "state": Verdict.WARN,
        "text": f"last tick {_fmt_age(snapshot_age)} ago (no store here to age against)",
        "exit": None,
    }


def _sinks_section(
    site: Any, conn: sqlite3.Connection | None
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Per-sink pending + dead-letter counts, from the queue tables themselves (the
    card's "no new schema"): `sink_cli.sink_rows` groups `push_queue`/`dead_letter` by
    `sink_name` and prints token REFERENCES only. One configured target today means one
    row; the day SINKS-WIRING-style multi-sink config lands the rows appear with no
    change here — that is what reading the tables buys.

    Dead-letter rows are a FAIL on exit 6: the 24 h §2c bound has been crossed for at
    least one punch, which is precisely what the reserved push code means.
    """
    try:
        rows = sink_cli.sink_rows(site, conn=conn)
    except (sqlite3.Error, ConfigError) as exc:
        return [], {"state": Verdict.FAIL, "text": f"sinks unreadable: {exc}", "exit": 2}
    dead = sum(int(row.get("dead_letter") or 0) for row in rows)
    if dead > 0:
        return rows, {
            "state": Verdict.FAIL,
            "text": f"{dead} dead-letter row(s): delivery is failing past the §2c bound",
            "exit": 6,
        }
    return rows, None


def _fold_sinks(rows: list[dict[str, Any]]) -> str:
    """The table's compact per-sink text: `name=pending/dead`, `;`-joined. The
    `(unconfigured)` row sink_cli appends for orphaned history stays visible — it is
    backlog an owner has to find, per sink_cli's own law."""
    folded = [
        f"{row['sink']}={row['pending']}/{row['dead_letter']}"
        for row in rows
        if "sink" in row and "pending" in row and "dead_letter" in row
    ]
    return "; ".join(folded) or "-"


def _last_push_section(
    conn: sqlite3.Connection | None, snapshot: dict[str, Any] | None
) -> dict[str, Any]:
    """The most recent push FACT on disk, in evidence order: a dead-letter row (the
    hardest fact — a send that died), then a queued row's own last failure (still
    retrying), then the snapshot's cumulative counters. Only the `error_class` column
    is ever selected — `payload` carries person data and stays unread.

    Nothing here FAILS the screen: a failed push with rows still queueing is the
    backoff working, and dead-letters already own the fail (exit 6) on the sinks line.
    """
    if conn is not None:
        try:
            row = conn.execute(
                "SELECT error_class, last_attempt_at FROM dead_letter"
                " ORDER BY last_attempt_at DESC, id DESC LIMIT 1"
            ).fetchone()
            if row is not None:
                return {
                    "state": Verdict.WARN,
                    "text": f"failed {row['error_class']} @ {row['last_attempt_at']}",
                    "exit": None,
                }
            row = conn.execute(
                "SELECT last_error_class, last_attempt_at FROM push_queue"
                " WHERE last_attempt_at IS NOT NULL"
                " ORDER BY last_attempt_at DESC, id DESC LIMIT 1"
            ).fetchone()
            if row is not None:
                return {
                    "state": Verdict.WARN,
                    "text": (
                        f"failing (retrying): {row['last_error_class']} @ {row['last_attempt_at']}"
                    ),
                    "exit": None,
                }
        except sqlite3.Error as exc:
            return {
                "state": Verdict.WARN,
                "text": f"unknown (push state unreadable: {exc})",
                "exit": None,
            }
    if snapshot is not None:
        metrics = {
            line["name"]: line.get("value")
            for line in snapshot.get("site_metrics", [])
            if isinstance(line, dict) and "name" in line
        }
        if metrics.get("push_failed"):
            return {
                "state": Verdict.WARN,
                "text": f"snapshot push_failed={metrics['push_failed']}",
                "exit": None,
            }
        if metrics.get("push_ok"):
            return {
                "state": Verdict.OK,
                "text": f"ok (snapshot push_ok={metrics['push_ok']})",
                "exit": None,
            }
    return {"state": Verdict.WARN, "text": "unknown (no push state here)", "exit": None}


def _roster_section(site: Any, now: datetime) -> dict[str, Any]:
    """Age since the last roster push, from the artifact the roster leg actually
    leaves on disk: a csv sink's `.roster` companion file (newest mtime across the
    rotated names — `sink_writers.roster_path` derives them as `<stem>[-<stamp>].roster
    <suffix>`). An https or jsonl sink leaves no dedicated roster artifact (jsonl's
    roster shares the self-describing punch stream; an https roster is a POST nobody
    records locally), so their age is honestly `unknown` — never a guessed number."""
    ages: list[float] = []
    for spec in site.effective_sinks:
        if spec.type != "csv" or not spec.path:
            continue
        base = Path(spec.path)
        try:
            candidates = list(base.parent.glob(f"{base.stem}*.roster{base.suffix}"))
        except OSError:
            candidates = []
        for candidate in candidates:
            age = _mtime_age(candidate, now)
            if age is not None:
                ages.append(age)
    if ages:
        return {"state": Verdict.OK, "text": f"{_fmt_age(min(ages))} ago", "exit": None}
    return {"state": Verdict.WARN, "text": "unknown (no roster artifact here)", "exit": None}


def _device_section(state_dir: Path, now: datetime) -> dict[str, Any]:
    """Device reachability, CACHED ONLY (the card's law: status must not hammer the
    device, and the offline suite proves this line opens no socket).

    A probe result fresher than DEVICE_PROBE_MAX_AGE_S is a fact — ok, or an exit-4
    fail when the probe said unreachable (the failure text is the cached CLASS-level
    detail, which by sink_cli's precedent names statuses and exceptions, never
    payloads). Anything older is a memory, and the honest line points at the probe:
    `run: gateclerk doctor`. No cache file at all is the same line — the sanctioned
    writer (CLI-DOCTOR) has not run here yet."""
    cached = _read_json_object(state_dir.joinpath(*PROBE_CACHE_PARTS))
    if cached is not None:
        age = _age_s(_parse_iso(str(cached.get("checked_at") or "")), now)
        if age is not None and age <= DEVICE_PROBE_MAX_AGE_S:
            if cached.get("ok"):
                return {"state": Verdict.OK, "text": f"ok ({_fmt_age(age)} ago)", "exit": None}
            detail = str(cached.get("detail") or "probe reported failure")
            return {
                "state": Verdict.FAIL,
                "text": f"unreachable ({_fmt_age(age)} ago): {detail[:160]}",
                "exit": 4,
            }
    return {"state": Verdict.WARN, "text": "unknown — run: gateclerk doctor", "exit": None}


def _config_section(site: Any) -> dict[str, Any]:
    """Config sanity beyond the parser — which already ran, because a block that
    fails validation raises at parse and never reaches a screen. The one key whose
    absence changes what the operator SEES downstream is `device_code`: Task 15's
    roster names the device by serial when it is unset (the ingest resolves serial ->
    code itself), so this is a WARN with the fix line, not a fail. When no https sink
    exists the roster never crosses a wire and the key is genuinely not needed."""
    needs_code = any(spec.type == "https" for spec in site.effective_sinks)
    if needs_code and not site.device_code:
        return {
            "state": Verdict.WARN,
            "text": (
                "device_code unset — the roster names this device by serial; set "
                "device_code in sites.toml to use the BC code"
            ),
            "exit": None,
        }
    return {"state": Verdict.OK, "text": "", "exit": None}
