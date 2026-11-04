"""SINKS-WIRING: the sink-side half of the fan-out — file writers, renderers, https factory.

SINKS-CORE shipped the config (`[[site.sink]]`, the type registry) and the per-sink queue
schema; this module is what the DRAIN talks to. It owns three things and nothing else:

* **the file sinks' writer** (`FileSinkWriter`) — the `(ref, body) -> status` callable a
  csv/jsonl sink drains through, plus the row renderer that turns a queued payload into a
  documented line;
* **the renderers** (`csv_line_for`, `json_line_for`, `roster_csv_line_for`) — the row
  shapes, kept here so the drain, the roster leg and any ad-hoc exporter agree byte-for-byte;
* **the https factory** (`build_https_sink_transport`) — Task 15's transport built from a
  sink's own token REF, so a sink may address a different token than its site's default.

The queue layer is untouched: `agent_push.drain` still receives one transport per sink,
still decides backoff, and still marks rows acked. Nothing here reads or writes `push_queue`
or `dead_letter` — that seam belongs to the pusher, and a sink that could touch the queue
could also clear its own backlog.

Why the transport renders its own rows
--------------------------------------
The queue's contract with a sink is two fields (`SinkSpec.name` + `.ref`) and it holds no
type-specific branch — that is what lets a new type be added without touching the queue. So
`drain` cannot know that a csv row needs columns while a jsonl row needs the payload
verbatim. Instead a transport may declare one optional capability:

    renders_rows = True
    render(payload, row_meta) -> str      # raising fails the ROW, exactly like a transport raise

`drain` supplies the facts only it owns (the queue row's `event_id`, its `sink_name`, its
`enqueued_at`) through `row_meta`, and the transport turns them plus the payload into the
line. A plain `(url, body) -> status` transport — `stub_transport`, `HttpsIngestTransport`,
every test fake — declares nothing and receives the payload unchanged, so the wire contract
and Task 15's tests stay byte-identical.

fsync-then-mark-acked (the law this module exists to obey)
----------------------------------------------------------
The queue's rule is that the send attempt happens before the DELETE, so a crash leaves the
row queued and the punch is re-delivered. A file sink inverts the physical order — the
"delivery" is a local write that can complete long before the ack — so durability has to be
stated explicitly:

    append + flush + os.fsync  ->  return 200  ->  drain DELETEs the queue row

`os.fsync` runs before any success is reported, so when `drain` deletes the row the bytes are
on the storage device, not in the page cache. A kill between the fsync and the delete leaves
BOTH artifacts (the line in the file, the row in the queue) and the row is delivered twice —
at-least-once, the same posture the https leg has, with the ingest-side idempotency key still
the dedupe authority. The reverse order (delete, then write) is the loss this law prevents:
a kill would drop the punch with no queue row and no dead-letter row to account for it.

Loud, never silent
------------------
A file sink that cannot write (path missing and un-creatable, permissions, path is a
directory, disk full) raises. `drain` turns that into a failed row — backoff, error class,
and eventually a dead-letter row that keeps the payload — and the agent's warn line names the
sink and the exception class. Returning 200 for a write that did not land is the one thing
this module may never do: it would mark the punch acked and delete the only record that it
was ever queued.

Rotation
--------
`daily` (the default) writes `<stem>-YYYY-MM-DD<suffix>`, `monthly` writes
`<stem>-YYYY-MM<suffix>`; the stamp is the UTC date of the line being written, and every line
of one pass lands in one file. The suffix survives because `csv`/`jsonl` is the type the
registry validated, so a reader can glob the series (`archive-*.csv`). `rotation=None`
(constructible, not reachable from config, whose default is `daily`) keeps the declared path
verbatim.
"""

from __future__ import annotations

import csv
import io
import json
import os
import threading
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from gateclerk.agent_push import default_row_meta
from gateclerk.model import RECORD_JSON_KEYS
from gateclerk.sinks import CSV_COLUMNS, SinkSpec

__all__ = [
    "REF_MISMATCH_STATUS",
    "ROSTER_CSV_COLUMNS",
    "ROSTER_CSV_COLUMNS_DOC",
    "ROTATED_STEM_LAW",
    "FileSinkWriter",
    "RosterSinkRow",
    "build_https_sink_transport",
    "csv_line_for",
    "default_row_meta",
    "is_roster_payload",
    "json_line_for",
    "roster_csv_line_for",
    "roster_stamp",
    "rotated_path",
    "rotation_date",
]

#: The rotation file-naming law, documented beside the code that implements it so an
#: operator reading the archive directory can predict the names.
ROTATED_STEM_LAW = (
    "daily -> <stem>-YYYY-MM-DD<suffix> · monthly -> <stem>-YYYY-MM<suffix> "
    "(the UTC date of the line written)"
)

#: A writer aimed at a sink that is not its own answers this status rather than raising: the
#: row's error class becomes `HttpStatus409` — "this sink is wired to the wrong target" —
#: which a bare exception class would not say, and the drain's failure model stays one shape.
REF_MISMATCH_STATUS = 409

#: The roster companion file's columns, in order, FOREVER (append-only — the same law
#: `sinks.CSV_COLUMNS` states for punch rows). A roster line is not an event, so it gets its
#: own table: `sink_name` + `enqueued_at` (a roster never enters the queue, so its own
#: production stamp IS the delivery stamp), then the roster line's own keys with `users` LAST
#: as JSON text (a list of objects: quoted, and last so a naive splitter still reads every
#: named field before it reaches this one).
ROSTER_CSV_COLUMNS: tuple[str, ...] = (
    "sink_name",
    "enqueued_at",
    "kind",
    "deviceCode",
    "users",
)

#: The prose half of that promise, importable so a test can require the columns and their
#: documentation to live in the same file (SINKS-CORE's precedent for `CSV_COLUMNS`: an
#: undocumented "stable" column set is one that changes the first time someone needs it).
ROSTER_CSV_COLUMNS_DOC = """\
csv sink roster columns (stable, append-only, in this order):
  sink_name    which sink wrote the row (attribution without re-reading the config)
  enqueued_at  when the roster was produced (UTC ISO, seconds) — its own production stamp
  kind         always 'device_users' (the ingest's classifier word, carried verbatim)
  deviceCode   the BC device code the roster names the device by
  users        the users list as JSON text, LAST (quoted; a naive splitter still reads
               every named field before it reaches this one)
"""

#: The envelope columns each table declares, checked against whatever `row_meta` supplies.
_PUNCH_ENVELOPE: tuple[str, ...] = CSV_COLUMNS[:3]
_ROSTER_ENVELOPE: tuple[str, ...] = ROSTER_CSV_COLUMNS[:2]


# --- the row renderers ------------------------------------------------------------------------


def _payload_dict(payload: str) -> dict[str, Any]:
    """A payload line back to its record dict, or raise.

    The raise is the point. A line that is not a JSON object cannot be projected into the
    stable columns, and writing empty cells for named columns would be exactly the silent
    contract drift `CSV_COLUMNS` exists to prevent. The caller (`drain`) turns this into a
    failed row: error class on the row, backoff, eventual dead-letter — never a skip.
    """
    text = payload.strip()
    if not text:
        raise ValueError("empty payload: a file sink row must carry the stored line")
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise ValueError(
            f"payload line parsed as {type(parsed).__name__}, not an object: the stable "
            "columns cannot be projected from it"
        )
    return parsed


def _require_meta(row_meta: Mapping[str, str] | None, needed: tuple[str, ...]) -> dict[str, str]:
    """The envelope, validated to cover the columns the target table declares.

    A caller-supplied builder that omits one is refused rather than filled with an empty
    string: a blank `sink_name` in a column documented as "attribution without re-reading
    the config" is a lie that outlives the bug that wrote it.
    """
    if row_meta is None:
        raise ValueError(
            f"a file sink row requires its envelope ({', '.join(needed)}): those columns are "
            "part of the documented file-sink contract and may not be written blank"
        )
    missing = [key for key in needed if key not in row_meta]
    if missing:
        raise ValueError(
            f"row envelope is missing column(s) {missing} — {list(needed)} are part of the "
            "documented file-sink contract and may not be written blank"
        )
    return dict(row_meta)


def csv_line_for(*, payload: str, row_meta: Mapping[str, str] | None, roster: bool = False) -> str:
    """Render one csv sink line (no header, newline-terminated).

    Column order is `CSV_COLUMNS`: the envelope, then every `RECORD_JSON_KEYS` field in the
    contract's own order. A key the payload does not carry becomes an empty field — the
    contract is append-only at the FRONT, a missing key is a value the record genuinely
    lacks, and `event_id`/`sink_name` still trace the row back to the queue row and the
    store. `raw` is JSON text: quoted by the writer, and last, so a naive splitter that stops
    at the first unquoted comma still reads every named field.

    `roster=True` renders the companion table instead (`ROSTER_CSV_COLUMNS`).
    """
    if roster:
        return roster_csv_line_for(payload=payload, row_meta=row_meta)
    if is_roster_payload(payload):
        raise ValueError(
            "a device_users line is not a punch: a csv sink keeps roster rows in its "
            "companion table (render_roster), so the punch archive stays one table"
        )
    meta = _require_meta(row_meta, _PUNCH_ENVELOPE)
    record = _payload_dict(payload)
    values = [meta[key] for key in _PUNCH_ENVELOPE]
    values.extend(_cell(record.get(key)) for key in RECORD_JSON_KEYS)
    return _csv_row(values)


def json_line_for(*, payload: str, row_meta: Mapping[str, str] | None) -> str:
    """Render one jsonl sink line: the stored payload bytes, verbatim, exactly one newline.

    No envelope and no re-serialisation. The stored line IS the wire line (the ingest
    fingerprints those exact bytes), so a jsonl sink is a copy of what the https sink would
    have sent — a reformatted copy would be a second truth about the same punch.
    """
    del row_meta  # the envelope is a csv construct; the jsonl line is the payload itself
    return payload if payload.endswith("\n") else f"{payload}\n"


def roster_csv_line_for(*, payload: str, row_meta: Mapping[str, str] | None) -> str:
    """Render one roster line into a csv sink's companion table (`ROSTER_CSV_COLUMNS`)."""
    meta = _require_meta(row_meta, _ROSTER_ENVELOPE)
    parsed = _payload_dict(payload)
    if parsed.get("kind") != "device_users":
        raise ValueError(
            "the roster table takes a device_users line only: routing a punch line here "
            "would remove it from the archive while looking delivered"
        )
    return _csv_row(
        [
            meta["sink_name"],
            meta["enqueued_at"],
            str(parsed.get("kind")),
            _cell(parsed.get("deviceCode")),
            _json_cell(parsed.get("users")),
        ]
    )


def roster_stamp(moment: datetime) -> str:
    """The roster row's `enqueued_at`: its own production stamp (UTC ISO, seconds).

    A roster never enters the queue, so there is no queue row to read a stamp from — the
    instant the loop produced the line IS the delivery stamp, and `RosterSinkRow` carries it
    for the same reason the punch rows carry the queue's: a reader must be able to tell how
    old a roster line is without guessing.
    """
    if moment.tzinfo is None:
        raise ValueError("roster stamps must be tz-aware (payroll data; pyproject DTZ)")
    return moment.astimezone(UTC).isoformat(timespec="seconds")


class RosterSinkRow:
    """The envelope a roster row carries (a roster is not an event, so it has no event_id).

    Exists so the roster leg and the punch leg hand a writer the same callable shape instead
    of inventing two conventions: `as_meta()` produces the mapping the roster renderer checks.
    """

    __slots__ = ("enqueued_at", "sink_name")

    def __init__(self, *, sink_name: str, enqueued_at: str) -> None:
        self.sink_name = sink_name
        self.enqueued_at = enqueued_at

    def as_meta(self) -> dict[str, str]:
        return {"sink_name": self.sink_name, "enqueued_at": self.enqueued_at}


def is_roster_payload(payload: str) -> bool:
    """Is this a roster line? The rule is the INGEST's own classifier word, nothing else.

    `{"kind": "device_users"}` is what `gateclerk_ingest` branches on (the frozen contract), so
    anything else is a punch line and must never reach the roster table — a heuristic here
    would silently split payroll from the archive and still look like a successful push.
    """
    text = payload.strip()
    if not text.startswith("{") or "device_users" not in text:
        return False
    try:
        parsed = json.loads(text)
    except ValueError:
        return False
    return isinstance(parsed, dict) and parsed.get("kind") == "device_users"


def _cell(value: Any) -> str:
    """One CSV cell: None -> empty, bool -> true/false, mapping/list -> JSON, else str().

    `str()` rather than `json.dumps()` for scalars on purpose: a payroll reader opening the
    file in a spreadsheet wants `5` and `in`, not `"5"` and `"in"`. The values stay exactly
    the record's own, and the CSV writer handles any separator they contain.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)):
        return str(value)
    return _json_cell(value)


def _json_cell(value: Any) -> str:
    if value is None:
        return ""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _csv_row(values: list[str]) -> str:
    buffer = io.StringIO()
    csv.writer(buffer, lineterminator="\n").writerow(values)
    return buffer.getvalue()


# --- rotation ----------------------------------------------------------------------------------


def rotation_date(moment: datetime) -> datetime:
    """The UTC instant rotation is keyed on (one resolution per drain pass)."""
    if moment.tzinfo is None:
        raise ValueError("sink rotation needs a tz-aware stamp (payroll data; pyproject DTZ)")
    return moment.astimezone(UTC)


def rotated_path(path: Path, rotation: str | None, moment: datetime) -> Path:
    """The file a line stamped `moment` belongs to.

    `daily` -> `<stem>-YYYY-MM-DD<suffix>`, `monthly` -> `<stem>-YYYY-MM<suffix>`; anything
    else (including `None`, which config cannot produce but a hand-built spec can) keeps the
    declared path verbatim — an operator who configured a path must find that file.
    """
    if rotation not in ("daily", "monthly"):
        return path
    when = rotation_date(moment)
    stamp = when.strftime("%Y-%m-%d" if rotation == "daily" else "%Y-%m")
    return path.with_name(f"{path.stem}-{stamp}{path.suffix}")


# --- the file sink's writer --------------------------------------------------------------------


class FileSinkWriter:
    """A csv/jsonl sink's `Transport`: appends one rendered body to the sink's rotated file.

    The shape is the seam P2-04 defined — `(ref, body) -> status` — so the queue, the ladder
    and the dead-letter machinery are unchanged by the existence of file sinks. A 200 answer
    means exactly one thing: the bytes are fsynced. Every other outcome raises, and `drain`
    turns that into a failed row (never a silent drop).

    One instance is one sink's writer, and a process holds at most one per sink: the header
    decision is cached per file, so "the header is written once per rotation file" holds
    across appends within a run and across restarts (a fresh instance reads the file).

    `renders_rows` / `render` are the optional capability the drain uses (module docstring):
    the sink's format is the sink's business, and `drain` only supplies the queue's facts.
    """

    renders_rows = True

    def __init__(
        self,
        spec: SinkSpec,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if spec.type not in ("csv", "jsonl"):
            raise TypeError(
                f"sink {spec.name!r} is type {spec.type!r}: a FileSinkWriter serves csv and "
                "jsonl sinks only (an https sink needs the bearer transport)"
            )
        if not spec.path:
            raise ValueError(
                f"sink {spec.name!r} has no path: the registry mints `path` for a file sink, "
                "so a spec without one did not come from the registry"
            )
        self.spec = spec
        self.path = Path(spec.path)
        self._clock = now
        self._lock = threading.Lock()
        self._header_written: set[str] = set()

    # --- the render seam (the drain calls this before the send) ------------------------------
    def render(self, payload: str, row_meta: Mapping[str, str] | None = None) -> str:
        """A queued payload -> the documented line for this sink's format.

        Raises for a payload that cannot be rendered; the drain maps that onto the row
        exactly as it maps a transport raise, so the row keeps its backoff and its eventual
        dead-letter instead of vanishing.
        """
        if self.spec.type == "csv":
            return csv_line_for(payload=payload, row_meta=row_meta)
        return json_line_for(payload=payload, row_meta=row_meta)

    def render_roster(self, payload: str, row_meta: Mapping[str, str] | None = None) -> str:
        """A roster line -> this sink's roster row (csv companion table only)."""
        return roster_csv_line_for(payload=payload, row_meta=row_meta)

    # --- the Transport seam ----------------------------------------------------------------
    def __call__(self, ref: str, body: str) -> int:
        if ref != self.spec.ref:
            return REF_MISMATCH_STATUS
        if not body:
            raise ValueError(f"sink {self.spec.name!r}: refusing to append an empty body")
        moment = self._clock() if self._clock is not None else datetime.now(UTC)
        return self._append(
            rotated_path(self.path, self.spec.rotation, moment), body, list(CSV_COLUMNS)
        )

    def write_line(self, body: str, *, moment: datetime) -> int:
        """Append one already-rendered line to this sink's rotated PUNCH file.

        The clock-aware sibling of `__call__`, for a caller that is not the queue: the roster
        leg delivers a line outside `push_queue`, so there is no row to ask and the loop's own
        instant is the only honest rotation stamp (a roster that landed in "today's" file
        while the punches were in another day's would be two calendars for one site). Same
        fsync-then-success law, same header rule, no envelope.
        """
        if not body:
            raise ValueError(f"sink {self.spec.name!r}: refusing to append an empty body")
        return self._append(rotated_path(self.path, self.spec.rotation, moment), body, None)

    def write_roster(self, body: str, *, moment: datetime) -> int:
        """Append one roster row to a csv sink's companion table (same fsync law).

        Returns 200 only when the bytes are durable, exactly like `__call__`. The roster leg
        never dead-letters, so a raise here becomes its warn-and-retry-next-hour line.
        """
        if self.spec.type != "csv":
            raise TypeError(
                f"sink {self.spec.name!r} is type {self.spec.type!r}: only a csv sink keeps a "
                "roster companion table (a jsonl line is self-describing, so it shares the "
                "punch stream)"
            )
        return self._append(self.roster_path(moment), body, list(ROSTER_CSV_COLUMNS))

    def roster_path(self, moment: datetime) -> Path:
        """Where a csv sink keeps roster rows: the punch name + `.roster` before the suffix.

        `archive.csv` + daily -> `archive-2026-10-19.roster.csv`. Deliberately a SEPARATE
        file, and deliberately derived from the rotated punch name: a punch archive payroll
        opens must not acquire rows of a different table, while both files still sit in the
        directory the operator declared and still roll on the sink's own rotation (one
        outage, one date range, no file that grows forever).
        """
        stamped = rotated_path(self.path, self.spec.rotation, rotation_date(moment))
        return self._roster_of(stamped)

    def _roster_of(self, target: Path) -> Path:
        return target.with_name(f"{target.stem}.roster{target.suffix}")

    # --- the write -------------------------------------------------------------------------
    def _append(self, target: Path, body: str, header_columns: list[str] | None) -> int:
        text = body if body.endswith("\n") else f"{body}\n"
        with self._lock:
            # Path created if missing (the card's law): a declared data directory the first
            # delivery has to create is normal, and refusing would be a mystery outage. A
            # directory that cannot be created raises, and the row stays queued.
            target.parent.mkdir(parents=True, exist_ok=True)
            header = self._pending_header(target, header_columns)
            handle = target.open("a", encoding="utf-8")
            try:
                if header is not None:
                    handle.write(header)
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())  # fsync-then-mark-acked (module docstring)
            finally:
                handle.close()
            self._header_written.add(str(target))
        return 200

    def _pending_header(self, target: Path, header_columns: list[str] | None) -> str | None:
        """The header line, when this file has not been given one yet.

        Headered files are csv ones only (a jsonl file has no header by definition), and the
        roster companion table gets its OWN column set — two tables, two headers, one writer.
        The decision reads the file rather than memory, so a fresh writer object over an
        existing file never duplicates the header: the same answer within a run and across
        restarts.
        """
        if header_columns is None or self.spec.type != "csv":
            return None
        key = str(target)
        if key in self._header_written:
            return None
        if target.exists() and target.stat().st_size > 0:
            return None
        return _csv_row(header_columns)


# --- the https sink's transport (Task 15 verbatim, addressed per sink) -------------------------


def build_https_sink_transport(
    site: str,
    spec: SinkSpec,
    *,
    env: Mapping[str, str] | None = None,
    keychain: Any = None,
    client: Any = None,
) -> Any:
    """Task 15's `HttpsIngestTransport` for one sink — same class, same wire contract.

    The sink layer adds one thing: WHERE the bearer comes from. `token_env` names an env var
    and `token_keychain` names a keychain SERVICE (both REFERENCES — a sink block cannot carry
    a value, SINKS-CORE's refusal), and a sink declaring neither falls through to the site's
    own rungs (`GATECLERK_INGEST_TOKEN_<SITE>` / `gateclerk-ingest-<site>`), which is why the
    implicit `legacy` sink needs no new keychain item at upgrade.

    A sink's extra `headers` ride on the request through a thin wrapper rather than by editing
    the transport: the two headers the wire contract owns (`Authorization`,
    `X-Gateclerk-Site`) stay the transport's, and `token_available` passes through so the
    agent's "no token -> skip this cycle, keep the rows queued" law still applies.
    """
    from gateclerk.agent_push import https_transport

    base = https_transport(
        site,
        token=_sink_token(site, spec, env=env, keychain=keychain),
        env=env,
        keychain=keychain,
        client=client,
    )
    extra = dict(spec.headers or {})
    return base if not extra else _HeaderAppendingTransport(base, extra)


class _HeaderAppendingTransport:
    """A sink's own headers on top of Task 15's transport (contract: still `-> status`).

    Deliberately not a subclass: `HttpsIngestTransport` owns the token rungs and the header
    pair the frozen contract names, and wrapping it keeps `test_t15_push_https.py` the
    unchanged authority on what goes on the wire.
    """

    def __init__(self, base: Any, headers: Mapping[str, str]) -> None:
        self._base = base
        self._extra = dict(headers)

    def __call__(self, url: str, body: str) -> int:
        base = self._base
        original_post = base._client.post
        extra = self._extra

        def post(target: str, *, content: Any = None, headers: Any = None, **kw: Any) -> Any:
            merged = dict(headers or {})
            merged.update(extra)
            return original_post(target, content=content, headers=merged, **kw)

        base._client = _DelegatingClient(base._client, post)
        try:
            return int(base(url, body))
        finally:
            base._client = base._client._inner

    def token_available(self) -> bool:
        return bool(self._base.token_available())

    @property
    def token_label(self) -> str | None:
        return self._base.token_label

    def close(self) -> None:
        self._base.close()


class _DelegatingClient:
    """The narrowest shim possible: one replaced method, everything else delegated."""

    def __init__(self, inner: Any, post: Any) -> None:
        self._inner = inner
        self.post = post

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def _sink_token(
    site: str,
    spec: SinkSpec,
    *,
    env: Mapping[str, str] | None,
    keychain: Any,
) -> Any:
    """Resolve a sink's token REF to a `Secret`, or None for the transport's own rungs.

    `token_env` outranks `token_keychain` (the p1-02 spirit: the cheaper, more explicit source
    first), and an env var that exists but is empty is not a token — `Secret`'s own rule
    treats a blank as absent, so the site rungs still get their turn. A keychain read that
    fails raises `CredentialUnavailable` from `config`, which `HttpsIngestTransport` turns into
    its ingest-specific message naming the service and the `security` command. No value is
    ever printed here; the label names the SOURCE only.
    """
    from gateclerk.config import DeviceTarget, KeychainReader
    from gateclerk.secrets import Secret

    environ: Mapping[str, str] = os.environ if env is None else env
    if spec.token_env:
        value = environ.get(spec.token_env)
        if value:
            return Secret(value, label=f"env:{spec.token_env}")
    if spec.token_keychain:
        reader = keychain if keychain is not None else KeychainReader()
        item = reader.read(
            DeviceTarget(host=site, site=site, keychain_service=spec.token_keychain),
            with_comment=False,
        )
        return item.password
    return None
