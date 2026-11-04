"""SINKS-WIRING: the drain fans out — per-sink backoff, per-sink dead-letter, local sinks.

BINDING SPEC: the operator's named-sinks goal + this card's wiring law. SINKS-CORE shipped
the config (`[[site.sink]]` + the type registry) and the per-sink queue schema
(`(event_id, sink_name)` via v5/v6). This file is the DRAIN side of that contract:

  (a) a failing https sink NEVER blocks or starves csv/jsonl sinks: each site drain pushes
      its pending batch to EVERY enabled sink independently, per-sink backoff ladder
      (today's 1→30 s cap ladder PER SINK), no shared head-of-line — a sink at its batch
      cap just stops claiming its own rows;
  (b) per-sink dead-letter isolation — a poison row dead-letters in ONE sink only, and a
      success on another sink does not clear it;
  (c) the implicit `push_target` sink behaves EXACTLY like today (upgrade-inert): zero
      config change, zero behaviour change, and ledger lines written BEFORE the upgrade
      keep excluding exactly the events they excluded before;
  (d) the roster (hourly device_users) fans out to every sink that accepts it, keeps the
      warn-and-retry-next-hour law PER SINK, csv/jsonl sinks store roster lines as
      documented rows, and a roster NEVER dead-letters (it is re-derivable from the
      device; only punches dead-letter — T15's law, now per sink).

The file sinks' own law, pinned here too: append with the stable columns
(`sinks.CSV_COLUMNS`, pinned by SINKS-CORE), fsync-then-mark-acked (the bytes are durable
BEFORE the queue row is deleted — the same crash-safety law the queue is built on),
rotation `daily|monthly` per sink config, path created if missing, refusal LOUD (a warn
line naming the sink and the exception class) and never silent loss (the row stays queued).

Offline by construction: the https leg is `httpx.MockTransport` — the fake transport arms
are the ones from test_t15_push_https.py, imported rather than duplicated (the card's
rule) — every path is under tmp_path, and the real keychain is never read (every
credential-shaped value here is a recognisable placeholder per test_repo_hygiene).

RED-FIRST: `gateclerk.sink_writers` and the `sink_name=`/`row_meta=`/`sinks=` seams below do
not exist yet, so this file's new cases fail before the wiring lands. The two cases in the
(c) section are deliberately expressible against today's code: they are the upgrade-inert
proof and must be green BEFORE and AFTER.
"""

from __future__ import annotations

import csv
import json
import sqlite3
from dataclasses import fields
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import gateclerk.agent_cli as agent_cli
import gateclerk.agent_db as agent_db
import gateclerk.agent_push as agent_push
import gateclerk.agent_store as agent_store
from gateclerk.agent_loop import DeviceLoop
from gateclerk.agent_push import ingest_keychain_service, ingest_token_env_var
from gateclerk.config import SiteConfig
from gateclerk.model import RECORD_JSON_KEYS, EventRecord, UserRecord, to_jsonl
from gateclerk.sinks import CSV_COLUMNS, IMPLICIT_SINK_NAME, SinkSpec
from test_p2_07b_agent_cli import AgentHarness, punch_events, seeded_device
from test_t15_push_https import (
    HTTPS_TARGET,
    SITE,
    T0,
    TOKEN,
    Rng,
    at,
    client_for,
    make_record,
)

HOST = "192.0.2.10"  # TEST-NET (tests/test_repo_hygiene.py allowlist)

#: A sink name that config cannot produce (`+` is rejected by the identifier rule): the
#: shape only the v5/v6 migration mints. Used by the identity-isolation probes.
MIGRATED_SHAPE = "legacy+999"


def iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="seconds")


def writers_mod() -> Any:
    """The module under test, imported lazily so the (c) upgrade-inert cases stay
    collectable against today's code (they must be green before the wiring lands)."""
    import gateclerk.sink_writers as sink_writers

    return sink_writers


# --- fixture: a real per-sink queue in a tmp-dir db -------------------------------------------


def real_db(tmp_path: Path) -> sqlite3.Connection:
    tmp_path.mkdir(parents=True, exist_ok=True)
    return agent_db.connect(tmp_path / "gateclerk-site-a.sqlite3", now_iso=iso(T0))


def store(db: sqlite3.Connection, record: EventRecord) -> int:
    """Store one record the real way; return its `events` rowid."""
    result = agent_store.store_events(db, [record], now=T0)
    assert result.inserted == 1
    row = db.execute(
        "SELECT id FROM events WHERE device_serial = ? AND serial_no = ?",
        (record.device_serial, record.serial_no),
    ).fetchone()
    return int(row["id"])


def store_n(db: sqlite3.Connection, n: int, *, start: int = 5700) -> tuple[int, ...]:
    return tuple(
        store(db, make_record(serial_no=start + i, employee_no=str(i + 1))) for i in range(n)
    )


def queue(
    db: sqlite3.Connection,
    ids: Any,
    *,
    sink: SinkSpec,
    now: datetime = T0,
    sink_name: str | None = None,
) -> None:
    agent_push.enqueue_events(db, ids, endpoint=sink.ref, sink_name=sink_name or sink.name, now=now)


def specs(tmp_path: Path, *, rotation: str = "daily") -> dict[str, SinkSpec]:
    """A three-sink site: one https ingest leg + one csv archive + one jsonl feed."""
    archive = tmp_path / "archive.csv"
    feed = tmp_path / "feed.jsonl"
    return {
        "bc": SinkSpec(name="bc", type="https", ref=HTTPS_TARGET),
        "archive": SinkSpec(
            name="archive",
            type="csv",
            ref=f"file://{archive}",
            path=str(archive),
            rotation=rotation,
        ),
        "feed": SinkSpec(
            name="feed",
            type="jsonl",
            ref=f"file://{feed}",
            path=str(feed),
            rotation=rotation,
        ),
    }


def FileSinkWriter(sink: SinkSpec, *, now: datetime = T0) -> Any:  # noqa: N802
    """A writer on the FROZEN clock: rotation stamps the file name, and a test that lets
    the wall clock decide the name would fail on the 20th of the following month.

    The helper is deliberately NAMED like the class it wraps — every call site below reads
    as constructing the real writer, only pinned to a frozen clock; a `make_writer` name
    would hide which object the test is actually exercising.
    """
    return writers_mod().FileSinkWriter(sink, now=lambda: now)


def row_meta(**over: str) -> Any:
    """The envelope builder a caller hands `drain` (production uses the default).

    Returns the callable shape `drain` calls: `(event_id, sink_name, enqueued_at)`.
    """

    def build(event_id: int, sink_name: str, enqueued_at: str) -> dict[str, str]:
        return {
            "event_id": str(event_id),
            "sink_name": sink_name,
            "enqueued_at": over.get("enqueued_at", enqueued_at),
        }

    return build


def drain_sink(
    db: sqlite3.Connection,
    sink: SinkSpec,
    transport: Any,
    *,
    now: datetime = T0,
    limit: int | None = None,
    dead_letter_after_s: int = 86400,
    sink_name: str | None = None,
    row_meta_fn: Any = None,
) -> Any:
    kwargs: dict[str, Any] = {
        "endpoint": sink.ref,
        "transport": transport,
        "now": now,
        "rng": Rng(1.0),
        "dead_letter_after_s": dead_letter_after_s,
        "sink_name": sink_name or sink.name,
    }
    if limit is not None:
        kwargs["limit"] = limit
    if row_meta_fn is not None:
        kwargs["row_meta"] = row_meta_fn
    return agent_push.drain(db, **kwargs)


def csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def at_path(tmp_path: Path, base: str, *, rotation: str = "daily") -> Path:
    """The rotated file the declared `base` name lands in, on the frozen clock.

    Rotation is the sink's config (default `daily`), so a test that read `archive.csv` would
    be asserting a filename the code only writes when rotation is off — this is the same
    helper the writer uses, so the expectation and the write cannot drift apart.
    """
    return writers_mod().rotated_path(tmp_path / base, rotation, T0)


class SilentClient:
    """The device client the roster/fan-out tests hand a loop: never knocked on."""

    def circuit_open(self) -> bool:
        return False

    def close(self) -> None:
        return None


class RecordingKeychain:
    """A KeychainReader stand-in that records WHICH SERVICE it was asked for."""

    def __init__(self, items: dict[str, str]) -> None:
        self.items = items
        self.services: list[str] = []

    def read(self, target: Any, *, with_comment: bool = True) -> Any:
        from gateclerk.secrets import Secret

        self.services.append(target.keychain_service)
        return type(
            "Item", (), {"password": Secret(self.items[target.keychain_service], label="k")}
        )()


class NoKeychain:
    def read(self, target: Any, *, with_comment: bool = True) -> Any:
        raise AssertionError("the env rung answered; the keychain must not be consulted")


def fanout_agent(
    tmp_path: Path,
    sink_map: dict[str, SinkSpec],
    *,
    site: SiteConfig | None = None,
    transports: dict[str, Any] | None = None,
    warn: Any = None,
) -> tuple[agent_cli.SiteAgent, sqlite3.Connection]:
    """A SiteAgent over a real db, wired to named sinks (no sockets, no keychain).

    The composition mirrors `build_site_agent`'s (real AlertPolicy over the same conn, one
    DeviceLoop) but injects per-sink transports so no token rung is ever resolved.
    """
    db = real_db(tmp_path)
    site = site or SiteConfig(
        name=SITE,
        host=HOST,
        iana_tz="Europe/Bucharest",
        sinks=tuple(sink_map.values()),
    )
    policy = agent_cli.AlertPolicy(
        site=SITE,
        cadence_s=site.cadence_s,
        now=lambda: T0,
        conn=db,
        park_dir=tmp_path / "park",
        sink=lambda _alert: None,
    )
    loop = DeviceLoop(
        client=SilentClient(),
        conn=db,
        site=SITE,
        site_tz="Europe/Bucharest",
        cadence_s=site.cadence_s,
        overlap_s=site.overlap_s,
        now=lambda: T0,
        monotonic=lambda: 0.0,
        sleep=lambda _s: None,
        warn=lambda _s: None,
        push_target=None,
        push_transport=None,
        sinks=tuple(sink_map.values()),
        roster=lambda: [],
    )
    agent = agent_cli.SiteAgent(
        site=site,
        loops=[loop],
        policy=policy,
        conn=db,
        db_path=str(tmp_path / "gateclerk-site-a.sqlite3"),
        sink_transports=dict(transports or {}),
        warn=warn if warn is not None else (lambda _s: None),
    )
    return agent, db


# =============================================================================================
# (a) a failing https sink never blocks the local sinks
# =============================================================================================


def test_https_502_loop_still_delivers_every_event_to_the_csv_and_jsonl_sinks(
    tmp_path: Path,
) -> None:
    """DoD (a): five drains against an ingest that 502s forever; the local files complete.

    Per-sink backoff is what makes this true: the https rows march their own 1→30 s ladder
    while the file sinks drain the SAME batch on the first pass. A shared ladder, or a
    drain that stopped at the first failing sink, would leave the files short.
    """
    db = real_db(tmp_path)
    ids = store_n(db, 3)
    sinks = specs(tmp_path)
    for name in ("bc", "archive", "feed"):
        queue(db, ids, sink=sinks[name])
    client, capture = client_for(*([502] * 20))
    https = agent_push.https_transport(SITE, token=TOKEN, client=client)

    for step in range(5):
        drain_sink(db, sinks["bc"], https, now=at(60 * step))
        for name in ("archive", "feed"):
            drain_sink(db, sinks[name], FileSinkWriter(sinks[name]), now=at(60 * step))

    # Three rows per drain, five drains: the ladder delays a ROW, and at 60 s steps every
    # row is due again on every pass (the ladder caps at 30 s).
    assert len(capture.requests) == 15, "the https sink attempted every row of every drain"
    assert agent_push.dead_letter_depth(db) == 0, "five minutes is not the 24 h bound"
    bc_pending = agent_push.pending_rows(db, sink_name="bc")
    assert {r.event_id for r in bc_pending} == set(ids), "the https rows are still queued"
    assert {r.attempts for r in bc_pending} == {5}, "the ladder is the https sink's own"
    assert agent_push.pending_rows(db, sink_name="archive") == ()
    assert agent_push.pending_rows(db, sink_name="feed") == ()
    assert len(csv_rows(at_path(tmp_path, "archive.csv"))) == 3
    feed_lines = (at_path(tmp_path, "feed.jsonl")).read_text(encoding="utf-8").splitlines()
    assert len(feed_lines) == 3
    for line, event_id in zip(feed_lines, ids, strict=True):
        serial = db.execute("SELECT serial_no FROM events WHERE id = ?", (event_id,)).fetchone()[
            "serial_no"
        ]
        assert json.loads(line)["serial_no"] == serial


def test_drain_claims_only_its_own_sink_rows_and_honours_its_own_cap(tmp_path: Path) -> None:
    """No shared head-of-line: a drain filters on `sink_name`, and a capped sink only stops
    claiming ITS rows — the next sink's batch is untouched by that cap."""
    db = real_db(tmp_path)
    ids = store_n(db, 4)
    sinks = specs(tmp_path)
    for sink in sinks.values():
        queue(db, ids, sink=sink)

    result = drain_sink(db, sinks["archive"], FileSinkWriter(sinks["archive"]), limit=2)
    assert result.sink_name == "archive"
    assert result.push_ok == 2
    assert len(csv_rows(at_path(tmp_path, "archive.csv"))) == 2
    assert len(agent_push.pending_rows(db, sink_name="bc")) == 4
    assert len(agent_push.pending_rows(db, sink_name="feed")) == 4
    assert len(agent_push.pending_rows(db, sink_name="archive")) == 2

    drain_sink(db, sinks["archive"], FileSinkWriter(sinks["archive"]))
    assert len(csv_rows(at_path(tmp_path, "archive.csv"))) == 4


def test_the_backoff_ladders_are_per_sink_not_shared(tmp_path: Path) -> None:
    """One event, two sinks: failing https accrues attempts and starts ITS outage clock
    while csv accepts the same event cleanly — no shared attempts, no shared clock."""
    db = real_db(tmp_path)
    (event_id,) = store_n(db, 1)
    sinks = specs(tmp_path)
    for sink in sinks.values():
        queue(db, [event_id], sink=sink)
    client, _capture = client_for(*([502] * 10))
    https = agent_push.https_transport(SITE, token=TOKEN, client=client)

    drain_sink(db, sinks["bc"], https)
    drain_sink(db, sinks["feed"], FileSinkWriter(sinks["feed"]))

    bc = agent_push.pending_rows(db, sink_name="bc")
    assert len(bc) == 1 and bc[0].attempts == 1
    assert bc[0].first_failed_at == iso(T0), "the outage clock is the https sink's own"
    assert bc[0].next_attempt_at > iso(T0), "rescheduled by the ladder, not shared state"
    assert agent_push.pending_rows(db, sink_name="feed") == ()
    # The third sink drains in the SAME pass and also takes the event cleanly: three sinks,
    # three independent outcomes, and only the https one's clock moved.
    drain_sink(db, sinks["archive"], FileSinkWriter(sinks["archive"]))
    assert agent_push.pending_rows(db, sink_name="archive") == ()
    assert len(csv_rows(at_path(tmp_path, "archive.csv"))) == 1
    assert agent_push.dead_letter_depth(db) == 0


def test_two_sinks_sharing_one_ref_keep_separate_delivery_state(tmp_path: Path) -> None:
    """Queue IDENTITY is the sink name, not the ref (SINKS-CORE's law, made visible in the
    wiring): two sinks aimed at one https ref each have their own row, ladder and clock."""
    db = real_db(tmp_path)
    (event_id,) = store_n(db, 1)
    bc = SinkSpec(name="bc", type="https", ref=HTTPS_TARGET)
    mirror = SinkSpec(name="mirror", type="https", ref=HTTPS_TARGET)
    queue(db, [event_id], sink=bc)
    queue(db, [event_id], sink=mirror)

    result = drain_sink(db, mirror, lambda url, body: 502)
    assert result.push_failed == 1
    other = agent_push.pending_rows(db, sink_name="bc")
    assert len(other) == 1 and other[0].attempts == 0, "the other sink's clock was not burned"


# =============================================================================================
# (b) per-sink dead-letter isolation
# =============================================================================================


class PoisonOnly:
    """An ingest that 502s ONE payload line and 200s every other (a real poison shape)."""

    def __init__(self, payload: str) -> None:
        self.payload = payload
        self.calls = 0

    def __call__(self, url: str, body: str) -> int:
        self.calls += 1
        return 502 if body.startswith(self.payload) else 200


def test_a_poison_row_dead_letters_in_one_sink_only(tmp_path: Path) -> None:
    """DoD (b): the https ingest 502s one row past the 24 h bound; the csv sink delivered
    that same row fine. Exactly one dead-letter row — keyed (event_id, sink_name) — on the
    failed sink only."""
    db = real_db(tmp_path)
    ids = store_n(db, 3)
    poison = ids[1]
    sinks = specs(tmp_path)
    for sink in sinks.values():
        queue(db, ids, sink=sink)
    poison_line = db.execute("SELECT jsonl FROM events WHERE id = ?", (poison,)).fetchone()["jsonl"]
    boundary = at(86401)  # past the 24 h bound (config's default)

    # The bound is measured from the row's FIRST failure, so a first pass at T0 stamps it
    # (the same two-pass shape tests/test_t15_push_https.py uses).
    drain_sink(db, sinks["bc"], PoisonOnly(poison_line), now=T0)
    drain_sink(db, sinks["bc"], PoisonOnly(poison_line), now=boundary, dead_letter_after_s=86400)
    drain_sink(db, sinks["archive"], FileSinkWriter(sinks["archive"]), now=boundary)

    dead = agent_push.dead_letter_rows(db)
    assert len(dead) == 1, f"expected exactly one dead-letter row, got {dead}"
    assert dead[0].event_id == poison
    assert dead[0].sink_name == "bc"
    assert dead[0].error_class == "HttpStatus502"
    assert dead[0].payload == poison_line, "the row carries the FULL payload for replay"
    assert dead[0].endpoint == sinks["bc"].ref
    assert agent_push.dead_letter_rows(db, sink_name="archive") == ()
    assert agent_push.dead_letter_rows(db, sink_name="feed") == ()
    assert len(csv_rows(at_path(tmp_path, "archive.csv"))) == 3, "the csv sink got all three rows"
    assert agent_push.pending_rows(db, sink_name="archive") == ()


def test_a_dead_letter_for_one_sink_survives_the_other_sinks_success(tmp_path: Path) -> None:
    """§2b's keep-everything, per sink: a punch that reached csv but not https keeps its
    https dead-letter row (the ingest has still not seen it), and only a successful push
    OF THAT SINK clears it."""
    db = real_db(tmp_path)
    (event_id,) = store_n(db, 1)
    sinks = specs(tmp_path)
    queue(db, [event_id], sink=sinks["bc"])
    boundary = at(86401)
    drain_sink(db, sinks["bc"], lambda url, body: 502, now=T0)  # stamps first_failed_at
    drain_sink(db, sinks["bc"], lambda url, body: 502, now=boundary)
    assert [d.sink_name for d in agent_push.dead_letter_rows(db)] == ["bc"]

    drain_sink(db, sinks["archive"], FileSinkWriter(sinks["archive"]), now=boundary)
    assert [d.sink_name for d in agent_push.dead_letter_rows(db)] == ["bc"], (
        "a success on another sink must not erase this sink's dead letter"
    )

    agent_push.replay_dead_letter(db, 1, now=boundary)
    drain_sink(db, sinks["bc"], lambda url, body: 200, now=at(90000))
    assert agent_push.dead_letter_depth(db) == 0
    assert agent_push.queue_depth(db) == 0


def test_the_fanout_queue_step_excludes_dead_letters_per_sink(tmp_path: Path) -> None:
    """The queue step's §2b exclusion is per sink: an event dead-lettered on https must not
    be re-queued FOR HTTPS (that is the poison loop), and must still be queueable for csv
    (a different identity, never served)."""
    db = real_db(tmp_path)
    store_n(db, 1)  # one stored event; the test asserts on the queue/dead-letter tables
    sinks = specs(tmp_path)
    assert agent_cli.queue_new_events(db, endpoint=sinks["bc"].ref, sink_name="bc", now=T0), (
        "the step queues an unseen event for its own sink"
    )
    drain_sink(db, sinks["bc"], lambda url, body: 502, now=T0)  # stamps first_failed_at
    drain_sink(db, sinks["bc"], lambda url, body: 502, now=at(86401))
    assert agent_push.dead_letter_depth(db) == 1

    assert agent_cli.queue_new_events(db, endpoint=sinks["bc"].ref, sink_name="bc", now=T0) == (), (
        "a dead-lettered key must never be re-queued for the same sink"
    )
    assert (
        agent_cli.queue_new_events(db, endpoint=sinks["archive"].ref, sink_name="archive", now=T0)
        != ()
    ), "csv is a different identity: it has never seen this event"


# =============================================================================================
# the file sinks' law: stable columns, fsync-then-mark-acked, rotation, loud refusal
# =============================================================================================


def test_csv_sink_writes_the_stable_columns_and_jsonl_sink_the_verbatim_line(
    tmp_path: Path,
) -> None:
    """The columns are the documented contract; the jsonl line is the stored bytes.

    `event_id`, `sink_name`, `enqueued_at`, then every `RECORD_JSON_KEYS` field in contract
    order with `raw` last as a quoted JSON field. The jsonl sink writes the queue payload
    byte-verbatim, so a reader diffing the two files sees one truth.
    """
    db = real_db(tmp_path)
    (event_id,) = store_n(db, 1)
    sinks = specs(tmp_path)
    queue(db, [event_id], sink=sinks["archive"], now=T0)
    queue(db, [event_id], sink=sinks["feed"], now=T0)

    drain_sink(db, sinks["archive"], FileSinkWriter(sinks["archive"]), row_meta_fn=row_meta())
    drain_sink(db, sinks["feed"], FileSinkWriter(sinks["feed"]), row_meta_fn=row_meta())

    rows = csv_rows(at_path(tmp_path, "archive.csv"))
    assert len(rows) == 1
    row = rows[0]
    assert list(row) == list(CSV_COLUMNS), "header IS the pinned stable column set, in order"
    assert row["event_id"] == str(event_id)
    assert row["sink_name"] == "archive"
    assert row["enqueued_at"] == iso(T0)
    assert row["employee_no"] == "1" and row["direction"] == "in"
    assert json.loads(row["raw"]) == make_record(serial_no=5700).raw

    stored_line = db.execute("SELECT jsonl FROM events WHERE id = ?", (event_id,)).fetchone()[
        "jsonl"
    ]
    assert (at_path(tmp_path, "feed.jsonl")).read_text(encoding="utf-8") == stored_line + "\n"


def test_a_sink_row_with_a_broken_envelope_fails_loudly_not_an_empty_column(
    tmp_path: Path,
) -> None:
    """A file sink row whose envelope cannot be built must fail the ROW, not write empty
    cells into columns the contract says are stable (a silently-blank `sink_name` column
    is exactly the undocumented drift CSV_COLUMNS exists to prevent)."""
    db = real_db(tmp_path)
    (event_id,) = store_n(db, 1)
    sinks = specs(tmp_path)
    queue(db, [event_id], sink=sinks["archive"], now=T0)

    def broken_envelope(event_id_: int, sink_name: str, enqueued_at: str) -> dict[str, str]:
        return {"event_id": str(event_id_)}  # the other two columns are simply absent

    result = agent_push.drain(
        db,
        endpoint=sinks["archive"].ref,
        transport=writers_mod().FileSinkWriter(sinks["archive"]),
        now=T0,
        rng=Rng(1.0),
        sink_name="archive",
        row_meta=broken_envelope,
    )
    assert result.push_failed == 1
    assert len(agent_push.pending_rows(db, sink_name="archive")) == 1
    written = tmp_path / "archive-2026-10-19.csv"
    body = written.read_text(encoding="utf-8") if written.exists() else ""
    assert len([x for x in body.splitlines() if x]) <= 1, (
        f"only the header may exist, never a short row: {body!r}"
    )


def test_file_write_is_durable_before_the_queue_row_is_deleted(tmp_path: Path) -> None:
    """fsync-then-mark-acked. A crash AFTER the file write and BEFORE the queue delete must
    leave BOTH artifacts — the line durable in the file and the row still queued. Replaying
    re-appends (at-least-once; the ingest-side idempotency key stays the dedupe authority),
    and a punch is never lost. This is the queue's own crash-safety law, applied to a file.
    """
    db = real_db(tmp_path)
    (event_id,) = store_n(db, 1)
    sinks = specs(tmp_path)
    queue(db, [event_id], sink=sinks["feed"], now=T0)
    # `sqlite3.Connection.execute` is a read-only attribute, so the crash is staged the
    # physical way the law is stated: the durable write happened, the ack did not. The
    # writer returns 200 only after fsync; a kill at that instant leaves BOTH artifacts.
    payload = db.execute("SELECT jsonl FROM events WHERE id = ?", (event_id,)).fetchone()["jsonl"]
    writer = FileSinkWriter(sinks["feed"])
    assert writer(sinks["feed"].ref, payload) == 200  # fsynced
    # ... and no drain ran, so no DELETE: exactly the post-crash state.
    assert len((at_path(tmp_path, "feed.jsonl")).read_text(encoding="utf-8").splitlines()) == 1
    assert len(agent_push.pending_rows(db, sink_name="feed")) == 1, "the ack never happened"

    drain_sink(db, sinks["feed"], FileSinkWriter(sinks["feed"]), now=at(60))
    assert len((at_path(tmp_path, "feed.jsonl")).read_text(encoding="utf-8").splitlines()) == 2, (
        "at-least-once: the crash re-appends, the ingest-side idempotency key dedupes"
    )
    assert agent_push.pending_rows(db, sink_name="feed") == ()


def test_csv_sink_refusal_is_loud_and_keeps_the_row_queued(tmp_path: Path) -> None:
    """A sink whose path cannot be written (here: the declared path is a directory) is a
    LOUD failure — a warn line naming the sink and the exception class — and the row stays
    queued. Silent loss is the one outcome a file sink may not have."""
    db = real_db(tmp_path)
    (event_id,) = store_n(db, 1)
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    # rotation=None (constructible, not reachable from config, whose default is `daily`):
    # that is the form where the DECLARED path is the file itself, so a directory there is
    # the write failure. With `daily` there is no failure to test — the writer would create
    # `blocked-<date>.csv` inside the directory, which is a legal write.
    sink = SinkSpec(
        name="badpath", type="csv", ref=f"file://{blocked}", path=str(blocked), rotation=None
    )
    queue(db, [event_id], sink=sink)
    warns: list[str] = []
    agent, conn = fanout_agent(
        tmp_path,
        {"badpath": sink},
        transports={"badpath": FileSinkWriter(sink)},
        warn=warns.append,
    )
    agent.tick()

    text = "\n".join(warns)
    assert "badpath" in text, f"the warn must name the sink: {warns}"
    assert agent_push.pending_rows(conn, sink_name="badpath"), "the row stays queued"
    assert agent_push.dead_letter_depth(conn) == 0
    assert any("IsADirectoryError" in w or "OSError" in w for w in warns), (
        f"the warn must name the failure class: {warns}"
    )


def test_file_sink_rotates_daily_and_monthly_and_creates_missing_dirs(tmp_path: Path) -> None:
    """Rotation is the SINK's config: daily rolls by day, monthly by month, and a sink whose
    parent directories do not exist creates them (path created if missing)."""
    mod = writers_mod()
    nested_path = tmp_path / "a" / "b" / "deep.jsonl"
    nested = SinkSpec(
        name="nested",
        type="jsonl",
        ref=f"file://{nested_path}",
        path=str(nested_path),
        rotation="daily",
    )
    assert mod.FileSinkWriter(nested, now=lambda: T0)(nested.ref, '{"a": 1}\n') == 200
    assert (tmp_path / "a" / "b" / "deep-2026-10-19.jsonl").exists(), (
        f"daily rotation stamps the date into the name ({mod.ROTATED_STEM_LAW})"
    )

    monthly_path = tmp_path / "m" / "rows.csv"
    monthly = SinkSpec(
        name="monthly",
        type="csv",
        ref=f"file://{monthly_path}",
        path=str(monthly_path),
        rotation="monthly",
    )
    assert mod.FileSinkWriter(monthly, now=lambda: T0)(monthly.ref, '{"employee_no": "1"}\n') == 200
    assert (tmp_path / "m" / "rows-2026-10.csv").exists()

    assert mod.rotated_path(Path("/x/feed.jsonl"), "daily", T0).name == "feed-2026-10-19.jsonl"
    assert mod.rotated_path(Path("/x/feed.jsonl"), "monthly", T0).name == "feed-2026-10.jsonl"
    # The non-rotating case keeps the declared path verbatim (an operator who set no
    # rotation must find exactly the file they configured).
    assert mod.rotated_path(Path("/x/p.jsonl"), None, T0).name == "p.jsonl"


def test_csv_header_is_written_once_and_survives_reopen(tmp_path: Path) -> None:
    """The header is part of the file contract: written when a rotation file is created,
    never duplicated by a later append — including by a NEW process (a second writer object
    for the same sink must see the existing header)."""
    mod = writers_mod()
    path = tmp_path / "archive.csv"
    sink = SinkSpec(
        name="archive",
        type="csv",
        ref=f"file://{path}",
        path=str(path),
        rotation="daily",
    )
    assert mod.FileSinkWriter(sink, now=lambda: T0)(sink.ref, '{"employee_no": "1"}\n') == 200
    assert mod.FileSinkWriter(sink, now=lambda: T0)(sink.ref, '{"employee_no": "2"}\n') == 200
    text = (tmp_path / "archive-2026-10-19.csv").read_text(encoding="utf-8")
    assert text.count("event_id,sink_name") == 1, f"header duplicated:\n{text}"
    assert text.splitlines()[0] == ",".join(CSV_COLUMNS)
    assert mod.FileSinkWriter(sink, now=lambda: T0)(sink.ref, '{"employee_no": "3"}\n') == 200
    assert (tmp_path / "archive-2026-10-19.csv").read_text(encoding="utf-8").count(
        "event_id,sink_name"
    ) == 1


def test_csv_line_renders_the_record_dict_with_raw_last() -> None:
    """`csv_line_for` is the renderer both the drain and any ad-hoc exporter use: envelope,
    then the contract's own order, `raw` LAST as a quoted JSON field (a naive splitter that
    stops at the first unquoted comma still reads every named field)."""
    mod = writers_mod()
    line = to_jsonl([make_record(serial_no=7)])[:-1]
    out = mod.csv_line_for(
        payload=line,
        row_meta={"event_id": "42", "sink_name": "archive", "enqueued_at": iso(T0)},
    )
    row = next(csv.reader([out]))
    assert len(row) == len(CSV_COLUMNS), "the data row has exactly the header's width"
    assert row[0] == "42" and row[1] == "archive" and row[2] == iso(T0)
    # The record's own values, in the contract's order, between the envelope and `raw`.
    # The header tuple (CSV_COLUMNS = envelope + RECORD_JSON_KEYS) puts `captured_at` last
    # and `raw` second-to-last — `raw` is the last field that can contain a comma/quote,
    # which is what the "naive splitter" law needs. (The sinks.py prose says "raw LAST";
    # the TUPLE is the contract and it says second-to-last — prose drift flagged on the
    # card for the SINKS-CORE owners, the columns themselves are frozen by list(row).)
    record = make_record(serial_no=7).to_dict()

    def cell(value: Any) -> str:
        """The writer's own cell law, mirrored here: None -> '', bool -> true/false,
        a mapping/list -> compact JSON (that is `raw`'s column, and why it stays last)."""
        if value is None:
            return ""
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
        return str(value)

    assert row[3 : 3 + len(RECORD_JSON_KEYS) - 1] == [
        cell(record[key]) for key in RECORD_JSON_KEYS[:-1]
    ]
    # `raw` sits at its contract position (second-to-last), and the FINAL column is
    # `captured_at` — the tuple, not the prose, is the contract.
    assert row[3 + RECORD_JSON_KEYS.index("raw")] == json.dumps(
        record["raw"], separators=(",", ":")
    )
    assert row[-1] == cell(record["captured_at"])
    # The header is the only place the KEY NAMES appear, and it names the same order:
    header = next(csv.reader([",".join(CSV_COLUMNS) + "\n"]))
    assert header[3 : 3 + len(RECORD_JSON_KEYS)] == list(RECORD_JSON_KEYS)
    # `raw` carries commas and quotes and must survive as ONE field:
    tricky = to_jsonl([make_record(serial_no=8, name='Comma, "Quoted" E8')])[:-1]
    again = next(
        csv.reader(
            [
                mod.csv_line_for(
                    payload=tricky,
                    row_meta={"event_id": "1", "sink_name": "s", "enqueued_at": iso(T0)},
                )
            ]
        )
    )
    assert len(again) == len(CSV_COLUMNS)
    assert again[3 + RECORD_JSON_KEYS.index("name")] == 'Comma, "Quoted" E8'


def test_jsonl_line_is_the_payload_verbatim_and_one_line(tmp_path: Path) -> None:
    """The jsonl renderer may not reformat: `json_line_for` returns the stored bytes plus
    exactly one newline (the payload IS the wire line — the fingerprint depends on it)."""
    mod = writers_mod()
    payload = to_jsonl([make_record(serial_no=11)])[:-1]
    out = mod.json_line_for(payload=payload, row_meta=None)
    assert out == payload + "\n"
    assert len(out.splitlines()) == 1
    # A payload that already ends with a newline still gets exactly one:
    assert mod.json_line_for(payload=payload + "\n", row_meta=None) == payload + "\n"


def test_a_sink_ref_is_the_writers_own_and_a_moved_target_is_refused(tmp_path: Path) -> None:
    """The ref is identity, not a hint: a writer aimed at a different ref refuses (409)
    rather than writing one sink's payload into another sink's file."""
    mod = writers_mod()
    path = tmp_path / "feed.jsonl"
    sink = SinkSpec(
        name="feed", type="jsonl", ref=f"file://{path}", path=str(path), rotation="daily"
    )
    writer = mod.FileSinkWriter(sink)
    assert writer("file:///somewhere/else.jsonl", "{}\n") == 409
    assert writer(sink.ref, "{}\n") == 200


def test_an_unparseable_payload_fails_the_row_loudly_never_a_silent_skip(tmp_path: Path) -> None:
    """A csv row whose payload is not a record dict cannot be rendered into the stable
    columns: loud row failure (stays queued, error class on the row), never a silently
    skipped punch and never a half-written line."""
    db = real_db(tmp_path)
    (event_id,) = store_n(db, 1)
    sinks = specs(tmp_path)
    queue(db, [event_id], sink=sinks["archive"], now=T0)
    db.execute(
        "UPDATE push_queue SET payload = ? WHERE sink_name = 'archive'",
        ("this is not a json object",),
    )
    result = drain_sink(db, sinks["archive"], FileSinkWriter(sinks["archive"]))
    assert result.push_failed == 1
    assert len(agent_push.pending_rows(db, sink_name="archive")) == 1
    assert agent_push.pending_rows(db, sink_name="archive")[0].last_error_class
    written = tmp_path / "archive-2026-10-19.csv"
    body = written.read_text(encoding="utf-8") if written.exists() else ""
    assert "this is not a json object" not in body


def test_a_migration_minted_sink_name_still_drains_through_a_file_writer(tmp_path: Path) -> None:
    """`legacy+<n>` (migration-minted, impossible in config) must drain, not vanish: the
    writer reads the payload and the envelope carries the row's REAL sink name."""
    db = real_db(tmp_path)
    (event_id,) = store_n(db, 1)
    sinks = specs(tmp_path)
    queue(db, [event_id], sink=sinks["archive"], sink_name=MIGRATED_SHAPE)
    drain_sink(
        db,
        sinks["archive"],
        FileSinkWriter(sinks["archive"]),
        sink_name=MIGRATED_SHAPE,
        row_meta_fn=row_meta(),
    )
    assert agent_push.pending_rows(db, sink_name=MIGRATED_SHAPE) == ()
    assert agent_push.dead_letter_depth(db) == 0
    rows = csv_rows(tmp_path / "archive-2026-10-19.csv")
    assert rows[0]["sink_name"] == MIGRATED_SHAPE


# =============================================================================================
# (d) roster fan-out
# =============================================================================================


class RosterUsers:
    def __call__(self) -> list[UserRecord]:
        return [
            UserRecord(
                employee_no=str(n),
                name=f"User E{n}",
                raw={"cardNo": f"c{n}", "numOfFace": n, "password": "fake-never-sent"},
            )
            for n in (1, 2, 3)
        ]


def roster_loop(
    tmp_path: Path,
    *,
    sinks: dict[str, SinkSpec],
    transports: dict[str, Any] | None = None,
    warn: Any = None,
    now_box: dict[str, datetime] | None = None,
    conn: sqlite3.Connection | None = None,
    device_code: str | None = "D-IF-1",
) -> Any:
    mod = writers_mod()
    return DeviceLoop(
        client=SilentClient(),
        conn=conn or _null_conn(),
        site=SITE,
        site_tz="Europe/Bucharest",
        cadence_s=300,
        overlap_s=300,
        now=lambda: (now_box or {"value": T0})["value"],
        monotonic=lambda: 0.0,
        sleep=lambda _s: None,
        warn=warn if warn is not None else (lambda _s: None),
        push_target=HTTPS_TARGET,
        push_transport=None,
        sinks=tuple(sinks.values()),
        device_code=device_code,
        roster=RosterUsers(),
        sink_transports=dict(transports or {}),
        sink_writers={
            name: mod.FileSinkWriter(sink, now=lambda: (now_box or {"value": T0})["value"])
            for name, sink in sinks.items()
            if sink.type in ("csv", "jsonl")
        },
    )


def _null_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    return conn


def test_roster_fans_out_to_every_sink_that_accepts_it(tmp_path: Path) -> None:
    """DoD (d): one hourly roster reaches https AND both file sinks; the file sinks store
    the roster line as documented rows (jsonl verbatim, csv as the roster table)."""
    sinks = specs(tmp_path)
    client, capture = client_for(200)
    https = agent_push.https_transport(SITE, token=TOKEN, client=client)
    warns: list[str] = []
    loop = roster_loop(tmp_path, sinks=sinks, transports={"bc": https}, warn=warns.append)

    result = loop.push_device_users()

    assert result is not None and result.users == 3
    by_sink = {p.sink_name: p for p in result.per_sink}
    assert set(by_sink) == {"bc", "archive", "feed"}
    assert {n: p.status for n, p in by_sink.items()} == {"bc": 200, "archive": 200, "feed": 200}
    assert result.ok is True
    assert capture.headers["authorization"] == f"Bearer {TOKEN}", "T15 leg verbatim"
    assert json.loads(capture.body.decode("utf-8"))["kind"] == "device_users"
    feed = (tmp_path / "feed-2026-10-19.jsonl").read_text(encoding="utf-8")
    parsed = json.loads(feed.splitlines()[-1])
    assert parsed["kind"] == "device_users" and parsed["deviceCode"] == "D-IF-1"
    assert [u["employee_no"] for u in parsed["users"]] == ["1", "2", "3"]
    rows = csv_rows(tmp_path / "archive-2026-10-19.roster.csv")
    assert list(rows[0]) == list(writers_mod().ROSTER_CSV_COLUMNS)
    assert rows[0]["sink_name"] == "archive"
    assert rows[0]["deviceCode"] == "D-IF-1"
    assert json.loads(rows[0]["users"])[0]["employee_no"] == "1"


def test_a_failing_https_roster_leg_never_stops_the_file_sinks(tmp_path: Path) -> None:
    """The warn-and-retry-next-hour law holds PER SINK: the ingest 502s, both file sinks
    still get the roster, and the warn line names the sink that failed and its status."""
    sinks = specs(tmp_path)
    client, _capture = client_for(502)
    https = agent_push.https_transport(SITE, token=TOKEN, client=client)
    warns: list[str] = []
    loop = roster_loop(tmp_path, sinks=sinks, transports={"bc": https}, warn=warns.append)

    result = loop.push_device_users()

    assert result is not None
    assert {p.sink_name: p.status for p in result.per_sink} == {
        "bc": 502,
        "archive": 200,
        "feed": 200,
    }
    assert result.ok is False, "a roster leg that failed anywhere reports not-ok"
    assert any("bc" in w and "502" in w for w in warns), f"per-sink warn missing: {warns}"
    assert (tmp_path / "feed-2026-10-19.jsonl").exists()
    assert (tmp_path / "archive-2026-10-19.roster.csv").exists()


def test_roster_never_dead_letters_even_against_a_real_db(tmp_path: Path) -> None:
    """Every sink fails (transport raises); the queue tables must stay EMPTY — a roster is
    re-derivable from the device, so only punches dead-letter (T15's law, now per sink)."""
    sinks = specs(tmp_path)
    db = real_db(tmp_path)

    def boom(url: str, body: str) -> int:
        raise ConnectionError("everything is down")

    loop = roster_loop(tmp_path, sinks=sinks, transports=dict.fromkeys(sinks, boom), conn=db)
    first = loop.push_device_users()
    second = loop.push_device_users()

    assert first is not None and first.ok is False
    assert second is not None and second.ok is False
    assert agent_push.queue_depth(db) == 0
    assert agent_push.dead_letter_depth(db) == 0
    # The https leg is the only one whose seam `transports` reaches; the file sinks deliver
    # through their writers, so the law asserted HERE is that a failing leg leaves no queue
    # or dead-letter row at all (the tables above) and the failed leg says why.
    bc = [p for p in second.per_sink if p.sink_name == "bc"]
    assert bc and bc[0].error is not None and bc[0].ok is False


def test_roster_is_hourly_across_the_whole_fanout(tmp_path: Path) -> None:
    """ONE hour-clock gates the fan-out: a second call inside the hour is a no-op for EVERY
    sink (the nonce-budget law stays per loop, not per sink)."""
    sinks = specs(tmp_path)
    calls = {"bc": 0}

    def counting(url: str, body: str) -> int:
        calls["bc"] += 1
        return 200

    box = {"value": T0}
    loop = roster_loop(tmp_path, sinks=sinks, transports={"bc": counting}, now_box=box)

    assert loop.push_device_users_if_due() is not None
    box["value"] = T0 + timedelta(seconds=1800)
    assert loop.push_device_users_if_due() is None, "not due yet, for any sink"
    box["value"] = T0 + timedelta(seconds=3601)
    assert loop.push_device_users_if_due() is not None
    assert calls["bc"] == 2


def test_a_sink_may_decline_the_roster(tmp_path: Path) -> None:
    """`accepts_roster=False` on a sink: the punches still flow, the roster does not — what
    a sink accepts is the sink's config, decided at parse/construct time."""
    sinks = specs(tmp_path)
    sinks["feed"] = SinkSpec(
        name="feed",
        type="jsonl",
        ref=sinks["feed"].ref,
        path=sinks["feed"].path,
        rotation="daily",
        accepts_roster=False,
    )
    warns: list[str] = []
    loop = roster_loop(
        tmp_path,
        sinks=sinks,
        transports={"bc": lambda url, body: 200},
        warn=warns.append,
    )
    result = loop.push_device_users()
    assert result is not None
    assert {p.sink_name for p in result.per_sink} == {"bc", "archive"}
    assert not (tmp_path / "feed-2026-10-19.jsonl").exists()


def test_roster_wire_shape_is_unchanged_by_the_fanout(tmp_path: Path) -> None:
    """The wire half is FROZEN: fan-out changed WHO receives the roster, not what a roster
    line is — the four-key projection, and the device `password` hash never appears."""
    sinks = specs(tmp_path)
    loop = roster_loop(tmp_path, sinks=sinks, transports={"bc": lambda url, body: 200})
    loop.push_device_users()
    feed = json.loads(
        (tmp_path / "feed-2026-10-19.jsonl").read_text(encoding="utf-8").splitlines()[-1]
    )
    assert sorted(feed["users"][0]) == ["cardNo", "employee_no", "hasFace", "name"]
    assert "password" not in json.dumps(feed)
    rows = csv_rows(tmp_path / "archive-2026-10-19.roster.csv")
    assert "password" not in json.dumps(rows)


def test_roster_csv_companion_columns_are_documented_and_pinned() -> None:
    """The roster csv companion file has its own documented column set (same law as
    CSV_COLUMNS: a downstream reader codes against it): envelope, then the roster line's
    own keys, `users` LAST as JSON text."""
    mod = writers_mod()
    assert mod.ROSTER_CSV_COLUMNS == (
        "sink_name",
        "enqueued_at",
        "kind",
        "deviceCode",
        "users",
    )
    assert mod.ROSTER_CSV_COLUMNS[-1] == "users"
    names = {f.name for f in fields(UserRecord)}
    assert "password" not in names, "UserRecord's own privacy law"


def test_is_roster_payload_uses_the_ingests_own_classifier_rule() -> None:
    """Recognising a roster line is the ingest's OWN rule (`kind == "device_users"`), never
    a heuristic that could swallow a punch line (that would write payroll into the roster
    table and drop it from the archive)."""
    mod = writers_mod()
    assert mod.is_roster_payload('{"kind":"device_users","deviceCode":"D","users":[]}\n')
    assert not mod.is_roster_payload(to_jsonl([make_record(serial_no=9)])[:-1])
    assert not mod.is_roster_payload('{"kind": 5}\n')
    assert not mod.is_roster_payload("not json\n")
    assert not mod.is_roster_payload('[{"kind": "device_users"}]')


def test_the_implicit_sink_site_rovers_via_the_same_hourly_leg(tmp_path: Path) -> None:
    """Upgrade-inert for the roster: a push_target-only site (declares no sinks) rovers
    exactly one target — the `legacy` sink — through the site's transport, as T15 shipped
    it. The fan-out list is empty; the legacy path is what answers."""
    loop = DeviceLoop(
        client=SilentClient(),
        conn=_null_conn(),
        site=SITE,
        site_tz="Europe/Bucharest",
        cadence_s=300,
        overlap_s=300,
        now=lambda: T0,
        monotonic=lambda: 0.0,
        sleep=lambda _s: None,
        warn=lambda _s: None,
        push_target=HTTPS_TARGET,
        push_transport=lambda url, body: 200,
        device_code="D-IF-1",
        roster=RosterUsers(),
    )
    result = loop.push_device_users()
    assert result is not None and result.ok is True and result.status == 200
    assert [p.sink_name for p in result.per_sink] == [IMPLICIT_SINK_NAME]
    assert loop.sinks == ()


# =============================================================================================
# (c) upgrade-inert: the implicit push_target sink behaves exactly like today
# =============================================================================================


def test_push_target_only_site_is_byte_identical_to_today(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DoD (c): a `push_target`-only site upgrades with ZERO config change and zero
    behaviour change — same stub ingest file, the implicit `legacy` sink as its only sink,
    empty queue at the end of the pass."""
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    # `now=T0`: the harness's own default clock is the SCHEDULER's T0 (10:00 local Bucharest =
    # 07:00 UTC), three hours before this file's T0, and a punch stamped at T0 would then be
    # in the future of the run and never stored.
    h = AgentHarness(tmp_path, device, monkeypatch, now=T0)  # push_target = stub:// (auto)
    code, out = h.cli(["run", "--site", SITE, "--state-root", str(h.state_root), "--once"])
    assert code == 0, out
    assert h.ingest_file is not None and h.ingest_file.exists()
    assert len(h.ingest_file.read_text(encoding="utf-8").splitlines()) == len(h.stored_serials())

    conn = h.conn()
    # A clean pass EMPTIES both tables (the drain deletes the row it acked), so "legacy was
    # the only sink" is read from what records the sends — the ledger — not from backlog
    # tables that success drains.
    assert agent_push.queue_depth(conn) == 0
    assert agent_push.dead_letter_depth(conn) == 0
    conn.close()
    ledger = h.state_root / "push-ledger.jsonl"
    assert ledger.exists(), "the ledger is the record of what left the building"
    lines = [json.loads(x) for x in ledger.read_text(encoding="utf-8").splitlines() if x]
    assert len(lines) == len(h.stored_serials())
    assert {rec["s"] for rec in lines} == {IMPLICIT_SINK_NAME}, (
        "the implicit sink is the ONLY sink a push_target-only site delivers through"
    )
    assert {rec["t"] for rec in lines} == {h.push_target}


def test_the_push_target_report_shape_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The report's existing keys keep their meaning for a legacy site (`pushed` = the
    count it always reported), so `agent run --output json | jq .pushed` still answers."""
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    h = AgentHarness(tmp_path, device, monkeypatch, now=T0)  # see the clock note above
    code, out = h.cli(
        ["run", "--site", SITE, "--state-root", str(h.state_root), "--once", "--output", "json"]
    )
    assert code == 0, out
    payload = json.loads(out[out.index("{") :])
    # `queued` is a per-pass key (tick_reports), never a run-level one — this is the exact
    # key set the report had before sinks existed, asserted as a set so a renamed key fails.
    for key in ("pushed", "push_failed", "dead_lettered", "push_target"):
        assert key in payload, f"{key} vanished from the report: {sorted(payload)}"
    assert "queued" in payload["tick_reports"][0], "the per-pass queued count is unchanged"
    assert payload["pushed"] == len(h.stored_serials())
    assert payload["push_failed"] == 0 and payload["dead_lettered"] == 0


def test_the_ledger_stays_upgrade_inert_across_the_sink_keying(tmp_path: Path) -> None:
    """The ledger is the poller's "already left the building" record, and its file predates
    sinks: a line written BEFORE the upgrade carries only `t` (the endpoint) and must keep
    excluding exactly the events it excluded before (a re-push storm on upgrade day is the
    failure this pins). A new append carries `t` AND `s` (the sink)."""
    ledger_path = tmp_path / "push-ledger.jsonl"
    ledger_path.write_text(
        json.dumps({"e": 1, "t": HTTPS_TARGET, "k": "sent"}) + "\n", encoding="utf-8"
    )
    ledger = agent_cli.PushLedger(ledger_path)
    assert 1 in ledger.known(IMPLICIT_SINK_NAME, endpoint=HTTPS_TARGET)

    db = real_db(tmp_path)
    ids = store_n(db, 3)
    queued = agent_cli.queue_new_events(
        db, endpoint=HTTPS_TARGET, sink_name=IMPLICIT_SINK_NAME, now=T0, ledger=ledger
    )
    assert queued, "the unsent rows still queue"
    assert ids[0] not in {
        r.event_id for r in agent_push.pending_rows(db, sink_name=IMPLICIT_SINK_NAME)
    }, "the ledger-known event stays excluded across the upgrade"

    ledger.append([ids[1]], endpoint=HTTPS_TARGET, sink_name=IMPLICIT_SINK_NAME)
    lines = [json.loads(x) for x in ledger_path.read_text().splitlines() if x.strip()]
    newest = lines[-1]
    assert newest["t"] == HTTPS_TARGET and newest["s"] == IMPLICIT_SINK_NAME
    fresh = agent_cli.PushLedger(ledger_path)
    assert fresh.known(IMPLICIT_SINK_NAME, endpoint=HTTPS_TARGET) >= {ids[0], ids[1]}
    # A legacy reader's view is untouched: every line still carries `e`/`t`/`k`.
    assert all({"e", "t", "k"} <= set(line) for line in lines)
    del queued


def test_queue_new_events_defaults_to_the_implicit_sink_and_needs_no_sink_name(
    tmp_path: Path,
) -> None:
    """The legacy call shape (no `sink_name=`) still works and lands on `legacy` — the
    upgrade-inert signature law: existing callers keep compiling and keep behaving."""
    db = real_db(tmp_path)
    ids = store_n(db, 2)
    queued = agent_cli.queue_new_events(db, endpoint=HTTPS_TARGET, now=T0)
    assert len(queued) == 2
    assert {r.event_id for r in agent_push.pending_rows(db)} == set(ids)
    assert {r.sink_name for r in agent_push.pending_rows(db)} == {IMPLICIT_SINK_NAME}


def test_site_with_zero_sinks_keeps_the_pusher_off_and_says_so_loudly(tmp_path: Path) -> None:
    """Config law: a site with neither `push_target` nor `[[site.sink]]` = pusher OFF
    (spec §3's absence law, unchanged) but LOUD at startup, mirroring the push_target-absent
    rule: the operator learns from the log line, not from a payroll gap months later."""
    site = SiteConfig(name=SITE, host=HOST, iana_tz="Europe/Bucharest")
    db = real_db(tmp_path)
    store_n(db, 1)
    warns: list[str] = []
    policy = agent_cli.AlertPolicy(
        site=SITE,
        cadence_s=site.cadence_s,
        now=lambda: T0,
        conn=db,
        park_dir=tmp_path / "park",
        sink=lambda _a: None,
    )
    loop = DeviceLoop(
        client=SilentClient(),
        conn=db,
        site=SITE,
        site_tz="Europe/Bucharest",
        cadence_s=site.cadence_s,
        overlap_s=site.overlap_s,
        now=lambda: T0,
        monotonic=lambda: 0.0,
        sleep=lambda _s: None,
        warn=lambda _s: None,
        roster=lambda: [],
    )
    agent = agent_cli.SiteAgent(
        site=site,
        loops=[loop],
        policy=policy,
        conn=db,
        db_path=str(tmp_path / "gateclerk-site-a.sqlite3"),
        warn=warns.append,
    )
    report = agent.tick()

    assert site.effective_sinks == ()
    assert report.pushed == 0 and report.queued == 0 and report.push_failed == 0
    assert agent_push.queue_depth(db) == 0, "no sinks -> nothing is queued"
    joined = "\n".join(warns)
    assert "sink" in joined.lower() and SITE in joined, f"startup warn missing: {warns}"


def test_build_site_agent_warns_at_startup_when_a_site_has_no_sinks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The startup half of the zero-sinks law through the real composition (mirrors the
    Task-15 missing-token line: loud at startup, not at dead-letter time)."""
    device = seeded_device()
    h = AgentHarness(tmp_path, device, monkeypatch, push_target=None)
    warns: list[str] = []
    agent = h.api_agent(warn=warns.append)
    assert agent.sinks == ()
    joined = "\n".join(warns)
    assert "sink" in joined.lower(), f"no startup warn for a pusher-off site: {warns}"


def test_a_named_sink_site_never_warns_about_missing_sinks(tmp_path: Path) -> None:
    """The startup law is about ABSENCE, not about https: a site that declared sinks must
    not nag every pass (an operator who configured csv+jsonl has no install step to fix)."""
    sinks = specs(tmp_path)
    warns: list[str] = []
    agent, db = fanout_agent(
        tmp_path,
        sinks,
        transports={"bc": lambda url, body: 200},
        warn=warns.append,
    )
    store_n(db, 1)
    agent.tick()
    joined = "\n".join(warns)
    assert "no sinks" not in joined, f"a configured site must not nag: {warns}"
    db.close()


# =============================================================================================
# the fan-out itself: independence, accounting, and the failure it must never become
# =============================================================================================


def test_fanout_counts_land_in_the_report_per_sink(tmp_path: Path) -> None:
    """`agent run`'s report stays honest with N sinks: the scalars are the sum and `sinks`
    carries the per-sink truth — one blended number would hide "the ingest leg failed while
    the archive succeeded", which is the outage an operator has to see."""
    sinks = specs(tmp_path)
    agent, db = fanout_agent(
        tmp_path,
        sinks,
        transports={"bc": lambda url, body: 502},
    )
    store_n(db, 2)
    report = agent.tick()
    data = report.as_dict()
    assert data["sinks"], f"per-sink counters missing from {data}"
    assert set(data["sinks"]) == {"bc", "archive", "feed"}
    assert data["sinks"]["archive"]["pushed"] == 2
    assert data["sinks"]["feed"]["pushed"] == 2
    assert data["sinks"]["bc"]["push_failed"] == 2
    assert data["pushed"] == 4 and data["push_failed"] == 2
    for per_sink in data["sinks"].values():
        assert not any(
            bad in key for key in per_sink for bad in ("payload", "password", "host", "jsonl")
        )
    db.close()


def test_one_sinks_broken_wiring_never_stops_the_other_sinks(tmp_path: Path) -> None:
    """The fan-out's own isolation: even an exception escaping one sink's step (a transport
    blowing up outside the contract, a writer mis-wired) is absorbed as a loud per-sink
    warn — the remaining sinks still receive their drain in the SAME pass."""

    class Detonates:
        """A wired object that is not a valid transport.

        A transport whose CALL raises is caught per row by `drain` — that is drain's own
        contract (one bad row must not break the pass), so it never reaches the fan-out's
        isolation. What the isolation exists for is a sink step that blows up OUTSIDE the
        transport call: the agent probes `token_available` on its own, and that is the seam
        a mis-wired object detonates on.
        """

        def token_available(self) -> bool:
            raise RuntimeError("sink wiring exploded")

        def __call__(self, url: str, body: str) -> int:
            return 200

    sinks = specs(tmp_path)
    warns: list[str] = []
    agent, db = fanout_agent(
        tmp_path,
        sinks,
        transports={"bc": Detonates()},
        warn=warns.append,
    )
    store_n(db, 2)
    report = agent.tick()

    assert report.pushed == 4, "the healthy sinks were not starved by the exploded one"
    assert any("bc" in w for w in warns), f"no per-sink warn: {warns}"
    db.close()


def test_the_https_leg_of_the_fanout_uses_the_injected_transport(tmp_path: Path) -> None:
    """The fan-out sends the https sink's rows through the injected T15 transport with the
    byte-verbatim payload (the wire contract is untouched by the sink layer)."""
    sinks = specs(tmp_path)
    client, capture = client_for(200, 200)
    https = agent_push.https_transport(SITE, token=TOKEN, client=client)
    agent, db = fanout_agent(tmp_path, sinks, transports={"bc": https})
    ids = store_n(db, 2)
    agent.tick()

    assert len(capture.requests) == 2
    assert capture.headers["authorization"] == f"Bearer {TOKEN}"
    assert capture.headers["content-type"] == "application/jsonl"
    assert capture.headers["x-gateclerk-site"] == SITE.upper()
    for request, event_id in zip(capture.requests, ids, strict=True):
        stored = db.execute("SELECT jsonl FROM events WHERE id = ?", (event_id,)).fetchone()[
            "jsonl"
        ]
        assert request.content.decode("utf-8") == stored + "\n"
    db.close()


def test_https_sink_token_is_read_from_the_sinks_ref_only(tmp_path: Path) -> None:
    """The bearer comes from the SINK's token REF (never a value in config): `token_env`
    names an env var, `token_keychain` names a keychain SERVICE, and absence falls through
    to the site's T15 rungs — which is why the implicit sink needs no new keychain item."""
    mod = writers_mod()
    env = {
        "CUSTOM_INGEST_TOKEN": "fake-sink-token",
        "GATECLERK_INGEST_TOKEN_SITE-A": "fake-site-token",
    }
    sink = SinkSpec(name="bc", type="https", ref=HTTPS_TARGET, token_env="CUSTOM_INGEST_TOKEN")
    transport = mod.build_https_sink_transport(SITE, sink, env=env, keychain=NoKeychain())
    client, capture = client_for(200)
    transport._client = client
    assert transport(HTTPS_TARGET, "{}\n") == 200
    assert capture.headers["authorization"] == "Bearer fake-sink-token"

    implicit = SinkSpec(name=IMPLICIT_SINK_NAME, type="https", ref=HTTPS_TARGET)
    transport2 = mod.build_https_sink_transport(SITE, implicit, env=env, keychain=NoKeychain())
    client2, capture2 = client_for(200)
    transport2._client = client2
    transport2(HTTPS_TARGET, "{}\n")
    assert capture2.headers["authorization"] == "Bearer fake-site-token"
    assert ingest_token_env_var(SITE) == "GATECLERK_INGEST_TOKEN_SITE-A"

    keychain = RecordingKeychain({"sink-vault": "fake-keychain-token"})
    vault = SinkSpec(name="bc2", type="https", ref=HTTPS_TARGET, token_keychain="sink-vault")
    transport3 = mod.build_https_sink_transport(SITE, vault, env={}, keychain=keychain)
    client3, capture3 = client_for(200)
    transport3._client = client3
    transport3(HTTPS_TARGET, "{}\n")
    assert capture3.headers["authorization"] == "Bearer fake-keychain-token"
    assert keychain.services == ["sink-vault"], "the sink's own service, not the site default"
    assert ingest_keychain_service(SITE) == "gateclerk-ingest-site-a"


def test_https_sink_custom_headers_ride_the_request_without_the_two_reserved_ones(
    tmp_path: Path,
) -> None:
    """A sink's `headers` reach the wire; the transport's own two (Authorization,
    X-Gateclerk-Site) stay the transport's (config cannot set them — SINKS-CORE's refusal)."""
    mod = writers_mod()
    sink = SinkSpec(
        name="bc",
        type="https",
        ref=HTTPS_TARGET,
        token_env="TOK",
        headers={"X-Tenant": "acme"},
    )
    # The mock client goes in through the FACTORY: the wrapper hands the request to the
    # transport it wraps, so swapping a client on the wrapper would be swapping nothing.
    client, capture = client_for(200)
    transport = mod.build_https_sink_transport(
        SITE, sink, env={"TOK": "fake-sink-token"}, keychain=NoKeychain(), client=client
    )
    transport(HTTPS_TARGET, "{}\n")
    assert capture.headers["x-tenant"] == "acme"
    assert capture.headers["authorization"] == "Bearer fake-sink-token"
    assert capture.headers["x-gateclerk-site"] == SITE.upper()


def test_the_file_sinks_are_wired_from_the_sink_config_alone(tmp_path: Path) -> None:
    """The composition derives a file sink's writer from the sink spec: an agent built from
    config with NO injected transport writes both files (a csv sink that silently never
    wrote would be payroll loss discovered in an audit)."""
    sinks = specs(tmp_path)
    site = SiteConfig(
        name=SITE,
        host=HOST,
        iana_tz="Europe/Bucharest",
        sinks=tuple(sinks.values()),
    )
    agent = agent_cli.SiteAgent(
        site=site,
        loops=[
            DeviceLoop(
                client=SilentClient(),
                conn=real_db(tmp_path / "x"),
                site=SITE,
                site_tz="Europe/Bucharest",
                cadence_s=300,
                overlap_s=300,
                now=lambda: T0,
                monotonic=lambda: 0.0,
                sleep=lambda _s: None,
                warn=lambda _s: None,
                roster=lambda: [],
            )
        ],
        policy=agent_cli.AlertPolicy(
            site=SITE,
            cadence_s=300,
            now=lambda: T0,
            conn=_null_conn(),
            park_dir=tmp_path / "park2",
            sink=lambda _a: None,
        ),
        conn=_null_conn(),
        db_path="unused",
        now=lambda: T0,  # the sink's rotation file name comes from the agent's own clock
    )
    writers = {name: agent._sink_transport(sinks[name]) for name in ("archive", "feed")}
    assert {type(w).__name__ for w in writers.values()} == {"FileSinkWriter"}
    assert writers["archive"](sinks["archive"].ref, '{"employee_no": "9"}\n') == 200
    assert (tmp_path / "archive-2026-10-19.csv").exists()
