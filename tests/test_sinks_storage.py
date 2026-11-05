"""SINKS-CORE: per-sink delivery state — the v5/v6 migration + the queue's new identity.

BINDING SPEC: the operator's named-sinks goal + this card's storage law: `push_queue`
and `dead_letter` were keyed `UNIQUE(event_id, endpoint)` (one target per site was all
the config could express); they move to per-sink identity `UNIQUE(event_id, sink_name)`
through a VERSIONED sqlite migration, keeping the three laws P2-04 shipped with:

  * keep-everything — a migration may not lose a row, a payload byte or a retry stamp;
  * the dead-letter stays a table in the SAME db and is deleted only by
    `delete_dead_letter`;
  * the queue is still a send buffer pointed at `events` (`ON DELETE RESTRICT`).

THE MIGRATION TEST runs against a COPY of a real-shaped db: the fixture is built by the
real migration code up to v4 (the exact schema a deployed site has on disk today) and
filled through the real store + real `enqueue_events` with realistic rows. It is always a
tmp-dir file — never the live db, never anything under `~/gateclerk/` (there is a guard
test for that sentence, because a migration test that found a real store would destroy
the site's backlog).

Pre-upgrade backlog must survive ADDRESSED TO THE IMPLICIT SINK (`legacy`), which is what
makes the backward-compat law real: after the upgrade, site-a's queued punches are still
queued, still counted, and now aimed at the sink its unchanged `push_target` implies.

Offline by construction (no socket, no keychain); masked fixture values only per
tests/test_repo_hygiene.py.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import gateclerk.agent_db as agent_db
import gateclerk.agent_push as agent_push
from gateclerk.model import RECORD_JSON_KEYS, EventRecord, event_keys, from_jsonl, to_jsonl
from gateclerk.sinks import IMPLICIT_SINK_NAME

SITE = "site-a"
SERIAL = "MASKED-SER-1"
LEGACY_TARGET = "https://ingest.example.invalid/gateclerk_ingest"
OLD_TARGET = "stub://ingest/site-a.jsonl"

T0 = datetime(2026, 10, 19, 10, 0, 0, tzinfo=UTC)
BOUND = 86400


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="seconds")


def parsed(line: str) -> EventRecord:
    """A stored payload line back to a record (model.from_jsonl returns a LIST)."""
    return from_jsonl(f"{line}\n")[0]


def make_record(serial_no: int, employee_no: str = "1") -> EventRecord:
    """One site-a-shaped record (masked: `User E<n>`, TEST-NET-era serial).

    Shaped like tests/test_p2_04_pusher.py's fixture (same enum spellings, same masked
    style) so the migration test's "realistic rows" are realistic in the same way the
    pusher suite's are — `raw` included, because it is a stored column the CSV contract
    has to carry.
    """
    payload: dict[str, Any] = {
        "site": SITE,
        "device_serial": SERIAL,
        "serial_no": serial_no,
        "employee_no": employee_no,
        "name": f"User E{employee_no}",
        "event_time_utc": "2026-10-12T12:11:16+00:00",
        "event_time_local": "2026-10-12T14:11:16+02:00",
        "tz_offset_min": 180,
        "tz_offset_min_device": 120,
        "tz_source": "site-tz",
        "iana_tz": "Europe/Bucharest",
        "tz_offset_mismatch": True,
        "direction": "in",
        "attendance_status": "checkIn",
        "direction_source": "device",
        "verify_mode": "cardOrFaceOrFp",
        "major": 5,
        "minor": 75,
        "outcome": "granted",
        "raw": {"major": 5, "minor": 75, "serialNo": serial_no},
        "captured_at": "2026-10-19T10:00:00+00:00",
    }
    return EventRecord.from_dict(payload)


# --- the fixture: a real v4 db, built by the real code, in a tmp dir -------------------------


def assert_not_a_live_store(path: Path) -> None:
    """The card's hard limit, one line away from the code that could break it.

    `~/gateclerk/` is where the deployed store lives; a migration test pointed at it would
    upgrade (and, on a bug, lose) a real site's un-pushed backlog. Cheap belt-and-braces
    because the fixture path is also asserted below to sit under `tmp_path`.
    """
    resolved = Path(path).resolve()
    home = Path.home()
    assert resolved != (home / "gateclerk").resolve(), f"refusing to touch {resolved}"
    assert home / "gateclerk" not in resolved.parents, f"refusing to touch {resolved}"


def build_pre_upgrade_db(path: Path, *, monkeypatch: pytest.MonkeyPatch) -> sqlite3.Connection:
    """A v4 db built exactly the way today's agent built it (real migrations, real pragmas).

    `MIGRATIONS[:4]` is the pre-upgrade history — v1 bookkeeping, v2 events+checkpoint,
    v3 push_queue, v4 dead_letter. The pin below is what stops this fixture from quietly
    becoming the NEW schema (which would make the migration test vacuous, the worst kind
    of green).
    """
    assert [m.version for m in agent_db.MIGRATIONS[:4]] == [1, 2, 3, 4], (
        "the fixture is 'the schema a deployed site has today'; if the history below "
        "changed shape, this test must be re-thought, not re-tuned"
    )
    assert_not_a_live_store(path)
    monkeypatch.setattr(agent_db, "MIGRATIONS", tuple(agent_db.MIGRATIONS[:4]))
    conn = agent_db.connect(path)
    monkeypatch.undo()  # restore BEFORE any reopen: the upgrade must use the real list
    return conn


def _store(conn: sqlite3.Connection, serial_nos: tuple[int, ...]) -> list[int]:
    """Store realistic events AT THE v4 SCHEMA; return the event rowids.

    The payload bytes these put in `events.jsonl` are `to_jsonl()` verbatim, which is
    what makes "the migration kept the punch" a real assertion rather than a string
    comparison. The writer is hand-rolled on purpose: this db is the pre-upgrade file,
    and the CURRENT `agent_store.store_events` writes the v7 `serial_epoch` column that
    a deployed v4 file does not have yet (card t_fbd85a10). Using it here made the
    fixture a partially-upgraded db and the migration test vacuous.
    """
    records = [make_record(n, employee_no=str(n)) for n in serial_nos]
    stamp = iso(T0)
    columns = (
        "id",
        "revision",
        "jsonl",
        "stored_at",
        "updated_at",
        "key_algorithm",
        "idempotency_hash",
        "idempotency_json",
        "fingerprint_hash",
        "fingerprint_json",
        *RECORD_JSON_KEYS,
    )
    rowids: list[int] = []
    conn.execute("BEGIN IMMEDIATE")
    try:
        for record in records:
            keys = event_keys(record)
            payload = record.to_dict()
            values: list[Any] = [
                None,
                1,
                to_jsonl([record])[:-1],
                stamp,
                stamp,
                keys["algorithm"],
                keys["idempotency_hash"],
                keys["idempotency_json"],
                keys["fingerprint_hash"],
                keys["fingerprint_json"],
            ]
            for column in RECORD_JSON_KEYS:
                value = payload[column]
                if column == "raw":
                    value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
                values.append(value)
            placeholders = ", ".join("?" for _ in values)
            conn.execute(
                f"INSERT INTO events ({', '.join(columns)}) VALUES ({placeholders})",  # noqa: S608
                values,
            )
            rowids.append(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")
    return rowids


def seed_backlog(conn: sqlite3.Connection, *, serial_nos: tuple[int, ...]) -> list[int]:
    """Queue rows AT THE v4 SCHEMA (the pre-upgrade fixture's own writer).

    Deliberately NOT `agent_push.enqueue_events`: this db is the pre-upgrade file, so the
    rows have to be written the way the shipped v4 code wrote them (no `sink_name` column
    exists yet). A fixture that queued through the new code would either fail — which is
    what this test caught on the first run — or, worse, quietly become a v5 fixture.
    """
    rowids = _store(conn, serial_nos)
    stamp = iso(T0)
    conn.execute("BEGIN IMMEDIATE")
    try:
        for event_id in rowids:
            conn.execute(
                """
                INSERT INTO push_queue (
                    id, event_id, payload, endpoint, attempts,
                    first_failed_at, last_attempt_at, last_error_class,
                    next_attempt_at, enqueued_at
                )
                SELECT NULL, events.id, events.jsonl, ?, 0,
                       NULL, NULL, NULL, ?, ?
                  FROM events WHERE events.id = ?
                """,
                (LEGACY_TARGET, stamp, stamp, event_id),
            )
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")
    return rowids


def seed_queued(conn: sqlite3.Connection, *, serial_nos: tuple[int, ...]) -> list[int]:
    """Queue rows through the CURRENT code (for tests that start from an upgraded db).

    Same events as `seed_backlog`, written by `enqueue_events` — so a test that needs rows
    on the v6 schema exercises the real writer, not a hand-rolled INSERT.
    """
    rowids = _store(conn, serial_nos)
    agent_push.enqueue_events(conn, rowids, endpoint=LEGACY_TARGET, now=T0)
    return rowids


@pytest.fixture
def upgraded(tmp_path, monkeypatch) -> tuple[sqlite3.Connection, Path]:
    """A v4 db with a realistic backlog, then reopened through the real upgrade."""
    path = tmp_path / "agent.sqlite3"
    conn = build_pre_upgrade_db(path, monkeypatch=monkeypatch)
    try:
        seed_backlog(conn, serial_nos=(5742, 5743, 5744))
        # A row that already failed: attempts + the outage clock are the state that must
        # survive, not decoration.
        conn.execute(
            "UPDATE push_queue SET attempts = 3, first_failed_at = ?, last_attempt_at = ?,"
            " last_error_class = 'HttpStatus503', next_attempt_at = ? WHERE event_id ="
            " (SELECT MIN(event_id) FROM push_queue)",
            (iso(T0), iso(T0), iso(at(60))),
        )
        # A dead-letter row from the outage last month: full payload, its own stamps.
        payload = conn.execute(
            "SELECT event_id, payload FROM push_queue ORDER BY event_id LIMIT 1"
        ).fetchone()
        conn.execute(
            "INSERT INTO dead_letter (id, event_id, payload, endpoint, error_class, attempts,"
            " first_attempt_at, last_attempt_at) VALUES (NULL, ?, ?, ?, 'HttpStatus502', 9, ?,"
            " ?)",
            (payload["event_id"], payload["payload"], LEGACY_TARGET, iso(at(-90000)), iso(T0)),
        )
    finally:
        conn.close()

    conn2 = agent_db.connect(path)  # <-- the upgrade happens here (real connect)
    return conn2, path


# -----------------------------------------------------------------------------------------
# (A) the migration is versioned, additive and lands on the new identity
# -----------------------------------------------------------------------------------------


def test_the_shipped_history_now_ends_at_the_two_per_sink_steps() -> None:
    """A versioned migration means APPENDED entries, never an edited v3: an agent at v4
    must reach v7 through the same code path that took it from v2 to v4."""
    names = [m.name for m in agent_db.MIGRATIONS]
    assert [m.version for m in agent_db.MIGRATIONS] == [1, 2, 3, 4, 5, 6, 7]
    assert names[4] == "push_queue_per_sink" and names[5] == "dead_letter_per_sink"
    for m in agent_db.MIGRATIONS[4:6]:
        assert "DROP TABLE" in m.sql.upper(), (
            f"migration {m.version} rebuilds a table: a UNIQUE constraint cannot be "
            "altered in sqlite, so this step must swap the table — see its own comment"
        )
        assert "sink_name" in m.sql, f"migration {m.version} must create the identity column"


def test_upgrade_bumps_the_recorded_version_and_leaves_the_old_history(
    upgraded,
) -> None:
    conn, _ = upgraded
    rows = list(conn.execute("SELECT version, name FROM schema_migrations ORDER BY version"))
    assert [r["version"] for r in rows] == [1, 2, 3, 4, 5, 6, 7]
    # The pre-upgrade entries keep their names: the history is a record, not a sketch.
    assert rows[2]["name"] == "push_queue" and rows[3]["name"] == "dead_letter"


def test_upgrade_is_idempotent_on_a_second_open(tmp_path, monkeypatch) -> None:
    """`connect` runs on every agent start: opening an already-v7 db must be a no-op, not
    a second rebuild that rewrites (or re-hashes) the backlog."""
    path = tmp_path / "agent.sqlite3"
    conn = build_pre_upgrade_db(path, monkeypatch=monkeypatch)
    seed_backlog(conn, serial_nos=(5742,))
    before = list(conn.execute("SELECT * FROM push_queue ORDER BY id"))
    conn.close()

    first = agent_db.connect(path)
    first.close()
    second = agent_db.connect(path)
    try:
        # Rows compare by identity, not value, so the bytes are compared as dicts — and
        # only over the columns the pre-upgrade table had, since the upgrade ADDS
        # `sink_name` (its value is pinned by the backlog test, not by this one).
        shared = tuple(dict(before[0]).keys())
        after = [dict(r) for r in second.execute("SELECT * FROM push_queue ORDER BY id")]
        assert [tuple(row[c] for c in shared) for row in after] == [
            tuple(row[c] for c in shared) for row in before
        ], "the second open rewrote nothing"
        assert agent_db.current_version(second) == 7
    finally:
        second.close()


def test_the_new_identity_is_a_unique_index_and_the_old_one_is_gone(upgraded) -> None:
    """Two sinks, one event = two rows (that is the point of the card). The old
    UNIQUE(event_id, endpoint) must be genuinely gone, or a second sink for the same
    target would be a silent `IntegrityError` on the next overlap poll."""
    conn, _ = upgraded
    cols = {r[1] for r in conn.execute("PRAGMA table_info(push_queue)")}
    assert "sink_name" in cols and "endpoint" in cols, "endpoint stays as provenance"
    ddl = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'push_queue'"
    ).fetchone()["sql"]
    assert "UNIQUE (event_id, sink_name)" in ddl, ddl
    assert "UNIQUE (event_id, endpoint)" not in ddl, ddl
    ddl_dl = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'dead_letter'"
    ).fetchone()["sql"]
    assert "UNIQUE (event_id, sink_name)" in ddl_dl and "UNIQUE (event_id, endpoint)" not in ddl_dl


def test_both_drain_query_shapes_are_indexed(upgraded) -> None:
    """The v3 index was (endpoint, next_attempt_at) — the drain's query shape. The
    per-sink drain queries by sink, so the upgrade must add that index too: without it a
    5-minute tick scans the whole backlog (the reason the original index exists)."""
    conn, _ = upgraded
    # Materialised, not nested: re-entering `conn.execute` while an outer cursor is still
    # iterating RESETS that cursor (sqlite3 semantics), which would read as "no indexes".
    # `index_info` (not `index_columns`): the latter returns unnamed rows on this sqlite
    # build, which would make the assertion vacuously false.
    names = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")]
    indexed = {tuple(r[2] for r in conn.execute(f"PRAGMA index_info({name})")) for name in names}
    assert ("sink_name", "next_attempt_at") in indexed, indexed
    assert ("endpoint", "next_attempt_at") in indexed, "today's drain must not lose its plan"
    assert ("sink_name",) in indexed, "the dead-letter triage list filters by sink"


def test_a_second_sink_for_the_same_event_is_a_second_row(upgraded) -> None:
    """The multi-sink promise, straight onto upgraded data: the same event queued at a
    second (named) sink is a separate buffer with its own retry state."""
    conn, _ = upgraded
    event_id = conn.execute("SELECT MIN(id) AS id FROM events").fetchone()["id"]
    ids = agent_push.enqueue_events(
        conn, [event_id], endpoint=OLD_TARGET, sink_name="archive", now=T0
    )
    assert len(ids) == 1
    rows = list(
        conn.execute("SELECT * FROM push_queue WHERE event_id = ? ORDER BY id", (event_id,))
    )
    assert {r["sink_name"] for r in rows} == {IMPLICIT_SINK_NAME, "archive"}
    # The new sink's buffer starts clean; the legacy one keeps the outage state the
    # fixture gave it — one sink's failure history must not be the other's.
    archive = next(r for r in rows if r["sink_name"] == "archive")
    assert archive["attempts"] == 0 and archive["first_failed_at"] is None
    assert archive["endpoint"] == OLD_TARGET


# -----------------------------------------------------------------------------------------
# (B) THE migration test the card dictates: pre-upgrade backlog survives on `legacy`
# -----------------------------------------------------------------------------------------


def test_pre_upgrade_pending_backlog_survives_addressed_to_the_implicit_sink(
    upgraded,
) -> None:
    """The backward-compat law, at the row level.

    Site-a upgrades with no config change. Its un-pushed punches must still be there, one
    per event, each now addressed to the sink its unchanged `push_target` implies
    (`legacy`) — because `enqueue_events` puts every `push_target`-only row there, the
    drain wiring will find them on the next tick without the operator doing anything.
    """
    conn, _ = upgraded
    rows = list(conn.execute("SELECT * FROM push_queue ORDER BY id"))
    assert len(rows) == 3, "one row per queued event, none lost, none duplicated"
    assert {r["sink_name"] for r in rows} == {IMPLICIT_SINK_NAME}
    # The ref it was aimed at is still recorded (provenance: an owner triaging an old
    # outage reads the endpoint the row actually failed against, not today's config).
    assert {r["endpoint"] for r in rows} == {LEGACY_TARGET}


def test_upgrade_preserves_payload_bytes_and_retry_state_byte_for_byte(
    tmp_path, monkeypatch
) -> None:
    """Keep-everything is not a slogan: the payload line is the punch, and
    `first_failed_at` is the 24 h outage clock. A rebuild that reset either would either
    lose a punch or silently buy a fresh 24 h for a week-long outage."""
    path = tmp_path / "agent.sqlite3"
    conn = build_pre_upgrade_db(path, monkeypatch=monkeypatch)
    rowids = seed_backlog(conn, serial_nos=(5742, 5743))
    conn.execute(
        "UPDATE push_queue SET attempts = 5, first_failed_at = ?, last_attempt_at = ?,"
        " last_error_class = 'HttpStatus503' WHERE event_id = ?",
        (iso(at(-70000)), iso(at(-10)), rowids[0]),
    )
    before = {r["event_id"]: dict(r) for r in conn.execute("SELECT * FROM push_queue ORDER BY id")}
    stored = {r["id"]: r["jsonl"] for r in conn.execute("SELECT id, jsonl FROM events ORDER BY id")}
    conn.close()

    conn2 = agent_db.connect(path)
    try:
        after = {r["event_id"]: dict(r) for r in conn2.execute("SELECT * FROM push_queue")}
        assert set(after) == set(before), "the same events are queued"
        for event_id, old in before.items():
            new = after[event_id]
            assert new["payload"] == old["payload"], "the punch bytes are unchanged"
            assert new["payload"] == stored[event_id], "and still match the store verbatim"
            for column in (
                "attempts",
                "first_failed_at",
                "last_attempt_at",
                "last_error_class",
                "next_attempt_at",
                "enqueued_at",
            ):
                assert new[column] == old[column], f"{column} moved across the upgrade"
            assert new["sink_name"] == IMPLICIT_SINK_NAME
        # The payload is still the frozen contract, parseable end to end.
        assert parsed(after[rowids[1]]["payload"]).serial_no == 5743
    finally:
        conn2.close()


def test_upgrade_survives_an_event_queued_at_two_targets_before_the_upgrade(
    tmp_path, monkeypatch
) -> None:
    """The ugly real case the migration must not choke on.

    `UNIQUE(event_id, endpoint)` allowed ONE event buffered against TWO targets (the
    operator changed `push_target` while a backlog was queued). A blind
    `sink_name = 'legacy'` backfill would violate the new UNIQUE and leave the db
    unopenable — the worst possible migration failure, discovered by an agent that
    cannot start. So the second row of an event keeps an identity of its own: the
    oldest row is `legacy`, any additional one is `legacy+<id>`, which cannot collide
    and cannot be mistaken for a configured sink name."""
    path = tmp_path / "agent.sqlite3"
    conn = build_pre_upgrade_db(path, monkeypatch=monkeypatch)
    rowids = seed_backlog(conn, serial_nos=(5742,))
    # A second buffer for the SAME event against the target the site used before.
    conn.execute(
        "INSERT INTO push_queue (id, event_id, payload, endpoint, attempts, first_failed_at,"
        " last_attempt_at, last_error_class, next_attempt_at, enqueued_at)"
        " SELECT NULL, event_id, payload, ?, 2, ?, ?, 'ConnectError', ?, ? FROM push_queue"
        " WHERE event_id = ?",
        (OLD_TARGET, iso(T0), iso(T0), iso(T0), iso(T0), rowids[0]),
    )
    assert conn.execute("SELECT COUNT(*) FROM push_queue").fetchone()[0] == 2, (
        "pre-upgrade: two buffers, one event"
    )
    conn.close()

    conn2 = agent_db.connect(path)
    try:
        rows = list(conn2.execute("SELECT * FROM push_queue ORDER BY id"))
        assert len(rows) == 2, "keep-everything: both buffers survived"
        assert rows[0]["sink_name"] == IMPLICIT_SINK_NAME, "the oldest row is the site's sink"
        assert rows[0]["endpoint"] == LEGACY_TARGET
        assert rows[1]["sink_name"].startswith("legacy+")
        assert rows[1]["endpoint"] == OLD_TARGET, "the orphan keeps its provenance"
        assert rows[1]["attempts"] == 2 and rows[1]["last_error_class"] == "ConnectError"
    finally:
        conn2.close()


def test_upgrade_carries_dead_letter_rows_onto_the_implicit_sink(upgraded) -> None:
    """The dead-letter is the record of what could NOT be sent; a migration that dropped
    it would be the silent data loss this module exists to prevent."""
    conn, _ = upgraded
    rows = list(conn.execute("SELECT * FROM dead_letter"))
    assert len(rows) == 1
    row = rows[0]
    assert row["sink_name"] == IMPLICIT_SINK_NAME
    assert row["endpoint"] == LEGACY_TARGET
    assert row["error_class"] == "HttpStatus502" and row["attempts"] == 9
    assert row["first_attempt_at"] == iso(at(-90000)), "the outage start is never moved"
    assert parsed(row["payload"]).serial_no == 5742, "the COMPLETE payload line is intact"


def test_only_the_owner_command_still_deletes_a_dead_letter_row_after_upgrade(
    upgraded,
) -> None:
    """§2b's law is about the table, not the version: the upgrade must not have quietly
    added a path (a purge, a success elsewhere, a TTL) that clears it."""
    conn, _ = upgraded
    row_id = conn.execute("SELECT id FROM dead_letter").fetchone()["id"]
    # A successful push of the SAME key clears it (that one is by design, P2-04) — but a
    # push of another key may not, and nothing else does either.
    assert conn.execute("SELECT COUNT(*) FROM dead_letter").fetchone()[0] == 1, (
        "a reopen alone did not clear the table"
    )
    assert agent_push.delete_dead_letter(conn, row_id) is True
    assert agent_push.dead_letter_depth(conn) == 0
    assert agent_push.delete_dead_letter(conn, row_id) is False, "an id typo is not a success"


def test_the_restrict_fk_survives_the_rebuild(upgraded) -> None:
    """`ON DELETE RESTRICT` is the load-bearing choice (a purge must not outrun the
    queue). A rebuild that wrote CASCADE would keep every existing test green and lose a
    punch the first time an owner purges — so the FK is pinned on the rebuilt table."""
    conn, _ = upgraded
    event_id = conn.execute("SELECT MIN(event_id) AS id FROM push_queue").fetchone()["id"]
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM events WHERE id = ?", (event_id,))
    kept = conn.execute(
        "SELECT COUNT(*) FROM push_queue WHERE event_id = ?", (event_id,)
    ).fetchone()[0]
    assert kept == 1, "the refused delete did not take the buffer with it"


def test_a_pre_v5_db_refuses_a_downgrade_like_every_other_step(tmp_path, monkeypatch) -> None:
    """An old binary meeting the new schema is a corruption event, not a compatibility
    question — the v5/v6 steps inherit that guard, they must not have bypassed it."""
    path = tmp_path / "agent.sqlite3"
    conn = build_pre_upgrade_db(path, monkeypatch=monkeypatch)
    conn.close()
    upgraded_conn = agent_db.connect(path)
    upgraded_conn.close()

    monkeypatch.setattr(agent_db, "MIGRATIONS", tuple(agent_db.MIGRATIONS[:4]))
    with pytest.raises(agent_db.MigrationTooNewError):
        agent_db.connect(path)


def test_the_migrations_never_name_a_live_store_path() -> None:
    """The fixture is built in tmp dirs by every test above. This pins the other half:
    the migration SQL itself carries no absolute path, no `ATTACH`, and no `~/gateclerk`
    — a DDL script that could reach outside the open db file is not a migration."""
    for step in agent_db.MIGRATIONS:
        text = step.sql.upper()
        assert "ATTACH" not in text, f"migration {step.version} opens another file"
        assert "GATECLERK/" not in text and "~" not in step.sql
        assert "/VAR/" not in text and "/ETC/" not in text, "DDL carries no filesystem paths"


def test_the_fixture_is_a_copy_in_tmp_never_the_live_db(tmp_path, monkeypatch) -> None:
    """Explicitly the card's sentence: NEVER the live db, never `~/gateclerk/`."""
    path = tmp_path / "agent.sqlite3"
    conn = build_pre_upgrade_db(path, monkeypatch=monkeypatch)
    conn.close()
    assert path.resolve().is_relative_to(tmp_path.resolve())
    assert_not_a_live_store(path)
    with pytest.raises(AssertionError):
        assert_not_a_live_store(Path.home() / "gateclerk" / "site-a.sqlite3")


# -----------------------------------------------------------------------------------------
# (C) the queue API reads and writes the new identity
# -----------------------------------------------------------------------------------------


def test_enqueue_defaults_to_the_implicit_sink(tmp_path) -> None:
    """Today's call shape (`endpoint=` only) is what `agent_cli` uses, so its default
    must be the implicit sink — that is the storage half of 'zero config change'."""
    conn = agent_db.connect(tmp_path / "agent.sqlite3")
    try:
        rowids = seed_queued(conn, serial_nos=(5742,))
        row = conn.execute("SELECT * FROM push_queue WHERE id = ?", (rowids[0],)).fetchone()
        assert row["sink_name"] == IMPLICIT_SINK_NAME
    finally:
        conn.close()


def test_enqueue_is_idempotent_per_sink_not_per_endpoint(tmp_path) -> None:
    """The overlap poll re-queues the same events every 5 minutes: one buffer per
    (event, sink), refreshed payload, preserved retry state — per sink, so two sinks
    each get their own independent outage clock."""
    conn = agent_db.connect(tmp_path / "agent.sqlite3")
    try:
        rowids = seed_queued(conn, serial_nos=(5742,))
        first = conn.execute("SELECT id, attempts FROM push_queue").fetchone()
        conn.execute("UPDATE push_queue SET attempts = 4, first_failed_at = ?", (iso(T0),))

        again = agent_push.enqueue_events(conn, rowids, endpoint=LEGACY_TARGET, now=at(300))
        assert again == (first["id"],), "same queue row, not a second buffer"
        row = conn.execute("SELECT * FROM push_queue").fetchone()
        assert row["attempts"] == 4 and row["first_failed_at"] == iso(T0), "outage clock kept"

        agent_push.enqueue_events(conn, rowids, endpoint=OLD_TARGET, sink_name="audit", now=at(600))
        audit = conn.execute("SELECT * FROM push_queue WHERE sink_name = 'audit'").fetchone()
        assert audit is not None and audit["attempts"] == 0, "fresh clock for a fresh sink"
    finally:
        conn.close()


def test_pending_rows_and_dead_letter_rows_expose_the_sink(upgraded) -> None:
    """The CLI/health read seams must not hand-write SQL against the new column: they
    carry `sink_name` out, and filter by it, so P2-07 can show 'which sink is behind'."""
    conn, _ = upgraded
    pending = agent_push.pending_rows(conn)
    assert pending and {p.sink_name for p in pending} == {IMPLICIT_SINK_NAME}
    assert pending[0].endpoint == LEGACY_TARGET

    # An unknown sink filter is a normal empty result, not an error (a sink can be
    # removed from config while its rows are still queued).
    assert agent_push.pending_rows(conn, sink_name="nope") == ()
    assert agent_push.pending_rows(conn, sink_name=IMPLICIT_SINK_NAME) == pending
    dead = agent_push.dead_letter_rows(conn, sink_name=IMPLICIT_SINK_NAME)
    assert len(dead) == 1 and dead[0].sink_name == IMPLICIT_SINK_NAME
    assert agent_push.dead_letter_rows(conn, sink_name="nope") == ()


def test_replay_requeues_the_dead_letter_under_its_own_sink(tmp_path) -> None:
    """'Replay = re-push' means re-push to the sink the row failed against, not to
    whatever the site's first sink happens to be."""
    conn = agent_db.connect(tmp_path / "agent.sqlite3")
    try:
        rowids = seed_queued(conn, serial_nos=(5742,))
        payload = conn.execute(
            "SELECT payload FROM push_queue WHERE event_id = ?", (rowids[0],)
        ).fetchone()["payload"]
        conn.execute("DELETE FROM push_queue WHERE event_id = ?", (rowids[0],))
        conn.execute(
            "INSERT INTO dead_letter (id, event_id, payload, sink_name, endpoint, error_class,"
            " attempts, first_attempt_at, last_attempt_at) VALUES (NULL, ?, ?, 'archive', ?, "
            "'HttpStatus502', 4, ?, ?)",
            (rowids[0], payload, OLD_TARGET, iso(T0), iso(T0)),
        )
        queue_id = agent_push.replay_dead_letter(conn, 1, now=T0)
        row = conn.execute("SELECT * FROM push_queue WHERE id = ?", (queue_id,)).fetchone()
        assert row["sink_name"] == "archive", "the replay carries the row's sink identity"
        assert row["endpoint"] == OLD_TARGET
        assert row["attempts"] == 4 and row["first_failed_at"] == iso(T0)
        assert conn.execute("SELECT COUNT(*) FROM dead_letter").fetchone()[0] == 1, (
            "the row stays until a push succeeds"
        )

        # A sink override re-targets the replay (the ingest moved, or the operator wants
        # it in the archive this time).
        conn.execute("DELETE FROM push_queue")
        queue_id = agent_push.replay_dead_letter(conn, 1, sink_name="bc", now=at(60))
        row = conn.execute("SELECT * FROM push_queue WHERE id = ?", (queue_id,)).fetchone()
        assert row["sink_name"] == "bc" and row["endpoint"] == OLD_TARGET
    finally:
        conn.close()


def test_the_queue_columns_grew_exactly_the_identity_column() -> None:
    """`QUEUE_COLUMNS`/`DEAD_LETTER_COLUMNS` are the read-side contract; the schema and
    the tuple must not drift (a stale tuple means a SELECT that names a missing column)."""
    assert agent_push.QUEUE_COLUMNS[:4] == (
        "id",
        "event_id",
        "payload",
        "sink_name",
    )
    assert "endpoint" in agent_push.QUEUE_COLUMNS, "provenance is still a column"
    assert agent_push.DEAD_LETTER_COLUMNS[:4] == (
        "id",
        "event_id",
        "payload",
        "sink_name",
    )


def test_a_config_named_sink_and_the_storage_identity_agree(tmp_path) -> None:
    """The seam between this card and SINKS-WIRING: the name a config declares IS the
    name the queue keys on, so a drain that selects `WHERE sink_name = ?` finds its own
    rows and nobody has to translate between the two worlds."""
    from gateclerk.config import parse_sites

    site = parse_sites(
        (
            f'[[site]]\nname = "{SITE}"\nhost = "192.0.2.10"\n'
            '  [[site.sink]]\n  name = "archive"\n  type = "jsonl"\n'
            '  path = "/var/lib/gateclerk/audit.jsonl"\n'
        ).encode()
    )[SITE]
    conn = agent_db.connect(tmp_path / "agent.sqlite3")
    try:
        sink = site.sinks[0]
        rowids = _store(conn, (5742,))
        queue_ids = agent_push.enqueue_events(
            conn, rowids, endpoint=sink.ref, sink_name=sink.name, now=T0
        )
        row = conn.execute("SELECT * FROM push_queue WHERE id = ?", (queue_ids[0],)).fetchone()
        assert row["sink_name"] == "archive" and row["endpoint"] == sink.ref
    finally:
        conn.close()


def test_enqueue_still_refuses_a_target_that_is_not_an_accepted_scheme(tmp_path) -> None:
    """§3 still guards the queue.

    `file://` IS accepted here now (a csv/jsonl sink's ref is a local path) but it cannot
    be hand-written around the registry: only `sinks._build_file` mints one, and only from
    an absolute, traversal-free path. `push_target` keeps refusing `file://` — see
    `test_push_target_still_refuses_a_file_scheme` in tests/test_sinks_config.py.
    """
    conn = agent_db.connect(tmp_path / "agent.sqlite3")
    try:
        with pytest.raises(agent_push.PushTargetError):
            agent_push.enqueue_events(conn, [1], endpoint="ftp://x.invalid/y", now=T0)
        with pytest.raises(agent_push.PushTargetError):
            agent_push.enqueue_events(conn, [1], endpoint="x.invalid/push", now=T0)
        assert agent_push.queue_depth(conn) == 0, "a refused target leaves no row"
    finally:
        conn.close()


def test_an_empty_sink_name_is_refused(tmp_path) -> None:
    """A row with no sink identity is unaddressable — it can never be drained by any
    configured sink, so it is a punch that will quietly never go out."""
    conn = agent_db.connect(tmp_path / "agent.sqlite3")
    try:
        with pytest.raises(agent_push.QueueError):
            agent_push.enqueue_events(conn, [1], endpoint=LEGACY_TARGET, sink_name="  ", now=T0)
    finally:
        conn.close()


def test_a_sink_named_with_sql_separators_is_refused(tmp_path) -> None:
    """The name is a plain column value (no string SQL is built from it) but it also
    lands in log lines and in the CSV envelope column, so it keeps the config's
    identifier rule instead of absorbing whatever a caller passes."""
    conn = agent_db.connect(tmp_path / "agent.sqlite3")
    try:
        for bad in ("a b", "a-b", "a.b", 'a"b'):
            with pytest.raises(agent_push.QueueError):
                agent_push.enqueue_events(conn, [1], endpoint=LEGACY_TARGET, sink_name=bad, now=T0)
    finally:
        conn.close()
