"""GC-P01 (E22) — the push queue carries only granted punch candidates.

The site agent STORES every access-control event: a denied credential, a door-state record
and an unreadable code all belong in `events` for diagnostics (GC-P20 reads them there).
`queue_new_events` is the only door between that store and a sink, and a queued row becomes
a real attendance punch in BC Table 70607 — so the punch rule has to be in this query.

The rule is `classify_event`'s, stated once in `event_codes._punch_decision`: major 5, a
known code, `granted`, an authentication pass minor, an employee number and a real
`currentVerifyMode`. These tests pin the SQL to that single rule two ways: a six-record
case table that names every rejection, and the recorded site-a page, where the queue's
result set must be EXACTLY the set `classify_event` calls a punch candidate. The second one
is what stops the query's verify-mode list from drifting away from
`NON_AUTH_VERIFY_MODES` — drift shows up as a set difference, not as a passing test.

Setup is the real thing, as in `tests/test_cli_doctor.py::_seed_store`: a real sqlite store
through `agent_db.connect` + `agent_store.store_events`, records assembled by
`pipeline.event_record_from_device` (the same call `DeviceLoop._assemble` makes, so the
stored `outcome`/`unknown_code`/`verify_mode` columns are exactly what production writes).
Nothing is mocked and nothing is dropped: every row goes in, the queue is read back out of
`push_queue`, and the `events` count is asserted at the end.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from gateclerk import agent_cli, agent_db, agent_store
from gateclerk.event_codes import NON_AUTH_VERIFY_MODES, classify_event
from gateclerk.pipeline import event_record_from_device

T0 = datetime(2026, 11, 13, 9, 0, 0, tzinfo=UTC)
SITE = "demo-a"
DEVICE = "DEMO-SN-01"
SITE_TZ = "Europe/Bucharest"
FIXTURE_PAGE = (
    Path(__file__).parent
    / "fixtures"
    / "recorded"
    / "site-a-ds-k1t341amf-s"
    / "events_major5_page1.json"
)

# The pass / door-state / denied codes the case table below uses, named so a future edit to
# the curated code table breaks a readable assert instead of silently testing nothing.
PASS_MINOR = 75  # CARD_PASS -> granted
DOOR_MINOR = 21  # MINOR_BUTTON_OPEN -> info
DENIED_MINOR = 8  # INVALID_CARD -> denied
UNKNOWN_MINOR = 999  # not in the curated table -> info + unknown_code


def _raw_event(
    serial_no: int,
    *,
    major: int = 5,
    minor: int = PASS_MINOR,
    employee: str | None = "1",
    verify: str | None = "cardOrFaceOrFp",
) -> dict[str, Any]:
    """One raw AcsEvent record, shaped like the recorded site-a page."""
    event: dict[str, Any] = {
        "major": major,
        "minor": minor,
        "time": (T0 + timedelta(seconds=serial_no)).isoformat(),
        "cardType": 1,
        "name": f"User {employee or 'Unknown'}",
        "cardReaderNo": 1,
        "doorNo": 1,
        "type": 0,
        "serialNo": serial_no,
        "userType": "normal",
        "mask": "no",
    }
    if employee is not None:
        event["employeeNoString"] = employee
    if verify is not None:
        event["currentVerifyMode"] = verify
    return event


def _store(conn: sqlite3.Connection, raw_events: list[dict[str, Any]]) -> dict[int, int]:
    """Store the batch the way the loop does; return serialNo -> events.id."""
    records = [
        event_record_from_device(
            event,
            site=SITE,
            device_serial=DEVICE,
            site_tz=SITE_TZ,
            captured_at=T0,
        )
        for event in raw_events
    ]
    res = agent_store.store_events(conn, records, now=T0)
    assert res.rowids is not None
    assert res.inserted == len(raw_events), res
    return dict(res.rowids)


def _queued_event_ids(conn: sqlite3.Connection) -> list[int]:
    """The events that have a send buffer, oldest queue row first."""
    return [
        row["event_id"]
        for row in conn.execute("SELECT event_id FROM push_queue ORDER BY id").fetchall()
    ]


def _stored_event_ids(conn: sqlite3.Connection) -> list[int]:
    return [row["id"] for row in conn.execute("SELECT id FROM events ORDER BY id").fetchall()]


def _queue(conn: sqlite3.Connection, tmp_path: Path, *, limit: int = 200) -> tuple[int, ...]:
    return agent_cli.queue_new_events(
        conn, endpoint=f"stub://{tmp_path / 'gc-p01.jsonl'}", now=T0, limit=limit
    )


def test_queue_skips_denied_info_unknown_and_unattributed_events(tmp_path: Path) -> None:
    """Six stored rows, one punch: only the granted attributed known code is queued."""
    raws = [
        _raw_event(101),  # major 5, granted, employee "1", cardOrFaceOrFp -> THE punch
        _raw_event(102, minor=DENIED_MINOR),  # a refused card
        _raw_event(103, minor=DOOR_MINOR),  # door state, informational
        _raw_event(104, minor=UNKNOWN_MINOR),  # unreadable code
        _raw_event(105, employee=None),  # granted pass with no employeeNoString
        _raw_event(106, verify="invalid"),  # granted pass, no credential authenticated
    ]
    # The case table is only meaningful while the classifier still calls these what the
    # test says: (outcome, unknown_code, punch_candidate) per row.
    verdicts = [
        (v.outcome.value, v.unknown_code, v.punch_candidate) for v in map(classify_event, raws)
    ]
    assert verdicts == [
        ("granted", False, True),
        ("denied", False, False),
        ("info", False, False),
        ("info", True, False),
        ("granted", False, False),
        ("granted", False, False),
    ]

    conn = agent_db.connect(tmp_path / "gc-p01.sqlite3", now_iso=T0.isoformat())
    try:
        ids = _store(conn, raws)
        queued = _queue(conn, tmp_path)
        # `queue_new_events` returns push_queue ids, so the event it chose is read back.
        assert len(queued) == 1
        assert _queued_event_ids(conn) == [ids[101]]
        assert conn.execute("SELECT COUNT(*) FROM push_queue").fetchone()[0] == 1
        # Nothing was dropped on the way in: the refused scan stays a diagnostic row.
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == len(raws)
        assert _stored_event_ids(conn) == [ids[s] for s in (101, 102, 103, 104, 105, 106)]
    finally:
        conn.close()


def test_queue_keeps_granted_punch_candidates(tmp_path: Path) -> None:
    """Two real punches queue, in `ORDER BY e.id` order, with the stored bytes as payload."""
    raws = [
        _raw_event(202, employee="2"),  # stored FIRST -> events.id 1
        _raw_event(201, employee="1"),  # stored SECOND -> events.id 2
    ]
    conn = agent_db.connect(tmp_path / "gc-p01.sqlite3", now_iso=T0.isoformat())
    try:
        ids = _store(conn, raws)
        queued = _queue(conn, tmp_path)
        assert len(queued) == 2
        # The queue's order is the STORE's order (`ORDER BY e.id`), not serialNo order —
        # the two disagree here on purpose, because serial 202 was stored before 201.
        assert _queued_event_ids(conn) == [ids[202], ids[201]] == sorted(ids.values())
        # Untouched by this card: the payload is the stored jsonl line, verbatim.
        payloads = {
            row["event_id"]: row["payload"]
            for row in conn.execute("SELECT event_id, payload FROM push_queue").fetchall()
        }
        for serial_no in (201, 202):
            body = json.loads(payloads[ids[serial_no]])
            assert body["serial_no"] == serial_no
            assert body["employee_no"] == str(serial_no - 200)
    finally:
        conn.close()


def test_non_auth_verify_modes_come_from_the_classifier_constant(tmp_path: Path) -> None:
    """Every `NON_AUTH_VERIFY_MODES` member is refused; an unseen plausible mode is kept.

    The list is `NON_AUTH_VERIFY_MODES` itself, matched case- and whitespace-insensitively
    exactly as `_verify_is_auth_mode` does, so this test iterates the constant instead of
    restating it: add a mode to the classifier and it is refused here without an edit.
    """
    unseen = "face"  # a mode the table has never seen is a REAL mode: dropping it loses a punch
    raws = [
        _raw_event(301, verify=unseen),
        # Every non-auth mode, in the classifier's own casing/whitespace tolerance. `""`
        # never reaches a column (`_text_or_none` stores it as NULL), so it is covered by
        # the missing-field row below rather than by the loop.
        *[
            _raw_event(310 + i, verify=f"  {mode.upper()}  ")
            for i, mode in enumerate(sorted(NON_AUTH_VERIFY_MODES - {""}))
        ],
        _raw_event(401, verify=None),
    ]
    verdicts = [classify_event(event) for event in raws]
    assert [v.punch_candidate for v in verdicts] == [True] + [False] * (len(raws) - 1)

    conn = agent_db.connect(tmp_path / "gc-p01.sqlite3", now_iso=T0.isoformat())
    try:
        ids = _store(conn, raws)
        _queue(conn, tmp_path)
        assert _queued_event_ids(conn) == [ids[301]]
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == len(raws)
    finally:
        conn.close()


def test_filter_matches_classify_event_on_recorded_fixtures(tmp_path: Path) -> None:
    """On the recorded site-a page, the queue's set IS the classifier's punch-candidate set."""
    raws: list[dict[str, Any]] = json.loads(FIXTURE_PAGE.read_text(encoding="utf-8"))["AcsEvent"][
        "InfoList"
    ]
    assert raws, "the recorded page is empty — this test would prove nothing"

    all_serials = {event["serialNo"] for event in raws}
    expected = {event["serialNo"] for event in raws if classify_event(event).punch_candidate}
    assert expected and expected != all_serials, (
        "the recorded page must contain both a punch candidate and a rejection, or the "
        "equivalence below is vacuous"
    )

    conn = agent_db.connect(tmp_path / "gc-p01.sqlite3", now_iso=T0.isoformat())
    try:
        ids = _store(conn, raws)
        queued = _queue(conn, tmp_path, limit=len(raws) + 1)
        # `queued` are push_queue ids; the equivalence is about WHICH EVENTS were chosen.
        assert len(queued) == len(expected)
        assert set(_queued_event_ids(conn)) == {ids[s] for s in expected}
        # The rejected rows stay where GC-P20 can read them.
        assert len(_stored_event_ids(conn)) == len(raws)
    finally:
        conn.close()
