# P2-02 store implementation notes (working notes; trimmed into the PR body)

## Environment facts verified this run

- Base gate on this branch (main 2a5f979, before any P2-02 file): `uv run pytest -q`
  = **1150 passed, 5 skipped, 1 deselected** in 34.7s — matches the card's base
  exactly. Run it with `PYTHONPATH=<worktree>/src` (t_7b073d11 lesson: the main
  checkout installs gateclerk editable, so a bare pytest in a worktree imports MAIN's
  src and prints a false green). tests/conftest.py's `_source_guard` aborts on that,
  which is why the prefix is needed rather than optional.
- Local sqlite is 3.50.4, `journal_mode=WAL` round-trips, `synchronous=NORMAL` reads
  back as 1.

## Probe results that the semantics are built on (scratch/sqlite_probe.py)

UPSERT shape:

```
INSERT ... ON CONFLICT(k) DO UPDATE
SET jsonl = excluded.jsonl, revision = t.revision + 1, updated_at = excluded.updated_at
WHERE t.jsonl IS NOT excluded.jsonl
```

- identical re-store: `cursor.rowcount == 0`, `total_changes` delta **0** — the write
  costs no statement at all, so "re-poll of the overlap window is FREE" is literally
  true, not just "no visible change".
- row identity survives: same rowid, same `stored_at`, same `revision`.
- changed bytes for the same key: `rowcount == 1`, revision 1→2, `updated_at` moves,
  `stored_at` stays (first-seen).
- checkpoint UPSERT with `WHERE excluded.serial >= t.serial`: a lower value costs 0
  statements and cannot regress the row. Equal also costs 0 (important: a 5-min poll
  with no new events re-advances the same serial every tick and must not churn).

## Migration list (what P2-04 appends to)

Shipped list: v1 `schema_migrations_bookkeeping`, v2 `events_and_checkpoint`
(v2 is "the agent db": events + checkpoint in one additive entry). **P2-04 appends
starting at v3** (e.g. v3 `push_queue`, v4 `dead_letter`) — its card calls this the
"extensible migration seam P2-02 left"; it is pinned by
test_a_new_migration_appends_and_applies_on_next_open, which appends a fake entry the
same way P2-04 will and reopens the db. Each entry applies in ONE explicit
transaction (statements run individually inside an explicit BEGIN — `executescript`
would commit the BEGIN first), versions must be strictly ascending from 1, and a db
newer than the code is refused rather than "migrated backwards".

## Mutation probes run (backup+restore, PYTHONDONTWRITEBYTECODE=1, no cacheprovider)

| mutant | caught by |
|---|---|
| M1 drop the free-overlap WHERE guard | idempotence + first-contact stamps (2 tests) |
| M2 checkpoint guard `>` -> `>=` | equal-value no-op pin |
| M3 `completed` flag ignored | refuses-an-uncompleted pin |
| M4 regression raise swallowed | never-regresses pin |
| M5 UPSERT RETURNING drops id | rowid/lookup pins |
| M6 store re-serialises instead of verbatim | byte-identity pin |
| M7 watermark `>` -> `>=` | boundary parametrization (3 cases) |
| M8 migration ascending check removed | SURVIVED the reversed-list test (the start-at-1 guard fired by accident) — fixed by the middle-swap test (1,3,2), which trips ONLY the ascending check |

M8 is the reason the order guard is pinned per-branch (ascending / start-at-1 /
duplicate / downgrade / mid-entry rollback) instead of by one reversed-list test.

## Decision the spec leaves open, and how it is handled

`EventRecord.serial_no` is `int | None`, and SQLite's UNIQUE treats NULLs as distinct:
probe shows `(SN-2, NULL)` stored **twice** with identical content. So for a record
with no serialNo the pinned key cannot dedupe at all — every overlap poll would add a
row — while a surrogate/digest-keyed dedupe would silently merge two genuinely
different serial-less events. Both are lossy in a way DESIGN.md ("everything is still
stored") would not forgive, and OBSERVED.md shows `serialNo` on every real record.

Chosen: `store_events` REFUSES a serial-less record loudly
(`UnusableRecordError`, names site + employee + time) and leaves the batch **unwritten**
(one transaction, no partial store). The caller (P2-03) routes it; alerting is P2-05.
Flagged to the orchestrator on the card rather than settled unilaterally.

## Decisions taken here that P2-03/P2-04 will consume

- `advance_checkpoint(conn, device_serial, max_serial, *, completed=True,
  checkpoint_time=None)` — refuses `completed=False`; refuses a lower serial
  (`CheckpointRegressionError`); an equal serial is a no-op (no write).
- `checkpoint_time` is stored **verbatim** from the caller (the device-local time of
  the record carrying that max serial — DESIGN.md's
  `(last_serial_no, last_event_time_local)`), never derived here, and a later advance
  with `None` never blanks it.
- `db_size_bytes` counts the main db file only (WAL bytes are not counted) — P2-05's
  gauge; boundary is `size > warn_bytes` (strictly).
- migrations: `MIGRATIONS` is a tuple of `(version, name, sql)` additive entries,
  forward-only (descending/duplicate version raises), each applied in its own
  transaction. P2-04 appends its queue/dead-letter entries.
