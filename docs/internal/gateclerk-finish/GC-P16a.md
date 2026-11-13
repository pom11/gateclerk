# GC-P16a — Prune already-pushed events from the local store

BOARD: gateclerk   DEPENDS ON: GC-P11   GATED: no   COVERS: GC-14 / —

## WHY

The site SQLite `events` table keeps every scan and its `name`, `employee_no` and `cardNo`
forever, after BC Table 70607 already owns the permanent record. This is unbounded local PII retention. This card prunes only rows the poller has already
pushed (or the owner discarded) and only after a retention window; the checkpoint and any
queued/dead-lettered row stay untouched. R1: BC is the store, the agent is a buffer.

## VERIFY

```bash
grep -rn "def prune_pushed_events\|DELETE FROM events" src/gateclerk --include='*.py'
```

Still broken while the command prints nothing (no product module defines the prune and no
product SQL deletes from `events`: the only `DELETE FROM events` is in tests).

If a retention/prune function already exists in `agent_store.py`, stop and close the card.

## FILES

- `src/gateclerk/agent_db.py:113-127` — the `events` table stores the flattened PII
  columns (`employee_no`, `name`, `raw`, `outcome`, ...).
- `src/gateclerk/agent_db.py:158-186` — `push_queue` has `event_id ... REFERENCES
  events(id) ON DELETE RESTRICT`; the database refuses to delete an event that is still
  queued. The delete must also respect `dead_letter`.
- `src/gateclerk/agent_cli.py:149-265` — `PushLedger` records `{"e", "t", "k", "s"}` lines
  for `sent`/`gone`; `_load` is the only parser.
- `src/gateclerk/agent_cli.py:637-690` — `SiteAgent.tick()` runs the push pass and then
  builds the report. This is the maintenance hook.
- `src/gateclerk/agent_store.py:276-300` — the store module's transaction idiom; a prune
  is one transaction per batch.

## CHANGE

1. Add a public ledger accessor in `src/gateclerk/agent_cli.py`:
   ```python
   def sent_event_ids(self) -> set[int]:
       """Every event this poller has recorded as sent or gone, across all sinks."""
       known = self._known if self._known is not None else self._load()
       return {event_id for ids in known.values() for event_id in ids}
   ```
   Do not expose endpoints, sink names or payloads; the caller needs only ids.

2. Add `prune_pushed_events` to `src/gateclerk/agent_store.py`:
   ```python
   def prune_pushed_events(
       conn: sqlite3.Connection,
       *,
       event_ids: set[int],
       before_utc: str,
   ) -> int:
       """Delete pushed events older than the cutoff; queued/dead-lettered rows survive.

       `push_queue` has ON DELETE RESTRICT, but the explicit NOT EXISTS keeps the intent
       readable and also protects a dead-lettered row that has no FK.
       """
       if not event_ids:
           return 0
       ids = sorted(event_ids)
       conn.execute("BEGIN IMMEDIATE")
       try:
           conn.execute("CREATE TEMP TABLE IF NOT EXISTS prune_ids "
                        "(event_id INTEGER NOT NULL PRIMARY KEY)")
           conn.execute("DELETE FROM temp.prune_ids")
           conn.executemany(
               "INSERT OR IGNORE INTO temp.prune_ids VALUES (?)",
               ((event_id,) for event_id in ids),
           )
           cur = conn.execute(
               """
               DELETE FROM events
                WHERE id IN (SELECT event_id FROM temp.prune_ids)
                  AND event_time_utc IS NOT NULL
                  AND event_time_utc < ?
                  AND NOT EXISTS (SELECT 1 FROM push_queue AS q WHERE q.event_id = events.id)
                  AND NOT EXISTS (SELECT 1 FROM dead_letter AS d WHERE d.event_id = events.id)
               """,
               (before_utc,),
           )
           deleted = cur.rowcount
       except BaseException:
           conn.execute("ROLLBACK")
           raise
       conn.execute("COMMIT")
       return deleted
   ```

3. In `src/gateclerk/agent_cli.py`, add `DEFAULT_LOCAL_RETENTION_DAYS = 14` and a
   `self._last_prune_at: datetime | None = None` field. In `SiteAgent.tick()`, after
   `self._push(moment, report)` and before `self._write_health()`:
   ```python
   if (
       self.ledger is not None
       and (self._last_prune_at is None
            or (moment - self._last_prune_at) >= timedelta(days=1))
   ):
       self._last_prune_at = moment
       cutoff = (moment - timedelta(days=DEFAULT_LOCAL_RETENTION_DAYS)).isoformat()
       prune_pushed_events(
           self.conn,
           event_ids=self.ledger.sent_event_ids(),
           before_utc=cutoff,
       )
   ```
   Import `prune_pushed_events` from `gateclerk.agent_store`.
4. Do not add a config key in this card. The 14-day constant is documented here and can
   become a config key later; an operator who needs a different window changes one
   constant and a test.

What must NOT change:

- The checkpoint, `push_queue`, `dead_letter`, `push-ledger.jsonl` format and the
  per-sink ledger keying.
- `store_events` and the in-window reset logic.
- The local store remains the diagnostic buffer; never prune an event that was not
  recorded as sent/gone.
- No PII is logged; the prune returns a count only.

## TESTS

Write `tests/test_gc_p16a_prune_events.py` first and run:

```bash
uv run --frozen pytest -q tests/test_gc_p16a_prune_events.py
```

Copy the store fixture from `tests/test_p2_02_store.py:436` and the ledger setup from
`tests/test_p2_07b_agent_cli.py:909`.

Tests:

- `test_old_pushed_event_is_deleted` — event 30 days old, ledger says `sent`; prune removes
  it and returns 1.
- `test_new_or_unpushed_event_is_kept` — a 30-day-old event not in the ledger and a
  one-day-old ledger event both survive.
- `test_queued_event_is_kept_even_when_old` — insert a `push_queue` row for the old event;
  prune leaves it (and the FK would also refuse).
- `test_dead_lettered_event_is_kept` — same for `dead_letter`.
- `test_prune_runs_at_most_once_per_day` — two ticks in one day call the prune once; the
  next day calls it again (monkeypatch `prune_pushed_events` and count calls).
- `test_prune_never_touches_the_checkpoint` — checkpoint row is identical before/after.

## GATE

```bash
uv run --frozen pytest -q
uv run --frozen ruff check src/gateclerk
```

## ACCEPT

- [ ] Pushed events older than 14 days are deleted.
- [ ] Unpushed, queued and dead-lettered events survive.
- [ ] The checkpoint is untouched.
- [ ] The prune runs at most once per day.
- [ ] No PII is printed; only a count is returned.
- [ ] Full pytest and ruff are green.

## OUT

`src/gateclerk/agent_db.py` schema, `push-ledger.jsonl` compaction (not in the plan; see
INDEX `NOT IN PLAN`), `src/gateclerk/users_import.py` (GC-P16b), and the bundle TTL
(GC-P16c).

## HANDOFF

Branch base `origin/main`; PR target `feat/gateclerk-finish`.

1. Run the GATE.
2. Open the PR against `feat/gateclerk-finish`.
3. When the gate is green and the PR is mergeable, run `gh pr merge <number> --squash`
   yourself.
4. Never merge into `main`/`master`; never force-push.
5. If the PR is not mergeable (conflict), rebase on `origin/feat/gateclerk-finish`, re-run
   the GATE, then merge. If that fails twice, stop and report `LEFT:`.

The card is complete only after the merge.

DONE: PR URL and merge commit.
LEFT: anything not merged, with the reason.
