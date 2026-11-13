# GC-P01 — Queue only granted punch candidates with a known code

BOARD: gateclerk   DEPENDS ON: —   GATED: no   COVERS: GC-01 / E22

## WHY

The site agent stores every access-control event, including denied, informational and
unknown-code events. `queue_new_events` then queues every stored row, so a failed card,
face or fingerprint attempt with an employee number becomes a real attendance punch in BC
Table 70607. This card filters the push queue only. BC stays the only store and the only
calculator (R1, R2); E22 requires that a denied or unknown scan creates no punch.

## VERIFY

```bash
uv run --frozen python - <<'PY'
import inspect
from gateclerk import agent_cli
src = inspect.getsource(agent_cli.queue_new_events)
print("outcome filter:", "outcome" in src)
print("unknown_code filter:", "unknown_code" in src)
PY
```

Still broken while the output is:

```text
outcome filter: False
unknown_code filter: False
```

If either line becomes `True`, stop: the finding no longer holds. Comment on the card with
the command output and close it.

## FILES

- `src/gateclerk/agent_cli.py:369-386` — the candidate query. It selects from `events` and
  filters only on the three exclusions (`push_queue`, `dead_letter`, ledger). There is no
  `outcome`, `unknown_code`, `major`, `employee_no` or `verify_mode` predicate:
  ```python
  SELECT e.id AS id
    FROM events AS e
   WHERE NOT EXISTS (... push_queue ...)
     AND NOT EXISTS (... dead_letter ...)
     AND NOT EXISTS (... temp.agent_push_ledger ...)
   ORDER BY e.id
   LIMIT ?
  ```
- `src/gateclerk/agent_db.py:119-120` — the flattened columns the queue can read:
  `outcome TEXT`, `unknown_code INTEGER`. The same table also stores `employee_no`,
  `verify_mode`, `major` and `minor` (`agent_db.py:99-123`).
- `src/gateclerk/event_codes.py:508-567` — `classify_event(record, *, capabilities=None)`
  returns `EventClassification` with `outcome`, `unknown_code`, `punch_candidate` and
  `reason`.
- `src/gateclerk/event_codes.py:584-625` — `_punch_decision(...)` is the single rule:
  major 5, known code, `granted`, an authentication pass minor, `employeeNoString`, and a
  real `currentVerifyMode`. `NON_AUTH_VERIFY_MODES` is defined at
  `src/gateclerk/event_codes.py:384`.
- `src/gateclerk/model.py:475-487` — `EventRecord.is_punch_candidate` states the stored
  subset: major 5, granted, employee present, not `unknown_code`.
- `src/gateclerk/agent_loop.py:937-959` — `_assemble` stores every classified record. Do
  not add a filter here: non-punch rows must stay in the local `events` table for
  diagnostics (GC-P20 reads them).

## CHANGE

1. In `src/gateclerk/agent_cli.py`, import the classifier vocabulary near the existing
   `agent_store` import:
   ```python
   from gateclerk.event_codes import NON_AUTH_VERIFY_MODES
   ```

2. Add one module-level SQL fragment beside `queue_new_events`, built from the same
   constant the classifier uses. Do not type the mode list twice:
   ```python
   _VERIFY_MODE_PLACEHOLDERS = ", ".join("?" for _ in sorted(NON_AUTH_VERIFY_MODES))
   _PUNCH_CANDIDATE_SQL = (
       "e.major = 5"
       " AND e.outcome = 'granted'"
       " AND e.unknown_code = 0"
       " AND e.employee_no IS NOT NULL AND e.employee_no <> ''"
       " AND e.verify_mode IS NOT NULL"
       f" AND lower(trim(e.verify_mode)) NOT IN ({_VERIFY_MODE_PLACEHOLDERS})"
   )
   ```

3. Make the existing query an f-string and add the fragment after the three `NOT EXISTS`
   clauses and before `ORDER BY e.id`:
   ```python
   rows = conn.execute(
       f"""
       SELECT e.id AS id
         FROM events AS e
        WHERE NOT EXISTS (...)
          AND NOT EXISTS (...)
          AND NOT EXISTS (...)
          AND {_PUNCH_CANDIDATE_SQL}
        ORDER BY e.id
        LIMIT ?
       """,
       (..., *sorted(NON_AUTH_VERIFY_MODES), max(1, int(limit))),
   ).fetchall()
   ```
   Keep the rest of the query text static; only the constant fragment is interpolated.
   Add the verify-mode parameters after the six existing exclusion parameters and before
   `max(1, int(limit))`:
   ```python
   (*sorted(NON_AUTH_VERIFY_MODES),)
   (max(1, int(limit)),)
   ```
   The final parameter tuple is: endpoint, sink, legacy, endpoint, sink, legacy, verify
   modes..., limit.

4. Update the `queue_new_events` docstring: it queues only granted punch candidates; a
   denied/info/unknown event stays in `events` and is never queued for any sink. The
   `push_queue`, `dead_letter` and ledger exclusions stay exactly as they are.

What must NOT change:

- `agent_store.store_events`, `DeviceLoop._assemble`, `event_codes.classify_event` and the
  27-key `EventRecord` contract. The local store keeps every event.
- `push_queue`/`dead_letter` schemas, the ledger table and the legacy-sink wildcard.
- The payload bytes: the queue still copies `events.jsonl` verbatim.

## TESTS

Write `tests/test_gc_p01_grant_filter.py` first and run:

```bash
uv run --frozen pytest -q tests/test_gc_p01_grant_filter.py
```

Copy the SQLite setup from `tests/test_cli_doctor.py:71` (`_seed_store`) and the event
construction from `tests/test_p2_07b_agent_cli.py:195` (`AgentHarness`). Use
`agent_db.connect`, `agent_store.store_events`, `agent_cli.queue_new_events`.

Tests:

- `test_queue_skips_denied_info_unknown_and_unattributed_events` — store six records:
  `(5, 75, granted, employee "1", verify "cardOrFaceOrFp")`; `(5, 8, denied, "1")`;
  `(5, 21, info, "1")`; `(5, 999, info + unknown_code, "1")`;
  `(5, 75, granted, employee None)`; `(5, 75, granted, verify "invalid")`. Call
  `queue_new_events(conn, endpoint=f"stub://{tmp_path}/gc-p01.jsonl", now=T0)` and assert only the
  first event id is returned and `SELECT COUNT(*) FROM push_queue` is 1.
- `test_queue_keeps_granted_punch_candidates` — two valid punches at different serials
  both queue, in `ORDER BY e.id` order.
- `test_filter_matches_classify_event_on_recorded_fixtures` — for every event record in
  `tests/fixtures/recorded/site-a-ds-k1t341amf-s/events_major5_page1.json`, compare
  `classify_event(record).punch_candidate` with membership in the queue result; the sets
  must be identical. This pins the SQL fragment to the classifier, including
  `NON_AUTH_VERIFY_MODES`.

## GATE

```bash
uv run --frozen pytest -q
uv run --frozen ruff check src/gateclerk
```

## ACCEPT

- [ ] `queue_new_events` SQL contains the granted/known-code/employee/verify-mode predicate.
- [ ] The verify-mode list comes from `NON_AUTH_VERIFY_MODES`, not a second literal.
- [ ] Denied, info, unknown-code, unattributed and non-auth-mode events remain in `events`.
- [ ] Only granted punch candidates enter `push_queue`.
- [ ] The recorded-fixture equivalence test passes.
- [ ] Full pytest and ruff are green.

## OUT

`src/gateclerk/agent_store.py`, `src/gateclerk/agent_loop.py`, `src/gateclerk/event_codes.py`,
`src/gateclerk/model.py`, `src/gateclerk/agent_push.py`, the `functions/main.py` ingest guard
(APP-P19, other repo), and all existing push/dead-letter tests.

## HANDOFF

Branch base `origin/main`; PR target `INTEGRATION_BRANCH` (`INDEX.md` § Conventions; the literal name is in your card).

1. Run the GATE.
2. Open the PR against `INTEGRATION_BRANCH`.
3. When the gate is green and the PR is mergeable, run `gh pr merge <number> --squash`
   yourself.
4. Never merge into `main`/`master`; never force-push.
5. If the PR is not mergeable (conflict), rebase on `origin/INTEGRATION_BRANCH`, re-run
   the GATE, then merge. If that fails twice, stop and report `LEFT:`.

The card is complete only after the merge.

DONE: PR URL and merge commit.
LEFT: anything not merged, with the reason.
