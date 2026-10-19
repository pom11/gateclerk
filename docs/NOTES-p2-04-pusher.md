# P2-04 pusher + dead-letter — implementation notes (working notes; trimmed into the PR body)

Binding spec: `docs/P2-SITE-AGENT.md` §2b (dead-letter), §2c (pusher backoff + bound),
§3 (abstract target) — SIGNED OFF 2026-10-19. Files: `src/gateclerk/agent_push.py` (new),
two additive migration entries in `src/gateclerk/agent_db.py` (v3/v4),
`tests/test_p2_04_pusher.py` (new, 56 tests).

## Environment facts verified this run

- Base gate on this branch (`origin/main` dcc2214 with `origin/wt/p2-02-store` merged):
  `PYTHONPATH=<worktree>/src uv run --frozen pytest -q --ignore=tests/test_p2_04_pusher.py`
  = **1255 passed, 5 skipped, 1 deselected**. My head: **1311 passed / 5 skipped /
  1 deselected** — exactly +56, and all 56 are in the new test file (verified by
  `--co`: 56 collected; no existing test gained or lost a parametrization).
- Run with `PYTHONPATH=<worktree>/src` (t_7b073d11: the main checkout installs gateclerk
  editable, so a bare pytest inside a worktree imports MAIN's `src` and prints a false
  green; `tests/_source_guard.py` aborts on that, which is why the prefix is required).
- Coverage gate run: `agent_push.py` **100%** (218 stmts, 0 miss), `agent_db.py` 100%.

## Probe results the semantics are built on

Dead-letter UPSERT (`UNIQUE(event_id, endpoint)`):

- re-failing a replay **refreshes** the row: same `id`, `first_attempt_at` unchanged,
  `attempts`/`last_attempt_at` move. So `dead_letter_depth` counts *pushes*, not attempts
  — which is what makes it an honest gauge for §2e's `dead_letter_depth`.
- a success for the same key DELETEs the dead-letter row in the same transaction as the
  queue DELETE: there is no state where a punch is both delivered and dead-lettered.

FK direction matters more than it looks. `push_queue.event_id` is
`REFERENCES events(id) ON DELETE RESTRICT`, deliberately *not* CASCADE: a purge that
outran the queue would delete an un-pushed punch with no dead-letter row to account for
it — silent payroll loss. The db refuses it, so the caller cannot get this wrong by
accident (`test_the_queue_cannot_reference_an_event_the_store_does_not_have`,
`test_a_queued_event_cannot_be_deleted_underneath_the_queue`). `dead_letter.event_id` has
NO fk on purpose: the row must outlive the event (§2b: deleted only by the owner's
command) and it carries its own payload, so it needs no parent to be readable.

Timestamps are `timespec="seconds"` (agent_store's shape). That single choice is why the
backoff needs a floor: a delay under 1 s rounds INTO the current second, leaving
`next_attempt_at <= now` on the next drain — an immediate re-hit of an endpoint that just
failed. Pinned with a deliberately tiny `base_s` so the rounding is visible
(`test_a_failure_never_schedules_a_retry_in_the_same_second`).

## Decisions taken here

1. **v3/v4 DDL lives in `agent_db.MIGRATIONS`** (the card's wording), not in an
   import-time append from `agent_push`. An append would mean `agent_db.connect()` alone
   does not create the tables — every existing consumer of `connect()` would meet a
   schema that its own module does not build, and `agent_db` would stop being the single
   place the schema is defined.
2. **Jitter = "equal jitter" (half fixed + half drawn), cap applied before the draw, and
   a 1 s floor.** Half-fixed because `rng() == 0` would otherwise schedule a retry at this
   exact instant and re-hit the endpoint inside the same tick (§1 seam 9). The cap is
   applied to the window *before* the draw, and the draw itself is clamped to [0, 1] —
   the rng is injected, so it must not be able to escape the numbers §2c pins; an
   oversized draw on *every* failure would also push each retry past the 24 h bound and
   silently disable dead-lettering, which is the worst failure an rng could cause.
   `random.random` (what the agent passes) is unaffected by the clamp.
3. **The dead-letter bound is the caller's** (`dead_letter_after_s`, defaulting to
   config's `DEFAULT_PUSH_DEAD_LETTER_AFTER_S`) and is measured from the FIRST failure,
   with `first_failed_at` preserved across re-enqueue *and* replay. Consequence pinned by
   `test_dead_lettering_the_same_key_twice_is_one_row`: replaying into an endpoint that is
   still down dead-letters again promptly rather than buying a fresh 24 h — an owner
   hitting replay repeatedly must not keep a poison payload alive in the hot queue.
4. **A dead-letter row is deleted only by a push of that same key succeeding, or by
   `delete_dead_letter`.** No TTL, no drain-side cleanup (§2b). `replay_dead_letter`
   deliberately leaves the row until acceptance: a replay that has not been accepted is
   not evidence the owner may discard the only copy of the payload.
5. **`drain` never sleeps.** Due-ness is a query (`next_attempt_at <= now`), so an agent
   tick that finds nothing due returns immediately, a systemd kill cannot interrupt a
   sleep mid-tick, and the 5-min poll cadence is never overslept. Tests inject `now`.
6. **`HttpStatusRejectedError` folds the status into the class name** (`HttpStatus503`)
   because §2b asks for one error-class column: `503` (wait for them) and `400`
   (our payload) need different owner actions, and the bare class name cannot tell them
   apart.
7. **The log sink gets row ids and counts only.** The card's "never log payload bodies"
   rule is a leak rule, not cosmetics: a JSONL line carries `employee_no` and `name`.
   Pinned with a payload-field canary, and `pending_rows` deliberately has no payload
   field at all so P2-07's CLI *cannot* print one by accident (while `dead_letter_rows`
   must carry it — a replay reads it back).

## One real bug the tests caught

`drain` wrote the failure record and the reschedule in **two** transactions. A SIGTERM
between them left `attempts` bumped while `next_attempt_at` was still `<= now`, so every
agent restart would re-hit the endpoint that had just failed — §1 seam 9 ("never hammer")
broken by a crash rather than by intent, and free to repeat because the UPSERT costs
nothing. Fixed by deciding the outage clock before the write and merging both halves into
ONE statement. Because a split is behaviourally identical, no behavioural test can catch
its reintroduction: `test_a_failure_and_its_reschedule_are_one_sql_statement` counts the
UPDATEs sqlite emits for one failed row (traced with `set_trace_callback`).

## Two existing tests I had to touch (flagged, not silent)

`test_a_store_from_the_future_is_refused` and
`test_a_failing_migration_rolls_back_whole_entry` pinned the migration list's *next*
version as a literal `3` — the value this card ships for real. Both now derive it from
`len(agent_db.MIGRATIONS)`. Same assertions, no behaviour change; a literal here would
make P2-02's own extensibility test break on every append, which is the opposite of what
it pins. The `MIGRATIONS`-length pin in `test_the_queue_and_dead_letter_tables_ship_in_the_same_db`
asserts `== 4` explicitly so *this* card's contribution is pinned too.

## DoD case map (card §DoD, five numbered cases → tests)

| DoD | test(s) |
|---|---|
| 1 success drains | `test_a_successful_push_deletes_the_queue_row_and_keeps_the_event`, `test_only_due_rows_are_sent`, `test_an_empty_queue_drains_to_nothing` |
| 2 backoff 1,2,4…cap 30 with injected rng pinned | `test_failures_back_off_one_two_four_then_cap_at_thirty` (rng=0.0/0.5/1.0 sequence), `test_the_jitter_is_the_injected_rng_and_stays_inside_the_cap`, `test_the_rng_is_called_exactly_once_per_failed_row`, `test_backoff_numbers_are_the_busy_families` |
| 3 24h → dead-letter with full §2b fields, then replay | `test_continuous_failure_past_the_bound_moves_the_row_to_dead_letter` (asserts the full `to_jsonl` line + endpoint + error class + attempts + first/last), `test_replay_requeues_then_success_clears_both_tables` (stub got the line, gone from both tables) |
| 4 dead-letter survives restart, deleted only by the command | `test_dead_letter_rows_survive_a_reopen` (re-open same db path), `test_a_dead_letter_row_is_deleted_only_by_the_owner_command`, `test_the_owner_command_deletes_exactly_the_named_row` |
| 5 stub ingest parses as exact `model.EventRecord.from_jsonl` | `test_stub_ingest_file_parses_as_exact_model_records`, `test_a_real_drain_to_the_stub_leaves_a_replayable_file` |

## Mutation probes — 18/18 caught

Method (this session's standing discipline): copy the file to a backup and restore by
bytes (never `git checkout --`, never `git stash`), refresh the backup before each edit,
one mutation at a time, run the FULL suite UNFILTERED (no `-k` — a filtered "survived" is
an artifact) with `PYTHONDONTWRITEBYTECODE=1` and `-p no:cacheprovider` (a byte-neutral
edit can reuse a same-second `__pycache__` and read false-green), assert the restored
file is byte-identical.

M1–M6 and M16–M17 were re-run in a second pass: M1–M6 because the first batch's console
output was truncated at the head (I refuse to fill this table from memory), and M16/M17
because the first attempt at each was a bad probe — M16 injected a list that was empty at
log time, and M17's anchor had drifted after `ruff format` (`PROBE DID NOT APPLY`). Both
were re-crafted faithfully against the current text before being counted.

| # | mutant | caught by |
|---|---|---|
| M1 | dead-letter bound `>=` → `>` (exclusive) | `test_continuous_failure_past_the_bound_moves_the_row_to_dead_letter` |
| M2 | backoff 1 s floor removed | `test_a_failure_never_schedules_a_retry_in_the_same_second` |
| M3 | outage clock restarts (`COALESCE(first_failed_at, ?)` → `?`) | `test_failures_back_off_one_two_four_then_cap_at_thirty` |
| M4 | rng never reaches the delay | `test_the_jitter_is_the_injected_rng_and_stays_inside_the_cap` |
| M5 | rng draw clamp removed | `test_an_out_of_range_rng_draw_cannot_escape_the_cap` |
| M6 | success leaves the dead-letter row behind | `test_replay_requeues_then_success_clears_both_tables` |
| M7 | re-failed replay duplicates instead of refreshing | `test_dead_lettering_the_same_key_twice_is_one_row` |
| M8 | queue FK `RESTRICT` → `CASCADE` | `test_a_queued_event_cannot_be_deleted_underneath_the_queue` |
| M9 | §3 scheme gate removed | `test_enqueue_refuses_a_target_that_is_not_an_accepted_scheme` |
| M10 | due-by `<=` → `<` | `test_re_enqueue_refreshes_the_payload_but_keeps_the_retry_state` |
| M11 | `drain` ignores `endpoint` (cross-site push) | `test_re_enqueue_refreshes_the_payload_but_keeps_the_retry_state` |
| M12 | `attempts` not incremented (ladder frozen at 1 s) | `test_re_enqueue_refreshes_the_payload_but_keeps_the_retry_state` |
| M13 | backoff split into TWO statements | `test_a_failure_and_its_reschedule_are_one_sql_statement` |
| M14 | non-2xx treated as accepted | `test_re_enqueue_refreshes_the_payload_but_keeps_the_retry_state` |
| M15 | error class loses the status | `test_a_non_2xx_status_is_a_failure_not_a_send` |
| M16 | log line carries the payload bodies | `test_the_log_never_carries_a_payload_body` |
| M17 | replay starts a fresh 24 h clock | `test_dead_lettering_the_same_key_twice_is_one_row` |
| M18 | re-enqueue resets the retry state | `test_re_enqueue_refreshes_the_payload_but_keeps_the_retry_state` |

Note on M10–M12/M14 all landing in the same test: that test walks a row through
re-enqueue → due → fail → backoff, so it is the suite's densest behavioural seam. Each
mutant is also caught by at least one narrower test; the reported catcher is simply the
first FAILED line the unfiltered run prints.

## What P2-05 / P2-06 / P2-07 consume

- `drain(conn, endpoint=…, transport=…, now=…, rng=…, dead_letter_after_s=…)` →
  `DrainResult` with `.push_ok` / `.push_failed` / `.dead_lettered` (§2e names these).
- `queue_depth` / `dead_letter_depth` (gauges), `pending_rows` (no payloads),
  `dead_letter_rows` (with payloads).
- `replay_dead_letter` + `delete_dead_letter` are the functions P2-07's CLI subcommands
  wrap; `delete_dead_letter` returns a bool so a typo'd id cannot look like a success.
- `stub_transport("stub://<path>")` is the only ingest this repo ships; a real `https://`
  target needs a transport the owner wires (§3 — no endpoint is invented here). The
  `Transport` type is `(url, body) -> status`, raising is "not accepted".
- Nothing here imports `httpx` or opens a socket: the module is socket-free by
  construction, not by convention.
