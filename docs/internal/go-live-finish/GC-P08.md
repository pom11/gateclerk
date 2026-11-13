# GC-P08 — Token refresh on 401/403; permanent 4xx not retried for 24 h

BOARD: gateclerk   DEPENDS ON: GC-P07   GATED: no   COVERS: GC-07 / —

## WHY

`HttpsIngestTransport` caches the bearer for the life of the process. Rotating the ingest
token on the site host leaves every push failing with 401/403 until a restart. Separately,
a permanently rejected payload (400/422) is retried for 24 hours. R2/R7: the agent must
recover without a restart and must not hammer an endpoint with a request it can never
accept.

## VERIFY

```bash
grep -n "_token = None\|PERMANENT\|HttpStatusRejectedError" src/gateclerk/agent_push.py
```

Still broken while the only `_token = None` is the constructor (`agent_push.py:1125`) and
`drain` has no permanent-status branch:

```text
1125:        self._token: Secret | None = None
591:class HttpStatusRejectedError(Exception):
523:        outcome = _send_row(...)
540:        if elapsed >= dead_letter_after_s:
```

If a 401/403 branch clears `_token` or a permanent-status branch exists, stop.

## FILES

- `src/gateclerk/agent_push.py:1152-1173` — `__call__` sends with the cached token and
  returns the status without touching `self._token`.
- `src/gateclerk/agent_push.py:522-569` — `drain` decides dead-letter only from elapsed
  time:
  ```python
  first_failed_at = row["first_failed_at"] or stamp
  elapsed = (now - _parse(first_failed_at)).total_seconds()
  if elapsed >= dead_letter_after_s:
      _move_to_dead_letter(...)
  else:
      delay_s = _backoff_delay_s(...)
      _note_failure(...)
  ```
- `src/gateclerk/agent_push.py:591-601` — `HttpStatusRejectedError` carries `.status`.
- `src/gateclerk/agent_push.py:604-666` — `_send_row`/`_call_transport` wrap a non-2xx
  status in `HttpStatusRejectedError`.

## CHANGE

1. Add a module constant near `HttpStatusRejectedError`:
   ```python
   #: Statuses that say the payload itself will never be accepted. Retrying them for
   #: 24 h only burns the site's request budget; the owner must fix or discard the row.
   #: 401/403 are deliberately NOT here: those are token/config problems that a re-read
   #: can fix (see the token refresh below).
   PERMANENT_REJECT_STATUSES: frozenset[int] = frozenset({400, 422})
   ```

2. In `HttpsIngestTransport.__call__`, after `response = self._client.post(...)` and before
   returning:
   ```python
   status = int(response.status_code)
   if status in (401, 403):
       # The next attempt re-reads the credential ladder (rotated token, wrong site,
       # credential file just installed). Do not dead-letter: this is an install step.
       self._token = None
   return status
   ```

3. In `drain`, replace the `if elapsed >= dead_letter_after_s:` condition with:
   ```python
   permanent = (
       isinstance(outcome, HttpStatusRejectedError)
       and outcome.status in PERMANENT_REJECT_STATUSES
   )
   if elapsed >= dead_letter_after_s or permanent:
   ```
   Keep the same `_move_to_dead_letter(...)` arguments and the same `else` branch. Add one
   sentence to the docstring: permanent payload rejections dead-letter on the first
   failure; transient 5xx/network failures keep the 24 h bound; 401/403 keep retrying so a
   token rotation can heal them.

4. Do not batch rows in this card. One POST per queue row stays exactly as it is; the
   finding's batching half is not in the plan (see INDEX `NOT IN PLAN`).

What must NOT change:

- The 15 s–15 min equal-jitter ladder, the 24 h bound for transient failures, and the
  `push drain:` log line shape.
- The `HttpStatus<code>` error class text and the dead-letter row fields.
- The 401/403 retry path: clearing the token is enough; do not immediately retry the same
  row in the same drain pass.

## TESTS

Write `tests/test_gc_p08_token_refresh.py` first and run:

```bash
uv run --frozen pytest -q tests/test_gc_p08_token_refresh.py
```

Copy the fake HTTP client from `tests/test_t15_push_https.py:648` and the drain/backoff
fixture from `tests/test_p2_04_pusher.py:520`.

Tests:

- `test_401_clears_the_cached_bearer_and_the_next_send_re_resolves` — fake client returns
  401 then 200; a token provider returns `"old"` then `"new"`; assert the second request's
  `Authorization` is `Bearer new`.
- `test_403_clears_the_cached_bearer` — same shape with 403.
- `test_400_dead_letters_on_the_first_failure` — one queue row, fake transport returns
  400; `drain` moves it to `dead_letter` with `attempts == 1` and no backoff row remains.
- `test_422_dead_letters_on_the_first_failure` — same with 422.
- `test_503_still_retries_with_backoff` — 503 stays in `push_queue`, `attempts == 1`,
  `next_attempt_at > now`.
- `test_a_401_does_not_dead_letter_and_does_not_burn_the_24h_clock` — 401 leaves the row
  queued; `first_failed_at` may be set, but the next attempt is retried.

## GATE

```bash
uv run --frozen pytest -q
uv run --frozen ruff check src/gateclerk
```

## ACCEPT

- [ ] A 401 clears the cached bearer; the next send uses the re-read token.
- [ ] A 403 does the same.
- [ ] 400 and 422 dead-letter on the first failure.
- [ ] 5xx and network failures keep the existing backoff and 24 h bound.
- [ ] The `push drain:` line and error-class text are unchanged.
- [ ] Full pytest and ruff are green.

## OUT

`functions/main.py` (the receiver's own status policy), `src/gateclerk/agent_cli.py` (no
batching change), the queue schema, and the existing retry/dead-letter tests.

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
