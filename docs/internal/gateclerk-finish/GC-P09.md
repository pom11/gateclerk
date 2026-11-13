# GC-P09 — Correct the stale env-var comment in `agent_push.py`

BOARD: gateclerk   DEPENDS ON: GC-P08   GATED: no   COVERS: GC-08 / —

## WHY

The comment above the agent's env prefix claims it mirrors the Cloud Run function's
variable name. It does not: the function's constant is `_GATECLERK_INGEST_SECRET_PREFIX`
(`GATECLERK_INGEST_TOKEN_<SITE>`), while the agent uses `GATECLERK_INGEST_TOKEN_<SITE>`.
The mismatch is NOT a defect: the two processes are configured separately and have
separate secret stores. Only the comment is wrong, and a wrong comment sends the
next operator to the wrong place. This is a comment-only card.

## VERIFY

```bash
sed -n '1001,1006p' src/gateclerk/agent_push.py
grep -n "_GATECLERK_INGEST_SECRET_PREFIX\|GATECLERK_SITES" ~/dev/example/functions/main.py | head
```

Still broken while the comment says the names mirror each other:

```text
1001: #: The env rung mirrors the function's OWN variable name (`_GATECLERK_INGEST_SECRET_PREFIX`
1002: #: in functions/main.py): one name per site works in the agent's environment and in the
1003: #: Cloud Run runtime, so an operator sets exactly one thing per site either way.
```

and the function actually uses:

```text
7796:_GATECLERK_INGEST_SECRET_PREFIX = "GATECLERK_INGEST_TOKEN_"
7847:    env_list = os.environ.get("GATECLERK_SITES", "")
```

If the comment already states that the two names are independent, stop and close the card.

## FILES

- `src/gateclerk/agent_push.py:1001-1006` — the stale comment.
- `src/gateclerk/agent_push.py:1035-1040` — `ingest_token_env_var` returns
  `GATECLERK_INGEST_TOKEN_<SITE>`; this is the agent's contract and does not change.
- `~/dev/example/functions/main.py:7796,7847` — the receiver's own names, read-only
  reference. Do not edit that repo in this card.

## CHANGE

1. Replace only the comment block at `agent_push.py:1001-1006` with:
   ```python
   #: The env rung is the AGENT's own contract: `GATECLERK_INGEST_TOKEN_<SITE>`.
   #: The Cloud Run receiver reads its own Secret Manager/env names
   #: (`_GATECLERK_INGEST_SECRET_PREFIX` / `GATECLERK_SITES` in functions/main.py).
   #: The two processes are configured separately; neither name has to match.
   ```
2. Do not change `INGEST_TOKEN_ENV_PREFIX`, `ingest_token_env_var`, the keychain service
   name, the resolver, or any test. The agent and receiver are intentionally decoupled.

What must NOT change:

- `INGEST_TOKEN_ENV_PREFIX = "GATECLERK_INGEST_TOKEN_"` and the keychain prefix.
- Any runtime behaviour, test, or config key.
- `functions/main.py` in the example repo.

## TESTS

None. This is a comment-only card; no product test and no new test file. The full suite is
the regression check, and the `VERIFY` grep proves the comment changed.

## GATE

```bash
uv run --frozen pytest -q
uv run --frozen ruff check src/gateclerk
```

## ACCEPT

- [ ] The comment names `_GATECLERK_INGEST_SECRET_PREFIX` / `GATECLERK_SITES` and says the
  names are independent.
- [ ] No `GATECLERK_INGEST_SECRET_PREFIX` remains in the comment.
- [ ] Runtime constants and tests are unchanged (comment-only diff).
- [ ] Full pytest and ruff are green (the diff is comment-only).

## OUT

`src/gateclerk/credentials.py`, `src/gateclerk/config.py`, `src/gateclerk/agent_cli.py`,
the example `functions/main.py`, and every runtime env-var name.

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
