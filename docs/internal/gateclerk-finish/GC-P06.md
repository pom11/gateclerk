# GC-P06 — Doctor checks the `token-ref` name the sink checker emits

BOARD: gateclerk   DEPENDS ON: —   GATED: no   COVERS: GC-05 / —

## WHY

`sink_cli` emits `SinkCheck(check="token-ref")`. `doctor_cli` looks for `"token-refs"`
(plural), so its Linux credential-file fallback and its config-error classification are
dead. A token stored in `~/.config/gateclerk/credentials.json` fails the doctor with exit 6,
and a genuinely missing token also exits 6 instead of 2 (R2: every write path must be
usable on Linux without a keychain).

## VERIFY

```bash
grep -n '"token-refs"\|"token-ref"' src/gateclerk/doctor_cli.py src/gateclerk/sink_cli.py
```

Still broken while the output shows `token-refs` only in `doctor_cli` and `token-ref` only
in `sink_cli`:

```text
src/gateclerk/doctor_cli.py:430:            if not chk.ok and chk.check == "token-refs":
src/gateclerk/doctor_cli.py:439:                if chk.check in ("config", "token-refs", "directory", "path-collision"):
src/gateclerk/sink_cli.py:1004:                    check="token-ref",
src/gateclerk/sink_cli.py:1022:                    check="token-ref",
src/gateclerk/sink_cli.py:1028:        check="token-ref",
```

If `doctor_cli` already says `token-ref`, stop and close the card.

## FILES

- `src/gateclerk/doctor_cli.py:426-442` — the two dead branches. The first comment even
  says `token-ref` while the code says `token-refs`.
- `src/gateclerk/sink_cli.py:998-1032` — `SinkCheck(check="token-ref", ...)` at the env,
  keychain and failure returns.
- `src/gateclerk/doctor_cli.py:444-470` — the `CONFIG_ERROR_EXIT` vs `PUSH_FAILURE_EXIT`
  mapping that depends on this name.

## CHANGE

1. In `src/gateclerk/doctor_cli.py`, replace both string literals:
   - line 430: `chk.check == "token-ref"`
   - line 439: `chk.check in ("config", "token-ref", "directory", "path-collision")`
2. Update the comment above line 430 to say `token-ref` (singular) and keep its meaning:
   the credential-file fallback is checked before the sink is marked failed.
3. Do not change `sink_cli` or the exit-code values. `CONFIG_ERROR_EXIT` stays 2 and
   `PUSH_FAILURE_EXIT` stays 6; only which bucket a missing token lands in changes.

What must NOT change:

- The keychain/env resolution order in `sink_cli.check_sink`.
- The `_check_cred_file_ref` helper and the `credentials.json` read rules.
- Any other doctor section or its exit code.

## TESTS

Write `tests/test_gc_p06_doctor_token_ref.py` first and run:

```bash
uv run --frozen pytest -q tests/test_gc_p06_doctor_token_ref.py
```

Copy the doctor config/store fixture from `tests/test_cli_doctor.py:42-125` and the
credential-file setup from `tests/test_cli_doctor.py:235-265`.

Tests:

- `test_doctor_token_ref_falls_back_to_credentials_file` — a site with an `https` sink
  carrying `token_keychain = "gateclerk-ingest-demo-a"`, a valid 0600
  `credentials.json` with that ref, keychain probe returns `False`; `run_doctor` exits 0
  and the sinks row passes.
- `test_doctor_missing_token_ref_is_exit_2_not_6` — no env, no keychain, no credential
  file; exit code is `CONFIG_ERROR_EXIT` (2), not 6.
- `test_doctor_and_sink_cli_use_the_same_check_name` — inspect the source of both modules;
  no `token-refs` literal remains.
- `test_doctor_still_exits_6_for_a_sink_push_failure` — a 5xx/delivery failure still maps
  to 6, so the fix did not flatten the exit matrix.

## GATE

```bash
uv run --frozen pytest -q
uv run --frozen ruff check src/gateclerk
```

## ACCEPT

- [ ] No `"token-refs"` literal remains in `doctor_cli.py`.
- [ ] A token in `credentials.json` passes the doctor with exit 0.
- [ ] A genuinely missing token exits 2, not 6.
- [ ] A push failure still exits 6.
- [ ] Full pytest and ruff are green.

## OUT

`src/gateclerk/sink_cli.py` (its `token-ref` name is correct), `src/gateclerk/credentials.py`,
`src/gateclerk/config.py`, and every other doctor section.

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
