# GC-P07 — Sink token resolved lazily through the credential provider

BOARD: gateclerk   DEPENDS ON: —   GATED: no   COVERS: GC-06 / —

## WHY

`build_https_sink_transport()` calls `_sink_token()` eagerly. When a sink declares
`token_keychain`, that helper calls `KeychainReader().read(...)` at agent startup, before
anything is queued. On headless Linux there is no `security` binary, so the agent crashes
even when the token is sitting in `~/.config/gateclerk/credentials.json` or the environment.
R2: the Linux production agent must resolve its ingest bearer without a keychain.

## VERIFY

```bash
grep -n "_sink_token\|KeychainReader()" src/gateclerk/sink_writers.py
```

Still broken while `_sink_token` contains the eager read:

```text
588:def _sink_token(
613:        reader = keychain if keychain is not None else KeychainReader()
614:        item = reader.read(
```

If the builder no longer calls `_sink_token`, stop and close the card.

## FILES

- `src/gateclerk/sink_writers.py:504-535` — `build_https_sink_transport` passes
  `token=_sink_token(...)` into `https_transport`. This is the eager call.
- `src/gateclerk/sink_writers.py:588-619` — `_sink_token`:
  ```python
  if spec.token_keychain:
      reader = keychain if keychain is not None else KeychainReader()
      item = reader.read(
          DeviceTarget(host=site, site=site, keychain_service=spec.token_keychain),
          with_comment=False,
      )
      return item.password
  ```
- `src/gateclerk/agent_push.py:1106-1125` — `HttpsIngestTransport.__init__` stores
  `self._env`, `self._keychain`, `self._explicit` and `self._token = None`.
- `src/gateclerk/agent_push.py:1213-1259` — `_resolve_token` is already lazy and calls
  `resolve_ingest_token(..., env_var=ingest_token_env_var(self.site),
  keychain_service=ingest_keychain_service(self.site))`.
- `src/gateclerk/agent_push.py:1292-1319` — `https_transport(...)` factory.
- `src/gateclerk/credentials.py:760-816` — `resolve_ingest_token` walks flag > env >
  keychain > 0600 credential file (and `$CREDENTIALS_DIRECTORY` through the store).

## CHANGE

1. Extend `HttpsIngestTransport.__init__` with two overrides, defaulting to the site's own
   refs:
   ```python
   token_env: str | None = (None,)
   token_keychain: str | None = (None,)
   ```
   Store `self._token_env = token_env` and `self._token_keychain = token_keychain` beside
   `self._env`/`self._keychain`.
2. In `_resolve_token`, pass the overrides:
   ```python
   env_var = (self._token_env or ingest_token_env_var(self.site),)
   keychain_service = (self._token_keychain or ingest_keychain_service(self.site),)
   ```
   Keep the lazy cache and the `IngestTokenUnavailableError` wrapping.
3. Extend `https_transport(...)` with the same two keyword arguments and pass them to the
   constructor.
4. In `build_https_sink_transport`, stop resolving the token. Pass the refs through:
   ```python
   base = https_transport(
       site,
       token=None,
       env=env,
       keychain=keychain,
       client=client,
       token_env=spec.token_env,
       token_keychain=spec.token_keychain,
   )
   ```
5. Delete `_sink_token` and any now-unused imports (`DeviceTarget`, `KeychainReader`,
   `Secret` if nothing else uses them). Keep the `_HeaderAppendingTransport` wrapper.

What must NOT change:

- The precedence: explicit flag > env (`spec.token_env` or
  `GATECLERK_INGEST_TOKEN_<SITE>`) > keychain (`spec.token_keychain` or
  `gateclerk-ingest-<site>`) > `~/.config/gateclerk/credentials.json` /
  `$CREDENTIALS_DIRECTORY`.
- The site's own rungs for the implicit `legacy` sink (no new keychain item at upgrade).
- No secret value in a log, exception or config.

## TESTS

Write `tests/test_gc_p07_lazy_sink_token.py` first and run:

```bash
uv run --frozen pytest -q tests/test_gc_p07_lazy_sink_token.py
```

Copy the sink wiring from `tests/test_sinks_wiring.py:1139` and the credential-file ladder
from `tests/test_credentials_file_backend.py` (`test_credentials_file_backend.py` has the
0600 store helpers).

Tests:

- `test_building_a_sink_transport_does_not_read_the_keychain` — monkeypatch
  `KeychainReader.read` to raise; `build_https_sink_transport` with
  `SinkSpec(token_keychain="gateclerk-ingest-demo-a")` returns without raising.
- `test_first_send_resolves_the_sink_token_from_the_credential_file` — no keychain, a 0600
  `credentials.json` with `gateclerk-ingest-demo-a`; call the transport against a fake
  client; assert the `Authorization` header is present and the token came from the file.
- `test_sink_env_ref_wins_over_the_site_env` — `spec.token_env` holds a different variable
  name; assert it is used.
- `test_missing_token_is_reported_on_first_send_not_at_build` — build succeeds;
  `token_available()` is `False`; the first send raises `IngestTokenUnavailableError`.

## GATE

```bash
uv run --frozen pytest -q
uv run --frozen ruff check src/gateclerk
```

## ACCEPT

- [ ] No keychain read happens at `build_https_sink_transport` time.
- [ ] A Linux `credentials.json` token resolves on the first send.
- [ ] Sink `token_env` / `token_keychain` still override the site defaults.
- [ ] Missing token fails on first send with the install-step class, rows stay queued.
- [ ] Full pytest and ruff are green.

## OUT

`src/gateclerk/credentials.py`, `src/gateclerk/config.py`, `src/gateclerk/agent_cli.py`,
the doctor sink check (GC-P06), and the token refresh/dead-letter policy (GC-P08).

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
