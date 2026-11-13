# GC-P10 — One poller per site: non-blocking advisory lock

BOARD: gateclerk   DEPENDS ON: GC-P01   GATED: no   COVERS: GC-11 / —

## WHY

Nothing stops a second `gateclerk agent run` from polling the same device and SQLite store
as the first. Two pollers burn the terminal's ~190-use digest nonce budget and can trip a
401 lockout. One site, one process, one store is the deployment law (R7: no device writes
from the cluster; a lockout is worse than a refused start).

## VERIFY

```bash
grep -n "flock\|fcntl" src/gateclerk/agent_cli.py
```

Still broken while the command prints nothing (the module has no `flock`/`fcntl` code).

## FILES

- `src/gateclerk/agent_cli.py:700-724` — `SiteAgent.run()` starts ticking with no guard.
- `src/gateclerk/agent_cli.py:1150-1172` — `resolve_state_root(site, state_root)` is the
  one writable directory where the store, `park/` and `health/` live. The lock belongs
  there.
- `src/gateclerk/exceptions.py:73-79` — `ConfigError` maps to CLI exit 2 through
  `cli_shared._fail`.
- `deploy/gateclerk-agent@.service:122-130` — `ReadWritePaths=<STATE_ROOT>/<SITE>`, so the
  lock file is writable in production.

## CHANGE

1. In `src/gateclerk/agent_cli.py`, add `import fcntl` and a lock suffix constant:
   ```python
   POLLER_LOCK_SUFFIX = ".lock"
   ```

2. Add one exception and two helpers beside `resolve_state_root`:
   ```python
   class PollerAlreadyRunning(ConfigError):
       """Another process already owns this site's poll loop (one site, one poller)."""


   def acquire_poller_lock(state_root: Path | str, site: str) -> Any:
       """Hold an exclusive non-blocking flock for the life of the agent process."""
       path = Path(state_root) / f"gateclerk-{site}{POLLER_LOCK_SUFFIX}"
       path.parent.mkdir(parents=True, exist_ok=True)
       handle = path.open("a+", encoding="utf-8")
       try:
           fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
       except BlockingIOError as exc:
           handle.close()
           raise PollerAlreadyRunning(
               f"another agent already polls site {site!r} (lock {path}); "
               "stop it before starting a second poller"
           ) from exc
       handle.seek(0)
       handle.truncate()
       handle.write(f"{os.getpid()}\n")
       handle.flush()
       return handle


   def release_poller_lock(handle: Any) -> None:
       """Release the lock and close the file; safe to call twice."""
       if handle is None:
           return
       try:
           fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
       finally:
           handle.close()
   ```

3. In `SiteAgent.__init__`, add `self._poller_lock: Any = None`. In `run()`, acquire before
   the first tick and release in a `finally`:
   ```python
   if self._poller_lock is None:
       self._poller_lock = acquire_poller_lock(Path(self._db_path).parent, self.site.name)
   try:
       ... existing loop ...
   finally:
       release_poller_lock(self._poller_lock)
       self._poller_lock = None
   ```
   Keep the existing `except BaseException:` abort line inside the loop; the `finally` runs
   after it.

4. In `SiteAgent.close()`, release the lock if it is still held. This covers a caller that
   builds the agent and closes it without `run()`.

What must NOT change:

- `build_site_agent()` does not acquire the lock; tests that call `agent.tick()` directly
  keep working.
- `agent ack`, `agent deadletter` and `status` do not acquire the poller lock; they are
  read/repair commands.
- The lock is per site, not per device; the schema has one device per site today.
- Exit code for a held lock is 2 through `ConfigError`.

## TESTS

Write `tests/test_gc_p10_poller_lock.py` first and run:

```bash
uv run --frozen pytest -q tests/test_gc_p10_poller_lock.py
```

Copy `AgentHarness` from `tests/test_p2_07b_agent_cli.py:195`.

Tests:

- `test_second_lock_on_the_same_state_root_is_refused` — `acquire_poller_lock(tmp_path,
  "site-a")` twice; the second raises `PollerAlreadyRunning` with the lock path.
- `test_releasing_the_first_lock_allows_the_second` — release, then acquire again.
- `test_two_sites_get_independent_locks` — `site-a` and `site-b` in the same root both
  acquire.
- `test_agent_run_refuses_when_the_lock_is_held` — hold the lock, build a `SiteAgent`, call
  `run(once=True)`; assert `PollerAlreadyRunning` and that no device request was served.
- `test_lock_file_contains_the_owner_pid` — after acquire, the file contains `os.getpid()`.

## GATE

```bash
uv run --frozen pytest -q
uv run --frozen ruff check src/gateclerk
```

## ACCEPT

- [ ] A second poller on the same site fails fast with exit class 2.
- [ ] The refusal happens before any device request.
- [ ] Releasing the lock lets the next process start.
- [ ] Two different sites can each hold their own lock.
- [ ] The lock file contains the owner PID and lives under the state root.
- [ ] Full pytest and ruff are green.

## OUT

`agent ack` / `agent deadletter` / `status` (read-only commands), `build_site_agent`, the
systemd unit and compose files, and the device loop.

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
