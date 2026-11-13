# GC-P11 — Write `agent.pid` and `status/device-probe.json`

BOARD: gateclerk   DEPENDS ON: GC-P10, GC-P06   GATED: no   COVERS: GC-12 / —

## WHY

`gateclerk status` reads `<state-root>/agent.pid` and `<state-root>/status/device-probe.json`,
but no code writes either file. The agent line always says `pid=None`, and the device line
always says `warn: unknown — run: gateclerk doctor` even right after `doctor --probe`.
R2: the operator needs a read-only status screen that tells the truth.

## VERIFY

```bash
grep -rn "agent.pid\|device-probe.json" src/gateclerk --include='*.py'
```

Still broken while both names appear only in `status_cli.py` (readers) and in constants:

```text
src/gateclerk/status_cli.py:101:PIDFILE_NAME = "agent.pid"
src/gateclerk/status_cli.py:107:PROBE_CACHE_PARTS = ("status", "device-probe.json")
src/gateclerk/status_cli.py:432:    pidfile = state_dir / PIDFILE_NAME
src/gateclerk/status_cli.py:633:    cached = _read_json_object(state_dir.joinpath(*PROBE_CACHE_PARTS))
```

If a writer exists in `agent_cli.py` or `doctor_cli.py`, stop and close the card.

## FILES

- `src/gateclerk/status_cli.py:97-107` — `PIDFILE_NAME = "agent.pid"`,
  `PROBE_CACHE_PARTS = ("status", "device-probe.json")`,
  `DEVICE_PROBE_MAX_AGE_S = 60`.
- `src/gateclerk/status_cli.py:432-445` — reads the pidfile and checks `_pid_alive(pid)`.
- `src/gateclerk/status_cli.py:633-645` — reads `{"checked_at", "ok", "detail"}` and
  accepts it for 60 seconds.
- `src/gateclerk/doctor_cli.py:318-375` — `_check_device_section` returns a `DoctorRow`
  but has no `state_root` parameter and writes nothing.
- `src/gateclerk/doctor_cli.py:610-625` — `run_doctor` loops over sites and calls
  `_check_device_section(site_cfg, env=env, now=moment, device_prober=device_prober)`.
- `src/gateclerk/agent_cli.py:700-724` — `SiteAgent.run()` (GC-P10 added the lock here).
- `src/gateclerk/agent_cli.py:1043-1055` — `_write_health` is the atomic-write precedent
  to copy (`tmp` + `Path.replace`).

## CHANGE

1. In `SiteAgent.__init__`, add `self._pidfile: Path | None = None`. In `run()`, after
   acquiring the poller lock:
   ```python
   root = Path(self._db_path).parent
   self._pidfile = root / "agent.pid"
   self._pidfile.write_text(f"{os.getpid()}\n", encoding="utf-8")
   ```
   Put the write inside the same `try`/`finally` as the lock; in `close()` remove the file
   only when its content is our PID:
   ```python
   if self._pidfile is not None:
       with contextlib.suppress(OSError):
           if self._pidfile.read_text(encoding="utf-8").strip() == str(os.getpid()):
               self._pidfile.unlink()
   ```
   Import `contextlib` if needed. A stale pid is already handled by `status_cli` as a FAIL,
   so removal on clean shutdown is the important half.

2. In `src/gateclerk/doctor_cli.py`, add `state_root` to `_check_device_section`:
   ```python
   def _check_device_section(
       site: cfg.SiteConfig,
       *,
       env: Mapping[str, str] | None,
       now: datetime,
       device_prober: Callable[..., tuple[str, float | None]] | None,
       state_root: Path | str | None = None,
   ) -> DoctorRow:
   ```
   After the existing `DoctorRow` is decided (pass, warn or fail), write the cache and
   return the row. Use a small helper:
   ```python
   def _write_device_probe(site, state_root, now, *, ok, detail) -> None:
       from gateclerk import agent_cli
       root = agent_cli.resolve_state_root(site, state_root)
       target = root.joinpath("status", "device-probe.json")
       target.parent.mkdir(parents=True, exist_ok=True)
       payload = {"checked_at": now.isoformat(), "ok": ok, "detail": detail[:160]}
       tmp = target.with_name(target.name + ".tmp")
       tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
       tmp.replace(target)
   ```
   Call it on every outcome of `_check_device_section`: `ok=True` for pass/warn, `ok=False`
   with the failure detail for the three exception branches. The `detail` is the same
   redacted text the row carries; never a payload or a secret.

3. In `run_doctor`, pass `state_root=state_root` to `_check_device_section`.

4. Do not change `status_cli`'s 60-second TTL or its verdict mapping.

What must NOT change:

- `status` stays zero-network and read-only.
- The doctor's exit codes and redaction rules.
- The health snapshot writer and `park/` files.
- The pidfile is per site; no global PID file.

## TESTS

Write `tests/test_gc_p11_status_writers.py` first and run:

```bash
uv run --frozen pytest -q tests/test_gc_p11_status_writers.py
```

Copy the doctor fixture from `tests/test_cli_doctor.py:42-125` and the status reader tests
from `tests/test_cli_status.py` (the tests that seed `agent.pid` and
`status/device-probe.json`; reuse their `collect_site_status` calls).

Tests:

- `test_doctor_writes_a_fresh_device_probe` — `run_doctor` with a fake device prober that
  returns `("model=... serial=...", 5.0)`; assert
  `<state-root>/status/device-probe.json` has `ok: true`, an ISO `checked_at`, and
  `collect_site_status(...)` reports the device as `ok`.
- `test_doctor_writes_a_failed_probe` — prober raises `IsapiError`; the cache has
  `ok: false` and status reports `unreachable`.
- `test_agent_writes_the_pidfile_during_a_tick` — monkeypatch `SiteAgent.tick` to read
  `<state-root>/agent.pid` while it runs; assert the content is `os.getpid()`.
- `test_agent_removes_its_pidfile_on_close` — after `run(once=True)` and `close()`, the
  file is gone.
- `test_a_foreign_pidfile_is_not_removed` — write another PID, call `close()`, assert the
  file remains (the owner is not us).

## GATE

```bash
uv run --frozen pytest -q
uv run --frozen ruff check src/gateclerk
```

## ACCEPT

- [ ] `gateclerk doctor` writes `status/device-probe.json` with `checked_at`, `ok`,
  `detail`.
- [ ] `gateclerk status` immediately reports the cached device probe.
- [ ] The agent writes `agent.pid` while running and removes its own file on exit.
- [ ] A foreign/stale pidfile is left alone.
- [ ] No new network call is added to `status`.
- [ ] Full pytest and ruff are green.

## OUT

`src/gateclerk/status_cli.py` (readers and TTL unchanged), `agent_health.py`, `park/`, the
health snapshot, and the service renderer.

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
