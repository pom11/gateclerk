# GC-P04 — Clock-skew alert and metric are wired into the running agent

BOARD: gateclerk   DEPENDS ON: GC-P03   GATED: no   COVERS: GC-09 / —

## WHY

`AlertPolicy.observe_skew()` and `AgentHealthCollector.observe_skew()` exist and are
unit-tested, but nothing calls them. A terminal whose RTC is hours off never raises a
`clock_skew` alert and `/metrics` never emits `device_clock_skew_seconds`. This card feeds
the reading GC-P03 already refreshes into both surfaces (R1: payroll scans depend on the
device clock).

## VERIFY

```bash
grep -rn "\.observe_skew(" src/gateclerk
```

Still broken while only the two definitions appear:

```text
src/gateclerk/agent_alert.py:570:    def observe_skew(self, skew: Skew) -> list[Alert]:
src/gateclerk/agent_health.py:445:    def observe_skew(self, device_serial: str, skew: Skew) -> None:
```

If a call site exists in `agent_loop.py` or `agent_cli.py`, stop and close the card.

## FILES

- `src/gateclerk/agent_alert.py:570-591` — `observe_skew(skew)` fires one
  `KIND_CLOCK_SKEW` warning above `skew.warn_seconds` and stays silent below.
- `src/gateclerk/agent_health.py:445-459` — `observe_skew(device_serial, skew)` stores the
  gauge and warns once per process.
- `src/gateclerk/agent_loop.py:128-172` — `TickResult` carries the tick's facts; add the
  skew here. GC-P03 leaves `DeviceLoop._last_skew` populated.
- `src/gateclerk/agent_loop.py:332-445` — `tick()` constructs every `TickResult`.
- `src/gateclerk/agent_cli.py:637-690` — `SiteAgent.tick()` receives each `TickResult`,
  already calls `collector.observe_tick(...)` and `policy.check_stall(...)`. This is the
  wiring point.
- `src/gateclerk/agent_health.py:650` — the metric description for
  `device_clock_skew_seconds`; it is emitted only after `observe_skew` stores a value.

## CHANGE

1. In `src/gateclerk/agent_loop.py`, import `Skew` (if GC-P03 has not already) and add a
   field to `TickResult` beside `termination`:
   ```python
   #: The device wall-clock reading from this tick's System/time refresh, if any.
   #: P2-05 turns a warning Skew into one clock_skew alert; P2-06 stores the gauge.
   clock_skew: Skew | None = None
   ```

2. In `DeviceLoop.tick()`, capture the skew after the refresh and attach it to the result.
   Use a local `skew = self._last_skew` after `_ensure_device_state()`/the refresh block.
   Add `clock_skew=skew` to the successful `TickResult(...)` return and to the
   `_failure(...)` path. For `_failure`, add a keyword-only parameter:
   ```python
   def _failure(self, exc: Exception, *, since: Any, until: Any,
                skew: Skew | None = None) -> TickResult:
   ```
   and pass `clock_skew=skew` in its `TickResult(...)`.
   The circuit-open early return stays as it is (no device read, no skew).

3. In `SiteAgent.tick()`, after `result = guarded_tick(self.policy, loop)` and the
   `if result is None: ... continue` branch, wire both surfaces:
   ```python
   if result.clock_skew is not None:
       report.alerts.extend(self.policy.observe_skew(result.clock_skew))
       if self.collector is not None:
           self.collector.observe_skew(loop.device_serial or PENDING_SERIAL, result.clock_skew)
   ```
   Use the same device key the rest of the pass uses (`loop.device_serial or
   PENDING_SERIAL`). Do not add the alert a second time in the `if result.ok` block.

4. Keep the existing `collector.observe_tick(...)` and `policy.check_stall(...)` order.
   The skew observation is independent of a failed walk: a device can be reachable enough
   to answer System/time but fail the event walk.

What must NOT change:

- `AlertPolicy.observe_skew`'s one-alert-per-episode rule and
  `AgentHealthCollector.observe_skew`'s gauge-only (never degraded) rule.
- No new alert kind, no new metric name, no device write.
- `SKEW_WARN_SECONDS = 120.0` stays in `tz.py`.

## TESTS

Write `tests/test_gc_p04_skew_wiring.py` first and run:

```bash
uv run --frozen pytest -q tests/test_gc_p04_skew_wiring.py
```

Copy the `SiteAgent` harness from `tests/test_p2_07b_agent_cli.py:195` (`AgentHarness`) and
the direct skew expectations from `tests/test_p2_05_alerts.py:487` and
`tests/test_p2_06_healthz.py:741`.

Tests:

- `test_run_once_emits_clock_skew_alert_over_threshold` — fake device `System/time` is one
  hour ahead of the agent clock; `agent.run(once=True)`; assert the report contains
  `warning:clock_skew` and the policy fired once.
- `test_run_once_under_threshold_is_silent` — 30 seconds of skew; no `clock_skew` alert.
- `test_health_snapshot_carries_device_clock_skew_seconds` — after the same tick, read
  `health/agent.json` and `/metrics` output; assert `device_clock_skew_seconds` is present
  for the device serial.
- `test_a_failed_walk_still_reports_the_skew_it_read` — make the event search fail after
  System/time succeeds; the tick is `ok=False` but the skew is still observed.

## GATE

```bash
uv run --frozen pytest -q
uv run --frozen ruff check src/gateclerk
```

## ACCEPT

- [ ] `TickResult` carries the skew from the refreshed reading.
- [ ] `SiteAgent.tick()` calls both `policy.observe_skew` and `collector.observe_skew`.
- [ ] Over 120 s produces exactly one `clock_skew` alert.
- [ ] `device_clock_skew_seconds` appears in the health snapshot and metrics.
- [ ] Under-threshold and failed-walk paths are pinned.
- [ ] Full pytest and ruff are green.

## OUT

`src/gateclerk/agent_alert.py` and `src/gateclerk/agent_health.py` (their behaviour is
already correct), `src/gateclerk/tz.py`, `src/gateclerk/agent_push.py`, and the existing
alert/health unit tests.

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
