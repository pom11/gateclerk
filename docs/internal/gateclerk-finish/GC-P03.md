# GC-P03 — Refresh the device UTC offset periodically (DST)

BOARD: gateclerk   DEPENDS ON: —   GATED: no   COVERS: GC-03 / —

## WHY

`DeviceLoop._ensure_device_state()` reads `/ISAPI/System/time` once per process and caches
the claimed UTC offset forever. A terminal whose offset changes at a DST transition keeps
stamping event windows with the old offset, shifting the poll window by one hour. R1: BC is
the only calculator, and it must receive the right scans.

## VERIFY

```bash
grep -n "labels = device_window_labels\|_bootstrapped" src/gateclerk/agent_loop.py
```

Still broken while the only `device_window_labels` call is inside the
`if self._bootstrapped: return` bootstrap block:

```text
830:        if self._bootstrapped:
838:        labels = device_window_labels(self.client)
843:        self._bootstrapped = True
```

If a periodic refresh call exists outside that block, stop and close the card.

## FILES

- `src/gateclerk/agent_loop.py:825-843` — `_ensure_device_state` reads the offset once:
  ```python
  labels = device_window_labels(self.client)
  self.device_serial = caps.serial
  self._caps = caps
  self._claim = labels.claimed_offset_min
  self._claim_note = labels.note
  self._bootstrapped = True
  ```
- `src/gateclerk/agent_loop.py:332-445` — `tick()` calls `_ensure_device_state()` at the
  start of every tick; this is the hook for the periodic refresh.
- `src/gateclerk/pipeline.py:365-395` — `device_window_labels(client)` performs
  `GET /ISAPI/System/time` through `device_time_reading` and returns
  `WindowLabels(claimed_offset_min, note)`.
- `src/gateclerk/tz.py:483-518` — `compute_skew(device_time, *, our_now=None,
  site_tz=DEFAULT_SITE_TZ, warn_seconds=SKEW_WARN_SECONDS) -> Skew` (already used by the
  doctor and `device time`).

## CHANGE

1. In `src/gateclerk/agent_loop.py`, import `IsapiAuthError` and the time/skew helpers:
   ```python
   from gateclerk.exceptions import IsapiAuthError, IsapiError
   from gateclerk.pipeline import device_time_reading
   from gateclerk.tz import Skew, compute_skew
   ```
   Keep the existing `device_window_labels` import if the bootstrap still uses it; after
   the refactor it does not, so remove it if ruff reports it unused.

2. Add a module constant beside `RESET_MIN_SERIAL_DROP`:
   ```python
   #: /ISAPI/System/time is a cheap GET, but every request spends the ~190-use nonce
   #: budget. Fifteen minutes is short enough for a DST transition and long enough that a
   #: 5-minute poll does not read the clock on every tick.
   DEVICE_CLAIM_REFRESH_S = 15 * 60
   ```

3. In `DeviceLoop.__init__`, add three fields beside the bootstrap state:
   ```python
   self._claim_read_at: float | None = None
   self._last_device_time: Any = None
   self._last_skew: Skew | None = None
   ```

4. Add `_refresh_device_claim()`. It is the only place that reads the clock after the
   bootstrap:
   ```python
   def _refresh_device_claim(self) -> None:
       """Read the claimed offset (and the wall clock for skew) on a bounded cadence."""
       try:
           reading, _raw = device_time_reading(self.client)
       except IsapiAuthError:
           raise
       except IsapiError as exc:
           # A transient read failure keeps the last good claim; the walk still runs.
           self._claim_note = f"System/time unreadable: {exc}"
           return
       self._last_device_time = reading
       self._last_skew = compute_skew(
           reading, our_now=self._now(), site_tz=self.site_tz
       )
       self._claim = reading.claimed_offset_minutes
       self._claim_note = (
           None if self._claim is not None else (reading.note or "no claimed UTC offset")
       )
       self._claim_read_at = self._monotonic()
   ```

5. In `_ensure_device_state`, replace the `labels = device_window_labels(...)` block with
   `self._refresh_device_claim()`. Keep the `caps` read and the blank-serial refusal.

6. In `tick()`, immediately after `self._ensure_device_state()` and the serial check, add:
   ```python
   if (
       self._claim_read_at is None
       or self._monotonic() - self._claim_read_at >= DEVICE_CLAIM_REFRESH_S
   ):
       self._refresh_device_claim()
   ```
   This means one clock GET at bootstrap and one every 15 minutes, not one per tick.

What must NOT change:

- The window math in `_window`, `iter_event_windows`, `major=5`, the checkpoint rules and
  `_walk`.
- The warning text for an unreadable clock; a refresh failure must still leave the last
  claim usable.
- No new device writes and no new endpoint.

## TESTS

Write `tests/test_gc_p03_claim_refresh.py` first and run:

```bash
uv run --frozen pytest -q tests/test_gc_p03_claim_refresh.py
```

Copy `LoopHarness` from `tests/test_p2_03_scheduler.py:156` and the System/time reset
pattern from `tests/test_p2_03_scheduler.py:464`.

Tests:

- `test_offset_flip_is_used_by_the_next_tick_without_restart` — seed events and tick once
  with `+02:00`; replace the `GET /ISAPI/System/time?format=json` response with a
  `+03:00` `localTime`; advance the fake clock and monotonic by 15 minutes; tick again.
  Assert the last `event_conditions()` `startTime`/`endTime` end with `+03:00`.
- `test_clock_is_not_read_before_the_refresh_interval` — two ticks five minutes apart;
  count authenticated `GET` requests to `/ISAPI/System/time?format=json`; assert exactly
  one before the 15-minute mark.
- `test_a_transient_system_time_failure_keeps_the_last_claim` — make the second read fail
  with `IsapiError`; the tick is still `ok` and the window label is the previous claim.
- `test_auth_error_on_refresh_still_raises` — `IsapiAuthError` is not swallowed.

## GATE

```bash
uv run --frozen pytest -q
uv run --frozen ruff check src/gateclerk
```

## ACCEPT

- [ ] A running loop re-reads `/ISAPI/System/time` at most every 15 minutes.
- [ ] A `+02:00` to `+03:00` flip changes the next tick's window label without restart.
- [ ] No extra clock GET on a normal 5-minute cadence.
- [ ] Transient failures keep the last claim; auth errors still surface.
- [ ] Full pytest and ruff are green.

## OUT

`src/gateclerk/pipeline.py` (`device_window_labels` stays for the CLI), `src/gateclerk/tz.py`,
`src/gateclerk/agent_cli.py`, the alert and health modules (GC-P04 owns the wiring), and all
existing scheduler tests.

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
