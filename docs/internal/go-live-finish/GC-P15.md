# GC-P15 — Detect a serial reset after a quiet period

BOARD: gateclerk   DEPENDS ON: GC-P05   GATED: no   COVERS: GC-16 / —

## WHY

A terminal that is factory-reset or replaced restarts `serialNo` near 1. The current reset
check only looks at records returned by the narrow poll window. If the replacement unit has
been quiet for more than `cadence + overlap`, the window returns no records, the check never
runs, and events that occurred before the window are skipped. R1: no punch may be lost
silently.

## VERIFY

```bash
grep -n "RESET_MIN_SERIAL_DROP\|_newest_serial_by_time\|_reset_evidence\|oldest_serial_in_window" src/gateclerk/agent_loop.py
```

Still broken while the reset decision exists only inside the per-chunk loop:

```text
372:                newest, newest_time = _newest_serial_by_time(chunk_result.records)
373:                if (
...
385:                    evidence = self._reset_evidence(current, newest)
```

and no code probes a wider window when the chunk list is empty.

## FILES

- `src/gateclerk/agent_loop.py:332-445` — `tick()` iterates `self._walk(since, until)`.
  The reset branch is inside the loop; a quiet tick yields no chunk and never reaches it.
- `src/gateclerk/agent_loop.py:845-880` — `_reset_evidence(checkpoint, newest)` reads
  fresh `deviceInfo`, refuses a serial change, and accepts a firmware change or a drop of
  at least `RESET_MIN_SERIAL_DROP`.
- `src/gateclerk/agent_loop.py:1087-1105` — `_newest_serial_by_time(records)` returns the
  serial and device-local time of the newest-by-time record.
- `src/gateclerk/paging.py:943-1015` — `iter_event_windows(..., page_size=...,
  max_pages=..., time_reverse_order=True)` supports a one-page newest-first read.
- `tests/test_p2_03_scheduler.py:708` — the existing reset test to copy.

## CHANGE

1. Add two constants beside `RESET_MIN_SERIAL_DROP`:
   ```python
   #: A quiet tick still needs a reset answer, but a wider read costs a request. Once an
   #: hour is enough for a hardware swap; the narrow poll window still runs every tick.
   RESET_PROBE_INTERVAL_S = 60 * 60
   #: The device ring holds roughly a week. A reset older than the ring cannot be proven
   #: from events; `deviceInfo` remains the fallback evidence.
   RESET_PROBE_WINDOW_S = 7 * 24 * 60 * 60
   ```

2. In `DeviceLoop.__init__`, add `self._last_reset_probe_at: float | None = None`.

3. Add `_probe_newest_serial(checkpoint)`:
   ```python
   def _probe_newest_serial(self, checkpoint: Checkpoint) -> tuple[int | None, str | None]:
       """One newest-first page over the retained window; no cursor walk."""
       lower = self._now() - timedelta(seconds=RESET_PROBE_WINDOW_S)
       if checkpoint.checkpoint_time:
           try:
               checkpoint_at = _parse_stamp(checkpoint.checkpoint_time, site_tz=self.site_tz)
               lower = max(lower, checkpoint_at)
           except Exception:
               pass
       limits = self._limits or (
           paging_limits_from_caps(self._caps) if self._caps is not None else PagingLimits()
       )
       for chunk in iter_event_windows(
           _search_reader(self.client),
           since=lower,
           until=self._now(),
           chunk=timedelta(seconds=RESET_PROBE_WINDOW_S),
           site_tz=self.site_tz,
           device_offset_min=self._claim,
           limits=limits,
           page_size=1,
           max_pages=1,
           inter_page_delay=self._inter_page_delay,
           sleep=self._sleep,
           clock=self._monotonic,
           major=0,
           time_reverse_order=True,
       ):
           return _newest_serial_by_time(chunk.records)
       return None, None
   ```

4. At the end of `tick()`, after the `for chunk_result in self._walk(...)` loop and before
   the final `TickResult`, add the quiet-tick branch:
   ```python
   if (
       current is not None
       and counts.records == 0
       and reset is None
       and (
           self._last_reset_probe_at is None
           or self._monotonic() - self._last_reset_probe_at >= RESET_PROBE_INTERVAL_S
       )
   ):
       self._last_reset_probe_at = self._monotonic()
       newest, newest_time = self._probe_newest_serial(current)
       if (
           newest is not None
           and newest < current.checkpoint_serial
           and _is_after_checkpoint(newest_time, current, self.site_tz)
       ):
           evidence = self._reset_evidence(current, newest)
           if evidence is not None:
               reset_checkpoint(
                   self.conn,
                   self.device_serial,
                   expected_serial=current.checkpoint_serial,
                   new_serial=newest,
                   checkpoint_time=newest_time,
                   firmware=self._caps.firmware if self._caps is not None else None,
                   now=self._now(),
               )
               current = read_checkpoint(self.conn, self.device_serial)
               reset = evidence
               advanced = True
               checkpoint_serial = newest
   ```
   If `evidence is None`, leave the checkpoint alone and warn once; a same-firmware small
   drop is a glitch, not a reset. Do not raise from the quiet probe.

5. Do not change the existing in-window reset branch or its `CheckpointRegressionError`.

What must NOT change:

- `_reset_evidence`'s refusal of a changed `deviceInfo` serial.
- The normal window/checkpoint path and the overlap re-read.
- The request budget: one extra page at most once per hour, only after a quiet tick.

## TESTS

Write `tests/test_gc_p15_cold_reset.py` first and run:

```bash
uv run --frozen pytest -q tests/test_gc_p15_cold_reset.py
```

Copy the reset setup from `tests/test_p2_03_scheduler.py:708` (`seed_events`,
`_set_firmware`, `device_event`) and `LoopHarness` from `:156`.

Tests:

- `test_quiet_replacement_is_detected_one_hour_after_the_last_tick` — seed a checkpoint at
  serial 100; reset the fake to serial 3 with a newer event time; advance the clock past
  `RESET_PROBE_INTERVAL_S`; the tick has no records in the narrow window but
  `serial_reset.new_serial == 3`, the checkpoint opens epoch 1, and the event is stored
  under the new epoch.
- `test_quiet_tick_without_a_reset_does_not_rewind` — newest serial equals or exceeds the
  checkpoint; no reset, no epoch change.
- `test_quiet_probe_runs_at_most_once_per_hour` — count event search POSTs across three
  quiet ticks; exactly one probe.
- `test_failed_quiet_probe_does_not_fail_the_tick` — make the probe raise; the tick remains
  `ok`, the checkpoint is untouched.

## GATE

```bash
uv run --frozen pytest -q
uv run --frozen ruff check src/gateclerk
```

## ACCEPT

- [ ] A quiet tick with a reset serial below the checkpoint opens a new epoch.
- [ ] Events from the replacement generation are stored, not skipped.
- [ ] A quiet tick without reset evidence does not rewind.
- [ ] The probe is bounded to one page per hour.
- [ ] A failed probe does not fail the tick or move the checkpoint.
- [ ] Full pytest and ruff are green.

## OUT

`src/gateclerk/paging.py`, `src/gateclerk/agent_store.py` (`reset_checkpoint` already
exists), `src/gateclerk/agent_cli.py`, and the existing in-window reset tests.

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
