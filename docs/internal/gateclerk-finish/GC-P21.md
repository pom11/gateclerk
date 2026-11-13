# GC-P21 — Alerts proven on the demo device: push failure, device offline, clock skew

BOARD: gateclerk   DEPENDS ON: GC-P04, GC-P08, GC-P17   GATED: no   COVERS: G3 / —

## WHY

G3 requires the alert path to be observed, not just unit-tested. This card proves three
real behaviours against the repo's demo device: a failed push keeps the row queued and
reports the failure, an offline device raises `checkpoint_stall`, and a skewed device clock
raises `clock_skew`. The demo device is synthetic and loopback-only; no real terminal or BC
is involved.

## VERIFY

```bash
uv run --frozen pytest -q tests/test_p2_05_alerts.py tests/test_p2_06_healthz.py -q
uv run --frozen gateclerk demo device --help
```

Both commands must pass/exit 0. The demo device is `gateclerk.demo_device.DemoDevice`
(loopback, synthetic fixtures, `Demo*` identities).

## FILES

Start command (loopback only, port 0 picks a free port):

```bash
uv run --frozen gateclerk demo device serve --host 127.0.0.1 --port 0
```

The tests below use the `demo_device` fixture, which starts the same server on an
ephemeral loopback port. Ready-made endpoint URLs and the synthetic credential pair:

```bash
uv run --frozen gateclerk demo device urls --port 80
```

- `src/gateclerk/demo_device.py:870-922` — `DemoDevice.start()`, `.stop()`, `.base_url`.
- `src/gateclerk/demo_device.py:255-285` — synthetic events at `2026-06-15 08:00+02:00`.
- `src/gateclerk/agent_loop.py` — `DeviceLoop.tick()`; GC-P04 adds `TickResult.clock_skew`.
- `src/gateclerk/agent_alert.py:570-591` — `observe_skew` / `KIND_CLOCK_SKEW`.
- `src/gateclerk/agent_alert.py:595-725` — `check_stall` / `KIND_CHECKPOINT_STALL`.
- `src/gateclerk/agent_push.py:465-588` — `drain`; GC-P08 adds the token/permanent-4xx
  handling. A 503 still retries, which is the push-failure proof.
- `tests/test_demo_device.py:87-110` — the `demo_device` / `demo_client` fixtures.
- `tests/test_p2_05_alerts.py:487` — the direct skew expectations.

## CHANGE

No product code. Add one proof test and commit its output as evidence.

1. Write `tests/test_gc_p21_alerts_proof.py`. Use the `socket_allow` fixture and
   `demo_device` fixture from `tests/test_demo_device.py:87-110`.
2. Test `test_push_failure_keeps_the_row_and_reports_it`:
   - open `agent_db.connect(tmp_path/"agent.sqlite3")`;
   - store one granted punch with `agent_store.store_events`;
   - insert it into `push_queue` with `agent_push.enqueue_events`;
   - call `agent_push.drain(...)` with a fake transport that returns `503`;
   - assert `result.push_failed == 1`, the row is still in `push_queue` with
     `attempts == 1`, and the error class is `HttpStatus503`.
3. Test `test_offline_device_raises_checkpoint_stall`:
   - use the live `demo_device` and `demo_client` to tick once and advance a checkpoint;
   - stop the demo device;
   - advance the fake clock past `STALL_STRIKES * cadence_s` and call `tick()` again
     (it fails, checkpoint unchanged);
   - call `AlertPolicy.check_stall(serial, gap_s=...)`;
   - assert one `checkpoint_stall` alert.
4. Test `test_clock_skew_on_the_demo_device_raises_clock_skew`:
   - start the demo device;
   - build a `DeviceLoop` with `now` set to `2026-06-15T09:05+02:00` (the demo clock says
     08:00, so skew is about +3600 s);
   - tick once;
   - assert `result.clock_skew.warn` is true;
   - call `AlertPolicy.observe_skew(result.clock_skew)` and assert one `clock_skew` alert.
5. Run the test and save the output:
   ```bash
   uv run --frozen pytest -q tests/test_gc_p21_alerts_proof.py -vv \
     | tee docs/internal/gateclerk-finish/evidence/GC-P21-alerts.log
   ```
   The log is the G3 evidence. It contains only synthetic demo values.

What must NOT change:

- `DemoDevice` fixtures, the alert thresholds (`SKEW_WARN_SECONDS = 120`,
  `STALL_STRIKES = 3`) and the alert kinds.
- No real device, no BC, no production store.
- No employee name, host or credential in the log; the demo names are synthetic and
  already public.

## TESTS

The three tests above are the card's tests. Run them first; a missing GC-P04 `clock_skew`
field or a missing GC-P08 permanent-status branch must fail the test, not be skipped.

```bash
uv run --frozen pytest -q tests/test_gc_p21_alerts_proof.py
```

## GATE

```bash
uv run --frozen pytest -q
```

The proof log plus the full suite is the G3 evidence. No BC suite runs here.

## ACCEPT

- [ ] A 503 push failure leaves the row queued, attempts = 1, class `HttpStatus503`.
- [ ] An offline demo device produces one `checkpoint_stall` alert.
- [ ] A one-hour demo clock skew produces one `clock_skew` alert.
- [ ] The evidence log is committed and contains only synthetic values.
- [ ] Full pytest is green.

## OUT

Real terminals, BC, mnotify delivery, the network, and the email allowlist. This card
proves the policy and the queue, not the mail transport (GC-P19 configures that).

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

DONE: PR URL, merge commit, evidence path.
LEFT: anything not proven, with the reason.
