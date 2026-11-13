# P2-05 notes — alerts + park-on-bad-creds

Card: t_4c2ab984. BINDING SPEC: docs/internal/P2-SITE-AGENT.md §2c (DECIDED verbatim).
Branch wt/p2-05-alerts. Parents P2-03 (agent_loop, #30) + P2-04 (agent_push, #31)
merged into main (c0b8ba0 / 9b7af27) mid-flight; this branch carries origin/main and
the diff vs main is exactly three files: `src/gateclerk/agent_alert.py` (new),
`tests/test_p2_05_alerts.py` (new, 20 tests), this notes file.

## Seams found (card: "read, don't edit; BLOCK if a hook is missing")

No hook is missing — the loop + transport already expose everything:

* `TickResult` (agent_loop.py): `skipped` (circuit-open, ZERO requests),
  `circuit_open`, `exception` (typed), `ok`, `advanced`, `device_serial`.
* `IsapiClient.circuit_open()` / `auth_recoveries` (isapi_transport.py) — read-only.
* `IsapiAuthError.locked` / `.unlock_time` (exceptions.py) — the §2c lock channel.
* `agent_store.read_checkpoint` — `updated_at` for the stall detector;
  `check_db_watermark` returns the §2b gauge (agent_store docstring already names
  "P2-05 alerts on warn" as the intended consumer).
* The ONE seam that did not exist: nothing gated whether a device gets a tick at
  all (the park). Added HERE, as a thin wrapper `guarded_tick(policy, loop)` —
  P2-07's CLI wraps the scheduler with it. agent_loop.py untouched (card rule).

## Decisions (each pinned by a named test)

- **Park is DISK state** (JSON files under an injected `park_dir`), not memory:
  `Restart=always` restarts must not launder a park (the circuit is in-memory; a
  memory-only park = wrong creds re-fed every 5 min into lockout accounting).
  Written atomically (tmp + rename); `parked`/`ack`/`attempt_allowed` all read
  through. An in-memory dict mode remains for pure-logic tests (card allows it).
- **Park key is dual: `pending` + device serial.** The bootstrap 401 (the wrong-
  creds case!) happens BEFORE the serial is ever read; a `pending` park closes the
  window where a restart-in-between would forget the failure. Once the serial is
  known both keys block, and a success unparks both.
- **`guarded_tick` refuses BEFORE `loop.tick()`** — a refused tick is not a failed
  tick and not a tick at all (served-count frozen, the card's pin).
- **The grid is consumed by the ATTEMPT, whatever it found** (`attempted=True`
  re-arms `next_attempt_at` from now even for a non-auth failure): an acked park
  means exactly one knock per 30-min period — a transient busy must not reopen the
  cadence door for the rest of the episode.
- **Ack semantics**: `ack(site)` -> int parks opened; 0 for a typo'd site/serial
  (an ack that cannot find a park must not look like success); re-acking an
  already-open park does NOT push the grid out; first re-probe is at ack+30 min,
  never immediately (ack = permission to schedule, not permission to hammer).
- **Lockout (lockStatus=lock) does NOT park**: the circuit IS the wait (§2c
  verbatim); parking too would make an un-ackable state worse for no benefit.
  It alerts `device_locked` critical once per episode.
- **Nonce recoveries: counter only** (`observe_recoveries` = monotone max of the
  transport's total). Never an alert — asserted by "sink never called".
- **Skew / watermark / stall: one page per episode, heal closes the episode**
  (a re-over after a heal is a NEW incident and re-fires — pinned for skew +
  watermark; stall tracks the frozen `updated_at` value itself).
- **Stall boundary: strictly OVER k*cadence** (watermark precedent "exactly-at is
  not over"), pinned at exactly k and k+1s. k=3 lives in `STALL_STRIKES` — no
  config key exists (config.py `_KNOWN_KEYS`), card says constant + comment; a
  caller can pass `stall_strikes=` if P2-06 adds the key.
- **Never leak**: `TickResult.error` embeds `str(exc)` and transport messages DO
  embed the base URL (`request to {base_url} failed`) — so alert notes are
  authored here from safe pieces (kind, site label, serial, numbers), never from
  the result strings. The leak scan asserts host/Authorization/payload AND the
  transport-detail fragments (`http_status`, `on device_info`, `statusCode`) are
  absent from the whole alert surface (sink records + default stderr line), with
  a positive control proving the scan sees real notes.
- **Default sink** = one stderr line (p1-05c `_default_warn` precedent,
  markup=False). Metric-counter increment per §2e joins when P2-06's vocabulary
  ships — `counters` dict + `Alert.kind` (snake_case §2e names) are the seam.
- Site guard on park access: a park record naming another site raises instead of
  being read/acked (park dirs are per-unit state, §2d).

## DoD case map (card numbering -> test names)

1. wrong-creds terminal 401 -> critical + parked + served-count frozen until ack:
   `test_wrong_creds_fire_critical_park_the_device_and_freeze_all_requests`,
   + `test_park_survives_a_restart_and_still_touches_nothing` (disk invariant).
2. ack -> re-probe at +30 min, every 30 after, success un-parks:
   `test_ack_opens_a_30_minute_re_probe_grid_and_a_success_un_parks`,
   + `test_ack_on_a_never_parked_device_is_a_no_op`.
3. unacked forever = zero probes across days (864 gated ticks / 3 days):
   `test_unacked_park_never_probes_again_across_days`.
4. lockStatus=lock -> critical on-site + no creds until unlockTime (served
   timeline pinned; circuit honored end-to-end through the real transport):
   `test_lockout_body_fires_critical_on_site_and_creds_wait_out_unlock_time`,
   + `test_circuit_open_skip_alerts_nothing_extra`.
5. nonce recovery -> info counter ONLY, no alert record:
   `test_nonce_recoveries_land_in_the_info_counter_and_never_alert`.
6. skew over -> warning, under -> silence: `test_skew_over_threshold_warns_under_is_silent`.
7. stall fires at k=3 (boundary + one-per-episode + heal re-arms):
   `test_checkpoint_stall_fires_at_three_cadences_and_silences_when_it_moves`,
   + `test_stall_is_quiet_for_a_device_that_never_advanced`.
Plus: watermark channel, non-auth-failure silence, leak scan, structured shape,
and five guard tests (in-memory parks, foreign-site file, wrong-site ack,
cadence refusal, no-conn stall).

## Gate (real numbers, run 2026-10-20)

- `uv run pytest -q`: **1345 passed / 5 skipped / 1 deselected** (main 1324/5/1 +
  20 new tests + 1 hygiene parametrization for the new file — verified by
  counting this file's tests). RED proven first: commit 01b6d03 shipped the
  suite alone, 15/15 failing with `No module named 'gateclerk.agent_alert'`.
- `ruff check .` + `ruff format --check .`: clean (whole tree).
- `agent_alert.py` coverage **99%** (237 stmts, 3 misses: DTZ guards 102/109 +
  the in-memory write branch 254).
- Mutation probes **11/11 caught** (scratch script, backup/restore,
  PYTHONDONTWRITEBYTECODE=1, restored byte-identical): gate neuter, unacked-
  treated-acked, 30min->5min, no re-arm, no un-park, stall `<=`->`<`, recovery
  pages, lockout parks, skip alerts, re-park spam, note carries str(exc).

## Handoff for P2-06 / P2-07

- P2-07 wires: `AlertPolicy(... park_dir=...)` per site; `guarded_tick(policy, loop)`
  around `run_forever`/`--once`; `gateclerk agent ack` -> `policy.ack(site)`.
- P2-06 healthz reads: `policy.counters` (all §2e names incl. `auth_recoveries`),
  `policy.parked(site, key)` per device, and the gate reason from
  `policy.attempt_allowed(serial)`.
- No config keys added (none existed for k; `stall_strikes` is constructor-injectable).
