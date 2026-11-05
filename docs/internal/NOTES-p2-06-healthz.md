# NOTES — P2-06 `/healthz` + metrics (card t_d7c96117)

Design decisions, probe evidence, and the DoD case map for `src/gateclerk/agent_health.py`
+ `tests/test_p2_06_healthz.py`. Binding spec: docs/P2-SITE-AGENT.md §2e (DECIDED
2026-10-19: carry over ALL listed P1 observables; minimal vocabulary; no dashboard).

## Decisions

**The sqlite db IS the state — no sidecar file.** The card allows "small sqlite or
json sidecar — your choice, document it". Every gauge source already lives in the db
or on objects the agent process holds (checkpoint/events tables, push_queue/dead_letter,
IsapiClient counters, TickResult). A sidecar would be a second truth that can drift.
`collect()` therefore only READS the db + live objects; no observation writes into the
db (health polling must not perturb the agent — pinned: `collect()` opens no device
request and issues no INSERT/UPDATE; the stall test counts `device.served` across a
collect).

**Serving contract for P2-07:** `snapshot_to_json()`/`snapshot_from_dict()` round-trip
the whole snapshot (pinned byte-equal re-render). P2-07's systemd+socat (or a trivial
stdlib wrapper) can serve a JSON file the agent writes, or call these functions
in-process. No sockets in this card (card rule; tests call builders directly).

**Vocabulary = exactly the 18 §2e names.** `METRIC_NAMES` set-equality pins it at the
contract level (`test_metric_vocabulary_is_exactly_the_spec_list`). Four names are
site-level (`SNAPSHOT_ONLY_NAMES`: db_size_bytes, dead_letter_depth, push_ok, push_ok's
pair push_failed — one pusher + one db per agent process, spec §2d), the other fourteen
render per device (`DEVICE_METRIC_NAMES`). `last_poll_ok_age_s` and `circuit_parked_s`
are healthz *fields* of the device block (the spec's healthz line names them), not
metric names — keeping them out of METRIC_NAMES is what "no new concepts" means here.

**degraded = circuit open OR checkpoint stall, nothing else** (card RULES + §2c).
Reason lines name the serial (P2-05 alert channel reads them). Recoveries, locked
events, skew, and NOMATCH termination are gauges/warnings, NEVER triggers
(individual pins: recovery test asserts status ok; skew test asserts gauge + one warn;
fallback test runs with termination NOMATCH and never claims ok-degraded).
`checkpoint_stall_s` is caller-supplied (P2-07 passes ~2× cadence from config; the
default 900 s = 2×5min cadence + slack) and `<= 0` raises at construction — a
zero threshold degrades every snapshot by construction.

**Aged facts split by clock.** `checkpoint_age_s` ages on the WALL clock (the
checkpoint row's `updated_at` is wall — a wall step moves it honestly);
`last_poll_ok_age_s` and `circuit_parked_s` age on MONOTONIC (process facts — an NTP
step must not make the agent look stalled or freshly-polled). Both seams are injected.

**Park-anchor semantics (the one real bug the probes found).** `circuit_parked_s`
ages from the first moment THIS process observed the circuit open (`observe_tick` on a
result with `circuit_open=True` — the failing tick that opened the circuit already
carries it, since `_failure` reads `circuit_open()` after the raise), and an ok tick
CLEARS the anchor so a second park episode ages from ITS first sight.
Original code used `anchor or now` — with a monotonic that legitimately reads 0.0 the
anchor was falsy and re-anchored on every skip, making the gauge read 0 forever. Fixed
to `is None`; the circuit test now advances 60 s across a second skip and pins the
age, and `test_two_park_episodes...` pins the episode boundary (dropping the ok-clear
reads 2000.0, not 0.0).

**`search_termination` is handed over, not re-walked.** `TickResult` gained ONE field,
`termination` (the normalized termination of the last completed chunk, from
`_WalkCounts`), because the card names "the loop result objects" as P2-06's read seam
and the §2e observable is per-SearchSummary (paging.py:351). The health side never
re-runs paging. `stats.last_termination` caches the last observed value so a collect
with an empty ticks map still reports what the loop last said (pinned on the naive
box: the fallback equals the observed `NOMATCH`, derived, never a constant).

**tz warning = delegate, never fork.** `mismatch_policy is cli._warn_tz_mismatch`
(anti-fork pin). The collector captures the policy's stderr line once per process
(the p1-06c once-per-run semantics; second collect adds nothing, pinned), forwards the
line to the warn sink (journalctl keeps what the CLI operator saw), and stores 0/1 as
`tz_offset_mismatch_warnings`. The per-record count comes from the events column
(the p1-12 rule: the flag is a fact about the data; the mapping silences the warning,
never the flag). The policy's INPUT is `EventRecord.from_dict` of the stored jsonl
lines — never re-derived (p1-12's rule: a summary that recomputes can disagree).
A corrupt jsonl line is skipped (`_parse_jsonl` → None), a crashing policy is caught:
the health surface bends, never breaks.

**site_labeled_windows from the loop's own label** (`window_label == SITE_LABELLED`,
per ok tick) — NOT from the warn stream: p1-05c prints the fallback line per risky
window, and counting both label and stream would double-count. `observe_warn` counts
nothing (pinned by feeding it both markers). The §5 rollout gate needs this counter as
EVIDENCE that fallback ≈ 0, so its source must be the loop's verdict.

**oldest_serial: MIN(events.serial_no)** — this is our keep-everything store's floor,
NOT the device's oldest retained event: no oldest-retained probe exists, so real
ring-rollover detection does not exist yet (card t_ed9c7e92). DESIGN.md:411 records
the intended device-side probe: record oldest-serialNo per poll; a monotonic increase
of the minimum means rolling started. P2-05's serial-floor arm reads this store value
and names what it actually detects: stored history disappeared. No fabrication; the
docstring says so and the test recomputes the SQL.

**push_ok/push_failed are the drain log's own cumulative counters** — wired as
`drain(..., log=collector.observe_push_log)`, parsed from the drain line itself so
health can never disagree with the queue; malformed lines are swallowed (a health
counter must not be able to break a drain). `dead_letter_depth` is the SQL count
(P2-04's `dead_letter_depth(conn)`), NOT a counter — the replay test proves depth
follows the rows (3 → 2 after a replayed row's DELETE), not the history.

**db_warn_bytes dropped.** Watermark alerting is P2-05's channel (agent_alert); a
collector param stored-but-never-read is a dead concept; the card forbids new concepts.

**Auth counters read the exception the tick carries.** `auth_terminal_failures` /
`device_locked_events` count `IsapiAuthError` verdicts on observed ticks (`.locked` =
the 401 body's lockStatus); a circuit-open skip adds nothing on top of the tick that
opened the circuit (no double-count, pinned), and a NON-auth failure (IsapiBadContent
from the Invalid-Content envelope) counts ZERO (spec §2c splits credential pages from
noise, pinned both directions). `auth_recoveries` is read LIVE off the client
(`IsapiClient.auth_recoveries`) — never copied at observe time, so it can never lag.

## Probe table (mutation runs, full suite unfiltered, PYTHONDONTWRITEBYTECODE=1)

| # | Mutation | Result |
|---|----------|--------|
| M1 | drop termination hand-off in observe_tick | caught |
| M2 | drop ok-branch park clear | caught |
| M3 | drop ok poll-heartbeat stamp | caught |
| M4 | push_failed forgets dead_lettered | caught |
| M5 | fallback gauge never counts | caught |
| M6 | mismatch policy re-runs every collect | caught |
| M7 | stall rule disabled | caught |
| M8 | park anchor `or`-idiom regression | caught |
| M9 | dead_letter_depth constant 0 | caught |
| M10 | db_size_bytes constant 0 | caught |
| M11 | auth_recoveries constant 0 | caught |
| M12 | circuit gauge always 0 | caught |
| M13 | records_stored never accumulates | caught |
| M14 | circuit-open degrade reason dropped | caught |

**14/14 caught** (run 2026-10-20; every probe ran the FULL suite with `-x`, pristine
tree green before the first probe, module restored + `git diff --quiet` clean after
each). M8 is the regression probe for the real bug shipped mid-card (see
"Park-anchor semantics" above) — it was found by a test pin written before the probe
run, then re-proven by the probe.

(harness at `~/.hermes/profiles/backend-engineer/cache/scratch/probe_p2_06.py`,
backup+restore, git-diff-clean assertion after each probe.)

## DoD case map

| DoD (card) | Test |
|------------|------|
| (1) vocabulary set-equality | `test_metric_vocabulary_is_exactly_the_spec_list` |
| (2) healthy run → ok + real ages/gauges | `test_healthy_fake_run_is_ok_with_real_ages_and_gauges`, `test_auth_recoveries_match_the_clients_own_counter_after_a_recovery`, byte-pin `test_healthz_text_is_byte_pinned_on_the_healthy_run`, `test_metrics_text_carries_every_name_with_value_and_source` |
| (3) circuit-open → degraded + named; stall → degraded + named | `test_circuit_open_device_makes_degraded_and_names_the_serial`, `test_two_park_episodes_anchor_the_second_at_its_own_first_sight`, `test_checkpoint_stall_makes_degraded_and_names_the_serial` |
| (4) dead-letter depth from store rows | `test_dead_letter_depth_and_push_counters_come_from_the_store` |
| (5) mapped (0 warn) vs unmapped (1 warn) + mismatch counts; site_labeled | `test_mapped_run_is_silent_unmapped_run_warns_once_records_mismatch_in_both`, `test_site_labeled_fallback_run_counts_windows_per_ok_tick`, `test_mismatch_policy_input_is_the_stores_own_rows_never_rederived` |
| (6) no secret-shaped strings | `test_emitted_text_carries_no_secret_shaped_strings` (password/host/IPv4/word scan + dead-letter payload fields, over the RICH run: locked 401 + dead letters + stub endpoint + db path) |
| rules: no sockets / purity / JSON | `test_device_health_builder_is_pure_and_callable_directly` (device.served unchanged), `test_snapshot_json_round_trips_for_a_separate_reader`, `test_observed_skew_is_a_gauge_not_a_degraded_trigger` |
| defensive posture | `test_health_surface_survives_a_corrupt_store`, `test_events_per_day_is_none_when_no_rate_is_definable`, `test_wiring_guards_and_unparseable_observations_are_loud_or_silent_as_appropriate`, `test_a_crashing_mismatch_policy_cannot_break_a_health_poll`, `test_default_warn_sink_prints_to_stderr`, `test_warn_stream_never_double_counts_the_fallback_gauge`, `test_auth_terminal_failures_counts_auth_verdicts_only` |
