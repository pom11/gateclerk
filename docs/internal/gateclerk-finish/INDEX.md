# Gateclerk finish — gateclerk card index

Directory: `docs/internal/gateclerk-finish/`
Board: `gateclerk`   Integration branch: `feat/gateclerk-finish`   PR target for every worker card: `feat/gateclerk-finish` (never `main`/`master`).
Plan: `~/dev/Example_customizations_bc/docs/superpowers/plans/2026-11-13-gateclerk-finish.md`, rev 4, section 4.3.
Audit: `docs/internal/AUDIT-2026-11-13.md`.

## Cards

| ID | Title | Wave | Depends on | Gated | Status |
|---|---|---|---|---|---|
| GC-P01 | Queue only granted punch candidates with a known code | 1 | — | no | OK |
| GC-P02 | Fingerprint write schema ships with the package | 1 | — | no | OK |
| GC-P03 | Refresh the device UTC offset periodically (DST) | 1 | — | no | OK |
| GC-P04 | Clock-skew alert and metric wired into the agent | 1 | GC-P03 | no | OK |
| GC-P05 | Hourly roster push carries card numbers | 1 | GC-P04 | no | OK |
| GC-P06 | Doctor checks the `token-ref` name the sink checker emits | 1 | — | no | OK |
| GC-P07 | Sink token resolved lazily through the credential provider | 1 | — | no | OK |
| GC-P08 | Token refresh on 401/403; permanent 4xx not retried for 24 h | 1 | GC-P07 | no | OK |
| GC-P09 | Correct the stale env-var comment in `agent_push.py` | 1 | GC-P08 | no | OK |
| GC-P10 | One poller per site: non-blocking advisory lock | 1 | GC-P01 | no | OK |
| GC-P11 | Write `agent.pid` and `status/device-probe.json` | 1 | GC-P10, GC-P06 | no | OK |
| GC-P12 | `export config` keeps `mnotify` sinks and valid sink keys | 1 | — | no | OK |
| GC-P13 | Self-contained `.pyz` release artifact | 1 | — | no | OK |
| GC-P14 | Container: all sites in the image; healthcheck fails when all parked | 1 | — | no | OK |
| GC-P15 | Detect a serial reset after a quiet period | 1 | GC-P05 | no | OK |
| GC-P16 | (split into GC-P16a/b/c) | 1 | — | no | SPLIT |
| GC-P16a | Prune already-pushed events from the local store | 1 | GC-P11 | no | OK (child) |
| GC-P16b | Mask card numbers in the Excel import results CSV | 1 | GC-P16a | no | OK (child) |
| GC-P16c | TTL cleanup for enrollment bundles and run journals | 1 | GC-P16b | no | OK (child) |
| GC-P17 | Linux container: agent against the demo device, push to a local sink | 2 (G3) | GC-P01, GC-P02, GC-P03, GC-P04, GC-P05, GC-P06, GC-P07, GC-P08, GC-P09, GC-P10, GC-P11, GC-P12, GC-P13, GC-P14, GC-P15, GC-P16a, GC-P16b, GC-P16c | no | OK |
| GC-P18 | Bench terminal: real `doctor` and one read-only poll cycle | 2 (G3) | GC-P17 | operator-session | OK |
| GC-P19 | Production install per site and enrollment import | 2 (G3/operator) | GC-P17, GC-P18, GC-P21 | operator | OK |
| GC-P20 | Read-only report: pushed events that were not granted punches | 1 | GC-P16a, GC-P12 | no | OK |
| GC-P21 | Alerts proven on the demo device: push failure, offline, clock skew | 2 (G3) | GC-P04, GC-P08, GC-P17 | no | OK |
| MN-P01 | Linux secret backend (file / env) for container alerts | 1 | — | no | DISCARD |

`GC-P16` is split because it carried three independent changes (event pruning, results-CSV
masking, bundle TTL). The three subcards are separate cards; no two cards were merged.

No gateclerk card is `GATED: sandbox`: none of them touches BC. The sandbox ruling applies
to the BC/app boards. If a gateclerk card is ever re-aimed at the sandbox, it must first do
a read-only GET of the installed version and confirm the `28.0.2.N` RC it needs is there.

## Existing files each card modifies

Use this table to compute lanes. Cards that modify the same existing file **must not run in
parallel**; the `Depends on` column above is the enforced order.

| ID | Existing files the card modifies |
|---|---|
| GC-P01 | `src/gateclerk/agent_cli.py` |
| GC-P02 | `src/gateclerk/migrate_fingerprints.py` |
| GC-P03 | `src/gateclerk/agent_loop.py` |
| GC-P04 | `src/gateclerk/agent_loop.py`, `src/gateclerk/agent_cli.py` |
| GC-P05 | `src/gateclerk/agent_loop.py` |
| GC-P06 | `src/gateclerk/doctor_cli.py` |
| GC-P07 | `src/gateclerk/agent_push.py`, `src/gateclerk/sink_writers.py` |
| GC-P08 | `src/gateclerk/agent_push.py` |
| GC-P09 | `src/gateclerk/agent_push.py` |
| GC-P10 | `src/gateclerk/agent_cli.py` |
| GC-P11 | `src/gateclerk/agent_cli.py`, `src/gateclerk/doctor_cli.py` |
| GC-P12 | `src/gateclerk/export_cli.py` |
| GC-P13 | `scripts/build_dist.py`, `scripts/smoke_artifact.py` |
| GC-P14 | `deploy/Dockerfile`, `deploy/container_healthcheck.sh` |
| GC-P15 | `src/gateclerk/agent_loop.py` |
| GC-P16a | `src/gateclerk/agent_cli.py`, `src/gateclerk/agent_store.py` |
| GC-P16b | `src/gateclerk/users_import.py` |
| GC-P16c | `src/gateclerk/migrate_bundle.py`, `src/gateclerk/migrate_cmds.py` |
| GC-P17 | new evidence file only (`docs/internal/gateclerk-finish/evidence/GC-P17-container.log`) |
| GC-P18 | new evidence file only (`docs/internal/gateclerk-finish/evidence/GC-P18-bench.log`) |
| GC-P19 | new evidence file only (`docs/internal/gateclerk-finish/evidence/GC-P19-<site>.md`) |
| GC-P20 | `src/gateclerk/export_cli.py`, `src/gateclerk/export_cmds.py` |
| GC-P21 | new test + evidence file only |
| MN-P01 | none (DISCARD) |

Lanes implied by the files:

- `agent_loop.py`: GC-P03 → GC-P04 → GC-P05 → GC-P15.
- `agent_cli.py`: GC-P01 → GC-P10 → GC-P11 → GC-P16a.
- `agent_push.py`: GC-P07 → GC-P08 → GC-P09.
- `doctor_cli.py`: GC-P06 → GC-P11.
- `export_cli.py`: GC-P12 → GC-P20.
- `users_import.py`: GC-P16b only; it still follows GC-P16a in the board order.
- `migrate_bundle.py` / `migrate_cmds.py`: GC-P16c only.

## Gate commands and baseline (run in this worktree, 2026-11-13)

| Command | Baseline result |
|---|---|
| `uv run --frozen pytest -q` | `2645 passed, 5 skipped, 1 deselected in 75.44s` |
| `uv run --frozen ruff check src/gateclerk` | `All checks passed!` |
| `uv run --frozen ruff check scripts` | `All checks passed!` |
| `uv run --frozen python -c "import gateclerk; print(gateclerk.__version__)"` | `0.1.0` |
| `PYTHONPATH="$HOME/dev/micro-notify/src" MICRO_NOTIFY_SECRETS=file MICRO_NOTIFY_SECRETS_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mn.XXXXXX")" python3 - <<'PY' …` | `backend: file`, `present: present`, `roundtrip: True` |

Every worker card uses the repo's full gate:

```bash
uv run --frozen pytest -q
uv run --frozen ruff check src/gateclerk
```

The container proof in GC-P17 and the bench proof in GC-P18 are not unit gates; they are
G3 evidence runs. Docker is not running in this worktree, so GC-P17's container command was
not executed here; the worker must run it on a host with Docker and stop with
`LEFT: Docker daemon unavailable` rather than invent a log.

**Sandbox baseline (measured 12:30 today):** sandbox `SANDBOX` runs `28.0.2.203` and all
seven headless suites pass there (setup 5, scan 6, schedule 8, calc 16, recalc 4, lock 9,
api 22 = 70 arms, 0 failed). No gateclerk card runs those suites or talks to BC; this fact
is for the BC/app boards and for GC-P19's operator record. If any gateclerk card is later
pointed at the sandbox, it must first do a read-only GET of the installed version and
compare it to the RC the card needs.

## Coverage

### Findings from the gateclerk audit

| Finding | Card | Note |
|---|---|---|
| GC-01 | GC-P01, GC-P20 | GC-P01 filters the queue; GC-P20 gives the operator the repair list. The ingest-side guard is APP-P19 (other repo). |
| GC-02 | GC-P02 | Embedded key tuple; no runtime `tests/` read. |
| GC-03 | GC-P03 | 15-minute refresh of the claimed offset. |
| GC-04 | GC-P05 | `CardInfo/Search` join; card-number rule pinned. |
| GC-05 | GC-P06 | `token-ref` singular. |
| GC-06 | GC-P07 | Lazy sink token through `resolve_ingest_token`. |
| GC-07 | GC-P08 | Token dropped on 401/403; 400/422 dead-letter immediately. The batching half is **not in the plan** (see below). |
| GC-08 | GC-P09 | Audit correction: not a defect; comment only. |
| GC-09 | GC-P04 | `observe_skew` wired to alert and health. |
| GC-10 | GC-P13 | Vendored runtime packages + isolated smoke. |
| GC-11 | GC-P10 | `flock` per site, exit 2 on a second poller. |
| GC-12 | GC-P11 | pidfile and probe-cache writers. |
| GC-13 | GC-P12 | `mnotify` and the four valid sink keys. |
| GC-14 | GC-P16a, GC-P16b, GC-P16c | Events, results CSV, bundles/journals. The ledger compaction half is **not in the plan**. |
| GC-15 | GC-P14 | `site-c` state dir; all-parked healthcheck. |
| GC-16 | GC-P15 | Cold-window reset probe. The audit's line numbers are stale; the defect is in `tick()`, not `_walk()`. |

### E rows owned by this board

| E row | Card | Note |
|---|---|---|
| E02 — see unlinked device users | GC-P05 | The roster carries the card number the unlinked view needs. |
| E03 — link one device user | GC-P05 | The BC dialog is BC-P06; the agent supplies `cardNo`. |
| E04 — link the same person on all devices | GC-P05 | Link-all is APP-P04/BC-P26; the roster is the agent input. |
| E05/E06 — review list and month grid | GC-P20 | Read-only diagnostic support; the screens are app/BC cards. |
| E22 — denied/unknown scan creates no punch | GC-P01, GC-P20 | Queue filter plus repair report. |
| G3 — agent, real | GC-P17, GC-P18, GC-P21 | Container demo, bench read-only cycle, alerts. |
| G3/operator install | GC-P19 | Production install and enrollment, operator only. |

## NOT IN PLAN

Findings met while verifying the cards that the plan does not assign a card to. No cards
were invented for them.

1. **GC-07's batching half.** `agent_push.drain` still sends one HTTP POST per queue row;
   the plan's GC-P08 names only token refresh and permanent-4xx handling. The audit's
   suggestion to batch multi-line JSONL is not covered.
2. **GC-14's `push-ledger.jsonl` growth.** GC-P16a prunes `events`, but the append-only
   ledger is not compacted or replaced by a SQLite marker. The plan's retention card names
   the event store, results CSV and bundle TTL, not the ledger.
3. **GC-08's receiver env prefix.** The actual receiver uses `GATECLERK_INGEST_TOKEN_<SITE>`
   / `GATECLERK_SITES`; the agent uses `GATECLERK_INGEST_TOKEN_<SITE>`. The plan says this is
   not a defect (separate processes, separate secret stores); GC-P09 fixes only the stale
   comment.
4. **Audit GC-01's `is_punch_candidate` SQL column.** There is no such column in `events`;
   the suggestion cannot be applied literally. GC-P01 uses the stored classification
   fields (`major`, `outcome`, `unknown_code`, `employee_no`, `verify_mode`) and pins them
   against `classify_event`.
5. **`docs/internal/PROD-GO-LIVE.md` duplicated `[Service]` line.** The credential drop-in
   example shows `[Service]` twice (around lines 118-120). It is a documentation defect,
   not a plan card; GC-P19 tells the operator to read the section, not to copy the block
   blindly.
6. **`deploy/CONTAINER.md` still says the image creates only `site-a` and `site-b`
   directories.** GC-P14 changes the Dockerfile default to `site-a site-b site-c`; the
   prose in `deploy/CONTAINER.md:44-50` is not updated by any plan card.
7. **GC-13's audit wording.** The audit calls the allowlist `_SINK_SCALAR_KEYS`; the real
   name in this worktree is `ALLOWED_SINK_KEYS` (`export_cli.py:174`). GC-P12 uses the real
   name.
