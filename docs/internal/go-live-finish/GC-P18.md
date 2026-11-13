# GC-P18 — Bench terminal: real `doctor` and one read-only poll cycle

BOARD: gateclerk   DEPENDS ON: GC-P17   GATED: operator-session   COVERS: G3 / —

## WHY

G3 requires one real read-only cycle against the bench terminal, run by the operator on the
dev Mac. This card proves the real `gateclerk doctor --probe` and one `agent run --once`
against the bench unit, with no BC push and no production store. It is the only gateclerk
card that talks to a real terminal; it is operator-session, not cluster, and it never writes
to the device.

## VERIFY

```bash
uv run --frozen gateclerk doctor --help
uv run --frozen gateclerk agent run --help
```

Both must exit 0. The operator must have a bench `sites.toml` and a bench state directory;
the card uses `<BENCH_SITE>`, `<BENCH_CONFIG>` and `<BENCH_STATE>` placeholders. No LAN
address, host name or credential is written into this card or the evidence file.

## FILES

- `docs/internal/PROD-GO-LIVE.md:358-381` — the read-only doctor command and the rule that
  `--probe` performs only `deviceInfo` and `System/time`.
- `docs/internal/PROD-GO-LIVE.md:430-490` — the switch-over order; this card is the bench
  proof before the production install.
- `src/gateclerk/doctor_cmds.py:39-69` — `doctor --probe` is read-only.
- `src/gateclerk/agent_cmds.py:90-118` — `agent run --once` is one poll; it stores and may
  push if a target is configured. This card removes the target for the bench run.
- `src/gateclerk/agent_cli.py:1130-1172` — `--state-root` resolution.

## CHANGE

No product code. The operator runs the steps and records evidence in
`docs/internal/go-live-finish/evidence/GC-P18-bench.log`.

1. Make a bench copy of the config with no push target and no sinks, under
   `${TMPDIR:-/tmp}/gc-p18/sites.toml`. Use the existing bench block but remove
   `push_target` and every `[[site.sink]]`. Set `db_path` to a scratch path under the same
   temp root. Do not copy any credential value into the file.
2. Run the read-only doctor against the real bench terminal:
   ```bash
   uv run --frozen gateclerk doctor \
     --config "${TMPDIR:-/tmp}/gc-p18/sites.toml" \
     --site <BENCH_SITE> \
     --state-root "${TMPDIR:-/tmp}/gc-p18/state" \
     --probe -o json
   ```
   Expected: exit 0; `device` row `pass` with model/serial and `clock skew ... within 120s`
   (or a `warn` for skew, which is a real finding, not a card failure). If the credential
   is missing, stop and record `LEFT:`.
3. Run exactly one poll cycle with no push:
   ```bash
   uv run --frozen gateclerk agent run \
     --config "${TMPDIR:-/tmp}/gc-p18/sites.toml" \
     --site <BENCH_SITE> \
     --state-root "${TMPDIR:-/tmp}/gc-p18/state" \
     --once -o json
   ```
   Expected: exit 0; `ticks_ok=1`, `ticks_refused=0`, `pushed=0`, `queued=0` (no sink), and
   a checkpoint serial/time in the JSON.
4. Prove the store is local and the checkpoint moved:
   ```bash
   uv run --frozen gateclerk status \
     --config "${TMPDIR:-/tmp}/gc-p18/sites.toml" \
     --site <BENCH_SITE> \
     --state-root "${TMPDIR:-/tmp}/gc-p18/state" -o json
   ```
   Expected: `agent` row reports the pidfile as `running` during the run or the health
   snapshot after it; `device` reports the cached probe (GC-P11). A `warn` for a stale
   snapshot after `--once` is acceptable; the checkpoint is the proof.
5. Save the three JSON outputs and the command lines (with placeholders, not real values)
   to `docs/internal/go-live-finish/evidence/GC-P18-bench.log`. The operator initials and
   dates the file.

What must NOT change:

- No device write, no `--apply`, no `migrate`, no `users import`.
- No BC push: the bench config has no `push_target` and no sinks.
- No production state root and no production credential.
- Do not commit the bench `sites.toml`, a host, a serial, a person's name or a secret.

## TESTS

The proof is the operator log. If the log is committed, add
`tests/test_gc_p18_evidence.py`:
- `test_bench_log_has_a_doctor_and_one_tick` — the log contains `"section": "device"`,
  `"ticks_ok": 1` and `"pushed": 0`.
- `test_bench_log_carries_no_private_address_or_name` — no RFC1918 address, no
  `employee_no`/`name` field.

Run:

```bash
uv run --frozen pytest -q tests/test_gc_p18_evidence.py
```

## GATE

```bash
uv run --frozen pytest -q
```

This is a proof card; the real gate is the operator's two commands above. This card is
GATED: operator-session, not cluster. Do not run it from the cluster.

## ACCEPT

- [ ] `doctor --probe` exits 0 against the bench terminal.
- [ ] One `agent run --once` exits 0 with `ticks_ok=1`, `pushed=0`.
- [ ] The local checkpoint advanced and no production store was touched.
- [ ] `status` reads the local store and cached probe.
- [ ] Evidence is committed with placeholders only.
- [ ] Full pytest is green.

## OUT

Production hosts, BC, the sandbox tenant, the bench terminal's configuration, enrollment,
and any device write. This card does not start a service.

## HANDOFF

GATED: operator-session. No branch, no PR, no cluster work.

The operator runs the steps, commits the evidence file on a docs branch if the board asks
for a PR, and reports:

DONE: evidence path, date, initials.
LEFT: the step that stopped and why.
