# GC-P17 — Linux container: agent against the demo device, push to a local sink

BOARD: gateclerk   DEPENDS ON: GC-P01, GC-P02, GC-P03, GC-P04, GC-P05, GC-P06, GC-P07, GC-P08, GC-P09, GC-P10, GC-P11, GC-P12, GC-P13, GC-P14, GC-P15, GC-P16a, GC-P16b, GC-P16c   GATED: no   COVERS: G3 / —

## WHY

The production shape is Alpine in a container. The unit tests run on the dev Mac with a
venv; they do not prove the image starts, polls a device on loopback, stores, queues and
delivers to a local sink. This is the G3 container proof, with no real terminal and no BC
contact. It uses the repo's own demo device and demo walkthrough (`gateclerk demo demo`),
which are synthetic and loopback-only.

## VERIFY

```bash
uv run --frozen gateclerk demo --help
uv run --frozen gateclerk demo demo --help
```

Both must exit 0. The demo command is `gateclerk demo demo`; its fake device is
`gateclerk.demo_device.DemoDevice`, bound to loopback, and its local sinks are a CSV
writer and a mock TLS ingest (see `src/gateclerk/demo_walkthrough.py:1-70`).

If either command is missing, stop: the repo's demo surface changed and this card must be
re-scoped before any container work.

## FILES

- `deploy/Dockerfile:95-117` — the image entrypoint is `gateclerk`; the default target
  (`alerts`) has `gateclerk` and `mnotify` on `PATH`.
- `deploy/CONTAINER.md:20-40` — build command:
  `docker build -f deploy/Dockerfile -t gateclerk-agent:local .`.
- `src/gateclerk/demo_cmds.py:134-200` — `demo demo` options: `--root`, `--ticks`,
  `--keep`, `-o`.
- `src/gateclerk/demo_walkthrough.py:559-690` — `run_demo_walkthrough` wires the real
  `SiteAgent.tick()` to `DemoDevice`, a CSV sink and a mock TLS ingest.
- `src/gateclerk/demo_walkthrough.py:345-399` — the mock ingest needs the `openssl` CLI;
  the runtime image does not install it, so the proof image adds it in a disposable layer.

## CHANGE

No product code. Produce and commit the evidence file described below. The card is a proof
card; the only repo change is
`docs/internal/gateclerk-finish/evidence/GC-P17-container.log`.

1. Build the runtime image from the repo root:
   ```bash
   docker build -f deploy/Dockerfile -t gateclerk-agent:local .
   ```
2. Create a disposable proof image that adds the `openssl` CLI. Write the Dockerfile under
   the session temp directory, not in the repo:
   ```bash
   mkdir -p "${TMPDIR:-/tmp}/gc-p17"
   cat > "${TMPDIR:-/tmp}/gc-p17/Dockerfile" <<'EOF'
   FROM gateclerk-agent:local
   USER root
   RUN apk add --no-cache openssl
   USER 10001:10001
   EOF
   docker build -f "${TMPDIR:-/tmp}/gc-p17/Dockerfile" -t gateclerk-agent:gc17 .
   ```
3. Run the full demo loop inside the container. `/tmp` is the only writable path; use a
   tmpfs. Capture stdout and stderr:
   ```bash
   docker run --rm --read-only --tmpfs /tmp:rw,size=64m \
     gateclerk-agent:gc17 \
     demo demo --root /tmp/gc17-demo --ticks 2 --keep -o json \
     | tee "${TMPDIR:-/tmp}/gc-p17/run.json"
   ```
4. Copy the evidence into the repo. The log must contain: image id, `demo demo` JSON with
   `csv.rows > 0`, the mock sink's `lines > 0`, and the two ticks' per-sink counters. Save
   it as `docs/internal/gateclerk-finish/evidence/GC-P17-container.log`:
   ```bash
   mkdir -p docs/internal/gateclerk-finish/evidence
   {
     docker image inspect gateclerk-agent:gc17 --format 'image={{.Id}}'
     cat "${TMPDIR:-/tmp}/gc-p17/run.json"
   } > docs/internal/gateclerk-finish/evidence/GC-P17-container.log
   ```
5. Do not point the demo at BC. It has no `push_target`; both sinks are local. No device
   write, no network beyond loopback.

What must NOT change:

- `deploy/Dockerfile`, `deploy/compose.yaml` and the product demo modules. The proof
  Dockerfile lives only in `${TMPDIR:-/tmp}`.
- No credential value, real host, tenant name or LAN address in the log.
- The container runs as uid 10001; do not `--user root` for the demo run.

## TESTS

The proof is the container log, not a pytest. Add one offline test if the evidence file is
committed: `tests/test_gc_p17_evidence.py` with
`test_container_log_shows_a_delivered_demo_run` — read the log and assert `"csv"` and
`"lines"` appear, and no `192.168.` / `10.` / `172.16.` address appears.

Run:

```bash
uv run --frozen pytest -q tests/test_gc_p17_evidence.py
```

## GATE

```bash
uv run --frozen pytest -q
```

The container commands above are the G3 proof, not the unit gate. Docker must be running on
the worker host; if it is not, stop with `LEFT: Docker daemon unavailable` rather than
faking the log.

## ACCEPT

- [ ] `gateclerk-agent:local` builds from `deploy/Dockerfile`.
- [ ] The proof image adds `openssl` only.
- [ ] `demo demo --ticks 2` exits 0 inside the container.
- [ ] The JSON shows CSV rows and mock-ingest lines greater than zero.
- [ ] The log is committed and contains no real host, name, tenant or secret.
- [ ] Full pytest is green.

## OUT

BC, the sandbox tenant, real terminals, the production compose service, mnotify delivery,
and `deploy/Dockerfile`. This card is local-only.

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

DONE: PR URL, merge commit, and the evidence path.
LEFT: anything not proven, with the reason.
