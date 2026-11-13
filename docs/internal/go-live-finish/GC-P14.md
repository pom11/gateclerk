# GC-P14 — Container: all sites in the image; healthcheck fails when every device is parked

BOARD: gateclerk   DEPENDS ON: —   GATED: no   COVERS: GC-15 / —

## WHY

The image pre-creates state directories only for `site-a site-b`; the documented third site
starts with a root-owned volume it cannot write. The Docker healthcheck also treats a
snapshot with `status == "degraded"` as healthy, so a container whose every terminal is
parked on a 401 lockout reports `healthy` while it delivers nothing. R7: the production
container must fail closed.

## VERIFY

```bash
grep -n 'ARG GATECLERK_SITES' deploy/Dockerfile
grep -n 'status not in\|degraded\|circuit_open' deploy/container_healthcheck.sh
```

Still broken while the output is:

```text
deploy/Dockerfile:77:ARG GATECLERK_SITES="site-a site-b"
deploy/container_healthcheck.sh:37:if status not in ("ok", "degraded"):
```

and there is no `circuit_open`/parked test in the healthcheck.

## FILES

- `deploy/Dockerfile:75-84` — `ARG GATECLERK_SITES="site-a site-b"` and the loop that
  `install -d` one state dir per site.
- `deploy/compose.yaml:55-76` — the `site-c` / second-site story (documented third site).
- `deploy/container_healthcheck.sh:30-41` — accepts any `ok`/`degraded` snapshot.
- `src/gateclerk/agent_health.py:195-206` — each device snapshot carries `circuit_open`
  and `circuit_parked_s`.
- `tests/test_deploy_templates.py:618-630` — the Dockerfile pin that currently expects
  `site-a site-b`.

## CHANGE

1. In `deploy/Dockerfile`, change the default:
   ```dockerfile
   ARG GATECLERK_SITES="site-a site-b site-c"
   ```
   Update the comment above it to say the list is the documented site set and that an
   operator adds a site with `--build-arg`.
2. In `deploy/container_healthcheck.sh`, after the `status` check and before the final
   `print`, add:
   ```python
   devices = snapshot.get("devices") or []
   if devices and all(bool(d.get("circuit_open")) for d in devices):
       print(f"unhealthy: every device is parked ({len(devices)} device(s))")
       sys.exit(1)
   ```
   Keep `ok` and `degraded` acceptable when at least one device is not parked; a single
   parked device is already `degraded` but the site can still deliver from the others.
   Handle an empty `devices` list as the existing status check does (no all-parked claim).
3. Do not change the snapshot age check or `GATECLERK_HEALTH_MAX_AGE_S`.

What must NOT change:

- One container per site, one state volume per site, non-root uid 10001.
- The `alerts`/`runtime` stage split and the micro-notify pin.
- The health snapshot format; no new field is needed.

## TESTS

Write `tests/test_gc_p14_container_health.py` first and run:

```bash
uv run --frozen pytest -q tests/test_gc_p14_container_health.py
```

Copy `tests/test_deploy_templates.py:618` for the Dockerfile assertion.

Tests:

- `test_dockerfile_creates_all_documented_site_dirs` — the default is
  `"site-a site-b site-c"`.
- `test_healthcheck_fails_when_every_device_is_parked` — run the embedded Python from
  `container_healthcheck.sh` against a temp snapshot with two devices both
  `"circuit_open": true`; exit 1 and the message names the parked state.
- `test_healthcheck_passes_when_one_device_is_healthy` — one parked, one open; exit 0.
- `test_healthcheck_still_fails_on_a_stale_or_error_snapshot` — age and status checks
  unchanged.

## GATE

```bash
uv run --frozen pytest -q
uv run --frozen ruff check src/gateclerk
```

## ACCEPT

- [ ] The image creates `site-a`, `site-b` and `site-c` state directories by default.
- [ ] All devices parked => healthcheck exits 1.
- [ ] One healthy device => healthcheck still accepts `degraded`.
- [ ] Snapshot age and status failures still exit 1.
- [ ] Full pytest and ruff are green.

## OUT

`deploy/compose.yaml` service definitions, the Docker stages, `src/gateclerk/agent_health.py`
and the status CLI.

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
