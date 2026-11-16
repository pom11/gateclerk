#!/bin/sh
# Docker HEALTHCHECK for the gateclerk agent image.
#
# The agent writes the P2-06 snapshot to <state dir>/health/agent.json after every pass
# (agent_cli.HEALTH_DIR_NAME + HEALTH_FILE_NAME, written atomically in _write_health).
# This check reads THAT file from the state volume: a running process with a stale
# snapshot is unhealthy, because the poll loop is what the snapshot reports on.
#
# GATECLERK_HEALTH_FILE     snapshot path (compose sets it per site)
# GATECLERK_HEALTH_MAX_AGE_S  oldest acceptable snapshot age; default 900 s = 3 x the
#                             default 300 s cadence (config.DEFAULT_CADENCE_S)
#
# A snapshot whose devices are ALL parked is unhealthy even at status "degraded": such a
# site is polling nothing, so the container must fail closed rather than look attached.
set -eu

snapshot="${GATECLERK_HEALTH_FILE:-/var/lib/gateclerk/site-a/health/agent.json}"
max_age="${GATECLERK_HEALTH_MAX_AGE_S:-900}"

exec python - "$snapshot" "$max_age" <<'PY'
import json
import os
import sys
import time

path, max_age = sys.argv[1], float(sys.argv[2])
try:
    age = time.time() - os.stat(path).st_mtime
    with open(path, encoding="utf-8") as handle:
        snapshot = json.load(handle)
except Exception as exc:
    print(f"unhealthy: no readable health snapshot at {path}: {exc}")
    sys.exit(1)

if age > max_age:
    print(f"unhealthy: health snapshot {path} is {age:.0f}s old (max {max_age:.0f}s)")
    sys.exit(1)

status = snapshot.get("status")
if status not in ("ok", "degraded"):
    print(f"unhealthy: health snapshot {path} has status {status!r}")
    sys.exit(1)

# "degraded" is deliverable while at least one terminal still polls: a single parked
# device is exactly what degraded means. When EVERY device sits on an open circuit the
# site moves no events at all, so the container must not report healthy (R7 fail closed).
# An empty device list is the agent's own "not polled yet" state — no all-parked claim.
devices = snapshot.get("devices") or []
if devices and all(bool(d.get("circuit_open")) for d in devices):
    print(f"unhealthy: every device is parked ({len(devices)} device(s))")
    sys.exit(1)

print(f"healthy: snapshot age {age:.0f}s, status={status}, site={snapshot.get('site')}")
PY
