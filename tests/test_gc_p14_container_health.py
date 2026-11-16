"""GC-P14 — the image pre-creates every documented site dir; the healthcheck fails closed.

Two container gaps, both of which make a broken container look fine:

1. `deploy/Dockerfile` pre-created state dirs for `site-a site-b` only. Docker gives an
   empty named volume the ownership of its image mount point, so the documented third
   site started with a root-owned `/var/lib/gateclerk/site-c` that uid 10001 cannot
   write — the agent dies on first write, outside this image's own view of why.
2. `deploy/container_healthcheck.sh` accepted any `ok`/`degraded` snapshot. A site whose
   every terminal is parked on a 401 lockout is `degraded` and delivers nothing, yet
   Docker reported `healthy` forever. R7: production fails closed.

Pinned here:

1. The `GATECLERK_SITES` default is the documented three-site set, and the loop really
   creates one dir per site owned by the non-root service uid.
2. Every device parked => exit 1, and the message says the site is parked.
3. One parked device among a working one => still accepted (`degraded` is deliverable).
4. Empty `devices` (a site that has never polled) is not an all-parked claim.
5. The snapshot age and `status` checks are unchanged, so a stale or `error` snapshot
   still exits 1.
6. The shipped shell script — not just the Python inside it — wires those two env vars
   through to that check, which is what Docker's `HEALTHCHECK` actually runs.

The snapshot fixtures are the real `HealthSnapshot`/`DeviceHealth` wire format, asserted
by round-tripping them through `HealthSnapshot.from_dict`: no new field is needed to make
the container fail closed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from gateclerk.agent_health import HealthSnapshot

REPO_ROOT = Path(__file__).resolve().parents[1]
DEPLOY = REPO_ROOT / "deploy"
DOCKERFILE = DEPLOY / "Dockerfile"
HEALTHCHECK = DEPLOY / "container_healthcheck.sh"

#: The shipped default in the script and the Dockerfile; a test that needs a different
#: bound passes max_age_s explicitly rather than editing this.
DEFAULT_MAX_AGE_S = 900


# --- the snapshot the agent writes ---------------------------------------------------------


def device_block(serial: str, *, parked: bool) -> dict[str, Any]:
    """One device in the shape `agent_health.DeviceHealth.to_dict()` writes.

    `circuit_open` is the field the healthcheck must read; the ages around it are what
    the real snapshot always carries alongside it.
    """
    return {
        "device_serial": serial,
        "circuit_open": parked,
        "circuit_parked_s": 1_260.0 if parked else 0.0,
        "checkpoint_serial": 4_210,
        "checkpoint_age_s": 12.5,
        "last_poll_ok_age_s": 1_260.0 if parked else 12.5,
        "metrics": [],
    }


def snapshot_body(
    *,
    status: str,
    parked: tuple[bool, ...],
    site: str = "site-a",
    reasons: tuple[str, ...] = (),
) -> dict[str, Any]:
    """A `HealthSnapshot` body for the named site, with one device per `parked` entry."""
    return {
        "site": site,
        "agent_version": "0.9.0",
        "status": status,
        "reasons": list(reasons),
        "checkpoint_stall_s": 900.0,
        "devices": [
            device_block(f"SER-{index:04d}", parked=p) for index, p in enumerate(parked, 1)
        ],
        "site_metrics": [],
    }


# --- running the healthcheck the container does -------------------------------------------


def embedded_python() -> str:
    """The Python between the script's `<<'PY'` heredoc opener and its closing `PY`."""
    lines = HEALTHCHECK.read_text(encoding="utf-8").splitlines()
    opener = next(i for i, line in enumerate(lines) if line.endswith("<<'PY'"))
    closer = next(i for i in range(len(lines) - 1, opener, -1) if lines[i] == "PY")
    body = "\n".join(lines[opener + 1 : closer]) + "\n"
    assert "sys.exit" in body, f"healthcheck heredoc not located in {HEALTHCHECK}"
    return body


def write_snapshot(tmp_path: Path, body: dict[str, Any], *, age_s: float = 0.0) -> Path:
    """Write the snapshot the way the agent does: the file's mtime is its freshness."""
    path = tmp_path / "agent.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body), encoding="utf-8")
    if age_s:
        stamp = time.time() - age_s
        os.utime(path, (stamp, stamp))
    return path


def run_embedded_check(
    tmp_path: Path,
    body: dict[str, Any],
    *,
    age_s: float = 0.0,
    max_age_s: float = DEFAULT_MAX_AGE_S,
) -> subprocess.CompletedProcess[str]:
    """Run the healthcheck's Python with argv as `exec python - "$snapshot" "$max_age"` does."""
    path = write_snapshot(tmp_path, body, age_s=age_s)
    return subprocess.run(  # noqa: S603 — argv list, no shell, this interpreter
        [sys.executable, "-", str(path), str(max_age_s)],
        input=embedded_python(),
        capture_output=True,
        text=True,
        check=False,
    )


def run_shipped_script(
    tmp_path: Path,
    body: dict[str, Any],
    *,
    age_s: float = 0.0,
    max_age_s: float = DEFAULT_MAX_AGE_S,
) -> subprocess.CompletedProcess[str]:
    """Run `deploy/container_healthcheck.sh` itself through `sh`, as Docker's HEALTHCHECK does.

    The script calls `exec python`, so a `python` resolving to this interpreter goes on
    PATH in a throwaway dir; everything else in the environment is inherited.
    """
    path = write_snapshot(tmp_path, body, age_s=age_s)
    shim = tmp_path / "bin"
    shim.mkdir(exist_ok=True)
    launcher = shim / "python"
    launcher.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    launcher.chmod(0o755)
    sh = shutil.which("sh") or "/bin/sh"
    env = {
        **os.environ,
        "PATH": f"{shim}{os.pathsep}{os.environ.get('PATH', '')}",
        "GATECLERK_HEALTH_FILE": str(path),
        "GATECLERK_HEALTH_MAX_AGE_S": str(max_age_s),
    }
    return subprocess.run(  # noqa: S603 — argv list, no shell string, absolute sh
        [sh, str(HEALTHCHECK)],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


# --- 1. the image creates every documented site's state dir -------------------------------


def test_dockerfile_creates_all_documented_site_dirs() -> None:
    """The default `GATECLERK_SITES` must be the documented three-site set.

    Copied in shape from `tests/test_deploy_templates.py`'s Dockerfile pin: the state
    dirs have to exist in the image so a named volume inherits uid 10001 instead of
    Docker's root-owned empty mount point.
    """
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert 'ARG GATECLERK_SITES="site-a site-b site-c"' in text, (
        "every documented site's state dir must exist in the image, or the third site "
        "starts on a root-owned volume uid 10001 cannot write"
    )
    # The default must be the thing the loop consumes, not a comment beside it.
    assert "for site in ${GATECLERK_SITES}" in text
    assert "install -d -o gateclerk -g gateclerk" in text
    # Must NOT change: the service account stays the unprivileged uid 10001.
    assert "-u 10001" in text


# --- 2..4. the all-parked rule --------------------------------------------------------------


def test_healthcheck_fails_when_every_device_is_parked(tmp_path: Path) -> None:
    """Every device parked on a 401 lockout delivers nothing: the container is unhealthy."""
    result = run_embedded_check(
        tmp_path, snapshot_body(status="degraded", parked=(True, True), reasons=("poll_fail",))
    )
    assert result.returncode == 1, f"stdout was {result.stdout!r}"
    out = result.stdout.lower()
    assert "unhealthy" in out, f"stdout was {result.stdout!r}"
    assert "parked" in out, f"the message must name the parked state: {result.stdout!r}"
    assert "2" in out, f"the message should count the parked devices: {result.stdout!r}"


def test_healthcheck_passes_when_one_device_is_healthy(tmp_path: Path) -> None:
    """One parked terminal among working ones is `degraded`, and the site still delivers."""
    result = run_embedded_check(
        tmp_path, snapshot_body(status="degraded", parked=(True, False), reasons=("poll_fail",))
    )
    assert result.returncode == 0, f"stdout was {result.stdout!r}"
    assert "healthy" in result.stdout.splitlines()[0].lower()
    assert "degraded" in result.stdout, f"status must be reported: {result.stdout!r}"


def test_healthcheck_accepts_a_snapshot_with_no_devices_yet(tmp_path: Path) -> None:
    """An empty `devices` list is not an all-parked claim — `all()` of nothing is vacuous."""
    result = run_embedded_check(tmp_path, snapshot_body(status="ok", parked=()))
    assert result.returncode == 0, f"stdout was {result.stdout!r}"
    assert "parked" not in result.stdout.lower()


def test_healthcheck_still_fails_on_a_stale_or_error_snapshot(tmp_path: Path) -> None:
    """The age check and the status check are unchanged by the parked rule."""
    healthy = snapshot_body(status="ok", parked=(False,))
    stale = run_embedded_check(tmp_path / "stale", healthy, age_s=DEFAULT_MAX_AGE_S + 60)
    assert stale.returncode == 1, f"stdout was {stale.stdout!r}"
    assert "old" in stale.stdout.lower(), f"the age message must say why: {stale.stdout!r}"

    errored = run_embedded_check(tmp_path / "errored", snapshot_body(status="error", parked=()))
    assert errored.returncode == 1, f"stdout was {errored.stdout!r}"
    assert "status" in errored.stdout.lower(), f"must name the check: {errored.stdout!r}"

    # And a fresh, non-parked snapshot within the bound is accepted: the bound is 900 s,
    # not something the parked rule moved.
    fresh = run_embedded_check(tmp_path / "fresh", healthy, age_s=DEFAULT_MAX_AGE_S - 60)
    assert fresh.returncode == 0, f"stdout was {fresh.stdout!r}"


# --- 5. the fixtures are the real wire format ---------------------------------------------


def test_parked_snapshot_needs_no_new_field() -> None:
    """The fixtures parse as `HealthSnapshot`, so `circuit_open` really is the carrier."""
    snapshot = HealthSnapshot.from_dict(
        snapshot_body(status="degraded", parked=(True, True), reasons=("poll_fail",))
    )
    assert [d.circuit_open for d in snapshot.devices] == [True, True]
    assert snapshot.devices[0].circuit_parked_s == 1_260.0


# --- 6. the shipped script, not just the Python inside it ----------------------------------


def test_shipped_script_wires_its_env_vars_through(tmp_path: Path) -> None:
    """Docker runs the shell script: it must pass both env vars into the check."""
    parked = run_shipped_script(
        tmp_path / "parked", snapshot_body(status="degraded", parked=(True, True))
    )
    assert parked.returncode == 1, f"stdout was {parked.stdout!r} stderr {parked.stderr!r}"
    assert "parked" in parked.stdout.lower()

    working = run_shipped_script(
        tmp_path / "working", snapshot_body(status="degraded", parked=(False, True))
    )
    assert working.returncode == 0, f"stdout was {working.stdout!r} stderr {working.stderr!r}"

    # GATECLERK_HEALTH_MAX_AGE_S is honoured by the script, not hardcoded in the Python.
    too_old = run_shipped_script(
        tmp_path / "too_old",
        snapshot_body(status="ok", parked=(False,)),
        age_s=120,
        max_age_s=60,
    )
    assert too_old.returncode == 1, f"stdout was {too_old.stdout!r}"
    assert "old" in too_old.stdout.lower()
