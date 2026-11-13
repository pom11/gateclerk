"""Card GC-P11: the two files `gateclerk status` READS must have a writer.

`status_cli` reads `<state-root>/agent.pid` (`PIDFILE_NAME`) and
`<state-root>/status/device-probe.json` (`PROBE_CACHE_PARTS`) but nothing in the tree ever
wrote either one. The consequence was a status screen that could not tell the truth (R2):
the agent line always degraded to `pid=None` and the device line always said
`warn: unknown — run: gateclerk doctor` even immediately after a probe had run.

The five pins are the card's five DoD tests, 1:1 to test names:

(1) `run_doctor` writes a fresh, `ok: true` probe cache and `status` reports the device ok;
(2) a raising prober writes `ok: false` and `status` reports `unreachable` (exit 4);
(3) `SiteAgent.run()` writes `agent.pid` containing our PID, visible from inside the tick;
(4) `close()` removes the pidfile it owns;
(5) a pidfile whose content is not our PID is left alone (the owner is another process).

Three more pin the rules the five above leave free: a warn probe caches `ok: true` (the
card's pass-or-warn rule — a skewed clock is not an unreachable device), `--state-root`
reaches the writer (otherwise doctor and status disagree about which file is the cache),
and a poller refused by GC-P10's lock writes no pidfile at all (a process that never
polled must not hand `status` a live PID).

Offline by construction: a fake device prober and a fake TLS prober are injected into
`run_doctor` (no socket), the keychain probe is injected (no macOS prompt), the agent tests
run the real `SiteAgent` over `AgentHarness`'s FakeDevice, and `status` is called through
`collect_site_status` — the same read-only path the CLI takes, which this file also pins as
side-effect-free by asserting the cache it reads is the one `doctor` wrote.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from gateclerk import doctor_cli, status_cli
from gateclerk.agent_cli import (
    PollerAlreadyRunning,
    SiteAgent,
    SiteTickReport,
    acquire_poller_lock,
    release_poller_lock,
)
from gateclerk.config import ConfigSurface, site_from_args
from gateclerk.exceptions import IsapiError
from gateclerk.status_cli import PIDFILE_NAME, PROBE_CACHE_PARTS
from test_cli_doctor import (
    FIXED_NOW,
    PLANTED_DEVICE_PW,
    PLANTED_INGEST_TOK,
    _seed_store,
    _write_fixture_config,
)
from test_p2_07b_agent_cli import AgentHarness, seeded_device

SITE = "demo-a"


# --- the doctor side: the device-probe cache --------------------------------------------------


def _run_doctor(config_path: Path, *, state_root: Path, device_prober: Any) -> dict[str, Any]:
    """`run_doctor` with every network/secrets seam injected, rows keyed by section.

    The env carries planted secrets so the "never a payload or a secret" rule is testable
    against the cache file itself, and `now` is the fixed instant the status call below
    uses — otherwise the 60-second TTL (`DEVICE_PROBE_MAX_AGE_S`) is a race, not a fact.
    """
    rows, _code = doctor_cli.run_doctor(
        config_path=config_path,
        site=SITE,
        state_root=state_root,
        env={
            "GATECLERK_192_0_2_10_PASSWORD": PLANTED_DEVICE_PW,
            "GATECLERK_INGEST_TOKEN_DEMO_A": PLANTED_INGEST_TOK,
        },
        now=FIXED_NOW,
        keychain_probe=lambda _service, _account: None,
        device_prober=device_prober,
        tls_prober=lambda _host, _port: "TLSv1.3 cert verified",
    )
    return {row.section: row for row in rows}


def _fixture(tmp_path: Path) -> Path:
    """The `test_cli_doctor` fixture: a store, a csv sink dir, and one sites.toml.

    `db_path` is absolute there, so `resolve_state_root` lands on `tmp_path` and the cache
    path this test asserts is the same one `status_cli` computes — one resolution rule,
    writer and reader agreeing (the whole point of the card).
    """
    db_path = tmp_path / "gateclerk-demo-a.sqlite3"
    csv_sink = tmp_path / "sinks" / "events.csv"
    csv_sink.parent.mkdir(parents=True, exist_ok=True)
    _seed_store(db_path)
    return _write_fixture_config(tmp_path, db_path=db_path, csv_sink_path=csv_sink)


def _status_device_section(cfg_file: Path, state_root: Path) -> dict[str, Any]:
    """The `status` device line, through the read-only collector the CLI uses."""
    site = site_from_args(site=SITE, config_path=cfg_file, surface=ConfigSurface.CLI)
    row = status_cli.collect_site_status(site, state_root=state_root, now=FIXED_NOW)
    return {"row": row, **row["sections"]["device"]}


def _read_probe_cache(state_root: Path) -> tuple[dict[str, Any], str]:
    cache = state_root.joinpath(*PROBE_CACHE_PARTS)
    raw = cache.read_text(encoding="utf-8")
    return json.loads(raw), raw


def test_doctor_writes_a_fresh_device_probe(tmp_path: Path) -> None:
    """A reachable probe lands in the cache and `status` reads it back as ok (ACCEPT 1+2)."""
    cfg_file = _fixture(tmp_path)
    by_section = _run_doctor(
        cfg_file,
        state_root=tmp_path,
        device_prober=lambda _site, **_kw: ("model=DS-K1T341 serial=DEMO-SN-01", 5.0),
    )
    assert by_section["device"].status == "pass"

    payload, raw = _read_probe_cache(tmp_path)
    assert payload["ok"] is True
    assert datetime.fromisoformat(payload["checked_at"]) == FIXED_NOW
    assert "model=DS-K1T341 serial=DEMO-SN-01" in payload["detail"]
    # The cache is the redacted row text, never a credential (the card's detail rule).
    assert PLANTED_DEVICE_PW not in raw
    assert PLANTED_INGEST_TOK not in raw

    section = _status_device_section(cfg_file, tmp_path)
    assert section["state"] == "ok"
    assert section["exit"] is None
    assert section["text"].startswith("ok (")
    assert section["row"]["device"] == section["text"]


def test_doctor_writes_a_failed_probe(tmp_path: Path) -> None:
    """An unreachable device caches `ok: false` with the row's own text; status says so."""
    cfg_file = _fixture(tmp_path)

    def _refused(_site: Any, **_kw: Any) -> tuple[str, float | None]:
        raise IsapiError(f"connection refused: {'x' * 400}")

    by_section = _run_doctor(cfg_file, state_root=tmp_path, device_prober=_refused)
    assert by_section["device"].status == "fail"

    payload, raw = _read_probe_cache(tmp_path)
    assert payload["ok"] is False
    assert "connection refused" in payload["detail"]
    # The cache is a bounded document: the row may carry a long transport message, the
    # file on disk carries at most the card's 160 characters.
    assert len(payload["detail"]) <= 160
    assert PLANTED_DEVICE_PW not in raw
    assert PLANTED_INGEST_TOK not in raw

    section = _status_device_section(cfg_file, tmp_path)
    # The card forbids touching status' verdict mapping: a cached failure is the exit-4
    # `unreachable` line, not a warn and not a silent ok.
    assert section["state"] == "fail"
    assert section["exit"] == 4
    assert section["text"].startswith("unreachable (")
    assert "connection refused" in section["text"]


# --- the doctor side: the ok=true half ---------------------------------------------------------


def test_a_warn_probe_is_cached_as_reachable(tmp_path: Path) -> None:
    """A clock skew is the doctor's complaint, not an unreachable device.

    The card's rule is `ok=True` for pass AND warn: `status`' device line answers "did the
    terminal answer?", and an `ok: false` here would put a working door controller on the
    operator's screen as an exit-4 `unreachable` line.
    """
    cfg_file = _fixture(tmp_path)
    by_section = _run_doctor(
        cfg_file,
        state_root=tmp_path,
        device_prober=lambda _site, **_kw: ("model=DS-K1T341 serial=DEMO-SN-01", 185.0),
    )
    assert by_section["device"].status == "warn"

    payload, _raw = _read_probe_cache(tmp_path)
    assert payload["ok"] is True
    assert "clock skew" in payload["detail"]

    section = _status_device_section(cfg_file, tmp_path)
    assert section["state"] == "ok"
    assert section["exit"] is None


def test_the_cache_lands_in_the_state_root_not_the_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--state-root` reaches the writer, or `doctor` and `status` disagree about the file.

    The README layout: a parent root holding one directory per site, with the store's
    relative default name. Here only `agent_cli.resolve_state_root(site, state_root)` can
    say where the cache goes; a `run_doctor` that forgot to thread `state_root` (the card's
    CHANGE § 3) would resolve it against the cwd instead and the operator's `status` would
    still read `unknown`. The `chdir` is what makes that failure a failed assertion rather
    than a file written into the repo.
    """
    db_name = "gateclerk-demo-a.sqlite3"
    per_site = tmp_path / "state" / SITE
    per_site.mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "sites.toml").write_text(
        f"""[[site]]
name = "{SITE}"
host = "192.0.2.10"
iana_tz = "Europe/Bucharest"
device_code = "DEMO-A-1"
db_path = "{db_name}"
""",
        encoding="utf-8",
    )
    cfg_file = tmp_path / "sites.toml"
    _seed_store(per_site / db_name)

    _run_doctor(
        cfg_file,
        state_root=tmp_path / "state",
        device_prober=lambda _site, **_kw: ("model=DS-K1T341 serial=DEMO-SN-01", 5.0),
    )

    assert per_site.joinpath(*PROBE_CACHE_PARTS).exists(), "the site's own state dir owns the cache"
    assert not (tmp_path / "status" / "device-probe.json").exists()

    section = _status_device_section(cfg_file, tmp_path / "state")
    assert section["state"] == "ok"


# --- the agent side: the pidfile ---------------------------------------------------------------


def _pidfile(harness: AgentHarness) -> Path:
    return harness.state_root / PIDFILE_NAME


def test_a_refused_start_writes_no_pidfile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The poller that lost GC-P10's lock leaves no pidfile behind.

    The pid lives INSIDE the lock's scope precisely so a refusal cannot write it: a second
    `agent run` that never polled would otherwise hand `gateclerk status` a live PID for a
    process that is about to exit with a config error, which is the false-alive line R2
    exists to prevent.
    """
    harness = AgentHarness(tmp_path, seeded_device(), monkeypatch)
    agent = harness.api_agent()
    held = acquire_poller_lock(harness.state_root, agent.site.name)
    try:
        with pytest.raises(PollerAlreadyRunning):
            agent.run(once=True)
        # Asserted BEFORE `close()`: shutdown clears our own pidfile, so checking after the
        # finally would pass even if `run()` had written one before losing the lock.
        assert not _pidfile(harness).exists(), "a poller that never polled leaves no pid behind"
    finally:
        agent.close()
        release_poller_lock(held)


def test_agent_writes_the_pidfile_during_a_tick(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Inside a live tick the pidfile exists and names THIS process (ACCEPT 3).

    The spy delegates to the real `tick()` rather than replacing it: `run()` aggregates the
    returned `SiteTickReport`s into the `SiteRunReport`, and a stub would pin the write
    against a run shape that never happens in production.
    """
    harness = AgentHarness(tmp_path, seeded_device(), monkeypatch)
    agent = harness.api_agent()
    pidfile = _pidfile(harness)
    seen: list[str] = []
    real_tick = SiteAgent.tick

    def _spy(self: SiteAgent) -> SiteTickReport:
        seen.append(pidfile.read_text(encoding="utf-8"))
        return real_tick(self)

    monkeypatch.setattr(SiteAgent, "tick", _spy)
    try:
        agent.run(once=True)
    finally:
        agent.close()

    assert seen == [f"{os.getpid()}\n"]


def test_agent_removes_its_pidfile_on_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Clean shutdown clears the file so `status` stops claiming a live agent."""
    harness = AgentHarness(tmp_path, seeded_device(), monkeypatch)
    agent = harness.api_agent()
    pidfile = _pidfile(harness)
    try:
        agent.run(once=True)
        assert pidfile.read_text(encoding="utf-8").strip() == str(os.getpid())
    finally:
        agent.close()
    assert not pidfile.exists()


def test_a_foreign_pidfile_is_not_removed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`close()` deletes only its OWN pidfile — another owner's line is not ours to clear.

    The sequence is the restart race: our run ends, the next poller (or a unit under
    `Restart=always`) writes its PID, and an unguarded `unlink()` here would erase the
    evidence that a poller is alive — turning a running agent into `status`' `pid=None`.
    """
    harness = AgentHarness(tmp_path, seeded_device(), monkeypatch)
    agent = harness.api_agent()
    pidfile = _pidfile(harness)
    agent.run(once=True)
    foreign = f"{os.getpid() + 1}\n"
    pidfile.write_text(foreign, encoding="utf-8")

    agent.close()

    assert pidfile.exists(), "a pidfile we do not own must survive our shutdown"
    assert pidfile.read_text(encoding="utf-8") == foreign
