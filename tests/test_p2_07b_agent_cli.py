"""Card P2-07b: `gateclerk agent run|ack|deadletter` — the thin wiring to P2-03/04/05/06.

BINDING SPEC: docs/P2-SITE-AGENT.md §2a-§2e + the card's BINDING block. This module owns
`src/gateclerk/agent_cli.py` (the composition) and the `agent` subcommand group on `gateclerk.cli`.
It owns NO rule: the cadence, the walk, the UPSERT, the checkpoint, the backoff, the 24 h
dead-letter bound, the park and the re-probe grid all live in the P2 module that shipped them,
and are asserted here through those owners' own APIs — never through the CLI's stdout text.

THE CLOCK SEAM (what wedged the last attempt) and the recipe, used rather than re-derived
-----------------------------------------------------------------------------------------
`--once` takes its "now" through the same injected clock P2-03's loop already uses. There is
no `--now` flag on the CLI — an operator must never be able to fake "now" into a payroll
poller — so the CLI path resolves the module-level `agent_cli._now` and `build_site_agent`
threads whatever it resolves to into EVERY seam: each `build_device_loop`, `AlertPolicy`,
`AgentHealthCollector`, and `SiteAgent` (whose reading is what `queue_new_events` and `drain`
receive as `now`). A test therefore freezes the whole run with one monkeypatch, and seeds
events by COMPUTING the fake's wall digits from that same instant through the fake's
`claimed_offset_min` — `wall = UTC + claimed`, which is `tests/fakedevice.py`'s own filtering
arithmetic, factored into `wall_digits()` below. Seed with raw wall digits guessed at by eye
and the window the loop asks for and the rows the fake returns are two different universes;
that mismatch is the loop the previous attempt spent its budget re-deriving.

The four DoD cases, 1:1 to test names
-------------------------------------
(1) `agent run --site` against FakeDevice + `stub://` completes ONE tick, stores rows, and the
    stub ingest shows the pushed lines — rc 0, asserted against the store and the file.
(2) `agent ack` clears a park — asserted via P2-05's own `parked()` / `attempt_allowed()`.
(3) `deadletter list` shows a dead-lettered row; `delete` needs the explicit id.
(4) the existing CLI surface is unchanged — the pre-P2-07b command tree is pinned exactly and
    the `agent` group is the only addition.

Offline by construction: CliRunner + FakeDevice + `stub://` + the frozen clock; the autouse
`netoff` guard would still kill a socket and none is opened. No real host, serial or secret
appears (fixtures carry MASKED-SER-1 and TEST-NET 192.0.2.x, and the run's own output is
scanned for both).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import httpx
import pytest
from typer.testing import CliRunner

import gateclerk.agent_cli as agent_cli
from fakedevice import FakeDevice
from gateclerk import agent_push
from gateclerk.agent_alert import PENDING_SERIAL, AlertPolicy
from gateclerk.agent_db import connect
from gateclerk.agent_store import read_checkpoint
from gateclerk.cli import AUTH_TERMINAL_EXIT, CONFIG_ERROR_EXIT, app
from gateclerk.config import ConfigSurface, KeychainItem, site_from_args
from gateclerk.endpoints import REGISTRY
from gateclerk.isapi_transport import IsapiClient
from gateclerk.secrets import Secret

# CLI-SPLIT-STRUCTURE: the ONE hand-maintained leaf set lives in test_cli_conventions
# (`EXPECTED_LEAVES`, with its len-pin + symmetric-difference message). The surface pins
# below DERIVE from it instead of keeping a second literal tree — four cards in a row had
# to hand-edit both. Importing it is also the drift channel: a rename that bumps the one
# set re-derives everything here.
from test_cli_conventions import EXPECTED_LEAVES
from test_p2_03_scheduler import (
    AC_CAPS_PATH,
    ACS_CAPS_PATH,
    CADENCE_S,
    DEVICE_INFO_PATH,
    EVENT_PATH,
    OVERLAP_S,
    PASSWORD,
    SCENARIOS,
    SITE,
    SITE_TZ,
    SYSTEM_TIME_PATH,
    T0,
    device_event,
)

RECORDED = Path(__file__).parent / "fixtures" / "recorded" / "site-a-ds-k1t341amf-s"

#: The fake's claimed offset (site-a stamps +02:00 year-round inside +03:00 summer,
#: OBSERVED.md "time/offset bug"). `wall_digits` below is what makes it load-bearing.
CLAIM_MIN = 120
HOST = "192.0.2.10"  # TEST-NET (tests/test_repo_hygiene.py allowlist)
SERIAL = "MASKED-SER-1"
#: The env rung for the fake host (`config.env_var_names(HOST)[1]`), spelled out so a change
#: to the sanitizer shows up here as a red test rather than as a credential that silently
#: resolves from somewhere else.
HOST_PASSWORD_ENV = "GATECLERK_192_0_2_10_PASSWORD"
#: A push target for tests that only need a dead-letter row: a valid `stub://` ref whose
#: ingest is a transport this test supplies (and fails on purpose).
DEAD_TARGET = "stub://dead-ingest/lines.jsonl"

runner = CliRunner()

#: What the agent may put on the wire (the p1-05c registry surface, spelled as paths).
ALLOWED_PATHS = frozenset(
    {DEVICE_INFO_PATH, SYSTEM_TIME_PATH, ACS_CAPS_PATH, AC_CAPS_PATH, EVENT_PATH}
)


def wall_digits(moment: datetime, *, claim_min: int = CLAIM_MIN) -> str:
    """The fake's wall DIGITS for an instant — THE clock-seam recipe, in one place.

    `tests/fakedevice.py` filters its event store by re-anchoring each posted bound on the
    device's OWN claimed clock (`fakedevice._bound_to_device_wall`): a bound with digits D
    labeled L names the instant D-L, and the fake matches events whose wall digits fall in
    D + claimed - L. The loop labels every window bound with the device's CLAIMED offset
    (agent_loop seam 7, `device_window_labels`), so here L == claimed and the effective bound
    is exactly the digits the loop asks for — the SITE-LOCAL digits of the instant. Seed with
    UTC digits (or any other anchoring) and the window the loop asks for and the rows the fake
    returns are two different universes; that mismatch is the loop the previous attempt spent
    its budget re-deriving. `claim_min` stays a knob so a test that *changes* the claim can
    see this function is the single place the arithmetic lives.
    """
    assert claim_min == CLAIM_MIN, "wall_digits assumes the loop labels bounds with the claim"
    return moment.astimezone(ZoneInfo(SITE_TZ)).strftime("%Y-%m-%dT%H:%M:%S")


class RotatingKeychain:
    """A fake keychain READER whose item value the test can rotate mid-run.

    `resolve_credentials` only needs `.read()`; recording `reads` is the keychain-prompt
    budget the agent must respect (each real `security` invocation can raise an ACL prompt).
    """

    def __init__(self, password: str) -> None:
        self.password = password
        self.reads = 0

    def read(self, target: Any, *, with_comment: bool = True) -> KeychainItem:
        self.reads += 1
        return KeychainItem(
            password=Secret(self.password, label=f"keychain:{target.host}"),
            comment=f"user={target.config_user}",
        )


class FakeMonotonic:
    """The transport/pacing monotonic seam, in the same fake-time universe as the clock."""

    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def seeded_device(**over: Any) -> FakeDevice:
    """A FakeDevice answering the loop's bootstrap GETs with the RECORDED site-a bodies."""
    device = FakeDevice(password=PASSWORD)
    device.claimed_offset_min = over.pop("claimed", CLAIM_MIN)
    assert not over, f"unknown seed knobs: {sorted(over)}"
    device.xml_ok("GET", DEVICE_INFO_PATH, (RECORDED / "device_info.xml").read_text())
    device.xml_ok("GET", SYSTEM_TIME_PATH, (RECORDED / "system_time.xml").read_text())
    device.add(
        "GET",
        ACS_CAPS_PATH,
        httpx.Response(200, content=(RECORDED / "acs_capabilities.json").read_bytes()),
    )
    device.add(
        "GET",
        AC_CAPS_PATH,
        httpx.Response(
            200,
            content=(
                SCENARIOS.parent / "synthetic" / "access_control_capabilities.json"
            ).read_bytes(),
        ),
    )
    return device


def punch_events(now: datetime, *offsets_s: int, start_serial: int = 200) -> list[dict[str, Any]]:
    """Events stamped from the SAME injected `now` the agent will run at.

    `offsets_s` are seconds relative to now (negative = already in the device log when the
    first pass runs); the digits come from `wall_digits`, so the cold-start window
    `[now - (cadence + overlap), now]` the loop builds answers with exactly these rows.
    """
    return [
        device_event(start_serial + i, wall_digits(now + timedelta(seconds=offset_s)))
        for i, offset_s in enumerate(offsets_s)
    ]


class AgentHarness:
    """sites.toml + FakeDevice + one frozen clock, driven through the real `gateclerk` CLI.

    Three monkeypatches make a whole run deterministic and offline, and nothing else:
    `agent_cli._now` (the clock seam), `agent_cli.IsapiClient` (the p1-09 redirection — the
    REAL client with FakeDevice's MockTransport under it) and the credential env rung. Every
    path the CLI takes from there is production code.
    """

    def __init__(
        self,
        tmp_path: Path,
        device: FakeDevice,
        monkeypatch: pytest.MonkeyPatch,
        *,
        db_path: str | None = None,
        push_target: str | None = "auto",
        password: str = PASSWORD,
        state_root: Path | None = None,
        now: datetime = T0,
    ) -> None:
        from gateclerk.capabilities import capability_cache

        # The capability cache is PROCESS state (p1-04): a stale entry from another test would
        # answer this walk's caps without the fake ever being asked — same clear as P2-03.
        capability_cache().clear()
        self.tmp = tmp_path
        self.device = device
        self.monkeypatch = monkeypatch
        self.now = now
        self.monotonic = FakeMonotonic()
        self.state_root = state_root or tmp_path / "state" / SITE
        self.db_path = db_path or f"gateclerk-{SITE}.sqlite3"  # relative: README's default form
        self.push_target = (
            f"stub://{tmp_path / 'ingest' / 'lines.jsonl'}"
            if push_target == "auto"
            else push_target
        )
        self.ingest_file = (
            Path(self.push_target[len("stub://") :])
            if self.push_target and self.push_target.startswith("stub://")
            else None
        )

        self.config = tmp_path / "sites.toml"
        self.write_site_block(iana_tz='"Europe/Bucharest"', device_tz=True)

        monkeypatch.setattr(agent_cli, "_now", lambda: self.now)
        # Stand-in for the CONSTRUCTOR the default path uses, so it takes what
        # `IsapiClient.__init__` takes (`read_timeout=...`) — the p1-09 redirection pattern:
        # the real client class, FakeDevice's MockTransport under it.
        monkeypatch.setattr(
            agent_cli,
            "IsapiClient",
            lambda base, user, secret, **kw: IsapiClient(
                base,
                user,
                secret,
                transport=device.transport,
                now=self.monotonic,
                **kw,
            ),
        )
        monkeypatch.setenv(HOST_PASSWORD_ENV, password)

    # -- configuration ------------------------------------------------------------------

    def write_site_block(
        self, *, iana_tz: str | None = '"Europe/Bucharest"', device_tz: bool = True
    ) -> None:
        lines = [
            "[[site]]",
            f'name = "{SITE}"',
            f'host = "{HOST}"',
        ]
        if iana_tz is not None:
            lines.append(f"iana_tz = {iana_tz}")
        if device_tz:
            # p1-12's mapping: site-a's digits ARE site-local, the claim is wrong. Declaring it
            # silences the run-level mismatch warning, which the health counters also record.
            lines.append('device_tz = "Europe/Bucharest"')
        lines.append(f'db_path = "{self.db_path}"')
        if self.push_target:
            lines.append(f'push_target = "{self.push_target}"')
        self.config.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def set_password(self, password: str) -> None:
        self.monkeypatch.setenv(HOST_PASSWORD_ENV, password)

    def site_config(self) -> Any:
        return site_from_args(site=SITE, config_path=self.config, surface=ConfigSurface.AGENT)

    # -- driving ------------------------------------------------------------------------

    def cli(
        self, args: list[str], *, env: dict[str, str] | None = None, config: bool = True
    ) -> tuple[int, str]:
        """`gateclerk agent ...` in-process, with the run's clock frozen to `self.now`.

        `--config` is added for you (the site block lives under tmp_path, and the CLI's default
        is ./sites.toml = the repo root); pass `config=False` for the cases that deliberately
        exercise a missing/alternative config path.
        """
        argv = [*args, "--config", str(self.config)] if config else list(args)
        result = runner.invoke(app, ["agent", *argv], env=env)
        out = result.output or ""
        if result.exception is not None and not isinstance(
            result.exception, (SystemExit, httpx.HTTPError)
        ):
            raise result.exception
        return result.exit_code, out

    def api_agent(self, **over: Any) -> Any:
        """`build_site_agent` with every seam injected (the direct, CLI-free path).

        The CLI cannot pass `now`/`sleep`/`monotonic` — no operator should — so the cadence
        math, the injected-clock wiring and the warn funnel are exercised here instead.
        """
        kwargs: dict[str, Any] = {
            "state_root": self.state_root,
            "now": lambda: self.now,
            "monotonic": self.monotonic,
            "sleep": over.pop("sleep", lambda _s: None),
            "warn": over.pop("warn", lambda _t: None),
            "sink": over.pop("sink", lambda _a: None),
            "client_factory": over.pop(
                "client_factory",
                lambda base, user, secret: IsapiClient(
                    base, user, secret, transport=self.device.transport, now=self.monotonic
                ),
            ),
        }
        kwargs.update(over)
        return agent_cli.build_site_agent(self.site_config(), **kwargs)

    # -- reading what the commands actually wrote ---------------------------------------

    def conn(self) -> Any:
        return connect(self.state_root / self.db_path)

    def stored_serials(self) -> list[int]:
        return [
            row["serial_no"]
            for row in self.conn().execute("SELECT serial_no FROM events ORDER BY serial_no")
        ]

    def pushed_lines(self) -> list[dict[str, Any]]:
        assert self.ingest_file is not None, "this harness has no stub ingest"
        if not self.ingest_file.exists():
            return []
        return [
            json.loads(line)
            for line in self.ingest_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def policy(self) -> AlertPolicy:
        """A FRESH policy over the same park dir: what survived the process IS the state.

        This is also why the park is on disk: `agent ack` is a different process from the
        `agent run` that parked the device, and it must find the park the unit left behind.
        The clock is the harness instant, not the wall: the re-probe GRID is arithmetic on
        `now`, and asserting it against a wall clock years away from T0 would make every
        "not due yet" assertion vacuously true.
        """
        return AlertPolicy(
            site=SITE,
            cadence_s=CADENCE_S,
            conn=self.conn(),
            park_dir=self.state_root / agent_cli.PARK_DIR_NAME,
            now=lambda: self.now,
        )

    def health_snapshot(self) -> dict[str, Any]:
        path = self.state_root / agent_cli.HEALTH_DIR_NAME / agent_cli.HEALTH_FILE_NAME
        return json.loads(path.read_text(encoding="utf-8"))

    def seed_dead_letter(self) -> int:
        """Drive a REAL outage into `dead_letter` through P2-04's own drain.

        Two failing drains, 25 h apart: the 24 h clock starts at the FIRST failure
        (`first_failed_at`), so one failure can never dead-letter — and a fixture row written
        by hand would prove nothing about the bound the CLI is reporting.
        """
        from gateclerk.agent_cli import queue_new_events

        agent = self.api_agent()
        agent.tick()  # store the window (push target is off for this harness shape)
        agent.close()
        conn = self.conn()
        assert queue_new_events(conn, endpoint=DEAD_TARGET, now=self.now), "must be queueable"
        failing = _refusing_transport()
        agent_push.drain(
            conn, endpoint=DEAD_TARGET, transport=failing, now=self.now, rng=lambda: 0.5
        )
        result = agent_push.drain(
            conn,
            endpoint=DEAD_TARGET,
            transport=failing,
            now=self.now + timedelta(hours=25),
            rng=lambda: 0.5,
        )
        assert len(result.dead_lettered) == 1, "the outage must be past the 24 h bound"
        dead_id = int(conn.execute("SELECT id FROM dead_letter").fetchone()["id"])
        conn.close()
        return dead_id


def _refusing_transport() -> Any:
    """A transport that raises — the normal shape of "the ingest is down" for P2-04."""

    def send(url: str, body: str) -> int:
        raise RuntimeError("ingest down")

    return send


# --- DoD (1): `agent run --site` = ONE tick, stored rows, a pushed line, rc 0 ----------------


def test_agent_run_once_stores_every_event_and_pushes_each_one_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The card's first DoD line, asserted where the facts live: the store and the ingest file.

    rc 0 is necessary and nowhere near sufficient. Underneath it: each event stored EXACTLY
    once, the checkpoint advanced over stored events only, and the stub ingest holds one pushed
    line per stored event — the queue->drain link nothing else in the codebase provided.
    """
    device = seeded_device()
    device.add_events(*punch_events(T0, -600, -420, -240, -120))  # all inside the cold start
    h = AgentHarness(tmp_path, device, monkeypatch)

    code, out = h.cli(["run", "--site", SITE, "--state-root", str(h.state_root), "--once"])

    assert code == 0, out
    assert h.stored_serials() == [200, 201, 202, 203], (
        "the cold-start window must store what the device has, exactly once each"
    )
    assert [line["serial_no"] for line in h.pushed_lines()] == [200, 201, 202, 203], (
        "every stored event must reach the push target"
    )
    # The store is the source of truth for the payload: the pushed line IS the stored line.
    conn = h.conn()
    stored = {
        row["serial_no"]: row["jsonl"]
        for row in conn.execute("SELECT serial_no, jsonl FROM events")
    }
    for line in h.pushed_lines():
        assert json.loads(stored[line["serial_no"]]) == line, (
            "the pushed payload must be the stored contract line, not a re-serialisation"
        )
    cp = read_checkpoint(conn, SERIAL)
    assert cp is not None and cp.checkpoint_serial == 203, "the checkpoint chases completed max"


def test_agent_run_once_reports_one_tick_and_is_the_smoke_test_shape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--once` means ONE tick, and the report says so (deploy/README.md step 3's proof).

    `systemd-run --wait ... --once` is how an operator proves a render before installing it;
    that only works if one invocation is one pass. Pinned on the report's own `ticks` field
    rather than on a sleep count, because the CLI path has no sleep recorder (an operator
    cannot inject one, by design) — the cadence loop itself is pinned through the API below.
    """
    device = seeded_device()
    device.add_events(*punch_events(T0, -300, -200))
    h = AgentHarness(tmp_path, device, monkeypatch)

    code, out = h.cli(
        ["run", "--site", SITE, "--state-root", str(h.state_root), "--once", "--output", "json"]
    )
    assert code == 0, out
    report = json.loads(out)
    assert report["ticks"] == 1
    assert report["site"] == SITE
    assert report["pushed"] == 2
    assert report["push_failed"] == 0 and report["dead_lettered"] == 0
    assert report["parked"] == [], "a healthy site must not report a park"


def test_agent_run_twice_against_the_same_store_re_read_is_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A restart must not churn the store or double-push (the property `Restart=always` needs).

    Two `agent run --once` processes over one store: the second re-reads the overlap window,
    every re-read row keeps `revision` 1 (P2-02's guard) and the queue's UNIQUE
    (event_id, endpoint) means no second send buffer — so the ingest has each line once, not
    twice.
    """
    device = seeded_device()
    device.add_events(*punch_events(T0, -300, -100))
    h = AgentHarness(tmp_path, device, monkeypatch)

    assert h.cli(["run", "--site", SITE, "--state-root", str(h.state_root), "--once"])[0] == 0
    h.now = T0 + timedelta(seconds=CADENCE_S)  # the next scheduled pass
    assert h.cli(["run", "--site", SITE, "--state-root", str(h.state_root), "--once"])[0] == 0

    rows = h.conn().execute("SELECT serial_no, revision FROM events ORDER BY serial_no").fetchall()
    assert [r["serial_no"] for r in rows] == [200, 201]
    assert all(r["revision"] == 1 for r in rows), "the overlap re-read must be a FREE conflict"
    assert [line["serial_no"] for line in h.pushed_lines()] == [200, 201], (
        "two passes, one send each: the queue dedupes per (event, endpoint)"
    )


def test_cadence_loop_sleeps_once_per_pass_at_the_configured_cadence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The unit's ExecStart shape, through the API (the CLI has no sleep seam to record).

    N passes cost N-1 sleeps, each `cadence - elapsed` floored at zero — never one sleep per
    device, never a busy loop. The README's warning ("never put --once in the unit") only
    means something because `run` without it actually waits the cadence.
    """
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    h = AgentHarness(tmp_path, device, monkeypatch)
    sleeps: list[float] = []
    agent = h.api_agent(sleep=sleeps.append)

    report = agent.run(max_ticks=3)
    assert report.ticks == 3
    assert len(sleeps) == 2, f"three passes sleep between them, twice: {sleeps}"
    assert all(0.0 <= s <= CADENCE_S for s in sleeps)
    assert all(s > CADENCE_S - 240 for s in sleeps), (
        f"the sleep is cadence MINUS the pass time (a full-cadence sleep would drift later "
        f"every cycle and leave a gap the overlap has to heal): {sleeps}"
    )
    agent.close()


def test_build_site_agent_opens_no_socket_and_threads_the_injected_clock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pure wiring: constructing the agent must not poll, and every seam shares one clock.

    P2-03 shipped `build_device_loop` with the no-socket rule; this is the same rule at the
    level `agent run` actually calls. The clock assertions are the seam itself: the loop, the
    policy and the agent all resolve `now` to the same injected instant (one clock per pass —
    two clocks would put the park grid and the window on different timelines).
    """
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    h = AgentHarness(tmp_path, device, monkeypatch)
    before = len(device.served)

    agent = h.api_agent()
    try:
        assert len(device.served) == before, "building the agent must not poll the device"
        assert agent.loops[0]._now() == T0
        assert agent.policy.now() == T0
        assert agent.now() == T0
    finally:
        agent.close()


def test_freezing_the_module_now_moves_the_whole_cli_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The `_now` indirection is the CLI-side seam, and it is the ONLY thing frozen.

    If `SiteAgent` had bound `self.now = _now` at construction, or if any seam had called the
    real `datetime.now`, this would fail: the window the loop asks for would be "real now"
    while the seeded events sit at T0, and the fake would answer with nothing.
    """
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    h = AgentHarness(tmp_path, device, monkeypatch)
    assert h.cli(["run", "--site", SITE, "--state-root", str(h.state_root), "--once"])[0] == 0
    assert h.stored_serials() == [200]

    # A different frozen instant, same harness: the run follows the clock, not the wall.
    later = T0 + timedelta(hours=2)
    h.now = later
    device.add_events(*punch_events(later, -60, start_serial=300))
    assert h.cli(["run", "--site", SITE, "--state-root", str(h.state_root), "--once"])[0] == 0
    assert h.stored_serials() == [200, 300]


# --- DoD (2): `agent ack` clears a park — asserted through P2-05's own state ------------------


def test_agent_ack_clears_the_park_in_policy_state_not_in_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The card's wording is explicit: assert via P2-05's policy state, not CLI text.

    Terminal 401 (rotated credential) -> park -> every later pass refused with ZERO requests ->
    `agent ack` -> the gate allows the next attempt again. Each step reads `parked()` /
    `attempt_allowed()`, the two functions that decide whether a door controller gets knocked.
    """
    device = seeded_device()
    h = AgentHarness(tmp_path, device, monkeypatch, password="fakepw-rotated")

    code, out = h.cli(["run", "--site", SITE, "--state-root", str(h.state_root), "--once"])
    # A terminal 401 is p1-08's exit 3: the transport circuit-opened to protect the lockout
    # budget, which is exactly the case that needs a human. Loud, never a silent 0.
    assert code == AUTH_TERMINAL_EXIT, out
    policy = h.policy()
    assert policy.parked(SITE, PENDING_SERIAL) is not None, "the terminal 401 must park"
    assert policy.attempt_allowed(None)[0] is False, "an unacked park must block the gate"

    served = len(device.served)
    code2, _ = h.cli(["run", "--site", SITE, "--state-root", str(h.state_root), "--once"])
    assert code2 == AUTH_TERMINAL_EXIT
    assert len(device.served) == served, (
        "a parked device must be touched NEVER AGAIN — not even by a fresh CLI process"
    )

    code3, out3 = h.cli(["ack", "--site", SITE, "--state-root", str(h.state_root)])
    assert code3 == 0, out3
    state = h.policy().parked(SITE, PENDING_SERIAL)
    assert state is not None and state.acked_at is not None, (
        "the on-disk park carries the ack: it is what survives the unit's restart"
    )
    # An ack is permission to SCHEDULE, not to hammer (P2-05's own rule, pinned there at
    # the grid level): the first knock is due only at ack + reprobe period.
    assert h.policy().attempt_allowed(None)[0] is False, "immediately after the ack: off-grid"
    h.now += timedelta(seconds=1800)  # the re-probe period (agent_alert.REPROBE_AFTER_S)
    assert h.policy().attempt_allowed(None)[0] is True, (
        "the ack opened the re-probe grid — that IS what 'cleared a park' means"
    )

    # And the gate actually lets the next pass through once the credential is fixed.
    h.set_password(PASSWORD)
    code4, out4 = h.cli(["run", "--site", SITE, "--state-root", str(h.state_root), "--once"])
    assert code4 == 0, out4
    assert len(device.served) > served, "the acked device was polled again"


def test_slice3_rotation_self_heals_in_one_process_without_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Slice 3 of D-001: the §2c self-heal, in ONE long-lived agent process.

    The pre-Slice-3 agent cached the plaintext at construction, so the acked re-probe
    knocked with the stale secret forever (a parked agent never crashes, so
    `Restart=always` never re-resolved it). Here the fake keychain rotates between ticks:
    tick 2 parks on a terminal 401, the operator acks, the circuit window expires, and
    tick 3 must re-read the source and succeed — with no second `build_site_agent` and
    no process restart. The read counter also pins the prompt budget: one resolve at
    construction, NONE while the circuit is open or on ordinary ticks, one at expiry.
    """
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    h = AgentHarness(tmp_path, device, monkeypatch, push_target=None)
    monkeypatch.delenv(HOST_PASSWORD_ENV, raising=False)  # force the fake keychain rung
    keychain = RotatingKeychain(PASSWORD)
    agent = h.api_agent(client_factory=None, env={}, keychain=keychain)
    try:
        assert keychain.reads == 1, "point (1): the ctor fail-fast resolve"

        first = agent.tick()
        assert first.ticks_ok == 1, first
        assert h.stored_serials() == [200]
        assert keychain.reads == 1, "an ordinary tick resolves nothing"

        # The device AND the source rotate while the SAME agent keeps running.
        device.password = "fakepw-rotated"
        keychain.password = "fakepw-rotated"

        second = agent.tick()
        assert second.ticks_failed == 1, second
        assert agent.loops[0].client.circuit_open(), "the terminal 401 opened the circuit"
        assert agent.policy.parked(SITE, "MASKED-SER-1") is not None
        assert keychain.reads == 1, "opening a circuit is not a provider-read point"

        served = len(device.served)
        refused = agent.tick()
        assert refused.ticks_refused == 1, "unacked: the gate refuses before any request"
        assert len(device.served) == served, "zero requests while the park is unacked"
        assert keychain.reads == 1, "a refused tick must not prompt the keychain"

        assert agent.policy.ack(SITE) == 1
        # The operator provisions the ROTATED secret; the agent process is still the original.
        keychain.password = "fakepw-rotated"
        h.now += timedelta(seconds=1800)  # REPROBE_AFTER_S: the re-probe grid opens
        h.monotonic.advance(311)  # past DEFAULT_CIRCUIT_FALLBACK_SECONDS + margin

        third = agent.tick()
        assert third.ticks_ok == 1, (third, [r.error for r in agent._last_tick.values()])
        assert keychain.reads == 2, "exactly one resolve at circuit expiry"
        assert not agent.loops[0].client.circuit_open()
        assert agent.policy.parked(SITE, "MASKED-SER-1") is None, "a good tick lifts the park"

        h.now += timedelta(seconds=CADENCE_S)
        h.monotonic.advance(CADENCE_S)
        fourth = agent.tick()
        assert fourth.ticks_ok == 1, fourth
        assert keychain.reads == 2, "ordinary requests after the heal never re-prompt"
    finally:
        agent.close()


def test_slice3_keychain_budget_is_one_read_per_rotation_episode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The prompt budget on its own: ordinary requests and in-window ticks are free.

    Each real `security` call can raise a macOS ACL prompt (KeychainReader's docstring),
    so re-resolution is allowed only at construction and the two lifetime points — never
    per request or per tick. This is Slice 2's contract observed through the agent path.
    """
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    h = AgentHarness(tmp_path, device, monkeypatch, push_target=None)
    monkeypatch.delenv(HOST_PASSWORD_ENV, raising=False)  # force the fake keychain rung
    keychain = RotatingKeychain(PASSWORD)
    agent = h.api_agent(client_factory=None, env={}, keychain=keychain)
    try:
        for step in range(3):
            h.now += timedelta(seconds=CADENCE_S)
            h.monotonic.advance(CADENCE_S)
            report = agent.tick()
            assert report.ticks_ok == 1, (step, report)
        assert keychain.reads == 1, "three ordinary ticks, one construction resolve"

        device.password = "fakepw-rotated"
        failed = agent.tick()
        assert failed.ticks_failed == 1, failed
        assert keychain.reads == 1, "the 401 that parks the device reads nothing"
    finally:
        agent.close()


def test_slice3_injected_client_factory_still_gets_the_eager_triple(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The injection seam is unchanged: a factory receives (base, user, secret).

    Only the DEFAULT construction path passes the provider; an owner-wired factory keeps
    the pre-Slice-3 contract, which is what leaves every existing offline test untouched.
    """
    h = AgentHarness(tmp_path, seeded_device(), monkeypatch, push_target=None)
    monkeypatch.delenv(HOST_PASSWORD_ENV, raising=False)  # force the fake keychain rung
    site = h.site_config()
    keychain = RotatingKeychain(PASSWORD)
    seen: list[tuple[str, str, str]] = []
    sentinel = object()

    def factory(base: str, user: str, secret: str) -> Any:
        seen.append((base, user, secret))
        return sentinel

    got = agent_cli._client_for_host(
        site,
        HOST,
        env={},
        keychain=keychain,
        client_factory=factory,
    )
    assert got is sentinel
    assert seen == [(f"http://{HOST}:{site.port}", site.isapi_user, PASSWORD)]
    assert keychain.reads == 1, "the eager path resolves once, as before"

    captured: dict[str, Any] = {}

    class CaptureClient:
        def __init__(self, base: str, user: str, password: str, **kw: Any) -> None:
            captured.update(base=base, user=user, password=password, **kw)

    monkeypatch.setattr(agent_cli, "IsapiClient", CaptureClient)
    agent_cli._client_for_host(
        site,
        HOST,
        env={},
        keychain=keychain,
        client_factory=None,
    )
    assert captured["user"] == "" and captured["password"] == ""
    provider = captured["credentials"]
    assert callable(provider)
    assert keychain.reads == 1, "building the client does not resolve until the ctor does"
    assert provider().password.reveal() == PASSWORD
    assert keychain.reads == 2


def test_agent_ack_of_a_site_with_no_park_exits_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Zero parks opened is exit 2, not a silent 0.

    An ack that found nothing must not read as a clear: the operator would believe the device
    is live and the site would stay silently parked (P2-05's own rule, enforced at the CLI edge).
    """
    device = seeded_device()
    h = AgentHarness(tmp_path, device, monkeypatch)
    code, out = h.cli(["ack", "--site", SITE, "--state-root", str(h.state_root)])
    assert code == CONFIG_ERROR_EXIT
    assert "nothing to ack" in out


def test_agent_ack_typo_device_serial_cannot_clear_a_real_park(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A typo'd --device-serial neither clears the park nor exits 0; the real serial does."""
    device = seeded_device()
    h = AgentHarness(tmp_path, device, monkeypatch, password="fakepw-rotated")
    h.cli(["run", "--site", SITE, "--state-root", str(h.state_root), "--once"])

    code, _ = h.cli(
        [
            "ack",
            "--site",
            SITE,
            "--state-root",
            str(h.state_root),
            "--device-serial",
            "MASKED-SER-TYPO",
        ]
    )
    assert code == CONFIG_ERROR_EXIT
    assert h.policy().attempt_allowed(None)[0] is False, "the real park is untouched"

    # The site-wide ack is what opens THIS park: the 401 arrived pre-bootstrap, so the
    # record's serial is `pending` and no real serial can name it (P2-05's own rule —
    # `ack(site)` without a serial acks every park of the site).
    code2, _ = h.cli(["ack", "--site", SITE, "--state-root", str(h.state_root)])
    assert code2 == 0
    assert h.policy().attempt_allowed(None)[0] is False, "acked but off-grid until +30min"
    h.now += timedelta(seconds=1800)  # agent_alert.REPROBE_AFTER_S
    assert h.policy().attempt_allowed(None)[0] is True


def test_agent_run_never_touches_a_parked_device_across_two_processes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lockout invariant, from the CLI side: the park is DISK state, not process state.

    `agent run` parks; a SEPARATE `agent run` process must still refuse the device. If the park
    lived in memory, systemd's `Restart=always` would hand a lockout-counting device a fresh
    attempt every 5 seconds (deploy/README.md step 4 is explicit about why it is on disk).
    """
    device = seeded_device()
    h = AgentHarness(tmp_path, device, monkeypatch, password="fakepw-rotated")
    h.cli(["run", "--site", SITE, "--state-root", str(h.state_root), "--once"])
    park_files = list((h.state_root / agent_cli.PARK_DIR_NAME).glob("*.json"))
    assert park_files, "the park must be a file under the state root"

    served = len(device.served)
    for _ in range(3):
        h.now += timedelta(seconds=CADENCE_S)
        h.cli(["run", "--site", SITE, "--state-root", str(h.state_root), "--once"])
    assert len(device.served) == served, "three passes, zero requests: the gate held"
    assert any(not s.had_auth for s in device.served[served:]) is False or True  # (see below)
    assert not any(s.had_auth for s in device.served[served:]), (
        "not even a credential was PRESENTED while parked"
    )


# --- DoD (3): deadletter list / delete --------------------------------------------------------


def test_deadletter_list_shows_the_dead_row_and_its_triage_columns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The owner's triage list: id, error class, attempts — and NOT the payload.

    A table that printed payloads is how an employee number and a name end up on a shared
    terminal, so P2-04's own read seams omit the body and the CLI inherits that.
    """
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    h = AgentHarness(tmp_path, device, monkeypatch, push_target=None)
    dead_id = h.seed_dead_letter()

    code, out = h.cli(["deadletter", "list", "--site", SITE, "--state-root", str(h.state_root)])
    assert code == 0, out
    assert str(dead_id) in out
    assert "RuntimeError" in out, "the error class is what tells an owner whose fault it is"
    conn = h.conn()
    payload = conn.execute("SELECT payload FROM dead_letter").fetchone()["payload"]
    conn.close()
    assert payload not in out, "the payload (an employee number and a name) must not print"
    assert "MASKED-SER-1" not in out or "employee" not in out.lower()


def test_deadletter_delete_needs_the_explicit_id_and_removes_exactly_one_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`delete` names a row or does nothing: no --all, no range, no "purge the table".

    A dead letter is the only copy of a punch that never reached the ingest, so the CLI gives
    the operator no lever that empties the table in one keystroke (§2b).
    """
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    h = AgentHarness(tmp_path, device, monkeypatch, push_target=None)
    dead_id = h.seed_dead_letter()

    # No id at all: click refuses the invocation and NOTHING is deleted.
    no_id = runner.invoke(
        app, ["agent", "deadletter", "delete", "--site", SITE, "--state-root", str(h.state_root)]
    )
    assert no_id.exit_code != 0
    assert agent_push.dead_letter_depth(h.conn()) == 1, "a missing id must delete nothing"

    # A wrong id: exit 2, row survives (a typo must not read as a deletion).
    code, _ = h.cli(
        ["deadletter", "delete", "99999", "--site", SITE, "--state-root", str(h.state_root)]
    )
    assert code == CONFIG_ERROR_EXIT
    assert agent_push.dead_letter_depth(h.conn()) == 1

    code2, out2 = h.cli(
        ["deadletter", "delete", str(dead_id), "--site", SITE, "--state-root", str(h.state_root)]
    )
    assert code2 == 0, out2
    assert agent_push.dead_letter_depth(h.conn()) == 0


def test_push_ledger_lands_in_the_state_root_and_carries_no_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ledger is site state beside the store — and it is counters, not content.

    `sent`/`gone` lines name (event id, endpoint): an employee number or a name in this file
    would be a second, un-governed copy of punch data outside the db (P2-06's snapshot rule
    applies here too: state files carry labels and counters, never payloads).
    """
    device = seeded_device()
    device.add_events(*punch_events(T0, -300, -200))
    h = AgentHarness(tmp_path, device, monkeypatch)
    assert h.cli(["run", "--site", SITE, "--state-root", str(h.state_root), "--once"])[0] == 0

    ledger = h.state_root / agent_cli.PUSH_LEDGER_FILE_NAME
    assert ledger.exists(), "the ledger is written under the SAME root as store, park, health"
    lines = [json.loads(line) for line in ledger.read_text().splitlines() if line.strip()]
    assert sorted(rec["e"] for rec in lines) == [1, 2], "one line per pushed event"
    assert all(rec["k"] == "sent" for rec in lines)
    raw = ledger.read_text(encoding="utf-8")
    assert "MASKED-SER-1" not in raw and "User E1" not in raw and PASSWORD not in raw


def test_ledger_known_rows_never_consume_the_batch_limit(tmp_path: Path) -> None:
    """Why the exclusion is INSIDE the query, pinned where a post-filter would fail.

    A post-filter over `LIMIT n` rows would return zero forever once the store's first n
    events are all ledger-known: the unsent rows behind them become unreachable and the site
    silently stops pushing. With the exclusion in the WHERE, a full batch still arrives.
    """
    from gateclerk.agent_cli import PushLedger, queue_new_events
    from gateclerk.agent_db import connect

    conn = connect(tmp_path / "agent.sqlite3")
    for serial in (300, 301, 302):
        conn.execute(
            "INSERT INTO events (jsonl, revision, stored_at, updated_at, key_algorithm,"
            " idempotency_hash, idempotency_json, fingerprint_hash, fingerprint_json,"
            " site, device_serial, serial_no, raw) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "{}",
                1,
                "2026-10-19T07:00:00+00:00",
                "2026-10-19T07:00:00+00:00",
                "sha256",
                f"h{serial}",
                "{}",
                f"f{serial}",
                "{}",
                SITE,
                SERIAL,
                serial,
                "{}",
            ),
        )
    conn.commit()
    ledger = PushLedger(tmp_path / "ledger.jsonl")
    ledger.append([1], endpoint=DEAD_TARGET)  # the OLDEST event is already pushed

    queued = queue_new_events(conn, endpoint=DEAD_TARGET, now=T0, limit=1, ledger=ledger)
    assert len(queued) == 1, "the known row must not eat the batch: a FULL batch still arrives"
    event_id = conn.execute("SELECT event_id FROM push_queue WHERE id = ?", queued).fetchone()[
        "event_id"
    ]
    assert event_id == 2, "the next UNSent row is event 2, not nothing"
    conn.close()


def test_deleted_dead_letter_never_returns_to_the_queue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§2b from the other side: the owner's `delete` must mean GONE, not "re-pushed next tick".

    Deleting a dead letter removes its `dead_letter` exclusion, so the still-stored event row
    would be re-queued by the very next pass — the payload the owner just discarded arriving
    at the ingest after all. The CLI records the delete in the ledger; the queue query then
    keeps excluding the id. Both halves are asserted: the CLI leaves the `gone` line, and
    `queue_new_events` over the same ledger queues NOTHING.
    """
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    h = AgentHarness(tmp_path, device, monkeypatch, push_target=None)
    dead_id = h.seed_dead_letter()

    code, _ = h.cli(
        ["deadletter", "delete", str(dead_id), "--site", SITE, "--state-root", str(h.state_root)]
    )
    assert code == 0
    ledger_path = h.state_root / agent_cli.PUSH_LEDGER_FILE_NAME
    records = [json.loads(x) for x in ledger_path.read_text().splitlines() if x.strip()]
    assert records and all(rec["k"] == "gone" for rec in records), "the delete is on disk"

    conn = h.conn()
    assert (
        agent_cli.queue_new_events(
            conn, endpoint=DEAD_TARGET, now=T0, ledger=agent_cli.PushLedger(ledger_path)
        )
        == ()
    ), "the discarded event must never be queued again"
    assert agent_push.queue_depth(conn) == 0
    conn.close()


def test_queue_step_never_reenqueues_a_dead_lettered_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The load-bearing exclusion in `queue_new_events` — agent_cli's only new logic.

    A dead-lettered row's queue buffer was DELETED because the 24 h bound expired. Without the
    `NOT EXISTS (dead_letter)` arm of the query, the next pass would re-enqueue it, re-push it
    and restart the failure clock on a poison event forever — silently, every tick, which is the
    exact opposite of §2b's "a dead letter leaves the table only through the owner's command".
    """
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    h = AgentHarness(tmp_path, device, monkeypatch, push_target=None)
    h.seed_dead_letter()

    conn = h.conn()
    assert agent_push.dead_letter_depth(conn) == 1
    assert agent_cli.queue_new_events(conn, endpoint=DEAD_TARGET, now=T0) == (), (
        "a dead-lettered event must never be queued again"
    )
    assert agent_push.queue_depth(conn) == 0


# --- DoD (4): the existing CLI surface is untouched ------------------------------------------


#: The command tree exactly as it was at 89e10d1 (pre-P2-07b main).
#:
#: CLI-SPLIT-STRUCTURE (operator instruction): this used to be a SECOND hand-maintained
#: leaf tree, and four cards in a row had to hand-edit both it and
#: `test_cli_conventions.EXPECTED_LEAVES` on every surface change. There is now ONE
#: authoritative hand-maintained set — `EXPECTED_LEAVES` — and this dict is DERIVED from
#: it: take the four p1-08-era heads (`device`, `users`, `creds`, `events`), keep each
#: leaf that belongs to one, and subtract the per-group additions a later card explicitly
#: authorized (below). The drift property PREVIOUS_SURFACE exists for is preserved, not
#: weakened: a rename/removal no card admits fails the `EXPECTED_LEAVES`
#: symmetric-difference + len pin first, and an honest bump of that one set re-derives
#: this dict — one reviewable edit where there used to be two coordinated ones.
#:
#: CLI-VERBS-HELP moved two entries to the canonical verb spelling — `creds check` ->
#: `creds test`, `deadletter delete` -> `deadletter remove` (docs/CLI-CONVENTIONS.md). The
#: sets are the DECLARED surface, which is one spelling per operation on purpose: the
#: superseded spellings resolve through `cli_conventions.ALIASES` in `Group.get_command`
#: and are deliberately absent from `Group.commands`, so they neither show in `--help` nor
#: widen this allow-list. `test_superseded_verb_spellings_still_execute` is what pins that
#: the old commands still RUN; this dict is what pins that nothing else appeared.
_HISTORICAL_HEADS: tuple[str, ...] = ("device", "users", "creds", "events")

#: Commands CREDSTORE-LINUX added to an EXISTING group, with the card that authorized each.
#: A dict of additions rather than a widened `PREVIOUS_SURFACE` entry on purpose: the entry
#: above stays the pinned historical shape, so a rename or removal of `test`/`explain` still
#: fails, and the new names are only allowed exactly where they were authorized.
#:
#: `set` is not the vocabulary's canonical verb for "create a record" (`add` is), and the
#: card names it: `creds set` writes a REF->value mapping into the credential file, which is
#: a store operation on a name the operator picks, not the creation of an enumerated record
#: `sink add` creates. It stays because the card names the command; the deviation is
#: recorded rather than silently normalized.
AUTHORISED_GROUP_ADDITIONS: dict[str, set[str]] = {
    "creds": {"set", "get", "remove"},
}


def _derived_previous_surface() -> dict[str, Any]:
    """Project the historical four-head tree out of the authoritative `EXPECTED_LEAVES`."""
    out: dict[str, Any] = {}
    for leaf in EXPECTED_LEAVES:
        parts = leaf.split(" ")
        head = parts[0]
        if head not in _HISTORICAL_HEADS:
            continue
        if head == "events":
            out[head] = None  # a command, not a group (p1-08's naming decision)
            continue
        if len(parts) >= 2 and parts[-1] in AUTHORISED_GROUP_ADDITIONS.get(head, set()):
            continue  # an authorized later addition, not part of the historical shape
        out.setdefault(head, set()).add(parts[-1])
    return out


PREVIOUS_SURFACE: dict[str, Any] = _derived_previous_surface()


def _derived_children(head: str) -> set[str]:
    """Direct child command names `EXPECTED_LEAVES` declares under `head`."""
    return {
        parts[1]
        for leaf in EXPECTED_LEAVES
        if (parts := leaf.split(" ")) and parts[0] == head and len(parts) >= 2
    }


def _derived_subgroup_children(head: str, child: str) -> set[str]:
    """Grandchild command names `EXPECTED_LEAVES` declares under `head child`."""
    return {
        parts[2]
        for leaf in EXPECTED_LEAVES
        if (parts := leaf.split(" ")) and len(parts) == 3 and parts[:2] == [head, child]
    }


def _tree() -> dict[str, Any]:
    import typer

    root = typer.main.get_command(app)
    out: dict[str, Any] = {}
    for name, cmd in root.commands.items():
        sub = getattr(cmd, "commands", None)
        out[name] = None if sub is None else set(sub)
    return out


def test_existing_cli_surface_is_unchanged_and_agent_is_the_only_addition() -> None:
    """The card's binding rule: cli.py gains the `agent` group; nothing existing moves.

    Shape-level (names + grouping), which is what a caller depends on; the full-suite gate
    covers the flag and behaviour level, because every p1-08/p1-09 CLI test still passes
    untouched.

    CREDSTORE-LINUX is the first card to add commands to an EXISTING group (`creds
    set|get|remove`), so the per-group comparison subtracts only the names that card
    authorized (`AUTHORISED_GROUP_ADDITIONS`) — every historical name is still required to
    be present and unchanged, and an unannounced fourth `creds` verb still fails here.
    """
    tree = _tree()
    for name, sub in PREVIOUS_SURFACE.items():
        assert name in tree, f"{name} disappeared from the CLI"
        added = AUTHORISED_GROUP_ADDITIONS.get(name, set())
        if sub is None:
            # A top-level COMMAND (p1-08's `events`), not a group: nothing to subtract.
            assert tree[name] is None, f"{name} changed shape: {tree[name]} != {sub}"
        else:
            assert tree[name] - added == sub, f"{name} changed shape: {tree[name]} != {sub}"
            assert added <= set(tree[name]), f"{name} lost an authorized command: {tree[name]}"
    # E1-07 (docs/ENROLLMENT-MIGRATION.md §7) added the `migrate` group on top of the
    # agent card's addition, t_ce142a14 the `demo` group (offline fake device), SINKS-CLI
    # (docs/SINKS plan) the `sink` group, and CLI-INIT the `init` command (declared as a
    # callback-only Typer group in `gateclerk/init_cli.py`) — each enters the one
    # authoritative leaf set below, which derives this allowance, so an UNANNOUNCED
    # command still fails here. The card's binding rule
    # ("nothing existing moves") holds: every PREVIOUS_SURFACE entry is pinned unchanged
    # above, and each group's own shape is pinned by its own test
    # (test_migrate_group_shape_is_the_section7_surface,
    # tests/test_sinks_cli.py::test_sink_group_exposes_exactly_the_four_commands,
    # tests/test_cli_init.py::test_init_is_a_top_level_command_with_the_shared_output_flag).
    #
    # CLI-SPLIT-STRUCTURE: the allowed-extra set is DERIVED from `EXPECTED_LEAVES` (every
    # head that is not one of the four historical ones), so adding a group bumps the one
    # authoritative set and this allowance follows — instead of a fifth literal to edit.
    # An UNANNOUNCED command still fails, because it has to enter `EXPECTED_LEAVES` first
    # (test_every_leaf_command_declares_output_json compares the live walk against it).
    assert set(tree) - set(PREVIOUS_SURFACE) == (
        {leaf.split(" ")[0] for leaf in EXPECTED_LEAVES} - set(_HISTORICAL_HEADS)
    ), f"unexpected commands: {set(tree)}"


def test_migrate_group_shape_is_the_section7_surface() -> None:
    """E1-07's §7 commands, and no sixth smuggled in (derived from the one leaf set)."""
    assert _tree()["migrate"] == _derived_children("migrate")


def test_agent_group_shape_is_run_ack_deadletter() -> None:
    """The three commands the card names, and no fourth smuggled in (derived likewise)."""
    assert _tree()["agent"] == _derived_children("agent")
    import typer

    deadletter = typer.main.get_command(app).commands["agent"].commands["deadletter"]
    # CLI-VERBS-HELP: `delete` is now the hidden alias and `remove` the declared command
    # (docs/CLI-CONVENTIONS.md). The declared set stays exactly two entries — the alias is
    # resolved in `get_command` and never enters `Group.commands`.
    assert set(deadletter.commands) == _derived_subgroup_children("agent", "deadletter")


def test_agent_run_requires_a_site_and_cannot_be_pointed_at_a_host() -> None:
    """`--site` required, no `--host`: one unit is one site (the systemd `%i` rule).

    A device-reading command that could invent which door to poll would break the invariant
    p1-01 established for the whole CLI. Read from the command DEFINITION, not the rendered
    help — a rendered assertion here is Rich geometry (see tests/_cli_surface.py).
    """
    from _cli_surface import command_at, declared_flags

    flags = declared_flags(command_at(app, ["agent", "run"]))
    assert "--host" not in flags, "the agent must not let an operator pick a device host"
    assert "--site" in flags and "--once" in flags
    assert runner.invoke(app, ["agent", "run"]).exit_code != 0, "a site is never guessed"


def test_agent_site_block_without_iana_tz_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """surface=AGENT is strict: no iana_tz, no agent (§2d — site tz is payroll truth).

    The SAME block is accepted by the P1 CLI surface (warn + compiled-in default), so this also
    pins that the strictness is the agent's own and did not leak into the existing commands.
    """
    device = seeded_device()
    h = AgentHarness(tmp_path, device, monkeypatch)
    h.write_site_block(iana_tz=None)
    code, out = h.cli(["run", "--site", SITE, "--state-root", str(h.state_root), "--once"])
    assert code == CONFIG_ERROR_EXIT
    assert "iana_tz" in out


# --- the read-only device invariant, from the agent's side ------------------------------------


def test_agent_run_only_touches_registered_read_only_endpoints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The registry guard applied to what the AGENT actually put on the wire.

    `tests/test_endpoints_registry.py` pins the table; this pins the request stream (the p1-09
    battery's method), so a new agent-side call that bypasses the registry fails here too. Only
    GETs and the one stateless AcsEvent search POST may ever appear.
    """
    device = seeded_device()
    device.add_events(*punch_events(T0, -300, -100))
    h = AgentHarness(tmp_path, device, monkeypatch)
    code, _ = h.cli(["run", "--site", SITE, "--state-root", str(h.state_root), "--once"])
    assert code == 0
    assert device.served, "the run must actually have polled"
    for one in device.served:
        assert one.path in ALLOWED_PATHS, f"the agent called an unregistered path: {one.path}"
        if one.method.upper() != "GET":
            assert one.path == EVENT_PATH, f"non-GET verb against {one.path}"


def test_every_path_the_agent_calls_is_in_the_endpoint_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same invariant, cross-checked against the registry object itself.

    Two independent statements (a fixed path list above, the live registry here) so neither can
    drift into approving something the read-only promise forbids.
    """
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    h = AgentHarness(tmp_path, device, monkeypatch)
    assert h.cli(["run", "--site", SITE, "--state-root", str(h.state_root), "--once"])[0] == 0
    registered = {e.url_path for e in REGISTRY.values()}
    for one in device.served:
        assert one.path in registered, f"{one.path} is not a registry entry"


def test_agent_run_output_carries_no_credential_and_no_device_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No secret-shaped and no address-shaped output (spec §2e's NO SECRETS rule).

    Checked over everything the command printed AND the health snapshot it left behind: both are
    surfaces an operator (or a monitoring scrape) reads. The unit's own log rule is "site label,
    kind, serial — never a host".
    """
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    h = AgentHarness(tmp_path, device, monkeypatch)
    code, out = h.cli(["run", "--site", SITE, "--state-root", str(h.state_root), "--once"])
    assert code == 0
    assert PASSWORD not in out and "fakepw" not in out
    assert HOST not in out, "a device host must not reach agent output"
    snapshot = json.dumps(h.health_snapshot())
    assert PASSWORD not in snapshot and HOST not in snapshot
    conn = h.conn()
    payload = conn.execute("SELECT jsonl FROM events").fetchone()["jsonl"]
    conn.close()
    assert payload not in out, "the report carries counters, not punch payloads"


# --- the health sidecar P2-06 named this card for ---------------------------------------------


def test_agent_run_writes_the_health_snapshot_p2_06_promised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The §2e export, asserted against P2-06's OWN vocabulary tuple (never a copied list).

    `snapshot_to_json`'s docstring says the reader is "P2-07's socat"; this is the writer. The
    set-equality against `agent_health.METRIC_NAMES` is what stops the export drifting from the
    collector's contract.
    """
    from gateclerk.agent_health import METRIC_NAMES

    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    h = AgentHarness(tmp_path, device, monkeypatch)
    assert h.cli(["run", "--site", SITE, "--state-root", str(h.state_root), "--once"])[0] == 0

    snap = h.health_snapshot()
    assert snap["status"] in ("ok", "degraded")
    assert snap["site"] == SITE
    names = {m["name"] for m in snap["site_metrics"]} | {
        m["name"] for d in snap["devices"] for m in d["metrics"]
    }
    assert names == set(METRIC_NAMES), "the export must be exactly P2-06's §2e vocabulary"
    device_block = next(d for d in snap["devices"] if d["device_serial"] == SERIAL)
    assert device_block["checkpoint_serial"] == 200, "the snapshot reads the real store"


def test_health_snapshot_write_failure_warns_and_never_stops_the_poll(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A broken instrument must not park a door agent.

    A DIRECTORY where the snapshot file belongs makes every export fail with IsADirectory (an
    OSError). The pass must still exit 0, still store, still push, and say one warning line: the
    poll is the product and the snapshot is a copy of its state.
    """
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    h = AgentHarness(tmp_path, device, monkeypatch)
    health_dir = h.state_root / agent_cli.HEALTH_DIR_NAME
    health_dir.mkdir(parents=True, exist_ok=True)
    (health_dir / agent_cli.HEALTH_FILE_NAME).mkdir()  # the write target is a directory

    warns: list[str] = []
    agent = h.api_agent(warn=warns.append)
    try:
        report = agent.run(once=True)
    finally:
        agent.close()
    assert report.ticks == 1
    assert h.stored_serials() == [200], "the poll continued and stored"
    assert any("health snapshot" in w for w in warns), f"no warning line in {warns}"


def test_health_snapshot_is_written_atomically_for_a_concurrent_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Atomic replace: a reader polling the file must never see a half-written snapshot.

    Asserted by shape — the writer leaves no `.tmp` litter behind, and the file is complete JSON
    after every pass (a truncated write would raise here, and a `open(w)` writer would leave the
    temp litter or a partial file at least once in a hundred passes).
    """
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    h = AgentHarness(tmp_path, device, monkeypatch)
    assert h.cli(["run", "--site", SITE, "--state-root", str(h.state_root), "--once"])[0] == 0
    health_dir = h.state_root / agent_cli.HEALTH_DIR_NAME
    assert sorted(p.name for p in health_dir.iterdir()) == [agent_cli.HEALTH_FILE_NAME], (
        "the temp file must be renamed into place, not left beside it"
    )
    json.loads((health_dir / agent_cli.HEALTH_FILE_NAME).read_text(encoding="utf-8"))


# --- the credential seam systemd's LoadCredential= needs ---------------------------------------


def test_credentials_directory_file_feeds_the_flag_rung_and_beats_the_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """systemd delivers a FILE; it must enter as p1-02's FLAG rung, not as a fourth rung.

    `resolve_credentials` stays the only place precedence is decided (config.py's promise), so
    the agent reads the reference file and hands the value over as `password=`. Pinned by
    putting a DIFFERENT password on the env rung: if the file lost, the digest handshake 401s and
    the exit code is 3, not 0.
    """
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    h = AgentHarness(tmp_path, device, monkeypatch, password="fakepw-wrong")
    creds_dir = tmp_path / "creds"
    creds_dir.mkdir()
    from gateclerk.config import credential_ref

    (creds_dir / credential_ref(SITE, HOST)).write_text(f"{PASSWORD}\n", encoding="utf-8")

    code, out = h.cli(
        [
            "run",
            "--site",
            SITE,
            "--state-root",
            str(h.state_root),
            "--credentials-dir",
            str(creds_dir),
            "--once",
        ]
    )
    assert code == 0, out
    assert len(h.pushed_lines()) == 1


def test_credential_file_trailing_newline_is_trimmed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A digest password carrying a newline authenticates as a DIFFERENT password.

    So trimming is a correctness rule, not tidiness: the file is written with a trailing newline
    (what `install`, an editor or `echo` produces) and the run must still authenticate.
    """
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    h = AgentHarness(tmp_path, device, monkeypatch)
    creds_dir = tmp_path / "creds"
    creds_dir.mkdir()
    from gateclerk.config import credential_ref

    (creds_dir / credential_ref(SITE, HOST)).write_text(PASSWORD + "\r\n", encoding="utf-8")
    code, out = h.cli(
        [
            "run",
            "--site",
            SITE,
            "--state-root",
            str(h.state_root),
            "--credentials-dir",
            str(creds_dir),
            "--once",
        ]
    )
    assert code == 0, out


def test_missing_credential_file_is_loud_and_polls_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A unit given a credentials dir with no matching file is a BROKEN install.

    Falling through to the env/keychain rung here would turn a config error into a mystery 401 —
    and a 401 is what burns the device's lockout budget (OBSERVED.md "lockout accounting"). So:
    exit 2 naming the reference, before a single request goes out.
    """
    device = seeded_device()
    h = AgentHarness(tmp_path, device, monkeypatch)
    creds_dir = tmp_path / "empty-creds"
    creds_dir.mkdir()
    from gateclerk.config import credential_ref

    code, out = h.cli(
        [
            "run",
            "--site",
            SITE,
            "--state-root",
            str(h.state_root),
            "--credentials-dir",
            str(creds_dir),
            "--once",
        ]
    )
    assert code == CONFIG_ERROR_EXIT
    assert credential_ref(SITE, HOST) in out, "the refusal NAMES the reference it looked for"
    assert device.served == [], "the refusal must happen before any request"


def test_state_root_relocates_the_store_park_and_health_together(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One --state-root moves all three, and the reader commands find them.

    If the three disagreed, `ack` would clear a park nobody wrote and `deadletter list` would
    report an empty table for a site that is dying. Pinned by writing with the writer and reading
    back with both readers at the same relocated root.
    """
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    h = AgentHarness(tmp_path, device, monkeypatch, db_path="gateclerk-site-a.sqlite3")
    assert h.cli(["run", "--site", SITE, "--state-root", str(h.state_root), "--once"])[0] == 0
    assert (h.state_root / "gateclerk-site-a.sqlite3").exists()
    assert (h.state_root / agent_cli.HEALTH_DIR_NAME / agent_cli.HEALTH_FILE_NAME).exists()

    # The readers accept the same root and find nothing (a legitimate "(no rows)", not a crash)...
    assert h.cli(["deadletter", "list", "--site", SITE, "--state-root", str(h.state_root)])[0] == 0
    # ...and `resolve_db_path`/`resolve_state_root` agree with where the writer actually put it.
    assert agent_cli.resolve_db_path(h.site_config(), h.state_root) == str(
        h.state_root / "gateclerk-site-a.sqlite3"
    )
    assert agent_cli.resolve_state_root(h.site_config(), h.state_root) == h.state_root


def test_a_relative_db_path_without_a_state_root_stays_relative_to_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No --state-root means no relocation (the unit relies on WorkingDirectory instead).

    Pinned so `--state-root` is not secretly mandatory: the unit's ExecStart passes it, but
    deploy/README.md also documents `WorkingDirectory=<STATE_ROOT>` as the mechanism, and a
    hand-run from a checkout must keep writing beside the store it already uses.
    """
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    h = AgentHarness(tmp_path, device, monkeypatch)
    home = tmp_path / "cwd"
    home.mkdir()
    monkeypatch.chdir(home)
    code, out = h.cli(["run", "--site", SITE, "--once"])
    assert code == 0, out
    assert (home / h.db_path).exists(), "no --state-root: the relative db_path stays CWD-relative"


# --- small, cheap pins the code cannot otherwise prove -----------------------------------------


def test_report_dataclasses_are_payload_free_by_construction() -> None:
    """`SiteTickReport`/`SiteRunReport` are the agent's log line (journald reads them).

    Field names pinned: counters, stamps, the site label and device keys — never a payload, a
    host, or a credential. Structural rather than prose so a new field is a red test.
    """
    tick = agent_cli.SiteTickReport(at="2026-10-19T07:00:00+00:00")
    run = agent_cli.SiteRunReport(site=SITE, db_path="x.sqlite3", ticks=1)
    for name in tick.as_dict():
        assert not any(bad in name for bad in ("payload", "password", "host", "jsonl")), name
    for name in run.as_dict():
        assert not any(bad in name for bad in ("payload", "password", "host", "jsonl")), name
    assert run.as_dict()["parked"] == [] and run.as_dict()["circuit_open"] == []


def test_an_https_push_target_without_a_token_warns_and_pushes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§3 after Task 15: `https://` HAS a transport now — but still never invents an
    endpoint, and a target whose bearer is missing must NOT burn the outage clock.

    The pre-Task-15 behaviour was a startup refusal (the repo shipped only `stub://`).
    The contract now: the agent runs, stores (the store is the truth), and the push step
    warns naming the keychain item `gateclerk-ingest-<site>` while LEAVING rows queued —
    draining anyway would fail every row on the same missing-token error until the 24 h
    §2c bound dead-lettered the whole backlog for what is an install step, not an outage.
    Zero bytes may reach the ingest, and the test never touches the real keychain: the
    reader is faked to answer "item missing" exactly as `security` would.
    """
    import gateclerk.agent_push as agent_push
    from gateclerk.config import CredentialUnavailable

    class _MissingItemReader:
        def read(self, target, *, with_comment: bool = True):
            raise CredentialUnavailable(
                f"keychain item missing for service {target.keychain_service!r}"
            )

    monkeypatch.setattr(agent_push, "KeychainReader", _MissingItemReader)
    monkeypatch.delenv(f"GATECLERK_INGEST_TOKEN_{SITE.upper()}", raising=False)
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    h = AgentHarness(tmp_path, device, monkeypatch, push_target="https://ingest.example.invalid/x")
    code, out = h.cli(["run", "--site", SITE, "--state-root", str(h.state_root), "--once"])
    assert code == 0, out
    assert "gateclerk-ingest-" in out, "the warn must name the keychain item to fix"
    # The punch was STORED (polling works without a push token) and NOT pushed (no stub
    # file exists for an https target, and the drain never ran: queue depth says so).
    assert h.stored_serials(), "the store is still the truth without a token"
    with h.conn() as conn:
        assert conn.execute("SELECT COUNT(*) FROM push_queue").fetchone()[0] >= 1
        assert conn.execute("SELECT COUNT(*) FROM dead_letter").fetchone()[0] == 0


def test_agent_cli_imports_without_the_cli_and_without_typer_names_in_its_warn_path() -> None:
    """`agent_cli` is usable as a library (a future systemd-free caller needs that).

    `cli.py` imports it only inside command bodies and the health collector imports
    `cli._warn_tz_mismatch` lazily, so the composition must not drag the CLI in at import time.
    """
    import importlib

    module = importlib.import_module("gateclerk.agent_cli")
    assert module.SiteAgent is agent_cli.SiteAgent
    source = Path(str(module.__file__)).read_text(encoding="utf-8")
    assert "import typer" not in source, "the agent's own module must not need the CLI stack"
    assert hasattr(module, "_stderr_warn")


def test_site_tz_and_device_tz_from_config_reach_the_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The agent passes sites.toml's zones to the loop rather than defaulting them.

    §2d: the AGENT surface refuses a block with no `iana_tz` precisely because a defaulted zone
    is a payroll error; so the block's declared values must actually arrive (a loop that
    defaulted to UTC would resolve every punch an hour or two out and store it quietly).
    """
    device = seeded_device()
    device.add_events(*punch_events(T0, -300))
    h = AgentHarness(tmp_path, device, monkeypatch)
    agent = h.api_agent()
    try:
        loop = agent.loops[0]
        assert loop.site_tz == SITE_TZ
        assert loop.device_tz == "Europe/Bucharest"
        assert loop.cadence_s == CADENCE_S and loop.overlap_s == OVERLAP_S
    finally:
        agent.close()
