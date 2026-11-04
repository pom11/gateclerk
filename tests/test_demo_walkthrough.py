"""DEMO-WALKTHROUGH: `gateclerk demo` runs the whole loop with no real anything.

The card's goal, pinned mechanically: one command must poll a device, store, queue and
deliver to two sinks — with **no** door controller, **no** ingest deployment, **no**
keychain item, **no** write outside a scratch directory, **no** prompt, **no** TTY and a
bounded runtime. Nothing here trusts the module's own narrative; each arm reads the
artifacts the run leaves behind (the csv, the mock sink's recorded batches, the device's
request log, the scratch tree) and asserts against them.

Arms (the CLI arm — the real subprocess under CI's proxy wall — sits at the bottom and
drives the shipped `demo demo` verb):

* ARM 1 — the loop's evidence: every synthetic event reaches BOTH sinks, the csv carries
  the frozen `CSV_COLUMNS` header verbatim, the mock saw the frozen contract headers.
* ARM 2 — the zero-keychain law: `KeychainReader` may not even be constructed, and no
  process spawn may name `security`, while `openssl` (the cert mint) must be spawned.
* ARM 3 — the zero-real-config law: `HOME` pointed at a directory of its own; afterwards
  it contains nothing, so `~/.gateclerk`/`~/gateclerk` were never consulted.
* ARM 4 — determinism + bounded time: two runs agree row-for-row, and a run is far inside
  the card's budget.
* ARM 5 — loud refusals: no `openssl` means refusal, not plaintext; `ticks=0` is refused;
  the bearer value appears in no printed line.
* ARM 6 — loopback discipline: every socket address the run touches is loopback, and an
  unpinned TLS client is refused.
* ARM 7 — the generated config: it passes the agent validator and carries references.

Synthetic-only law: the only addresses here are loopback, and the only credential-shaped
values are the demo module's own recognisable placeholders (imported, never re-typed).
"""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import _socketseam
import gateclerk.agent_push as agent_push
import gateclerk.cli as cli_mod
import gateclerk.config as cfg
import gateclerk.credentials as creds
import gateclerk.demo_walkthrough as dw
import gateclerk.sink_writers as sink_writers
from gateclerk import demo_device as demo
from gateclerk.sinks import CSV_COLUMNS

runner = CliRunner()

#: The card's bounded-time budget (60 s), halved so a merely-slow machine still passes
#: while a run that hangs is still caught. A real run measures ~1 s.
RUN_BUDGET_S = 30.0


# --- harness -------------------------------------------------------------------------------------


@dataclass
class DemoRun:
    """One in-process demo run: the report plus everything it printed."""

    report: dw.WalkthroughReport
    lines: list[str]

    @property
    def output(self) -> str:
        return "\n".join(self.lines)


@pytest.fixture
def socket_allow(monkeypatch: pytest.MonkeyPatch) -> None:
    """Undo the autouse `netoff` guard for THIS test (the demo talks to loopback sockets).

    Same reason tests/test_demo_device.py needs it: the subject IS a server answering a
    real client, which `httpx.MockTransport` cannot express. `tests/_socketseam.py` holds
    the only honest capture of the real socket attributes (taken at import, before any
    patch); it also unsets the proxy vars so loopback legs are not CONNECT-ed to CI's
    dead-port proxy.
    """
    _socketseam.release(monkeypatch)


@pytest.fixture
def scratch_root(tmp_path: Path) -> Path:
    """A root OUTSIDE the user's home for one demo run (tmp_path already is)."""
    return tmp_path / "demo-run"


class _KeychainTripwire:
    """Every way this repo can reach `/usr/bin/security`, replaced by a recorder.

    Three surfaces, because the keychain is reachable from three places: the resolver's
    `KeychainReader`, the pusher's own reference to that class, and `subprocess.run`
    itself (what a real reader eventually calls). Any of them firing records the offender
    and raises — a demo that touched the keychain fails LOUD rather than passing on a
    machine that happens to have an item in it.

    `subprocess.run` is wrapped, not replaced: the demo legitimately spawns `openssl` for
    its certificate, and this repo's rule is that the demo proves that path rather than
    stubbing it. `security` in the argv is the refusal.
    """

    def __init__(self) -> None:
        self.spawns: list[str] = []
        self.keychain_hits: list[str] = []

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        outer = self

        class _TripwireReader:
            def __init__(self, *args: object, **kwargs: object) -> None:
                outer.keychain_hits.append("KeychainReader() constructed")

            def read(self, *args: object, **kwargs: object) -> object:
                outer.keychain_hits.append("KeychainReader.read()")
                raise AssertionError("the demo read the keychain")

        for module in (cfg, agent_push, creds):
            monkeypatch.setattr(module, "KeychainReader", _TripwireReader, raising=False)

        real_run = subprocess.run

        def record_run(argv: Any, *args: Any, **kwargs: Any) -> Any:
            words = [str(word) for word in (argv if isinstance(argv, list) else [argv])]
            outer.spawns.append(" ".join(words))
            if any(Path(word).name == "security" for word in words):
                raise AssertionError(f"the demo spawned the keychain tool: {words}")
            return real_run(argv, *args, **kwargs)

        monkeypatch.setattr(subprocess, "run", record_run)


@pytest.fixture
def no_keychain(monkeypatch: pytest.MonkeyPatch) -> _KeychainTripwire:
    """Install the keychain tripwire and the spawn recorder for this test only."""
    trip = _KeychainTripwire()
    trip.install(monkeypatch)
    return trip


def _run_inprocess(root: Path, *, ticks: int = 3, keep: bool = True) -> DemoRun:
    """One demo run into `root`, capturing everything it said."""
    lines: list[str] = []
    report = dw.run_demo_walkthrough(
        root=root, ticks=ticks, keep=keep, out=lines.append, seed=20260615
    )
    return DemoRun(report=report, lines=lines)


def _csv_rows(path: Path) -> list[dict[str, str]]:
    """The csv as dicts, keyed by the frozen column names."""
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _tree(directory: Path) -> set[str]:
    return {str(path.relative_to(directory)) for path in directory.rglob("*")}


# --- ARM 1: the loop's evidence -------------------------------------------------------------------


def test_demo_delivers_every_synthetic_event_to_both_sinks(
    scratch_root: Path, socket_allow: None, no_keychain: _KeychainTripwire
) -> None:
    """The card's core claim: the fake device's events reach the csv AND the mock ingest."""
    run = _run_inprocess(scratch_root)
    report = run.report
    want = [int(event["serialNo"]) for event in demo.demo_events()]

    assert report.ticks == 3
    assert report.inserted == demo.DEMO_EVENT_COUNT == len(want)
    assert report.checkpoint_serial == want[-1], "the checkpoint is the last synthetic serial"
    assert report.csv_rows == len(want)
    assert report.mock_lines == len(want)
    assert report.batches, "the mock ingest received nothing"

    # Both sinks took every row, none failed, none was dead-lettered.
    for name in (dw.DEMO_CSV_SINK_NAME, dw.DEMO_MOCK_SINK_NAME):
        counts = report.per_sink[name]
        assert counts["pushed"] == len(want), (name, counts)
        assert counts["push_failed"] == 0 and counts["dead_lettered"] == 0, (name, counts)

    # The csv holds exactly the synthetic serials, once each, in store order.
    rows = _csv_rows(report.csv_path)
    assert [int(row["serial_no"]) for row in rows] == want, "csv rows are the corpus, oldest-first"
    assert {row["sink_name"] for row in rows} == {dw.DEMO_CSV_SINK_NAME}
    assert {row["site"] for row in rows} == {dw.DEMO_SITE_NAME}
    assert {row["device_serial"] for row in rows} == {demo.DEMO_SERIAL}

    # The mock leg is the per-row transport contract: one line per batch.
    assert [batch.lines for batch in report.batches] == [1] * len(want)


def test_demo_csv_carries_the_frozen_columns_verbatim(
    scratch_root: Path, socket_allow: None
) -> None:
    """The header row IS `sinks.CSV_COLUMNS` — the demo may not invent its own columns."""
    report = _run_inprocess(scratch_root).report
    header_line = report.csv_path.read_text(encoding="utf-8").splitlines()[0]
    assert header_line == ",".join(CSV_COLUMNS)
    assert report.csv_header == CSV_COLUMNS
    assert report.csv_path.is_file()
    assert str(scratch_root) in str(report.csv_path)


def test_demo_mock_sink_sees_the_contract_headers(scratch_root: Path, socket_allow: None) -> None:
    """`Authorization` PRESENCE (never the value), `X-Gateclerk-Site`, `application/jsonl`."""
    report = _run_inprocess(scratch_root).report
    assert report.batches, "the mock ingest received nothing"
    for batch in report.batches:
        assert batch.authorization_present is True
        assert batch.gateclerk_site == dw.DEMO_SITE_NAME.upper()
        assert batch.content_type == "application/jsonl"
        assert batch.path == "/ingest"
    # The presence flag is all the mock keeps: no batch carries a header value anywhere.
    assert all(dw.DEMO_MOCK_TOKEN not in batch.describe() for batch in report.batches)


def test_demo_summary_prints_the_evidence_the_card_asks_for(
    scratch_root: Path, socket_allow: None
) -> None:
    """Events seen, per-sink delivered, csv row count, csv path and tail — on the output."""
    run = _run_inprocess(scratch_root)
    out = run.output
    for needle in (
        "events stored",
        f"sink {dw.DEMO_CSV_SINK_NAME}",
        f"sink {dw.DEMO_MOCK_SINK_NAME}",
        "mock batches",
        "csv rows",
        "csv path",
        "tail",
        "matches CSV_COLUMNS",
    ):
        assert needle in out, f"summary is missing {needle!r}:\n{out}"
    assert str(run.report.csv_path) in out
    assert f"pushed={demo.DEMO_EVENT_COUNT}" in out


def test_demo_csv_tail_and_report_tail_agree(scratch_root: Path, socket_allow: None) -> None:
    """The report's `csv_tail` is the file's last lines — not a paraphrase of them."""
    report = _run_inprocess(scratch_root).report
    last_lines = report.csv_path.read_text(encoding="utf-8").splitlines()[1:][-3:]
    assert last_lines == list(report.csv_tail)


def test_demo_repeat_ticks_do_not_redeliver(scratch_root: Path, socket_allow: None) -> None:
    """The checkpoint law, shown by the demo: 3 ticks still produce 46 rows, not 138.

    This is the arm that catches a demo whose "walkthrough" quietly re-sends the corpus
    every tick — which would teach a developer that the agent's cursor does not work.
    """
    report = _run_inprocess(scratch_root, ticks=3).report
    assert report.inserted == demo.DEMO_EVENT_COUNT
    assert report.unchanged > 0, "later ticks saw nothing unchanged: the cursor is not holding"
    assert report.csv_rows == demo.DEMO_EVENT_COUNT
    assert report.mock_lines == demo.DEMO_EVENT_COUNT


def test_report_as_dict_is_json_serialisable(scratch_root: Path, socket_allow: None) -> None:
    """The summary the CLI renders is plain JSON — no Path objects escaping into it."""
    report = _run_inprocess(scratch_root).report
    decoded = json.loads(json.dumps(report.as_dict()))
    assert decoded["site"] == dw.DEMO_SITE_NAME
    assert decoded["csv"]["header"] == list(CSV_COLUMNS)
    assert decoded["csv"]["rows"] == demo.DEMO_EVENT_COUNT
    assert decoded["sinks"][dw.DEMO_MOCK_SINK_NAME]["pushed"] == demo.DEMO_EVENT_COUNT


# --- ARM 2: the zero-keychain law -----------------------------------------------------------------


def test_demo_never_touches_the_keychain(
    scratch_root: Path, socket_allow: None, no_keychain: _KeychainTripwire
) -> None:
    """No `KeychainReader` construction, no `read`, no `security` process. Ever."""
    _run_inprocess(scratch_root)
    assert no_keychain.keychain_hits == []
    assert not any("security" in line for line in no_keychain.spawns), no_keychain.spawns
    # ...and the one thing it DID spawn is the certificate mint, proving that path.
    assert any("openssl" in line for line in no_keychain.spawns), no_keychain.spawns


def test_demo_still_works_when_the_ambient_password_is_someone_elses(
    scratch_root: Path, socket_allow: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An ambient `GATECLERK_*` on a developer's laptop cannot leak into the demo.

    The digest box accepts exactly one password, so if the resolver had taken the env rung
    from the process environment the run would 401 and deliver nothing. It does not, which
    proves the demo's own credential won — and the ambient variables survive the run
    untouched, so nothing leaks out the other way either.
    """
    ambient = "ambient-not-the-demo-credential"
    monkeypatch.setenv("GATECLERK_PASSWORD", ambient)
    monkeypatch.setenv("GATECLERK_127_0_0_1_PASSWORD", ambient)
    monkeypatch.setenv(dw.DEMO_INGEST_ENV, ambient)
    report = _run_inprocess(scratch_root).report
    assert report.inserted == demo.DEMO_EVENT_COUNT
    assert report.mock_lines == demo.DEMO_EVENT_COUNT
    assert os.environ["GATECLERK_PASSWORD"] == ambient
    assert os.environ[dw.DEMO_INGEST_ENV] == ambient


# --- ARM 3: nothing outside the scratch dir -------------------------------------------------------


def test_demo_writes_nothing_outside_its_root(
    tmp_path: Path, socket_allow: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`HOME` stays untouched: the demo's root is the tree.

    `~/.gateclerk` and `~/gateclerk` are the bundle-root defaults the `migrate` group uses; a
    demo that consulted them would leave a trace in a directory the card forbids. HOME and
    CWD are pointed at a directory of our own and then required to contain exactly what the
    test put in them.
    """
    fake_home = tmp_path / "fake-home"
    cwd = tmp_path / "cwd"
    for directory in (fake_home, cwd):
        directory.mkdir(parents=True, exist_ok=True)
    (fake_home / "keepme.txt").write_text("unchanged", encoding="utf-8")
    (cwd / "keepme.txt").write_text("unchanged", encoding="utf-8")
    before_home, before_cwd = _tree(fake_home), _tree(cwd)
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.chdir(cwd)

    report = dw.run_demo_walkthrough(
        root=tmp_path / "run", ticks=2, keep=True, out=lambda text: None, seed=7
    )

    assert _tree(fake_home) == before_home, "the demo wrote inside HOME"
    assert _tree(cwd) == before_cwd, "the demo wrote in the working directory"
    assert not (fake_home / ".gateclerk").exists()
    assert not (fake_home / "gateclerk").exists()
    # ...and everything it DID write is under the root it was given.
    for path in (p for p in (tmp_path / "run").rglob("*") if p.is_file()):
        assert path.is_relative_to(report.root)


def test_demo_removes_its_scratch_dir_unless_kept(socket_allow: None) -> None:
    """No `--root`: `mkdtemp` under the temp dir, gone again when the run returns."""
    report = dw.run_demo_walkthrough(ticks=1, out=lambda text: None, seed=11)
    assert report.root.is_absolute()
    assert dw.DEMO_SCRATCH_PREFIX in report.root.name
    assert not report.root.exists(), "a default demo run left its scratch directory behind"
    assert report.kept is False, "a discarded tree must not be reported as kept"


def test_demo_keep_leaves_a_readable_tree_with_a_private_key(
    scratch_root: Path, socket_allow: None
) -> None:
    """`--keep` is a developer affordance: readable config + csv, key file not world-read."""
    report = _run_inprocess(scratch_root).report
    assert (scratch_root / "sites.toml").is_file()
    assert report.csv_path.is_file()
    health = scratch_root / "state" / "health" / "agent.json"
    assert health.is_file(), "the agent's own health snapshot belongs in the scratch tree"
    key = scratch_root / "tls" / "mock-ingest-key.pem"
    assert key.is_file()
    assert key.stat().st_mode & 0o777 == 0o600
    assert report.kept is True


# --- ARM 4: determinism and the time budget -------------------------------------------------------


def test_demo_is_deterministic_across_runs(tmp_path: Path, socket_allow: None) -> None:
    """Two runs of the same command produce the same rows, batches and checkpoint serial.

    The card asks for a deterministic seed; this is the observable version of that promise
    — a developer on another machine sees the same demo, and a test can assert exact counts
    instead of "at least something".
    """
    first = _run_inprocess(tmp_path / "a").report
    second = _run_inprocess(tmp_path / "b").report

    assert first.checkpoint_serial == second.checkpoint_serial
    assert first.csv_rows == second.csv_rows == demo.DEMO_EVENT_COUNT
    assert len(first.batches) == len(second.batches)
    assert first.per_sink == second.per_sink
    assert _csv_rows(first.csv_path) == _csv_rows(second.csv_path)


def test_demo_run_is_well_inside_the_bounded_time_budget(
    scratch_root: Path, socket_allow: None
) -> None:
    """Three ticks, two servers, TLS and a full drain — a tenth of the card's budget."""
    started = time.monotonic()
    _run_inprocess(scratch_root)
    elapsed = time.monotonic() - started
    assert elapsed < RUN_BUDGET_S / 3, f"the demo took {elapsed:.1f}s; budget is {RUN_BUDGET_S}s"


def test_demo_bounded_tick_count_is_honoured(tmp_path: Path, socket_allow: None) -> None:
    """`ticks` is the bound the card demands, and one tick is already a full delivery."""
    one = _run_inprocess(tmp_path / "one", ticks=1).report
    assert one.ticks == 1
    assert one.inserted == demo.DEMO_EVENT_COUNT
    assert one.csv_rows == demo.DEMO_EVENT_COUNT


def test_demo_device_requests_stay_within_a_bounded_request_budget(
    scratch_root: Path, socket_allow: None
) -> None:
    """Three ticks must not hammer the box — the request count is part of the story."""
    report = _run_inprocess(scratch_root).report
    assert report.device_requests > 0
    assert report.device_requests < 100, report.device_requests


# --- ARM 5: loud refusals ------------------------------------------------------------------------


def test_demo_refuses_to_run_without_a_certificate_tool(
    scratch_root: Path, socket_allow: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No `openssl` means a refusal naming the clear-text law — never a plaintext fallback."""
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(dw.DemoWalkthroughError) as raised:
        dw.run_demo_walkthrough(root=scratch_root, ticks=1, out=lambda text: None)
    message = str(raised.value).lower()
    assert "openssl" in message
    assert "clear-text" in message or "clear text" in message


@pytest.mark.parametrize("ticks", [0, -1])
def test_demo_refuses_a_bounded_tick_count_below_one(ticks: int) -> None:
    with pytest.raises(dw.DemoWalkthroughError):
        dw.run_demo_walkthrough(root=None, ticks=ticks, out=lambda text: None)


def test_demo_never_prints_the_bearer_value(scratch_root: Path, socket_allow: None) -> None:
    """The printed loop prints header PRESENCE only; the token appears nowhere in the output."""
    run = _run_inprocess(scratch_root)
    assert dw.DEMO_MOCK_TOKEN not in run.output
    assert "Bearer" not in run.output
    arrivals = [line for line in run.lines if line.lstrip().startswith("batch")]
    assert len(arrivals) == demo.DEMO_EVENT_COUNT
    assert all("Authorization=present" in line for line in arrivals)


def test_demo_refuses_a_non_loopback_mock_bind(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """SYNTHETIC-ONLY LAW on the ingest too: a non-loopback bind host is refused."""
    monkeypatch.setattr(dw, "DEMO_DEVICE_HOST", demo.DEMO_DOCUMENT_HOST)
    with pytest.raises(dw.DemoWalkthroughError):
        dw.MockIngestSink(cert_dir=tmp_path).start()


def test_demo_hands_the_mock_sink_a_refusing_keychain_reader(
    scratch_root: Path, socket_allow: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The zero-keychain law is structural, not a happy accident of resolution order.

    `agent_push._resolve_token` builds its reader as an ARGUMENT
    (`keychain=… if self._keychain is not None else KeychainReader()`), so an un-seamed
    transport CONSTRUCTS a real `KeychainReader` on every drain even when the bearer is
    already in hand from the env rung — harmless today, one refactor away from an ACL
    prompt. The demo passes the factory's own `keychain=` seam instead, and this arm
    pins that object: reading through it raises a sentence rather than asking the
    operator's laptop for permission.
    """
    seen: list[Any] = []
    real = sink_writers.build_https_sink_transport

    def spy(site: str, spec: Any, **kwargs: Any) -> Any:
        seen.append(kwargs.get("keychain"))
        return real(site, spec, **kwargs)

    monkeypatch.setattr(sink_writers, "build_https_sink_transport", spy)
    _run_inprocess(scratch_root)

    assert seen, "the demo never built the https sink transport"
    injected = [reader for reader in seen if reader is not None]
    assert injected, "the https sink leg was given no keychain seam (the default reader)"
    for reader in injected:
        with pytest.raises(dw.DemoWalkthroughError):
            reader.read("gateclerk-ingest-demo-site")


def test_mock_ingest_start_twice_is_a_loud_error(tmp_path: Path, socket_allow: None) -> None:
    box = dw.MockIngestSink(cert_dir=tmp_path).start()
    try:
        with pytest.raises(dw.DemoWalkthroughError):
            box.start()
    finally:
        box.stop()


def test_received_batch_describe_is_facts_only() -> None:
    """The one line the mock prints carries counts and presence, never a value or a host."""
    batch = dw.ReceivedBatch(
        path="/ingest",
        authorization_present=True,
        gateclerk_site=dw.DEMO_SITE_NAME.upper(),
        content_type="application/jsonl",
        lines=3,
    )
    line = batch.describe()
    assert "lines=3" in line and "Authorization=present" in line
    assert dw.DEMO_MOCK_TOKEN not in line
    assert demo.DEMO_DOCUMENT_HOST not in line
    assert batch.as_dict()["authorization_present"] is True


# --- ARM 6: loopback discipline -------------------------------------------------------------------


def test_demo_opens_sockets_to_nothing_but_loopback(
    scratch_root: Path, socket_allow: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every bind and connect the run performs is loopback — the SYNTHETIC-ONLY boundary."""
    seen: set[str] = set()
    real_socket = _socketseam.REAL["socket"]

    class _SpySocket(real_socket):  # type: ignore[misc,valid-type]
        def connect(self, address: Any) -> None:
            self._note(address)
            super().connect(address)

        def bind(self, address: Any) -> None:
            self._note(address)
            super().bind(address)

        @staticmethod
        def _note(address: Any) -> None:
            if isinstance(address, tuple) and address:
                seen.add(str(address[0]))

    monkeypatch.setattr(socket, "socket", _SpySocket)
    _run_inprocess(scratch_root)

    assert seen, "the demo opened no sockets, which would mean it did not run"
    offenders = {host for host in seen if not (host.startswith("127.") or host in {"::1", ""})}
    assert not offenders, f"the demo used a non-loopback address: {sorted(offenders)}"


@pytest.mark.parametrize(("method", "path"), [("GET", "/")])
def test_mock_ingest_answers_a_liveness_read(
    method: str, path: str, tmp_path: Path, socket_allow: None
) -> None:
    """The mock is curl-able: a GET answers 200 and is not counted as a delivered batch."""
    import httpx

    box = dw.MockIngestSink(cert_dir=tmp_path).start()
    pin = ssl.create_default_context(cafile=str(box.ca_bundle))
    try:
        response = httpx.get(f"{box.base_url}{path}", verify=pin, trust_env=False, timeout=10)
        assert response.status_code == dw.DEMO_MOCK_INGEST_STATUS
        assert box.received() == ()
        post = httpx.post(
            box.ingest_url, content=b'{"a":1}\n', verify=pin, trust_env=False, timeout=10
        )
        assert post.status_code == dw.DEMO_MOCK_INGEST_STATUS
        assert [batch.lines for batch in box.received()] == [1]
    finally:
        box.stop()


def test_mock_ingest_refuses_an_unpinned_client(tmp_path: Path, socket_allow: None) -> None:
    """TLS is real, not decorative: a client that does not pin the CA bundle fails.

    The whole §4.1 posture rests on the transport verifying. If the mock answered plain
    HTTP, or answered to any certificate, this arm is the one that would say so.
    """
    import httpx

    box = dw.MockIngestSink(cert_dir=tmp_path).start()
    try:
        with pytest.raises(httpx.ConnectError):
            httpx.get(box.base_url, trust_env=False, timeout=10)
    finally:
        box.stop()


# --- ARM 7: the generated config ------------------------------------------------------------------


def test_demo_sites_toml_parses_on_the_agent_surface_and_carries_no_values(
    tmp_path: Path,
) -> None:
    """The generated config is real config: it passes the agent validator and names refs.

    `device_tz` + `iana_tz` + an absolute csv path + a `token_env` REFERENCE and no
    credential value anywhere is the SINKS-CORE law, checked here against the text the demo
    actually writes rather than against a hand-written example.
    """
    text = dw.demo_sites_toml(root=tmp_path, device_port=8080, ingest_url="https://127.0.0.1:9/x")
    path = tmp_path / "sites.toml"
    path.write_text(text, encoding="utf-8")
    site = cfg.load_sites(path, surface=cfg.ConfigSurface.AGENT)[dw.DEMO_SITE_NAME]

    sinks = {spec.name: spec for spec in site.effective_sinks}
    assert set(sinks) == {dw.DEMO_CSV_SINK_NAME, dw.DEMO_MOCK_SINK_NAME}
    assert sinks[dw.DEMO_CSV_SINK_NAME].path is not None
    assert sinks[dw.DEMO_CSV_SINK_NAME].path.startswith(str(tmp_path))
    assert sinks[dw.DEMO_MOCK_SINK_NAME].ref == "https://127.0.0.1:9/x"
    assert sinks[dw.DEMO_MOCK_SINK_NAME].token_env == dw.DEMO_INGEST_ENV
    assert site.iana_tz == site.device_tz == demo.DEMO_SITE_TZ
    assert site.push_target is None, "a sink-declaring site must not also carry push_target"
    assert "password" not in text.lower()
    assert dw.DEMO_MOCK_TOKEN not in text
    assert demo.DEMO_DEFAULT_PASSWORD not in text


# --- the CLI arm (the `demo demo` verb) --------------------------------------------


def test_demo_verb_help_is_read_only_and_names_the_scratch_root() -> None:
    """`--help` works without a TTY and its prose stays read-only + honest about paths."""
    from _cli_surface import command_at, declared_flags, declared_prose

    group = command_at(cli_mod.app, ["demo"])
    assert "demo" in getattr(group, "commands", {}), "no `demo` verb on the demo group"
    cmd = command_at(cli_mod.app, ["demo", "demo"])
    assert {"--root", "--ticks", "--keep", "--output"} <= declared_flags(cmd)

    prose = declared_prose(cmd).lower()
    # Word boundaries are the whole test (same law as test_cli_commands.py's mutating-verb
    # tripwire): a naive `"put " in text` fires on "out**put** format", which every command
    # prints, and a tripwire that cries wolf gets switched off.
    for verb in (r"\bput\b", r"\bdelete\b", r"\breboot\b", r"\bshutdown\b"):
        assert re.search(verb, prose) is None, f"demo help mentions a write verb: {verb}"
    assert "temp" in prose or "scratch" in prose

    shown = runner.invoke(cli_mod.app, ["demo", "demo", "--help"])
    assert shown.exit_code == 0
    # Assert the render only renders (exit 0, and the usage line Rich never elides). Which
    # flags exist is asserted from the DEFINITION above via `declared_flags`: on a no-TTY CI
    # stream Rich wraps the option panel at 80 columns and truncates the middle of it, so an
    # assertion of the form ` "--root" in shown.output` fails there while passing locally —
    # the same reason `declared_prose` reads the definition, documented in _cli_surface.py.
    assert "gateclerk demo demo" in shown.output


def test_demo_device_group_shape_is_unchanged() -> None:
    """This card adds a verb to the `demo` group; `demo device`'s surface must not move."""
    from _cli_surface import command_at

    assert set(getattr(command_at(cli_mod.app, ["demo", "device"]), "commands", {})) == {
        "serve",
        "urls",
    }


def test_demo_command_runs_end_to_end_and_exits_zero(tmp_path: Path) -> None:
    """THE CI arm: a child process runs the whole loop and exits 0 under CI's proxy wall.

    A subprocess rather than the CliRunner, because the card's claim is about the shipped
    command: exit code, no TTY requirement, and a machine-readable summary. The proxy
    variables are set the way CI sets them (dead port, empty NO_PROXY) — that wall is
    exactly what would break a loopback demo that honoured `trust_env`, so the arm runs
    *inside* it rather than opting out of it.
    """
    root = tmp_path / "cli-run"
    env = {
        **os.environ,
        "HTTP_PROXY": "http://127.0.0.1:9",
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "ALL_PROXY": "http://127.0.0.1:9",
        "NO_PROXY": "",
        # A developer's laptop may have a real GATECLERK_* set; the demo must not read it.
        "GATECLERK_PASSWORD": "***",
        "GATECLERK_127_0_0_1_PASSWORD": "***",
    }
    started = time.monotonic()
    proc = subprocess.run(  # noqa: S603 - argv list, no shell, this interpreter
        [
            sys.executable,
            "-m",
            "gateclerk.cli",
            "demo",
            "demo",
            "--root",
            str(root),
            "--ticks",
            "3",
            "--keep",
            "--output",
            "json",
        ],
        capture_output=True,
        text=True,
        timeout=RUN_BUDGET_S,
        env=env,
        cwd=str(Path(__file__).resolve().parents[1]),
    )
    assert proc.returncode == 0, (
        f"exit {proc.returncode}\n--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
    )
    assert time.monotonic() - started < RUN_BUDGET_S

    rows = _summary_rows(proc.stdout)
    assert rows, f"no JSON summary in:\n{proc.stdout}"
    row = rows[-1]
    assert row["site"] == dw.DEMO_SITE_NAME
    assert row["ticks"] == 3
    assert row["csv"]["rows"] == demo.DEMO_EVENT_COUNT
    assert row["csv"]["header"] == list(CSV_COLUMNS)
    assert row["sinks"][dw.DEMO_CSV_SINK_NAME]["pushed"] == demo.DEMO_EVENT_COUNT
    assert row["sinks"][dw.DEMO_MOCK_SINK_NAME]["pushed"] == demo.DEMO_EVENT_COUNT
    assert dw.DEMO_MOCK_TOKEN not in proc.stdout


def test_demo_command_reports_a_failure_as_exit_two_with_no_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A demo that cannot run exits non-zero with the refusal — not a Python traceback.

    `no openssl` is the reachable failure (a CI image without the tool). The mapping must
    be the documented configuration-failure code (2) with a sentence a human can act on.
    """
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    result = runner.invoke(
        cli_mod.app, ["demo", "demo", "--root", str(tmp_path / "nope"), "--ticks", "1"]
    )
    assert result.exit_code == 2, result.output
    assert "openssl" in result.output.lower()
    assert "Traceback" not in result.output


def _summary_rows(stdout: str) -> list[dict[str, Any]]:
    """The JSON objects the command printed, in order (the narration is plain text)."""
    rows: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        text = line.strip()
        if text.startswith("{") and text.endswith("}"):
            try:
                rows.append(json.loads(text))
            except json.JSONDecodeError:
                continue
    return rows
