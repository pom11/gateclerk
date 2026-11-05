"""ALERT-SINK-MNOTIFY: the typed alert route and its never-block fallback.

The contract is micro-notify's ``docs/SERVICE-INTEGRATION.md``: argv array, body in a
file, exit code is the verdict, no retry here, secrets stay in mnotify's own backend.
These tests are offline: the subprocess is an injected runner, alerts are hand-built,
and no host, tenant, token or real name appears (MASKED-* placeholders only).
"""

from __future__ import annotations

import subprocess
import threading
import time
from pathlib import Path

import pytest

from gateclerk.agent_alert import Alert
from gateclerk.agent_mnotify import MNOTIFY_TIMEOUT_S, MnotifySink, alert_mail
from gateclerk.config import ConfigError, parse_sites
from gateclerk.sinks import MNOTIFY_TIMEOUT_S as SINK_DEFAULT_TIMEOUT_S

SITE = "site-a"
HOST = "192.0.2.10"
SERIAL = "MASKED-SER-1"
TO = "alerts@example.invalid"


def _site_toml(*sink_blocks: str) -> bytes:
    lines = ["[[site]]", f'name = "{SITE}"', f'host = "{HOST}"', *sink_blocks]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _sink(name: str, sink_type: str, **fields: object) -> str:
    out = ["  [[site.sink]]", f'  name = "{name}"', f'  type = "{sink_type}"']
    for key, value in fields.items():
        out.append(f"  {key} = {value!r}")
    return "\n".join(out)


def _alert(**overrides: object) -> Alert:
    values = {
        "level": "critical",
        "kind": "auth_terminal",
        "site": SITE,
        "device_serial": SERIAL,
        "at": "2026-01-01T00:00:00+00:00",
        "note": "terminal 401 with a challenge — the device loop is PARKED",
        "device_key": SERIAL,
        "park_state": "parked, unacked (operator ack required)",
    }
    values.update(overrides)
    return Alert(**values)  # type: ignore[arg-type]


class Runner:
    """A recording subprocess seam; each test sets ``result`` or ``raises``."""

    def __init__(
        self, *, result: object | None = None, raises: BaseException | None = None
    ) -> None:
        self.result = result
        self.raises = raises
        self.calls: list[list[str]] = []
        self.body: str | None = None
        self.active = 0
        self.max_active = 0
        self._lock = threading.Lock()

    def __call__(self, argv: list[str], **kwargs: object) -> object:
        del kwargs
        with self._lock:
            self.calls.append(list(argv))
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            body_path = argv[argv.index("--body-file") + 1]
            self.body = Path(body_path).read_text(encoding="utf-8")
            assert Path(body_path).exists(), "the body file must exist while mnotify runs"
            time.sleep(0.01)
            if self.raises is not None:
                raise self.raises
            return self.result
        finally:
            with self._lock:
                self.active -= 1


class BlockingRunner:
    """A runner that proves the caller is not waiting on the exec."""

    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **kwargs: object) -> object:
        del kwargs
        self.calls.append(list(argv))
        self.started.set()
        assert self.release.wait(5), "the test must release the blocked runner"
        self.finished.set()
        return subprocess.CompletedProcess(argv, 0, stdout='{"ok": true}', stderr="")


def _sink_with(
    runner: Runner | BlockingRunner,
    *,
    fallback: list[Alert],
    warns: list[str],
    **kwargs: object,
) -> MnotifySink:
    return MnotifySink(
        to=TO,
        warn=warns.append,
        fallback=fallback.append,
        runner=runner,
        **kwargs,
    )


def test_success_sends_one_argv_only_mail_with_the_body_in_a_file(
    tmp_path: Path,
) -> None:
    runner = Runner(
        result=subprocess.CompletedProcess(
            [], 0, stdout='{"ok": true, "outcome": "sent", "requestId": "req-1"}', stderr=""
        )
    )
    fallback: list[Alert] = []
    warns: list[str] = []
    sink = _sink_with(runner, fallback=fallback, warns=warns)
    alert = _alert()

    sink(alert)
    sink.close()

    assert warns == []
    assert fallback == [alert], "the local evidence line is written before the page is queued"
    assert len(runner.calls) == 1
    argv = runner.calls[0]
    assert argv[:4] == ["mnotify", "mail", "send", "--to"]
    assert argv[4] == TO
    assert argv[-1] == "--json"
    assert alert.note not in " ".join(argv), "untrusted alert text belongs in the body file"
    body = runner.body or ""
    for expected in (SERIAL, "auth_terminal", "parked, unacked", "gateclerk-agent@site-a"):
        assert expected in body
    body_path = Path(argv[argv.index("--body-file") + 1])
    assert not body_path.exists(), "the temporary body file is removed after the exec"


def test_subject_and_body_carry_the_operator_restart_hint_and_park_state() -> None:
    subject, body = alert_mail(_alert())
    assert "CRITICAL" in subject and "auth_terminal" in subject and SERIAL in subject
    assert "park_state: parked, unacked" in body
    assert "device_key: " + SERIAL in body
    assert "operator only: restart the site's service" in body
    assert "systemd unit gateclerk-agent@site-a" in body
    assert "compose service site-a" in body
    assert "a restart does NOT clear a park" in body
    assert "`gateclerk agent ack --site site-a`" in body


def test_timeout_falls_back_to_stderr_and_warns_without_raising() -> None:
    runner = Runner(raises=subprocess.TimeoutExpired(["mnotify"], MNOTIFY_TIMEOUT_S))
    fallback: list[Alert] = []
    warns: list[str] = []
    alert = _alert()
    sink = _sink_with(runner, fallback=fallback, warns=warns)

    sink(alert)
    sink.close()

    assert fallback == [alert]
    assert len(warns) == 1 and "timed out" in warns[0]
    assert "UNKNOWN" in warns[0]
    assert "local alert line was already written" in warns[0]


def test_non_zero_exit_falls_back_with_the_exit_code_and_no_retry() -> None:
    runner = Runner(
        result=subprocess.CompletedProcess(
            [],
            5,
            stdout='{"ok": false, "outcome": "error", "exitCode": 5, "message": "webhook 503"}',
            stderr="",
        )
    )
    fallback: list[Alert] = []
    warns: list[str] = []
    alert = _alert()
    sink = _sink_with(runner, fallback=fallback, warns=warns)

    sink(alert)
    sink.close()

    assert fallback == [alert], "the evidence line is written exactly once, before the send"
    assert len(runner.calls) == 1, "the contract forbids a blind retry"
    assert "exit 5" in warns[0] and "webhook 503" in warns[0]
    assert "local alert line was already written" in warns[0]


def test_missing_binary_falls_back_to_stderr() -> None:
    runner = Runner(raises=FileNotFoundError("mnotify"))
    fallback: list[Alert] = []
    warns: list[str] = []
    sink = _sink_with(runner, fallback=fallback, warns=warns)

    sink(_alert())
    sink.close()

    assert fallback == [_alert()]
    assert "not found on PATH" in warns[0]


def test_any_unexpected_runner_failure_falls_back_and_never_raises() -> None:
    runner = Runner(raises=RuntimeError("boom"))
    fallback: list[Alert] = []
    warns: list[str] = []
    sink = _sink_with(runner, fallback=fallback, warns=warns)

    sink(_alert())
    sink.close()

    assert len(fallback) == 1
    assert "RuntimeError: boom" in warns[0]


def test_exit_zero_wins_over_unparseable_stdout() -> None:
    runner = Runner(result=subprocess.CompletedProcess([], 0, stdout="not json", stderr=""))
    fallback: list[Alert] = []
    warns: list[str] = []
    sink = _sink_with(runner, fallback=fallback, warns=warns)

    sink(_alert())
    sink.close()

    assert fallback == [_alert()] and warns == []


def test_call_returns_promptly_while_the_runner_blocks() -> None:
    runner = BlockingRunner()
    fallback: list[Alert] = []
    warns: list[str] = []
    sink = _sink_with(runner, fallback=fallback, warns=warns, drain_timeout_s=2.0)
    alert = _alert()

    started = time.monotonic()
    sink(alert)
    elapsed = time.monotonic() - started

    assert elapsed < 1.0, "__call__ must not wait for mnotify"
    assert fallback == [alert], "the evidence line goes out before the worker is asked"
    assert runner.started.wait(2), "the daemon worker should pick the page up"
    assert not runner.finished.is_set(), "the exec is deliberately still blocked"

    runner.release.set()
    sink.close()
    assert runner.finished.is_set() and warns == []


def test_queue_full_warns_and_drops_the_page_but_keeps_the_evidence_line() -> None:
    runner = BlockingRunner()
    fallback: list[Alert] = []
    warns: list[str] = []
    sink = _sink_with(runner, fallback=fallback, warns=warns, queue_max=1, drain_timeout_s=2.0)

    sink(_alert(kind="first"))
    assert runner.started.wait(2), "the one worker is busy, so the queue slot is free"
    sink(_alert(kind="second"))
    sink(_alert(kind="third"))

    assert len(fallback) == 3, "every alert leaves a local line, queued or not"
    assert any("queue full" in text and "dropped the page" in text for text in warns)

    runner.release.set()
    sink.close()
    assert len(runner.calls) == 2, "the in-flight page and the one queued page are sent"


def test_exit_warns_when_a_page_is_still_in_flight() -> None:
    runner = BlockingRunner()
    fallback: list[Alert] = []
    warns: list[str] = []
    sink = _sink_with(runner, fallback=fallback, warns=warns, drain_timeout_s=0.05)

    sink(_alert())
    assert runner.started.wait(2)
    sink.close()

    assert not runner.finished.is_set(), "close must not wait past its bounded timeout"
    assert any("page unfinished" in text and "already written" in text for text in warns)

    runner.release.set()
    assert runner.finished.wait(2)
    assert fallback == [_alert()]


def test_sends_are_serialised_one_writer_at_a_time() -> None:
    runner = Runner(result=subprocess.CompletedProcess([], 0, stdout='{"ok": true}', stderr=""))
    sink = _sink_with(runner, fallback=[], warns=[])

    threads = [threading.Thread(target=sink, args=(_alert(),)) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    sink.close()

    assert len(runner.calls) == 4
    assert runner.max_active == 1, "mnotify's unlocked daily counter needs one writer"


# --- configuration: one typed alert route in the sink vocabulary ---------------------------


def test_mnotify_sink_is_parsed_as_the_alert_route_not_an_event_sink() -> None:
    site = parse_sites(
        _site_toml(
            _sink("alerts", "mnotify", to=TO),
            _sink("archive", "csv", path="/var/lib/gateclerk/events.csv"),
        )
    )[SITE]

    assert site.alert_sink is not None and site.alert_sink.name == "alerts"
    assert site.alert_sink.ref == f"mailto:{TO}"
    assert site.alert_sink.to == TO
    assert site.alert_sink.timeout_s == SINK_DEFAULT_TIMEOUT_S == MNOTIFY_TIMEOUT_S
    assert [sink.name for sink in site.event_sinks] == ["archive"]
    assert site.alert_sink.accepts_roster is False


def test_two_alert_routes_are_refused() -> None:
    with pytest.raises(ConfigError, match="at most one mnotify alert sink"):
        parse_sites(
            _site_toml(
                _sink("alerts", "mnotify", to=TO),
                _sink("alerts2", "mnotify", to="other@example.invalid"),
            )
        )


def test_mnotify_requires_a_recipient_and_a_positive_timeout() -> None:
    with pytest.raises(ConfigError, match="missing required key"):
        parse_sites(_site_toml(_sink("alerts", "mnotify")))
    with pytest.raises(ConfigError, match="timeout_s must be a number > 0"):
        parse_sites(_site_toml(_sink("alerts", "mnotify", to=TO, timeout_s=0)))


def test_sink_add_writes_the_alert_block_and_it_reparses(tmp_path: Path) -> None:
    from gateclerk import sink_cli
    from gateclerk.config import load_sites

    config = tmp_path / "sites.toml"
    config.write_text(_site_toml().decode("utf-8"), encoding="utf-8")

    edit = sink_cli.add_sink_block(
        config, site=SITE, name="alerts", sink_type="mnotify", to=TO, timeout_s=120
    )

    assert edit.changed
    site = load_sites(config)[SITE]
    assert site.alert_sink is not None
    assert site.alert_sink.to == TO
    assert site.alert_sink.timeout_s == 120.0
    assert site.event_sinks == ()


def test_mnotify_check_names_the_recipient_and_probe_uses_a_dry_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gateclerk import sink_cli

    site = parse_sites(_site_toml(_sink("alerts", "mnotify", to=TO)))[SITE]
    spec = site.alert_sink
    assert spec is not None
    checks = {check.check: check for check in sink_cli.check_sink(site, spec)}
    assert checks["config"].ok
    assert checks["recipient"].ok and TO in checks["recipient"].detail

    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, stdout='{"ok": true}', stderr="")

    monkeypatch.setattr(sink_cli.subprocess, "run", fake_run)
    probe = sink_cli.probe_sink(site, spec)
    assert probe.ok and "dry-run" in probe.summary
    assert calls and calls[0][:4] == ["mnotify", "mail", "send", "--to"]
    assert "--dry-run" in calls[0] and "--json" in calls[0]
    body_path = Path(calls[0][calls[0].index("--body-file") + 1])
    assert not body_path.exists()
