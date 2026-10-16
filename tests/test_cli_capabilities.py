"""`gateclerk device capabilities` — the raw dump that becomes the OBSERVED.md evidence.

Offline: the client built inside cli.py is redirected to FakeDevice's MockTransport, so
these exercise the real command body (site/creds resolution, discovery, rendering, exit
codes) without a socket. The password arrives via the flag rung, so no keychain call.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

import gateclerk.cli as cli_mod
from fakedevice import BASE_URL, FakeDevice
from gateclerk.cli import AUTH_TERMINAL_EXIT, DEVICE_ERROR_EXIT, app
from gateclerk.isapi_transport import IsapiClient

RECORDED = Path(__file__).parent / "fixtures/recorded/site-a-ds-k1t341amf-s"
SYNTH = Path(__file__).parent / "fixtures/synthetic"

CAPS_PATH = "/ISAPI/AccessControl/AcsEvent/capabilities?format=json"
AC_CAPS_PATH = "/ISAPI/AccessControl/capabilities?format=json"
DEVICE_INFO_PATH = "/ISAPI/System/deviceInfo?format=json"

runner = CliRunner()


@pytest.fixture
def device() -> FakeDevice:
    d = FakeDevice()
    d.xml_ok("GET", DEVICE_INFO_PATH, (RECORDED / "device_info.xml").read_text(encoding="utf-8"))
    d.add(
        "GET",
        CAPS_PATH,
        httpx.Response(
            200,
            content=(RECORDED / "acs_capabilities.json").read_bytes(),
            headers={"Content-Type": "application/json"},
        ),
    )
    d.json_ok(
        "GET", AC_CAPS_PATH, json.loads((SYNTH / "access_control_capabilities.json").read_bytes())
    )
    return d


@pytest.fixture(autouse=True)
def redirect_transport(monkeypatch: pytest.MonkeyPatch, device: FakeDevice) -> FakeDevice:
    """Every IsapiClient the CLI builds rides the FakeDevice transport."""

    def factory(base_url: str, user: str, password: str, **kw: object) -> IsapiClient:
        assert base_url == f"{BASE_URL}:80"
        return IsapiClient(
            base_url, user, password, transport=device.transport, sleep=lambda _s: None
        )

    monkeypatch.setattr(cli_mod, "IsapiClient", factory)
    # The process-wide cache is module state; isolate tests from each other's runs.
    from gateclerk.capabilities import capability_cache

    capability_cache().clear()
    return device


def run(args: list[str]) -> tuple[int, str]:
    result = runner.invoke(app, args)
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        raise result.exception
    return result.exit_code, result.stdout or ""


BASE = ["device", "capabilities", "--host", "192.0.2.10", "--user", "admin", "--password", "fakepw"]


# --- happy path ---------------------------------------------------------------------------


def test_json_flag_emits_the_raw_dump(device: FakeDevice) -> None:
    code, out = run([*BASE, "--json"])
    assert code == 0
    doc = json.loads(out.strip().splitlines()[-1])
    assert doc["limits"]["max_results"] == 30
    assert doc["limits"]["search_id_max"] == 64
    assert doc["serial"] == "MASKED-SER-1"
    assert doc["firmware"] == "V3.2.30"
    # The raw bodies ride along untouched — this is the OBSERVED.md paste target.
    assert doc["raw_acs_event_capabilities"] == json.loads(
        (RECORDED / "acs_capabilities.json").read_text(encoding="utf-8")
    )


def test_output_json_format_matches_the_json_flag(device: FakeDevice) -> None:
    _, a = run([*BASE, "--json"])
    _, b = run([*BASE, "--output", "json"])
    assert json.loads(a.strip().splitlines()[-1]) == json.loads(b.strip().splitlines()[-1])


def test_table_view_shows_the_advertised_limits(device: FakeDevice) -> None:
    code, out = run(BASE)
    assert code == 0
    assert "maxResults @max" in out and "30" in out
    assert "minorEvent" in out and "75" in out
    assert "NOT advertised" in out, "eventAttribute absence must be visible in the table too"


def test_command_is_read_only_against_the_wire(device: FakeDevice) -> None:
    """Every request the CLI made is a GET to a registered read path (defense in depth
    on top of the registry test)."""
    run([*BASE, "--json"])
    assert {s.method for s in device.served} == {"GET"}
    assert all(s.path.endswith("format=json") for s in device.served)


def test_password_never_appears_in_output(device: FakeDevice) -> None:
    code, out = run([*BASE, "--json"])
    assert code == 0
    assert "fakepw" not in out


# --- cache behaviour ------------------------------------------------------------------------


def test_second_invocation_in_one_process_serves_from_the_cache(device: FakeDevice) -> None:
    """Same (serial, firmware): the second run re-reads only deviceInfo (the cache key),
    never the capability bodies."""
    run([*BASE, "--json"])
    cap_reads = [s for s in device.served if s.path.startswith("/ISAPI/AccessControl/")]
    code, _ = run([*BASE, "--json"])
    assert code == 0
    assert [s for s in device.served if s.path.startswith("/ISAPI/AccessControl/")] == cap_reads


def test_refresh_flag_bypasses_the_cache(device: FakeDevice) -> None:
    run([*BASE, "--json"])
    cap_reads = len([s for s in device.served if s.path.startswith("/ISAPI/AccessControl/")])
    code, _ = run([*BASE, "--json", "--refresh"])
    assert code == 0
    served = len([s for s in device.served if s.path.startswith("/ISAPI/AccessControl/")])
    assert served > cap_reads, "--refresh must actually re-read the caps"


# --- failure exits ----------------------------------------------------------------------------


def test_caps_endpoint_absent_exits_device_error(device: FakeDevice) -> None:
    """No caps, no guessed codes: the command fails loudly with exit 4 and says why."""
    device.routes.clear()
    device.add(
        "GET",
        DEVICE_INFO_PATH,
        httpx.Response(
            200,
            text=(RECORDED / "device_info.xml").read_text(encoding="utf-8"),
            headers={"Content-Type": "application/xml"},
        ),
    )
    code, out = run([*BASE, "--json"])
    assert code == DEVICE_ERROR_EXIT
    doc = json.loads(out.strip().splitlines()[-1])
    assert "refusing to" in doc["error"] and doc["exit_code"] == DEVICE_ERROR_EXIT


def test_bad_password_exits_auth_terminal(device: FakeDevice) -> None:
    """A 401 must exit 3 with the lockout warning — and must NOT have retried into a loop
    (the transport circuit opens after the one re-auth httpx spends)."""
    code, out = run(
        [
            "device",
            "capabilities",
            "--host",
            "192.0.2.10",
            "--user",
            "admin",
            "--password",
            "wrongpw",
            "--json",
        ]
    )
    assert code == AUTH_TERMINAL_EXIT
    assert "lockout" in out.lower()
    authed = [s for s in device.served if s.had_auth]
    assert len(authed) <= 2, "no retry loop into lockout"


def test_missing_creds_exits_config_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """No flags, no env, no keychain (CI host) => exit 2 before any socket."""
    monkeypatch.setattr(
        "shutil.which", lambda _name: None
    )  # pretend a non-macOS host: no /usr/bin/security
    monkeypatch.delenv("GATECLERK_192_0_2_10_PASSWORD", raising=False)
    monkeypatch.delenv("GATECLERK_PASSWORD", raising=False)
    code, _ = run(["device", "capabilities", "--host", "192.0.2.10"])
    assert code == 2


def test_host_is_never_guessed() -> None:
    code, _ = run(["device", "capabilities"])
    assert code not in (0, 3, 4)
