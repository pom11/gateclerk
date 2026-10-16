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
    """Every IsapiClient the CLI builds rides the FakeDevice transport.

    The base_url the CLI assembled is *recorded*, not asserted here: a malformed --host
    must reach IsapiClient so httpx gets to reject it (the exit-2 contract under test in
    test_malformed_host_exits_config_error_with_no_traceback). The wiring assertion lives
    in test_client_url_is_assembled_from_host_and_port, where the host is well-formed.
    """
    seen: list[str] = []
    device.assembled_base_urls = seen  # type: ignore[attr-defined]

    def factory(base_url: str, user: str, password: str, **kw: object) -> IsapiClient:
        seen.append(base_url)
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


def test_client_url_is_assembled_from_host_and_port(device: FakeDevice) -> None:
    """The wiring assertion the redirect fixture used to carry inline: the CLI builds
    `http://<host>:<port>` from the resolved site, and --port is honoured."""
    run([*BASE, "--json"])
    assert device.assembled_base_urls == [f"{BASE_URL}:80"]  # type: ignore[attr-defined]
    run([*BASE, "--port", "8080", "--json"])
    assert device.assembled_base_urls[-1] == f"{BASE_URL}:8080"  # type: ignore[attr-defined]


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


# --- malformed host: the exit-2 config contract (review round 1, finding 1) --------------


#: Hosts the config path must refuse with exit 2: the first group is what httpx refuses
#: (InvalidURL — NOT a ValueError subclass, which is why `except ValueError` alone let the
#: reviewer's repro escape as a raw traceback); the second group is what the env-rung name
#: derivation refuses (host sanitizes to an empty variable name).
HTTPX_REJECTED_HOSTS = ("[fe80::1", "192.0.2.10:99999", "a\nb", "e\u202evilsite")
SANITIZER_REJECTED_HOSTS = ("..", "-", "//")


@pytest.mark.parametrize("bad_host", HTTPX_REJECTED_HOSTS + SANITIZER_REJECTED_HOSTS)
def test_malformed_host_exits_config_error_with_no_traceback(bad_host: str) -> None:
    """A malformed --host is a config problem (exit 2), not a crash (exit 1 + traceback).

    Regression pinned twice over: `except ValueError` in `_client_for` missed
    httpx.InvalidURL, and `_resolve_creds` missed the ConfigError that `host_env_prefix`
    raises for a host with no alphanumerics. Both now land on the documented exit 2.
    """
    code, out = run(
        [
            "device",
            "capabilities",
            "--host",
            bad_host,
            "--user",
            "admin",
            "--password",
            "fakepw",
            "--json",
        ]
    )
    assert code == 2, f"malformed host must be the exit-2 config contract, got {code}"
    lowered = out.lower()
    assert "traceback" not in lowered and "httpx" not in lowered, out
    doc = json.loads(out.strip().splitlines()[-1])
    assert doc["exit_code"] == 2 and doc["error"]


@pytest.mark.parametrize(
    "host",
    [
        *HTTPX_REJECTED_HOSTS,
        *SANITIZER_REJECTED_HOSTS,
        "http://[fe80::1",  # httpx *accepts* this shape; the mock box then answers 404
        "host name with spaces",  # ditto: httpx does not reject it, the device path decides
        "ftp://host",
        "x" * 300,
    ],
)
def test_no_host_shape_escapes_with_an_uncaught_exception(host: str) -> None:
    """The contract, stated as the absence of a crash: any host string either exits with
    a documented code (2 config / 3 auth / 4 device) or is accepted and served (0, via
    the mock), but never exits 1 with a traceback. What a host *may* legally be is
    p1-02's config grammar — deliberately not re-litigated here; this pins only that the
    CLI converts everything it refuses, instead of escaping."""
    code, out = run(
        [
            "device",
            "capabilities",
            "--host",
            host,
            "--user",
            "admin",
            "--password",
            "fakepw",
            "--json",
        ]
    )
    assert code in (0, 2, 3, 4), f"host {host!r} escaped with exit {code}"
    assert "traceback" not in out.lower()
