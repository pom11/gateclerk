"""DOCTOR-REAL-DEVICE (card t_a063374a): the real `default_*` paths, exercised for real.

The failure this file exists for: every check that touches the OS or the wire ships behind
a module-level seam (`default_device_prober`, `default_tls_prober`, `default_keychain_probe`,
...) and `tests/test_cli_doctor.py` replaces those exact names with lambdas. That is right
for unit isolation and fatal for truth: `gateclerk doctor` died on the operator's laptop
with `TypeError: IsapiClient.__init__() got an unexpected keyword argument 'port'` while
the suite was green, because the real prober was written against a client API that does not
exist (`port=`/`credentials=`, `client.get_xml(...)`, `device_identity(client)`) and nothing
ever called it.

So these arms run the UNREPLACED defaults:

* the demo fake device (`gateclerk.demo_device`, a loopback HTTP server) through the REAL
  `doctor_cli.default_device_prober` — the same unmodified `IsapiClient` over a real socket
  that tests/test_demo_device.py pins, so a ctor-signature or registry-name regression dies
  HERE instead of on a door controller;
* the sanctioned shared prober `cli_shared.default_device_prober`, which builds its client
  through `_client_for` — the factory every read command uses (the point: doctor and the
  read commands cannot drift apart again);
* `init_cli.probe_device`, the other real client construction in the init wizard;
* the real `default_tls_prober` handshake against the demo walkthrough's HTTPS mock ingest
  (cert verified against its own minted bundle — a `verify=False` shortcut would fail this);
* `sink_cli.default_keychain_probe` returning None when `security` is not the binary it
  would run (the Linux/CI answer doctor must print as "keychain unavailable here", not a
  traceback);
* `service_cli.default_config_path` / `default_state_dir` path math (the real default, not
  the injected `home=` double the service suite passes);
* the NO_PROXY law the doctor docstring promised: the real prober builds with
  `trust_env=False`, asserted at the seam.

Every device read here is a GET through the read-only registry; the mock ingest answers
POST /ingest only because that is what a sink probe does — no service manager, no restart,
no write to a real site.
"""

from __future__ import annotations

import ssl
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

import _socketseam
import gateclerk.demo_device as demo
import gateclerk.demo_walkthrough as walkthrough
from gateclerk import cli_shared, doctor_cli, service_cli, sink_cli
from gateclerk import config as cfg
from gateclerk.cli import app
from gateclerk.exceptions import IsapiAuthError, IsapiError
from gateclerk.isapi_transport import IsapiClient
from gateclerk.secrets import Secret

DEMO_USER = "admin"
DEMO_PASSWORD = "fake" + "pw"  # placeholder policy (tests/test_repo_hygiene.py PLACEHOLDER)
DEMO_SITE = "demo-real-prober"

#: The demo box's claimed wall clock is pinned (`_DEMO_LOCAL_TIME` = 2026-06-15T18:05+02:00),
#: so "now" is pinned to the same instant and the skew this file asserts is arithmetic, not
#: a timestamp. Europe/Bucharest is +03:00 in June, so 18:05 local is 15:05 UTC.
DEMO_INSTANT = datetime(2026, 6, 15, 15, 5, 0, tzinfo=UTC)

#: The env rung `resolve_credentials` reads for a loopback host (host_env_prefix shape).
DEMO_PW_ENV = "GATECLERK_127_0_0_1_PASSWORD"

runner = CliRunner()


# --- the socket seam (same sanctioned module tests/test_demo_device.py uses) --------------


@pytest.fixture
def socket_allow(monkeypatch: pytest.MonkeyPatch) -> None:
    _socketseam.release(monkeypatch)


@pytest.fixture
def demo_box(socket_allow: None) -> Iterator[demo.DemoDevice]:
    box = demo.DemoDevice(username=DEMO_USER, password=DEMO_PASSWORD)
    box.start()
    try:
        yield box
    finally:
        box.stop()


@pytest.fixture
def demo_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """The env rung the real resolver reads — no keychain, no credential file.

    The autouse `no_ambient_credential_file` fixture already seals the file rung, so env is
    the only source that can answer: a prober that quietly read a real keychain would come
    back empty here and the arm would pass on the wrong thing.
    """
    monkeypatch.setenv(DEMO_PW_ENV, DEMO_PASSWORD)


def demo_site(box: demo.DemoDevice, **overrides: object) -> cfg.SiteConfig:
    """A `[[site]]` block pointing at the live demo box, built like the loader builds one."""
    fields: dict[str, object] = {
        "name": DEMO_SITE,
        "host": box.host,
        "port": box.port,
        "iana_tz": "Europe/Bucharest",
        "device_tz": "Europe/Bucharest",
        "isapi_user": DEMO_USER,
    }
    fields.update(overrides)
    return cfg.SiteConfig(**fields)  # type: ignore[arg-type]


# --- the real device prober ---------------------------------------------------------------


def test_default_device_prober_reads_the_real_demo_box(
    demo_box: demo.DemoDevice, demo_env: None
) -> None:
    """THE arm. Nothing patched: real `IsapiClient`, real socket, real digest handshake."""
    summary, skew = doctor_cli.default_device_prober(demo_site(demo_box), now=DEMO_INSTANT)

    assert summary == f"model={demo.DEMO_MODEL} serial={demo.DEMO_SERIAL}"
    assert skew is not None and abs(skew) < 2.0, skew

    # Read-only law, read off the box's own request log rather than asserted from intent.
    served = {(r.method, r.path) for r in demo_box.requests}
    assert all(method == "GET" for method, _ in served), served
    paths = {path for _, path in served}
    assert any("deviceInfo" in p for p in paths), paths
    assert any("time" in p.lower() for p in paths), paths
    assert not any(p.startswith(("/ISAPI/Intelligent/", "/ISAPI/System/reboot")) for p in paths)


def test_default_device_prober_serves_the_real_device_tz_via_device_tz(
    demo_box: demo.DemoDevice, demo_env: None
) -> None:
    """`device_tz` (p1-12) decides the skew the operator reads — the box claims +02:00 while
    its digits are Europe/Bucharest; a prober that ignored `device_tz` would report the
    ~1 h tz bug as clock skew (the false alarm OBSERVED.md names)."""
    _summary, skew = doctor_cli.default_device_prober(demo_site(demo_box), now=DEMO_INSTANT)
    assert skew is not None and abs(skew) < 2.0


def test_default_device_prober_wrong_password_raises_auth_error(
    demo_box: demo.DemoDevice, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(DEMO_PW_ENV, "definitely-not-the-demo-password")
    with pytest.raises(IsapiAuthError):
        doctor_cli.default_device_prober(demo_site(demo_box), now=DEMO_INSTANT)


def test_default_device_prober_unreachable_box_raises_isapi_error(
    socket_allow: None, demo_env: None
) -> None:
    """A loopback port with nothing behind it: the failure the section mapper turns into
    exit 4, reached through the real prober rather than a lambda that raises it."""
    site = cfg.SiteConfig(name=DEMO_SITE, host="127.0.0.1", port=1, iana_tz="UTC")
    with pytest.raises(IsapiError):
        doctor_cli.default_device_prober(site, now=DEMO_INSTANT)


def test_default_device_prober_missing_credential_raises_credential_unavailable(
    demo_box: demo.DemoDevice, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(DEMO_PW_ENV, raising=False)
    with pytest.raises(cfg.CredentialUnavailable):
        doctor_cli.default_device_prober(demo_site(demo_box), now=DEMO_INSTANT)


def test_default_device_prober_honours_the_no_proxy_law(
    demo_box: demo.DemoDevice, demo_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`trust_env=False` is asserted at the seam, not inferred from a passing request: the
    docstring promised NO_PROXY and httpx defaults to the opposite, so a proxy exported in
    the operator's shell would have CONNECT-ed the device GET to a dead proxy and printed
    "device unreachable" about a healthy box."""
    seen: dict[str, object] = {}
    real = IsapiClient

    def spy(base_url: str, user: str, password: str, **kw: object) -> IsapiClient:
        seen.update(kw)
        return real(base_url, user, password, **kw)

    # The prober imports IsapiClient inside the function body, so the patch that counts is
    # on the module it is imported FROM — patching `doctor_cli.IsapiClient` would be a
    # no-op dressed as a seam.
    import gateclerk.isapi_transport as transport_mod

    monkeypatch.setattr(transport_mod, "IsapiClient", spy)

    doctor_cli.default_device_prober(demo_site(demo_box), now=DEMO_INSTANT)
    assert seen.get("trust_env") is False, seen


def test_shared_cli_prober_uses_the_same_client_factory(
    demo_box: demo.DemoDevice, demo_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`cli_shared.default_device_prober` builds through `_client_for` — the factory every
    read command shares — and still reads the box correctly. This is the arm that keeps
    doctor's probe and `gateclerk users list` from drifting into two half-broken clients."""
    built: list[str] = []
    real_for = cli_shared._client_for

    def spy(target: object, creds: object, **kw: object):
        built.append(str(getattr(target, "host", "")))
        return real_for(target, creds, **kw)

    monkeypatch.setattr(cli_shared, "_client_for", spy)

    summary, skew = cli_shared.default_device_prober(demo_site(demo_box), now=DEMO_INSTANT)
    assert summary == f"model={demo.DEMO_MODEL} serial={demo.DEMO_SERIAL}"
    assert skew is not None and abs(skew) < 2.0
    assert built == [demo_box.host]


def test_doctor_cli_device_section_reads_the_real_demo_box(
    demo_box: demo.DemoDevice, demo_env: None, tmp_path: Path
) -> None:
    """The whole command, with NOTHING patched except the socket seam: the acceptance
    shape (`--config ... --state-root ... --site ...`) run offline against the demo box.

    The device row must READ the box — model + serial from the wire, `reachable`. Its
    pass/warn status is arithmetic the CLI cannot fake: the demo pins its `localTime` to
    a fixed June instant, so against today's wall clock the skew is months and the row is
    `warn` ("clock skew exceeds 120s") — the honest answer, and the same line the real
    canary produces when its NTP is off. The green-skip case here would be a row that
    *read* the device.
    """
    cfg_file = tmp_path / "sites.toml"
    cfg_file.write_text(
        "[[site]]\n"
        f'name = "{DEMO_SITE}"\n'
        f'host = "{demo_box.host}"\n'
        f"port = {demo_box.port}\n"
        'iana_tz = "Europe/Bucharest"\n'
        'device_tz = "Europe/Bucharest"\n'
        f'isapi_user = "{DEMO_USER}"\n',
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        [
            "doctor",
            "--config",
            str(cfg_file),
            "--state-root",
            str(tmp_path),
            "--site",
            DEMO_SITE,
            "-o",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    import json

    by_section = {}
    for line in result.output.splitlines():
        if line.startswith("{"):
            row = json.loads(line)
            by_section[row["section"]] = row
    device = by_section["device"]
    assert device["status"] in ("pass", "warn"), device
    assert "reachable" in device["detail"], device
    assert demo.DEMO_MODEL in device["detail"]
    assert demo.DEMO_SERIAL in device["detail"]
    assert DEMO_PASSWORD not in result.output


def test_doctor_cli_probe_flag_routes_through_the_shared_factory(
    demo_box: demo.DemoDevice, demo_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--probe` selects `cli_shared.default_device_prober` (the read-command factory),
    not doctor's own construction — the flag's whole purpose."""
    calls: list[str] = []
    real = cli_shared.default_device_prober

    def spy(site: cfg.SiteConfig, **kw: object):
        calls.append(site.name)
        return real(site, **kw)

    monkeypatch.setattr(cli_shared, "default_device_prober", spy)

    cfg_file = tmp_path / "sites.toml"
    cfg_file.write_text(
        "[[site]]\n"
        f'name = "{DEMO_SITE}"\n'
        f'host = "{demo_box.host}"\n'
        f"port = {demo_box.port}\n"
        'iana_tz = "Europe/Bucharest"\n'
        'device_tz = "Europe/Bucharest"\n'
        f'isapi_user = "{DEMO_USER}"\n',
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        ["doctor", "--config", str(cfg_file), "--state-root", str(tmp_path), "--probe"],
    )
    assert result.exit_code == 0, result.output
    assert calls == [DEMO_SITE]
    assert f"model={demo.DEMO_MODEL}" in result.output


# --- init's real probe path ----------------------------------------------------------------


def test_init_probe_device_reads_the_real_demo_box(demo_box: demo.DemoDevice) -> None:
    """`gateclerk init`'s device probe is the other real `IsapiClient` construction; it must
    survive the same ctor/registry reality the doctor prober just proved."""
    from gateclerk import init_cli

    report = init_cli.probe_device(
        host=demo_box.host,
        port=demo_box.port,
        user=DEMO_USER,
        password=Secret(DEMO_PASSWORD),
    )
    assert report.serial == demo.DEMO_SERIAL
    assert report.model == demo.DEMO_MODEL
    assert report.firmware == demo.DEMO_FIRMWARE
    assert report.user_count_known


# --- the real TLS prober ---------------------------------------------------------------


def test_default_tls_prober_verifies_a_pinned_certificate_then_refuses_without_it(
    socket_allow: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two arms, one law: `default_tls_prober` VERIFIES (gotchas §4.1 bans `verify=False`
    repo-wide, so a prober that reported success unconditionally is the bug).

    * positive: the walkthrough's HTTPS mock ingest, whose minted cert doubles as its own CA
      bundle, trusted through `SSL_CERT_FILE` — the same env var `ssl.create_default_context`
      reads, so the arm pins trust without patching the prober or weakening it;
    * negative: the identical handshake with the pin removed must raise
      `CERTIFICATE_VERIFY_FAILED`. A prober that skipped verification would report
      "cert verified" both times, and only this arm tells them apart.
    """
    sink = walkthrough.MockIngestSink(cert_dir=tmp_path).start()
    try:
        port = int(sink.base_url.rsplit(":", 1)[1])
        monkeypatch.setenv("SSL_CERT_FILE", str(sink.ca_bundle))
        summary = doctor_cli.default_tls_prober("127.0.0.1", port, timeout_s=5.0)
        assert summary.startswith("TLS"), summary
        assert "cert verified" in summary

        monkeypatch.delenv("SSL_CERT_FILE")
        with pytest.raises(ssl.SSLCertVerificationError):
            doctor_cli.default_tls_prober("127.0.0.1", port, timeout_s=5.0)
    finally:
        sink.stop()


def test_default_tls_prober_fails_on_a_plain_http_port(
    demo_box: demo.DemoDevice,
) -> None:
    """The negative arm: the demo device speaks plain HTTP, so a TLS handshake against it
    must raise — this is the line `doctor` shows when a sink's URL says https and the box
    does not answer TLS."""
    with pytest.raises((ssl.SSLError, OSError)):
        doctor_cli.default_tls_prober(demo_box.host, demo_box.port, timeout_s=5.0)


# --- the keychain probe, the service path defaults ---------------------------------------


def test_default_keychain_probe_says_unavailable_without_the_binary(
    socket_allow: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The Linux/CI answer is None ("cannot tell"), which the doctor prints as 'keychain
    unavailable here' — never a traceback, never a confident 'not there'."""
    monkeypatch.setattr(sink_cli.shutil, "which", lambda _name: None)
    assert sink_cli.default_keychain_probe("gateclerk-hikvision", "127.0.0.1") is None


def test_default_keychain_probe_reports_presence_from_exit_code(
    socket_allow: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []

    class Done:
        returncode = 0

    def fake_run(argv: list[str], **_kw: object) -> Done:
        calls.append(argv)
        return Done()

    monkeypatch.setattr(sink_cli.shutil, "which", lambda _name: "/usr/bin/security")
    monkeypatch.setattr(sink_cli.subprocess, "run", fake_run)
    assert sink_cli.default_keychain_probe("gateclerk-hikvision", "127.0.0.1") is True
    assert calls and "-w" not in calls[0], calls[0]  # metadata lookup, never a value read


def test_service_default_paths_are_the_documented_layout(
    socket_allow: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`default_config_path` / `default_state_dir` are the paths `service install` writes
    when the operator passed no `--config`/`--state-dir`; the suite injects `home=`, so this
    is the only arm that exercises the real HOME/XDG read."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    assert service_cli.default_config_path() == str(tmp_path / "gateclerk" / "sites.toml")
    assert service_cli.default_state_dir("launchd", "site-a") == str(
        tmp_path / "Library" / "Application Support" / "gateclerk" / "site-a"
    )
    assert service_cli.default_state_dir("systemd-user", "site-a") == str(
        tmp_path / "state" / "gateclerk" / "site-a"
    )
