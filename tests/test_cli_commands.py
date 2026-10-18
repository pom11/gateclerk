"""Card p1-08's definition of done: every command driven against FakeDevice.

One file per command-group on purpose — the three existing CLI files each own a contract
that predates this card (scaffold surface, credential resolution, capability discovery) and
their stub assertions are updated in place below. This file owns the behaviour the card
asked for:

* a command for each thing in the card's scope, exercised end to end offline;
* the exit-code contract 0/2/3/4/5, including the two codes (3, 5) nothing tested before;
* `--format jsonl` output that feeds `gateclerk.model.from_jsonl()` losslessly;
* `gateclerk events` on a 3-page fixture printing 3 pages, in order;
* the two filters OBSERVED.md says must be re-applied client-side, and the `--verbose`
  request log with the credential withheld.

Nothing here opens a socket: `conftest.netoff` (autouse) makes a real socket raise, and the
CLI's `IsapiClient` is redirected to FakeDevice's MockTransport. The password arrives on the
flag rung so no keychain is consulted (the fake device's password is a placeholder, see
`tests/test_repo_hygiene.py`).
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import httpx
import pytest
import typer
from typer.testing import CliRunner

import gateclerk.cli as cli_mod
from _cli_surface import command_at, declared_flags, declared_param, declared_prose
from fakedevice import BASE_URL, FakeDevice
from gateclerk.cli import (
    AUTH_TERMINAL_EXIT,
    CONFIG_ERROR_EXIT,
    DEVICE_ERROR_EXIT,
    RUNAWAY_EXIT,
    app,
)
from gateclerk.isapi_transport import IsapiClient
from gateclerk.model import from_jsonl

RECORDED = Path(__file__).parent / "fixtures/recorded/site-a-ds-k1t341amf-s"
SYNTH = Path(__file__).parent / "fixtures/synthetic"

#: The zone every test's site runs in. Recorded on purpose rather than imported from the
#: default, so a change to the product default cannot quietly re-define these assertions.
SITE_TZ = "Europe/Bucharest"

DEVICE_INFO_PATH = "/ISAPI/System/deviceInfo?format=json"
SYSTEM_TIME_PATH = "/ISAPI/System/time?format=json"
CAPS_PATH = "/ISAPI/AccessControl/AcsEvent/capabilities?format=json"
AC_CAPS_PATH = "/ISAPI/AccessControl/capabilities?format=json"
EVENT_PATH = "/ISAPI/AccessControl/AcsEvent?format=json"
USER_SEARCH_PATH = "/ISAPI/AccessControl/UserInfo/Search?format=json"
USER_COUNT_PATH = "/ISAPI/AccessControl/UserInfo/Count?format=json"
TOTAL_NUM_PATH = "/ISAPI/AccessControl/AcsEventTotalNum?format=json"

FAKE_PW = "fakepw"
HOST = "192.0.2.10"

runner = CliRunner()

#: base_urls the CLI asked for, reset by the `device` fixture; read via `served_urls`.
_BASE_URLS: list[str] = []


def fixture_text(name: str, *, directory: Path = RECORDED) -> str:
    return (directory / name).read_text(encoding="utf-8")


def fixture_json(name: str, *, directory: Path = RECORDED) -> dict[str, Any]:
    return json.loads(fixture_text(name, directory=directory))


def json_ok(payload: Any) -> httpx.Response:
    return httpx.Response(200, json=payload)


def _notsupport(status: int = 400) -> httpx.Response:
    """The envelope site-a answers an unknown/unsupported endpoint with (OBSERVED.md)."""
    return httpx.Response(
        status,
        json={
            "statusCode": 4,
            "statusString": "Invalid Operation",
            "subStatusCode": "notSupport",
            "errorCode": 1073741825,
            "errorMsg": "unknow",
        },
    )


# --- the device every test in this file rides ------------------------------------------


@pytest.fixture
def device(monkeypatch: pytest.MonkeyPatch) -> FakeDevice:
    """One FakeDevice per test, answering every endpoint the CLI is allowed to reach.

    Every response is registered through the `add`/`json_ok`/`xml_ok` helpers, so the
    device records each request it served — the read-only guard and the request-shape
    tests read `d.served` as a black-box assertion instead of trusting the caller.

    The fixture is what redirects the CLI onto the device: it patches the name the CLI
    constructs (`cli_mod.IsapiClient`) with a factory that injects `device.transport`. The
    real class is captured before the patch and called through it, so the CLI's own
    construction path still runs — including the httpx.InvalidURL contract — and only the
    transport is swapped. The capability cache is process state and is cleared, otherwise
    one test's discovery answers another's.
    """
    d = FakeDevice(password=FAKE_PW)
    d.xml_ok("GET", DEVICE_INFO_PATH, fixture_text("device_info.xml"))
    d.xml_ok("GET", SYSTEM_TIME_PATH, fixture_text("system_time.xml"))
    d.add(
        "GET",
        CAPS_PATH,
        httpx.Response(200, content=fixture_text("acs_capabilities.json").encode()),
    )
    d.json_ok(
        "GET",
        AC_CAPS_PATH,
        fixture_json("access_control_capabilities.json", directory=SYNTH),
    )
    d.json_ok("POST", EVENT_PATH, fixture_json("events_major5_page1.json"))
    d.json_ok("POST", USER_SEARCH_PATH, fixture_json("user_search_page1.json"))
    d.json_ok("GET", USER_COUNT_PATH, fixture_json("user_count.json"))
    d.json_ok("POST", TOTAL_NUM_PATH, {"AcsEventTotalNum": {"totalNum": 30}})

    real = IsapiClient

    def factory(base_url: str, user: str, password: str, **kw: Any) -> IsapiClient:
        _BASE_URLS.append(base_url)
        return real(base_url, user, password, transport=d.transport, sleep=lambda _s: None)

    _BASE_URLS.clear()
    monkeypatch.setattr(cli_mod, "IsapiClient", factory)
    from gateclerk.capabilities import capability_cache

    capability_cache().clear()
    return d


@pytest.fixture
def served_urls(device: FakeDevice) -> list[str]:
    """The base_url of every client the CLI built against `device` this test."""
    return _BASE_URLS


# --- invocation helpers -----------------------------------------------------------------


def run(args: list[str]) -> tuple[int, str]:
    """Invoke the CLI; a non-SystemExit exception is a test failure, not a result."""
    result = runner.invoke(app, args)
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        raise result.exception
    return result.exit_code, result.stdout or ""


def stderr_of(args: list[str]) -> str:
    result = runner.invoke(app, args)
    return result.stderr or ""


def base_args(*extra: str) -> list[str]:
    return ["--host", HOST, "--user", "admin", "--password", FAKE_PW, *extra]


def rows(out: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in out.strip().splitlines() if line.strip()]


WINDOW = ["--since", "2026-05-21T00:00:00", "--until", "2026-05-22T00:00:00"]


def events_args(*extra: str) -> list[str]:
    return ["events", *base_args(*WINDOW, *extra)]


def event_pages(*pages: list[dict[str, Any]], status_last: str = "OK") -> list[httpx.Response]:
    """Page bodies for a multi-page walk: MORE for every page but the last."""
    total = sum(len(p) for p in pages)
    out: list[httpx.Response] = []
    for i, page in enumerate(pages):
        status = status_last if i == len(pages) - 1 else "MORE"
        out.append(
            json_ok(
                {
                    "AcsEvent": {
                        "searchID": f"probe-{i}",
                        "totalMatches": total,
                        "responseStatusStrg": status,
                        "numOfMatches": len(page),
                        "InfoList": page,
                    }
                }
            )
        )
    return out


def recorded_records() -> list[dict[str, Any]]:
    return fixture_json("events_major5_page1.json")["AcsEvent"]["InfoList"]


# --- device info ------------------------------------------------------------------------


def test_device_info_table_shows_identity(device: FakeDevice, served_urls: list[str]) -> None:
    code, out = run(["device", "info", *base_args()])
    assert code == 0, out
    assert "MASKED-SER-1" in out
    assert "V3.2.30" in out
    assert "DS-K1T341AMF-S" in out
    assert served_urls == [f"{BASE_URL}:80"]


def test_device_info_json_is_the_raw_body(device: FakeDevice) -> None:
    """`--json` is the passthrough the card asked for: the body as the device answered it."""
    code, out = run(["device", "info", *base_args("--json")])
    assert code == 0, out
    (row,) = rows(out)
    # parse_body flattens this firmware's XML into a DeviceInfo wrapper (OBSERVED.md).
    node = row.get("DeviceInfo", row)
    assert node["serialNumber"] == "MASKED-SER-1"
    assert node["model"] == "DS-K1T341AMF-S"


def test_device_info_port_is_honoured(device: FakeDevice, served_urls: list[str]) -> None:
    run(["device", "info", *base_args("--port", "8080", "--json")])
    assert served_urls[-1] == f"{BASE_URL}:8080"


def test_device_info_password_never_printed(device: FakeDevice) -> None:
    for flag in ([], ["--json"]):
        _, out = run(["device", "info", *base_args(*flag)])
        assert FAKE_PW not in out


# --- device time ------------------------------------------------------------------------


def test_device_time_reports_the_verbatim_clock(device: FakeDevice) -> None:
    code, out = run(["device", "time", *base_args()])
    assert code == 0, out
    # The card's whole point for this command: the device's own string is shown, not a
    # normalised one, because its offset claim is wrong on this firmware.
    assert "2026-10-15T16:39:32+02:00" in out
    assert "Europe/Bucharest" in out


def test_device_time_json_carries_the_raw_body_and_both_offsets(device: FakeDevice) -> None:
    code, out = run(["device", "time", *base_args("--json")])
    assert code == 0, out
    (row,) = rows(out)
    assert "<localTime>2026-10-15T16:39:32+02:00</localTime>" in row["raw_body"]
    assert row["device_claimed_offset_min"] == 120
    # The Hikvision dialect is carried for diagnostics and never used for UTC math.
    assert "CST-2:00:00" in row["tz_rule"]
    assert row["skew_warn_seconds"] == 120.0


def test_device_time_skew_is_wall_clock_not_instant(device: FakeDevice) -> None:
    """The ~1 h tz bug must NOT be reported as ~3600 s of clock drift.

    This is the ownership note from 2026-10-16 restated as an assertion: comparing
    instants would turn the device's +02:00-in-+03:00 mistake into a permanent "NTP skew"
    alarm blaming the clock for a timezone error. A wall-clock comparison in the site zone
    puts the two clocks ~4 s apart, which is what OBSERVED.md measured.
    """
    # Both clocks have to be running now for the comparison to mean anything: the recorded
    # System/time body is a snapshot from a probe, so its wall reading falls further behind
    # ours every day the suite runs, and a passing "no skew" test would age into a failure
    # for a reason that has nothing to do with the code under test.
    device.reset(
        "GET",
        SYSTEM_TIME_PATH,
        httpx.Response(
            200,
            text=fixture_text("system_time.xml").replace(
                "2026-10-15T16:39:32+02:00",
                datetime.now(ZoneInfo(SITE_TZ)).isoformat(timespec="seconds"),
            ),
            headers={"Content-Type": "application/xml"},
        ),
    )
    code, out = run(["device", "time", *base_args("--json")])
    assert code == 0, out
    skew = rows(out)[0]["skew_seconds"]
    assert skew is not None
    assert abs(skew) < 60.0, f"skew {skew}s looks like the instant-comparison bug, not drift"
    assert abs(skew - 4.0) < 30.0, "OBSERVED.md measured ~4 s; a big value needs explaining"


def test_device_time_warns_over_the_threshold_without_promising_a_write(
    device: FakeDevice,
) -> None:
    """A skewed clock is a log line, never an auto-fix: this connector cannot write."""
    device.routes.clear()
    device.xml_ok("GET", DEVICE_INFO_PATH, fixture_text("device_info.xml"))
    device.xml_ok(
        "GET",
        SYSTEM_TIME_PATH,
        fixture_text("system_time.xml").replace("2026-10-15T16:39:32", "2026-10-15T18:00:00"),
    )
    out = stderr_of(["device", "time", *base_args("--json")])
    assert "warning" in out.lower()
    lowered = out.lower()
    for verb in ("fixed", "set the clock", "sync the device", "wrote"):
        assert verb not in lowered, f"a read-only tool must not promise {verb!r}"


# --- device time: the tz_offset_mismatch verdict (card p1-11, DESIGN.md item 7) -----------

#: The rendered verdict text for "there was no claim to compare" — pinned as an exact
#: string because the card's whole requirement is that this case is *worded* as absence.
#: `model.py`'s convention: `None` means "no evidence", never "fine".
NO_EVIDENCE = "no evidence (device claims nothing)"


def set_device_clock(device: FakeDevice, local_time: str) -> None:
    """Replace the fake's `System/time` answer with one stamped `local_time` verbatim.

    Only `localTime` changes: the recorded `timeZone` dialect line stays, so a test that
    moves the stamp cannot accidentally "fix" the dialect too. `reset` (not `add`) because
    the fixture pre-seeds this route — an appended page would be served after the fixture.
    """
    body = re.sub(
        r"<localTime>[^<]*</localTime>",
        f"<localTime>{local_time}</localTime>",
        fixture_text("system_time.xml"),
    )
    device.reset(
        "GET",
        SYSTEM_TIME_PATH,
        httpx.Response(200, text=body, headers={"Content-Type": "application/xml"}),
    )


def test_device_time_json_flags_the_site_a_summer_shape(device: FakeDevice) -> None:
    """(a) claim +02:00 while the site zone holds +03:00 → true, both offsets visible.

    This is site-a in summer (OBSERVED.md "The time/offset bug"): the skew is ~0 so the
    clock looks healthy to the operator standing at the device, while the offset label is
    wrong on every record they are about to export. The flag is what makes that visible
    without a laptop, and the offsets have to be *in the payload* for the operator to see
    which side disagrees.
    """
    set_device_clock(device, "2026-06-15T14:30:00+02:00")
    code, out = run(["device", "time", *base_args("--json")])
    assert code == 0, out
    (row,) = rows(out)
    assert row["tz_offset_mismatch"] is True
    assert row["device_claimed_offset_min"] == 120, "the device's own label, kept as claimed"
    assert row["site_offset_min_at_instant"] == 180, "Europe/Bucharest at that wall time"
    # PR #24's invariant, restated here: the verdict is data on stdout; a diagnostic
    # (this shape also trips the skew warning — the wall digits are a fixture's) stays
    # on stderr, so `--json > f` stays parseable.
    assert "warning" not in out


def test_device_time_table_names_claim_and_site_resolved_offset(device: FakeDevice) -> None:
    """(a, human view) one extra row that says claim vs site-resolved, not just a number.

    Both offsets are in the row's own text, minutes included: the operator at the device
    must be able to tell WHICH side disagrees without switching to `--json`.
    """
    set_device_clock(device, "2026-06-15T14:30:00+02:00")
    code, out = run(["device", "time", *base_args()])
    assert code == 0, out
    assert "tz offset vs site (verdict)" in out
    assert "MISMATCH" in out
    assert "device claims +02:00 (120 min)" in out
    assert "site resolves +03:00 (180 min)" in out


def test_device_time_verdict_stops_firing_when_the_device_agrees(device: FakeDevice) -> None:
    """(b) DESIGN.md item 7's promise: owner fixes the device tz → the flag reads False.

    Same wall digits, correct label: the site-side offset is unchanged (180) and the
    verdict flips, which is the "the flag stops firing when the owner fixes the device tz"
    sentence rendered. A flag that stayed true here would be accusing a clock the owner
    already repaired.
    """
    set_device_clock(device, "2026-06-15T14:30:00+03:00")
    code, out = run(["device", "time", *base_args("--json")])
    assert code == 0, out
    (row,) = rows(out)
    assert row["tz_offset_mismatch"] is False
    assert row["device_claimed_offset_min"] == 180
    assert row["site_offset_min_at_instant"] == 180, "the site side never moved"
    _, table = run(["device", "time", *base_args()])
    assert "MISMATCH" not in table
    assert "device claims +03:00 (180 min)" in table
    assert "site resolves +03:00 (180 min)" in table


def test_device_time_unreadable_claim_is_no_evidence_not_agreement(device: FakeDevice) -> None:
    """(c) THE pin: an unreadable claim is null and must read as ABSENCE, never as agreement.

    A naive `localTime` (this fw variant exists — `tests/fixtures/scenarios/naive_time`)
    asserts nothing, so there is nothing to compare. Rendering that as `false`/`"agrees"`
    would be a false reassurance in the operator's hand, which is exactly the failure
    tz_mismatch.py refuses: None is not False. This test is the mutant catcher — swap the
    None arm for `False` (or drop the `is None` guard in the renderer) and the two
    negative assertions below go red while everything else stays green.
    """
    set_device_clock(device, "2026-06-15T14:30:00")
    code, table = run(["device", "time", *base_args()])
    assert code == 0, table
    assert NO_EVIDENCE in table, "the missing claim must be named, not left as a blank cell"
    assert "MISMATCH" not in table, "absence of a claim is not evidence of a mismatch"
    assert "agrees" not in table, "absence of a claim is not agreement either"

    code, out = run(["device", "time", *base_args("--json")])
    assert code == 0, out
    (row,) = rows(out)
    assert row["tz_offset_mismatch"] is None, "null in JSON — never false for 'no claim'"
    assert row["device_claimed_offset_min"] is None
    # The site side still resolves: the verdict is missing because ONE side is silent,
    # and the payload must show which side that was.
    assert row["site_offset_min_at_instant"] == 180


@pytest.mark.parametrize(
    ("local_time", "expected_site_min"),
    [
        # Bucharest winter: the zone holds +02:00, so a +02:00 claim AGREES there.
        pytest.param("2026-01-15T12:00:00+02:00", 120, id="winter-wall-claims-plus-02"),
        # Bucharest summer: +03:00, so the same +03:00 claim agrees there instead.
        pytest.param("2026-06-15T12:00:00+03:00", 180, id="summer-wall-claims-plus-03"),
    ],
)
def test_device_time_resolves_the_site_zone_at_the_device_wall_not_ours(
    device: FakeDevice, local_time: str, expected_site_min: int
) -> None:
    """The comparison anchors on the device's stamped wall time, never on our clock.

    Mutation catcher (probe m4): resolving the site zone at OUR wall passes every other
    test here, because the two clocks sit seconds apart in the fixtures — yet it is a
    second, different rule, and the wrong one. The offset a zone holds is a property of
    the wall time the device stamped (tz_mismatch.py's rule), which is what makes the
    verdict immune to the device's own label and what keeps a device whose clock has
    drifted by months from being judged against a DST moment it never claimed.

    The two cases are the two sides of the Bucharest DST pair, and the winter one does
    the work: today (mid-October) our own clock still resolves +03:00, so a site zone
    anchored on OUR instant returns 180 for a January stamp where the device's own digits
    say 120.
    """
    set_device_clock(device, local_time)
    code, out = run(["device", "time", *base_args("--json")])
    assert code == 0, out
    (row,) = rows(out)
    assert row["site_offset_min_at_instant"] == expected_site_min, (
        "the site offset is resolved at the DEVICE's wall digits, not at our instant"
    )
    assert row["tz_offset_mismatch"] is False, (
        "a claim that matches the zone AT THE STAMPED INSTANT agrees, whatever our "
        "calendar says today"
    )


def test_device_time_unreadable_wall_clock_is_its_own_no_evidence(device: FakeDevice) -> None:
    """No wall digits → the site side cannot be resolved either, and nothing says "fine".

    A `System/time` body without `localTime` (OBSERVED.md: a device that omits a field is
    a fact to report, not an exception) leaves BOTH sides of the comparison empty — the
    claim and the wall time come out of the same string. The verdict must name which fact
    is missing instead of printing a bare `-`, and the site offset must stay null rather
    than resolving against a clock we do not have. Exit code unchanged: the clock is
    unreadable, the command is not broken.
    """
    body = re.sub(
        r"<localTime>[^<]*</localTime>\n?",
        "",
        fixture_text("system_time.xml"),
    )
    device.reset(
        "GET",
        SYSTEM_TIME_PATH,
        httpx.Response(200, text=body, headers={"Content-Type": "text/xml"}),
    )
    code, table = run(["device", "time", *base_args()])
    assert code == 0, table
    assert "no evidence (no readable device wall clock)" in table
    assert "MISMATCH" not in table and "agrees" not in table

    code, out = run(["device", "time", *base_args("--json")])
    assert code == 0, out
    (row,) = rows(out)
    assert row["tz_offset_mismatch"] is None
    assert row["site_offset_min_at_instant"] is None, "no wall digits, no resolved site offset"
    assert row["skew_seconds"] is None and row["skew_reason"], "skew already says why"


def test_device_time_verdict_costs_no_extra_device_read(device: FakeDevice) -> None:
    """The card's rule: the comparison rides the reading already fetched (one cheap GET).

    Counted on AUTHENTICATED requests: every logical request is two served lines, the
    unauthenticated one the digest challenge answers and the retry that carries the
    credential (see tests/fakedevice.py's `Served.had_auth`).
    """
    set_device_clock(device, "2026-06-15T14:30:00+02:00")
    run(["device", "time", *base_args("--json")])
    clock_reads = [s for s in device.served if s.path == SYSTEM_TIME_PATH and s.had_auth]
    assert len(clock_reads) == 1, (
        f"the verdict must reuse the System/time reading, got {len(clock_reads)} reads"
    )
    assert {s.method for s in device.served} == {"GET"}, "still read-only on the wire"


# --- device capabilities ------------------------------------------------------------------


def test_capabilities_json_is_the_observed_evidence_trail(device: FakeDevice) -> None:
    code, out = run(["device", "capabilities", *base_args("--json")])
    assert code == 0, out
    doc = rows(out)[-1]
    assert doc["limits"]["max_results"] == 30
    assert doc["limits"]["search_id_max"] == 64
    assert doc["raw_acs_event_capabilities"] == fixture_json("acs_capabilities.json")


def test_capabilities_is_read_only_on_the_wire(device: FakeDevice) -> None:
    """Every request this command made was a GET (defense in depth on the registry test)."""
    run(["device", "capabilities", *base_args("--json")])
    assert {s.method for s in device.served} == {"GET"}


# --- users list ---------------------------------------------------------------------------


def test_users_list_table_is_the_cards_three_columns(device: FakeDevice) -> None:
    code, out = run(["users", "list", *base_args()])
    assert code == 0, out
    for column in ("employee_no", "name", "valid"):
        assert column in out
    assert "User E1" in out


def test_users_list_json_is_the_record_and_the_password_hash_is_gone(device: FakeDevice) -> None:
    """OBSERVED.md: UserInfo/Search answers with a `password` hash per user. Stripped."""
    device.routes.clear()
    body = fixture_json("user_search_page1.json")
    for user in body["UserInfoSearch"]["UserInfo"]:
        user["password"] = "$2a$10$fakedummyhashfakedummyhashfakedummyhashfakedummy"
    device.reset_json("POST", USER_SEARCH_PATH, body)
    code, out = run(["users", "list", *base_args("--output", "json")])
    assert code == 0, out
    records = rows(out)
    assert records, "the roster came back"
    assert all("password" not in r for r in records)
    assert "$2a$" not in out, "the hash must never reach stdout"


def test_users_list_valid_reports_unknown_as_its_own_answer(device: FakeDevice) -> None:
    """An absent `Valid.enable` is not a denial — it is the device not having said."""
    device.routes.clear()
    body = fixture_json("user_search_page1.json")
    users = body["UserInfoSearch"]["UserInfo"]
    users[0]["Valid"]["enable"] = False
    del users[1]["Valid"]
    device.reset_json("POST", USER_SEARCH_PATH, body)
    code, out = run(["users", "list", *base_args("--output", "json")])
    assert code == 0, out
    by_no = {r["employee_no"]: r for r in rows(out)}
    assert by_no[users[0]["employeeNo"]]["valid_enabled"] is False
    assert by_no[users[1]["employeeNo"]]["valid_enabled"] is None
    _, table = run(["users", "list", *base_args()])
    assert "unknown" in table


def test_users_list_employee_filter_is_client_side(device: FakeDevice) -> None:
    """UserInfo/Search has never been probed for a server-side employee filter, so the
    CLI must not rely on one: it filters what came back."""
    code, out = run(["users", "list", *base_args("--employee-no", "1", "--output", "json")])
    assert code == 0, out
    records = rows(out)
    assert [r["employee_no"] for r in records] == ["1"]
    # And it never invented a server-side filter for the roster either.
    sent = [json.loads(s.body) for s in device.served if s.path == USER_SEARCH_PATH]
    assert sent and all("employeeNoString" not in b["UserInfoSearchCond"] for b in sent)


def test_users_list_count_is_advisory_and_goes_to_stderr(device: FakeDevice) -> None:
    code, out = run(["users", "list", *base_args("--count", "--output", "json")])
    assert code == 0, out
    assert len(rows(out)) == 4, "stdout is still only the records"
    assert "count" in stderr_of(["users", "list", *base_args("--count")]).lower()
    assert any(s.path == USER_COUNT_PATH for s in device.served)


def test_users_list_survives_a_missing_count_endpoint(device: FakeDevice) -> None:
    """A roster count that 404s is a missing number, not a failed pull."""
    device.reset_raw("GET", USER_COUNT_PATH, _notsupport(404))
    code, out = run(["users", "list", *base_args("--count", "--output", "json")])
    assert code == 0, out
    assert len(rows(out)) == 4


# --- events: the paging DoD ----------------------------------------------------------------


def test_events_prints_three_pages_in_order(device: FakeDevice) -> None:
    """Card DoD: `gateclerk events` on a 3-page fixture prints 3 pages, in order."""
    records = recorded_records()
    device.reset(
        "POST",
        EVENT_PATH,
        *event_pages(records[:10], records[10:20], records[20:]),
    )
    code, out = run(events_args("--format", "jsonl"))
    assert code == 0, out
    printed = rows(out)
    assert len(printed) == 30
    assert [r["serial_no"] for r in printed] == [r["serialNo"] for r in records], (
        "the printed order is the device's page order, not a sort of our own"
    )
    hits = [s for s in device.served if s.path == EVENT_PATH]
    assert len(hits) == 3, f"three pages means three POSTs, saw {len(hits)}"
    # The cursor is the engine's and advances by what the device returned.
    positions = [json.loads(s.body)["AcsEventCond"]["searchResultPosition"] for s in hits]
    assert positions == [0, 10, 20]


def test_events_one_logical_search_keeps_one_search_id_per_chunk(device: FakeDevice) -> None:
    """One chunk = one logical search = one `searchID`, frozen across its pages.

    The length bound is the capability's, not a guess: site-a advertises `@max = 64`
    (OBSERVED.md:42) and the engine clamps to `min(@max, 32)`, so a 32-char hex id is what
    this box is allowed. The 20-char myth comes from sibling models that reject longer ids
    — those get their first 20 characters, which is `paging.new_search_id`'s job and is
    covered by p1-05's own suite. Here the point is the freeze, because a searchID that
    changes mid-walk restarts page 1 SILENTLY (references §1.2).
    """
    records = recorded_records()
    device.reset("POST", EVENT_PATH, *event_pages(records[:10], records[10:20], records[20:]))
    run(events_args("--format", "jsonl"))
    bodies = [json.loads(s.body)["AcsEventCond"] for s in device.served if s.path == EVENT_PATH]
    assert len({b["searchID"] for b in bodies}) == 1, "one chunk = one logical search"
    assert all(16 <= len(b["searchID"]) <= 64 for b in bodies), "within the advertised @max"


def test_events_chunks_the_window_and_walks_oldest_first(device: FakeDevice) -> None:
    """`--chunk 1d` over two days: two windows, each its own search, chronological."""
    device.reset_json("POST", EVENT_PATH, fixture_json("events_no_match.json"))
    code, out = run(
        events_args(
            "--since",
            "2026-05-21T00:00:00",
            "--until",
            "2026-05-23T00:00:00",
            "--chunk",
            "1d",
            "--format",
            "jsonl",
        )
    )
    assert code == 0, out
    bodies = [json.loads(s.body)["AcsEventCond"] for s in device.served if s.path == EVENT_PATH]
    assert len({b["searchID"] for b in bodies}) == 2
    starts = [b["startTime"] for b in bodies]
    assert starts == sorted(starts), "backfill order is oldest-first"
    assert (
        len(starts) == 2
        and starts[0].startswith("2026-05-21")
        and starts[1].startswith("2026-05-22")
    )


def test_events_empty_window_is_a_clean_zero(device: FakeDevice) -> None:
    """Orchestrator note: 'nobody clocked in' is a valid answer, not a failure.

    `NO MATCH` with a space (OBSERVED.md) must terminate the walk after one page.
    """
    device.reset_json("POST", EVENT_PATH, fixture_json("events_no_match.json"))
    code, out = run(events_args())
    assert code == 0, out
    assert "no rows" in out
    assert len([s for s in device.served if s.path == EVENT_PATH]) == 1


def test_events_empty_window_json_prints_nothing(device: FakeDevice) -> None:
    device.reset_json("POST", EVENT_PATH, fixture_json("events_no_match.json"))
    code, out = run(events_args("--format", "jsonl"))
    assert code == 0
    assert out.strip() == ""


# --- events: the jsonl DoD -----------------------------------------------------------------


def test_events_jsonl_feeds_from_jsonl_losslessly(device: FakeDevice) -> None:
    """Card DoD: the jsonl the CLI prints parses back through p1-07 with no loss.

    Compared against `to_dict()` of the re-parsed record rather than against a hand-written
    key list: the record contract owns its field set, and a field the CLI dropped (or
    reformatted) shows up here as an inequality instead of as a test that agrees with the
    implementation.
    """
    code, out = run(events_args("--format", "jsonl"))
    assert code == 0, out
    printed = rows(out)
    assert printed
    round_tripped = from_jsonl(out)
    assert len(round_tripped) == len(printed)
    for got, expected in zip(round_tripped, printed, strict=True):
        assert got.to_dict() == expected, f"jsonl round-trip lost something: {got.serial_no}"


@pytest.fixture
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> datetime:
    """Pin the CLI's `captured_at` clock.

    `captured_at` is a wall-clock stamp, so two runs of the same command a microsecond
    apart can never print byte-identical lines. Pinning it through the CLI's own seam
    (`cli_mod._now`, which is what `RunContext.now` is wired to) is what lets the
    byte-equality tests below compare output instead of tolerating a race.
    """
    instant = datetime(2026, 5, 21, 12, 0, 0, tzinfo=UTC)
    monkeypatch.setattr(cli_mod, "_now", lambda: instant)
    return instant


def test_events_json_and_jsonl_are_the_same_bytes(
    device: FakeDevice, frozen_clock: datetime
) -> None:
    """`jsonl` is a second spelling of the same stream, not a second renderer."""
    _, a = run(events_args("--format", "json"))
    _, b = run(events_args("--format", "jsonl"))
    assert a == b


def test_events_output_flag_and_format_flag_are_synonyms(
    device: FakeDevice, frozen_clock: datetime
) -> None:
    _, a = run(events_args("--format", "jsonl"))
    _, b = run(events_args("--output", "jsonl"))
    _, c = run(events_args("-o", "jsonl"))
    assert a == b == c


def test_events_record_carries_site_serial_and_both_offsets(device: FakeDevice) -> None:
    code, out = run(events_args("--format", "jsonl", "--site-label", "gate-3"))
    assert code == 0, out
    (row,) = rows(out)[:1]
    assert row["site"] == "gate-3"
    assert row["device_serial"] == "MASKED-SER-1"
    # The tz bug the two columns exist to reveal: site zone says +180, device claimed +120.
    assert row["tz_offset_min"] == 180
    assert row["tz_offset_min_device"] == 120
    assert row["tz_offset_mismatch"] is True


def test_events_site_label_falls_back_to_the_host(device: FakeDevice) -> None:
    """No `--site`, no `--site-label`: the host is the only identity available, so it is used.

    `site-a` is p1-02's sites.toml selector and this run has no sites.toml. Inventing that
    label would stamp records with a site name the operator never chose, and two controllers
    read with `--host` would then share a label — a merged punch table would be silently
    wrong. The `--site`-named case is the next test.
    """
    _, out = run(events_args("--format", "jsonl"))
    assert rows(out)[0]["site"] == HOST


def test_events_site_label_comes_from_the_site_name(device: FakeDevice, tmp_path: Path) -> None:
    sites = tmp_path / "sites.toml"
    sites.write_text(
        '[[site]]\nname = "north-gate"\nhost = "192.0.2.10"\niana_tz = "Europe/Bucharest"\n',
        encoding="utf-8",
    )
    code, out = run(
        [
            "events",
            "--site",
            "north-gate",
            "--config",
            str(sites),
            "--user",
            "admin",
            "--password",
            FAKE_PW,
            *WINDOW,
            "--format",
            "jsonl",
        ]
    )
    assert code == 0, out
    assert rows(out)[0]["site"] == "north-gate", (
        "--site names the record when --site-label is absent"
    )


def test_events_table_shows_utc_and_device_local_side_by_side(device: FakeDevice) -> None:
    """Card: 'payroll people ask which one is this' — both stamps, one row."""
    code, out = run(events_args())
    assert code == 0, out
    assert "utc" in out and "local" in out
    # The device's +02:00 string and our resolved +00:00 instant must both be legible in
    # the same row, which is what the width floor in output.py exists to make possible.
    first = re.search(r"│.*?│", out, re.S)
    assert first is not None
    assert not re.search(r"2026-0\s*│", out), "a timestamp split across rows is not visible"
    assert "cardOrFaceOrFp" in out


def test_events_table_columns_are_the_cards_nine(device: FakeDevice) -> None:
    _, out = run(events_args())
    for column in (
        "serial",
        "utc",
        "local",
        "employ",
        "name",
        "verify",
        "outco",
        "status",
        "direc",
    ):
        assert column in out, f"missing column {column}"


# --- events: the filters --------------------------------------------------------------------


def test_events_noise_is_excluded_by_default_and_kept_on_demand(device: FakeDevice) -> None:
    """OBSERVED.md census: 10,169 of 10,199 site-a events are major=3 heartbeats."""
    records = recorded_records()
    noise = [
        {
            "major": 3,
            "minor": 1029,
            "time": "2026-05-21T12:00:00+02:00",
            "type": 0,
            "serialNo": 900 + i,
            "currentVerifyMode": "invalid",
        }
        for i in range(3)
    ]
    device.reset_json(
        "POST",
        EVENT_PATH,
        {
            "AcsEvent": {
                "searchID": "mix",
                "totalMatches": len(records) + len(noise),
                "responseStatusStrg": "OK",
                "numOfMatches": len(records) + len(noise),
                "InfoList": records + noise,
            }
        },
    )
    _, quiet = run(events_args("--format", "jsonl"))
    assert all(r["major"] == 5 for r in rows(quiet))
    assert 900 not in [r["serial_no"] for r in rows(quiet)]

    _, loud = run(events_args("--format", "jsonl", "--include-noise"))
    assert any(r["major"] == 3 for r in rows(loud)), "--include-noise must actually add them"


def test_events_noise_is_filtered_client_side_even_if_the_device_ignores_major(
    device: FakeDevice,
) -> None:
    """We ask for major=5 AND drop major=3 locally: a filter we have not probed is a hint."""
    device.reset_json(
        "POST",
        EVENT_PATH,
        {
            "AcsEvent": {
                "searchID": "ignored-filter",
                "totalMatches": 1,
                "responseStatusStrg": "OK",
                "numOfMatches": 1,
                "InfoList": [
                    {
                        "major": 3,
                        "minor": 1029,
                        "time": "2026-05-21T12:00:00+02:00",
                        "serialNo": 1,
                        "currentVerifyMode": "invalid",
                    }
                ],
            }
        },
    )
    code, out = run(events_args("--format", "jsonl"))
    assert code == 0, out
    assert out.strip() == "", "the device ignored its major filter; the CLI did not"


def test_events_employee_filter_goes_out_as_employee_no_string_and_refilters(
    device: FakeDevice,
) -> None:
    """Orchestrator brief: employeeNoString, never employeeNo, AND re-filter locally."""
    records = recorded_records()
    device.reset_json(
        "POST",
        EVENT_PATH,
        {
            "AcsEvent": {
                "searchID": "emp",
                "totalMatches": len(records),
                "responseStatusStrg": "OK",
                "numOfMatches": len(records),
                "InfoList": records,
            }
        },
    )
    code, out = run(events_args("--format", "jsonl", "--employee-no", "1"))
    assert code == 0, out
    assert {r["employee_no"] for r in rows(out)} == {"1"}
    body = json.loads(next(s for s in device.served if s.path == EVENT_PATH).body)
    cond = body["AcsEventCond"]
    assert cond["employeeNoString"] == "1"
    assert "employeeNo" not in cond, (
        "the suffixless employeeNo is SILENTLY IGNORED on this firmware (OBSERVED.md)"
    )


def test_events_verify_filter_is_a_substring_question(device: FakeDevice) -> None:
    """site-a answers `cardOrFaceOrFp` for every pass, so `--verify face` asks 'could this
    have been a face pass' — a substring match, not an equality match."""
    _, out = run(events_args("--format", "jsonl", "--verify", "face"))
    assert out.strip(), "cardOrFaceOrFp must match --verify face"
    assert all("Face" in r["verify_mode"] or "face" in r["verify_mode"] for r in rows(out))
    _, out = run(events_args("--format", "jsonl", "--verify", "password"))
    assert out.strip() == "", "no site-a record was a password pass"


def test_events_outcome_filter_uses_the_classifier_verdict(device: FakeDevice) -> None:
    _, out = run(events_args("--format", "jsonl", "--outcome", "granted"))
    granted = rows(out)
    assert granted and all(r["outcome"] == "granted" for r in granted)
    _, out = run(events_args("--format", "jsonl", "--outcome", "info"))
    assert all(r["outcome"] == "info" for r in rows(out))
    _, both = run(events_args("--format", "jsonl", "--outcome", "granted", "--verify", "face"))
    assert all(r["outcome"] == "granted" and "Face" in r["verify_mode"] for r in rows(both))


@pytest.mark.parametrize("flag", ["--verify", "--outcome"])
def test_events_rejects_an_unknown_filter_value_as_exit_two(device: FakeDevice, flag: str) -> None:
    """A typo'd filter must not produce an empty table: an empty table reads as 'nobody
    clocked in'. It fails instead, and before any request."""
    bad = "finger" if flag == "--verify" else "maybe"
    code, out = run(events_args(flag, bad, "--format", "jsonl"))
    assert code == CONFIG_ERROR_EXIT, out
    assert bad in out
    assert not [s for s in device.served if s.path == EVENT_PATH], "refused before the wire"


def test_events_max_results_caps_output_after_filtering(device: FakeDevice) -> None:
    """`--max-results 10 --verify face` means ten MATCHING records, not ten then filtered."""
    _, out = run(events_args("--format", "jsonl", "--max-results", "5"))
    assert len(rows(out)) == 5
    _, out = run(events_args("--format", "jsonl", "--max-results", "3", "--verify", "face"))
    matching = rows(out)
    assert len(matching) == 3
    assert all("Face" in r["verify_mode"] for r in matching)


def test_events_reverse_asks_the_device_for_newest_first(device: FakeDevice) -> None:
    run(events_args("--format", "jsonl", "--reverse"))
    cond = json.loads(next(s for s in device.served if s.path == EVENT_PATH).body)["AcsEventCond"]
    assert cond["timeReverseOrder"] is True


def test_events_count_reads_the_documented_count_endpoint_as_advisory(
    device: FakeDevice,
) -> None:
    """`--count` is the AcsEventTotalNum cross-check: displayed, never a loop bound."""
    code, out = run(events_args("--format", "jsonl", "--count"))
    assert code == 0, out
    assert len(rows(out)) == 30, "stdout is the records only"
    hits = [s for s in device.served if s.path == TOTAL_NUM_PATH]
    assert len(hits) == 1
    cond = json.loads(hits[0].body)["AcsEventTotalNumCond"]
    assert cond["major"] == 5 and cond["minor"] == 0
    # p1-05b: the count probe takes the SAME body shape as AcsEvent, so a naive
    # startTime here draws the same 400 badJsonContent — the fake would reject it and
    # the advisory line would print "no readable count" instead of "device says 30".
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}", cond["startTime"])
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}", cond["endTime"])
    line = stderr_of(events_args("--format", "jsonl", "--count"))
    assert "device says 30" in line and "printed 30" in line


def test_events_count_explains_a_legitimate_mismatch(device: FakeDevice) -> None:
    """Device says 30, printed 5 because --max-results capped it: say so, don't alarm."""
    line = stderr_of(events_args("--format", "jsonl", "--count", "--max-results", "5"))
    assert "device says 30, printed 5" in line
    assert "max-results" in line, "the line must name the reason the numbers differ"


def test_events_count_absent_endpoint_is_not_a_failure(device: FakeDevice) -> None:
    """The obvious endpoint name 400s notSupport on this fw; even the right name can be
    missing on another box. A missing advisory number is not a failed payroll pull."""
    device.reset_raw("POST", TOTAL_NUM_PATH, _notsupport())
    code, out = run(events_args("--format", "jsonl", "--count"))
    assert code == 0, out
    assert len(rows(out)) == 30
    assert "no readable count" in stderr_of(events_args("--format", "jsonl", "--count"))


def test_events_never_sends_pic_enable(device: FakeDevice) -> None:
    """DESIGN.md paging rule, checked on the wire the CLI actually used."""
    run(events_args("--format", "jsonl"))
    for s in device.served:
        if s.path == EVENT_PATH:
            assert "picEnable" not in s.body.decode()


def test_events_query_is_always_bounded(device: FakeDevice) -> None:
    run(events_args("--format", "jsonl", "--chunk", "6h"))
    bodies = [json.loads(s.body)["AcsEventCond"] for s in device.served if s.path == EVENT_PATH]
    assert bodies
    assert all("startTime" in b and "endTime" in b for b in bodies)


def test_events_uses_the_device_advertised_page_size(device: FakeDevice) -> None:
    """The capability says @max 30; the CLI must ask for 30, not a guessed 100."""
    run(events_args("--format", "jsonl"))
    cond = json.loads(next(s for s in device.served if s.path == EVENT_PATH).body)["AcsEventCond"]
    assert cond["maxResults"] == 30


# --- events: bounds and the exit-code contract ----------------------------------------------


def test_events_requires_both_bounds(device: FakeDevice) -> None:
    """DESIGN.md forbids an unbounded history walk, so a missing bound is a usage error.

    Built from the pieces rather than through `events_args`: that helper prepends the full
    window, so a test that "removed" one bound by deleting it from a copy still sent both
    and the CLI happily answered with records — a test that could only ever pass.
    """
    for missing in ("--since", "--until"):
        kept: list[str] = []
        for flag, value in zip(WINDOW[::2], WINDOW[1::2], strict=True):
            if flag != missing:
                kept += [flag, value]
        code, out = run(["events", *base_args("--format", "jsonl"), *kept])
        assert code == CONFIG_ERROR_EXIT, f"{missing} missing -> {code}: {out}"
        assert missing in out
        assert not [s for s in device.served if s.path == EVENT_PATH], "refused before the wire"


@pytest.mark.parametrize(
    ("since", "until"),
    [
        ("not-a-date", "2026-05-22T00:00:00"),
        ("2026-05-22T00:00:00", "2026-05-21T00:00:00"),  # backwards
        ("2026-13-45T99:99:99", "2026-05-22T00:00:00"),
    ],
)
def test_events_bad_bounds_exit_two(device: FakeDevice, since: str, until: str) -> None:
    code, out = run(events_args("--since", since, "--until", until, "--format", "jsonl"))
    assert code == CONFIG_ERROR_EXIT, out
    assert not [s for s in device.served if s.path == EVENT_PATH]


def test_events_bad_chunk_exits_two(device: FakeDevice) -> None:
    code, out = run(events_args("--chunk", "every-monday", "--format", "jsonl"))
    assert code == CONFIG_ERROR_EXIT, out
    assert "chunk" in out.lower()


def test_events_unknown_timezone_exits_two_before_any_request(device: FakeDevice) -> None:
    code, out = run(events_args("--tz", "Mars/Olympus_Mons", "--format", "jsonl"))
    assert code == CONFIG_ERROR_EXIT, out
    assert "Olympus" in out
    assert device.served == [], "a typo'd zone must fail before the walk, not on page 40"


def test_events_missing_serial_exits_device_error(device: FakeDevice) -> None:
    """No serialNumber => no idempotency key => refuse rather than stamp blank serials."""
    device.routes.clear()
    device.xml_ok(
        "GET",
        DEVICE_INFO_PATH,
        fixture_text("device_info.xml").replace(
            "<serialNumber>MASKED-SER-1</serialNumber>", "<serialNumber></serialNumber>"
        ),
    )
    code, out = run(events_args("--format", "jsonl"))
    assert code == DEVICE_ERROR_EXIT, out
    assert "serialNumber" in out
    assert not [s for s in device.served if s.path == EVENT_PATH]


def test_events_runaway_paging_exits_five(device: FakeDevice, tmp_path: Path) -> None:
    """Exit 5: the device kept saying MORE past the page cap. Nothing tested 3 or 5 before.

    A device that answers `numOfMatches: 0` while saying MORE is exactly the silent-clamp
    failure p1-05's cap exists for: the cursor never advances, so the walk would loop
    forever. Reaching the cap honestly (10k pages) is what proves the CLI maps the raise to
    5 rather than 4, so the route sticks forever and the pacing is set to 0 ms through
    sites.toml — the cap is real, only the wait between pages is not.
    """
    # One record per page: an empty InfoList ends the walk on page 1 (paging.py's other
    # termination rule), which would prove nothing about the page cap.
    forever = json_ok(
        {
            "AcsEvent": {
                "searchID": "runaway",
                "totalMatches": 999999,
                "responseStatusStrg": "MORE",
                "numOfMatches": 1,
                "InfoList": [
                    {
                        "major": 3,
                        "minor": 1029,
                        "time": "2026-05-21T12:00:00+02:00",
                        "serialNo": 1,
                        "currentVerifyMode": "invalid",
                    }
                ],
            }
        }
    )
    device.reset("POST", EVENT_PATH, forever)
    sites = tmp_path / "sites.toml"
    sites.write_text(
        '[[site]]\nname = "site-a"\nhost = "192.0.2.10"\n'
        'iana_tz = "Europe/Bucharest"\npage_delay_ms = 0\n',
        encoding="utf-8",
    )
    code, out = run(
        [
            "events",
            "--site",
            "site-a",
            "--config",
            str(sites),
            "--user",
            "admin",
            "--password",
            FAKE_PW,
            *WINDOW,
            "--format",
            "jsonl",
        ]
    )
    assert code == RUNAWAY_EXIT, out
    assert "cap" in out.lower() and "page" in out.lower()
    assert out.strip().endswith(f'"exit_code":{RUNAWAY_EXIT}}}'), "exit 5 must be machine-readable"
    pages = [s for s in device.served if s.path == EVENT_PATH]
    assert len(pages) >= 10_000, "the cap was reached by walking, not by short-circuiting"


def test_events_device_error_exits_four(device: FakeDevice) -> None:
    device.reset_raw(
        "POST",
        EVENT_PATH,
        httpx.Response(
            400,
            json={
                "requestURL": EVENT_PATH,
                "statusCode": 6,
                "statusString": "Invalid Content",
                "subStatusCode": "badParameters",
            },
        ),
    )
    code, out = run(events_args("--format", "jsonl"))
    assert code == DEVICE_ERROR_EXIT, out
    assert "Invalid Content" in out


def test_events_auth_failure_exits_three_with_the_lockout_warning(device: FakeDevice) -> None:
    code, out = run(
        [
            "events",
            "--host",
            HOST,
            "--user",
            "admin",
            "--password",
            "fake-wrong-pw",
            *WINDOW,
            "--format",
            "jsonl",
        ]
    )
    assert code == AUTH_TERMINAL_EXIT, out
    assert "lockout" in out.lower()
    authed = [s for s in device.served if s.had_auth]
    assert len(authed) <= 2, "the transport circuit-opened instead of retrying into a lockout"


def test_events_missing_credential_exits_two(
    device: FakeDevice, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("shutil.which", lambda _name: None)
    monkeypatch.delenv("GATECLERK_192_0_2_10_PASSWORD", raising=False)
    monkeypatch.delenv("GATECLERK_PASSWORD", raising=False)
    code, out = run(["events", "--host", HOST, *WINDOW, "--format", "jsonl"])
    assert code == CONFIG_ERROR_EXIT, out
    assert device.served == []


def test_device_info_device_error_exits_four(device: FakeDevice) -> None:
    device.reset_raw("GET", DEVICE_INFO_PATH, httpx.Response(503, text="webs is busy"))
    code, out = run(["device", "info", *base_args("--json")])
    assert code == DEVICE_ERROR_EXIT, out
    assert FAKE_PW not in out


# --- --verbose --------------------------------------------------------------------------------


def test_verbose_logs_the_exact_request_with_the_credential_withheld(
    device: FakeDevice,
) -> None:
    """Card: "I want the request body on screen, not guessed" — and no Authorization."""
    err = stderr_of(events_args("--format", "jsonl", "--verbose"))
    assert "POST" in err and "/ISAPI/AccessControl/AcsEvent" in err
    assert "format=json" in err, "the logged path must be the digest uri= the device hashed"
    assert "AcsEventCond" in err and "startTime" in err, "the BODY, not just the path"
    assert "searchResultPosition" in err
    lowered = err.lower()
    assert "authorization" not in lowered, "the request log must not print the auth header"
    assert FAKE_PW not in err
    assert "digest" not in lowered or "response=" not in lowered


def test_verbose_logs_the_response_and_the_chunk_summaries(device: FakeDevice) -> None:
    err = stderr_of(events_args("--format", "jsonl", "--verbose"))
    assert "chunk" in err and "termination=" in err
    assert "records=30" in err


def test_verbose_lines_cannot_pollute_the_jsonl_on_stdout(device: FakeDevice) -> None:
    """The reason verbose writes to stderr: `--format jsonl > f.jsonl` must stay parseable."""
    code, out = run(events_args("--format", "jsonl", "--verbose"))
    assert code == 0
    for line in out.strip().splitlines():
        (json.loads(line),)  # every stdout line is a record; nothing else may be there


def test_without_verbose_there_is_no_request_log(device: FakeDevice) -> None:
    err = stderr_of(events_args("--format", "jsonl"))
    assert "AcsEventCond" not in err


# --- read-only, from the CLI side ---------------------------------------------------------------


#: The paths the four commands may put on the wire. Everything else in this file's
#: `device.served` is a card violation.
ALLOWED_PATHS = {
    DEVICE_INFO_PATH,
    SYSTEM_TIME_PATH,
    CAPS_PATH,
    AC_CAPS_PATH,
    EVENT_PATH,
    USER_SEARCH_PATH,
    USER_COUNT_PATH,
    TOTAL_NUM_PATH,
}

WRITE_SMELLS = ("/reboot", "/shutdown", "/delete", "/add", "/set", "/clear", "/import", "/update")


@pytest.mark.parametrize(
    "argv",
    [
        ["device", "info", *base_args("--json")],
        ["device", "time", *base_args("--json")],
        ["device", "capabilities", *base_args("--json")],
        ["users", "list", *base_args("--output", "json")],
        ["users", "list", *base_args("--count", "--output", "json")],
        events_args("--format", "jsonl", "--count"),
        events_args("--format", "jsonl", "--include-noise", "--reverse"),
    ],
    ids=["info", "time", "caps", "users", "users-count", "events-count", "events-flags"],
)
def test_no_command_issues_a_write_or_an_unregistered_path(
    device: FakeDevice, argv: list[str]
) -> None:
    """Every request the CLI made is a GET, or a POST to a registered stateless search."""
    assert run(argv)[0] == 0, argv
    for served in device.served:
        assert served.path in ALLOWED_PATHS, f"unregistered path on the wire: {served.path}"
        low = served.path.lower()
        assert not any(smell in low for smell in WRITE_SMELLS), f"write-ish path: {served.path}"
        if served.method == "POST":
            assert low in {
                EVENT_PATH.lower(),
                USER_SEARCH_PATH.lower(),
                TOTAL_NUM_PATH.lower(),
            }, f"POST to a non-search path: {served.path}"


# --- help texts ("help texts sane") ---------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["device", "info"],
        ["device", "time"],
        ["device", "capabilities"],
        ["users", "list"],
        ["events"],
    ],
)
def test_command_help_documents_its_flags_and_exits_zero(argv: list[str]) -> None:
    """Each command declares the shared connection flags, and the help path runs.

    Flag presence comes from Click's parameter list, not from the rendered help:
    Typer renders help through Rich, which on a GitHub Actions runner is told it has
    a terminal and then *elides* rows it cannot fit (seen in CI: an options block
    collapsed to `...` and `--host` vanished from the text). A substring test on that
    render measures Rich's layout, not the command. `--help` is still invoked, because
    "the help path runs and prints" is a real contract too.
    """
    code, out = run([*argv, "--help"])
    assert code == 0, out
    assert out.strip(), f"{argv} --help printed nothing"
    cmd = command_at(app, argv)
    declared = declared_flags(cmd)
    for flag in (
        "--host",
        "--port",
        "--user",
        "--password",
        "--timeout",
        "--site",
        "--config",
    ):
        assert flag in declared, f"{argv} does not declare {flag}"
    # Defaults are DESIGN.md decisions, asserted as values rather than as a
    # substring of a rendered "default: 80".
    assert declared_param(cmd, "--port").default == 80
    assert declared_param(cmd, "--timeout").default == 30.0


def test_events_help_names_the_window_flags_and_every_format() -> None:
    """The window flags are the whole user-facing contract, so they are pinned as
    declarations (see the note in the shared-flag test about why the render is not
    the source of truth)."""
    code, out = run(["events", "--help"])
    assert code == 0
    assert out.strip(), "events --help printed nothing"
    declared = declared_flags(command_at(app, ["events"]))
    for flag in (
        "--since",
        "--until",
        "--employee-no",
        "--verify",
        "--outcome",
        "--chunk",
        "--format",
        "--max-results",
        "--include-noise",
        "--reverse",
        "--count",
        "--site-label",
        "--tz",
    ):
        assert flag in declared, f"events does not declare {flag}"
    # The card's three formats are the option's declared choices, and the timezone
    # default is the value, not a rendered string.
    fmt_param = declared_param(command_at(app, ["events"]), "--format")
    assert set(fmt_param.type.choices) == {"table", "json", "jsonl"}
    assert declared_param(command_at(app, ["events"]), "--tz").default == "Europe/Bucharest"


def test_events_no_longer_lives_under_a_search_subcommand() -> None:
    """The card and DESIGN.md's phase plan spell it `gateclerk events --since ...`."""
    # No `--help` here: it is an eager option, so click prints the `events` help and exits
    # 0 before it validates the extra argument at all.
    code, _ = run(["events", "search", "--host", HOST, "--user", "admin", "--password", FAKE_PW])
    assert code != 0, "`events` is a command now, not a group"
    # Declared, not rendered: `events` must be a top-level command of the app.
    root = typer.main.get_command(app)
    assert "events" in getattr(root, "commands", {}), "events is not a top-level command"
    assert getattr(command_at(app, ["events"]), "commands", None) is None, (
        "`events` must be a command, not a group"
    )


def test_no_help_text_advertises_a_write() -> None:
    """No help screen may name a mutating verb — the invariant in the user's own manual.

    Word boundaries are the whole test: a naive `"put "` substring check fires on the word
    "OUTPUT" (o-u-t-**p-u-t**-space), which every help screen here prints. A help screen
    that mentioned PUT/DELETE would mean the registry grew a write path, which is a design
    change rather than a diff (DESIGN.md).
    """
    verbs = (r"\bput\b", r"\bdelete\b", r"\breboot\b", r"\bshutdown\b", r"\bsettime\b")
    for argv in (
        ["events"],
        ["users", "list"],
        ["device", "info"],
        ["device", "time"],
        ["device", "capabilities"],
    ):
        # Word boundaries are the whole test: a naive `"put " in text` fires on
        # "out**put** format", which every command prints. The prose comes from the
        # command definition rather than the rendered screen because a tripwire that
        # reads a render Rich may have truncated can pass *because* the offending line
        # was elided — which is the one failure direction this must never allow.
        lowered = declared_prose(command_at(app, argv)).lower()
        for verb in verbs:
            assert re.search(verb, lowered) is None, f"{argv} help mentions {verb}"


def test_readme_describes_the_shipped_surface() -> None:
    """The scaffold's README documented stubs; a reader must not be told they are stubs."""
    text = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
    assert "not implemented yet" not in text.lower()
    assert "events search" not in text.lower()
    assert "gateclerk events --since" in text or "--since" in text
