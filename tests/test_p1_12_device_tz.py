"""Card p1-12: sites.toml `device_tz` — mapped device is authoritative, warning silenced.

Owner decision (2026-10-18, do not re-litigate): device clocks stay broken. Each device
may declare the zone its wall digits actually live in — site-a stamps +02:00 year-round
while the digits ARE Europe/Bucharest (OBSERVED.md "time/offset bug") — and with that
mapping declared:

* the run resolves punches in the MAPPED zone (authoritative over the claimed offset);
* the run-level p1-06c warning prints NOTHING (the wrongness is known and accepted);
* record provenance is UNTOUCHED: `tz_offset_mismatch` + both offset fields populate
  every record exactly as an unmapped run would;
* `device time` compares claim vs the effective zone and says `mapped via sites.toml`
  so the operator can see WHY the run-level surface stays quiet.

Cases the card dictates, mapped 1:1 to test names below:

(a) mapped site-a shape (June, claim +02:00): records byte-identical to the UNMAPPED
    run's committed golden, provenance fields still true+populated, stderr has NO
    mismatch line. The golden comparison is the strongest form of "same records":
    tests/golden/events_happy_day.jsonl is produced by the no-mapping path.
(b) unmapped device: current behaviour exactly — the ONE warning line still fires,
    byte-pinned. Mutant catcher: key the suppression on anything other than the
    mapping ("no records", "some records", a typo'd config key) and this goes red
    while (a) stays green.
(c) DST boundary both sides: June (+03:00 vs claim +02:00 -> true, silent via mapping)
    and December (+02:00 == claim -> false, silent regardless), plus a window crossing
    the autumn fold that keeps BOTH record shapes in one silent run.

Plus: the `--tz` precedence decision (an explicitly typed `--tz` beats a declared
mapping — and then the mapping is NOT what resolved the zone, so the alarm returns;
the untouched declared default must NOT beat it), the `device time` mapped verdict,
the invalid-zone config error pinning the message, and the unit-level guarantee that
the suppression is keyed on the mapping flag alone.

Offline by construction: the p1-09 harness (e2e_harness.install) and FakeDevice —
`conftest.netoff` still blocks every real socket. Where a test runs the CLI twice
against one box (mapped then unmapped arms), the sites file is rewritten between
runs and the fake's sticky page queue serves the identical page to both, so the two
arms differ ONLY in the mapping.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

import gateclerk.cli as cli_mod
from e2e_harness import EVENT_PATH, GOLDEN_DIR, SCENARIOS, Scenario, fresh_system_time, install
from gateclerk.config import ConfigError, SiteConfig, load_sites, parse_sites
from gateclerk.model import EventRecord

FAKE_PW = "fakepw"  # placeholder policy (tests/test_repo_hygiene.py)
HOST = "192.0.2.10"  # TEST-NET (tests/test_repo_hygiene.py allowlist)

SYSTEM_TIME_PATH = "/ISAPI/System/time?format=json"

#: Identifies THE mismatch line — same discriminator tests/test_cli_tz_warning.py uses:
#: a substring of the payload, not the `warning:` prefix, because other warnings
#: (p1-05c's window-label fallback) legitimately share the stream.
MISMATCH_MARK = "tz_offset_mismatch=true"

#: The substring that marks "a mapping silenced this run" on the `device time` surface.
MAPPED_MARK = "mapped via sites.toml"

#: The warning bytes p1-06c pinned; p1-12 must reproduce them for every unmapped run.
UNMAPPED_WARNING = (
    "warning: 12 of 12 events have tz_offset_mismatch=true "
    "(device claims +02:00; site Europe/Bucharest resolves +03:00 at these instants) "
    "— records are correct, site-tz resolution is authoritative"
)

SITE_A_MAPPED_TOML = f"""[[site]]
name = "site-a"
host = "{HOST}"
iana_tz = "Europe/Bucharest"
device_tz = "Europe/Bucharest"
"""

SITE_A_UNMAPPED_TOML = f"""[[site]]
name = "site-a"
host = "{HOST}"
iana_tz = "Europe/Bucharest"
"""


def write_sites(tmp_path: Path, toml: str) -> Path:
    path = tmp_path / "sites.toml"
    path.write_text(toml, encoding="utf-8")
    return path


def site_args(sites: Path, *extra: str) -> list[str]:
    """Connection args for a `--site`-named run (the mapping only exists in sites.toml)."""
    return [
        "--site",
        "site-a",
        "--config",
        str(sites),
        "--user",
        "admin",
        "--password",
        FAKE_PW,
        *extra,
    ]


@pytest.fixture
def box(monkeypatch: pytest.MonkeyPatch):
    """Install a named scenario as a live E2E (returns the harness) — p1-09's pattern."""

    def _install(name: str):
        return install(SCENARIOS[name], monkeypatch)

    return _install


# --- fake-page authoring (window-insensitive box; see test_cli_tz_warning.py) -------------


def _page(items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "AcsEvent": {
            "searchID": "p1-12-dtz",
            "totalMatches": len(items),
            "responseStatusStrg": "OK",
            "numOfMatches": len(items),
            "InfoList": items,
        }
    }


def _event(serial: int, wall: str, *, employee: str = "1") -> dict[str, Any]:
    """One major=5 punch stamped `wall` — the offset inside the string IS the scenario."""
    return {
        "major": 5,
        "minor": 1,
        "time": wall,
        "cardType": 1,
        "name": f"User {employee}",
        "cardReaderNo": 1,
        "doorNo": 1,
        "employeeNoString": employee,
        "type": 0,
        "serialNo": serial,
        "userType": "normal",
        "currentVerifyMode": "cardOrFaceOrFp",
        "mask": "no",
        "attendanceStatus": "checkIn",
    }


def serve(e2e, *events: dict[str, Any]) -> None:
    """Replace the box's event answer with one OK page of exactly these records."""
    e2e.device.reset_json("POST", EVENT_PATH, _page(list(events)))


def run_events(e2e, since: str, until: str, args: list[str], *extra: str) -> tuple[int, str, str]:
    """`gateclerk events --format jsonl` with an explicit window and connection args.

    One invocation, both streams (the invariant test_cli_tz_warning pins: counts
    compared across two invocations can pass by accident).
    """
    result = CliRunner().invoke(
        cli_mod.app,
        [
            "events",
            *args,
            "--since",
            since,
            "--until",
            until,
            "--format",
            "jsonl",
            *e2e.scenario.event_args,
            *extra,
        ],
    )
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        raise result.exception
    return result.exit_code, result.stdout or "", result.stderr or ""


def warn_lines(err: str) -> list[str]:
    return [line for line in err.splitlines() if MISMATCH_MARK in line]


def rows_of(out: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in out.strip().splitlines() if line.strip()]


# --- (a) mapped device: same records, provenance intact, no warning -----------------------


def test_mapped_run_prints_the_same_records_as_the_unmapped_golden(box, tmp_path) -> None:
    """site-a shape (June, claim +02:00, device_tz Europe/Bucharest): byte-identical rows.

    The comparison is against the committed golden — the bytes the UNMAPPED path
    produces (test_cli_e2e.py runs every scenario through `--host`, which has no
    mapping surface). "Same records as unmapped" with nothing relaxed: the mapping
    changes WHICH zone the resolution used (here: the same zone, declared explicitly)
    and must not move a single output byte.
    """
    e2e = box("happy_day")
    sites = write_sites(tmp_path, SITE_A_MAPPED_TOML)
    s: Scenario = e2e.scenario
    # `--site-label` matches the golden's label on purpose: the golden run connects via
    # `--host`, whose label default IS the host, while a `--site` run defaults to the
    # site name. The label is the run's identity, not the mapping's effect — pinning it
    # equal is what lets the comparison cover EVERY other byte of every record.
    code, out, err = run_events(e2e, s.since, s.until, site_args(sites, "--site-label", HOST))
    assert code == 0, out
    golden = (GOLDEN_DIR / "events_happy_day.jsonl").read_text(encoding="utf-8")
    assert out == golden, "a mapped run moved a record byte — the mapping must be display-only"
    # Provenance survives the silence: the flag and BOTH offsets still populate.
    rows = rows_of(out)
    assert len(rows) == 12 and all(r["tz_offset_mismatch"] is True for r in rows), (
        "dropping provenance together with the warning is the exact regression this pin exists for"
    )
    assert all(r["tz_offset_min_device"] == 120 for r in rows), "claim kept verbatim"
    assert all(r["tz_offset_min"] == 180 for r in rows), "mapped zone actually used"
    assert all(r["iana_tz"] == "Europe/Bucharest" for r in rows)
    # And the run is SILENT: zero mismatch lines on stderr.
    assert warn_lines(err) == [], f"mapped device must print no warning, got: {err!r}"


def test_mapped_run_keeps_stdout_parseable_and_exit_zero(box, tmp_path) -> None:
    """Silence is display-only: the jsonl contract and the exit code are untouched."""
    e2e = box("happy_day")
    sites = write_sites(tmp_path, SITE_A_MAPPED_TOML)
    s: Scenario = e2e.scenario
    code, out, err = run_events(e2e, s.since, s.until, site_args(sites))
    assert code == 0
    assert len(rows_of(out)) == 12, "stdout stays the parseable stream from_jsonl consumes"
    assert warn_lines(err) == []


# --- (b) unmapped device: the default path did not move ----------------------------------


def test_unmapped_site_still_warns_exactly_once(box, tmp_path) -> None:
    """Same box, same June page, site block WITHOUT device_tz -> the one warning fires.

    This is the mutant catcher the card demands: key the suppression on anything other
    than the mapping (no-records, some-records, a typo'd config key) and this goes red
    while (a) stays green. The line is byte-pinned to the same bytes
    tests/test_cli_tz_warning.py pins, so the default path is proven unmoved.
    """
    e2e = box("happy_day")
    sites = write_sites(tmp_path, SITE_A_UNMAPPED_TOML)
    s: Scenario = e2e.scenario
    code, out, err = run_events(e2e, s.since, s.until, site_args(sites))
    assert code == 0
    assert all(r["tz_offset_mismatch"] is True for r in rows_of(out))
    lines = warn_lines(err)
    assert len(lines) == 1, f"unmapped mismatch run must still warn exactly once: {lines}"
    assert lines[0] == UNMAPPED_WARNING


def test_mapped_then_unmapped_same_box_swaps_silence_for_the_warning(box, tmp_path) -> None:
    """One box, one page, two runs: only the sites file changes between the arms.

    The sticky fake queue serves BOTH runs the identical 12 pages, so a difference on
    stderr can only come from `device_tz` — the tightest possible proof that the
    suppression is keyed on the mapping and nothing else.
    """
    e2e = box("happy_day")
    s: Scenario = e2e.scenario
    sites = write_sites(tmp_path, SITE_A_MAPPED_TOML)
    code, out_a, err_a = run_events(e2e, s.since, s.until, site_args(sites))
    sites.write_text(SITE_A_UNMAPPED_TOML, encoding="utf-8")
    code2, out_b, err_b = run_events(e2e, s.since, s.until, site_args(sites))
    assert code == 0 and code2 == 0
    assert out_a == out_b, "the mapping moved a record byte"
    assert warn_lines(err_a) == [], "mapped arm silent"
    assert warn_lines(err_b) == [UNMAPPED_WARNING], "unmapped arm warns byte-for-byte"


def test_host_rung_never_sees_a_mapping(box) -> None:
    """`--host` has no sites.toml block, so it cannot be mapped: the warning stays."""
    e2e = box("happy_day")
    s: Scenario = e2e.scenario
    code, out, err = run_events(
        e2e, s.since, s.until, ["--host", HOST, "--user", "admin", "--password", FAKE_PW]
    )
    assert code == 0 and len(rows_of(out)) == 12
    assert warn_lines(err) == [UNMAPPED_WARNING]


# --- (c) DST boundary, both sides ----------------------------------------------------------


def test_mapped_june_mismatch_is_true_and_silent(box, tmp_path) -> None:
    """June: mapped zone resolves +03:00, the box claims +02:00 -> true, silenced."""
    e2e = box("happy_day")
    serve(e2e, _event(1, "2026-06-15T08:00:00+02:00"))
    sites = write_sites(tmp_path, SITE_A_MAPPED_TOML)
    code, out, err = run_events(e2e, "2026-06-15T00:00:00", "2026-06-16T00:00:00", site_args(sites))
    assert code == 0
    (row,) = rows_of(out)
    assert row["tz_offset_mismatch"] is True
    assert (row["tz_offset_min_device"], row["tz_offset_min"]) == (120, 180)
    assert warn_lines(err) == []


def test_december_agrees_silent_mapped_and_unmapped(box, tmp_path) -> None:
    """December (+02:00 == claim -> False) on BOTH arms, same box, same served page.

    Silent either way because there is no mismatch to announce. Pinned on both arms so
    a "silence" that only fires in December (a keyed-on-offset bug) cannot sneak past
    one half of the pair.
    """
    e2e = box("happy_day")
    serve(e2e, _event(1, "2026-12-15T08:00:00+02:00"))
    sites = write_sites(tmp_path, SITE_A_MAPPED_TOML)
    code, out, err = run_events(e2e, "2026-12-15T00:00:00", "2026-12-16T00:00:00", site_args(sites))
    assert code == 0
    (row,) = rows_of(out)
    assert row["tz_offset_mismatch"] is False
    assert (row["tz_offset_min_device"], row["tz_offset_min"]) == (120, 120)
    assert warn_lines(err) == []

    sites.write_text(SITE_A_UNMAPPED_TOML, encoding="utf-8")
    code, out, err = run_events(e2e, "2026-12-15T00:00:00", "2026-12-16T00:00:00", site_args(sites))
    assert code == 0
    (row,) = rows_of(out)
    assert row["tz_offset_mismatch"] is False, "the site zone really is +02:00 in December"
    assert warn_lines(err) == []


def test_mapped_window_crossing_the_autumn_fold_keeps_both_shapes(box, tmp_path) -> None:
    """One window, two record shapes: the mapped zone has REAL DST, the clock does not.

    2026-10-25 is Bucharest's autumn fold (04:00 +03:00 -> 03:00 +02:00): 01:30 still
    resolves +03:00 (claim +02:00 -> true), 10:00 resolves +02:00 (claim +02:00 ->
    false). Both rows keep their own offsets, and the mapped run stays silent even
    though half the window mismatches — the whole point of "known-wrong, declared".
    """
    e2e = box("happy_day")
    serve(
        e2e,
        _event(1, "2026-10-25T01:30:00+02:00"),
        _event(2, "2026-10-25T10:00:00+02:00", employee="2"),
    )
    sites = write_sites(tmp_path, SITE_A_MAPPED_TOML)
    code, out, err = run_events(e2e, "2026-10-25T00:00:00", "2026-10-26T00:00:00", site_args(sites))
    assert code == 0
    rows = rows_of(out)
    assert [r["tz_offset_mismatch"] for r in rows] == [True, False]
    assert [(r["tz_offset_min_device"], r["tz_offset_min"]) for r in rows] == [
        (120, 180),
        (120, 120),
    ]
    assert warn_lines(err) == []


# --- the precedence decision: an explicit --tz beats the mapping ---------------------------


LONDON_MAPPED_TOML = (
    f'[[site]]\nname = "site-a"\nhost = "{HOST}"\n'
    'iana_tz = "Europe/Bucharest"\ndevice_tz = "Europe/London"\n'
)


def test_explicit_tz_beats_the_mapping_and_the_alarm_returns(box, tmp_path) -> None:
    """Typed `--tz` is the operator speaking; the mapping yields — and loses its silence.

    sites.toml maps the device to Europe/London; the operator types
    `--tz Europe/Bucharest`. The records must resolve in the TYPED zone (+03:00), and
    because the mapping is then NOT what made the run's zone, the p1-06c warning fires
    again. Suppression belongs to the mapping, not to the box: muting the alarm while
    the operator overrode the mapping would hide a mismatch nobody declared.
    """
    e2e = box("happy_day")
    sites = write_sites(tmp_path, LONDON_MAPPED_TOML)
    s: Scenario = e2e.scenario
    code, out, err = run_events(e2e, s.since, s.until, site_args(sites), "--tz", "Europe/Bucharest")
    assert code == 0
    rows = rows_of(out)
    assert all(r["tz_offset_min"] == 180 for r in rows), "the typed zone resolved the run"
    assert all(r["tz_offset_mismatch"] is True for r in rows)
    lines = warn_lines(err)
    assert len(lines) == 1, "an explicit --tz overriding the mapping brings the alarm back"
    assert lines[0] == UNMAPPED_WARNING


def test_untouched_default_tz_never_beats_the_mapping(box, tmp_path) -> None:
    """`--tz` carries a DECLARED default (Europe/Bucharest) — not giving it is not typing it.

    sites.toml maps to Europe/London; no flag is passed. The mapping must win even
    though the value the command function receives is the default string: only Click's
    parameter source can tell those two states apart, and this pin is what stops a
    "simpler" `tz != DEFAULT_TZ` rewrite — which would silently prefer Bucharest here,
    resolve payroll in the wrong zone, and re-fire the alarm for a mapped box.
    """
    e2e = box("happy_day")
    sites = write_sites(tmp_path, LONDON_MAPPED_TOML)
    s: Scenario = e2e.scenario
    code, out, err = run_events(e2e, s.since, s.until, site_args(sites))
    assert code == 0
    rows = rows_of(out)
    assert all(r["tz_offset_min"] == 60 for r in rows), "mapped Europe/London used (+01:00)"
    assert all(r["tz_offset_mismatch"] is True for r in rows)
    assert all(r["iana_tz"] == "Europe/London" for r in rows)
    assert warn_lines(err) == [], "mapped: silent"


# --- `device time`: the verdict compares claim vs the EFFECTIVE zone -----------------------


def set_clock(device, local_time: str) -> None:
    """Replace the fake's System/time answer with `local_time` verbatim.

    Only `localTime` changes; the recorded +02:00 stamp suffix and the Hikvision tz
    dialect survive (the same rule as test_cli_commands.set_device_clock). A FIXED wall
    is required: the harness refreshes wall digits to "now", and a verdict must not
    flip with the calendar between the June and December arms.
    """
    body = re.sub(
        r"<localTime>[^<]*</localTime>",
        f"<localTime>{local_time}</localTime>",
        fresh_system_time(),
    )
    device.reset(
        "GET",
        SYSTEM_TIME_PATH,
        httpx.Response(200, text=body, headers={"Content-Type": "application/xml"}),
    )


def invoke_device_time(*args: str) -> tuple[int, str]:
    result = CliRunner().invoke(cli_mod.app, ["device", "time", *args])
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        raise result.exception
    return result.exit_code, result.stdout or ""


def test_device_time_mapped_verdict_names_the_mapping_and_uses_the_mapped_zone(
    box, tmp_path
) -> None:
    """Claim +02:00 at a June wall, mapped to Europe/London (+01:00 there).

    Two pins in one sentence: the comparison ran against the MAPPED zone (site resolves
    +01:00/60 — NOT Bucharest's +03:00/180 that `iana_tz` alone would give), and the
    detail says `mapped via sites.toml`, so the operator sees why the run surface is
    silent instead of concluding the two surfaces disagree with each other.
    """
    e2e = box("happy_day")
    set_clock(e2e.device, "2026-06-15T14:30:00+02:00")
    sites = write_sites(tmp_path, LONDON_MAPPED_TOML)
    code, out = invoke_device_time(*site_args(sites))
    assert code == 0, out
    assert "MISMATCH" in out
    assert "device claims +02:00 (120 min)" in out
    assert "site resolves +01:00 (60 min)" in out, "the EFFECTIVE zone, not iana_tz's"
    assert MAPPED_MARK in out
    # The machine surface carries the same fact as a field, not only as prose.
    code, out = invoke_device_time(*site_args(sites, "--json"))
    assert code == 0, out
    (row,) = rows_of(out)
    assert row["tz_mapped_via"] == "Europe/London"
    assert row["tz_offset_mismatch"] is True
    assert row["site_offset_min_at_instant"] == 60


def test_device_time_unmapped_verdict_keeps_today_text(box, tmp_path) -> None:
    """Same shape, no device_tz key: byte-for-byte today's sentence (no mapped note)."""
    e2e = box("happy_day")
    set_clock(e2e.device, "2026-06-15T14:30:00+02:00")
    sites = write_sites(tmp_path, SITE_A_UNMAPPED_TOML)
    code, out = invoke_device_time(*site_args(sites))
    assert code == 0, out
    assert "MISMATCH" in out
    assert "site resolves +03:00 (180 min)" in out
    assert MAPPED_MARK not in out, "no mapping -> no note (unmapped = today, byte-for-byte)"


def test_device_time_mapped_none_claim_stays_no_evidence(box, tmp_path) -> None:
    """The three-valued None rule is unchanged by the mapping: naive wall -> absence.

    naive_time stamps no offset at all, so there is no claim to compare: the verdict
    must still read as ABSENCE with a mapping in play — never as agreement, and never
    as a mapped MISMATCH. The mapping changes the zone, never the three-valued policy.
    """
    box("naive_time")  # installs the naive-clock fake box the command will be served by
    sites = write_sites(tmp_path, SITE_A_MAPPED_TOML)
    code, out = invoke_device_time(*site_args(sites))
    assert code == 0, out
    assert "no evidence (device claims nothing)" in out


# --- the unit seam: suppression keyed on the mapping flag, nothing else --------------------


def _flagged(**over: Any) -> EventRecord:
    payload: dict[str, Any] = {
        "site": "site-a",
        "device_serial": "SN-1",
        "serial_no": 1,
        "event_time_utc": "2026-06-15T05:00:00+00:00",
        "event_time_local": "2026-06-15T08:00:00+02:00",
        "tz_offset_min": 180,
        "tz_offset_min_device": 120,
        "tz_source": "site-tz",
        "iana_tz": "Europe/Bucharest",
        "tz_offset_mismatch": True,
    }
    payload.update(over)
    return EventRecord.from_dict(payload)


def test_suppression_ignores_records_entirely_when_mapping_declared(capsys) -> None:
    """Unit pin: mapping_declared=True prints NOTHING even for a fully-flagged set.

    Direct on the seam (same style as test_cli_tz_warning's wild-claim pins): the
    suppression must not inspect records at all, so this hands it the worst case.
    """
    cli_mod._warn_tz_mismatch([_flagged(), _flagged(serial_no=2)], mapping_declared=True)
    assert capsys.readouterr().err == ""


def test_default_flag_off_reproduces_the_exact_warning(capsys) -> None:
    """Unit pin: without the flag the same single line as today fires (default False)."""
    cli_mod._warn_tz_mismatch([_flagged()])
    err = capsys.readouterr().err
    assert err.count(MISMATCH_MARK) == 1
    assert "device claims +02:00; site Europe/Bucharest resolves +03:00" in err


# --- config layer: the key parses, validates loudly, defaults quietly -----------------------


def test_device_tz_parses_and_defaults_to_none() -> None:
    site = parse_sites(SITE_A_MAPPED_TOML.encode())["site-a"]
    assert site.device_tz == "Europe/Bucharest"
    plain = parse_sites(b'[[site]]\nname = "s"\nhost = "h"\n')["s"]
    assert plain.device_tz is None, "the key is OPTIONAL: absent must mean today's behaviour"


def test_unknown_key_still_refused_device_tz_accepted() -> None:
    """`device_tz` joined `_KNOWN_KEYS` — and its lookalike `dev_tz` must still be loud."""
    parse_sites(SITE_A_MAPPED_TOML.encode())  # must NOT raise
    with pytest.raises(ConfigError, match="unknown key"):
        parse_sites(b'[[site]]\nname = "s"\nhost = "h"\ndev_tz = "Europe/Bucharest"\n')


def test_invalid_device_tz_is_a_loud_config_error_naming_the_key() -> None:
    """The card's pin: unknown zone -> error NAMING `device_tz`, never a silent fallback."""
    with pytest.raises(ConfigError) as exc:
        parse_sites(
            f'[[site]]\nname = "s"\nhost = "{HOST}"\ndevice_tz = "Mars/Olympus_Mons"\n'.encode()
        )
    msg = str(exc.value)
    assert "device_tz" in msg, f"error must name the key: {msg}"
    assert "Mars/Olympus_Mons" in msg, "error must name the value"
    assert "not a resolvable IANA zone" in msg
    # The site-level prefix is present too — the operator sees WHICH site.
    assert "misconfigured" in msg


def test_invalid_device_tz_reaches_the_cli_as_exit_two(box, tmp_path) -> None:
    """Parse-time strictness end to end: the events command refuses before any socket."""
    sites = write_sites(
        tmp_path,
        f'[[site]]\nname = "site-a"\nhost = "{HOST}"\ndevice_tz = "Not/AZone"\n',
    )
    e2e = box("happy_day")
    s: Scenario = e2e.scenario
    code, out, _err = run_events(e2e, s.since, s.until, site_args(sites))
    assert code == 2
    assert "device_tz" in out


def test_constructor_validates_device_tz_too() -> None:
    """Not only TOML: `SiteConfig(...)` directly must refuse the same nonsense."""
    with pytest.raises(ConfigError, match="device_tz"):
        SiteConfig(name="s", host="h", device_tz="Mars/Olympus_Mons")


def test_the_shipped_example_declares_the_mapping() -> None:
    """The example is executable documentation (test_config_credentials's rule)."""
    example = Path(__file__).resolve().parents[1] / "sites.toml.example"
    site = load_sites(example)["site-a"]
    assert site.device_tz == "Europe/Bucharest"
