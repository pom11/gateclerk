"""Card p1-09 harness: drive the FULL CLI against FakeDevice, per documented scenario.

`tests/test_cli_commands.py` (card p1-08) proves each command's behaviour against a
hand-seeded device. This harness is the layer above it: a named scenario corpus
(`tests/fixtures/scenarios/`, documented in tests/fixtures/README.md) where each scenario
is one whole fake box — caps, identity, roster, event pages, clock — and test modules run
`gateclerk ...` end to end against every scenario, comparing the `--format jsonl` stream
against a committed golden file.

Why goldens: `EventRecord.to_dict()` is key-ordered and `captured_at` is pinned through the
CLI's own clock seam (`cli_mod._now`), so the jsonl bytes for a scenario are a
deterministic, diffable contract. When someone changes the record shape, the golden diff
*is* the review artifact — a silently dropped field becomes a visible line. Regenerate
deliberately with `GATECLERK_UPDATE_GOLDEN=1 uv run pytest`, read the diff, then commit.

Why a module (not inside test_cli_commands.py): the scenario registry plus the
install/run/golden mechanics are shared by two test modules (test_cli_e2e.py per scenario,
test_cli_e2e_battery.py across all of them). One definition of "what a scenario is", not
two that can drift.

Everything here is offline by construction: the CLI's `IsapiClient` is rebuilt with
FakeDevice's MockTransport, the autouse `netoff` guard still blocks any real socket, and
the fake speaks the recorded digest challenge (tests/fakedevice.py).
"""

from __future__ import annotations

import difflib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import httpx
import pytest
from typer.testing import CliRunner

import gateclerk.cli as cli_mod
from fakedevice import FakeDevice, busy_503, invalid_content
from gateclerk.isapi_transport import IsapiClient

RECORDED = Path(__file__).parent / "fixtures/recorded/site-a-ds-k1t341amf-s"
SCENARIOS_DIR = Path(__file__).parent / "fixtures/scenarios"
SYNTH = Path(__file__).parent / "fixtures/synthetic"
GOLDEN_DIR = Path(__file__).parent / "golden"

#: The zone every scenario's site runs in (OBSERVED.md site-a). Recorded here on purpose
#: rather than imported from the product default: a change to the default must not quietly
#: redefine what these goldens mean.
SITE_TZ = "Europe/Bucharest"

FAKE_PW = "fakepw"  # placeholder policy (tests/test_repo_hygiene.py)
HOST = "192.0.2.10"  # TEST-NET (tests/test_repo_hygiene.py allowlist)

DEVICE_INFO_PATH = "/ISAPI/System/deviceInfo?format=json"
SYSTEM_TIME_PATH = "/ISAPI/System/time?format=json"
CAPS_PATH = "/ISAPI/AccessControl/AcsEvent/capabilities?format=json"
AC_CAPS_PATH = "/ISAPI/AccessControl/capabilities?format=json"
EVENT_PATH = "/ISAPI/AccessControl/AcsEvent?format=json"
USER_SEARCH_PATH = "/ISAPI/AccessControl/UserInfo/Search?format=json"
USER_COUNT_PATH = "/ISAPI/AccessControl/UserInfo/Count?format=json"
TOTAL_NUM_PATH = "/ISAPI/AccessControl/AcsEventTotalNum?format=json"

#: What the CLI is allowed to put on the wire (DESIGN.md read-only registry). The battery
#: asserts every served request is in this set — the read-only promise, checked against
#: what the device actually received rather than against the endpoint table.
ALLOWED_PATHS = frozenset(
    {
        DEVICE_INFO_PATH,
        SYSTEM_TIME_PATH,
        CAPS_PATH,
        AC_CAPS_PATH,
        EVENT_PATH,
        USER_SEARCH_PATH,
        USER_COUNT_PATH,
        TOTAL_NUM_PATH,
    }
)
#: The only endpoints a POST may ever reach (the stateless searches).
ALLOWED_POST_PATHS = frozenset({EVENT_PATH, USER_SEARCH_PATH, TOTAL_NUM_PATH})

#: The one instant for every golden. `captured_at` is a wall-clock stamp, so without
#: pinning it through the CLI's own seam two runs can never print identical bytes.
GOLDEN_NOW = datetime(2026, 6, 15, 12, 0, 0, tzinfo=UTC)

runner = CliRunner()


def fixture_text(directory: Path, name: str) -> str:
    return (directory / name).read_text(encoding="utf-8")


def fixture_json(directory: Path, name: str) -> dict[str, Any]:
    return json.loads(fixture_text(directory, name))


def fresh_system_time() -> str:
    """site-a's recorded System/time body with a CURRENT wall clock, same broken stamp.

    A golden run must not age: the recorded `localTime` is a 2026-10-15 probe snapshot, so
    a "device time" answer compared against it would drift further from our clock every day
    the suite runs. This keeps the parts that define the scenario — the +02:00-in-+03:00
    offset label and the never-engaging DST rule (OBSERVED.md) — and moves only the wall
    reading, which is exactly what `gateclerk device time` compares (wall vs wall in site tz).
    """
    return _fresh_wall(fixture_text(RECORDED, "system_time.xml"))


def _fresh_wall(text: str) -> str:
    """Rewrite any <localTime> wall digits to the CURRENT site wall clock, stamp kept.

    Applied to scenario-authored clocks too: what a scenario file defines — the
    +02:00-in-+03:00 stamp, the naive no-stamp spelling, the tz rule — survives verbatim;
    only the wall digits move, so no golden ages and `device time` skew measures the
    clock, not fixture rot from a 2026-10-15 probe snapshot.
    """
    wall = datetime.now(ZoneInfo(SITE_TZ)).strftime("%Y-%m-%dT%H:%M:%S")
    return re.sub(
        r"<localTime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}([^<]*)</localTime>",
        lambda m: f"<localTime>{wall}{m.group(1)}</localTime>",
        text,
    )


@dataclass(frozen=True, slots=True)
class Scenario:
    """One whole fake box. Each field names a fixture file or a behaviour the fake runs.

    `events` is the per-page queue for POST AcsEvent: FakeDevice pops one response per
    request and the LAST sticks, so a multi-page scenario is an ordered list of page
    bodies. The fake does NOT filter by time window — it serves the pages a device of this
    shape serves. What the CLI *puts* in the window is asserted from the served request
    bodies (see `E2E.event_bodies`), never from the served responses.
    """

    name: str
    #: --since/--until the scenario's golden run uses (both naive; read in SITE_TZ).
    since: str
    until: str
    events: tuple[Path, ...]
    users: Path
    #: None -> serve the recorded 4-user count (userNumber 4).
    user_count: Path | None = None
    #: None -> the recorded AcsEvent capabilities (maxResults 30, searchID 64).
    acs_caps: Path | None = None
    #: None -> fresh_system_time() (current wall clock, broken +02:00 stamp).
    system_time: Path | None = None
    #: webs retires the session nonce after the first accepted request (p1-09 "digest
    #: stale nonce"): exactly one stale="true" re-challenge, and the client recovers.
    nonce_rotates: bool = False
    #: webs answers deviceBusy (statusCode 2 / HTTP 503) twice mid-session, then serves
    #: (p1-09 "busy→retry"): the walk must finish byte-identical to the same pages served
    #: without the busy pair.
    busy_then_ok: bool = False
    #: the events endpoint answers Invalid Content/badParameters and STAYS there (p1-09
    #: "Invalid-Content responses", terminal class 6): exit 4 with the body quoted.
    invalid_content: bool = False
    #: the exit code the scenario's golden run must print (4 for the terminal-error box).
    expect_exit: int = 0
    #: extra flags appended to `gateclerk events` for this scenario's golden run.
    event_args: tuple[str, ...] = ()


def _sc(name: str, *parts: str) -> Path:
    return SCENARIOS_DIR.joinpath(name, *parts)


#: The corpus. Each name maps 1:1 to a table row in tests/fixtures/README.md; adding a
#: scenario means adding BOTH (test_cli_e2e.py pins the set against the README).
SCENARIOS: dict[str, Scenario] = {
    # Attendance mode ON (DESIGN.md option A, simulated): checkIn/checkOut plus face
    # (minor 75) and card (minor 1) passes, offset-bearing strings carrying the site-a
    # +02:00-in-+03:00 stamp. The payroll happy path in one box.
    "happy_day": Scenario(
        name="happy_day",
        since="2026-06-15T00:00:00",
        until="2026-06-16T00:00:00",
        events=(_sc("happy_day", "events.json"),),
        users=_sc("happy_day", "users.json"),
        user_count=_sc("happy_day", "user_count.json"),
    ),
    # The same day walked in two 12h chunks: each chunk is its own logical search (new
    # searchID, cursor restarts at 0) and chunk edges OVERLAP by design — the device's
    # startTime/endTime bounds are inclusive — so the noon boundary punch (serial 9013)
    # arrives from BOTH pages. That duplication is the documented contract P2's UPSERT on
    # (device_serial, serial_no) makes free; proving the walk does not LOSE it to chunking
    # is the point. Pages are two real half-day fixtures, not one replayed page.
    "happy_day_chunked": Scenario(
        name="happy_day_chunked",
        since="2026-06-15T00:00:00",
        until="2026-06-16T00:00:00",
        events=(
            _sc("happy_day_chunked", "events_am.json"),
            _sc("happy_day_chunked", "events_pm.json"),
        ),
        users=_sc("happy_day", "users.json"),
        user_count=_sc("happy_day", "user_count.json"),
        event_args=("--chunk", "12h"),
    ),
    # A firmware variant that stamps NO offset at all: the same site-tz policy must resolve
    # identically (tz_source=site-tz, and NO device claim to compare — the mismatch flag is
    # None, not False). The box's System/time is naive too: the whole device speaks wall
    # clock without labels.
    "naive_time": Scenario(
        name="naive_time",
        since="2026-06-16T00:00:00",
        until="2026-06-17T00:00:00",
        events=(_sc("naive_time", "events.json"),),
        users=_sc("happy_day", "users.json"),
        system_time=_sc("naive_time", "system_time.xml"),
    ),
    # Bucharest 2026 DST edges in one page: the autumn fold (02:00-02:59 repeated on 25 Oct)
    # — including two employees stamped the SAME local 02:30 — and the spring gap
    # (03:00-03:59 skipped on 29 Mar) in both the naive and the +02:00-stamped spelling.
    "dst_day": Scenario(
        name="dst_day",
        since="2026-10-25T00:00:00",
        until="2026-10-26T00:00:00",
        events=(_sc("dst_day", "events.json"),),
        users=_sc("happy_day", "users.json"),
    ),
    # Device caps maxResults at 10 (some DS-K1T* boxes; synthetic caps): six pages of
    # exactly ten, six employees, sixty events.
    "max10_box": Scenario(
        name="max10_box",
        since="2026-06-20T00:00:00",
        until="2026-06-21T00:00:00",
        events=tuple(_sc("max10_box", f"events_p{i}.json") for i in range(1, 7)),
        users=_sc("unicode_names", "users.json"),
        acs_caps=SYNTH / "acs_capabilities_max10.json",
    ),
    # Device SILENTLY serves fewer than the requested 30 (seven, per the vendor text): the
    # cursor must follow the returned numOfMatches — advancing by the requested 30 would
    # skip the last four events with no error at all. That is the payroll bug.
    "clamped_maxresults": Scenario(
        name="clamped_maxresults",
        since="2026-06-21T00:00:00",
        until="2026-06-22T00:00:00",
        events=tuple(_sc("clamped_maxresults", f"events_p{i}.json") for i in (1, 2)),
        users=_sc("unicode_names", "users.json"),
    ),
    # Device IGNORES employeeNoString and serves everyone (OBSERVED.md, which is why the
    # filter is re-applied CLIENT-side): the output must still be exactly employee 2's.
    "ignored_employee_filter": Scenario(
        name="ignored_employee_filter",
        since="2026-06-22T00:00:00",
        until="2026-06-23T00:00:00",
        events=(_sc("ignored_employee_filter", "events.json"),),
        users=_sc("unicode_names", "users.json"),
    ),
    # site-a's REAL mode (OBSERVED.md): attendanceStatus absent on every event -> every
    # punch is direction=unknown / direction_source=none. This scenario serves the RECORDED
    # masked capture itself; no synthetic page is involved.
    "attendance_absent": Scenario(
        name="attendance_absent",
        since="2026-05-21T00:00:00",
        until="2026-05-22T00:00:00",
        events=(RECORDED / "events_major5_page1.json",),
        users=RECORDED / "user_search_page1.json",
        user_count=RECORDED / "user_count.json",
    ),
    # Encrypted-person-data site variant (DESIGN.md failure mode; synthetic because site-a
    # is plaintext): a base64 blob in `name` must be flagged, kept verbatim, never decoded
    # or dropped.
    "encrypted_person_data": Scenario(
        name="encrypted_person_data",
        since="2026-06-18T00:00:00",
        until="2026-06-19T00:00:00",
        events=(_sc("encrypted_person_data", "events.json"),),
        users=_sc("encrypted_person_data", "users.json"),
    ),
    # RO names with diacritics stored NFD by the device (different bytes than composed NFC
    # for the same person): the model normalizes to NFC, `raw` keeps the device bytes.
    "unicode_names": Scenario(
        name="unicode_names",
        since="2026-06-17T00:00:00",
        until="2026-06-18T00:00:00",
        events=(_sc("unicode_names", "events.json"),),
        users=_sc("unicode_names", "users.json"),
    ),
    # webs rotates the digest nonce mid-session: exactly one stale="true" re-challenge,
    # zero lost records, and every request after it carries the NEW nonce.
    "digest_stale_nonce": Scenario(
        name="digest_stale_nonce",
        since="2026-06-15T00:00:00",
        until="2026-06-16T00:00:00",
        events=(_sc("happy_day", "events.json"),),
        users=_sc("happy_day", "users.json"),
        nonce_rotates=True,
    ),
    # webs answers deviceBusy (statusCode 2 / HTTP 503) twice mid-session, then serves: the
    # CLI backs off and the OUTPUT is byte-identical to happy_day.
    "busy_then_retry": Scenario(
        name="busy_then_retry",
        since="2026-06-15T00:00:00",
        until="2026-06-16T00:00:00",
        events=(_sc("happy_day", "events.json"),),
        users=_sc("happy_day", "users.json"),
        busy_then_ok=True,
    ),
    # The events endpoint answers Invalid Content/badParameters and stays there (terminal
    # class 6 — retrying that class is the door-terminal lockout path): exit 4, body quoted,
    # and ZERO records printed.
    "invalid_content": Scenario(
        name="invalid_content",
        since="2026-06-15T00:00:00",
        until="2026-06-16T00:00:00",
        events=(_sc("happy_day", "events.json"),),  # never served; shape parity only
        users=_sc("happy_day", "users.json"),
        invalid_content=True,
        expect_exit=4,
    ),
}


@dataclass
class E2E:
    """One scenario installation: the fake that was wired up, what it served, and the
    sleeps the client took (inter-page pacing and busy backoff both flow through it)."""

    scenario: Scenario
    device: FakeDevice
    sleeps: list[float] = field(default_factory=list)
    base_urls: list[str] = field(default_factory=list)

    def run(self, args: list[str]) -> tuple[int, str]:
        """Invoke the CLI; a non-SystemExit exception is a failure, not a result."""
        result = runner.invoke(cli_mod.app, args)
        if result.exception is not None and not isinstance(result.exception, SystemExit):
            raise result.exception
        return result.exit_code, result.stdout or ""

    def run_events(self, *extra: str) -> tuple[int, str]:
        """`gateclerk events --format jsonl` for this scenario's window (+ scenario flags)."""
        s = self.scenario
        return self.run(
            [
                "events",
                *conn_args(),
                "--since",
                s.since,
                "--until",
                s.until,
                "--format",
                "jsonl",
                *s.event_args,
                *extra,
            ]
        )

    # -- what the device actually received -----------------------------------------

    def served_paths(self) -> list[str]:
        return [f"{s.method} {s.path}" for s in self.device.served]

    def event_requests(self) -> list[dict[str, Any]]:
        """The parsed bodies of every event POST the fake received (authed or not)."""
        return [
            _loads_or_empty(s.body) for s in self.device.served if s.path == EVENT_PATH and s.body
        ]

    def cond(self) -> list[dict[str, Any]]:
        """The AcsEventCond block of every page request — the cursor, the window, the cap.

        Filtered to requests that actually carry one, so an assertion about positions never
        silently reads a list that is short because a broken POST (no cond) was skipped.
        """
        return [b["AcsEventCond"] for b in self.event_requests() if "AcsEventCond" in b]

    def positions(self) -> list[int]:
        return [c["searchResultPosition"] for c in self.cond()]

    def max_results_requested(self) -> list[int]:
        return [c["maxResults"] for c in self.cond()]

    def search_ids(self) -> list[str]:
        return [c["searchID"] for c in self.cond()]

    def window_strings(self) -> list[tuple[str, str]]:
        return [(c["startTime"], c["endTime"]) for c in self.cond()]

    def auth_nonces(self) -> list[str]:
        """The `nonce=` of every authenticated request, in arrival order."""
        return [s.digest.get("nonce", "") for s in self.device.served if s.had_auth]

    @staticmethod
    def rows(out: str) -> list[dict[str, Any]]:
        return [json.loads(line) for line in out.strip().splitlines() if line.strip()]


def conn_args() -> list[str]:
    return ["--host", HOST, "--user", "admin", "--password", FAKE_PW]


def _loads_or_empty(body: bytes) -> dict[str, Any]:
    """Parse a request body, tolerating the non-JSON a broken POST can still carry."""
    try:
        loaded = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def install(scenario: Scenario, monkeypatch: pytest.MonkeyPatch) -> E2E:
    """Seed a FakeDevice with `scenario` and point the CLI at it.

    Same redirection as p1-08's `device` fixture — the real `IsapiClient` is still
    constructed (so its InvalidURL/timeout contract keeps running under test); only the
    transport and the pacing sleep are swapped. The capability cache is process state and
    is cleared, or one scenario's caps would answer another's walk. The clock is pinned
    through the CLI's own seam, so golden bytes never race a wall clock.
    """
    device = FakeDevice(password=FAKE_PW)
    e2e = E2E(scenario=scenario, device=device)

    device.xml_ok("GET", DEVICE_INFO_PATH, fixture_text(RECORDED, "device_info.xml"))
    # Scenario-authored clocks get the same wall-refresh as the default: the file
    # defines the SHAPE (naive or stamped, the tz rule); the digits never age.
    system_time = (
        _fresh_wall(scenario.system_time.read_text(encoding="utf-8"))
        if scenario.system_time is not None
        else fresh_system_time()
    )
    device.xml_ok("GET", SYSTEM_TIME_PATH, system_time)
    caps_body = (
        scenario.acs_caps.read_text(encoding="utf-8")
        if scenario.acs_caps is not None
        else fixture_text(RECORDED, "acs_capabilities.json")
    )
    device.add("GET", CAPS_PATH, httpx.Response(200, content=caps_body.encode()))
    device.json_ok("GET", AC_CAPS_PATH, fixture_json(SYNTH, "access_control_capabilities.json"))

    if scenario.invalid_content:
        # reset_raw repeats the last item, so "broken" STAYS broken: the transport's single
        # 5xx retry must not find a healthy page waiting on attempt two.
        device.reset_raw("POST", EVENT_PATH, invalid_content())
    else:
        for page in scenario.events:
            device.add("POST", EVENT_PATH, httpx.Response(200, content=page.read_bytes()))
        if scenario.busy_then_ok:
            # "Busy MID-SESSION": the busy pair must land on AUTHORIZED event requests. The
            # first POST arrives unauthenticated (the session was primed on GETs, but httpx
            # DigestAuth caches its challenge per client — the first event POST still pays
            # its own 401 on this fake), so the queue is: challenge (paid), then two 503s on
            # the replays, then the route queue serves the pages. A raw busy pair WITHOUT the
            # leading challenge would model a different bug — busy on unauthenticated probes.
            device.add_raw("POST", EVENT_PATH, device.challenge(), busy_503(), busy_503())
    if scenario.nonce_rotates:
        device.expire_after = 1

    device.reset_json("POST", USER_SEARCH_PATH, _read_json(scenario.users))
    count_body = (
        _read_json(scenario.user_count)
        if scenario.user_count is not None
        else fixture_json(RECORDED, "user_count.json")
    )
    device.reset_json("GET", USER_COUNT_PATH, count_body)
    device.reset_json(
        "POST", TOTAL_NUM_PATH, {"AcsEventTotalNum": {"totalNum": _total_events(scenario)}}
    )

    real = IsapiClient

    def factory(base_url: str, user: str, password: str, **kw: Any) -> IsapiClient:
        e2e.base_urls.append(base_url)
        return real(base_url, user, password, transport=device.transport, sleep=e2e.sleeps.append)

    from gateclerk import cli_shared

    monkeypatch.setattr(cli_shared, "IsapiClient", factory)
    monkeypatch.setattr(cli_shared, "_now", lambda: GOLDEN_NOW)
    from gateclerk.capabilities import capability_cache

    capability_cache().clear()
    return e2e


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _total_events(scenario: Scenario) -> int:
    """What AcsEventTotalNum should answer for this box.

    The stuck-page queue (ONE page body is replayed for every request once the queue
    drains) is read once per chunk, so a chunked scenario's window really does contain
    the page items per chunk. The count is advisory (never a walk bound); being exact is
    what lets the battery's `--count` cross-check pass instead of merely warn.
    """
    if scenario.invalid_content:
        return 0
    per_page = [
        len(_read_json(page).get("AcsEvent", {}).get("InfoList") or []) for page in scenario.events
    ]
    if len(per_page) == 1:
        return per_page[0] * _chunk_count(scenario)
    return sum(per_page)


def _chunk_count(scenario: Scenario) -> int:
    """How many `--chunk` windows the scenario's [since, until] splits into."""
    from gateclerk.paging import parse_chunk

    flags = dict(zip(scenario.event_args[::2], scenario.event_args[1::2], strict=False))
    step = parse_chunk(flags.get("--chunk", "1d"))
    span = datetime.fromisoformat(scenario.until) - datetime.fromisoformat(scenario.since)
    return max(1, -(-span // step))  # ceil, same shape as iter_event_windows


# --- goldens ---------------------------------------------------------------------------


def golden_name(command: str, scenario: Scenario) -> str:
    """tests/golden file name for one scenario's `command` stream.

    One file per (command, scenario): `events_happy_day.jsonl`, `users_max10_box.jsonl`.
    The scenario name is already the full identity of the box (a variant box like
    happy_day_chunked is its own name, not a suffix), so a renamed scenario renames its
    goldens with it — and a golden whose name no scenario claims is dead weight `git
    status` will show.
    """
    return f"{command}_{scenario.name}.jsonl"


def check_golden(name: str, produced: str) -> None:
    """Compare `produced` against tests/golden/<name>, or (re)write it when asked.

    GATECLERK_UPDATE_GOLDEN=1 is the deliberate regeneration switch: run it, READ the git
    diff, and only then commit. A golden that changed because a record field changed is the
    review artifact; one that changed for no reason is the bug this exists to catch.
    """
    path = GOLDEN_DIR / name
    if os.environ.get("GATECLERK_UPDATE_GOLDEN") == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(produced, encoding="utf-8")
        return
    if not path.exists():
        raise AssertionError(
            f"golden {path.name} is missing — generate with "
            "GATECLERK_UPDATE_GOLDEN=1 uv run pytest tests/test_cli_e2e.py and review the diff"
        )
    expected = path.read_text(encoding="utf-8")
    if produced != expected:
        diff = "\n".join(
            difflib.unified_diff(
                expected.splitlines(),
                produced.splitlines(),
                "golden",
                "produced",
                lineterm="",
                n=1,
            )
        )
        raise AssertionError(
            f"golden {path.name} differs ({len(expected.splitlines())} golden line(s) vs "
            f"{len(produced.splitlines())} produced). If the change is intended: "
            "GATECLERK_UPDATE_GOLDEN=1 uv run pytest, review the diff, commit.\n"
            f"{diff[:4000]}"
        )
