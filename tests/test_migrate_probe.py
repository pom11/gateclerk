"""Card E1-03 definition of done: the capability probe, driven against FakeDevice.

`gateclerk.migrate_probe` is the gate every later E1 card (diff, apply, template port)
reads, so these tests pin what the gate promises (docs/ENROLLMENT-MIGRATION.md v4 §3):

* every surface carries the DEVICE's verdict — never an inherited assumption. The
  no-assumption-leak test flips each fake knob to a non-OK answer and asserts the
  matrix records exactly what this device said, with bench A's truth nowhere near it;
* the v4 discovery traps stay armed: FDSearch availability comes from the CALL
  (flat dialect — the wrapped one is what 400'd), never from `isSuportFDSearch:false`
  in FDLib caps, which sits in the same matrix as `face_search_available_by_call`
  and must not contaminate it;
* one authorized request per surface, fail-closed on the two derived bodies
  (FDSearch without a discovered FDID, the FP read without a discovered employeeNo
  record zero requests and record ERROR-not-sent rather than guessing a shape);
* the persisted matrix is PII-free by construction (a serialization scan, not a
  promise), file mode 0600, and the freshness gate refuses missing, stale, naive,
  future-stamped and corrupt probes alike — every one injected-clock, never `now()`.

Nothing here opens a socket (`conftest.netoff`, autouse) and nothing invents a
device answer: every envelope the fake serves is the one OBSERVED.md recorded, or
the documented extrapolation next to it.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from fakedevice import (
    BASE_URL,
    FakeDevice,
    not_support,
)
from gateclerk.capabilities import CapabilityCache
from gateclerk.isapi_transport import IsapiClient
from gateclerk.migrate_probe import (
    CapabilityMatrix,
    ProbeAbortedError,
    ProbeStaleError,
    Verdict,
    load_matrix,
    probe_device,
    probe_file_name,
    probes_dir,
    require_fresh,
    require_fresh_probe,
    save_matrix,
)
from gateclerk.tz import TimestampInputError

RECORDED = Path(__file__).parent / "fixtures/recorded/site-a-ds-k1t341amf-s"
SYNTH = Path(__file__).parent / "fixtures/synthetic"

SITE_TZ = "Europe/Bucharest"
HOST = "192.0.2.10"  # TEST-NET (tests/test_repo_hygiene.py allowlist)
FAKE_PW = "fakepw"  # placeholder policy (tests/test_repo_hygiene.py)

#: One fixed instant for every matrix in this file: `probed_at` must come from the
#: injected clock, so a test that pins `now` pins the stamp byte-for-byte.
NOW = datetime(2026, 10, 21, 9, 0, 0, tzinfo=UTC)

DEVICE_INFO_PATH = "/ISAPI/System/deviceInfo?format=json"
SYSTEM_TIME_PATH = "/ISAPI/System/time?format=json"
CAPS_PATH = "/ISAPI/AccessControl/AcsEvent/capabilities?format=json"
AC_CAPS_PATH = "/ISAPI/AccessControl/capabilities?format=json"

# Enrollment paths WITHOUT the query: the fake matches on `request.url.path`, and
# the request log keys carry `?format=json` — `hits()` strips before comparing.
USER_SEARCH_PATH = "/ISAPI/AccessControl/UserInfo/Search"
CARD_SEARCH_PATH = "/ISAPI/AccessControl/CardInfo/Search"
DETAIL_SEARCH_PATH = "/ISAPI/AccessControl/UserInfoDetail/Search"
FD_LIB_PATH = "/ISAPI/Intelligent/FDLib"
FD_SEARCH_PATH = "/ISAPI/Intelligent/FDLib/FDSearch"
FP_UPLOAD_PATH = "/ISAPI/AccessControl/FingerPrintUpload"
FP_SEARCH_PATH = "/ISAPI/AccessControl/FingerPrint/Search"
USER_CAPS_PATH = "/ISAPI/AccessControl/UserInfo/capabilities"
CARD_CAPS_PATH = "/ISAPI/AccessControl/CardInfo/capabilities"
FD_CAPS_PATH = "/ISAPI/Intelligent/FDLib/capabilities"
ACS_CFG_CAPS_PATH = "/ISAPI/AccessControl/AcsCfg/capabilities"
USER_SETUP_CAPS_PATH = "/ISAPI/AccessControl/UserInfo/SetUp/capabilities"
USER_SEARCH_CAPS_PATH = "/ISAPI/AccessControl/UserInfo/Search/capabilities"
FP_DOWNLOAD_CAPS_PATH = "/ISAPI/AccessControl/FingerPrintDownload/capabilities"
PLAN_TEMPLATE_PATH = "/ISAPI/AccessControl/PlanTemplate1"


def fixture_text(name: str, *, directory: Path = RECORDED) -> str:
    return (directory / name).read_text(encoding="utf-8")


def fixture_json(name: str, *, directory: Path = RECORDED) -> dict[str, Any]:
    return json.loads(fixture_text(name, directory=directory))


def hits(device: FakeDevice, method: str, path: str) -> int:
    """Authorized requests to `path` (query stripped) — the per-surface budget pin."""
    want = f"{method} {path}"
    return sum(
        count for key, count in device.authorized_by_path.items() if key.split("?")[0] == want
    )


@pytest.fixture
def device() -> FakeDevice:
    """Bench-A-shaped box: classic identity/caps routes plus the enrollment read axis.

    The classic routes are registered explicitly (deviceInfo/System:time/both caps
    bodies are the recorded fixtures — the same bytes every other suite replays);
    `install_enrollment` then arms the enrollment axis with v4/OBSERVED truth and
    the dialect strictness the device actually has (wrapped-only UserInfo/Search,
    flat-only FDSearch, FingerPrintCond wrapper, and 404-notSupport for everything
    bench A genuinely lacks).
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
        "GET", AC_CAPS_PATH, fixture_json("access_control_capabilities.json", directory=SYNTH)
    )
    d.install_enrollment()
    return d


@pytest.fixture
def client(device: FakeDevice) -> IsapiClient:
    return IsapiClient(
        BASE_URL, "admin", FAKE_PW, transport=device.transport, sleep=lambda _s: None
    )


def probe(client: IsapiClient, **kw: Any) -> CapabilityMatrix:
    options: dict[str, Any] = {
        "now": NOW,
        "site": "site-a",
        "host": HOST,
        "site_tz": SITE_TZ,
        "cache": CapabilityCache(),
    }
    options.update(kw)
    return probe_device(client, **options)


# --- the happy path: bench A's recorded truth, discovered not assumed ---------------------


def test_bench_a_matrix_is_the_observed_truth(client: IsapiClient, device: FakeDevice) -> None:
    m = probe(client)

    # identity: from deviceInfo, serial PREFIX only (§3 never keeps the full serial)
    assert m.model and m.firmware
    assert m.serial_prefix and len(m.serial_prefix) == 4

    # §1 v4: the searches the device answers
    assert m.verdict_of("users") is Verdict.OK
    assert m.users_count == 3  # OK-checked totalMatches, not a page length
    assert m.verdict_of("cards") is Verdict.OK
    assert m.cards_count == 0  # device's own NO MATCH is a VERIFIED zero, not silence
    assert m.template_nos == ("1",)  # from RightPlan — the only template evidence (§3)

    # §1 v4: faces. Availability came from the FDSearch CALL succeeding...
    assert m.verdict_of("face_records") is Verdict.OK
    assert m.face_fdids == ("1", "2")  # FDID 2 = infraredFD exists (OBSERVED)
    assert m.face_search_available_by_call is True
    assert m.face_template_exportable is True  # rows carried modelData
    # ...while the caps document SAYS the opposite. Both facts persist side by side;
    # the product must never read the claim as availability (v4's caps-under-claim).
    assert m.caps_raw["caps_fd_lib"]["FDLibCap"]["isSuportFDSearch"] is False

    # §1 v4: the fingerprint READ is FingerPrintUpload-Cond (misleading name), and
    # FingerPrint/Search really is notSupport.
    assert m.verdict_of("fingerprints_read") is Verdict.OK
    assert m.fp_templates_readable is True
    assert m.verdict_of("fingerprints_search") is Verdict.NOT_SUPPORT

    # §1 v4: the genuinely-absent surfaces, recorded as DISCOVERED notSupport.
    assert m.verdict_of("per_person_detail") is Verdict.NOT_SUPPORT
    assert m.verdict_of("plan_templates") is Verdict.NOT_SUPPORT
    assert m.verdict_of("caps_user_setup") is Verdict.NOT_SUPPORT
    assert m.verdict_of("caps_user_info_search") is Verdict.NOT_SUPPORT
    assert m.verdict_of("caps_fingerprint_download") is Verdict.NOT_SUPPORT
    # ...and the caps documents that v3 wrongly filed as 404: they answer.
    assert m.ok("caps_user_info") and m.ok("caps_card_info")
    assert m.ok("caps_fd_lib") and m.ok("caps_acs_cfg")
    assert m.valid_time_type_opts == ("local",)  # drives §5.1a's payroll stakes

    # the photo-bytes question is CLOSED (faceURL 404, OBSERVED) — settled fact,
    # zero requests spent re-arguing it.
    assert "faceURL 404" in m.face_photo_bytes
    assert hits(device, "GET", "/LOCALS") == 0  # type: ignore[arg-type]

    # paging evidence came from the device's own caps (@max 30 in the fixture)
    assert m.search_max_results == 30
    assert m.probed_at == NOW.isoformat()


def test_clock_skew_is_wall_not_the_self_labelled_instant(client: IsapiClient) -> None:
    """The OBSERVED offset bug must not reappear as a 3600 s false alarm.

    The recorded System/time says `localTime 2026-10-15T16:39:32+02:00` while the
    site zone (Europe/Bucharest, October) is +03:00. Comparing UTC INSTANTS would
    call that a one-hour device-clock error; comparing WALL clocks reports what is
    actually true — the device's wall IS one hour behind ours here, and the claimed
    offset (+02:00) is recorded separately as the device's own (wrong) claim.
    """
    ours = datetime(2026, 10, 15, 14, 39, 32, tzinfo=UTC)  # 17:39:32 site wall
    m = probe(client, now=ours)
    assert m.clock_skew_s == -3600.0  # device wall minus site wall, seconds
    assert m.clock_claimed_offset_min == 120  # the +02:00 claim, kept as claim
    assert m.verdict_of("clock") is Verdict.OK


def test_probed_at_comes_from_the_injected_clock(client: IsapiClient) -> None:
    late = NOW + timedelta(days=3)
    assert probe(client, now=late).probed_at == late.isoformat()
    with pytest.raises(TimestampInputError):
        probe(client, now=datetime(2026, 10, 21, 9, 0, 0))  # noqa: DTZ001 - naive: refuse, not guess


# --- the v4 dialect pins: the fake enforces them, the probe obeys them ---------------------


def test_fdsearch_goes_out_flat_never_wrapped(client: IsapiClient, device: FakeDevice) -> None:
    """One wrong wrapper cost a whole probe round: the flat body is the proven one."""
    probe(client)
    body = next(s.body.decode() for s in device.served if s.path.split("?")[0] == FD_SEARCH_PATH)
    sent = json.loads(body)
    assert "FDSearchCond" not in sent
    assert sent["faceLibType"] == "blackFD"
    assert sent["FDID"] == "1"  # discovered from the FDLib GET, not hardcoded
    assert sent["maxResults"] == 30  # clamped to the caps @max, not our wish
    assert hits(device, "POST", FD_SEARCH_PATH) == 1


def test_user_info_search_goes_out_wrapped_with_search_id(
    client: IsapiClient, device: FakeDevice
) -> None:
    """Flat UserInfo/Search 400s badJsonContent on this fw (OBSERVED) — wrapped +
    searchID is the shape that answers."""
    probe(client)
    body = next(s.body.decode() for s in device.served if s.path.split("?")[0] == USER_SEARCH_PATH)
    cond = json.loads(body)["UserInfoSearchCond"]
    assert cond["searchID"]  # missing searchID answered MessageParametersLack
    assert cond["searchResultPosition"] == 0


def test_fp_read_uses_the_cond_wrapper_the_device_requires(
    client: IsapiClient, device: FakeDevice
) -> None:
    probe(client)
    body = next(s.body.decode() for s in device.served if s.path.split("?")[0] == FP_UPLOAD_PATH)
    cond = json.loads(body)["FingerPrintCond"]
    assert cond["dataType"] == "template"
    assert cond["fpIndex"] == 0
    # the probe read SOME employeeNo (which one is device state, not our choice)
    assert cond["employeeNo"]


# --- budget: one attempt per surface, and fail-closed surfaces spend zero ------------------


def test_one_authorized_attempt_per_surface(client: IsapiClient, device: FakeDevice) -> None:
    """The card's budget rule (§0.5): a surface is asked ONCE. No retries dressed as
    probes — a 400 is an answer, and the transport is what retries (busy/stale), not
    this module."""
    probe(client)
    budgeted = [
        ("GET", "/ISAPI/System/deviceInfo"),
        ("GET", "/ISAPI/AccessControl/AcsEvent/capabilities"),
        ("GET", "/ISAPI/AccessControl/capabilities"),
        ("GET", "/ISAPI/System/time"),
        ("GET", USER_CAPS_PATH),
        ("GET", CARD_CAPS_PATH),
        ("GET", FD_CAPS_PATH),
        ("GET", ACS_CFG_CAPS_PATH),
        ("GET", USER_SETUP_CAPS_PATH),
        ("GET", USER_SEARCH_CAPS_PATH),
        ("GET", FP_DOWNLOAD_CAPS_PATH),
        ("POST", USER_SEARCH_PATH),
        ("POST", CARD_SEARCH_PATH),
        ("POST", DETAIL_SEARCH_PATH),
        ("GET", FD_LIB_PATH),
        ("POST", FD_SEARCH_PATH),
        ("POST", FP_UPLOAD_PATH),
        ("POST", FP_SEARCH_PATH),
        ("GET", "/ISAPI/AccessControl/PlanTemplate1"),
    ]
    for method, path in budgeted:
        assert hits(device, method, path) == 1, f"{method} {path} asked more than once"


def test_fdsearch_not_sent_without_a_discovered_fdid(device: FakeDevice) -> None:
    """FDLib GET dead → we refuse to GUESS the FDSearch body (OBSERVED: eight guessed
    shapes, eight 400s). The row records ERROR-with-reason and the box never sees a
    second request."""
    device.add("GET", FD_LIB_PATH + "?format=json", not_support())
    client = IsapiClient(
        BASE_URL, "admin", FAKE_PW, transport=device.transport, sleep=lambda _s: None
    )
    m = probe(client)
    assert m.verdict_of("face_libs") is Verdict.NOT_SUPPORT
    row = m.surface("face_records")
    assert row is not None and row.verdict is Verdict.ERROR
    assert "refusing to guess" in (row.note or "")
    assert m.face_search_available_by_call is False
    assert hits(device, "POST", FD_SEARCH_PATH) == 0


def test_fp_read_not_sent_without_a_discovered_employee_no(device: FakeDevice) -> None:
    """UserInfo/Search dead → no employeeNo known → the FP read is recorded not-sent
    rather than fired at a guessed target."""
    device.install_enrollment(answer_search="notSupport")
    client = IsapiClient(
        BASE_URL, "admin", FAKE_PW, transport=device.transport, sleep=lambda _s: None
    )
    m = probe(client)
    assert m.verdict_of("users") is Verdict.NOT_SUPPORT
    assert m.users_count is None  # a notSupport is never read as "0 users" (§0.7)
    row = m.surface("fingerprints_read")
    assert row is not None and row.verdict is Verdict.ERROR
    assert "fail closed" in (row.note or "")
    assert m.fp_templates_readable is False
    assert hits(device, "POST", FP_UPLOAD_PATH) == 0


def test_auth_refusal_aborts_without_knocking(device: FakeDevice) -> None:
    """§0.5: a refusal is an abort, not a retry loop — lockout accounting."""
    client = IsapiClient(
        BASE_URL, "admin", "wrongpw", transport=device.transport, sleep=lambda _s: None
    )
    with pytest.raises(ProbeAbortedError):
        probe(client)
    assert sum(device.authorized_by_path.values()) == 0  # nothing was ever served


# --- no-assumption leak: the fake answers differently, the matrix follows ------------------


def test_matrix_records_this_devices_answers_not_bench_as_truth(device: FakeDevice) -> None:
    """Every v4 "works on bench A" fact behind a knob, answered NOT-SUPPORT here.

    The design's fear in one test: a probe that hardcodes "faces work, fingerprints
    read" would report it on a box where the fw says otherwise. Flip three surfaces
    and the matrix must carry the local verdict with bench A nowhere in it.
    """
    device.install_enrollment(
        answer_fd_search="notSupport",
        answer_fp_read="notSupport",
        answer_user_caps="notSupport",
    )
    client = IsapiClient(
        BASE_URL, "admin", FAKE_PW, transport=device.transport, sleep=lambda _s: None
    )
    m = probe(client)
    assert m.verdict_of("face_records") is Verdict.NOT_SUPPORT
    # The FP read fires (users were OK) and the box refuses it: the verdict must be
    # THIS box's notSupport, not bench A's "works".
    assert m.verdict_of("fingerprints_read") is Verdict.NOT_SUPPORT
    assert m.verdict_of("caps_user_info") is Verdict.NOT_SUPPORT
    assert m.face_search_available_by_call is False
    assert m.face_template_exportable is False
    assert m.fp_templates_readable is False
    assert m.users_count == 3  # the untouched surfaces keep their device-earned facts
    assert m.template_nos == ("1",)
    assert "caps_user_info" not in m.caps_raw
    assert m.valid_time_type_opts == ()  # absent, NOT defaulted to "local"
    # and the untouched surfaces keep their own device-earned verdicts — the leak
    # test is per-surface, not a blanket ERROR dump.
    assert m.verdict_of("cards") is Verdict.OK


def test_rejected_shape_is_recorded_verbatim_never_upgraded(device: FakeDevice) -> None:
    """A device that rejects our shape gets recorded AS REJECTED (v3's FDSearch row
    was this shape of evidence; v4 proved the wrapper was OUR mistake — which is
    exactly why the verdict vocabulary keeps the two apart instead of flattening)."""
    device.add(
        "GET",
        USER_CAPS_PATH + "?format=json",
        httpx.Response(
            400,
            json={
                "statusCode": 6,
                "statusString": "Invalid Content",
                "subStatusCode": "badJsonContent",
                "errorMsg": "UserInfoCap",
            },
        ),
    )
    client = IsapiClient(
        BASE_URL, "admin", FAKE_PW, transport=device.transport, sleep=lambda _s: None
    )
    m = probe(client)
    row = m.surface("caps_user_info")
    assert row is not None
    assert row.verdict is Verdict.REJECTED_SHAPE
    assert row.sub_status_code == "badJsonContent"
    assert m.ok("caps_user_info") is False


def test_unexpected_envelope_is_error_not_zero(client: IsapiClient, device: FakeDevice) -> None:
    """§0.7: a 200 whose envelope we cannot read is an error, never "0 users"."""
    device.add(
        "POST",
        USER_SEARCH_PATH + "?format=json",
        httpx.Response(200, json={"SomethingElse": {"responseStatusStrg": "OK"}}),
    )
    client = IsapiClient(
        BASE_URL, "admin", FAKE_PW, transport=device.transport, sleep=lambda _s: None
    )
    m = probe(client)
    row = m.surface("users")
    assert row is not None and row.verdict is Verdict.ERROR
    assert "envelope" in (row.note or "")
    assert m.users_count is None


# --- persisted artifact: PII-free, 0600, round-trippable ----------------------------------


def test_persisted_matrix_carries_no_pii_or_biometrics(client: IsapiClient, tmp_path: Path) -> None:
    m = probe(client)
    text = m.as_json()
    # names, template bytes, face-model bytes, photo URLs, and RECORD-form keys
    # (the caps documents legitimately carry `userType`/`cardType` as schema CLAIMS
    # — banning those keys would ban the caps bodies §3 requires us to keep).
    for banned in (
        "User E1",
        "User E2",
        "FAKE-FACE-MODEL",
        "FAKE-FP-TEMPLATE",
        "LOCALS/pic",
        '"employeeNo"',
        '"UserInfo"',  # the quoted closing form: "UserInfoCap" (a caps CLAIM) stays legal
        '"password": "',
        '"fingerData"',
        '"modelData"',
    ):
        assert banned not in text, f"persisted matrix leaked {banned!r}"
    # caps bodies (claims) DO survive — they're device metadata, not PII
    assert "isSuportFDSearch" in text


def test_save_load_roundtrip_and_file_hygiene(client: IsapiClient, tmp_path: Path) -> None:
    m = probe(client)
    path = save_matrix(m, tmp_path)
    assert path == probes_dir(tmp_path) / probe_file_name("site-a", HOST)
    assert oct(path.stat().st_mode)[-3:] == "600"  # §2: biometric-adjacent hygiene
    assert oct(path.parent.stat().st_mode)[-3:] == "700"
    assert load_matrix(tmp_path, "site-a", HOST) == m  # frozen/tuples: real equality
    assert require_fresh_probe(tmp_path, "site-a", HOST, NOW) == m


def test_host_labels_cannot_escape_the_probes_dir(tmp_path: Path) -> None:
    name = probe_file_name("../../etc", "192.0.2.10/../passwd")
    assert "/" not in name
    assert name.endswith(".json")
    # the real check: writing through the name lands INSIDE probes/, not on `../`
    matrix = CapabilityMatrix(site="../../etc", host="192.0.2.10/../passwd")
    path = save_matrix(matrix, tmp_path)
    assert path.parent == probes_dir(tmp_path).resolve()
    assert path.exists()
    assert load_matrix(tmp_path, "../../etc", "192.0.2.10/../passwd") is not None


# --- the freshness gate (§4): every doubt refuses ------------------------------------------


def _aged(matrix: CapabilityMatrix, age: timedelta) -> CapabilityMatrix:
    return replace(matrix, probed_at=(NOW - age).isoformat())


def test_fresh_gate_refuses_missing_stale_naive_future_corrupt(
    client: IsapiClient, tmp_path: Path
) -> None:
    m = probe(client)

    # missing → the gate names the remedy (probe first), never "assume fresh"
    with pytest.raises(ProbeStaleError, match="never been probed"):
        require_fresh(None, NOW)

    assert require_fresh(m, NOW + timedelta(days=6, hours=9)) is not None  # card: +6d9h ok
    with pytest.raises(ProbeStaleError, match="stale"):
        require_fresh(m, NOW + timedelta(days=7, seconds=1))  # card: +7d+1s refused

    # naive stamp: we cannot place it against the injected clock → stale
    with pytest.raises(ProbeStaleError, match="naive"):
        require_fresh(replace(m, probed_at="2026-10-21T09:00:00"), NOW)
    # absent stamp
    with pytest.raises(ProbeStaleError, match="no readable"):
        require_fresh(replace(m, probed_at=""), NOW)
    # future stamp beyond tolerance: clock integrity doubt, same fail-closed
    with pytest.raises(ProbeStaleError, match="future"):
        require_fresh(m, NOW - timedelta(days=1))
    # naive `now` itself is a config error, not a staleness call
    with pytest.raises(TimestampInputError):
        require_fresh(m, datetime(2026, 10, 21, 9, 0, 0))  # noqa: DTZ001 - naive now IS the input

    # a file that EXISTS but will not parse is a human problem, not "no probe yet"
    save_matrix(m, tmp_path)
    path = probes_dir(tmp_path) / probe_file_name("site-a", HOST)
    path.write_text("{ not json", encoding="utf-8")
    with pytest.raises(ProbeStaleError, match="unreadable"):
        load_matrix(tmp_path, "site-a", HOST)
