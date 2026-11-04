"""`gateclerk demo device` — a loopback fake of the `webs` server, synthetic data only.

The operator product goal this module exists for: a developer must be able to try
gateclerk with NO real door controller. That is only true if the demo box speaks the
same ISAPI the production client reads, so this is not a helper the tests cooperate
with — it is an HTTP server the **unmodified** `gateclerk.isapi_transport.IsapiClient`
talks to (tests/test_demo_device.py points the real client at it over a real socket).

Envelope SHAPES are faithful to the recorded captures (docs/OBSERVED.md and
docs/OBSERVED-site-B.md): the XML-despite-?format=json answer on System/*, the
silent `maxResults` clamp to the advertised cap (30 on both recorded sites),
`MORE` until the last page, advance-by-`numOfMatches`, the `NO MATCH` (with the
space) empty window that carries NO `InfoList` key at all, the recorded rejections
(naive/fractional window bound -> `badJsonContent`/`errorMsg=startTime`;
`AcsEvent/Total` -> `400 notSupport`/errorCode 1073741825), and the digest contract
(401 + `WWW-Authenticate: Digest qop="auth"` with the masked realm, then authorized
GETs, `Server: webs`).

SYNTHETIC-ONLY LAW (the card's hard rule, pinned both ways by ARM B of the test):

* every IP is RFC 5737 (192.0.2.x / 198.51.100.x / 203.0.113.x) or loopback;
* person identities are obviously-demo Romanians ("Demo Popescu", "Demoana Ionescu");
* serials are `DEMO-SERIAL-*`, cards `DEMO-CARD-*` — self-labelling, so a human
  reading `gateclerk users list` against the box can SEE the fixture is fake;
* no name/serial/card from ANY capture appears here, and nothing here appears in
  the captures — tests/test_demo_device.py scans both directions on every commit.

Deliberate lenience-free design: the digest `response` is recomputed the way the
device computes it — HA2 over the **request-target the server actually received**
(including `?format=json`), not the `uri=` the client claims (gotchas §1.4: the
infinite-401-loop bug). A fake that trusted the claimed uri, or accepted any
Authorization, would teach a developer a client story that dies on real hardware.
Like `tests/fakedevice.py` (whose masked realm constant this module is the home of),
it is body-strict too: a naive or fractional window 400s HERE, exactly like the box
(OBSERVED.md 2026-10-17 / 2026-10-21), because a demo more lenient than the device
is the false-green machine this repo's history keeps naming.

Known recorded quirks reproduced rather than "fixed": `AcsEvent/capabilities` says
the truth about the cap; `CardInfo/Search` answers the recorded bench-A NO MATCH
even though the roster carries card numbers (users on the capture have numOfCard 0
too — the empty card search is the recorded device answer, so it is the demo answer);
`System/time` claims +02:00 year-round in a Europe/Bucharest site so the product's
tz-mismatch warning is demonstrable offline (the site-a DST bug, OBSERVED.md).

The server binds loopback ONLY (the CLI refuses any other --host) and never needs a
config file: `gateclerk demo device serve` is the whole story.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import secrets
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, ClassVar

from gateclerk.endpoints import REGISTRY

__all__ = [
    "DEMO_BIND_HOST",
    "DEMO_CLAIMED_OFFSET_MIN",
    "DEMO_DEFAULT_PASSWORD",
    "DEMO_DEFAULT_USER",
    "DEMO_DEVICE_NAME",
    "DEMO_DEVICE_TYPE",
    "DEMO_DOCUMENT_HOST",
    "DEMO_EVENT_COUNT",
    "DEMO_FIRMWARE",
    "DEMO_FIRST_SERIAL",
    "DEMO_MAX_RESULTS_CAP",
    "DEMO_MODEL",
    "DEMO_REALM",
    "DEMO_SERIAL",
    "DEMO_SERVER_HEADER",
    "DEMO_SITE_TZ",
    "DEMO_USER_COUNT",
    "SYNTHETIC_FIXTURE_STRINGS",
    "DemoDevice",
    "RequestedCall",
    "demo_answered_addresses",
    "demo_answered_values",
    "demo_card_numbers",
    "demo_employee_nos",
    "demo_events",
    "demo_user_names",
    "is_loopback_bind_host",
    "is_synthetic_address",
    "is_synthetic_serial",
    "last_served_url",
    "report_served_url",
]

# --- the masked device vocabulary (one home; tests/fakedevice.py imports these) ----------

#: The masked realm the fixtures recorded (tests/fixtures/.../digest_challenge_401.txt).
#: Shared home: `tests/fakedevice.py` imports it from here so the offline fake and the
#: demo box cannot drift into two realms (pinned by tests/test_demo_device.py).
DEMO_REALM = "DS-39DED0D1"
#: The device's own server signature (OBSERVED.md: `Server: webs`). Protocol vocabulary,
#: not an identity — the demo must not advertise "Python http.server" to a developer.
DEMO_SERVER_HEADER = "webs"

#: What site-a's clock claims year-round (OBSERVED.md "time/offset bug": +02:00 even in
#: +03:00 summer). The demo claims the SAME wrong offset on purpose — it is what makes
#: `gateclerk`'s tz-mismatch warning demonstrable with no hardware in the loop.
DEMO_CLAIMED_OFFSET_MIN = 120
#: The site zone the demo window is spoken in. The tz-mismatch story needs the zone to
#: be one that is +03:00 in summer while the box claims +02:00 (the site-a bug).
DEMO_SITE_TZ = "Europe/Bucharest"

# --- the synthetic identity corpus (SYNTHETIC-ONLY LAW lives in these values) ------------

#: A model string that is shape-faithful (`DS-…`) and impossible to mistake for a real
#: unit. The captures record `DS-K1T341AMF-S`; this is the demo's own model, never that.
DEMO_MODEL = "DS-K1T341DEMO-S"
DEMO_SERIAL = "DEMO-SERIAL-001"
DEMO_FIRMWARE = "V3.2.30DEMO"
#: Protocol enum (like `userType: "normal"`), faithful to the capture's vocabulary.
DEMO_DEVICE_TYPE = "ACS"
DEMO_DEVICE_NAME = "DEMO-CONTROLLER-1"
#: Locally-administered (02:..) — cannot be a real NIC, and is not the capture's mac.
DEMO_MAC_ADDRESS = "02:DE:AD:BE:EF:01"

#: The placeholder credential pair (same policy as tests/test_repo_hygiene.py PLACEHOLDER:
#: recognisably fake). The CLI prints these so `gateclerk --host 127.0.0.1 ...` just works.
DEMO_DEFAULT_USER = "admin"
DEMO_DEFAULT_PASSWORD = "fake" + "pw"  # assembled: authoring tooling redacts this shape

_DEMO_PEOPLE: tuple[tuple[str, str], ...] = (
    ("Demo Popescu", "D001"),
    ("Demoana Ionescu", "D002"),
    ("Demo Georgescu", "D003"),
    ("Demoana Dumitrescu", "D004"),
    ("Demo Stan", "D005"),
)

DEMO_USER_COUNT = len(_DEMO_PEOPLE)

#: The advertised page cap both recorded sites clamp to (acs_capabilities @max=30).
DEMO_MAX_RESULTS_CAP = 30
#: 46 events = cap (30) + short last page (16): a two-page walk with a MORE/OK
#: boundary is the smallest corpus that exercises the pagination contract.
DEMO_EVENT_COUNT = 46
DEMO_FIRST_SERIAL = 1001

#: The RFC 5737 documentation ranges this repo may use as a device host (the same list
#: tests/test_repo_hygiene.py allows). The bind host is loopback; this is the address the
#: `urls` command suggests writing into a site config for a LAN-visible demo of the OTHER
#: machine reading this box — never bound to.
DEMO_BIND_HOST = "127.0.0.1"
DEMO_DOCUMENT_HOST = "192.0.2.10"
_SYNTHETIC_NETS = tuple(
    ipaddress.ip_network(net) for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)

#: Identity strings the demo corpus puts on the wire — the needles ARM B scans against
#: `docs/OBSERVED*.md`. Identity-shaped on purpose (long, non-numeric): caps and enum
#: vocabulary legitimately appear in both corpora, names/serials/cards never may.
SYNTHETIC_FIXTURE_STRINGS: tuple[str, ...] = (
    DEMO_MODEL,
    DEMO_SERIAL,
    DEMO_FIRMWARE,
    DEMO_DEVICE_NAME,
    "DEMO-SERIAL",
    "DEMO-CARD",
    *(name for name, _ in _DEMO_PEOPLE),
)


def demo_user_names() -> list[str]:
    """The demo roster's person names, in employee order (all obviously-demo)."""
    return [name for name, _ in _DEMO_PEOPLE]


def demo_employee_nos() -> list[str]:
    """Synthetic employee numbers (`D###`) — never the capture's `"1".."4"`/`"90"`."""
    return [emp for _, emp in _DEMO_PEOPLE]


def demo_card_numbers() -> list[str]:
    """Self-labelling card numbers, one per enrollee (1..20-char strings, per caps)."""
    return [f"DEMO-CARD-{i:06d}" for i in range(1, DEMO_USER_COUNT + 1)]


def demo_answered_values(key: str | None = None) -> set[str]:
    """The identity values the demo corpus puts on the wire.

    `key` narrows to one ISAPI field the way ARM B's reverse scan reads the captures
    (`"serialNumber"`, `"name"`, `"cardNo"`); with no key it is the whole identity set.
    The reverse synthetic-proof test intersects this with every value the captures
    store under those keys — the intersection must be empty in both directions.
    """
    if key == "serialNumber":
        return {DEMO_SERIAL}
    if key == "name":
        return set(demo_user_names())
    if key == "cardNo":
        return set(demo_card_numbers())
    return set(demo_user_names()) | set(demo_card_numbers()) | {DEMO_SERIAL, DEMO_DEVICE_NAME}


def demo_answered_addresses() -> tuple[str, ...]:
    """Every address the demo puts on the wire: the bind host and the documented host."""
    return (DEMO_BIND_HOST, DEMO_DOCUMENT_HOST)


def is_synthetic_address(value: str) -> bool:
    """True for loopback and RFC 5737 documentation addresses only (the SYNTHETIC law)."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_loopback or any(ip in net for net in _SYNTHETIC_NETS)


def is_synthetic_serial(value: str) -> bool:
    """True only for the self-labelling `DEMO-SERIAL-*` shape."""
    return value.startswith("DEMO-SERIAL-")


def is_loopback_bind_host(host: str) -> bool:
    """Whether `--host` may be bound (the CLI's loopback-only rule)."""
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.version == 4 and ip.is_loopback


# --- the synthetic event corpus -------------------------------------------------------------

#: The box's claimed clock as a tzinfo: +02:00 year-round (the site-a bug, reproduced
#: on purpose so the product's tz-mismatch warning is demonstrable offline).
_DEMO_CLAIMED_TZ = timezone(timedelta(minutes=DEMO_CLAIMED_OFFSET_MIN))
#: The demo day, in the box's OWN wall digits (stamped with the claimed offset, like
#: every capture row): 2026-06-15 morning, the shape of the recorded dense day.
_DEMO_DAY = datetime(2026, 6, 15, 8, 0, 0, tzinfo=_DEMO_CLAIMED_TZ)
_DEMO_DAY_LABEL = "+02:00"  # == DEMO_CLAIMED_OFFSET_MIN, spelled the wire way
_DEMO_TZ_RULE = "CST-2:00:00DST01:00:00,M3.4.1/00:00:00,M10.5.0/23:00:00"
_DEMO_LOCAL_TIME = "2026-06-15T18:05:00+02:00"

# (major, minor) cycle mirroring the capture's dense day: grant, grant, door-open,
# door-close (minor 75/21/22 from OBSERVED.md's major=5 event mix).
_GRANT_CYCLE: tuple[int, ...] = (75, 75, 21, 22)


def demo_events() -> list[dict[str, Any]]:
    """The full synthetic event corpus, oldest-first, deterministic by construction.

    Serials are `DEMO_FIRST_SERIAL .. DEMO_FIRST_SERIAL + DEMO_EVENT_COUNT - 1` with no
    gaps (the card's "deterministic or advanceable event serials" — a second call must
    return the identical corpus), and the wall digits sit inside the demo day's 08:00
    window so a full-day search matches every row. Granted rows carry the identity keys
    the capture records (name/employeeNoString/cardType/...); door open/close rows
    carry the capture's sparse shape (no name — the box logs no person there).
    """
    names = demo_user_names()
    employees = demo_employee_nos()
    events: list[dict[str, Any]] = []
    for i in range(DEMO_EVENT_COUNT):
        minor = _GRANT_CYCLE[i % len(_GRANT_CYCLE)]
        wall = _DEMO_DAY + timedelta(seconds=10 * i)
        # Bare wall DIGITS + the claimed label (the capture's stamp shape: every row
        # carries the same claimed offset). `wall` carries a tzinfo only to satisfy
        # DTZ; the wire string is digits+label exactly like the device's rows.
        stamp = f"{wall.replace(tzinfo=None).isoformat()}{_DEMO_DAY_LABEL}"
        row: dict[str, Any] = {
            "major": 5,
            "minor": minor,
            "time": stamp,
            "doorNo": 1,
            "type": 0,
            "serialNo": DEMO_FIRST_SERIAL + i,
        }
        if minor == 75:
            person = i // 2
            row.update(
                {
                    "cardType": 1,
                    "name": names[person % len(names)],
                    "cardReaderNo": 1,
                    "employeeNoString": employees[person % len(employees)],
                    "userType": "normal",
                    "currentVerifyMode": "cardOrFaceOrFp",
                    "mask": "no",
                }
            )
        else:
            row["currentVerifyMode"] = "invalid"
        events.append(row)
    return events


def _user_rows() -> list[dict[str, Any]]:
    """Roster rows with the recorded UserInfo shape (OBSERVED.md / user_search fixture)."""
    rows: list[dict[str, Any]] = []
    for name, emp in _DEMO_PEOPLE:
        rows.append(
            {
                "employeeNo": emp,
                "name": name,
                "userType": "normal",
                "closeDelayEnabled": False,
                "Valid": {
                    "enable": True,
                    "beginTime": "2000-01-01T00:00:00",
                    "endTime": "2037-12-31T23:59:59",
                    "timeType": "local",
                },
                "belongGroup": "",
                "doorRight": "1",
                "RightPlan": [{"doorNo": 1, "planTemplateNo": "1"}],
                "maxOpenDoorTime": 0,
                "openDoorTime": 0,
                "roomNumber": 0,
                "floorNumber": 0,
                "localUIRight": False,
                "gender": "unknown",
                "numOfCard": 0,
                "numOfFP": 0,
                "numOfFace": 1,
                "PersonInfoExtends": [{"value": ""}],
            }
        )
    return rows


def _device_info_xml() -> bytes:
    """`System/deviceInfo` as XML despite `?format=json` (OBSERVED.md delta 1).

    `parse_body` strips the root, so the client sees the flat fields — which is exactly
    what `capabilities.device_identity` reads on a real device.
    """
    fields = "".join(
        f"<{key}>{value}</{key}>"
        for key, value in (
            ("deviceName", DEMO_DEVICE_NAME),
            ("deviceID", "255"),
            ("model", DEMO_MODEL),
            ("serialNumber", DEMO_SERIAL),
            ("macAddress", DEMO_MAC_ADDRESS),
            ("firmwareVersion", DEMO_FIRMWARE),
            ("firmwareReleasedDate", "build 000000"),
            ("encoderVersion", "V1.0"),
            ("encoderReleasedDate", "build 000000"),
            ("deviceType", DEMO_DEVICE_TYPE),
            ("telecontrolID", "1"),
            ("supportBeep", "false"),
            ("localZoneNum", "0"),
            ("alarmOutNum", "0"),
            ("electroLockNum", "1"),
            ("RS485Num", "1"),
            ("marketType", "2"),
        )
    )
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<DeviceInfo version="2.0" xmlns="http://www.isapi.org/ver20/XMLSchema">\n'
        f"{fields}\n"
        "</DeviceInfo>"
    )
    return xml.encode("utf-8")


def _system_time_xml() -> bytes:
    """`System/time`: Manual mode, the claimed-offset stamp, the recorded tz rule shape."""
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Time version="2.0" xmlns="http://www.isapi.org/ver20/XMLSchema">\n'
        "<timeMode>Manual</timeMode>\n"
        f"<localTime>{_DEMO_LOCAL_TIME}</localTime>\n"
        f"<timeZone>{_DEMO_TZ_RULE}</timeZone>\n"
        "</Time>"
    )
    return xml.encode("utf-8")


def _acs_event_capabilities() -> dict[str, Any]:
    """The caps document p1-04 reads to learn the cap — shape faithful, values scoped
    to what the demo corpus actually emits (the full minor sets are protocol facts the
    demo does not need to recite; the test pins `maxResults.@max`)."""
    return {
        "AcsEvent": {
            "AcsEventCond": {
                "searchID": {"@min": 1, "@max": 64},
                "searchResultPosition": {"@min": 0, "@max": 150000},
                "maxResults": {"@min": 1, "@max": DEMO_MAX_RESULTS_CAP},
                "major": {"@opt": "0,1,2,3,5"},
                "minorEvent": {"@opt": "21,22,75"},
                "startTime": {"@min": 1, "@max": 32},
                "endTime": {"@min": 1, "@max": 32},
                "timeReverseOrder": {"@opt": "true,false"},
            }
        }
    }


# --- the recorded rejection shapes ----------------------------------------------------------


def _not_support_envelope() -> dict[str, Any]:
    """`400 notSupport` as recorded for `AcsEvent/Total` (error_total_notsupport.json):
    statusCode 4, errorCode 1073741825, and the firmware's own `unknow` typo."""
    return {
        "statusCode": 4,
        "statusString": "Invalid Operation",
        "subStatusCode": "notSupport",
        "errorCode": 1073741825,
        "errorMsg": "unknow",
    }


def _bad_json_envelope(field: str) -> dict[str, Any]:
    """`badJsonContent` for one named field (error_naive_start_time.json): the device's
    answer to a naive OR fractional-second window bound (OBSERVED 2026-10-17/21)."""
    return {
        "statusCode": 6,
        "statusString": "Invalid Content",
        "subStatusCode": "badJsonContent",
        "errorMsg": field,
    }


#: A legal event bound: whole seconds + explicit offset (`Z` or `±HH:MM`). Anything
#: this refuses — naive, fractional, missing — is the `badJsonContent` shape.
_BOUND_RE = re.compile(
    r"^(?P<digits>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?P<label>[Zz]|[+-]\d{2}:\d{2})$"
)


def _rejectable_bound_field(cond: Mapping[str, Any]) -> str | None:
    """The first window bound the device would 400 on (`startTime` before `endTime`)."""
    for field in ("startTime", "endTime"):
        value = cond.get(field)
        if not isinstance(value, str) or _BOUND_RE.match(value) is None:
            return field
    return None


def _bound_to_device_wall(value: str, field: str) -> datetime:
    """One posted bound -> the device-wall instant, with the DEVICE's arithmetic.

    Digits D labeled L name the instant D-L; the box reads that instant back on its OWN
    claimed clock, so the effective wall bound is D + claimed - L (OBSERVED.md "Window
    offsets are ARITHMETIC", the p1-05c A/B). Same rule `tests/fakedevice.py` enforces.
    """
    match = _BOUND_RE.match(value)
    if match is None:  # defensive: callers run the reject check first
        raise ValueError(f"{field} passed the window-bound reject check; cannot reach here")
    digits = datetime.fromisoformat(match.group("digits"))
    label = match.group("label")
    if label in ("Z", "z"):
        label_min = 0
    else:
        sign = 1 if label[0] == "+" else -1
        hours, minutes = label[1:].split(":")
        label_min = sign * (int(hours) * 60 + int(minutes))
    return digits + timedelta(minutes=DEMO_CLAIMED_OFFSET_MIN - label_min)


# --- digest (RFC 2617 qop="auth", computed the way the device computes it) ------------------

_AUTH_RE = re.compile(r'(\w+)=(?:"([^"]*)"|([^",]+))')


def _parse_authorization(header: str) -> dict[str, str]:
    if not header.lower().startswith("digest "):
        return {}
    out: dict[str, str] = {}
    for match in _AUTH_RE.finditer(header[len("Digest ") :]):
        key = match.group(1).lower()
        out[key] = match.group(2) if match.group(2) is not None else (match.group(3) or "")
    return out


def _md5(data: str) -> str:
    # MD5 is mandated by RFC 2617 digest (the device computes it this way); this is
    # protocol conformance, not a security decision — hence usedforsecurity=False.
    return hashlib.md5(data.encode("utf-8"), usedforsecurity=False).hexdigest()


def _expected_digest_response(
    username: str, password: str, *, method: str, target: str, fields: Mapping[str, str]
) -> str:
    """The qop=auth `response` the SERVER computes — over the request-target it actually
    received (`method`+`target`, which carries `?format=json`), never the `uri=` the
    client claims (gotchas §1.4: trusting the claim is the infinite-401-loop blind spot).
    """
    ha1 = _md5(f"{username}:{DEMO_REALM}:{password}")
    ha2 = _md5(f"{method}:{target}")
    return _md5(
        ":".join(
            [
                ha1,
                fields.get("nonce", ""),
                fields.get("nc", ""),
                fields.get("cnonce", ""),
                fields.get("qop", "auth"),
                ha2,
            ]
        )
    )


# --- the server -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RequestedCall:
    """One request the box saw (server-side proof of the read-only surface)."""

    method: str
    #: request-target as received, INCLUDING the `?format=json` query — so a test can
    #: compare it against `Endpoint.url_path` without re-deriving the suffix.
    path: str
    authenticated: bool


class _DemoHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, host: str, port: int, box: DemoDevice) -> None:
        super().__init__((host, port), _DemoHandler)
        self.box = box


class _DemoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = DEMO_SERVER_HEADER
    sys_version = ""

    server: _DemoHTTPServer  # type: ignore[assignment]  # narrowed by _DemoHTTPServer

    # -- plumbing ------------------------------------------------------------------

    def version_string(self) -> str:
        return DEMO_SERVER_HEADER

    def log_message(self, format: str, *args: object) -> None:
        # (stdlib signature; the base names this parameter `format`.) The demo must not
        # spam the developer's terminal with per-request wire logs.
        return

    def do_GET(self) -> None:
        self._serve("GET")

    def do_POST(self) -> None:
        self._serve("POST")

    # -- the one request pipeline: auth first, routes second (like `webs`) ----------

    def _serve(self, method: str) -> None:
        target = self.path  # request-target as received, query included
        path = target.partition("?")[0]
        # Drain the body BEFORE any verdict, including the 401: under HTTP/1.1
        # keep-alive an unread request body would sit in the socket and be parsed as
        # the NEXT request (the classic embedded-server desync).
        body = self._read_body()
        fields = _parse_authorization(self.headers.get("Authorization", ""))
        authenticated = self._digest_ok(method, target, fields)
        self.server.box.record(method, target, authenticated)
        if not authenticated:
            self._send_challenge()
            return
        status, content_type, payload = self._route(method, path, body)
        self._send(status, payload, content_type)

    def _digest_ok(self, method: str, target: str, fields: Mapping[str, str]) -> bool:
        if not fields:
            return False
        box = self.server.box
        if fields.get("username") != box.username:
            return False
        if fields.get("realm") != DEMO_REALM or fields.get("qop") != "auth":
            return False
        if fields.get("nonce") not in box.accepted_nonces():
            return False
        return fields.get("response") == _expected_digest_response(
            box.username, box.password, method=method, target=target, fields=fields
        )

    def _read_body(self) -> bytes:
        length = self.headers.get("Content-Length")
        return self.rfile.read(int(length)) if length else b""

    # -- routing -------------------------------------------------------------------

    def _route(self, method: str, path: str, body: bytes) -> tuple[int, str, bytes]:
        xml = "application/xml"
        js = "application/json"
        if method == "GET" and path == "/ISAPI/System/deviceInfo":
            return 200, xml, _device_info_xml()
        if method == "GET" and path == "/ISAPI/System/time":
            return 200, xml, _system_time_xml()
        if method == "GET" and path == "/ISAPI/AccessControl/AcsEvent/capabilities":
            return 200, js, _json_bytes(_acs_event_capabilities())
        if method == "GET" and path == "/ISAPI/AccessControl/UserInfo/Count":
            return 200, js, _json_bytes({"UserInfoCount": {"userNumber": DEMO_USER_COUNT}})
        if method == "POST" and path == "/ISAPI/AccessControl/UserInfo/Search":
            return self._search(
                body, "UserInfoSearchCond", "UserInfoSearch", "UserInfo", _user_rows()
            )
        if method == "POST" and path == "/ISAPI/AccessControl/AcsEvent":
            return self._event_search(body)
        if method == "POST" and path == "/ISAPI/AccessControl/AcsEventTotalNum":
            return self._event_total_num(body)
        if method == "POST" and path == "/ISAPI/AccessControl/CardInfo/Search":
            # The RECORDED bench-A answer (endpoints.py: "bench A answered NO MATCH —
            # 0 cards"). The roster carrying card numbers while this search says zero is
            # the device quirk as recorded, reproduced rather than tidied away.
            return 200, js, _json_bytes(_search_envelope("NO MATCH", "", "CardInfo", []))
        # Everything else is the RECORDED unregistered-path answer (`AcsEvent/Total`
        # 400 notSupport, error_total_notsupport.json) — the firmware's own lesson for a
        # developer exploring paths the registry never registered.
        return 400, js, _json_bytes(_not_support_envelope())

    def _search(
        self,
        body: bytes,
        cond_key: str,
        envelope_key: str,
        record_key: str,
        matched: list[dict[str, Any]],
    ) -> tuple[int, str, bytes]:
        payload = _json_request(body)
        cond = payload.get(cond_key) if isinstance(payload, dict) else None
        if not isinstance(cond, dict):
            return 400, "application/json", _json_bytes(_bad_json_envelope(cond_key))
        return (
            200,
            "application/json",
            _json_bytes(_paged_envelope(cond, envelope_key, record_key, matched)),
        )

    def _windowed(
        self, body: bytes, cond_key: str
    ) -> tuple[list[dict[str, Any]], Mapping[str, Any]] | tuple[None, None]:
        """Shared event leg: auth-clean body -> (windowed rows, cond), or the rejection."""
        payload = _json_request(body)
        cond = payload.get(cond_key) if isinstance(payload, dict) else None
        if not isinstance(cond, dict):
            return None, None
        bad = _rejectable_bound_field(cond)
        if bad is not None:
            return None, None
        start = _bound_to_device_wall(str(cond["startTime"]), "startTime")
        end = _bound_to_device_wall(str(cond["endTime"]), "endTime")
        rows = [
            row
            for row in demo_events()
            if start
            <= datetime.fromisoformat(str(row["time"]).removesuffix(_DEMO_DAY_LABEL))
            <= end
        ]
        return rows, cond

    def _event_search(self, body: bytes) -> tuple[int, str, bytes]:
        rows, cond = self._windowed(body, "AcsEventCond")
        if cond is None or rows is None:
            return (
                400,
                "application/json",
                _json_bytes(_bad_json_envelope(_rejection_field(body))),
            )
        return (
            200,
            "application/json",
            _json_bytes(_paged_envelope(cond, "AcsEvent", "InfoList", rows)),
        )

    def _event_total_num(self, body: bytes) -> tuple[int, str, bytes]:
        rows, _cond = self._windowed(body, "AcsEventTotalNumCond")
        if rows is None:
            return (
                400,
                "application/json",
                _json_bytes(_bad_json_envelope(_rejection_field(body, "AcsEventTotalNumCond"))),
            )
        return 200, "application/json", _json_bytes({"AcsEventTotalNum": {"totalNum": len(rows)}})

    # -- the two answers every request becomes --------------------------------------

    def _send_challenge(self) -> None:
        box = self.server.box
        nonce = box.issue_nonce()
        self._send(
            401,
            (
                b"<userCheck><statusValue>401</statusValue>"
                b"<statusString>Unauthorized</statusString>"
                b"<lockStatus>unlock</lockStatus><unlockTime>0</unlockTime>"
                b"<retryLoginTime>6</retryLoginTime></userCheck>"
            ),
            "application/xml",
            extra_headers={
                "WWW-Authenticate": (
                    f'Digest qop="auth", realm="{DEMO_REALM}", nonce="{nonce}", '
                    f'stale="false", domain="::"'
                )
            },
        )

    def _send(
        self,
        status: int,
        payload: bytes,
        content_type: str,
        *,
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)


def _json_request(body: bytes) -> Any:
    if not body:
        return {}
    try:
        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _rejection_field(body: bytes, cond_key: str = "AcsEventCond") -> str:
    """Which field the 400 names: the first bound the device would reject, else the cond."""
    payload = _json_request(body)
    cond = payload.get(cond_key) if isinstance(payload, dict) else None
    if isinstance(cond, Mapping):
        return _rejectable_bound_field(cond) or cond_key
    return cond_key


def _json_bytes(payload: object) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _search_envelope(
    status: str,
    search_id: str,
    record_key: str,
    rows: list[dict[str, Any]],
    total: int | None = None,
) -> dict[str, Any]:
    """Wrapped search envelope with the RECORDED empty shape: NO MATCH (the space!)
    and the record key ABSENT, never `[]` (OBSERVED.md, events_no_match.json).

    `numOfMatches` counts THIS page; `totalMatches` counts the whole match set when
    `total` is given (the paging contract both recorded sites show: site-B's
    `numOfMatches:30` / `totalMatches:38`) — which is why the walker advances by
    `numOfMatches`, never by the requested page size.
    """
    envelope: dict[str, Any] = {
        "searchID": search_id,
        "responseStatusStrg": status,
        "numOfMatches": len(rows),
        "totalMatches": len(rows) if total is None else total,
    }
    if rows:
        envelope[record_key] = rows
    return envelope


def _paged_envelope(
    cond: Mapping[str, Any], envelope_key: str, record_key: str, matched: list[dict[str, Any]]
) -> dict[str, Any]:
    """The device's own paging semantics (both recorded sites): `maxResults` is
    clamped to the advertised cap SILENTLY — no error, no echo of the reduced cap
    (OBSERVED-site-B "Silent maxResults clamp"); a truncated page says MORE, never a
    complete-looking OK; the last page says OK; an exhausted window says NO MATCH with
    the record key absent. `numOfMatches` counts THIS page, `totalMatches` the set —
    which is exactly why the walker advances by `numOfMatches` (paging.py)."""
    search_id = str(cond.get("searchID") or "")
    try:
        position = max(0, int(cond.get("searchResultPosition") or 0))
    except (TypeError, ValueError):
        position = 0
    raw_max = cond.get("maxResults")
    if raw_max is None:
        # No documented device default for an absent maxResults; the established fake
        # answers the whole match set (fakedevice._paged_search_envelope), and the
        # client engine always sends one anyway (paging.PagedSearch owns the cursor).
        limit = len(matched)
    else:
        try:
            limit = min(max(0, int(raw_max)), DEMO_MAX_RESULTS_CAP)
        except (TypeError, ValueError):
            limit = len(matched)
    window = matched[position : position + limit]
    if not window:
        return {envelope_key: _search_envelope("NO MATCH", search_id, record_key, [])}
    status = "MORE" if position + len(window) < len(matched) else "OK"
    return {
        envelope_key: _search_envelope(status, search_id, record_key, list(window), len(matched))
    }


# --- the serve surface ------------------------------------------------------------------------

_served_lock = threading.Lock()
_last_served_url: str | None = None


def report_served_url(url: str) -> None:
    """Record the URL the most recent `serve` bound (the CLI test reads it back).

    Only the CLI's serve path calls this — a `DemoDevice` started directly by a test
    does NOT pollute it, so a reader can never mistake a fixture box for the served one.
    """
    global _last_served_url
    with _served_lock:
        _last_served_url = url


def last_served_url() -> str | None:
    with _served_lock:
        return _last_served_url


class DemoDevice:
    """A live fake device on loopback. `start()`, talk ISAPI to it, `stop()`.

    Bind is loopback by default and ephemeral by default (port 0), so two runs on one
    laptop never collide and nothing is ever exposed to a LAN. Digest state is per-box:
    nonces it issued are the only nonces it pays, and a wrong password 401s forever,
    like the door terminal (which is the difference between teaching digest and
    pretending to).
    """

    _nonce_cap: ClassVar[int] = 4096  # memory bound, not a device claim

    def __init__(
        self,
        *,
        username: str = DEMO_DEFAULT_USER,
        password: str = DEMO_DEFAULT_PASSWORD,
        host: str = DEMO_BIND_HOST,
        port: int = 0,
    ) -> None:
        if not is_loopback_bind_host(host):
            raise ValueError(
                f"the demo device binds loopback only (SYNTHETIC-ONLY LAW); got {host!r}"
            )
        self.username = username
        self.password = password
        self.host = host
        self.port = port
        self.requests: list[RequestedCall] = []
        self._nonces: set[str] = set()
        self._nonce_lock = threading.Lock()
        self._server: _DemoHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._stopped = threading.Event()

    # -- lifecycle -------------------------------------------------------------------

    def start(self) -> DemoDevice:
        if self._server is not None:
            raise RuntimeError("demo device already started")
        server = _DemoHTTPServer(self.host, self.port, self)
        bound_host, bound_port = server.server_address[0], server.server_address[1]
        self.host, self.port = str(bound_host), int(bound_port)
        self._server = server
        self._thread = threading.Thread(
            target=server.serve_forever, name="gateclerk-demo-device", daemon=True
        )
        self._stopped.clear()
        self._thread.start()
        return self

    def stop(self) -> None:
        server, thread = self._server, self._thread
        self._server = self._thread = None
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=5.0)
        self._stopped.set()

    def wait(self, seconds: float | None = None) -> None:
        """Block until stopped (or `seconds` elapse). The CLI's serve loop is this."""
        self._stopped.wait(seconds)

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    # -- handler-facing state ----------------------------------------------------------

    def record(self, method: str, path: str, authenticated: bool) -> None:
        self.requests.append(RequestedCall(method, path, authenticated))

    def issue_nonce(self) -> str:
        nonce = secrets.token_hex(16)
        with self._nonce_lock:
            if len(self._nonces) >= self._nonce_cap:
                self._nonces.clear()
            self._nonces.add(nonce)
        return nonce

    def accepted_nonces(self) -> frozenset[str]:
        with self._nonce_lock:
            return frozenset(self._nonces)


# Endpoint URLs the `urls` command prints — the three calls the product makes first.
_DEMO_SHOWCASE_ENDPOINTS = ("device_info", "user_info_search", "acs_event_search")


def demo_endpoint_urls(base_url: str) -> list[tuple[str, str]]:
    """(name, full URL) for the showcase endpoints, straight from the registry —
    `urls` cannot drift from `endpoints.REGISTRY` because it reads it."""
    return [(name, f"{base_url}{REGISTRY[name].url_path}") for name in _DEMO_SHOWCASE_ENDPOINTS]
