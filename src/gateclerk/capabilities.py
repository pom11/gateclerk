"""Capability discovery: what THIS device advertises, so we never guess (card p1-04).

docs/DESIGN.md ("Why we read /capabilities instead of hardcoding event codes") is the
contract: Hikvision minor/major codes are model- and firmware-dependent, the community
tables disagree with each other, and the device itself tells us the truth via

    GET /ISAPI/AccessControl/AcsEvent/capabilities?format=json
    GET /ISAPI/AccessControl/capabilities

This module parses those responses into `DeviceCapabilities` (page-size clamp, searchID
limit, supported major set, per-major minor sets, eventAttribute support), and caches
the result in-process per `(serial, firmwareVersion)` — a firmware upgrade can change
the whole table, so firmware is part of the cache key (DESIGN.md capability-cache seam).

Device truth (docs/OBSERVED.md, site-a DS-K1T341AMF-S fw V3.2.30): `maxResults @max=30`,
`searchID @max=64`, `major @opt=0,1,2,3,5`, full minorEvent/minorAlarm/minorException/
minorOperation sets, and **no `eventAttribute` capability** — which is why filters stay
client-side (OBSERVED.md "Server-side filter truth").

What the capabilities do NOT decide: names. Naming lives in `gateclerk.event_codes`
(curated table). The capability decides what is *queryable* — a code we can ask the box
for; curation only says what a code *means*. Two deliberate separations follow from that:

* a code the device does not advertise is still classified and kept (never dropped),
  just flagged `not_advertised`;
* the `currentVerifyMode @opt` list is stored as data but never gates the punch rule —
  site-a emits `cardOrFaceOrFp`, which its own capability list does not enumerate
  (OBSERVED.md), so gating on it would drop every real pass.

Formats: the recorded capability body is JSON on this firmware, but the same `webs`
server answers `System/*` as XML *despite* `?format=json` (OBSERVED.md endpoint table),
so the parser takes JSON and XML alike. The XML capability shape was never observed on
site-a — the fallback accepts both ISAPI XML idioms (attributes `max="30"` and child
nodes `<max>30</max>`) rather than betting on one; see tests/fixtures/synthetic/.

Nothing here opens a socket: `discover()` receives an `IsapiClient` (p1-03), which every
test satisfies with `FakeDevice`.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Any
from xml.etree import ElementTree as ET

from gateclerk.exceptions import GateClerkError, IsapiError, IsapiNotFound
from gateclerk.isapi_response import parse_body, parse_isapi_xml, strip_ns

__all__ = [
    "DEFAULT_MAX_RESULTS",
    "DEFAULT_SEARCH_ID_MAX",
    "CapabilityCache",
    "CapabilityDiscoveryError",
    "DeviceCapabilities",
    "capability_cache",
    "device_identity",
    "discover",
    "parse_access_control_capabilities",
    "parse_acs_event_capabilities",
    "xml_capabilities_to_dict",
]

#: Floor used when a device gives no `maxResults @max` (DESIGN.md: "we clamp to the
#: advertised max and never assume" — with nothing advertised, the smallest cap ever
#: reported for this family (10, docs/references/acs-event-codes.md §1.5) is the only
#: request size that cannot fail).
DEFAULT_MAX_RESULTS = 10

#: Sibling models reject searchID longer than 20 with `badParameters` (references §1.2);
#: site-a tolerates 64. When unadvertised, keep the safe-common rule: <= 20.
DEFAULT_SEARCH_ID_MAX = 20

#: Which capability field lists the minors for each major (references §1.1 + the
#: recorded capability fixture: minorAlarm/minorException/minorOperation/minorEvent map
#: 1:1 onto majors 1/2/3/5; major 0 is the "all" filter value, not an event class).
_MINOR_FIELD_BY_MAJOR = {
    1: "minorAlarm",
    2: "minorException",
    3: "minorOperation",
    5: "minorEvent",
}


# --- value coercion ------------------------------------------------------------------
# The capability JSON uses "@min"/"@max"/"@opt" keys (recorded fixture); XML-ified
# bodies lose the @ (and carry strings). Coerce, never guess: an unparseable value is
# `None`, and `None` means "the device did not tell us", which selects a conservative
# default instead of a plausible-looking number.


def _as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def _as_opt_ints(value: Any) -> frozenset[int]:
    """`"1,6,7"` or `["1","6",7]` -> {1,6,7}. Unparseable members are skipped, loudly
    counted, never silently dropped (a truncated set would hide queryable codes)."""
    items: list[Any]
    if value is None:
        return frozenset()
    if isinstance(value, str):
        items = value.split(",")
    elif isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
    else:
        items = [value]
    out: list[int] = []
    for item in items:
        text = str(item).strip()
        if not text:
            continue
        parsed = _as_int(text)
        if parsed is not None:
            out.append(parsed)
    return frozenset(out)


def _as_opt_strs(value: Any) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, str):
        parts = value.split(",")
    elif isinstance(value, (list, tuple, set, frozenset)):
        parts = [str(v) for v in value]
    else:
        parts = [str(value)]
    return frozenset(p.strip() for p in parts if p.strip())


def _field_table(fields: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    """The `{min,max,opt}` table for one field, tolerating the @-prefixed JSON spelling."""
    raw = fields.get(name)
    if isinstance(raw, Mapping):
        return raw
    return {}


def _limit(fields: Mapping[str, Any], name: str, key: str) -> int | None:
    table = _field_table(fields, name)
    return _as_int(table.get(f"@{key}", table.get(key)))


def _opt(fields: Mapping[str, Any], name: str) -> Any:
    table = _field_table(fields, name)
    return table.get("@opt", table.get("opt"))


# --- XML normalisation ---------------------------------------------------------------


def _xml_field_to_table(node: ET.Element) -> dict[str, Any]:
    """One ISAPI capability field -> the JSON shape's dict, from attributes OR children.

    ISAPI capability XML appears in the wild in two idioms — `<maxResults max="30"/>`
    and `<maxResults><max>30</max></maxResults>` — and the XML capability shape was
    never actually observed on site-a (this endpoint answers JSON there). Refusing
    either idiom means the fallback fails exactly when it is needed, so both are read.

    Only limit/opt child tags (`min`/`max`/`opt`/…) collapse into `@` entries; any other
    child is a *nested field* (e.g. `<InfoList maxSize="30"><time>…</time></InfoList>`)
    and recurses, so a group element carrying one attribute never swallows its children
    as attribute text.
    """
    table: dict[str, Any] = {}
    for attr, value in node.attrib.items():
        table[f"@{strip_ns(attr)}"] = value
    for child in node:
        key = strip_ns(child.tag)
        if key in _LIMIT_CHILD_TAGS:
            table[f"@{key}"] = (child.text or "").strip() or None
        else:
            table[key] = (
                _xml_field_to_table(child)
                if (len(child) or child.attrib)
                else ((child.text or "").strip() or None)
            )
    return table


#: Child element names ISAPI uses to spell a limit as a node instead of an attribute.
_LIMIT_CHILD_TAGS = frozenset({"min", "max", "opt", "minLength", "maxLength", "items"})


def _is_field_element(node: ET.Element) -> bool:
    """A capability *field* element: carries limits as attributes or as min/max/opt kids."""
    if node.attrib:
        return True
    return any(strip_ns(child.tag) in _LIMIT_CHILD_TAGS for child in node)


def xml_capabilities_to_dict(root: ET.Element) -> dict[str, Any]:
    """Normalise a capability XML tree into the same nested-dict shape as the JSON body.

    Each capability field element becomes a `{@min,@max,@opt}` table; anything deeper is
    walked recursively so `AcsEventCond`/`InfoList` groupings survive. Leaves (plain text
    nodes that are not one of the limit/opt idioms) become their text.
    """
    out: dict[str, Any] = {}
    for child in root:
        key = strip_ns(child.tag)
        if _is_field_element(child):
            out[key] = _xml_field_to_table(child)
        elif len(child):
            out[key] = xml_capabilities_to_dict(child)
        else:
            out[key] = (child.text or "").strip() or None
    return out


# --- the parsed view -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DeviceCapabilities:
    """What one device (one firmware) advertised about AcsEvent querying.

    `raw` is the untouched parsed body — the `gateclerk device capabilities --json` dump
    (and eventually the OBSERVED.md evidence trail) is this dict, not our summary of it.
    Every derived number below is `None` when the device did not say, and `None` selects
    the conservative default at the clamp call sites, never a guess.
    """

    raw: Mapping[str, Any] = field(default_factory=dict)
    max_results: int | None = None
    max_results_min: int | None = None
    search_id_max: int | None = None
    search_id_min: int | None = None
    majors: frozenset[int] = frozenset()
    #: major -> advertised minor codes (1:alarm, 2:exception, 3:operation, 5:event)
    minors: Mapping[int, frozenset[int]] = field(default_factory=dict)
    #: raw `@opt` strings, kept verbatim for the raw-dump summary
    minor_options_raw: Mapping[str, str] = field(default_factory=dict)
    info_list_max_size: int | None = None
    #: `attendance` / `other` when the fw advertises the filter (site-a: NOT present).
    event_attribute_options: frozenset[str] = frozenset()
    #: `currentVerifyMode @opt`, kept as DATA. Never gates the punch rule — site-a
    #: emits `cardOrFaceOrFp`, which its own list omits (OBSERVED.md).
    verify_modes: frozenset[str] = frozenset()
    attendance_statuses: frozenset[str] = frozenset()
    #: raw `/ISAPI/AccessControl/capabilities` body (None when the fw 404s it).
    access_control_raw: Mapping[str, Any] | None = None
    access_control_error: str | None = None
    #: AcsEvent ring capacity from AccessControl caps when advertised (advisory).
    acs_event_capacity: int | None = None
    #: provenance for the cache key + the raw dump header
    serial: str | None = None
    firmware: str | None = None
    model: str | None = None
    #: what the parser had to normalise (e.g. "xml-fallback"), for the dump
    format_note: str | None = None

    # --- clamping -------------------------------------------------------------------

    def clamp_max_results(self, requested: int) -> int:
        """The page size we may actually send. `min(requested, @max)`, floor 1.

        DESIGN.md: oversized `maxResults` is *silently clamped* on some firmware and
        `badParameters` on others — and a silent clamp turns "advance by requested page
        size" into skipped punches. Callers advance by the returned `numOfMatches`
        regardless (p1-05); this only keeps our request legal on every box.
        """
        cap = self.max_results if self.max_results is not None else DEFAULT_MAX_RESULTS
        return max(1, min(int(requested), int(cap)))

    def clamp_search_id(self, search_id: str) -> str:
        """Truncate to the advertised length — never send an id the device may reject.

        Truncation (not rejection) because a too-long id is our own construction, and
        `badParameters` mid-backfill is a worse outcome than a slightly shorter unique id.
        Uniqueness is preserved in practice: the tail of a uuid4 hex is what varies.
        """
        cap = self.search_id_max if self.search_id_max is not None else DEFAULT_SEARCH_ID_MAX
        return search_id[: max(1, int(cap))]

    def make_search_id(self, prefix: str = "gateclerk-") -> str:
        """A fresh searchID for one logical search — the caller keeps it byte-identical
        across that search's pages (references §1.2: changing it mid-walk silently
        restarts page 1)."""
        budget = self.search_id_max if self.search_id_max is not None else DEFAULT_SEARCH_ID_MAX
        head = prefix[: max(0, budget - 8)]
        return self.clamp_search_id(f"{head}{uuid.uuid4().hex}")

    # --- queryability ----------------------------------------------------------------

    def supports_major(self, major: int) -> bool:
        """Whether the device lists this major as queryable. Unknown major set -> True
        (no advertisement = no basis to refuse; the search itself will say)."""
        return major in self.majors if self.majors else True

    def is_advertised(self, major: int, minor: int) -> bool | None:
        """True/False when the device enumerated the set, None when it did not say.

        None is NOT False: firmware that omits the minor lists entirely gives us no
        basis to call a code unqueryable, and treating silence as refusal is how codes
        go missing silently.
        """
        field_name = _MINOR_FIELD_BY_MAJOR.get(major)
        if field_name is None:
            return None
        advertised = self.minors.get(major)
        if advertised is None:
            return None
        return minor in advertised

    @property
    def supports_event_attribute(self) -> bool:
        return bool(self.event_attribute_options)

    # --- serialisation ----------------------------------------------------------------

    def as_dict(self) -> dict[str, Any]:
        """The `gateclerk device capabilities --json` shape: extracted limits + raw dumps.

        Raw bodies first-class: the orchestrator pastes this output into OBSERVED.md, so
        anything the extractor failed to see must still be visible here.
        """
        return {
            "serial": self.serial,
            "model": self.model,
            "firmware": self.firmware,
            "format_note": self.format_note,
            "limits": {
                "max_results": self.max_results,
                "max_results_min": self.max_results_min,
                "search_id_max": self.search_id_max,
                "info_list_max_size": self.info_list_max_size,
                "acs_event_capacity": self.acs_event_capacity,
            },
            "queryable": {
                "majors": sorted(self.majors),
                "minor_alarm": sorted(self.minors.get(1, frozenset())),
                "minor_exception": sorted(self.minors.get(2, frozenset())),
                "minor_operation": sorted(self.minors.get(3, frozenset())),
                "minor_event": sorted(self.minors.get(5, frozenset())),
                "event_attribute_options": sorted(self.event_attribute_options),
                "verify_modes": sorted(self.verify_modes),
                "attendance_statuses": sorted(self.attendance_statuses),
            },
            "raw_acs_event_capabilities": dict(self.raw),
            "raw_access_control_capabilities": (
                None if self.access_control_raw is None else dict(self.access_control_raw)
            ),
            "access_control_error": self.access_control_error,
        }

    def as_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.as_dict(), indent=indent, ensure_ascii=False, default=str)

    def summary_rows(self) -> list[dict[str, Any]]:
        """Rows for the human `table` view — one per advertised aspect."""
        rows: list[dict[str, Any]] = [
            {"capability": "maxResults @max", "value": self.max_results},
            {"capability": "searchID @max", "value": self.search_id_max},
            {"capability": "InfoList maxSize", "value": self.info_list_max_size},
            {"capability": "major @opt", "value": ",".join(str(m) for m in sorted(self.majors))},
            {
                "capability": "eventAttribute",
                "value": (
                    ",".join(sorted(self.event_attribute_options))
                    if self.supports_event_attribute
                    else "NOT advertised (filter client-side)"
                ),
            },
        ]
        for major, label in (
            (1, "minorAlarm"),
            (2, "minorException"),
            (3, "minorOperation"),
            (5, "minorEvent"),
        ):
            advertised = self.minors.get(major)
            rows.append(
                {
                    "capability": label,
                    "value": ",".join(str(m) for m in sorted(advertised)) if advertised else None,
                }
            )
        return rows


# --- parsing ---------------------------------------------------------------------------


def _find_cond_table(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    """Locate the dict that carries `maxResults`/`minorEvent`, wherever the root sits.

    Recorded shape: `{"AcsEvent": {"AcsEventCond": {...}}}`. Other firmwares root the
    same content under `AcsEventCapabilities`/`AccessControlCap` (and the XML fallback
    normalisation keeps whatever root the box used). A bounded depth-3 walk finds the
    cond table under any of those without hardcoding one root name — a hardcoded root is
    a parser that only ever parses the one box we already probed.
    """
    stack: list[tuple[Mapping[str, Any], int]] = [(payload, 0)]
    while stack:
        node, depth = stack.pop()
        if "maxResults" in node and ("minorEvent" in node or "major" in node):
            return node
        if depth >= 3:
            continue
        for value in node.values():
            if isinstance(value, Mapping):
                stack.append((value, depth + 1))
    # Nothing matched: returning the payload itself lets the extractor report every
    # limit as None (and the raw dump show why) instead of raising on a weird root.
    return payload


def _find_info_list(payload: Mapping[str, Any], *, depth: int = 0) -> Mapping[str, Any]:
    """The `InfoList` field table, wherever it sits.

    In the recorded site-a body `InfoList` is a **sibling** of `AcsEventCond` (both under
    `AcsEvent`), while some firmware nests it inside — and `verify_modes` /
    `attendance_statuses` / `maxSize` live there, so looking for it in exactly one place
    silently yields "the device advertised no verify modes" on the other shape. Bounded
    walk, same rule as the cond table.
    """
    if depth > 3:
        return {}
    direct = payload.get("InfoList")
    if isinstance(direct, Mapping):
        return direct
    for value in payload.values():
        if isinstance(value, Mapping):
            found = _find_info_list(value, depth=depth + 1)
            if found:
                return found
    return {}


def _extract(payload: Mapping[str, Any], *, format_note: str | None) -> DeviceCapabilities:
    cond = _find_cond_table(payload)
    info_fields = _find_info_list(payload)

    minors: dict[int, frozenset[int]] = {}
    minor_raw: dict[str, str] = {}
    for major, field_name in _MINOR_FIELD_BY_MAJOR.items():
        opt = _opt(cond, field_name)
        parsed = _as_opt_ints(opt)
        if parsed:
            minors[major] = parsed
            minor_raw[field_name] = (
                opt if isinstance(opt, str) else ",".join(str(v) for v in sorted(parsed))
            )

    return DeviceCapabilities(
        raw=payload,
        max_results=_limit(cond, "maxResults", "max"),
        max_results_min=_limit(cond, "maxResults", "min"),
        search_id_max=_limit(cond, "searchID", "max"),
        search_id_min=_limit(cond, "searchID", "min"),
        majors=_as_opt_ints(_opt(cond, "major")),
        minors=minors,
        minor_options_raw=minor_raw,
        info_list_max_size=_as_int(
            info_fields.get("maxSize", info_fields.get("@maxSize"))
            if isinstance(info_fields, Mapping)
            else None
        ),
        event_attribute_options=_as_opt_strs(_opt(cond, "eventAttribute")),
        verify_modes=_as_opt_strs(_opt(info_fields, "currentVerifyMode")),
        attendance_statuses=_as_opt_strs(_opt(info_fields, "attendanceStatus")),
        format_note=format_note,
    )


def parse_acs_event_capabilities(body: bytes | str) -> DeviceCapabilities:
    """Parse `GET /ISAPI/AccessControl/AcsEvent/capabilities` — JSON or XML.

    The body arrives via the same sniffing rule as every other ISAPI response
    (isapi_response.parse_body: first byte decides, Content-Type lies). A body whose
    first byte is not JSON-shaped comes back through `parse_body` as a *flattened XML
    dict*, which loses attribute-carried limits — so we re-parse XML from the source
    with `xml_capabilities_to_dict`, the one shape-agnostic normalisation.
    """
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    stripped = text.strip()
    if stripped and stripped[0] not in "{[":
        root = parse_isapi_xml(stripped)
        return _extract(xml_capabilities_to_dict(root), format_note="xml-fallback")
    payload = parse_body(stripped)
    return _extract(payload, format_note=None)


def parse_access_control_capabilities(body: bytes | str) -> tuple[Mapping[str, Any], int | None]:
    """Parse `GET /ISAPI/AccessControl/capabilities` -> (raw dict, AcsEvent capacity).

    Advisory only (ring capacity feeds DESIGN.md open question 4, the rolling-event
    question) — a firmware without this endpoint is expected on some models, so the
    caller treats `IsapiNotFound` as data, not failure.

    The capacity is read from the `AcsEvent` group specifically, not from any
    `maxCapacity` in the body: this endpoint enumerates several groups (Face, Card,
    AcsEvent...) each with its own `maxCapacity`, and whichever one a stack walk pops
    first would otherwise decide the number — an event-ring capacity of "3000" when the
    face library is 3000 is exactly the kind of confidently-wrong number we refuse.
    """
    payload = parse_body(body)

    def find_acs_event(node: Mapping[str, Any], depth: int = 0) -> Mapping[str, Any] | None:
        if depth > 3:
            return None
        inner = node.get("AcsEvent")
        if isinstance(inner, Mapping):
            return inner
        for value in node.values():
            if isinstance(value, Mapping):
                found = find_acs_event(value, depth + 1)
                if found is not None:
                    return found
        return None

    group = find_acs_event(payload)
    capacity = _as_int(group.get("maxCapacity")) if group is not None else None
    return payload, capacity


# --- identity ---------------------------------------------------------------------------


def device_identity(body: Mapping[str, Any]) -> tuple[str | None, str | None, str | None]:
    """(serial, firmware, model) from a parsed `System/deviceInfo` body.

    This firmware answers deviceInfo as **XML despite `?format=json`** (OBSERVED.md), so
    the dict arrives already flattened by `parse_body` under a `DeviceInfo` root — the
    walk below covers both the wrapped and (defensively) the flat spelling.
    """
    node: Mapping[str, Any] = body
    for value in body.values():
        if isinstance(value, Mapping) and any(k in value for k in ("serialNumber", "model")):
            node = value
            break
    serial = node.get("serialNumber")
    firmware = node.get("firmwareVersion")
    model = node.get("model")
    return (
        str(serial) if serial else None,
        str(firmware) if firmware else None,
        str(model) if model else None,
    )


# --- discovery + cache ---------------------------------------------------------------------


class CapabilityCache:
    """In-process cache keyed `(serial, firmwareVersion)` (card p1-04).

    Deliberately tiny and explicit: no TTL, no disk, no eviction policy. The cache exists
    so a long-lived poller does not re-GET caps per page, and firmware-in-the-key means a
    device that gets upgraded re-reads on the next poll instead of inheriting stale
    limits forever. The P2 store can persist these bodies if we ever want history.
    """

    def __init__(self) -> None:
        self._by_identity: dict[tuple[str | None, str | None], DeviceCapabilities] = {}

    def __len__(self) -> int:
        return len(self._by_identity)

    def get(self, serial: str | None, firmware: str | None) -> DeviceCapabilities | None:
        return self._by_identity.get((serial, firmware))

    def put(
        self, serial: str | None, firmware: str | None, caps: DeviceCapabilities
    ) -> DeviceCapabilities:
        self._by_identity[(serial, firmware)] = caps
        return caps

    def clear(self) -> None:
        self._by_identity.clear()


#: The process-wide default cache; callers may pass their own (tests do) to stay isolated.
_capability_cache = CapabilityCache()


def capability_cache() -> CapabilityCache:
    return _capability_cache


class CapabilityDiscoveryError(GateClerkError):
    """The AcsEvent capability endpoint — the important one — could not be read.

    Not a subclass of IsapiError: this is our verdict ("we refuse to guess codes
    without it"), one layer above the transport's typed failure. The transport error is
    the cause and travels in the message.
    """


def discover(
    client: Any,
    *,
    cache: CapabilityCache | None = None,
    force_refresh: bool = False,
) -> DeviceCapabilities:
    """Read deviceInfo + both capability endpoints once; serve repeats from the cache.

    Order is load-bearing: deviceInfo first for `(serial, firmware)` — the cache key —
    before any capability is fetched or trusted. `force_refresh` bypasses the read but
    still repopulates (an operator who just upgraded firmware should not need a restart).

    `client` is structurally an `IsapiClient` (`.get(name)`); typing it loosely here keeps
    this module free of httpx so its tests need no transport import at all.
    """
    cache = cache if cache is not None else _capability_cache

    info = client.get("device_info")
    serial, firmware, model = device_identity(dict(info) if info else {})
    cached = None if force_refresh else cache.get(serial, firmware)
    if cached is not None:
        return cached

    try:
        body = client.get_response("acs_event_capabilities").content
    except IsapiError as exc:
        raise CapabilityDiscoveryError(
            f"cannot read AcsEvent capabilities from the device ({exc}); refusing to "
            "guess event codes — see docs/DESIGN.md 'Why we read /capabilities'"
        ) from exc
    caps = parse_acs_event_capabilities(body)

    access_raw: Mapping[str, Any] | None = None
    access_error: str | None = None
    capacity: int | None = None
    try:
        access_raw, capacity = parse_access_control_capabilities(
            client.get_response("access_control_capabilities").content
        )
    except IsapiNotFound as exc:
        access_error = f"not advertised on this firmware: {exc}"
    except IsapiError as exc:  # a hard failure here is *not* fatal: caps stay advisory
        access_error = str(exc)

    caps = replace(
        caps,
        access_control_raw=access_raw,
        access_control_error=access_error,
        acs_event_capacity=capacity,
        serial=serial,
        firmware=firmware,
        model=model,
    )
    return cache.put(serial, firmware, caps)
