"""How one ISAPI response body is read: XML safety, the three envelope shapes, and
the envelope -> typed-exception mapping. Pure functions; nothing here touches a socket.

Why this module exists separately from the transport (p1-03 card)
-----------------------------------------------------------------
docs/OBSERVED.md and docs/references/isapi-client-gotchas.md §3 establish that a
Hikvision `webs` server does **not** honour the format you asked for on the error
path: a `?format=json` request can answer XML, with a quoted `charset="UTF-8"`, under
at least four different XML namespaces, using `statusCode` **or** `statusValue`. So
"parse the body" is a security-and-correctness decision, not a convenience, and it
belongs in exactly one place that every caller (and every test) goes through.

Three envelope shapes are handled (gotchas §3.1-3.3, DESIGN.md "Error envelopes come
in three shapes"):

1. canonical XML ``<ResponseStatus><statusCode>4</statusCode>…`` (namespaced);
2. JSON **flat** ``{"statusCode": 4, …}`` — the `ResponseStatus` wrapper is dropped in
   JSON, and the number arrives as an int in one firmware and a numeric string in
   another, so both are coerced;
3. auth/lock replies as ``<userCheck><statusValue>401</statusValue>`` — note
   `statusValue` is an *HTTP-ish* number and is NOT the same field as `statusCode`
   (1..7). Both names are accepted; a response carrying either is understood.

A search payload (`{"AcsEvent": {"responseStatusStrg": "OK", …}}`) is **not** an
envelope: it has no `statusCode`/`statusValue`, and `parse_envelope()` deliberately
returns `None` for it. The corollary — never look for `statusCode` on a search response
nor `responseStatusStrg` on a plain GET — is pinned by a test.

Ownership (orchestrator note on card p1-03, 2026-10-16): this module is the single
ISAPI response-parsing policy for the package. `parse_isapi_xml()` is the same size-
capped / DTD-refusing parser that PR #2 (p1-06) currently carries inside
`gateclerk/tz.py`; when p1-06 is revised it should import it from here rather than
keeping a second XML security policy alive next to this one.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from xml.etree import ElementTree as ET

from gateclerk.exceptions import (
    IsapiAuthError,
    IsapiBadContent,
    IsapiBusy,
    IsapiError,
    IsapiNotFound,
    IsapiPayloadError,
)

__all__ = [
    "MAX_ISAPI_XML_BYTES",
    "TEXT_KEY",
    "Envelope",
    "envelope_to_error",
    "flatten_xml",
    "parse_body",
    "parse_envelope",
    "parse_isapi_xml",
    "strip_ns",
]

#: ISAPI System/* answers are small (< 4 kB observed on site-a). We parse XML coming
#: from a box on the LAN, so the input is bounded rather than trusted.
MAX_ISAPI_XML_BYTES = 64 * 1024

#: Envelope field names we understand. `statusValue` is the `userCheck` spelling.
_STATUS_KEYS = ("statusCode", "statusValue")

#: Fields that make a body an *envelope* rather than a payload.
_ENVELOPE_MARKERS = frozenset(
    {*_STATUS_KEYS, "subStatusCode", "statusString", "errorMsg", "lockStatus"}
)

#: Root element names an envelope may arrive under (namespace-stripped).
_ENVELOPE_ROOTS = frozenset({"ResponseStatus", "userCheck"})

_NS = re.compile(r"^\{[^}]*\}")


def strip_ns(tag: str) -> str:
    """`{http://www.isapi.org/ver20/XMLSchema}statusCode` -> `statusCode`.

    Live samples use at least four namespace URIs (std-cgi.org, isapi.com, isapi.org,
    hikvision.com/ver20/XMLSchema) and they are not interchangeable in a naive `find()`,
    so the namespace is dropped before any key lookup.
    """
    return _NS.sub("", tag) if isinstance(tag, str) else str(tag)


def parse_isapi_xml(payload: str) -> ET.Element:
    """Parse an ISAPI XML body with two explicit bounds: size and DTD/entity use.

    `xml.etree.ElementTree` resolves no external entities, so the remaining hazards are
    size and entity expansion — both refused here rather than delegated to a dependency
    that would buy a claim, not a control.

    The DTD/entity refusal scans the **whole** payload, not a head window. An internal
    entity bomb (no external entity needed) padded behind ~20 kB of comments slipped
    past a `payload[:16 kB]` scan while the body stayed under the 64 kB cap, and
    ElementTree then expanded it (architect handoff on p1-03, eec6658: a real bypass,
    reproduced). The scan is a plain `in` over at most 64 kB — cheap, and the whole
    point is that no offset can hide the token.

    Conservative by design: any `<!DOCTYPE`/`<!ENTITY` token in the string is refused,
    so a CDATA section that *mentions* one is refused too. This is an XML body from an
    access terminal, not a document authoring pipeline; a false refusal is a loud
    IsapiPayloadError, a false accept is decompression on the payroll path.
    """
    if len(payload.encode("utf-8", "replace")) > MAX_ISAPI_XML_BYTES:
        raise IsapiPayloadError(
            f"ISAPI XML body exceeds {MAX_ISAPI_XML_BYTES} bytes — refusing to parse"
        )
    if "<!DOCTYPE" in payload or "<!ENTITY" in payload:
        raise IsapiPayloadError("ISAPI XML body declares a DTD or entity — refusing to parse")
    try:
        # S314 is suppressed here on purpose. defusedxml's controls are DTD/entity
        # expansion and size, and this function refuses both explicitly above (any
        # DOCTYPE/ENTITY is rejected before parsing; the byte cap is enforced).
        # ElementTree resolves no external entities on its own, so an extra dependency
        # would add a claim, not a control.
        return ET.fromstring(payload)  # noqa: S314
    except ET.ParseError as exc:
        raise IsapiPayloadError(f"ISAPI XML body is not well-formed XML: {exc}") from exc


#: Key a leaf's text gets when that leaf also carries attributes (the leaf became a
#: dict for the `@` keys, so the text needs a name). Convention from the round-1
#: review on t_a8cdd1a9; `@`/`#text` match the recorded JSON capability fixtures
#: (`tests/fixtures/recorded/site-a-ds-k1t341amf-s/acs_capabilities.json` uses `@max`).
TEXT_KEY = "#text"


def _flatten_element(el: ET.Element) -> Any:
    """One element -> its value under the `@`-prefix convention.

    - attributes (always, on any element) become `@`-prefixed keys on that element's
      dict — an element with no other content flattens to just those keys;
    - a leaf with attributes AND text becomes `{"@…": …, TEXT_KEY: text}`;
    - text-only leaves, empty leaves (`None`), and repeated tags (lists) UNCHANGED.
      Mixed content on an element that has children still drops the leading text, as
      before — out of scope, ISAPI capability/payload elements are not mixed content.
    """
    attrs = {f"@{strip_ns(name)}": value for name, value in el.attrib.items()}
    if len(el):
        nested = flatten_xml(el)
        nested.update(attrs)
        return nested
    text = (el.text or "").strip()
    if attrs:
        return {**attrs, TEXT_KEY: text} if text else attrs
    return text if text else None


def flatten_xml(root: ET.Element) -> dict[str, Any]:
    """XML -> plain dict, namespace-stripped, repeated tags collected into lists.

    This is what makes OBSERVED.md delta (1) (`System/deviceInfo` and `System/time`
    answer **XML even with `?format=json`**) a non-event for callers: `parse_body()`
    hands back a dict either way.

    Leaf text becomes a str; an element with children becomes a nested dict; an element
    with neither becomes `None` (present-but-empty, e.g. `<requestURL></requestURL>`)
    rather than `""`, so "the device said nothing" stays distinguishable from "the
    device said the empty string" only where it matters, and never silently becomes a
    falsy that a caller mistakes for absence... it stays a key, with `None`.

    Attributes are data, not decoration (review defect #1 of PR #5): the device puts
    capability limits in XML attributes (`maxResults@max=30`, `searchID@max=64`,
    `major@opt=…` — OBSERVED.md) and p1-04's clamping reads them through this fallback.
    They become `@`-prefixed keys on the element's dict, and a leaf with attributes AND
    text carries its text under `TEXT_KEY` (`"#text"`). An element whose only content
    was attributes is now that attribute dict — never the silent `None` that made a
    real capability read as no-data.
    """
    out: dict[str, Any] = {}
    for child in root:
        key = strip_ns(child.tag)
        value = _flatten_element(child)
        if key in out:
            existing = out[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                out[key] = [existing, value]
        else:
            out[key] = value
    return out


def parse_body(body: bytes | str) -> dict[str, Any]:
    """Decode an ISAPI body to a dict, format-agnostically. Never trusts Content-Type.

    Sniff the first non-whitespace byte (`{`/`[`) -> JSON, else XML (gotchas §3.3:
    `?format=json` does not bind the response format, and the device also sends the
    malformed `application/json;charset="UTF-8"`, so the header is worthless).

    An empty body is `{}` — a 204-ish/empty ack is a fact, not a crash. A body that is
    neither JSON nor well-formed XML raises `IsapiPayloadError`: silently returning
    `{}` there would turn a corrupt device response into "no data", which on a payroll
    pipeline reads as "nobody clocked in".
    """
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    stripped = text.strip()
    if not stripped:
        return {}
    if stripped[0] in "{[":
        try:
            decoded = json.loads(stripped)
        except json.JSONDecodeError:
            # JSON was promised, XML is what arrived (or garbage). Fall through to XML.
            pass
        else:
            if isinstance(decoded, dict):
                return decoded
            raise IsapiPayloadError(f"ISAPI JSON body is a {type(decoded).__name__}, not an object")
    return flatten_xml(parse_isapi_xml(stripped))


@dataclass(frozen=True, slots=True)
class Envelope:
    """A normalised ISAPI error/ack envelope. `http_status` is the transport's verdict,
    `status_code`/`status_value` the device's — they disagree by design (§3.3)."""

    http_status: int | None
    #: canonical `statusCode` (1..7) when the body carries one.
    status_code: int | None = None
    #: `userCheck`'s `statusValue` — an HTTP-ish number (401), never mixed with 1..7.
    status_value: int | None = None
    status_string: str | None = None
    sub_status_code: str | None = None
    error_code: str | None = None
    error_msg: str | None = None
    request_url: str | None = None
    #: lockout fields (DESIGN.md "Account lockout is machine-readable").
    lock_status: str | None = None
    unlock_seconds: int | None = None
    retry_login_seconds: int | None = None
    #: True when the body used the `userCheck`/`statusValue` spelling.
    is_user_check: bool = False
    #: the parsed body, verbatim, for callers that want a field we did not promote.
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        """statusCode 1 (`OK`) is a success envelope, not an error."""
        return self.status_code == 1

    @property
    def locked(self) -> bool:
        return (self.lock_status or "").strip().lower() in {"locked", "lock", "1"}


def _as_int(value: Any) -> int | None:
    """int or numeric string -> int; anything else -> None (never a guess)."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def _as_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (str, int)):
        return str(value)
    return None


def _envelope_dict(payload: dict[str, Any]) -> dict[str, Any] | None:
    """The dict that holds the envelope fields, if this payload is an envelope at all."""
    # Tolerate the wrapped JSON form even though the firmware we observe drops it.
    wrapped = payload.get("ResponseStatus")
    if isinstance(wrapped, dict):
        return wrapped
    if any(k in payload for k in _ENVELOPE_MARKERS):
        return payload
    return None


def parse_envelope(body: bytes | str, *, http_status: int | None = None) -> Envelope | None:
    """Parse any of the three envelope shapes, or return None for a plain payload.

    A body we cannot parse at all is *not* an envelope: the transport keeps the raw
    bytes for the error message instead.
    """
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    if not text.strip():
        return None if http_status is None or 200 <= http_status < 300 else Envelope(http_status)
    try:
        payload = parse_body(text)
    except IsapiPayloadError:
        return None
    source = _envelope_dict(payload)
    if source is None:
        return None

    status_code = _as_int(source.get("statusCode"))
    status_value = _as_int(source.get("statusValue"))
    unlock = _as_int(source.get("unlockTime"))
    retry = _as_int(source.get("retryLoginTime"))
    return Envelope(
        http_status=http_status,
        status_code=status_code,
        status_value=status_value,
        status_string=_as_str(source.get("statusString")),
        sub_status_code=_as_str(source.get("subStatusCode")),
        error_code=_as_str(source.get("errorCode")),
        error_msg=_as_str(source.get("errorMsg")),
        request_url=_as_str(source.get("requestURL")),
        lock_status=_as_str(source.get("lockStatus")),
        unlock_seconds=unlock,
        retry_login_seconds=retry,
        is_user_check="statusValue" in source,
        raw=dict(payload),
    )


# --- envelope -> typed exception ----------------------------------------------------

#: `statusCode` 2 family (vendor "Response Codes of Text Protocol", gotchas §2.2):
#: the retryable class. `activeOperator` is *not* in the vendor table (gotchas §2.3
#: could not substantiate it) but DESIGN.md names it, so it is bucketed as busy —
#: "someone else holds the operator slot" is a wait, never an auth failure.
_BUSY_SUBCODES = frozenset(
    {"deviceBusy", "serviceUnavailable", "noMemory", "upgrading", "activeOperator"}
)
#: A different operator holds the resource: wait, but it is not our bug and not auth.
_BUSY_WAIT_SUBCODES = frozenset({"beingExportedByAnotherUser"})
#: Terminal: our request is wrong (gotchas §2.2, classes 5 and 6).
_BAD_FORMAT_SUBCODES = frozenset({"badXmlFormat", "badContent", "badParameters", "badXmlContent"})
#: Absent on this model/firmware — e.g. `AcsEvent/Total` on our unit (OBSERVED.md).
_NOT_FOUND_SUBCODES = frozenset({"notSupport"})


def _envelope_fields(env: Envelope) -> dict[str, Any]:
    """The envelope as the exception's `envelope=` dict (kept for the error message).

    Explicit wire-name keys, because the attribute names and the wire names differ by
    design (`status_code` is `statusCode`, `unlock_seconds` is `unlockTime`).
    """
    out: dict[str, Any] = {}
    pairs = (
        ("statusCode", env.status_code),
        ("statusValue", env.status_value),
        ("statusString", env.status_string),
        ("subStatusCode", env.sub_status_code),
        ("errorCode", env.error_code),
        ("errorMsg", env.error_msg),
        ("lockStatus", env.lock_status),
        ("unlockTime", env.unlock_seconds),
        ("retryLoginTime", env.retry_login_seconds),
    )
    out.update({k: v for k, v in pairs if v is not None})
    return out


def envelope_to_error(
    *,
    http_status: int,
    envelope: Envelope | None,
    endpoint: str,
    request_body: str | None = None,
    raw_body: bytes | None = None,
) -> IsapiError | None:
    """Turn a response into the typed failure it deserves, or None if it is a success.

    Ordering is deliberate and each step is a real device behaviour, not a style choice:

    1. HTTP 401 wins over everything, envelope or no envelope — the account-lockout
       risk (DESIGN.md: "surface it and stop") outranks message quality.
    2. `notSupport` / HTTP 404 -> `IsapiNotFound` **before** the generic 400 rule: our
       own fixture `error_total_notsupport.json` is an HTTP 400 carrying
       `subStatusCode:"notSupport"`, and calling that "bad request" would send a
       developer hunting our body instead of reading "this firmware has no such
       endpoint".
    3. `statusCode` 2 / HTTP 503 -> `IsapiBusy` (the retryable class).
    4. `statusCode` 6 / bad-format subcodes / HTTP 400 -> `IsapiBadContent`, with the
       request body verbatim in the message (DESIGN.md: it is almost always our shape).
    """
    env = envelope
    sub = (env.sub_status_code if env else None) or ""
    fields = _envelope_fields(env) if env else {}
    status_code = env.status_code if env else None
    status_value = env.status_value if env else None

    def detail(context: str) -> str:
        parts = [f"{context} on {endpoint}", f"http_status={http_status}"]
        parts.extend(f"{k}={v}" for k, v in fields.items())
        if not fields:
            snippet = (raw_body or b"").decode("utf-8", "replace").strip()
            parts.append(f"body={snippet[:300]!r}" if snippet else "body=<empty>")
        return " ".join(parts)

    if http_status == 401 or status_value == 401:
        return IsapiAuthError(
            detail("unauthorized"),
            status_code=http_status,
            envelope=fields,
            request_body=request_body,
            lock_status=env.lock_status if env else None,
            unlock_seconds=env.unlock_seconds if env else None,
            retry_login_seconds=env.retry_login_seconds if env else None,
        )
    if http_status == 404 or sub in _NOT_FOUND_SUBCODES:
        return IsapiNotFound(
            detail("endpoint not available on this firmware"),
            status_code=http_status,
            envelope=fields,
            request_body=request_body,
        )
    if (
        status_code == 2
        or http_status == 503
        or sub in _BUSY_SUBCODES
        or sub in _BUSY_WAIT_SUBCODES
    ):
        return IsapiBusy(
            detail("device busy"),
            status_code=http_status,
            envelope=fields,
            request_body=request_body,
        )
    if status_code == 3:
        # Device Error (vendor class 3): the `statusCode` drives the retry table
        # (DESIGN.md: "3 once then alert"), so this check runs BEFORE the generic
        # HTTP-400 rule — an HTTP-400-carried statusCode 3 is a device failure, not
        # "our request shape", and mislabelling it sends the reader to the wrong file.
        return IsapiError(
            detail("device error"),
            status_code=http_status,
            envelope=fields,
            request_body=request_body,
        )
    if status_code == 6 or sub in _BAD_FORMAT_SUBCODES or http_status == 400:
        return IsapiBadContent(
            detail("device rejected our request shape"),
            status_code=http_status,
            envelope=fields,
            request_body=request_body,
        )
    if status_code not in (None, 1):
        # statusCode 3 (deviceError) and anything unclassified land here: terminal, and
        # deliberately NOT auto-retried. Auto-retrying an unclassified code is how a
        # polling loop turns into a lockout (gotchas §2.4).
        return IsapiError(
            detail("device reported an error"),
            status_code=http_status,
            envelope=fields,
            request_body=request_body,
        )
    if not 200 <= http_status < 300:
        return IsapiError(
            detail("unexpected HTTP status"),
            status_code=http_status,
            envelope=fields,
            request_body=request_body,
        )
    return None
