"""Capability probe (card E1-03): what THIS device can actually do, recorded not assumed.

docs/ENROLLMENT-MIGRATION.md v4 §3 makes this matrix the gate for every export AND
apply of the E1 migration feature: identity, a per-endpoint availability matrix,
counts, the templateNo evidence set, the face/FP situation, and the clock-skew
evidence the apply gate (§5 step 1a) consumes. §0.7 decides how errors are treated:
**fail closed** — a surface we could not read is recorded as `error`, silence is
never interpreted as "empty" or "supported", and a zero is only a zero when the
device said OK.

Three rules make this module trustworthy rather than convenient:

* **Discovered, never inferred — in EITHER direction.** Every verdict comes from one
  request the device actually answered on THIS device (design §3: "notSupport is a
  discovered fact, never assumed" — B/C firmwares are unknown until creds arrive,
  §8 R4). And v4 added the mirror image: caps switches must not *grant* availability
  either — bench A's `FDLib/capabilities` says `isSuportFDSearch=false` while the
  FDSearch POST demonstrably works (OBSERVED.md "E1 enrollment-read probes",
  2026-10-21). So caps bodies are recorded verbatim as *claims* (`caps_raw`), and
  the face-availability fact is sourced ONLY from the FDSearch call itself
  (`face_search_available_by_call`). The verdict vocabulary is exactly the four
  answers the transport can distinguish — `OK`, `notSupport`, `rejected_shape`,
  `error` — each carrying the `subStatusCode` string the device sent.
* **Budget respect (§0.5).** Exactly one request per probed surface, and an error
  response is NEVER retried (the transport already treats notSupport/badContent as
  terminal; the probe adds no retry of its own — pinned against FakeDevice's
  per-path authorized-request counter, tests/test_e1_03_migrate_probe.py). A 401
  ABORTS the whole probe: a credential problem is not a per-surface fact, and
  knocking again is exactly the lockout accounting §0.5 forbids. Settled axes are
  not re-probed (policy reaffirmed in OBSERVED.md): the faceURL photo-bytes question
  is recorded as a CLOSED dead-end, the probe does not spend GETs re-arguing it.
* **PII discipline (§0.4).** The matrix stores counts, verdicts and caps — never
  names, never the `password` value, never the full serial, never biometric bytes.
  Identity is recorded as model, firmware and a **serial prefix** only (4 chars).
  The FP-read probe needs an employeeNo (the device demands one); the value is used
  for the request and NOT persisted.

Clock skew note (why `clock_skew_s` is a WALL comparison): the card names the
"p1-11 path", and that path — `pipeline.device_time_reading` + `tz.compute_skew` —
compares device wall clock to our wall clock *in the site zone*, deliberately not
instants. OBSERVED.md ("The time/offset bug", VERIFIED) proves this firmware's wall
clock is right while its offset LABEL is wrong (`+02:00` in Bucharest summer); an
instant comparison would report that tz bug as a permanent 3600 s "skew" and the
§5.1a apply gate would refuse every write to a healthy device forever. The thing
`timeType=local` validity strings actually land on is the device's WALL clock (and
bench A's UserInfo caps say `timeType @opt` is `"local"` ONLY), so that is the
number we record — and the claimed offset travels beside it as evidence
(`clock_claimed_offset_min`), never folded in.

Freshness (§4): probes are persisted under `<bundles-root>/probes/<site>-<host>.json`
with `probed_at` stamped from an INJECTED clock, and `require_fresh()` is the helper
E1-02/E1-04 import as the gate — a missing, corrupt, stale (default 7 d) or
future-dated probe is refused, never tolerated.

Nothing here opens a socket: `probe_device` receives an `IsapiClient` (p1-03), which
every test satisfies with `tests/fakedevice.py` seeded to bench A's discovered truth
(docs/OBSERVED.md "E1 enrollment-read probes").
"""

from __future__ import annotations

import contextlib
import json
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from gateclerk import migrate_bundle
from gateclerk.capabilities import CapabilityCache, DeviceCapabilities, discover
from gateclerk.exceptions import (
    GateClerkError,
    IsapiAuthError,
    IsapiBadContent,
    IsapiError,
    IsapiNotFound,
    IsapiPayloadError,
)
from gateclerk.pipeline import device_time_reading
from gateclerk.tz import DEFAULT_SITE_TZ, TimestampInputError, compute_skew

__all__ = [
    "DEFAULT_PROBE_MAX_AGE_S",
    "MATRIX_SCHEMA_VERSION",
    "CapabilityMatrix",
    "ProbeAbortedError",
    "ProbeStaleError",
    "SurfaceProbe",
    "Verdict",
    "load_matrix",
    "probe_device",
    "probe_file_name",
    "probes_dir",
    "require_fresh",
    "require_fresh_probe",
    "save_matrix",
]

#: Bump when the persisted shape changes so a reader can tell an old probe file apart.
MATRIX_SCHEMA_VERSION = 2

#: §3: "applied probes older than 7 days are stale; staleness is not trusted".
DEFAULT_PROBE_MAX_AGE_S = 7 * 24 * 60 * 60

#: Probes stamped further in the FUTURE than this are refused too (clock games, a
#: restored file from a box with a broken clock — same fail-closed logic as §5.1a).
_MAX_FUTURE_TOLERANCE_S = 300.0

#: v4 §3/§5.1a: the photo-bytes question is CLOSED as a dead-end (faceURL 404s on
#: bench A after bounded rounds — OBSERVED.md). Recorded as a settled fact, and the
#: probe spends NO requests re-arguing it ("no device re-probes on a settled axis").
FACE_PHOTO_BYTES_CLOSED = "not_exportable_on_bench_A_fw (faceURL 404 — OBSERVED.md, closed)"


class Verdict(StrEnum):
    """The four answers a probe surface can honestly give (design §3)."""

    OK = "OK"
    #: Endpoint absent on this firmware — HTTP 404 or the `notSupport` subStatusCode.
    NOT_SUPPORT = "notSupport"
    #: Endpoint exists but rejected our request shape (`badJsonContent`,
    #: `MessageParametersLack`, ...). Recorded verbatim; never upgraded to OK.
    REJECTED_SHAPE = "rejected_shape"
    #: Anything else the device answered (busy-exhausted, device error, unparseable
    #: body, or a request we refused to build rather than guess). §0.7: an error is
    #: an error — never "empty", never "supported".
    ERROR = "error"


class ProbeStaleError(GateClerkError):
    """The freshness gate (§4) refused: no probe, unreadable probe, or too old.

    This is the error E1-02 (diff) and E1-04 (apply) see when they call
    `require_fresh`/`require_fresh_probe` — one vocabulary for "we refuse to write
    against unverified device truth", named once, here.
    """


class ProbeAbortedError(GateClerkError):
    """The probe could not run at all (auth refused us). Fail-closed abort (§0.5)."""


@dataclass(frozen=True, slots=True)
class SurfaceProbe:
    """One probed surface: the request we made and the verdict the device earned."""

    #: stable key from design §1's row table (users, cards, face_records, ...)
    key: str
    #: the registry endpoint name (gateclerk.endpoints) the request went to
    endpoint: str
    method: str
    path: str
    verdict: Verdict
    #: verbatim `subStatusCode` from the device's envelope, when it sent one
    sub_status_code: str | None = None
    http_status: int | None = None
    #: anything the reader needs to trust (or distrust) this row
    note: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "endpoint": self.endpoint,
            "method": self.method,
            "path": self.path,
            "verdict": str(self.verdict),
            "sub_status_code": self.sub_status_code,
            "http_status": self.http_status,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> SurfaceProbe:
        return cls(
            key=str(raw.get("key") or ""),
            endpoint=str(raw.get("endpoint") or ""),
            method=str(raw.get("method") or ""),
            path=str(raw.get("path") or ""),
            verdict=Verdict(str(raw.get("verdict") or Verdict.ERROR)),
            sub_status_code=_as_opt_str(raw.get("sub_status_code")),
            http_status=_as_opt_int(raw.get("http_status")),
            note=_as_opt_str(raw.get("note")),
        )


@dataclass(frozen=True, slots=True)
class CapabilityMatrix:
    """The persisted probe result — JSON round-trippable, PII-free by construction.

    Frozen with tuple members so `==` (and therefore "the file we loaded is the
    matrix we wrote") is a real check, not a field-by-field hope. `caps_raw` keeps
    the device's capability bodies verbatim — as CLAIMS, never as availability
    (module docstring: bench A's `isSuportFDSearch=false` while FDSearch works).
    """

    schema: int = MATRIX_SCHEMA_VERSION
    site: str = ""
    host: str = ""
    # --- identity (§3: model, fw, serial PREFIX — never the full serial) ----------
    model: str | None = None
    firmware: str | None = None
    serial_prefix: str | None = None
    # --- clock evidence for the §5.1a apply gate ------------------------------------
    #: device wall clock minus our wall clock, seconds, both in the site zone
    #: (see module docstring: wall, not instants — OBSERVED.md's offset bug).
    clock_skew_s: float | None = None
    clock_device_wall: str | None = None
    clock_claimed_offset_min: int | None = None
    clock_site_tz: str | None = None
    #: why the skew is None ("System/time said notSupport", "unparseable localTime")
    clock_note: str | None = None
    # --- paging evidence from the device's own capabilities (search @max) -----------
    search_max_results: int | None = None
    # --- the availability matrix (one row per surface, device-answered) ------------
    surfaces: tuple[SurfaceProbe, ...] = ()
    # --- counts (§0.7: a count is None unless the device SAID it) --------------------
    users_count: int | None = None
    cards_count: int | None = None
    #: the ONLY plan-template evidence that exists on this family (§3): the union of
    #: templateNos OBSERVED in this device's own UserInfo RightPlan records.
    template_nos: tuple[str, ...] = ()
    # --- face / fingerprint situation (§1 v4: these ARE the product) -----------------
    face_fdids: tuple[str, ...] = ()
    face_lib_names: tuple[str, ...] = ()
    #: True ONLY when the FDSearch POST itself answered OK with rows — sourced from
    #: the call, NEVER from `FDLib/capabilities isSuportFDSearch` (bench A: false
    #: while the call works — v4's caps-under-claim trap, symmetric with the
    #: silently-ignored-filter trap of OBSERVED.md).
    face_search_available_by_call: bool = False
    #: True only when FDSearch rows carried `modelData` (the face TEMPLATE — the
    #: thing that makes a face work; v4 scope: template port is the product).
    face_template_exportable: bool = False
    #: settled-axis record, zero requests spent (module docstring).
    face_photo_bytes: str = FACE_PHOTO_BYTES_CLOSED
    #: True only when FingerPrintUpload-Cond answered OK with a template row.
    fp_templates_readable: bool = False
    # --- capability bodies, recorded as device CLAIMS (never availability) ----------
    caps_raw: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    #: UserInfo caps `Valid.timeType @opt` — v4: bench A offers `"local"` ONLY, which
    #: is exactly what makes the §5.1a clock-skew gate payroll-critical.
    valid_time_type_opts: tuple[str, ...] = ()
    #: ISO-8601 stamp from the INJECTED clock (never `datetime.now()` internally).
    probed_at: str = ""

    # --- lookup ----------------------------------------------------------------------

    def surface(self, key: str) -> SurfaceProbe | None:
        for probe in self.surfaces:
            if probe.key == key:
                return probe
        return None

    def verdict_of(self, key: str) -> Verdict | None:
        found = self.surface(key)
        return None if found is None else found.verdict

    def ok(self, key: str) -> bool:
        """Whether the DEVICE said OK for this surface — never a default."""
        return self.verdict_of(key) is Verdict.OK

    # --- serialisation ----------------------------------------------------------------

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "site": self.site,
            "host": self.host,
            "identity": {
                "model": self.model,
                "firmware": self.firmware,
                "serial_prefix": self.serial_prefix,
            },
            "clock": {
                "skew_s": self.clock_skew_s,
                "device_wall": self.clock_device_wall,
                "claimed_offset_min": self.clock_claimed_offset_min,
                "site_tz": self.clock_site_tz,
                "note": self.clock_note,
            },
            "search_max_results": self.search_max_results,
            "surfaces": [probe.as_dict() for probe in self.surfaces],
            "counts": {
                "users": self.users_count,
                "cards": self.cards_count,
            },
            "template_nos": list(self.template_nos),
            "face": {
                "fdids": list(self.face_fdids),
                "lib_names": list(self.face_lib_names),
                "search_available_by_call": self.face_search_available_by_call,
                "template_exportable": self.face_template_exportable,
                "photo_bytes": self.face_photo_bytes,
            },
            "fingerprints": {
                "templates_readable": self.fp_templates_readable,
            },
            "caps_raw": {name: dict(body) for name, body in self.caps_raw.items()},
            "valid_time_type_opts": list(self.valid_time_type_opts),
            "probed_at": self.probed_at,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> CapabilityMatrix:
        identity = _mapping(raw.get("identity"))
        clock = _mapping(raw.get("clock"))
        counts = _mapping(raw.get("counts"))
        face = _mapping(raw.get("face"))
        prints = _mapping(raw.get("fingerprints"))
        caps = raw.get("caps_raw")
        return cls(
            schema=_as_opt_int(raw.get("schema")) or MATRIX_SCHEMA_VERSION,
            site=str(raw.get("site") or ""),
            host=str(raw.get("host") or ""),
            model=_as_opt_str(identity.get("model")),
            firmware=_as_opt_str(identity.get("firmware")),
            serial_prefix=_as_opt_str(identity.get("serial_prefix")),
            clock_skew_s=_as_opt_float(clock.get("skew_s")),
            clock_device_wall=_as_opt_str(clock.get("device_wall")),
            clock_claimed_offset_min=_as_opt_int(clock.get("claimed_offset_min")),
            clock_site_tz=_as_opt_str(clock.get("site_tz")),
            clock_note=_as_opt_str(clock.get("note")),
            search_max_results=_as_opt_int(raw.get("search_max_results")),
            surfaces=tuple(
                SurfaceProbe.from_dict(item)
                for item in raw.get("surfaces") or []
                if isinstance(item, Mapping)
            ),
            users_count=_as_opt_int(counts.get("users")),
            cards_count=_as_opt_int(counts.get("cards")),
            template_nos=tuple(str(v) for v in raw.get("template_nos") or ()),
            face_fdids=tuple(str(v) for v in face.get("fdids") or ()),
            face_lib_names=tuple(str(v) for v in face.get("lib_names") or ()),
            face_search_available_by_call=bool(face.get("search_available_by_call", False)),
            face_template_exportable=bool(face.get("template_exportable", False)),
            face_photo_bytes=str(face.get("photo_bytes") or FACE_PHOTO_BYTES_CLOSED),
            fp_templates_readable=bool(prints.get("templates_readable", False)),
            caps_raw={
                str(name): dict(_mapping(body))
                for name, body in (caps.items() if isinstance(caps, Mapping) else ())
            },
            valid_time_type_opts=tuple(str(v) for v in raw.get("valid_time_type_opts") or ()),
            probed_at=str(raw.get("probed_at") or ""),
        )

    def as_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.as_dict(), indent=indent, ensure_ascii=False, default=str)

    def probed_at_instant(self) -> datetime | None:
        """Parsed `probed_at`; None when absent/unparseable — the gate treats that as
        stale (fail closed), never as "fresh enough"."""
        if not self.probed_at:
            return None
        try:
            parsed = datetime.fromisoformat(self.probed_at)
        except ValueError:
            return None
        return parsed


def probe_device(
    client: Any,
    *,
    now: datetime,
    site: str = "",
    host: str = "",
    site_tz: str = DEFAULT_SITE_TZ,
    cache: CapabilityCache | None = None,
) -> CapabilityMatrix:
    """Probe one device READ-ONLY and return the discovered matrix.

    `now` is REQUIRED and injected: `probed_at` and the clock-skew comparison both
    come from it, so the caller owns the clock (the repo's injected-clock seam;
    a naive `now` is refused, never guessed at). Each surface gets exactly one
    request; verdicts come only from what the device answered (§0.7 fail closed);
    a 401 aborts the probe instead of adding requests to a lockout risk (§0.5).

    `discover()` (card p1-04) is reused — not reimplemented — for identity and the
    search `@max`: it is the one place deviceInfo/capabilities parsing lives, and
    forcing a refresh keeps a cached caps result from silencing THIS probe's
    evidence. That coupling is deliberate and honest: a device whose AcsEvent
    capabilities cannot be read at all aborts with `ProbeAbortedError` naming the
    cause, because with no caps we cannot even size the search page and guessing
    page sizes is the class of bug OBSERVED.md is written against.

    `site`/`host` are labels for the persisted file name (§3's
    `<site>-<host>.json`); the probe itself trusts no label — identity comes from
    deviceInfo.
    """
    if now.tzinfo is None:
        raise TimestampInputError(
            "probe_device needs a tz-aware injected `now` (probed_at + skew are "
            f"payroll evidence; got naive {now!r})"
        )
    now = now.astimezone(UTC)

    try:
        caps = discover(client, cache=cache or CapabilityCache(), force_refresh=True)
    except IsapiAuthError as exc:
        raise ProbeAbortedError(
            f"capability probe aborted before any surface was read: the device "
            f"refused our credentials ({exc}); not retrying — lockout accounting "
            "(docs/ENROLLMENT-MIGRATION.md §0.5)"
        ) from exc
    except GateClerkError as exc:
        raise ProbeAbortedError(
            f"capability probe aborted: deviceInfo/capabilities unreadable ({exc}); "
            "refusing to size or shape searches by guess"
        ) from exc

    surfaces: list[SurfaceProbe] = [
        SurfaceProbe(
            key="device_info",
            endpoint="device_info",
            method="GET",
            path="/ISAPI/System/deviceInfo",
            verdict=Verdict.OK,
            note="read via capabilities.discover (raises unless OK)",
        ),
        SurfaceProbe(
            key="acs_event_caps",
            endpoint="acs_event_capabilities",
            method="GET",
            path="/ISAPI/AccessControl/AcsEvent/capabilities",
            verdict=Verdict.OK,
            note="read via capabilities.discover (raises unless OK)",
        ),
        _access_control_caps_row(caps),
    ]
    matrix = CapabilityMatrix(
        site=site,
        host=host,
        model=caps.model,
        firmware=caps.firmware,
        serial_prefix=None if caps.serial is None else str(caps.serial)[:4],
        search_max_results=caps.clamp_max_results(1_000_000),
        clock_site_tz=site_tz,
        probed_at=now.isoformat(),
    )

    matrix = _probe_clock(client, matrix, surfaces, now=now, site_tz=site_tz)

    caps_raw: dict[str, Mapping[str, Any]] = {}
    matrix, caps_raw = _probe_caps(
        client, matrix, caps_raw, surfaces, key="caps_acs_cfg", endpoint="acs_cfg_capabilities"
    )
    matrix, caps_raw = _probe_caps(
        client, matrix, caps_raw, surfaces, key="caps_user_info", endpoint="user_info_capabilities"
    )
    matrix, caps_raw = _probe_caps(
        client, matrix, caps_raw, surfaces, key="caps_card_info", endpoint="card_info_capabilities"
    )
    matrix, caps_raw = _probe_caps(
        client, matrix, caps_raw, surfaces, key="caps_fd_lib", endpoint="fd_lib_capabilities"
    )
    # v4/steering: these two caps paths ARE the 404s on bench A — probed so the fact
    # is discovered per device, not carried forward from a document.
    _probe_simple(
        client,
        surfaces,
        key="caps_user_setup",
        method="GET",
        endpoint="user_info_setup_capabilities",
    )
    _probe_simple(
        client,
        surfaces,
        key="caps_user_info_search",
        method="GET",
        endpoint="user_info_search_capabilities",
    )
    _probe_simple(
        client,
        surfaces,
        key="caps_fingerprint_download",
        method="GET",
        endpoint="finger_print_download_capabilities",
    )

    matrix, employee_nos = _probe_users(client, matrix, surfaces, caps=caps)
    matrix = _probe_cards(client, matrix, surfaces, caps=caps)
    _probe_simple(
        client,
        surfaces,
        key="per_person_detail",
        method="POST",
        endpoint="user_info_detail_search",
        cond_key="UserInfoDetailSearchCond",
    )
    matrix = _probe_face_libs(client, matrix, surfaces)
    matrix = _probe_face_records(client, matrix, surfaces, caps=caps)
    matrix = _probe_fp_read(client, matrix, surfaces, caps=caps, employee_nos=employee_nos)
    _probe_simple(
        client,
        surfaces,
        key="fingerprints_search",
        method="POST",
        endpoint="fingerprint_search",
        cond_key="FingerPrintSearchCond",
    )
    _probe_simple(client, surfaces, key="plan_templates", method="GET", endpoint="plan_template")

    matrix = replace(
        matrix,
        surfaces=tuple(surfaces),
        caps_raw=caps_raw,
        valid_time_type_opts=_time_type_opts(caps_raw.get("caps_user_info") or {}),
    )
    return matrix


# --- request plumbing ------------------------------------------------------------------


def _call(
    client: Any,
    surfaces: list[SurfaceProbe],
    *,
    key: str,
    endpoint: str,
    method: str,
    payload: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """One request to one registered endpoint; append the device's verdict.

    Returns the parsed body on OK, None on a recorded non-OK verdict. A 401 raises
    `ProbeAbortedError` (abort, never knock again); everything the transport typed
    as a device answer becomes a verdict row — never a retry, never a swallow.
    """
    from gateclerk.endpoints import endpoint_for

    ep = endpoint_for(endpoint)
    try:
        if method == "POST":
            body = client.search(endpoint, payload if payload is not None else {})
        else:
            body = client.get(endpoint)
    except IsapiAuthError as exc:
        raise ProbeAbortedError(
            f"capability probe aborted at surface {key!r}: auth refused "
            f"({exc}); the remaining surfaces stay unprobed (§0.5)"
        ) from exc
    except (IsapiError, IsapiPayloadError) as exc:
        surfaces.append(_error_row(key, endpoint, ep.path, method, exc))
        return None
    surfaces.append(
        SurfaceProbe(key=key, endpoint=endpoint, method=method, path=ep.path, verdict=Verdict.OK)
    )
    return dict(body) if isinstance(body, Mapping) else {}


def _error_row(
    key: str, endpoint: str, path: str, method: str, exc: IsapiError | IsapiPayloadError
) -> SurfaceProbe:
    return SurfaceProbe(
        key=key,
        endpoint=endpoint,
        method=method,
        path=path,
        verdict=_verdict_for(exc),
        sub_status_code=_opt_str(_envelope_of(exc).get("subStatusCode")),
        http_status=_status_of(exc),
        # `_opt_str` (strip) is what keeps `load(save(m)) == m` exactly true: the
        # from_dict path strips notes, so an unstripped note at write time would
        # round-trip to a DIFFERENT matrix — and "the file we loaded is the matrix
        # we wrote" is the equality the freshness gate leans on.
        note=_opt_str(str(exc)[:300]),
    )


def _not_sent_row(key: str, endpoint: str, path: str, method: str, note: str) -> SurfaceProbe:
    """A surface we could NOT legally request (fail-closed: recorded, budget spent 0)."""
    return SurfaceProbe(
        key=key,
        endpoint=endpoint,
        method=method,
        path=path,
        verdict=Verdict.ERROR,
        note=note,
    )


def _envelope_of(exc: BaseException) -> Mapping[str, Any]:
    return getattr(exc, "envelope", {}) or {}


def _status_of(exc: BaseException) -> int | None:
    value = getattr(exc, "status_code", None)
    return value if isinstance(value, int) else None


def _verdict_for(exc: IsapiError | IsapiPayloadError) -> Verdict:
    """Map the transport's typed failure onto §3's vocabulary — no inference.

    `IsapiNotFound` is what `envelope_to_error` raises for HTTP 404 *or* the
    `notSupport` subStatusCode (our own fixture `error_total_notsupport.json` is a
    400 carrying notSupport), so both device-side "no such endpoint" answers land on
    NOT_SUPPORT. `IsapiBadContent` (statusCode 6 / bad-format subcodes / HTTP 400)
    is the device rejecting our SHAPE — REJECTED_SHAPE (e.g. the wrapped-FDSearch
    dialect OBSERVED.md records being 400'd). Anything else — exhausted busy,
    statusCode 3/5, unparseable body — is ERROR: §0.7 forbids reading it as either
    "supported" or "absent".
    """
    if isinstance(exc, IsapiNotFound):
        return Verdict.NOT_SUPPORT
    if isinstance(exc, IsapiBadContent):
        return Verdict.REJECTED_SHAPE
    return Verdict.ERROR


# --- the discover()-derived row ----------------------------------------------------------


def _access_control_caps_row(caps: DeviceCapabilities) -> SurfaceProbe:
    """Row for `GET /ISAPI/AccessControl/capabilities`, verdict honest to its source.

    `discover()` fetched it and kept raw-or-error: `access_control_error` is set to
    a "not advertised" sentence exactly on `IsapiNotFound`, to the error text on any
    other transport failure, and to None on success — so the verdict here maps onto
    the transport's typed failure and cannot silently drift.
    """
    path = "/ISAPI/AccessControl/capabilities"
    if caps.access_control_raw is not None and caps.access_control_error is None:
        return SurfaceProbe(
            key="caps_access_control",
            endpoint="access_control_capabilities",
            method="GET",
            path=path,
            verdict=Verdict.OK,
        )
    error = caps.access_control_error or ""
    verdict = Verdict.NOT_SUPPORT if "not advertised" in error else Verdict.ERROR
    return SurfaceProbe(
        key="caps_access_control",
        endpoint="access_control_capabilities",
        method="GET",
        path=path,
        verdict=verdict,
        note=error or "no AccessControl capabilities body",
    )


# --- the individual surfaces -------------------------------------------------------------


def _probe_clock(
    client: Any,
    matrix: CapabilityMatrix,
    surfaces: list[SurfaceProbe],
    *,
    now: datetime,
    site_tz: str,
) -> CapabilityMatrix:
    """GET System/time -> wall-clock skew for the §5.1a gate (module docstring: why wall).

    The read goes through `pipeline.device_time_reading` — the p1-11 path the design
    names — so this probe and `gateclerk device time` can never disagree about what
    the device's clock said.
    """
    from gateclerk.endpoints import endpoint_for

    ep = endpoint_for("system_time")
    try:
        reading, _raw = device_time_reading(client)
    except IsapiAuthError as exc:
        raise ProbeAbortedError(
            f"capability probe aborted at surface 'clock': auth refused ({exc}); §0.5"
        ) from exc
    except (IsapiError, IsapiPayloadError) as exc:
        surfaces.append(_error_row("clock", "system_time", ep.path, "GET", exc))
        return replace(matrix, clock_note=f"System/time unreadable: {exc}")
    surfaces.append(
        SurfaceProbe(
            key="clock", endpoint="system_time", method="GET", path=ep.path, verdict=Verdict.OK
        )
    )
    skew = compute_skew(reading, our_now=now, site_tz=site_tz)
    return replace(
        matrix,
        clock_skew_s=skew.skew_seconds,
        clock_device_wall=None if skew.device_wall is None else skew.device_wall.isoformat(),
        clock_claimed_offset_min=reading.claimed_offset_minutes,
        clock_note=skew.reason or reading.note,
    )


def _probe_caps(
    client: Any,
    matrix: CapabilityMatrix,
    caps_raw: dict[str, Mapping[str, Any]],
    surfaces: list[SurfaceProbe],
    *,
    key: str,
    endpoint: str,
) -> tuple[CapabilityMatrix, dict[str, Mapping[str, Any]]]:
    """One capabilities GET: the body is recorded verbatim as a CLAIM, nothing inferred.

    (v4: bench A's FDLib caps say `isSuportFDSearch=false` while FDSearch works —
    caps bodies are evidence of what the device SAYS, never of what it DOES.)
    """
    body = _call(client, surfaces, key=key, endpoint=endpoint, method="GET")
    if body is not None:
        caps_raw[key] = body
    return matrix, caps_raw


def _probe_users(
    client: Any,
    matrix: CapabilityMatrix,
    surfaces: list[SurfaceProbe],
    *,
    caps: DeviceCapabilities,
) -> tuple[CapabilityMatrix, tuple[str, ...]]:
    """POST UserInfo/Search once: OK-checked count + the ONLY templateNo evidence (§3).

    v4 dialect (OBSERVED.md, live-proven): body MUST be wrapped —
    `{"UserInfoSearchCond":{searchID,...}}` — flat bodies 400 `badJsonContent`. The
    fake enforces that; the probe always sends the wrapped form.
    """
    body = _call(
        client,
        surfaces,
        key="users",
        endpoint="user_info_search",
        method="POST",
        payload=_search_cond(caps, cond_key="UserInfoSearchCond"),
    )
    count, records, note = _search_result(
        body, envelope_key="UserInfoSearch", record_key="UserInfo"
    )
    if body is not None and note is not None:
        surfaces[-1] = replace(surfaces[-1], verdict=Verdict.ERROR, note=note)
        return replace(matrix, users_count=None), ()
    employee_nos = tuple(
        str(r["employeeNo"]) for r in records if isinstance(r.get("employeeNo"), str)
    )
    return (
        replace(matrix, users_count=count, template_nos=tuple(sorted(_template_nos(records)))),
        employee_nos,
    )


def _probe_cards(
    client: Any,
    matrix: CapabilityMatrix,
    surfaces: list[SurfaceProbe],
    *,
    caps: DeviceCapabilities,
) -> CapabilityMatrix:
    """POST CardInfo/Search once (A answered NO MATCH — 0 cards; read path exercised)."""
    body = _call(
        client,
        surfaces,
        key="cards",
        endpoint="card_info_search",
        method="POST",
        payload=_search_cond(caps, cond_key="CardInfoSearchCond"),
    )
    count, _records, note = _search_result(
        body, envelope_key="CardInfoSearch", record_key="CardInfo"
    )
    if body is not None and note is not None:
        surfaces[-1] = replace(surfaces[-1], verdict=Verdict.ERROR, note=note)
        return replace(matrix, cards_count=None)
    return replace(matrix, cards_count=count)


def _probe_simple(
    client: Any,
    surfaces: list[SurfaceProbe],
    *,
    key: str,
    endpoint: str,
    method: str,
    cond_key: str | None = None,
) -> None:
    """One request, one verdict row, no derived data (detail/fp-search/plan/caps-404s)."""
    payload = None if cond_key is None else {cond_key: {"searchResultPosition": 0, "maxResults": 1}}
    _call(client, surfaces, key=key, endpoint=endpoint, method=method, payload=payload)


def _probe_face_libs(
    client: Any, matrix: CapabilityMatrix, surfaces: list[SurfaceProbe]
) -> CapabilityMatrix:
    """GET Intelligent/FDLib: the FDID inventory (§1: FDID 1 blackFD, 2 infraredFD)."""
    body = _call(client, surfaces, key="face_libs", endpoint="fd_lib", method="GET")
    if body is None:
        return matrix
    entries = _find_record_list(body, must_contain="FDID")
    fdids: list[str] = []
    names: list[str] = []
    for entry in entries:
        fdid = entry.get("FDID")
        if fdid is None:
            continue
        fdids.append(str(fdid))
        name = entry.get("name") or entry.get("faceLibType")
        if name is not None:
            names.append(str(name))
    return replace(matrix, face_fdids=tuple(fdids), face_lib_names=tuple(names))


def _probe_face_records(
    client: Any,
    matrix: CapabilityMatrix,
    surfaces: list[SurfaceProbe],
    *,
    caps: DeviceCapabilities,
) -> CapabilityMatrix:
    """POST FDSearch once with the PROVEN FLAT body — availability from the CALL.

    v4/OBSERVED (2026-10-21): the working dialect is FLAT (no cond wrapper):
    `{"searchResultPosition":0,"maxResults":30,"faceLibType":"blackFD","FDID":"1"}`.
    The wrapped dialect is what 400'd in the earlier rounds — the fake rejects
    wrapped exactly like the device did, and this module never sends one.
    `FDID`/`faceLibType` come from the FDLib GET's answer; without it we refuse to
    guess the body (OBSERVED: ~8 guessed shapes all 400'd) and record ERROR-not-sent,
    spending zero requests.
    """
    from gateclerk.endpoints import endpoint_for

    ep = endpoint_for("fd_search")
    if not matrix.face_fdids:
        surfaces.append(
            _not_sent_row(
                "face_records",
                "fd_search",
                ep.path,
                "POST",
                "FDLib GET gave no FDID list; refusing to guess the FDSearch body "
                "(§0.7 fail closed — no request spent)",
            )
        )
        return replace(matrix, face_search_available_by_call=False)
    fdid = matrix.face_fdids[0]
    face_lib_type = matrix.face_lib_names[0] if matrix.face_lib_names else "blackFD"
    cond: dict[str, Any] = {
        "searchResultPosition": 0,
        "maxResults": caps.clamp_max_results(30),
        "faceLibType": face_lib_type,
        "FDID": fdid,
    }
    body = _call(
        client, surfaces, key="face_records", endpoint="fd_search", method="POST", payload=cond
    )
    if body is None:
        return replace(matrix, face_search_available_by_call=False)
    # The verdict (availability) came with the OK; `modelData` rows are found by
    # bounded walk rather than one hardcoded envelope key — OBSERVED records the ROW
    # shape ({FPID, faceURL, modelData}) but not the wrapper name, and betting on a
    # wrapper is how a working endpoint gets recorded as exporting nothing.
    records = _find_record_list(body, must_contain="modelData") or _find_record_list(
        body, must_contain="FPID"
    )
    return replace(
        matrix,
        face_search_available_by_call=True,
        face_template_exportable=_has_key_in(records, "modelData"),
    )


def _probe_fp_read(
    client: Any,
    matrix: CapabilityMatrix,
    surfaces: list[SurfaceProbe],
    *,
    caps: DeviceCapabilities,
    employee_nos: tuple[str, ...],
) -> CapabilityMatrix:
    """POST FingerPrintUpload-Cond once: the PROVEN fingerprint READ (v4, §1).

    Misleading name — device→client — and shape-strict on the device's truth: the
    `FingerPrintCond` wrapper with `searchID`+`employeeNo`+`fpIndex`+
    `dataType:"template"` is required (plain body → 400 `MessageParametersLack
    FingerPrintCond`, OBSERVED.md). The probe reads the FIRST UserInfo's employeeNo
    (enough to discover whether templates are readable on this fw; E1-05's export
    walks every person separately); the employeeNo itself is NOT persisted (PII).
    """
    from gateclerk.endpoints import endpoint_for

    ep = endpoint_for("finger_print_upload")
    if not employee_nos:
        surfaces.append(
            _not_sent_row(
                "fingerprints_read",
                "finger_print_upload",
                ep.path,
                "POST",
                "no employeeNo discovered (UserInfo/Search not OK or roster empty); "
                "FP read not probed — §0.7 fail closed, zero requests spent",
            )
        )
        return replace(matrix, fp_templates_readable=False)
    body = _call(
        client,
        surfaces,
        key="fingerprints_read",
        endpoint="finger_print_upload",
        method="POST",
        payload={
            "FingerPrintCond": {
                "searchID": caps.make_search_id("gateclerk-e1-"),
                "employeeNo": employee_nos[0],
                "fpIndex": 0,
                "dataType": "template",
            }
        },
    )
    if body is None:
        return replace(matrix, fp_templates_readable=False)
    entries = _find_record_list(body, must_contain="fingerData")
    return replace(
        matrix,
        fp_templates_readable=any(str(entry.get("fingerData") or "").strip() for entry in entries),
    )


# --- search-envelope reading (§0.7: OK-checked or it is not a count) ---------------------


_SEARCH_OK_STATUSES = frozenset({"ok", "more"})
_SEARCH_EMPTY_STATUS = "no match"


def _search_cond(caps: DeviceCapabilities, *, cond_key: str) -> dict[str, Any]:
    """A minimal, legal WRAPPED search body — searchID is REQUIRED on this fw (§1)."""
    return {
        cond_key: {
            "searchID": caps.make_search_id("gateclerk-e1-"),
            "searchResultPosition": 0,
            "maxResults": caps.clamp_max_results(30),
        }
    }


def _search_result(
    body: Mapping[str, Any] | None, *, envelope_key: str, record_key: str
) -> tuple[int | None, list[Mapping[str, Any]], str | None]:
    """(count, records, note) from a search envelope — §0.7's OK check lives here.

    `count` is None (never 0!) unless the device said so: `OK`/`MORE` carry
    `totalMatches`, `NO MATCH` (the space spelling OBSERVED.md records, with the
    record key ABSENT rather than empty) is the device's own verified zero. A 200
    under the wrong envelope key or a missing `responseStatusStrg` is a note — the
    caller downgrades the row to ERROR rather than reporting "0 users".
    """
    if body is None:
        return None, [], None
    envelope = body.get(envelope_key)
    if not isinstance(envelope, Mapping):
        return None, [], f"200 without {envelope_key!r} envelope — not a search answer"
    status = str(envelope.get("responseStatusStrg") or "").strip().lower()
    if status in _SEARCH_OK_STATUSES:
        count = _as_opt_int(envelope.get("totalMatches"))
        note = None if count is not None else f"{status!r} without totalMatches"
        records = [r for r in (envelope.get(record_key) or []) if isinstance(r, Mapping)]
        return count, records, note
    if status == _SEARCH_EMPTY_STATUS:
        return 0, [], None
    return None, [], f"unexpected responseStatusStrg {status!r}"


def _template_nos(records: Iterable[Mapping[str, Any]]) -> set[str]:
    """Union of templateNos from UserInfo RightPlan entries — the only evidence that
    exists (§1 v4: PlanTemplate is notSupport, so nothing else can say which presets
    exist; bench A references "1" from every person). Both wire spellings are read;
    nothing is synthesized."""
    out: set[str] = set()
    for record in records:
        plans = record.get("RightPlan")
        entries = (
            [plans] if isinstance(plans, Mapping) else (plans if isinstance(plans, list) else [])
        )
        for plan in entries:
            if not isinstance(plan, Mapping):
                continue
            value = plan.get("planTemplateNo")
            if value is None:
                value = plan.get("templateNo")
            if value is not None and str(value).strip():
                out.add(str(value).strip())
    return out


def _has_key_in(records: list[Mapping[str, Any]], name: str) -> bool:
    return any(str(record.get(name) or "").strip() for record in records)


# --- bounded body walks (never one hardcoded root: shapes vary per fw) -------------------


def _find_record_list(
    payload: Mapping[str, Any], *, must_contain: str, depth: int = 0
) -> list[Mapping[str, Any]]:
    if depth > 4:
        return []
    for value in payload.values():
        if isinstance(value, list):
            entries = [item for item in value if isinstance(item, Mapping)]
            if entries and any(must_contain in item for item in entries):
                return entries
        elif isinstance(value, Mapping):
            found = _find_record_list(value, must_contain=must_contain, depth=depth + 1)
            if found:
                return found
    return []


def _time_type_opts(user_caps: Mapping[str, Any]) -> tuple[str, ...]:
    """`Valid.timeType @opt` from the UserInfo caps body (v4: bench A = "local" only).

    Bounded walk (the caps nesting depth is not a constant we get to assume); an
    absent field stays () — absence is recorded as absence, never defaulted.
    """

    def walk(node: Mapping[str, Any], depth: int) -> tuple[str, ...]:
        if depth > 4:
            return ()
        valid = node.get("Valid")
        if isinstance(valid, Mapping):
            time_type = valid.get("timeType")
            table = time_type if isinstance(time_type, Mapping) else {}
            opt = table.get("@opt", table.get("opt"))
            if isinstance(opt, str) and opt.strip():
                return tuple(part.strip() for part in opt.split(",") if part.strip())
        for value in node.values():
            if isinstance(value, Mapping):
                found = walk(value, depth + 1)
                if found:
                    return found
        return ()

    return walk(user_caps, 0)


# --- persistence + the freshness gate (§4) -------------------------------------------------

_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def _slug(value: str) -> str:
    """Filesystem-safe label; a host can never walk out of probes/ with `../`."""
    return _UNSAFE_NAME.sub("-", value).strip("-._") or "unknown"


def probe_file_name(site: str, host: str) -> str:
    return f"{_slug(site)}-{_slug(host)}.json"


def probes_dir(root: str | os.PathLike[str]) -> Path:
    return Path(root) / "probes"


def save_matrix(matrix: CapabilityMatrix, root: str | os.PathLike[str]) -> Path:
    """Persist under `<root>/probes/<site>-<host>.json`, dir 0700 / file 0600 (§2 hygiene).

    §9.1 finding 1 (E1-08, live-validated): the probe document is PII-adjacent — the
    device host rides in the FILENAME and identity evidence rides inside — and the
    default root resolves under `~/gateclerk`, which on the ops box is a git repo. So the
    persist passes through `migrate_bundle`'s repo-out guard, the SAME shared seam
    `export --out` refuses through (§2 "REFUSE an --out inside the repo"). Reused, not
    re-expressed (§5a no-duplication): the call goes through the module attribute, so
    one guard governs every persist seam and stubbing it stubs this one too. Journals
    keep their own `_refuse_repo_path` (migrate_write) — untouched here.
    """
    directory = probes_dir(root)
    # The dir, not the final file: `_slug` keeps the name inside probes/, so refusing
    # the dir refuses every file this function can write — BEFORE the first mkdir.
    migrate_bundle._refuse_repo_out(directory)
    directory.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):  # exotic filesystems; content still written
        directory.chmod(0o700)
    path = directory / probe_file_name(matrix.site, matrix.host)
    path.write_text(matrix.as_json() + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def load_matrix(root: str | os.PathLike[str], site: str, host: str) -> CapabilityMatrix | None:
    """Read a persisted matrix; None when the probe simply is not there.

    A file that EXISTS but cannot be parsed is a `ProbeStaleError`, not a None: the
    gate refuses to treat a corrupt artifact as "no probe yet, go make one" — the
    difference matters because the remedy for a corrupt probe is a human looking at
    it, not silently trusting whatever wrote it.
    """
    path = probes_dir(root) / probe_file_name(site, host)
    if not path.exists():
        return None
    try:
        return CapabilityMatrix.from_dict(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError) as exc:
        raise ProbeStaleError(
            f"probe file {path} is unreadable ({exc}); re-probe required"
        ) from exc


def require_fresh(
    matrix: CapabilityMatrix | None,
    now: datetime,
    max_age_s: float = DEFAULT_PROBE_MAX_AGE_S,
) -> CapabilityMatrix:
    """THE freshness gate E1-02/E1-04 import (§4): stale or missing probe = refused.

    Fail-closed on every doubt: no probe, unparseable stamp, naive stamp (we cannot
    place it against `now` honestly), older than `max_age_s` (default 7 d), or
    stamped implausibly in the future. `now` is injected, so a test — and the apply
    path — decides what "now" is.
    """
    if now.tzinfo is None:
        raise TimestampInputError("require_fresh needs a tz-aware injected `now`")
    if matrix is None:
        raise ProbeStaleError(
            "no capability probe found — the device has never been probed (or the "
            "probe file was removed); run `gateclerk migrate probe` first (design §3: "
            "never write to a device we have not probed)"
        )
    probed = matrix.probed_at_instant()
    if probed is None:
        raise ProbeStaleError(
            f"probe for {matrix.site or '?'}/{matrix.host or '?'} carries no readable "
            f"probed_at ({matrix.probed_at!r}); staleness cannot be evaluated (§4)"
        )
    if probed.tzinfo is None:
        raise ProbeStaleError(
            f"probe probed_at {matrix.probed_at!r} is naive; we refuse to compare a "
            "zone-less stamp against the injected clock (§4, fail closed)"
        )
    age_s = (now.astimezone(UTC) - probed.astimezone(UTC)).total_seconds()
    if age_s < -_MAX_FUTURE_TOLERANCE_S:
        raise ProbeStaleError(
            f"probe for {matrix.site or '?'}/{matrix.host or '?'} is stamped "
            f"{-age_s:.0f}s in the future — clock or file integrity problem; re-probe"
        )
    if age_s > max_age_s:
        raise ProbeStaleError(
            f"probe for {matrix.site or '?'}/{matrix.host or '?'} is {age_s / 3600:.1f}h "
            f"old (max {max_age_s / 3600:.1f}h) — staleness is not trusted (design §4); "
            "re-probe before diff/apply"
        )
    return matrix


def require_fresh_probe(
    root: str | os.PathLike[str],
    site: str,
    host: str,
    now: datetime,
    max_age_s: float = DEFAULT_PROBE_MAX_AGE_S,
) -> CapabilityMatrix:
    """`load_matrix` + `require_fresh` in one call — the shape E1-04's apply uses."""
    return require_fresh(load_matrix(root, site, host), now, max_age_s=max_age_s)


# --- coercion (None means the device did not SAY it, never a defaulted guess) -------------


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _opt_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _as_opt_str(value: Any) -> str | None:
    return _opt_str(value)


def _as_opt_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        return int(text)
    except ValueError:
        return None


def _as_opt_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
