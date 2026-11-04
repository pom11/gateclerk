"""Named sinks: the `[[site.sink]]` registry — one site, several delivery targets.

Card SINKS-CORE (operator product goal: replace the one-per-site `push_target` with NAMED
SINKS). This module is the CONFIG half of that: parse the sink blocks, validate them
against a registry keyed by type, and hand the rest of the system a tuple of `SinkSpec`.
It does not send anything — the queue and the drain keep their own machinery, and the
wiring card (SINKS-WIRING) is what feeds these specs to it.

Why a registry instead of an `if type == "https"` chain
-------------------------------------------------------
The card's requirement is that MORE types can be added without touching the queue. That
holds only if the queue depends on nothing type-specific, so the contract with the queue
is exactly two fields of `SinkSpec`:

* `name` — the sink's IDENTITY. `push_queue`/`dead_letter` key on `(event_id, sink_name)`,
  and the name is stable across restarts (never derived from the ref: an ingest URL that
  moves must not orphan the backlog addressed to it).
* `ref`  — the PHYSICAL target as one string (`https://…`, `stub://…`, `file:///…`).

Everything else (`headers`, `token_env`, `rotation`, `path`) is for the sink's own writer,
and a new type adds a registry entry declaring its keys — no branch elsewhere.

The three shipped types
-----------------------
`https`  url + optional custom headers + optional token REFERENCES. Keeps Task 15's wire
         contract untouched (POST, `Content-Type: application/jsonl`, `Authorization
         Bearer <token>`, `X-Gateclerk-Site` confirmation); the transport is unchanged by
         this module. The token is a REF only, never a value: `token_env` names an
         environment variable, `token_keychain` names a keychain service, and the
         resolver's default rungs stay exactly T15's per-site ones
         (`GATECLERK_INGEST_TOKEN_<SITE>` / `gateclerk-ingest-<site>`) — see IMPLICIT_SINK_NAME.
`csv`    an absolute local path, rotation `daily|monthly`, and the STABLE columns below.
`jsonl`  an absolute local path, rotation `daily|monthly`, one payload line per row.

CSV columns (STABLE — documented here because a downstream reader codes against them)
-------------------------------------------------------------------------------------
`CSV_COLUMNS` is the header row, in this order, and it is append-only like the payload
contract it embeds:

* `event_id`    the `events.id` this line was pushed for — the join back to the store.
* `sink_name`   which sink accepted it (a row read out of a shared archive directory must
                be attributable without re-reading the config).
* `enqueued_at` when the queue buffered it (UTC, ISO, second resolution — the same stamp
                the queue row carries), so a reader can tell queue lag from event time.
* then EVERY key of `model.RECORD_JSON_KEYS`, in the contract's own order. The record
  contract is append-only (renaming a key is a spec discussion), so a reader's column
  index for any named field is stable forever. `raw` is the device dict as JSON text and
  carries commas and quotes: it is a quoted CSV field and MUST stay the LAST field that
  can contain a comma or a quote — the tuple puts `captured_at` after it (`raw` is
  second-to-last, being record field order with `captured_at` the final EventRecord
  field), so a naive splitter that stops at the first unquoted comma still reads the
  named fields.

Backward compat (the law this module exists to obey)
----------------------------------------------------
A site with only `push_target` gets ONE implicit https sink named `legacy`
(`SiteConfig.effective_sinks`), so a live site needs ZERO config change at upgrade. That
name is a contract with the storage layer: the v5/v6 migrations stamp it onto every
pre-upgrade queue and dead-letter row. Declaring both `push_target` and `[[site.sink]]`
is refused — two sources for one site's sinks would either double-push or silently drop
the legacy target, and neither is a state an operator should discover in a payroll export.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from gateclerk.config import PUSH_TARGET_SCHEMES
from gateclerk.exceptions import ConfigError
from gateclerk.model import RECORD_JSON_KEYS

__all__ = [
    "CSV_COLUMNS",
    "CSV_COLUMNS_DOC",
    "DEFAULT_ROTATION",
    "IMPLICIT_SINK_NAME",
    "ROTATIONS",
    "SINK_TYPES",
    "SINK_URL_SCHEMES",
    "SinkSpec",
    "SinkType",
    "parse_site_sinks",
    "register_sink_type",
    "sink_name_problem",
]

#: The sink a site gets when it declares only `push_target` — the backward-compat name.
#:
#: Fixed, documented and never computed: `push_queue.sink_name` and `dead_letter.sink_name`
#: carry it for every row that existed before named sinks shipped, so "which sink was this
#: site's original push target" stays answerable in a five-year-old db. A configured sink
#: may not take this name (refused), which keeps it unique.
IMPLICIT_SINK_NAME = "legacy"

#: The rotation policies a file sink may ask for. `daily` is the default (see
#: `DEFAULT_ROTATION`): a month-long outage then lands in ~30 files instead of one giant
#: one, and a day's data is the smallest unit an operator re-delivers by hand.
ROTATIONS = ("daily", "monthly")
DEFAULT_ROTATION = "daily"

#: The URL schemes an `https` sink may name. It IS `config.PUSH_TARGET_SCHEMES` — one
#: tuple, one law (§3: real HTTPS or the owner-authorized local stub; `http://` would put
#: a bearer token on the wire in clear text, and no endpoint may ever be invented).
SINK_URL_SCHEMES = PUSH_TARGET_SCHEMES

#: A sink name is used as a sqlite column VALUE (safe: parameters, never string SQL), as a
#: log-line token, and as the value of the CSV `sink_name` column — so it is a plain
#: identifier. Spaces, separators and dots would make all three ambiguous (and a name
#: containing a `,` would corrupt the CSV row this module promises is stable).
_SINK_NAME = re.compile(r"^[A-Za-z0-9_]+$")


def sink_name_problem(name: object) -> str | None:
    """`None` when `name` is a usable sink identity, else a refusal naming the rule.

    Shared with the queue on purpose: a name the queue accepts must be one the config
    could have produced, or the two layers could disagree about which rows are addressable.
    """
    if not isinstance(name, str) or not name.strip():
        return "sink name must not be empty (each sink is addressed by name)"
    if name != name.strip():
        return f"sink name {name!r} has leading or trailing whitespace"
    if not _SINK_NAME.match(name):
        return (
            f"sink name {name!r} is not a valid identifier: use letters, digits and "
            "underscore only (the name lands in a sqlite key, a log line and the CSV "
            "sink_name column)"
        )
    return None


@dataclass(frozen=True, slots=True)
class SinkSpec:
    """One parsed sink. The queue reads `name` + `ref`; everything else is the writer's.

    Frozen so a parsed config cannot be edited mid-run (a sink whose ref changed between
    enqueue and drain would send a queued punch somewhere nobody configured). `headers` is
    a read-only mapping for the same reason: a dict handed to a transport and then mutated
    by the caller is a header set that differs from the one that was validated.
    """

    name: str
    type: str
    ref: str
    # --- https-only (None / empty on a file sink, so the drain's bearer branch can ask
    #     directly instead of `getattr`-ing around a type it should not know about) -------
    #: An environment variable NAME holding the bearer token (a REF, never a value).
    token_env: str | None = None
    #: A keychain SERVICE name holding the bearer token (a REF, never a value).
    token_keychain: str | None = None
    #: Extra request headers. `Authorization` and `X-Gateclerk-Site` may not appear here
    #: (refused at parse time): the first would put a bearer in a committed config and
    #: fight the transport's own header, the second would let a config claim another site.
    headers: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    # --- file-sink-only ---------------------------------------------------------------
    #: `daily` | `monthly` (None for a sink that does not rotate).
    rotation: str | None = None
    #: The declared absolute path a file sink writes (also carried inside `ref` as
    #: `file://<path>`, because `ref` is the one field the queue is allowed to read).
    path: str | None = None
    # --- shared, and only honoured by the roster leg ----------------------------------
    #: Whether the hourly `device_users` roster is delivered to this sink too.
    #:
    #: Default True: a sink an operator configured is a place site data goes, and a roster
    #: that quietly skipped it would be a gap discovered in a review. Flipped to False for a
    #: sink that is only ever meant to hold punches (an archive payroll reconciles against
    #: event rows, where roster lines would be foreign rows in a documented table). It is
    #: decided at parse time so the drain never has to re-read the config mid-pass.
    accepts_roster: bool = True


def sink_spec_problem(spec: SinkSpec) -> str | None:
    """`None` when a hand-built `SinkSpec` could actually be drained, else a refusal.

    `parse_site_sinks` already validates everything it produces; this exists because
    `SiteConfig` may also be built in code, and every config key in this repo obeys the
    rule that constructing the object cannot escape validation. The four things that make
    a spec undrainable are checked here: an unregistered type (nothing would ever write
    it), an empty ref (a row nobody can address), headers that would fight the transport's
    own two headers, and a rotation value the file writer has no rule for.
    """
    if sink_name_problem(spec.name) is not None:
        return None  # the caller reports the name problem; one message per fault
    if spec.type not in SINK_TYPES:
        known = " or ".join(sorted(SINK_TYPES))
        return (
            f"sink {spec.name!r} has type {spec.type!r}, which is not registered "
            f"(accepted: {known}) — an unregistered type is a sink nothing will ever write"
        )
    if not isinstance(spec.ref, str) or not spec.ref.strip():
        return f"sink {spec.name!r} has an empty ref: a queue row must name a target"
    for key in spec.headers:
        lowered = key.strip().lower()
        if lowered in ("authorization", "x-gateclerk-site"):
            return (
                f"sink {spec.name!r} declares a {key!r} header: the bearer token and the "
                "site confirmation are the transport's own headers (and a token in a "
                "committed config is the mistake this seam exists to prevent)"
            )
    if spec.rotation is not None and spec.rotation not in ROTATIONS:
        return (
            f"sink {spec.name!r} has rotation {spec.rotation!r} (accepted: "
            f"{' or '.join(ROTATIONS)})"
        )
    return None


@dataclass(frozen=True, slots=True)
class SinkType:
    """One registry entry: what a type is called, the keys it accepts, how to build it.

    `build` receives the validated sink table and the site name and returns
    `(ref, extras)` — `ref` is the physical target string the queue will store, `extras`
    are `SinkSpec` keyword arguments for the fields only this type uses. A new type adds an
    entry here and touches nothing else.
    """

    name: str
    #: Every key this type understands (anything else in the block is refused loudly).
    keys: tuple[str, ...]
    #: The keys that must be present.
    required: tuple[str, ...]
    build: Callable[[Mapping[str, Any], str], tuple[str, Mapping[str, Any]]]


# --- the registry ----------------------------------------------------------------------------

SINK_TYPES: dict[str, SinkType] = {}


def register_sink_type(entry: SinkType) -> None:
    """Add a sink type to the registry. An existing name is refused, never replaced.

    Overwriting `https` would move Task 15's wire contract (and the queue rows already
    addressed to it) under whoever is adding a type — that is a reviewed edit to this
    module, not a side effect of a registration call.
    """
    if entry.name in SINK_TYPES:
        raise ConfigError(
            f"sink type {entry.name!r} is already registered: redefine it in "
            "gateclerk.sinks (a registered type is the identity of queue rows that already "
            "carry that name), never by replacing it at runtime"
        )
    if sink_type_problem(entry) is not None:  # pragma: no cover - guarded at parse time
        raise ConfigError(sink_type_problem(entry) or "")
    SINK_TYPES[entry.name] = entry


def sink_type_problem(entry: SinkType) -> str | None:
    """A registry entry that could not work is a bug, so it is checked where it registers."""
    if not entry.name or not _SINK_NAME.match(entry.name):
        return f"sink type name {entry.name!r} is not a valid identifier"
    if set(entry.required) - set(entry.keys):
        return (
            f"sink type {entry.name!r} requires a key it does not declare: "
            f"{sorted(set(entry.required) - set(entry.keys))}"
        )
    return None


# --- validation helpers -----------------------------------------------------------------------


def _text(table: Mapping[str, Any], key: str, *, site: str, sink: str) -> str:
    value = table[key]
    if not isinstance(value, str):
        raise ConfigError(
            f"site {site!r} sink {sink!r}: {key} must be a string, got {type(value).__name__}"
        )
    if not value.strip():
        raise ConfigError(f"site {site!r} sink {sink!r}: {key} must not be empty")
    return value


def _headers(table: Mapping[str, Any], *, site: str, sink: str) -> Mapping[str, str]:
    """Custom headers, validated for the two things that make them dangerous.

    A header VALUE that is not a string would raise inside the transport on the first
    send — i.e. during the outage the agent is already fighting — and `Authorization` /
    `X-Gateclerk-Site` are the transport's own two headers: the first is the bearer token
    (which has exactly one home: the ref rungs), the second is the site confirmation the
    ingest cross-checks against the token (a config that could set it could claim another
    site with this site's credentials).
    """
    raw = table.get("headers", {})
    if not isinstance(raw, Mapping):
        raise ConfigError(
            f"site {site!r} sink {sink!r}: headers must be a table of string values, got "
            f"{type(raw).__name__}"
        )
    out: dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not key.strip():
            raise ConfigError(
                f"site {site!r} sink {sink!r}: header names must be non-empty strings"
            )
        if not isinstance(value, str):
            raise ConfigError(
                f"site {site!r} sink {sink!r}: header {key!r} must be a string value, got "
                f"{type(value).__name__} (a header goes on the wire as bytes)"
            )
        lowered = key.strip().lower()
        if lowered == "authorization":
            raise ConfigError(
                f"site {site!r} sink {sink!r}: headers may not carry Authorization — the "
                "bearer token has exactly one home, `token_env` / `token_keychain` (a "
                "reference), and the transport sets the header itself"
            )
        if lowered == "x-gateclerk-site":
            raise ConfigError(
                f"site {site!r} sink {sink!r}: headers may not carry X-Gateclerk-Site — it "
                "confirms the site the token already determines, and a config that could "
                "set it could claim another site"
            )
        out[key] = value
    return MappingProxyType(out)


def _file_path(table: Mapping[str, Any], *, site: str, sink: str) -> str:
    """An absolute, traversal-free path for a file sink.

    Absolute because a relative path under a systemd unit resolves against
    `WorkingDirectory` — deployment state an operator reading this line cannot see, and a
    payroll archive that silently lives somewhere else is a compliance problem, not a
    convenience. `..` because a declared data path must be auditable from the line the
    operator wrote.
    """
    value = _text(table, "path", site=site, sink=sink)
    if not value.startswith("/"):
        raise ConfigError(
            f"site {site!r} sink {sink!r}: path {value!r} must be absolute — a relative "
            "path resolves against the service's working directory, which is deployment "
            "state, not config"
        )
    if ".." in value.split("/"):
        raise ConfigError(
            f"site {site!r} sink {sink!r}: path {value!r} contains `..` — a declared data "
            "path must be auditable from the line that declares it"
        )
    return value


def _rotation(table: Mapping[str, Any], *, site: str, sink: str) -> str:
    if "rotation" not in table:
        return DEFAULT_ROTATION
    value = _text(table, "rotation", site=site, sink=sink)
    if value not in ROTATIONS:
        raise ConfigError(
            f"site {site!r} sink {sink!r}: rotation {value!r} is unknown "
            f"(accepted: {' or '.join(ROTATIONS)})"
        )
    return value


def _token_ref(table: Mapping[str, Any], key: str, *, site: str, sink: str) -> str | None:
    """A token REFERENCE (env var name / keychain service), or None for the default rungs.

    Blank is refused rather than treated as absent: `token_env = ""` would resolve the
    empty string as a variable name, which is a rung that can never exist — a missing
    token dressed up as a configured one.
    """
    if key not in table:
        return None
    return _text(table, key, site=site, sink=sink)


# --- the three shipped types ------------------------------------------------------------------


def _accepts_roster(table: Mapping[str, Any], *, site: str, sink: str) -> bool:
    """Whether this sink is a roster destination too (default: yes).

    A non-boolean is refused rather than coerced: `accepts_roster = "no"` is a TOML
    string, and a truthy string would silently switch a sink's roster OFF (or on) in a
    payroll archive — the same class of mistake `rotation` refuses by whitelist.
    """
    if "accepts_roster" not in table:
        return True
    value = table["accepts_roster"]
    if not isinstance(value, bool):
        raise ConfigError(
            f"site {site!r} sink {sink!r}: accepts_roster must be a boolean (true/false), "
            f"got {type(value).__name__} — a roster that is silently included or excluded "
            "is a gap in a documented file"
        )
    return value


def _build_https(table: Mapping[str, Any], site: str) -> tuple[str, Mapping[str, Any]]:
    """An https sink: the url is the ref, the token stays a reference.

    `_check_sink_url` deliberately reuses §3's tuple rather than loosening it for sinks:
    a sink is a new NAME for a target, not a new kind of target, so `http://` and
    scheme-less values are refused exactly as `push_target` refuses them today.
    """
    url = _text(table, "url", site=site, sink=str(table.get("name", "?")))
    if not url.startswith(SINK_URL_SCHEMES):
        allowed = " or ".join(SINK_URL_SCHEMES)
        raise ConfigError(
            f"site {site!r} sink {table.get('name')!r}: url {url!r} has an unacceptable "
            f"scheme: a sink url must start with {allowed} (never a default endpoint — "
            "docs/P2-SITE-AGENT.md §3)"
        )
    sink = str(table.get("name", "?"))
    return url, {
        "token_env": _token_ref(table, "token_env", site=site, sink=sink),
        "token_keychain": _token_ref(table, "token_keychain", site=site, sink=sink),
        "headers": _headers(table, site=site, sink=sink),
        "accepts_roster": _accepts_roster(table, site=site, sink=sink),
    }


def _build_file(kind: str) -> Callable[[Mapping[str, Any], str], tuple[str, Mapping[str, Any]]]:
    """A factory for the two file-backed types: identical rules, different extension prose.

    The ref is MINTED here (`file://` + the validated absolute path) and nowhere else: the
    queue accepts `file://` refs because this function can only produce a clean absolute
    one, so a hand-written `file://` target outside the registry is still impossible.
    """

    def build(table: Mapping[str, Any], site: str) -> tuple[str, Mapping[str, Any]]:
        sink = str(table.get("name", "?"))
        path = _file_path(table, site=site, sink=sink)
        return f"file://{path}", {
            "path": path,
            "rotation": _rotation(table, site=site, sink=sink),
            "accepts_roster": _accepts_roster(table, site=site, sink=sink),
        }

    return build


register_sink_type(
    SinkType(
        name="https",
        keys=("url", "token_env", "token_keychain", "headers", "accepts_roster"),
        required=("url",),
        build=_build_https,
    )
)
register_sink_type(
    SinkType(
        name="csv",
        keys=("path", "rotation", "accepts_roster"),
        required=("path",),
        build=_build_file("csv"),
    )
)
register_sink_type(
    SinkType(
        name="jsonl",
        keys=("path", "rotation", "accepts_roster"),
        required=("path",),
        build=_build_file("jsonl"),
    )
)


# --- the CSV contract -------------------------------------------------------------------------

#: The header row a `csv` sink writes, in order, FOREVER (append-only — see module
#: docstring). `event_id`, `sink_name`, `enqueued_at` then every `RECORD_JSON_KEYS` field.
CSV_COLUMNS: tuple[str, ...] = (
    "event_id",
    "sink_name",
    "enqueued_at",
    *RECORD_JSON_KEYS,
)

#: The prose half of that promise, kept importable so a test can require the columns and
#: their documentation to stay in the same file (an undocumented "stable" column set is a
#: column set that changes the first time someone needs a different order).
CSV_COLUMNS_DOC = """\
csv sink columns (stable, append-only, in this order):
  event_id     events.id this line was pushed for (the join back to the store)
  sink_name    which sink wrote the row (attribution without re-reading the config)
  enqueued_at  when the queue buffered it (UTC ISO, seconds) — queue lag vs event time
  ...then every key of model.RECORD_JSON_KEYS in the contract's own order, ending
               `..., raw, captured_at` — `raw` is SECOND-TO-LAST because the tuple IS the
               record's field order and `captured_at` is the final field of EventRecord.
               (raw is the device dict as JSON text: quoted, and the LAST field that can
               contain a comma or a quote, so a naive splitter still reads every named
               field before it reaches it)
"""


# --- parsing ----------------------------------------------------------------------------------


def parse_site_sinks(tables: Sequence[Any], *, site: str) -> tuple[SinkSpec, ...]:
    """Turn a site block's `[[site.sink]]` tables into validated `SinkSpec`s.

    Loud on every mistake, because a sink that is quietly absent is a punch that quietly
    never arrives:

    * an unknown `type` names the known set (a typo like `s3` must not become "no sinks");
    * a missing `name`/`type` is refused;
    * names must be identifiers, unique within the site, and not the implicit `legacy`;
    * a key that belongs to another type is refused (a copy-paste `url` on a csv sink
      would otherwise decide nothing while looking configured).

    Declaration order is preserved: it is the order SINKS-WIRING will drain in, and a
    config that reads top-to-bottom should behave top-to-bottom.
    """
    specs: list[SinkSpec] = []
    seen: set[str] = set()
    for table in tables:
        if not isinstance(table, Mapping):
            raise ConfigError(f"site {site!r}: a [[site.sink]] entry is not a table")
        for key in ("name", "type"):
            if key not in table:
                raise ConfigError(
                    f"site {site!r}: a [[site.sink]] block is missing required key {key!r}"
                )
        name = _text(table, "name", site=site, sink="?")
        problem = sink_name_problem(name)
        if problem is not None:
            raise ConfigError(f"site {site!r}: {problem}")
        if name == IMPLICIT_SINK_NAME:
            raise ConfigError(
                f"site {site!r}: sink name {IMPLICIT_SINK_NAME!r} is reserved for the "
                "implicit sink a site gets from `push_target` alone"
            )
        if name in seen:
            raise ConfigError(
                f"site {site!r}: duplicate sink name {name!r} — two sinks with one name "
                "would share one queue row and silently merge their targets"
            )
        seen.add(name)

        kind = _text(table, "type", site=site, sink=name)
        entry = SINK_TYPES.get(kind)
        if entry is None:
            known = " or ".join(sorted(SINK_TYPES))
            raise ConfigError(
                f"site {site!r} sink {name!r}: type {kind!r} is unknown (accepted: "
                f"{known}). A sink whose type nobody implements must be refused, never "
                "skipped: a skipped sink is a punch that silently never arrives."
            )
        foreign = sorted(set(table) - set(entry.keys) - {"name", "type"})
        if foreign:
            raise ConfigError(
                f"site {site!r} sink {name!r} (type {kind!r}) has key(s) {foreign} that "
                f"this type does not read (accepted: {sorted(entry.keys)})"
            )
        missing = [key for key in entry.required if key not in table]
        if missing:
            raise ConfigError(
                f"site {site!r} sink {name!r} (type {kind!r}) is missing required key(s) {missing}"
            )
        ref, extras = entry.build(table, site)
        specs.append(SinkSpec(name=name, type=kind, ref=ref, **dict(extras)))
    return tuple(specs)


def implicit_https_sink(ref: str) -> SinkSpec:
    """The one sink a site gets from `push_target` alone (the backward-compat law).

    No `token_env`/`token_keychain`: absence is the signal the resolver reads to fall
    through to Task 15's per-site rungs, which is why a deployed site needs no new
    keychain item (and no config edit) the day this ships.
    """
    return SinkSpec(name=IMPLICIT_SINK_NAME, type="https", ref=ref)
