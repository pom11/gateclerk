"""SINKS-CORE: `[[site.sink]]` named sinks + the type registry (config layer only).

BINDING SPEC: the operator's product goal (replace the one-per-site `push_target` with
NAMED SINKS) + the card's laws, each of which is a section below:

  (1) a site may declare SEVERAL `[[site.sink]]` blocks, each named, each typed
      (`https` | `csv` | `jsonl`), and the type set is a REGISTRY keyed by type so a new
      type can be added without touching the queue;
  (2) an unknown `type` is a LOUD config error (never a silently-ignored sink: a punch
      that silently never reaches a sink is payroll loss);
  (3) an https sink carries url + token REFERENCES (env var NAME / keychain SERVICE —
      never a value) + optional custom headers, and keeps T15's wire contract untouched;
  (4) csv/jsonl sinks carry an absolute path + rotation `daily|monthly`, and the CSV
      columns are STABLE and documented in the module (a downstream reader codes against
      them);
  (5) BACKWARD COMPAT LAW: a site with only `push_target` = one implicit https sink of
      the fixed name `legacy`, so live site-a needs ZERO config change at upgrade.

Nothing here wires the drain (SINKS-WIRING's card): this file is config parsing and the
registry only. Offline by construction: no socket, no keychain (a token is a NAME in a
config string; every credential-shaped value here is a recognisable placeholder per
tests/test_repo_hygiene.py) and every host is TEST-NET or `.invalid`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from gateclerk.agent_push import ingest_keychain_service, ingest_token_env_var
from gateclerk.config import PUSH_TARGET_SCHEMES, ConfigSurface, SiteConfig, load_sites, parse_sites
from gateclerk.exceptions import ConfigError
from gateclerk.model import RECORD_JSON_KEYS
from gateclerk.sinks import (
    CSV_COLUMNS,
    IMPLICIT_SINK_NAME,
    ROTATIONS,
    SINK_TYPES,
    SINK_URL_SCHEMES,
    SinkSpec,
    SinkType,
    register_sink_type,
)

HOST = "192.0.2.10"
SITE = "site-a"
URL = "https://ingest.example.invalid/gateclerk_ingest"


def toml_of(*lines: str) -> bytes:
    """One `[[site]]` block with the given body lines appended verbatim."""
    body = "\n".join((f'name = "{SITE}"', f'host = "{HOST}"', *lines))
    return ("[[site]]\n" + body + "\n").encode("utf-8")


def sink_lines(**fields: Any) -> list[str]:
    """One `[[site.sink]]` sub-table, TOML-encoded (`headers` takes a dict)."""
    out = ["  [[site.sink]]"]
    for key, value in fields.items():
        if isinstance(value, dict):
            rendered = ", ".join(f'{k} = "{v}"' for k, v in value.items())
            out.append(f"  {key} = {{{rendered}}}")
        elif isinstance(value, str):
            out.append(f'  {key} = "{value}"')
        else:  # pragma: no cover - the helpers below only pass strings/dicts
            out.append(f"  {key} = {value}")
    return out


def parse(raw: bytes, *, surface: str = "cli") -> SiteConfig:
    return parse_sites(raw, surface=surface)[SITE]


def sink_of(site: SiteConfig, name: str) -> SinkSpec:
    for sink in site.sinks:
        if sink.name == name:
            return sink
    raise AssertionError(f"no sink named {name!r} in {[s.name for s in site.sinks]}")


# -----------------------------------------------------------------------------------------
# (5) BACKWARD COMPAT LAW first: today's file must mean one sink named `legacy`
# -----------------------------------------------------------------------------------------


def test_push_target_alone_is_the_implicit_sink_with_zero_config_change() -> None:
    """Live site-a's file is byte-identical after the upgrade — that is the law.

    No `[[site.sink]]` line, no new required key, and the sink it gets is an https sink
    aimed at exactly the ref it already pushed to, under the fixed documented name.
    """
    site = parse(toml_of(f'push_target = "{URL}"'))
    assert site.push_target == URL, "the key itself is still parsed (P1/T15 unchanged)"
    assert site.sinks == (), "explicit sinks are ONLY what the file declares"

    effective = site.effective_sinks
    assert [s.name for s in effective] == [IMPLICIT_SINK_NAME]
    assert effective[0].type == "https"
    assert effective[0].ref == URL


def test_implicit_sink_name_is_documented_and_stable() -> None:
    """The name is a contract (the queue's `sink_name` column carries it for every
    pre-upgrade row), so it is a constant, not something computed per site."""
    assert IMPLICIT_SINK_NAME == "legacy"


def test_no_push_target_means_no_sinks_and_stays_inert() -> None:
    """A site that never opted into pushing still has nothing to push (spec §3: no
    endpoint is ever defaulted, so absence means the pusher is off — unchanged)."""
    site = parse(toml_of())
    assert site.push_target is None
    assert site.effective_sinks == ()


def test_implicit_sink_declares_no_token_ref_so_t15s_site_rungs_are_used() -> None:
    """Zero config change must mean zero KEYCHAIN change too.

    An implicit sink carries no explicit token keys, which is the signal the resolver
    reads to fall through to the rungs Task 15 shipped. If those rung NAMES moved, every
    deployed site would need a new keychain item the day this ships — so the names this
    card depends on are pinned here as well as by test_t15_push_https.py.
    """
    site = parse(toml_of(f'push_target = "{URL}"'))
    implicit = site.effective_sinks[0]
    assert implicit.token_env is None and implicit.token_keychain is None
    assert ingest_token_env_var(SITE) == "GATECLERK_INGEST_TOKEN_SITE-A"
    assert ingest_keychain_service(SITE) == "gateclerk-ingest-site-a"


def test_named_https_sink_defaults_to_the_site_rungs_too() -> None:
    """T15's contract is that the bearer DETERMINES the site, so per-site is the natural
    default for every https sink; `token_env` / `token_keychain` name a different rung
    when an operator wants one sink-specific credential."""
    plain = parse(toml_of(*sink_lines(name="bc", type="https", url=URL)))
    assert sink_of(plain, "bc").token_env is None
    assert sink_of(plain, "bc").token_keychain is None


def test_site_with_push_target_and_sinks_is_refused() -> None:
    """Two sources for one site's sinks cannot both win: `push_target` + `[[site.sink]]`
    would either double-push (the same punch accepted twice) or silently drop the legacy
    target. Loud refusal naming both keys is the only honest answer."""
    with pytest.raises(ConfigError) as exc:
        parse(toml_of(f'push_target = "{URL}"', *sink_lines(name="bc", type="https", url=URL)))
    msg = str(exc.value)
    assert "push_target" in msg and "sink" in msg and SITE in msg


# -----------------------------------------------------------------------------------------
# (1) several sinks per site, typed, parsed as data
# -----------------------------------------------------------------------------------------


def test_a_site_may_declare_several_sinks_in_order() -> None:
    raw = toml_of(
        *sink_lines(name="bc", type="https", url=URL),
        *sink_lines(name="archive", type="csv", path="/var/lib/gateclerk/site-a.csv"),
        *sink_lines(name="audit", type="jsonl", path="/var/lib/gateclerk/site-a.jsonl"),
    )
    site = parse(raw)
    assert [s.name for s in site.sinks] == ["bc", "archive", "audit"], "declaration order"
    assert [s.type for s in site.sinks] == ["https", "csv", "jsonl"]
    # The queue's identity is (event_id, sink_name); its physical target is `ref`.
    assert sink_of(site, "bc").ref == URL
    assert sink_of(site, "archive").ref == "file:///var/lib/gateclerk/site-a.csv"
    assert sink_of(site, "audit").ref == "file:///var/lib/gateclerk/site-a.jsonl"


def test_sink_spec_is_frozen_data_with_the_three_fields_the_queue_reads() -> None:
    """The queue may only ever read `name` (identity) and `ref` (physical target) — a
    third field it depends on would mean a new sink type needs a queue change, which the
    registry exists to prevent. `frozen` so a parsed config cannot be edited mid-run."""
    spec = SinkSpec(name="bc", type="https", ref=URL)
    assert spec.name == "bc" and spec.type == "https" and spec.ref == URL
    with pytest.raises((AttributeError, TypeError)):
        spec.ref = "https://elsewhere.invalid/"  # type: ignore[misc]


def test_sink_names_must_be_unique_within_a_site() -> None:
    """Two sinks called `bc` would be one queue row competing with itself: the
    UNIQUE(event_id, sink_name) buffer would silently merge the two targets."""
    with pytest.raises(ConfigError) as exc:
        parse(
            toml_of(
                *sink_lines(name="bc", type="https", url=URL),
                *sink_lines(name="bc", type="jsonl", path="/var/lib/gateclerk/b.jsonl"),
            )
        )
    msg = str(exc.value)
    assert "duplicate" in msg.lower() and "bc" in msg and SITE in msg


@pytest.mark.parametrize("bad", ["", "   ", "not ok", "-lead", "sink/one", "a.b"])
def test_sink_name_must_be_a_safe_identifier(bad: str) -> None:
    """The name lands in a sqlite column value, in log lines and in the CSV `sink_name`
    column — whitespace, separators and dots make all three ambiguous (and a name
    containing a comma would corrupt a CSV row)."""
    with pytest.raises(ConfigError) as exc:
        parse(toml_of(*sink_lines(name=bad, type="jsonl", path="/var/lib/gateclerk/x.jsonl")))
    assert "name" in str(exc.value)


def test_the_implicit_sink_name_is_reserved() -> None:
    """`legacy` is the implicit sink's name; an explicit sink taking it would make
    "which sink was this site's original target" unanswerable in an upgraded db."""
    with pytest.raises(ConfigError) as exc:
        parse(toml_of(*sink_lines(name=IMPLICIT_SINK_NAME, type="jsonl", path="/x.jsonl")))
    assert IMPLICIT_SINK_NAME in str(exc.value)


def test_every_sink_refusal_names_the_site() -> None:
    """A sites.toml may hold many blocks; a refusal that says only "bad sink type"
    cannot be located, so each one carries the site name (repo-wide style)."""
    with pytest.raises(ConfigError, match=SITE):
        parse(toml_of(*sink_lines(name="ok", type="wat", url=URL)))


# -----------------------------------------------------------------------------------------
# (2) the registry: keyed by type, unknown type is LOUD, extensible without the queue
# -----------------------------------------------------------------------------------------


def test_registry_is_keyed_by_type_and_holds_the_three_shipped_types() -> None:
    assert {"https", "csv", "jsonl"} <= set(SINK_TYPES)
    for key, entry in SINK_TYPES.items():
        assert entry.name == key, "the key and the entry agree (no aliasing)"


def test_sink_url_scheme_set_agrees_with_the_push_target_law() -> None:
    """§3 has exactly one set of URL schemes. Two independently maintained tuples would
    drift, and the drift would show up as a sink the validator lets through that the
    transport refuses at send time — i.e. during an outage."""
    assert SINK_URL_SCHEMES == PUSH_TARGET_SCHEMES


def test_unknown_sink_type_is_a_loud_error_naming_the_known_types() -> None:
    """Never a silently-skipped sink: an operator who wrote `type = "s3"` must learn it
    at parse time, not discover the archive is empty at the next payroll review."""
    with pytest.raises(ConfigError) as exc:
        parse(toml_of(*sink_lines(name="cold", type="s3", path="/var/lib/gateclerk/x")))
    msg = str(exc.value)
    assert "s3" in msg, msg
    assert "https" in msg and "csv" in msg and "jsonl" in msg, "the known set is printed"


def test_missing_type_is_refused() -> None:
    with pytest.raises(ConfigError) as exc:
        parse(toml_of(*sink_lines(name="bc", url=URL)))
    assert "type" in str(exc.value)


def test_a_missing_sink_name_is_refused() -> None:
    with pytest.raises(ConfigError) as exc:
        parse(toml_of(*sink_lines(type="jsonl", path="/var/lib/gateclerk/x.jsonl")))
    assert "name" in str(exc.value)


def test_a_new_type_registers_without_touching_the_queue() -> None:
    """The registry's whole purpose: a type added by another card must parse through the
    SAME code path, declaring its own keys. Nothing here edits a shared validation
    branch, and `ref` still comes out as one string the queue can store."""
    try:
        register_sink_type(
            SinkType(
                name="memory",
                keys=("path",),
                required=("path",),
                build=lambda table, site: (f"memory://{table['path']}", {}),
            )
        )
        site = parse(toml_of(*sink_lines(name="buf", type="memory", path="ring")))
        fresh = sink_of(site, "buf")
        assert fresh.type == "memory" and fresh.ref == "memory://ring"
        # The queue-visible surface is still exactly name + ref.
        assert (fresh.name, fresh.ref) == ("buf", "memory://ring")
    finally:
        SINK_TYPES.pop("memory", None)
    assert "memory" not in SINK_TYPES, "the registry entry is removable (test hygiene)"


def test_registering_an_existing_type_is_refused() -> None:
    """Silently replacing `https` would move the wire contract under T15's tests; the
    registry is append-only, and redefining a type is a reviewed edit to the module."""
    with pytest.raises(ConfigError) as exc:
        register_sink_type(
            SinkType(name="https", keys=("url",), required=(), build=lambda t, s: ("", {}))
        )
    assert "https" in str(exc.value)


def test_registry_entry_declares_its_own_keys_and_refuses_foreign_ones() -> None:
    """`url` belongs to an https sink, `path` to a file sink. A sink block carrying the
    other type's key is a copy-paste mistake: refusing it is how the operator finds out
    before a file sink starts writing where nobody declared."""
    with pytest.raises(ConfigError) as exc:
        parse(toml_of(*sink_lines(name="archive", type="csv", url=URL)))
    assert "url" in str(exc.value)
    with pytest.raises(ConfigError) as exc:
        parse(toml_of(*sink_lines(name="bc", type="https", url=URL, path="/var/lib/gateclerk/x.csv")))
    assert "path" in str(exc.value)


# -----------------------------------------------------------------------------------------
# (3) the https sink: url + token REFERENCE + optional headers, wire contract untouched
# -----------------------------------------------------------------------------------------


def test_https_sink_requires_a_url() -> None:
    with pytest.raises(ConfigError) as exc:
        parse(toml_of(*sink_lines(name="bc", type="https")))
    assert "url" in str(exc.value)


@pytest.mark.parametrize(
    "bad",
    ["ftp://x.invalid/y", "http://x.invalid/y", "file:///x", "x.invalid", "HTTPS://x.invalid"],
)
def test_https_sink_refuses_every_scheme_but_the_accepted_ones(bad: str) -> None:
    """§3 unchanged for an https sink: a bearer token never crosses clear text and no
    endpoint is invented. Case matters (`HTTPS://` is a mistake worth a loud error, as
    P2-01 already decides). A file sink's `file://` ref is minted by the registry, never
    written into a url key."""
    with pytest.raises(ConfigError) as exc:
        parse(toml_of(*sink_lines(name="bc", type="https", url=bad)))
    assert "url" in str(exc.value)


def test_https_sink_accepts_the_stub_scheme() -> None:
    """The stub ingest is a real target today (`stub://` in sites.toml) and a sink must
    be able to name it, or upgrading would break every dry-run config."""
    site = parse(toml_of(*sink_lines(name="stub", type="https", url="stub://ingest/a.jsonl")))
    assert sink_of(site, "stub").ref == "stub://ingest/a.jsonl"


def test_push_target_still_refuses_a_file_scheme() -> None:
    """§3 for `push_target` is UNCHANGED: adding a local file sink type must not widen
    what a push target may be (a `file://` push target would let a site "push" punches
    somewhere the drain's transports do not police)."""
    with pytest.raises(ConfigError) as exc:
        parse(toml_of('push_target = "file:///var/lib/gateclerk/x.jsonl"'))
    assert "push_target" in str(exc.value)


def test_https_sink_token_is_a_reference_never_a_value() -> None:
    """`token_env` names an ENV VAR and `token_keychain` names a SERVICE — both are
    references. A literal bearer value in sites.toml is the mistake this whole seam
    exists to make impossible (DESIGN.md 'Credential plumbing')."""
    site = parse(
        toml_of(
            *sink_lines(
                name="bc",
                type="https",
                url=URL,
                token_env="GATECLERK_INGEST_TOKEN_SITE_A_BC",
                token_keychain="gateclerk-ingest-site-a-bc",
            )
        )
    )
    sink = sink_of(site, "bc")
    assert sink.token_env == "GATECLERK_INGEST_TOKEN_SITE_A_BC"
    assert sink.token_keychain == "gateclerk-ingest-site-a-bc"


def test_a_literal_token_key_is_refused_and_points_at_the_two_refs() -> None:
    """There is no `token` key at all, so a config carrying a bearer VALUE cannot parse —
    and the refusal names the two keys that ARE accepted so the fix is one edit."""
    with pytest.raises(ConfigError) as exc:
        parse(toml_of(*sink_lines(name="bc", type="https", url=URL, token="fake-ingest-token-x")))
    msg = str(exc.value)
    assert "token" in msg and "token_env" in msg and "token_keychain" in msg


@pytest.mark.parametrize("blank", ["", "   "])
def test_token_rung_names_must_not_be_blank(blank: str) -> None:
    """`token_env = ""` resolves the empty string as a variable name — a rung that can
    never exist, which reads as "no token" while looking configured."""
    with pytest.raises(ConfigError) as exc:
        parse(toml_of(*sink_lines(name="bc", type="https", url=URL, token_env=blank)))
    assert "token_env" in str(exc.value)
    with pytest.raises(ConfigError) as exc:
        parse(toml_of(*sink_lines(name="bc", type="https", url=URL, token_keychain=blank)))
    assert "token_keychain" in str(exc.value)


def test_https_sink_headers_are_optional_string_pairs() -> None:
    site = parse(
        toml_of(
            *sink_lines(name="bc", type="https", url=URL, headers={"X-Gateclerk-Trace": "sinks-core"})
        )
    )
    assert sink_of(site, "bc").headers == {"X-Gateclerk-Trace": "sinks-core"}


def test_headers_may_not_carry_authorization() -> None:
    """A hand-written `Authorization` header is a bearer token in a committed config —
    and it would fight the transport's own `Authorization: Bearer *** line, which is
    T15's frozen wire contract. The token has exactly one home: the ref rungs."""
    with pytest.raises(ConfigError) as exc:
        parse(
            toml_of(
                *sink_lines(
                    name="bc",
                    type="https",
                    url=URL,
                    headers={"Authorization": "***"},
                )
            )
        )
    msg = str(exc.value)
    assert "Authorization" in msg and "token_env" in msg


def test_headers_may_not_carry_the_site_confirmation_either() -> None:
    """`X-Gateclerk-Site` is the transport's confirmation header (T15: it CONFIRMS the
    token's site, and a contradicting claim is a 403 server-side). A config that could
    set it could claim another site with this site's token."""
    with pytest.raises(ConfigError) as exc:
        parse(
            toml_of(
                *sink_lines(name="bc", type="https", url=URL, headers={"X-Gateclerk-Site": "SITE-B"})
            )
        )
    assert "X-Gateclerk-Site" in str(exc.value)


def test_headers_refuse_a_non_string_value() -> None:
    """Headers go on the wire as bytes; an int would raise inside the transport on the
    first send (i.e. during an outage) instead of at parse time."""
    raw = toml_of(
        *sink_lines(name="bc", type="https", url=URL),
        "  [site.sink.headers]",
        "  X-Retry = 3",
    )
    with pytest.raises(ConfigError) as exc:
        parse(raw)
    msg = str(exc.value)
    assert "X-Retry" in msg and "header" in msg and SITE in msg


def test_headers_may_not_be_declared_on_a_file_sink() -> None:
    with pytest.raises(ConfigError) as exc:
        parse(
            toml_of(
                *sink_lines(
                    name="archive", type="csv", path="/var/lib/gateclerk/a.csv", headers={"X-A": "b"}
                )
            )
        )
    assert "headers" in str(exc.value)


# -----------------------------------------------------------------------------------------
# (4) csv / jsonl sinks: path + rotation, stable documented columns
# -----------------------------------------------------------------------------------------


def test_file_sink_requires_a_path() -> None:
    with pytest.raises(ConfigError) as exc:
        parse(toml_of(*sink_lines(name="archive", type="csv")))
    assert "path" in str(exc.value)


def test_file_sink_requires_an_absolute_path() -> None:
    """A relative path under a systemd unit resolves against `WorkingDirectory`, which is
    deployment state nobody reading the config can see. Absolute, or loud."""
    with pytest.raises(ConfigError) as exc:
        parse(toml_of(*sink_lines(name="archive", type="csv", path="out/a.csv")))
    assert "path" in str(exc.value)


def test_file_sink_path_must_be_free_of_dot_dot() -> None:
    """`..` in a declared path is a traversal the operator cannot audit from the line
    they wrote, and the store's law is that a data path is declared, not derived."""
    with pytest.raises(ConfigError) as exc:
        parse(toml_of(*sink_lines(name="archive", type="csv", path="/var/lib/../etc/a.csv")))
    assert "path" in str(exc.value)


def test_file_sink_refuses_a_blank_path() -> None:
    with pytest.raises(ConfigError) as exc:
        parse(toml_of(*sink_lines(name="archive", type="csv", path="   ")))
    assert "path" in str(exc.value)


def test_rotation_accepts_only_daily_and_monthly() -> None:
    assert set(ROTATIONS) == {"daily", "monthly"}
    for ok in ("daily", "monthly"):
        site = parse(
            toml_of(*sink_lines(name="a", type="jsonl", path="/var/lib/a.jsonl", rotation=ok))
        )
        assert sink_of(site, "a").rotation == ok


def test_rotation_defaults_to_daily_and_is_a_constant() -> None:
    """Daily is the conservative default (a month-long outage lands in ~30 files instead
    of one giant one). The default must be a constant the wiring card reads, not an
    `or "daily"` sprinkled at a call site."""
    site = parse(toml_of(*sink_lines(name="a", type="jsonl", path="/var/lib/a.jsonl")))
    assert sink_of(site, "a").rotation == "daily"


def test_unknown_rotation_is_refused_naming_the_two_values() -> None:
    with pytest.raises(ConfigError) as exc:
        parse(toml_of(*sink_lines(name="a", type="csv", path="/var/lib/a.csv", rotation="weekly")))
    msg = str(exc.value)
    assert "weekly" in msg and "daily" in msg and "monthly" in msg


def test_rotation_may_not_be_declared_on_an_https_sink() -> None:
    with pytest.raises(ConfigError) as exc:
        parse(toml_of(*sink_lines(name="bc", type="https", url=URL, rotation="daily")))
    assert "rotation" in str(exc.value)


def test_csv_columns_are_the_frozen_contract_plus_the_envelope() -> None:
    """STABLE columns, documented in the module: the three envelope columns first (so a
    row can be traced back to the queue row that produced it), then EVERY key of
    `model.RECORD_JSON_KEYS` in the contract's own order. The payload contract is
    append-only, so a CSV reader's header index is stable forever — and this pin is what
    makes a silent reorder in model.py fail here rather than in a payroll spreadsheet."""
    assert CSV_COLUMNS[:3] == ("event_id", "sink_name", "enqueued_at")
    assert CSV_COLUMNS[3:] == tuple(RECORD_JSON_KEYS)


def test_csv_columns_are_unique_and_documented_where_they_are_defined() -> None:
    assert len(set(CSV_COLUMNS)) == len(CSV_COLUMNS), "a duplicate header is a lost column"
    from gateclerk import sinks

    doc = f"{sinks.__doc__ or ''}\n{sinks.CSV_COLUMNS_DOC}"
    for column in CSV_COLUMNS[:3]:
        assert column in doc, f"{column} must be documented where it is defined"


def test_file_sink_has_no_token_and_no_headers() -> None:
    """A file sink has neither: `None`/`{}` keeps the drain's 'https-only bearer' branch
    honest (SINKS-WIRING must not need a `getattr` to ask)."""
    site = parse(toml_of(*sink_lines(name="archive", type="csv", path="/var/lib/a.csv")))
    sink = sink_of(site, "archive")
    assert sink.token_env is None and sink.token_keychain is None
    assert sink.headers == {}
    assert sink.path == "/var/lib/a.csv"


# -----------------------------------------------------------------------------------------
# the config surface: agent surface + file entry points carry sinks the same way
# -----------------------------------------------------------------------------------------


def test_agent_surface_accepts_a_sink_block_and_still_requires_iana_tz() -> None:
    """Sinks do not relax §2d: the agent still refuses a block with no zone, and the
    sinks on a valid block parse identically to the CLI surface."""
    body = "\n".join(sink_lines(name="bc", type="https", url=URL))
    raw = f'[[site]]\nname = "{SITE}"\nhost = "{HOST}"\n{body}\n'.encode()
    with pytest.raises(ConfigError, match="iana_tz"):
        parse(raw, surface=ConfigSurface.AGENT)
    site = parse(
        (
            f'[[site]]\nname = "{SITE}"\nhost = "{HOST}"\niana_tz = "Europe/Bucharest"\n{body}\n'
        ).encode(),
        surface=ConfigSurface.AGENT,
    )
    assert sink_of(site, "bc").ref == URL


def test_load_sites_carries_sinks_from_a_file(tmp_path: Path) -> None:
    path = tmp_path / "sites.toml"
    path.write_text(
        toml_of(
            *sink_lines(name="bc", type="https", url=URL),
            *sink_lines(name="archive", type="csv", path="/var/lib/a.csv"),
        ).decode("utf-8"),
        encoding="utf-8",
    )
    site = load_sites(path)[SITE]
    assert [s.name for s in site.effective_sinks] == ["bc", "archive"]


def test_construct_time_validation_matches_parse_time() -> None:
    """`SiteConfig(...)` built directly must refuse the same nonsense (the rule every
    SiteConfig key obeys: the agent cannot escape validation by building the object)."""
    with pytest.raises(ConfigError) as exc:
        SiteConfig(name=SITE, host=HOST, sinks=(SinkSpec(name="ok", type="wat", ref="x"),))
    assert "wat" in str(exc.value)


def test_construct_time_refuses_a_sink_that_would_double_the_push_target() -> None:
    """The parse-time refusal must have a construct-time twin, or a caller that builds
    the object gets the double-push the file path refuses."""
    with pytest.raises(ConfigError) as exc:
        SiteConfig(
            name=SITE,
            host=HOST,
            push_target=URL,
            sinks=(SinkSpec(name="bc", type="https", ref=URL),),
        )
    assert "push_target" in str(exc.value)


def test_sinks_field_is_not_a_top_level_site_key() -> None:
    """`sinks = [...]` (a plain array, not `[[site.sink]]`) is a shape mistake that would
    otherwise be silently ignored — the unknown-key refusal must still fire."""
    with pytest.raises(ConfigError) as exc:
        parse(toml_of("sinks = []"))
    assert "unknown" in str(exc.value).lower()
