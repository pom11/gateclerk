"""Card p2-01: the P2 sites.toml schema — explicit `iana_tz` REQUIRED, refs-only creds,
every P2 key defined up front (this card owns `config.py` + `sites.toml.example` for P2).

BINDING: docs/internal/P2-SITE-AGENT.md §2a/§2b/§2c/§2d (SIGNED OFF 2026-10-19) + DESIGN.md
"Credential plumbing". Decisions pinned by the card, implemented and pinned here:

* **Enforcement scoping**: the validator REFUSES a block without an explicit `iana_tz`
  on the **agent surface** — `surface="agent"` at construct time (`__post_init__`) and
  at parse time (`parse_sites`/`load_sites`/`site_from_args`), plus the process-wide
  `explicit_iana_tz_required()` context manager for an agent process that cannot thread
  the argument through every call site. A P1 CLI `--site` read of such a block keeps
  working byte-for-byte (site tz is payroll truth, but P1 must not start failing) and
  gets ONE stderr warning per read naming site+key — the `pipeline._warn_site_labeled`
  "warn, don't fail" precedent. `DEFAULT_IANA_TZ` never appears in an agent/strict path.
* Every P2 key exists NOW with the decided defaults, so P2-03/04/05 only READ:
  cadence_s 300 / overlap_s 300 (§2a), db_path derived `./gateclerk-<site>.sqlite3`
  (§2b), db_warn_bytes 2 GiB (§2b), push_target NEVER defaulted with `stub://`+`https://`
  only (§3: stub-only, no invented BC endpoint), push_dead_letter_after_s 86400 (§2c).
* Creds stay REFS ONLY: a `password=` key falls into the existing unknown-key refusal;
  the ref-name convention `gateclerk-<site>-<host>` (§2d) is a helper (config.py owns it)
  so later cards never hand-craft the string.

Offline by construction (pure parsing; `conftest.netoff` blocks sockets anyway). Hosts
are TEST-NET per tests/test_repo_hygiene.py; every secret-looking value is a placeholder.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import gateclerk.config as cfg
from gateclerk.config import (
    DEFAULT_CADENCE_S,
    DEFAULT_DB_PATH_TEMPLATE,
    DEFAULT_DB_WARN_BYTES,
    DEFAULT_OVERLAP_S,
    DEFAULT_PUSH_DEAD_LETTER_AFTER_S,
    PUSH_TARGET_SCHEMES,
    ConfigSurface,
    SiteConfig,
    credential_ref,
    explicit_iana_tz_required,
    load_sites,
    parse_sites,
    site_from_args,
)
from gateclerk.exceptions import ConfigError

HOST = "192.0.2.10"  # TEST-NET (tests/test_repo_hygiene.py allowlist)

#: An owner-shaped agent block: every P2 key explicit, zone declared, stub push only.
FULL_AGENT_TOML = f"""[[site]]
name = "site-a"
host = "{HOST}"
iana_tz = "Europe/Bucharest"
cadence_s = 120
overlap_s = 60
db_path = "./custom-store.sqlite3"
db_warn_bytes = 1073741824
push_target = "stub://local/ingest"
push_dead_letter_after_s = 3600
"""


def block(**keys: Any) -> str:
    """One `[[site]]` block as TOML text; `name`/`host` unless overridden."""
    table: dict[str, Any] = {"name": "site-a", "host": HOST}
    table.update(keys)
    lines = ["[[site]]"]
    for key, value in table.items():
        if value is ...:  # sentinel: emit the key with no value (malformed TOML tests)
            lines.append(f"{key} = ")
        elif isinstance(value, bool):  # TOML literals are lowercase
            lines.append(f"{key} = {'true' if value else 'false'}")
        elif isinstance(value, str):
            lines.append(f'{key} = "{value}"')
        else:
            lines.append(f"{key} = {value}")
    return "\n".join(lines) + "\n"


def parse_agent(text: str) -> dict[str, SiteConfig]:
    return parse_sites(text.encode(), surface=ConfigSurface.AGENT)


def parse_cli(text: str) -> dict[str, SiteConfig]:
    return parse_sites(text.encode())


# --- DoD 1: block without iana_tz refused, naming site + key --------------------------


def test_agent_surface_refuses_a_block_without_iana_tz_naming_site_and_key() -> None:
    """Spec §2d: site tz is payroll truth, never defaulted — the agent refuses it.

    The message must name BOTH the site and the key (card DoD: 'loud errors naming
    site+key', same style as the unknown-key refusal and the p1-12 device_tz check),
    or the operator has to diff their TOML against the spec to find the missing line.
    """
    with pytest.raises(ConfigError) as exc:
        parse_agent(block())
    msg = str(exc.value)
    assert "site-a" in msg, msg
    assert "iana_tz" in msg, msg
    assert "required" in msg.lower(), msg


def test_agent_surface_refuses_at_construct_time_too() -> None:
    """Construct-time AND parse-time (card: 'mirror SiteConfig.__post_init__').

    `SiteConfig(name=..., host=..., surface="agent")` directly — no TOML involved —
    must hit the same wall: the agent surface cannot be 'unloaded from' by building
    the object in code instead of reading the file.
    """
    with pytest.raises(ConfigError) as exc:
        SiteConfig(name="site-a", host=HOST, surface=ConfigSurface.AGENT)
    msg = str(exc.value)
    assert "site-a" in msg and "iana_tz" in msg


def test_load_sites_carries_the_agent_surface(tmp_path: Path) -> None:
    """Parse-time enforcement on the file entry point the agent process will use."""
    path = tmp_path / "sites.toml"
    path.write_text(block(), encoding="utf-8")
    with pytest.raises(ConfigError, match="iana_tz"):
        load_sites(path, surface=ConfigSurface.AGENT)
    # And the plain CLI read of the SAME file still works (no BC break).
    assert load_sites(path)["site-a"].iana_tz is None


def test_site_from_args_carries_the_agent_surface(tmp_path: Path) -> None:
    path = tmp_path / "sites.toml"
    path.write_text(block(), encoding="utf-8")
    with pytest.raises(ConfigError, match="iana_tz"):
        site_from_args(site="site-a", config_path=path, surface=ConfigSurface.AGENT)


def test_process_wide_strict_mode_for_agent_processes() -> None:
    """`explicit_iana_tz_required()` — the seam for a daemon that cannot thread the
    surface argument into every config read (agent main() turns it on once).

    Inside it, even a plain CLI-surface construction without a zone is refused; leaving
    it restores today's behaviour exactly (context-var scoped, exception-safe).
    """
    with pytest.raises(ConfigError, match="iana_tz"), explicit_iana_tz_required():
        SiteConfig(name="site-a", host=HOST)

    # Outside: byte-for-byte P1.
    assert SiteConfig(name="site-a", host=HOST).iana_tz is None

    # The mode nests (two managers) and unwinds even through an exception.
    with (
        pytest.raises(ValueError, match="boom"),
        explicit_iana_tz_required(),
        explicit_iana_tz_required(),
    ):
        raise ValueError("boom")
    assert parse_cli(block())["site-a"].iana_tz is None


def test_agent_surface_accepts_a_block_with_an_explicit_zone() -> None:
    """Positive control for every refusal above: the wall is the MISSING zone."""
    site = parse_agent(block(iana_tz="Europe/Bucharest"))["site-a"]
    assert site.iana_tz == "Europe/Bucharest"


def test_an_explicit_but_unresolvable_zone_is_still_refused_naming_the_key() -> None:
    """REQUIRED must not regress into 'any string': the p1-12 strictness carries.

    (Empty string included — `iana_tz = ""` is not a declared zone, it is a missing one
    wearing a costume.)
    """
    for bad in ("Mars/Olympus_Mons", ""):
        with pytest.raises(ConfigError) as exc:
            parse_agent(block(iana_tz=bad))
        assert bad in str(exc.value) or "iana_tz" in str(exc.value)


# --- DoD 2: every P2 key parses, with defaults, and validates --------------------------


def test_p2_defaults_are_the_signed_off_numbers() -> None:
    """§2a 5 min/5 min, §2b 2 GiB watermark, §2c 24 h dead-letter bound.

    The constants are exported precisely so P2-03/04/05 read `DEFAULT_*` instead of
    re-typing 300/300/86400 — this test pins constant AND field default together.
    """
    site = parse_cli(block())["site-a"]
    assert (site.cadence_s, site.overlap_s) == (300, 300) == (DEFAULT_CADENCE_S, DEFAULT_OVERLAP_S)
    assert site.db_warn_bytes == 2 * 1024**3 == DEFAULT_DB_WARN_BYTES
    assert site.push_dead_letter_after_s == 86400 == DEFAULT_PUSH_DEAD_LETTER_AFTER_S
    # §2b: the default db path derives from the SITE NAME, and the pattern is already
    # gitignored (*.sqlite3) — no new gitignore entry needed, and none is added.
    assert site.db_path is None
    assert site.db_path_resolved == "./gateclerk-site-a.sqlite3"
    assert DEFAULT_DB_PATH_TEMPLATE == "./gateclerk-{site}.sqlite3"


def test_push_target_is_never_defaulted() -> None:
    """Spec §3 + card: NEVER a hardcoded default endpoint.

    Two pins: the field default is None (pusher-off is a legal config), and there is no
    `DEFAULT_PUSH_TARGET` constant to import — a 'helpful' later card that adds one
    (the exact mistake this rule forbids) goes red here first. The constant probe is
    done on `dir()`, not `hasattr`: the latter would trippingly run any module
    `__getattr__` instead of answering the question.
    """
    assert parse_cli(block())["site-a"].push_target is None
    assert "DEFAULT_PUSH_TARGET" not in dir(cfg)
    # The agent surface does NOT require a push target: absence means 'pusher off',
    # P2-04's decision point — only the ZONE is required.
    assert parse_agent(block(iana_tz="Europe/Bucharest"))["site-a"].push_target is None


def test_every_p2_key_parses_explicitly_and_survives_the_agent_surface() -> None:
    """One owner-shaped block: all six keys set, agent surface, nothing refused."""
    site = parse_agent(FULL_AGENT_TOML)["site-a"]
    assert (site.cadence_s, site.overlap_s) == (120, 60)
    assert site.db_path == "./custom-store.sqlite3"
    assert site.db_path_resolved == "./custom-store.sqlite3"
    assert site.db_warn_bytes == 1073741824
    assert site.push_target == "stub://local/ingest"
    assert site.push_dead_letter_after_s == 3600


@pytest.mark.parametrize(
    ("toml", "needle"),
    [
        # cadence<=0 would busy-poll a door controller whose nonce budget is ~190
        # requests (OBSERVED.md) — refused, not floored.
        (block(cadence_s=0), "cadence_s"),
        (block(cadence_s=-5), "cadence_s"),
        # a negative overlap moves the window's lower bound into the future: a silent
        # gap in exactly the crash-heal case the overlap exists for.
        (block(overlap_s=-1), "overlap_s"),
        (block(db_warn_bytes=0), "db_warn_bytes"),
        (block(db_warn_bytes=-1), "db_warn_bytes"),
        (block(push_dead_letter_after_s=0), "push_dead_letter_after_s"),
        (block(push_dead_letter_after_s=-1), "push_dead_letter_after_s"),
        # types: the _int/_number strictness carries to the new keys. (TOML has no
        # bool-vs-int ambiguity trap here — `cadence_s = true` parses to Python True,
        # which _int refuses exactly like the `port = true` pin in p1-02's suite.)
        (block(cadence_s="300"), "cadence_s must be an integer"),
        (block(cadence_s=True), "cadence_s must be an integer"),
        (block(db_warn_bytes=1.5), "db_warn_bytes must be an integer"),
        # an empty/whitespace value for a path is a mis-typed line, not "use default".
        (block(db_path=""), "db_path"),
        (block(db_path="   "), "db_path"),
    ],
)
def test_p2_value_validation_names_the_offending_key(toml: str, needle: str) -> None:
    with pytest.raises(ConfigError, match=needle):
        parse_cli(toml)


@pytest.mark.parametrize(
    ("target", "refused"),
    [
        ("stub://local/ingest", False),  # the authorized test/stub scheme
        ("stub:///var/lib/gateclerk/ingest", False),
        ("https://ingest.example.test/push", False),  # a real ref is allowed, never default
        ("ftp://ingest.example.test/push", True),  # the card's named example
        ("http://ingest.example.test/push", True),  # plaintext push leg: §3 says HTTPS
        ("file:///tmp/stolen", True),
        ("//no-scheme.example", True),
        ("HTTPS://INGEST.EXAMPLE.TEST", True),  # schemes are matched exactly, not case-folded
        ("stub:/one-slash", True),  # scheme-less lookalike
    ],
)
def test_push_target_scheme_gate(target: str, refused: bool) -> None:
    """`stub://` accepted for tests, `https://` allowed, EVERYTHING else refused naming
    the value and the allowed set (DoD 2). No endpoint is invented anywhere: the only
    https URL in this file is an .example.test domain.
    """
    if refused:
        with pytest.raises(ConfigError) as exc:
            parse_cli(block(push_target=target))
        msg = str(exc.value)
        assert target in msg, "the refusal must quote the value it refused"
        assert "stub://" in msg and "https://" in msg, "and name what IS allowed"
    else:
        assert parse_cli(block(push_target=target))["site-a"].push_target == target


def test_push_target_scheme_gate_fires_on_the_agent_surface_too() -> None:
    """Surface independence: the scheme wall is not a CLI-only courtesy."""
    with pytest.raises(ConfigError, match="ftp://"):
        parse_agent(block(iana_tz="Europe/Bucharest", push_target="ftp://x.test/p"))


def test_push_target_scheme_constant_matches_the_gate() -> None:
    """P2-04 reads PUSH_TARGET_SCHEMES for its own messaging — pin the pair, exactly."""
    assert PUSH_TARGET_SCHEMES == ("stub://", "https://")


# --- DoD 3: creds stay REFS ONLY ---------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    ["password", "passwd", "pwd", "secret", "token", "credential", "api_key"],
)
def test_a_credential_value_key_is_refused_as_unknown(key: str) -> None:
    """No password VALUES in any config surface (DESIGN.md "Credential plumbing").

    The refusal is the EXISTING unknown-key machinery — this pins that the new P2 keys
    did not smuggle a value channel in, and that the error says 'unknown key' with the
    offending name, so a mis-placed `password =` is never silently dropped.
    """
    with pytest.raises(ConfigError) as exc:
        parse_cli(block(**{key: "fake-pw"}))
    msg = str(exc.value)
    assert "unknown key" in msg and key in msg


def test_unknown_key_error_still_lists_the_accepted_keys() -> None:
    """The p1-02 message shape survives the key expansion."""
    with pytest.raises(ConfigError) as exc:
        parse_cli(block(nope=1))
    msg = str(exc.value)
    assert "unknown key" in msg
    for accepted in ("cadence_s", "push_target", "iana_tz", "device_tz"):
        assert accepted in msg, f"accepted-keys list must teach the operator: {msg}"


# --- DoD 4: credential-ref naming convention (spec §2d) --------------------------------


def test_credential_ref_follows_the_gateclerk_site_host_convention() -> None:
    """`gateclerk-<site>-<host>` — the systemd-credential ref name (spec §2d).

    A helper, not prose: P2-04/05 call it instead of hand-crafting the string, so the
    convention physically cannot drift between services and unit files.
    """
    assert credential_ref("site-a", HOST) == f"gateclerk-site-a-{HOST}"
    assert credential_ref("site-b", "door-1.example.test") == "gateclerk-site-b-door-1.example.test"


@pytest.mark.parametrize(("site", "host"), [("", HOST), ("site-a", ""), ("site-a", "   ")])
def test_credential_ref_refuses_empty_parts(site: str, host: str) -> None:
    with pytest.raises(ConfigError):
        credential_ref(site, host)


def test_the_shipped_example_documents_the_ref_convention_and_parses_on_both_surfaces() -> None:
    """Docs are executable (same precedent as the p1-02 example-parse test): the ref
    convention appears in sites.toml.example, and the example block is valid for an
    agent too — an operator copying it must not start on the wrong side of §2d.
    """
    example = Path(__file__).resolve().parents[1] / "sites.toml.example"
    text = example.read_text(encoding="utf-8")
    assert "gateclerk-<site>-<host>" in text, "the example must carry the §2d convention"
    assert load_sites(example)["site-a"].iana_tz == "Europe/Bucharest"
    assert load_sites(example, surface=ConfigSurface.AGENT)["site-a"].cadence_s == DEFAULT_CADENCE_S


# --- surface plumbing: argument, enum, and 'surface is not TOML data' -------------------


def test_surface_is_not_a_toml_key() -> None:
    """Strictness belongs to the CALLING CODE (which process is reading), never to the
    config file: a shared sites.toml must not be able to disqualify its own CLI use.
    """
    with pytest.raises(ConfigError, match="unknown key"):
        parse_cli(block(surface="agent"))


def test_an_unknown_surface_is_a_config_error_not_a_silent_cli() -> None:
    """Silently treating `surface="agenta"` as CLI would re-open the whole §2d hole."""
    with pytest.raises(ConfigError, match="surface"):
        SiteConfig(name="s", host="h", surface="agenta")


def test_surface_accepts_the_plain_string_form() -> None:
    """StrEnum ergonomics: an agent entry point may pass the literal "agent"."""
    with pytest.raises(ConfigError, match="iana_tz"):
        SiteConfig(name="site-a", host=HOST, surface="agent")


# --- the CLI `--site` warning (the scoped decision's other half) -------------------------


def test_cli_site_read_of_a_zoneless_block_warns_naming_site_and_key(tmp_path: Path) -> None:
    """P1 keeps working (no exception, no exit-code change) but says so on stderr:
    the fallback is exactly the thing §2d refuses to let an agent take.
    """
    path = tmp_path / "sites.toml"
    path.write_text(block(), encoding="utf-8")
    seen: list[str] = []
    site = site_from_args(site="site-a", config_path=path, warn=seen.append)
    assert site.iana_tz is None, "warn, don't fail — the read still returns"
    assert len(seen) == 1, seen
    assert "site-a" in seen[0] and "iana_tz" in seen[0]


def test_cli_site_read_with_a_declared_zone_is_silent(tmp_path: Path) -> None:
    path = tmp_path / "sites.toml"
    path.write_text(block(iana_tz="Europe/Bucharest"), encoding="utf-8")
    seen: list[str] = []
    site_from_args(site="site-a", config_path=path, warn=seen.append)
    assert seen == [], "the warning is for the missing zone, not for --site in general"


def test_the_default_warning_emitter_reaches_stderr(tmp_path: Path, capsys) -> None:
    """The injected `warn` above is a test seam; production uses the default emitter,
    which must land on **stderr** (the jsonl-pipe invariant `--verbose` pins: stdout
    stays parseable). Pin the real path, not just the seam.
    """
    path = tmp_path / "sites.toml"
    path.write_text(block(), encoding="utf-8")
    site_from_args(site="site-a", config_path=path)
    err = capsys.readouterr().err
    assert "warning:" in err and "site-a" in err and "iana_tz" in err


def test_host_one_off_never_warns(tmp_path: Path) -> None:
    """P1 byte-for-byte: `--host` builds a one-off outside sites.toml; the warning is
    scoped to `--site` reads, and a missing zone is not even expressible as a refusal
    here (no block involved).
    """
    seen: list[str] = []
    site = site_from_args(host="192.0.2.99", config_path=tmp_path / "absent.toml", warn=seen.append)
    assert site.host == "192.0.2.99"
    assert seen == []


# --- P1 behaviour survives the expansion (DoD 5, the belt over the existing suite) -------


def test_p1_minimal_block_is_still_enough_for_every_p1_surface(tmp_path: Path) -> None:
    """name+host only: load/parse/find/site_from_args all work, and `target()` — the
    seam p1-03 holds — is untouched by the P2 keys.
    """
    text = block()
    site = parse_cli(text)["site-a"]
    assert (site.port, site.timeout_s, site.page_delay_ms) == (80, 30.0, 100)
    tgt = site.target()
    assert tgt.keychain_account == HOST
    assert tgt.keychain_service == "gateclerk-hikvision"
    # The new fields all arrive at their defaults, so no P1 construction path grew a
    # required argument: positional `SiteConfig(name, host)` keeps compiling.
    assert SiteConfig("s", "h").push_target is None


def test_device_tz_and_p2_keys_coexist() -> None:
    """p1-12's device_tz and the P2 keys are orthogonal fields of ONE block."""
    site = parse_agent(block(iana_tz="Europe/Bucharest", device_tz="Europe/Bucharest"))["site-a"]
    assert site.device_tz == "Europe/Bucharest"
    assert site.cadence_s == DEFAULT_CADENCE_S
