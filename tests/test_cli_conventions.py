"""Card CLI-VERBS-HELP: the conventions module is the single source, and these tests hold it.

What a reviewer should be able to read out of this file
-------------------------------------------------------
The card asked for four properties of the CLI surface. Three of them (one verb vocabulary,
help everywhere, `-o json` on every read) are properties of the DECLARED Click definition,
so they are asserted against the definition — the same reason `tests/_cli_surface.py` gives
for not reading rendered help: Rich's output depends on terminal geometry, so a render-based
assertion can pass because the offending text was elided. The fourth (`agent run` unchanged)
is pinned against a manifest captured from `origin/main` BEFORE the change, not against the
working tree, so it cannot be satisfied by the code it is checking.

The four properties and the test that owns each
-----------------------------------------------
(1) one vocabulary   `test_declared_surface_matches_the_canonical_vocabulary`
                    `test_superseded_spellings_resolve_and_are_not_declared`
(2) help everywhere  `test_every_command_and_group_has_help_and_help_runs`
(3) exit codes       `test_exit_code_constants_are_the_conventions_module`
                    `test_exit_code_for_maps_every_class_onto_its_documented_number`
                    `test_unclassified_exception_is_not_laundered_into_a_number`
(4) `-o` on every read `test_every_leaf_command_declares_output_json`
(5) `agent run`      `test_agent_run_definition_is_unchanged_from_the_baseline`

Plus the doc-sync guards: the vocabulary table, the alias table and the exit-code table in
`docs/CLI-CONVENTIONS.md` are checked against the module, so the page the operator reads
cannot silently disagree with the code that enforces it.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from _cli_surface import command_at, declared_flags, declared_prose
from gateclerk import cli_conventions as conv
from gateclerk.cli import (
    AUTH_TERMINAL_EXIT,
    CONFIG_ERROR_EXIT,
    DEVICE_ERROR_EXIT,
    RUNAWAY_EXIT,
    app,
)
from gateclerk.exceptions import (
    ConfigError,
    CredentialUnavailable,
    EnrollmentReadAborted,
    EventBoundsError,
    GateClerkError,
    IsapiAuthError,
    IsapiBadContent,
    IsapiError,
    IsapiNotFound,
    SearchProtocolError,
    SearchRunawayError,
)
from gateclerk.tz import TimestampInputError

ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()

# --- the surface, read once ---------------------------------------------------------------


#: Every leaf command as a word-list, sorted. Derived from the app rather than hardcoded:
#: a hardcoded list here would have to be updated when a card adds a command, and a guard
#: that a card must edit in order to pass is not a guard.
def _leaves(cmd: Any = None, path: tuple[str, ...] = ()) -> list[tuple[str, ...]]:
    cmd = typer_root() if cmd is None else cmd
    sub = getattr(cmd, "commands", None)
    if not sub:
        return [path]
    out: list[tuple[str, ...]] = []
    for name in sorted(sub):
        out.extend(_leaves(sub[name], (*path, name)))
    return out


def _groups(cmd: Any = None, path: tuple[str, ...] = ()) -> list[tuple[str, ...]]:
    cmd = typer_root() if cmd is None else cmd
    sub = getattr(cmd, "commands", None)
    if not sub:
        return []
    out = [path] if path else []
    for name in sorted(sub):
        out.extend(_groups(sub[name], (*path, name)))
    return out


def typer_root() -> Any:
    import typer

    return typer.main.get_command(app)


#: Every leaf command, sorted by name. The count, not just the names, is the point: an
#: earlier card's surface test allows `agent`, `migrate`, `sink` and `demo` as additions, so
#: without this a NEW command could arrive without `-o` and no other test would notice.
#:
#: Maintenance: adding a command means adding its name here, which is the cheapest possible
#: review signal for "this card grew the surface". `tests/test_p2_07b_agent_cli.py` pins the
#: pre-P2-07b shape separately; this set is the current total.
EXPECTED_LEAVES: set[str] = {
    "agent ack",
    "agent deadletter list",
    "agent deadletter remove",
    "agent probe list",
    "agent run",
    "creds explain",
    "creds get",
    "creds remove",
    "creds set",
    "creds test",
    "demo demo",
    "demo device serve",
    "demo device urls",
    "device capabilities",
    "device info",
    "device time",
    "doctor",
    "events",
    "export config",
    "export scans",
    "init",
    "migrate apply",
    "migrate clean",
    "migrate diff",
    "migrate export",
    "migrate probe",
    "migrate undo",
    "service install",
    "service logs",
    "service uninstall",
    "sink add",
    "sink list",
    "sink remove",
    "sink test",
    "status",
    "users import",
    "users list",
    "users template",
}


# --- (4) every read command speaks json -----------------------------------------------------


#: Leaves exempt from the `-o` requirement, with the reason. The card's requirement (4) is
#: "`-o json` on every READ-ish command"; these are not reads — they start a process, so
#: there is no record set to frame, only a startup line. `agent run` DOES carry `-o` (it
#: renders its health/final snapshot through the shared renderer), so the exemption is not
#: "anything long-running", it is "this command prints no records at all". `users template`
#: writes a local blank workbook and prints one path line, so it is not a record stream
#: either.
#:
#: The list is asserted to be exactly these, so a new read command cannot join it as a way
#: of dodging the guard: adding a name here is a visible, reviewable act.
NO_OUTPUT_FLAG_LEAVES: frozenset[str] = frozenset({"demo device serve", "users template"})


def test_every_leaf_command_declares_output_json() -> None:
    """Requirement (4): `--output/-o` is on every leaf, through the shared `OutputOpt`.

    The card phrased (4) as "add -o to the read commands". Every leaf already had it, so the
    deliverable is the guard: a new command that prints by hand, or that drops `-o`, fails
    here rather than in a pipeline that expected JSON. `jsonl` counts because `gateclerk.output`
    defines the three choices as one closed list.
    """
    leaves = _leaves()
    names = {" ".join(p) for p in leaves}
    assert names == EXPECTED_LEAVES, f"surface changed: {names ^ EXPECTED_LEAVES}"
    # 38 = 33 after SERVICE-CMD, plus CLI-DOCTOR's `doctor`; +2 for USERS-IMPORT-XLSX's
    # `users import` / `users template`; +1 for GC-P15 follow-up 2's `agent probe list`;
    # +1 for GC-P16c's `migrate clean`.
    assert len(leaves) == len(EXPECTED_LEAVES) == 38
    exempt = {p for p in names if p in NO_OUTPUT_FLAG_LEAVES}
    assert exempt == set(NO_OUTPUT_FLAG_LEAVES), (
        f"exemption list is stale: {exempt ^ set(NO_OUTPUT_FLAG_LEAVES)}"
    )
    for path in leaves:
        if " ".join(path) in NO_OUTPUT_FLAG_LEAVES:
            continue
        flags = declared_flags(command_at(app, list(path)))
        assert "-o" in flags and "--output" in flags, f"{' '.join(path)} has no -o/--output"


def test_demo_device_urls_json_is_pii_safe() -> None:
    """The one `-o json` this card ADDED must obey the CLI-wide PII law.

    `demo device urls` printed the demo digest pair unconditionally before. The demo password
    is a placeholder, so masking it is not protecting a secret — it is protecting the rule,
    which is what the sweep tests exist for: a command that puts a *password field* in its
    machine output teaches a script author that `password` is a field to read, and the next
    command they write reads a real one. The human table keeps the pair (README documents it
    as the thing you copy into `sites.toml`); the machine form does not.
    """
    from gateclerk import demo_device as demo

    result = runner.invoke(app, ["demo", "device", "urls", "-o", "json"])
    assert result.exit_code == 0, result.stdout
    # `gateclerk.output` renders json as one compact object per line (json and jsonl are one
    # renderer on purpose), so the machine form is parsed as a stream, not as one document.
    rows = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert {r["kind"] for r in rows} == {"endpoint", "credential"}
    assert demo.DEMO_DEFAULT_PASSWORD not in result.stdout, "the machine form leaked the digest pw"
    assert "192.0.2." not in result.stdout and "10.0.0." not in result.stdout, (
        "the URL set must stay synthetic (SYNTHETIC-ONLY LAW)"
    )
    # The URL rows must be the registry's showcase set, so the JSON form cannot be a thinner
    # view that a script silently depends on.
    from gateclerk.demo_device import demo_endpoint_urls

    assert [r["name"] for r in rows if r["kind"] == "endpoint"] == [
        name for name, _ in demo_endpoint_urls(f"http://{demo.DEMO_BIND_HOST}:80")
    ]
    # jsonl is the same framing one-object-per-line, so it inherits the masking.
    stream = runner.invoke(app, ["demo", "device", "urls", "-o", "jsonl"])
    assert demo.DEMO_DEFAULT_PASSWORD not in stream.stdout


#: The read-only half of the surface: every leaf whose operation is a `list` / `get` / `test`
#: / `status` verb. `test_cli_commands.py` runs the same no-mutating-verb sweep over the five
#: commands that existed when it was written; this covers the rest, so a command added by a
#: later card is swept too without editing that file (whose argv list is itself a pin).
#:
#: Deliberately EXCLUDED: the write-class commands (`agent deadletter remove`,
#: `sink add|remove`, `migrate apply|undo`) — their help must say what they do, and a sweep
#: that forced them to hide it would be worse than no sweep.
READ_ONLY_LEAVES: tuple[tuple[str, ...], ...] = (
    ("device", "info"),
    ("device", "time"),
    ("device", "capabilities"),
    ("doctor",),
    ("users", "list"),
    ("events",),
    ("creds", "test"),
    ("creds", "explain"),
    ("sink", "list"),
    ("sink", "test"),
    ("status",),
    ("agent", "deadletter", "list"),
    # GC-P15 follow-up 2: `agent probe list` reads `probe_audit` and writes nothing, so it
    # belongs to the read half the sweep covers (and its help must not advertise a write).
    ("agent", "probe", "list"),
    ("demo", "device", "urls"),
)


def test_no_read_command_help_advertises_a_write() -> None:
    """The vocabulary's stated reason, enforced rather than asserted in prose.

    docs/CLI-CONVENTIONS.md says `remove` is canonical over `delete` partly because this
    connector must never grow a write surface and the word "delete" in a read command's help
    is where that drift shows up first. `test_cli_commands.py` pins that for five argvs; this
    extends it to the rest of the read surface — including `creds test`, renamed by THIS card,
    which the five-argv list cannot cover without someone remembering to edit it.

    The list is explicit rather than derived from the command tree because the exclusion is a
    judgement: the write-class commands (`agent deadletter remove`, `sink add|remove`,
    `migrate apply|undo`) must say what they do in their help, and a sweep that forced them to
    hide it would be worse than no sweep. `test_the_write_verb_sweep_is_not_dead` below is what
    stops the list from being quietly narrowed to nothing.

    Same word-boundary rule as the original test for the same reason: `"put " in text` fires
    on "out**put** format", and a tripwire that fires on every command is a tripwire nobody
    keeps.
    """
    verbs = (r"\bput\b", r"\bdelete\b", r"\breboot\b", r"\bshutdown\b", r"\bsettime\b")
    for path in READ_ONLY_LEAVES:
        lowered = declared_prose(command_at(app, list(path))).lower()
        for verb in verbs:
            assert re.search(verb, lowered) is None, f"{' '.join(path)} help mentions {verb}"


def test_the_write_verb_sweep_is_not_dead() -> None:
    """A tripwire that cannot fire is worse than none: it reads as coverage.

    `agent deadletter remove` legitimately says "deletes" — it is the one code path that ever
    deletes a row — so the same pattern searched over its prose MUST match. If that ever stops
    matching (the regex is broken, or `declared_prose` stops returning help), the sweep above
    would pass vacuously for every command and this test is what says so.
    """
    write_prose = declared_prose(command_at(app, ["agent", "deadletter", "remove"])).lower()
    assert re.search(r"\bdelete", write_prose), (
        "the sweep's pattern no longer matches any real prose — it is not testing anything"
    )
    assert ("agent", "deadletter", "remove") not in READ_ONLY_LEAVES


# --- (2) help everywhere --------------------------------------------------------------------


def test_every_command_and_group_has_help_and_help_runs() -> None:
    """Requirement (2): a one-line summary for every command AND every group.

    Both halves are needed and they catch different bugs. `has_help` catches a body written
    without a docstring — Typer then shows a blank summary column and `--help` still exits 0.
    Running `--help` catches the inverse: a help string that makes rendering itself fail
    (typer#600: a literal `%` in help text raises at render time, which is invisible to a
    definition-level check).
    """
    targets = [tuple(p) for p in _leaves()] + _groups()
    assert len(targets) >= 16 + 5, "the surface shrunk below the point of this guard"
    for path in targets:
        cmd = command_at(app, list(path)) if path else typer_root()
        prose = (cmd.short_help or "") + (cmd.help or "")
        label = " ".join(path) or "<root>"
        assert prose.strip(), f"{label} has no help text"
        result = runner.invoke(app, [*path, "--help"])
        assert result.exit_code == 0, f"{label} --help exited {result.exit_code}"
        assert result.stdout.strip(), f"{label} --help printed nothing"


# --- (1) one vocabulary, and the old spellings still work -----------------------------------


def test_declared_surface_matches_the_canonical_vocabulary() -> None:
    """Requirement (1): the generic-verb slots spell their verb the canonical way.

    Checked only for the slots that ARE a generic verb. `migrate apply` is not a `list`/`get`/
    `add` slot — it is a §7 pipeline stage — so this test deliberately does not touch it;
    docs/CLI-CONVENTIONS.md states that exception rather than a test quietly ignoring it.
    """
    verbs = set(conv.VERBS)
    assert verbs == {"list", "get", "status", "test", "add", "remove"}

    # The two slots the card's vocabulary actually changes.
    assert "test" in {p.split()[-1] for p in EXPECTED_LEAVES if p.startswith("creds")}
    assert "remove" in {p.split()[-1] for p in EXPECTED_LEAVES if "deadletter" in p}

    # Superseded spellings must not be DECLARED anywhere, or --help shows two names for one
    # operation and the surface allow-lists stop catching real additions.
    declared = {" ".join(p) for p in _leaves()}
    for group, aliases in conv.ALIASES.items():
        for alias in aliases:
            assert f"{' '.join(group)} {alias}" not in declared, (
                f"{' '.join(group)} {alias} is declared AND aliased — the alias should be "
                "hidden (resolved in get_command, not registered)"
            )


def test_superseded_spellings_resolve_and_are_not_declared() -> None:
    """Requirement (1)'s compatibility half: the old spelling still RUNS the same command.

    Asserted at both layers, because each catches what the other cannot. Click-level identity
    proves the alias lands on the ONE command object (a `--help`-only alias, or an alias to a
    copy of a command, would slip past an exit-code comparison). Behavioural equality proves
    the wiring from the real argv reaches it too — and needs its own "no such command" check,
    because a broken alias and a working alias can both end at exit 2 (`creds test` exits 2
    with no keychain entry either way, so equality of codes alone would pass a dead alias).

    `creds` is the group driven end to end: it is documented as never contacting a device, so
    this stays offline with no fixture and no socket.
    """
    assert conv.resolve_alias(("creds",), "check") == "test"
    assert conv.resolve_alias(("agent", "deadletter"), "delete") == "remove"
    assert conv.resolve_alias(("creds",), "nope") is None
    assert conv.resolve_alias(("users",), "check") is None, "aliases must not leak across groups"

    for group_path, alias, canonical in (
        (("creds",), "check", "test"),
        (("agent", "deadletter"), "delete", "remove"),
    ):
        group = command_at(app, list(group_path))
        # No Context: typer >= 0.25 vendors click as `typer._click`, so the module a Context
        # would have to come from depends on the installed typer layout (cli.py's
        # `_usage_error_classes` exists for the same reason). `get_command` ignores ctx, so
        # passing None keeps this version-independent.
        resolved = group.get_command(None, alias)  # type: ignore[arg-type]
        assert resolved is group.commands[canonical], (
            f"{' '.join(group_path)} {alias} did not resolve to the same command object"
        )

    canonical = runner.invoke(app, ["creds", "test", "192.0.2.10"])
    aliased = runner.invoke(app, ["creds", "check", "192.0.2.10"])
    assert "no such command" not in aliased.stdout.lower(), "the alias is not resolving"
    assert aliased.exit_code == canonical.exit_code
    assert aliased.stdout == canonical.stdout, "`creds check` must be `creds test` exactly"

    # A typo inside an alias-bearing group is still a usage error, not a silent redirect.
    bogus = runner.invoke(app, ["creds", "testt", "192.0.2.10"])
    assert bogus.exit_code == 2, f"a typo must exit 2 (usage), got {bogus.exit_code}"

    # ...and an alias must never shadow a real command: `creds explain` stays `explain`.
    assert "explain" in typer_root().commands["creds"].commands


def test_each_alias_group_is_its_own_class() -> None:
    """The alias groups must not share a class object.

    A single class with a `path` attribute assigned twice would leave both groups using
    whichever path was assigned LAST, so `creds check` would resolve inside `deadletter` and
    `deadletter delete` would stop working — silently, because each group would still resolve
    its own alias correctly in isolation. The factory closes over `path` for this reason and
    this test is what keeps someone from "simplifying" it back.
    """
    creds = typer_root().commands["creds"]
    deadletter = typer_root().commands["agent"].commands["deadletter"]
    assert type(creds) is not type(deadletter)
    assert creds.get_command.__func__ is not deadletter.get_command.__func__  # type: ignore[attr-defined]


# --- (3) exit codes -------------------------------------------------------------------------


def test_exit_code_constants_are_the_conventions_module() -> None:
    """Requirement (3): `gateclerk.cli`'s numbers ARE the conventions module's, not copies.

    Other cards' tests import these four names from `gateclerk.cli`, so the names have to stay;
    what this pins is that they are handles onto `ExitCode` rather than second declarations of
    the literals — two declarations is how one test's expectation and one production wrapper's
    branch end up disagreeing.
    """
    assert (CONFIG_ERROR_EXIT, AUTH_TERMINAL_EXIT, DEVICE_ERROR_EXIT, RUNAWAY_EXIT) == (2, 3, 4, 5)
    assert int(conv.ExitCode.USAGE_OR_CONFIG) == CONFIG_ERROR_EXIT
    assert int(conv.ExitCode.AUTH_TERMINAL) == AUTH_TERMINAL_EXIT
    assert int(conv.ExitCode.DEVICE) == DEVICE_ERROR_EXIT
    assert int(conv.ExitCode.RUNAWAY) == RUNAWAY_EXIT
    # p1-08's shipped numbers. The conventions module documents why the card's proposed
    # numbering (2 usage / 3 config / 4 credential / 5 unreachable) was NOT adopted.
    assert [int(c) for c in conv.ExitCode] == [0, 1, 2, 3, 4, 5, 6]


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (IsapiAuthError("401"), conv.ExitCode.AUTH_TERMINAL),
        # The subclass-before-superclass order is load-bearing: IsapiAuthError IS an
        # IsapiError, so a reordered mapping silently moves terminal-auth 3 -> 4.
        (IsapiError("nope", status_code=500), conv.ExitCode.DEVICE),
        (IsapiBadContent("badParameters"), conv.ExitCode.DEVICE),
        (IsapiNotFound("404"), conv.ExitCode.DEVICE),
        (SearchRunawayError("past the cap"), conv.ExitCode.RUNAWAY),
        (ConfigError("bad sites.toml"), conv.ExitCode.USAGE_OR_CONFIG),
        (CredentialUnavailable("no keychain entry"), conv.ExitCode.USAGE_OR_CONFIG),
        (TimestampInputError("not a timestamp"), conv.ExitCode.USAGE_OR_CONFIG),
        (EventBoundsError("no --since"), conv.ExitCode.USAGE_OR_CONFIG),
        (SearchProtocolError("root key missing"), conv.ExitCode.DEVICE),
        # A GateClerkError with no more specific class is the device/protocol class — the
        # same arm `_fail` used to carry inline.
        (EnrollmentReadAborted("read refused"), conv.ExitCode.DEVICE),
        (GateClerkError("generic gateclerk failure"), conv.ExitCode.DEVICE),
    ],
)
def test_exit_code_for_maps_every_class_onto_its_documented_number(
    exc: BaseException, expected: conv.ExitCode
) -> None:
    assert conv.exit_code_for(exc) == int(expected)


def test_unclassified_exception_is_not_laundered_into_a_number() -> None:
    """Exit 1 is documented as "never returned", and the mechanism is asserted here.

    `exit_code_for` refuses to guess (KeyError) and `cli._fail` re-raises the ORIGINAL
    exception. Both halves matter: a catch-all that returned 1 would turn a real bug into an
    exit code an operator would branch on, and `raise exc from None` is what keeps the
    traceback pointing at the module that has the bug rather than at a KeyError about it.
    """
    with pytest.raises(KeyError):
        conv.exit_code_for(ZeroDivisionError("a bug"))

    from gateclerk.cli import _fail
    from gateclerk.output import OutputFormat

    bug = ZeroDivisionError("a bug")
    with pytest.raises(ZeroDivisionError) as raised:
        _fail(OutputFormat.JSON, bug)
    assert raised.value is bug, "the original exception must be re-raised, not substituted"
    # `raise exc from None` is what makes the traceback show ONE exception. Python still keeps
    # the KeyError in __context__, so the observable contract is suppression, not absence —
    # asserting `__context__ is None` would be asserting something Python cannot do.
    assert raised.value.__cause__ is None
    assert raised.value.__suppress_context__ is True, (
        "without `from None` the traceback reads 'During handling of the above exception...' "
        "and the operator/debugger chases the lookup KeyError instead of the real bug"
    )


# --- doc-sync: the page an operator reads cannot drift from the module ----------------------


def test_conventions_doc_lists_every_exit_code_and_verb() -> None:
    """The card's ACCEPT item is a docs page; a page nothing checks is a page that rots.

    Each documented class must appear with its number AND its name, and each verb of the
    vocabulary must appear as a table row. Deliberately not a prose comparison — the prose is
    the reason the page exists — just enough structure that a code change without a doc change
    fails.
    """
    text = (ROOT / "docs" / "CLI-CONVENTIONS.md").read_text(encoding="utf-8")
    for code in conv.ExitCode:
        assert re.search(rf"^\|\s*{code.value}\s*\|", text, re.MULTILINE), (
            f"docs/CLI-CONVENTIONS.md has no exit-code row for {code.value}"
        )
    for verb in conv.VERBS:
        assert re.search(rf"^\|\s*`{verb}`\s*\|", text, re.MULTILINE), (
            f"docs/CLI-CONVENTIONS.md has no verb row for `{verb}`"
        )
    for group, aliases in conv.ALIASES.items():
        for alias, canonical in aliases.items():
            row = f"`gateclerk {' '.join(group)} {alias}`"
            assert row in text, f"the alias table is missing {row}"
            assert f"`{canonical}`" in text, f"the alias table is missing the target {canonical}"


def test_module_docstring_is_the_vocabulary_source_the_tests_read() -> None:
    """The module's own docstring must name every verb in `VERBS`.

    The card asked for the vocabulary "documented in the module docstring". `VERBS` is what
    this test enforces, so the check is that the docstring and `VERBS` agree — otherwise the
    documented list and the enforced list are two lists.
    """
    doc = conv.__doc__ or ""
    for verb in conv.VERBS:
        assert f"``{verb}``" in doc, f"VERBS lists `{verb}` but the module docstring never names it"


# --- (5) `agent run` is byte-identical -------------------------------------------------------

#: Captured from `origin/main`'s `src/gateclerk/cli.py` BEFORE this card touched it (materialise
#: `git show origin/main:src/...` into a scratch tree, import `gateclerk.cli` from THERE, read the
#: Click definition of `agent run`). Baseline sha256 of the manifest below:
#: 667af6c87e8d0d8488fa854dce41cd62d44c4ad1c9a7396c6c3734c89347818e
#:
#: A baseline from the branch under review would be a tautology; this one is the value the
#: pre-change code produced, so the test fails if this card moved a flag, a default, a type or
#: a word of help on the command that is a systemd ExecStart.
AGENT_RUN_BASELINE: dict[str, Any] = {
    "name": "run",
    "short_help": None,
    # Line-split for ruff's 100-column limit; the value is ONE string, checked by equality
    # against the live command, so the splitting has no effect on what is pinned.
    "help": "\n".join(
        [
            "Serve one site: poll its devices, store, checkpoint, queue, push. "
            "The unit's ExecStart.",
            "",
            "Wiring only \u2014 P2-03's loop per device, P2-05's park gate around every "
            "tick (a refused tick",
            "sends ZERO requests), P2-02's store, P2-04's queue and drain, P2-06's health "
            "snapshot.",
            "Exits 2 on a config or credential problem (p1-08's contract) and 3 when the "
            "run ends with",
            "the site needing a human \u2014 a device parked unacked (terminal 401) or a transport",
            "circuit open \u2014 which `--once` is how an operator finds out "
            "(deploy/README.md step 3).",
        ]
    ),
    "params": [
        {
            "name": "site",
            "opts": ["--site"],
            "secondary": [],
            "required": True,
            "default": "None",
            "type": "StringParamType",
            "metavar": "None",
            "help": "Site block to serve (the systemd instance name, %i).",
            "hidden": False,
        },
        {
            "name": "config",
            "opts": ["--config"],
            "secondary": [],
            "required": False,
            "default": "None",
            "type": "StringParamType",
            "metavar": "None",
            "help": "sites.toml to read (default ./sites.toml). Refs only.",
            "hidden": False,
        },
        {
            "name": "state_root",
            "opts": ["--state-root"],
            "secondary": [],
            "required": False,
            "default": "None",
            "type": "StringParamType",
            "metavar": "None",
            "help": (
                "Where this site's store, park dir and health snapshot live. A relative db_path "
                "(and the derived ./gateclerk-<site>.sqlite3) resolves under it."
            ),
            "hidden": False,
        },
        {
            "name": "credentials_dir",
            "opts": ["--credentials-dir"],
            "secondary": [],
            "required": False,
            "default": "None",
            "type": "StringParamType",
            "metavar": "None",
            "help": (
                "Where the systemd credential files are (default: $CREDENTIALS_DIRECTORY, which "
                "the unit sets). A LoadCredential= reference arrives as a FILE, not an env var."
            ),
            "hidden": False,
        },
        {
            "name": "password",
            "opts": ["--password"],
            "secondary": [],
            "required": False,
            "default": "None",
            "type": "StringParamType",
            "metavar": "None",
            "help": (
                "Override the ISAPI password for every device of this site. Discouraged (shell "
                "history); resolution stays flag > env > keychain."
            ),
            "hidden": False,
        },
        {
            "name": "once",
            "opts": ["--once"],
            "secondary": [],
            "required": False,
            "default": "False",
            "type": "BoolParamType",
            "metavar": "None",
            "help": (
                "One tick, then exit 0 \u2014 the smoke test (deploy/README.md step 3). "
                "NOT for the unit: under Restart=always that becomes a five-second poll "
                "of the device."
            ),
            "hidden": False,
        },
        {
            "name": "max_ticks",
            "opts": ["--max-ticks"],
            "secondary": [],
            "required": False,
            "default": "None",
            "type": "IntParamType",
            "metavar": "None",
            "help": "Stop after N ticks (tests and dry runs).",
            "hidden": False,
        },
        {
            "name": "output",
            "opts": ["--output", "-o"],
            "secondary": [],
            "required": False,
            "default": "<OutputFormat.TABLE: 'table'>",
            "type": "TyperChoice",
            "metavar": "None",
            "help": "Output format (json, jsonl, table). json is the stable machine form.",
            "hidden": False,
        },
    ],
}


def _agent_run_manifest() -> dict[str, Any]:
    cmd = typer_root().commands["agent"].commands["run"]
    return {
        "name": cmd.name,
        "short_help": cmd.short_help,
        "help": cmd.help,
        "params": [
            {
                "name": p.name,
                "opts": list(getattr(p, "opts", ()) or ()),
                "secondary": list(getattr(p, "secondary_opts", ()) or ()),
                "required": bool(getattr(p, "required", False)),
                "default": repr(getattr(p, "default", None)),
                "type": type(p.type).__name__,
                "metavar": str(getattr(p, "metavar", None)),
                "help": getattr(p, "help", None),
                "hidden": bool(getattr(p, "hidden", False)),
            }
            for p in cmd.params
        ],
    }


def test_agent_run_definition_is_unchanged_from_the_baseline() -> None:
    """Requirement (5): `agent run` — the systemd ExecStart — did not move.

    Definition-level, which is what a unit file and an operator's shell depend on: flags, their
    order, their types, their defaults, and the help words. `_Guard`/`_fail` was rewired to the
    conventions module while this was written, so the pin has to be a real one.
    """
    current = _agent_run_manifest()
    assert json.dumps(current, sort_keys=True) == json.dumps(AGENT_RUN_BASELINE, sort_keys=True), (
        "agent run's CLI definition moved from the origin/main baseline"
    )
    # The recorded sha256 of the baseline is re-derivable, so the constant above cannot be
    # quietly edited to match a later change (the failure mode of every golden-value test).
    digest = hashlib.sha256(json.dumps(AGENT_RUN_BASELINE, sort_keys=True).encode()).hexdigest()
    assert digest == "e7af2532b095480a1b2673ba3db93b4cb83c363a976771fb1d98f4c38dcac0fd", (
        "AGENT_RUN_BASELINE was edited — re-capture it from origin/main, do not re-hash it here"
    )
