"""The `gateclerk sink` surface: list / add / remove / test, plus the per-sink checks.

Card SINKS-CLI. SINKS-CORE shipped the config half (`gateclerk.sinks`: the `[[site.sink]]`
registry, `SinkSpec`, `SiteConfig.effective_sinks`) and the per-sink storage identity
(`push_queue.sink_name`, `dead_letter.sink_name`). This module is the OPERATOR half: read
the sink list, edit the file safely, and answer "is this sink actually usable" — the three
things an operator at a site needs before the agent is started.

What lives here versus in `cli.py`
---------------------------------
Every rule is in this module and importable, so the CLI bodies stay three steps (resolve,
call, render) exactly as the `agent` and `migrate` groups did. Nothing in this module
imports typer or rich except through `gateclerk.output` at render time.

THE ONE LAW THIS MODULE EXISTS TO KEEP: **a reference is printed, a value never is.**
A sink's bearer token lives in an env var or a keychain item and the config names only
which of those holds it (`token_env` / `token_keychain`). Every string this module produces
is therefore built from names only — it never calls `Secret.reveal()`, never passes `-w` to
`security`, and never echoes a value it suspects is a secret (a refusal that prints the
rejected token would leak the token through the refusal). `tests/test_sinks_cli.py` sweeps
every subcommand's output for a planted secret, in the style of T15's
`test_token_never_logged`.

Why the file edit is read-parse-write-temp-rename
-------------------------------------------------
`sites.toml` is the deployment's truth: an agent unit reads it at start, so a half-written
or malformed file is an agent that will not start (or, worse, starts with a different sink
set than the operator believes). So an edit: (1) parses the CURRENT bytes with the real
validator, so we are never editing a file the product itself rejects; (2) builds the new
text in a temp file in the SAME directory (rename is atomic on the same filesystem); (3)
re-parses the temp file with the real validator and checks the intended sink is present
(and, for removal, absent, with every other sink byte-preserved); (4) only then
`os.replace`s. A crash at any point leaves either the old file or the new one, never a
truncated one, and the file the operator ends up with is one the config layer accepted.

Why `remove` touches the config file and nothing else
-----------------------------------------------------
Queue and dead-letter rows keep their `sink_name` (SINKS-CORE's migrations), and that is
the whole point: a punch that failed against a sink the operator just deleted is still
attributable, and `deadletter list` still shows it. Deleting config is not deleting
history, so `remove` opens no database connection for writing, deletes no row, and reports
the counts it left behind.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import subprocess
import tempfile
import tomllib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

if TYPE_CHECKING:  # the annotation is the only use; the value is imported where it is built
    from gateclerk.secrets import Secret

__all__ = [
    "CHECK_OK",
    "SINK_COLUMNS",
    "ProbeResult",
    "SinkCheck",
    "SinkEdit",
    "add_sink_block",
    "check_sink",
    "check_site_sinks",
    "keychain_item_exists",
    "remove_sink_block",
    "sink_rows",
    "token_ref_problem",
]

CHECK_OK = "ok"

#: The `sink list` table. `target` is the ref (a URL or a path — config, not a secret) and
#: `token_ref` names WHERE a bearer lives; there is deliberately no column a token value
#: could go in, and `render(..., columns=...)` is what pins the order for the human view.
SINK_COLUMNS = ("sink", "type", "target", "token_ref", "pending", "dead_letter")

#: Rows whose `sink_name` matches no configured sink get this label. The v5/v6 migration
#: mints `legacy+<id>` for a pre-upgrade event that had been buffered twice, and a sink
#: removed from config still has its rows: both are real backlog the operator has to see,
#: and neither belongs to a row of the table.
UNCONFIGURED_LABEL = "(unconfigured)"


class SinkCliError(Exception):
    """A refusal the operator has to act on (config file, sink name, or a secret-shaped
    flag). The CLI maps it onto exit 2 — the p1-08 "you have not told me how to reach it"
    class — so this module adds no exit code of its own.

    Messages here never interpolate a value the caller may have mistaken for a secret;
    `token_ref_problem` is the case that matters and it names the rule, not the string.
    """


# --- the secret-shaped flag guard -------------------------------------------------------------


def token_ref_problem(ref: object) -> str | None:
    """`None` when `ref` is a plausible REFERENCE name, else a refusal that does not echo it.

    `sink add --token-env/--token-keychain` take the NAME of an env var or a keychain
    service. The mistake this refuses is the one that puts a bearer token into a committed
    config file: an operator who types the token instead of the variable name must be
    stopped, and must not be shown the token again in the error text (that text goes to a
    terminal, a pipe, and often a ticket).

    Three rungs, cheapest first:

    * shape — a reference is a dotted/dashed/underscored token with no whitespace; a real
      bearer is not (it is base64/hex-shaped and usually carries `+`, `/` or `=`);
    * the repo's own base64 detector (`exceptions.redact_b64`, which is what already keeps
      a `security` stderr line from quoting a secret into an error) — if it fires, the
      string is a blob, not a name;
    * entropy — a long alnum run with NO separator (`.` `-` `_` `:`) and both digits and
      letters is a credential, not a name. `GATECLERK_INGEST_TOKEN_SITE-A`,
      `gateclerk-ingest-site-a` and `INGEST_BC_TOKEN` all pass; a 40-char random key does not.
    """
    if not isinstance(ref, str) or not ref.strip():
        return "a token reference is empty: name the env var or keychain service, not the value"
    if ref != ref.strip():
        return "a token reference has leading or trailing whitespace"
    if any(ch.isspace() for ch in ref):
        return (
            "a token reference contains whitespace: an env var name and a keychain service "
            "are single words (this looks like a VALUE, so it is refused and not echoed)"
        )
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._:\-]*$", ref):
        return (
            "a token reference may only contain letters, digits and `._:-` (a base64-shaped "
            "value with `+`, `/` or `=` is a secret, not a name — refused, not echoed)"
        )
    from gateclerk.exceptions import redact_b64

    if redact_b64(ref) != ref:
        return (
            "a token reference looks like a base64 payload: this flag takes the NAME of a "
            "keychain service or env var (the value stays out of sites.toml by design)"
        )
    # A credential-shaped RUNG can hide inside an otherwise name-shaped string: a bearer
    # like `sInK-ClI-6f3d9a1b7c5e4d2f` passes the shape test (letters, digits, dashes) and
    # survives redact_b64 (no `+`, `/` or `=`), but it carries a hex run of credential
    # length. A name segment that is >=16 chars of pure hex WITH a digit is a value
    # segment, not a word — none of the repo's real reference names contain one.
    for segment in re.split(r"[._:\-]+", ref):
        if (
            len(segment) >= 16
            and re.fullmatch(r"[0-9a-fA-F]+", segment)
            and any(ch.isdigit() for ch in segment)
        ):
            return (
                "a token reference contains a hex run the length of a real credential: "
                "this flag takes the NAME of a keychain service or env var (the value "
                "stays out of sites.toml by design; refused, not echoed)"
            )
    separators = set("._:-")
    if (
        len(ref) >= 24
        and not (set(ref) & separators)
        and any(c.isdigit() for c in ref)
        and any(c.isalpha() for c in ref)
    ):
        return (
            f"a token reference of {len(ref)} chars with no `_`, `-`, `.` or `:` separator "
            "looks like a credential, not a name: point the flag at a reference instead"
        )
    return None


# --- config-file editing ----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SinkEdit:
    """One applied config edit. Carries counts and names only — never the file's text."""

    config: str
    site: str
    changed: bool
    sink_names: tuple[str, ...]
    #: What the edit added or removed (`None` when the edit was a no-op).
    detail: str | None = None


_HEADER = re.compile(r"^\s*(?P<open>\[+)(?P<name>[^\[\]]+?)(?P<close>\]+)\s*(?P<comment>#.*)?$")


def _header_of(line: str) -> tuple[str, bool] | None:
    """`(dotted_name, is_array_of_tables)` for a TOML table header line, else None."""
    match = _HEADER.match(line)
    if match is None:
        return None
    name = match.group("name").strip()
    # Strip the quotes a quoted key would carry (`[[site."my sink"]]`) — we only ever
    # compare against `site` / `site.sink`, which are bare keys in this repo's schema.
    return name, match.group("open") == "[["


def _site_spans(lines: Sequence[str]) -> dict[str, tuple[int, int]]:
    """`{site_name: (header_index, end_index_exclusive)}` for each top-level site block.

    `config.parse_sites` is the authority on what the file MEANS; this is only the
    authority on where the bytes are. A block runs from its `[[site]]` header to just
    before the next TOP-LEVEL header (a header whose name has no dot), which is exactly
    TOML's own scope rule for a top-level array-of-tables. Trailing blank lines are cut
    from the span so an insertion lands with the block's keys, not in the gap before the
    next block.
    """
    starts: list[int] = []
    for index, line in enumerate(lines):
        header = _header_of(line)
        if header is not None and header[0] == "site":
            starts.append(index)
    spans: dict[str, tuple[int, int]] = {}
    for position, start in enumerate(starts):
        limit = starts[position + 1] if position + 1 < len(starts) else len(lines)
        # `name` is read from the parsed doc, not from the text: `name = "site-a"` may
        # carry comments, single quotes or be spread oddly, and the parser already knows.
        end = limit
        while end > start + 1 and not lines[end - 1].strip():
            end -= 1
        name = _site_name_of(lines[start:end])
        if name is not None:
            spans[name] = (start, end)
    return spans


def _site_name_of(block: Sequence[str]) -> str | None:
    """The block's `name` key, parsed the way TOML parses it (not by regex)."""
    doc = tomllib.loads("\n".join(block))
    site = doc.get("site")
    if isinstance(site, list) and site:
        value = site[0].get("name")
        return value if isinstance(value, str) else None
    return None


def _sink_element_ranges(lines: Sequence[str], start: int, end: int) -> list[tuple[int, int]]:
    """`(start, end)` for each `[[site.sink]]` element inside site block `[start, end)`.

    An element runs from its own header up to the next header that is NOT a sub-table of
    it (`[site.sink.headers]` travels with the sink it configures — TOML's own rule, and
    the difference between deleting a sink and deleting a sink plus its neighbour's
    headers). The site block's end closes the last element.
    """
    starts: list[int] = []
    ends: list[int] = []
    open_from: int | None = None
    for index in range(start + 1, end):
        header = _header_of(lines[index])
        if header is None:
            continue
        name, is_array = header
        if name == "site.sink" and is_array:
            if open_from is not None:
                ends.append(index)
            starts.append(index)
            open_from = index
        elif open_from is not None and not name.startswith("site.sink."):
            ends.append(index)
            open_from = None
    if open_from is not None:
        ends.append(end)
    return list(zip(starts, ends, strict=True))


def _element_table(lines: Sequence[str], element_range: tuple[int, int]) -> dict[str, Any]:
    """The parsed table of one `[[site.sink]]` element (parsed, not regex-matched)."""
    doc = tomllib.loads("\n".join(lines[element_range[0] : element_range[1]]))
    entries = doc.get("site", {}).get("sink", [])
    return entries[0] if entries else {}


def _read_sites(config: Path) -> bytes:
    """The file's bytes, refused early when it is not there or not readable.

    `config.load_sites` gives the same message for the same mistake, but it parses before
    we know which site the operator meant; this is the file-level half of that error.
    """
    try:
        return config.read_bytes()
    except FileNotFoundError:
        raise SinkCliError(
            f"sites file {config} not found: pass --config, or create it from "
            "sites.toml.example (one [[site]] block, refs only)"
        ) from None
    except OSError as exc:
        raise SinkCliError(f"cannot read sites file {config}: {exc.strerror or exc}") from None


def _install(config: Path, text: str, *, verify: Callable[[dict[str, Any]], None]) -> None:
    """Write `text` to `config` atomically, but only after the real validator accepts it.

    Temp file in the same directory (so `os.replace` cannot fall off a filesystem edge),
    `flush` + `fsync` (a crash between rename and flush loses the edit — the same
    fsync-before-marking-acked law the queue writes obey), then validate, then replace.
    `verify` raises `SinkCliError` to abort; the temp file is removed on every path.

    A validator refusal (`ConfigError` from the re-parse — "path must be absolute", an
    unknown rotation, anything the real config layer rejects) is folded into a
    `SinkCliError`, keeping the validator's own words. Without the fold the operator gets a
    bare traceback and exit 1 for what is a config refusal, and the difference matters:
    exit 2 is "your input was wrong", exit 1 is "the tool broke", and a script that retries
    on 1 would retry forever on a mistake that can only be fixed by editing the flag.
    """
    temp = config.parent / f".{config.name}.sink-tmp"
    try:
        with temp.open("w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        tomllib.loads(text)  # the bytes we are about to install are at least TOML
        try:
            verify({})
        except SinkCliError:
            raise
        except Exception as exc:  # the staged file is not what the deployment needs
            raise SinkCliError(f"{exc} — nothing was written to {config}") from None
        temp.replace(config)  # atomic: same directory, same filesystem (Path.replace law)
    except SinkCliError:
        raise
    except tomllib.TOMLDecodeError as exc:
        raise SinkCliError(
            f"the edited config would not parse ({exc}) — nothing was written to {config}"
        ) from exc
    except OSError as exc:
        raise SinkCliError(f"cannot write sites file {config}: {exc.strerror or exc}") from exc
    finally:
        temp.unlink(missing_ok=True)


def _require_site(raw: bytes, *, origin: str, site: str) -> Any:
    from gateclerk.config import parse_sites

    try:
        sites = parse_sites(raw, origin=origin)
    except Exception as exc:  # ConfigError and TOML errors are both "fix the file first"
        raise SinkCliError(str(exc)) from None
    if site not in sites:
        known = ", ".join(sorted(sites)) or "(none configured)"
        raise SinkCliError(f"no site named {site!r} in {origin}; configured: {known}")
    return sites[site]


def add_sink_block(
    config: Path | str,
    *,
    site: str,
    name: str,
    sink_type: str,
    url: str | None = None,
    path: str | None = None,
    rotation: str | None = None,
    token_env: str | None = None,
    token_keychain: str | None = None,
    to: str | None = None,
    timeout_s: float | None = None,
) -> SinkEdit:
    """Append one `[[site.sink]]` block to `site`'s block, atomically. Refuses loudly first.

    Refusals, in the order that is most useful to whoever typed the command:

    * a token flag that looks like a VALUE (`token_ref_problem`) — before anything is read,
      because this is the one mistake that leaves a credential in a committed file;
    * `sink_type` not in the registry — the registry is the list of types something will
      actually write, and SINKS-CORE's law is that an unknown type is refused, not skipped;
    * the site declaring `push_target` too — config law: two sources for one site's sinks
      would either double-push every punch or silently drop the legacy target;
    * a duplicate name, or the reserved `legacy` name;
    * the file, after the edit, not parsing or not carrying the sink we meant to add
      (`_install` re-parses before the rename, so an edit that would break the deployment
      never becomes the deployment).
    """
    target = Path(config)
    for flag, value in (("token-env", token_env), ("token-keychain", token_keychain)):
        if value is None:
            continue
        problem = token_ref_problem(value)
        if problem is not None:
            raise SinkCliError(f"--{flag}: {problem}")

    from gateclerk.sinks import IMPLICIT_SINK_NAME, SINK_TYPES, sink_name_problem

    if sink_type not in SINK_TYPES:
        known = " or ".join(sorted(SINK_TYPES))
        raise SinkCliError(
            f"sink type {sink_type!r} is unknown (accepted: {known}) — a sink whose type "
            "nobody implements must be refused, never written down and skipped"
        )
    problem = sink_name_problem(name)
    if problem is not None:
        raise SinkCliError(problem)
    if name == IMPLICIT_SINK_NAME:
        raise SinkCliError(
            f"sink name {IMPLICIT_SINK_NAME!r} is reserved: it is the implicit sink a site "
            "gets from `push_target` alone, and cannot be declared"
        )
    if (url is None) == (path is None) and sink_type != "mnotify":
        raise SinkCliError(
            "exactly one of --url (an https sink) or --path (a csv/jsonl sink) is required"
        )
    if sink_type == "mnotify":
        if url is not None or path is not None or rotation is not None:
            raise SinkCliError(
                "an mnotify sink takes --to (and optional --timeout-s); it is an alert "
                "route, not an event endpoint or file"
            )
        if to is None or not to.strip():
            raise SinkCliError("--to is required for an mnotify alert sink")
    elif to is not None or timeout_s is not None:
        raise SinkCliError("--to/--timeout-s are only valid for an mnotify sink")
    if timeout_s is not None and timeout_s <= 0:
        raise SinkCliError("--timeout-s must be > 0")
    if url is not None:
        _check_sink_url(url, sink=name)
    if rotation is not None:
        from gateclerk.sinks import ROTATIONS

        if rotation not in ROTATIONS:
            raise SinkCliError(
                f"rotation {rotation!r} is unknown (accepted: {' or '.join(ROTATIONS)})"
            )

    raw = _read_sites(target)
    existing = _require_site(raw, origin=str(target), site=site)
    if existing.push_target is not None:
        raise SinkCliError(
            f"site {site!r} still declares push_target = ... : `push_target` and "
            "[[site.sink]] cannot both be declared (one site would have two sources for "
            f"its sinks). Move the target in as a named sink first — `gateclerk sink add "
            f"--site {site} --name <name> --type https --url <that url>` and only then "
            "delete `push_target`."
        )
    declared = {spec.name for spec in existing.sinks}
    if name in declared:
        raise SinkCliError(
            f"site {site!r} already has a sink named {name!r}: two sinks with one name "
            "would share one queue row and silently merge their targets"
        )

    lines = raw.decode("utf-8").splitlines()
    spans = _site_spans(lines)
    if site not in spans:  # pragma: no cover - parse_sites already refused this shape
        raise SinkCliError(f"cannot locate the [[site]] block for {site!r} in {target}")
    _, end = spans[site]

    block = ["  [[site.sink]]", f"  name = {name!r}", f"  type = {sink_type!r}"]
    if url is not None:
        block.append(f"  url = {url!r}")
    if path is not None:
        block.append(f"  path = {path!r}")
    if rotation is not None:
        block.append(f"  rotation = {rotation!r}")
    if token_env is not None:
        block.append(f"  token_env = {token_env!r}")
    if token_keychain is not None:
        block.append(f"  token_keychain = {token_keychain!r}")
    if to is not None:
        block.append(f"  to = {to!r}")
    if timeout_s is not None:
        block.append(f"  timeout_s = {timeout_s!r}")

    edited = lines[:end] + block + lines[end:]
    wanted = tuple(sorted(declared | {name}))

    def verify(document: dict[str, Any]) -> None:
        del document
        from gateclerk.config import parse_sites

        site_after = parse_sites("\n".join(edited).encode("utf-8"), origin=f"{target} (staged)")[
            site
        ]
        got = tuple(sorted(spec.name for spec in site_after.effective_sinks))
        if got != wanted:
            raise SinkCliError(
                f"the edited config parses to sinks {got}, expected {wanted}: nothing written"
            )

    _install(target, "\n".join(edited) + "\n", verify=verify)
    return SinkEdit(
        config=str(target),
        site=site,
        changed=True,
        sink_names=wanted,
        detail=f"added sink {name!r} (type {sink_type})",
    )


def remove_sink_block(
    config: Path | str, *, site: str, name: str, keep_history: bool = True
) -> SinkEdit:
    """Delete one `[[site.sink]]` block from the config file. Queue and dead-letter rows stay.

    `keep_history` is not a flag that toggles behaviour — it is a pin: there is no code path
    here that opens the database for writing, and the card's law ("`sink remove` keeps
    queue/dead-letter rows") says it must stay that way. A sink whose rows are still queued
    keeps them under its own name; `sink list` shows that backlog as `UNCONFIGURED_LABEL`
    until the operator re-adds the sink or the rows drain, and `agent deadletter` still
    lists what died against it.

    The implicit `legacy` sink is refused: it is not a config entry, and deleting it means
    deleting `push_target` — an edit the operator should make on purpose.
    """
    del keep_history  # see docstring: nothing here touches the db
    target = Path(config)
    raw = _read_sites(target)
    existing = _require_site(raw, origin=str(target), site=site)
    from gateclerk.sinks import IMPLICIT_SINK_NAME

    if name == IMPLICIT_SINK_NAME:
        raise SinkCliError(
            f"sink {IMPLICIT_SINK_NAME!r} is the implicit sink a site gets from "
            "`push_target`; it is not a [[site.sink]] entry — delete the site's "
            "`push_target` line to turn the pusher off"
        )
    if name not in {spec.name for spec in existing.sinks}:
        known = ", ".join(sorted(spec.name for spec in existing.sinks)) or "(none declared)"
        raise SinkCliError(
            f"site {site!r} declares no sink named {name!r} (declared: {known}); the "
            "config file was not modified"
        )

    lines = raw.decode("utf-8").splitlines()
    start, end = _site_spans(lines)[site]
    victims = [
        element_range
        for element_range in _sink_element_ranges(lines, start, end)
        if _element_table(lines, element_range).get("name") == name
    ]
    if len(victims) != 1:  # pragma: no cover - parse_sites already refuses duplicates
        raise SinkCliError(
            f"found {len(victims)} [[site.sink]] blocks named {name!r} in {target}; "
            "the config file was not modified"
        )
    element_start, element_end = victims[0]
    edited = lines[:element_start] + lines[element_end:]
    survivors = tuple(sorted(s for s in (spec.name for spec in existing.sinks) if s != name))

    def verify(document: dict[str, Any]) -> None:
        del document
        from gateclerk.config import parse_sites

        site_after = parse_sites("\n".join(edited).encode("utf-8"), origin=f"{target} (staged)")[
            site
        ]
        got = tuple(sorted(spec.name for spec in site_after.sinks))
        if got != survivors:
            raise SinkCliError(
                f"after the edit the site's sinks are {got}, expected {survivors}: nothing written"
            )

    _install(target, "\n".join(edited) + "\n", verify=verify)
    return SinkEdit(
        config=str(target),
        site=site,
        changed=True,
        sink_names=survivors,
        detail=f"removed sink {name!r} (queue and dead-letter rows kept)",
    )


def _check_sink_url(url: str, *, sink: str) -> None:
    """Parse the url NOW, at the moment of writing, rather than at the first push.

    `sinks._build_https` already refuses a bad scheme; this adds the two shapes it cannot
    see (a URL with no host, and credentials smuggled into the netloc, which would put a
    secret in the file by the back door). `stub://` is a sink ref like it is a push_target
    ref (§3), so it is allowed here too — and `stub://` writing a local file is the
    owner-authorized dry-run ingest, not a secret.
    """
    from gateclerk.sinks import SINK_URL_SCHEMES

    if not url.startswith(SINK_URL_SCHEMES):
        allowed = " or ".join(SINK_URL_SCHEMES)
        raise SinkCliError(
            f"sink {sink!r}: url {url!r} must start with {allowed} — no endpoint is ever "
            "invented (docs/P2-SITE-AGENT.md §3)"
        )
    parts = urlsplit(url)
    if not parts.netloc:
        raise SinkCliError(f"sink {sink!r}: url {url!r} names no host")
    if "@" in parts.netloc:
        raise SinkCliError(
            f"sink {sink!r}: url must not carry credentials in its netloc — a bearer token "
            "has exactly one home, `token_env` / `token_keychain` (a reference)"
        )


# --- the sink table ---------------------------------------------------------------------------


def _counts_by_sink(conn: Any) -> dict[str, dict[str, int]]:
    """`{sink_name: {pending, dead_letter}}` read from the site's store (never written).

    Two literal queries rather than one assembled from a loop variable: the table names are
    constants in this file, and a query built by concatenation is the shape S608 exists to
    flag — a function this short has no reason to ask a reader to prove the variable is safe.
    """
    counts: dict[str, dict[str, int]] = {}
    pending = conn.execute("SELECT sink_name, COUNT(*) AS n FROM push_queue GROUP BY sink_name")
    for row in pending:
        _add_count(counts, str(row["sink_name"]), "pending", int(row["n"]))
    dead = conn.execute("SELECT sink_name, COUNT(*) AS n FROM dead_letter GROUP BY sink_name")
    for row in dead:
        _add_count(counts, str(row["sink_name"]), "dead_letter", int(row["n"]))
    return counts


def _add_count(counts: dict[str, dict[str, int]], sink_name: str, key: str, amount: int) -> None:
    counts.setdefault(sink_name, {"pending": 0, "dead_letter": 0})[key] = amount


def token_ref_text(site: str, spec: Any) -> str:
    """What we may SAY about a sink's bearer token: the reference, and nothing else.

    Absence of `token_env`/`token_keychain` is not "no token" — it is the implicit sink's
    signal to use Task 15's per-site rungs, so the text names those two rungs. A value is
    never resolved here, let alone printed: `KeychainReader.read` and `Secret.reveal` are
    not called on this path at all.
    """
    from gateclerk.agent_push import ingest_keychain_service, ingest_token_env_var

    if spec.token_env and spec.token_keychain:
        return f"env {spec.token_env} | keychain {spec.token_keychain}"
    if spec.token_env:
        return f"env {spec.token_env}"
    if spec.token_keychain:
        return f"keychain {spec.token_keychain}"
    return (
        f"default rungs: env {ingest_token_env_var(site)} "
        f"| keychain {ingest_keychain_service(site)}"
    )


def _no_sinks_row(site: Any) -> dict[str, Any]:
    """The row `sink list` prints for a site with no sinks (the pusher is off).

    A bare `list` must answer, not raise: an operator listing a site to find out why
    nothing is arriving gets one more useful answer than a traceback.
    """
    return {
        "sink": "(none)",
        "type": "-",
        "target": "no push_target and no [[site.sink]] — the pusher is off for this site",
        "token_ref": "-",
        "pending": 0,
        "dead_letter": 0,
    }


def sink_rows(
    site: Any,
    *,
    conn: Any | None = None,
) -> list[dict[str, Any]]:
    """One row per sink the site has: name, type, target, token REF, pending, dead-letter.

    `conn` is optional because `list` is a read: a site that has never been polled has no
    store, and "no store yet" is not an error worth failing a listing over (the counts are
    then 0, which is also true of them). The per-sink counts are grouped by `sink_name`, so
    a row addressed to a sink that is no longer configured shows up under
    `UNCONFIGURED_LABEL` rather than vanishing — the whole point of keeping those rows is
    that somebody can still find them.
    """
    counts = _counts_by_sink(conn) if conn is not None else {}
    sinks = site.effective_sinks
    if not sinks:
        return [_no_sinks_row(site)]
    rows: list[dict[str, Any]] = []
    configured: set[str] = set()
    for spec in sinks:
        configured.add(spec.name)
        per = counts.get(spec.name, {"pending": 0, "dead_letter": 0})
        rows.append(
            {
                "sink": spec.name,
                "type": spec.type,
                "target": spec.ref,
                "token_ref": token_ref_text(site.name, spec) if spec.type == "https" else "-",
                "pending": per["pending"],
                "dead_letter": per["dead_letter"],
            }
        )
    leftover = {name: per for name, per in counts.items() if name not in configured}
    if leftover:
        rows.append(
            {
                "sink": UNCONFIGURED_LABEL,
                "type": "-",
                "target": "-",
                "token_ref": "-",
                "pending": sum(per["pending"] for per in leftover.values()),
                "dead_letter": sum(per["dead_letter"] for per in leftover.values()),
            }
        )
    return rows


# --- the per-sink checks (`sink test`, and what `gateclerk doctor` will call) -------------------


@dataclass(frozen=True, slots=True)
class SinkCheck:
    """One named check of one sink. `ok` is the verdict; `detail` is REFs and integers.

    `detail` is the string that reaches a terminal and a log, so it is built from names,
    statuses and counts only — see the module docstring's one law.
    """

    sink: str
    check: str
    ok: bool
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {"sink": self.sink, "check": self.check, "ok": self.ok, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """The outcome of the one benign probe `sink test` sends. Never carries a payload."""

    sink: str
    ok: bool
    summary: str


def keychain_item_exists(
    service: str,
    *,
    account: str,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] | None = None,
    binary: str | None = None,
) -> bool | None:
    """Whether a generic-password item EXISTS — an attribute lookup, never a read.

    No `-w`: the whole point is that this answer is printable and loggable. `-w` would put
    the token in this process's memory (and on macOS the whole reason `KeychainReader` makes
    one call instead of two is that each call can raise an ACL prompt — so a diagnostic that
    prompts on every run is a diagnostic nobody runs).

    Returns None when the keychain is not available here (a Linux agent host, CI): "I cannot
    tell" is a different answer from "it is not there", and printing the first as the second
    would send an operator looking in the wrong place.
    """
    from gateclerk.config import SECURITY_BIN

    executable = binary or SECURITY_BIN
    if runner is None and shutil.which(executable) is None:
        return None
    run = runner or subprocess.run
    argv = [executable, "find-generic-password", "-s", service, "-a", account]
    try:
        completed = run(argv, capture_output=True, check=False)
    except OSError:
        return None
    return int(completed.returncode) == 0


def _token_rungs(site: str, spec: Any) -> tuple[tuple[str, str], ...]:
    """The (kind, name) references a sink's bearer would be read from, in precedence order.

    Explicit `token_env`/`token_keychain` when the sink declares them, else Task 15's
    per-site defaults — the same two names `agent_push` resolves, imported rather than
    re-derived so the doctor can never describe a rung the transport does not read.
    """
    from gateclerk.agent_push import ingest_keychain_service, ingest_token_env_var

    if spec.token_env or spec.token_keychain:
        rungs: list[tuple[str, str]] = []
        if spec.token_env:
            rungs.append(("env", spec.token_env))
        if spec.token_keychain:
            rungs.append(("keychain", spec.token_keychain))
        return tuple(rungs)
    return (
        ("env", ingest_token_env_var(site)),
        ("keychain", ingest_keychain_service(site)),
    )


def check_sink(
    site: Any,
    spec: Any,
    *,
    env: Mapping[str, str] | None = None,
    keychain_probe: Callable[[str, str], bool | None] | None = None,
    other_paths: Sequence[str] = (),
) -> tuple[SinkCheck, ...]:
    """Every config-level check one sink must pass, as data. No socket, no secret.

    This is the function `gateclerk doctor` is meant to call per sink (see `sink test`'s
    docstring for why it is surfaced here until CLI-DOCTOR lands). It answers the question
    "could this sink deliver anything", which is a different question from "did it
    deliver", and answers it without sending a byte — a doctor that probes the ingest on
    every run is a doctor that spends a keychain prompt and a request per sink.
    """
    from gateclerk.sinks import sink_spec_problem

    checks: list[SinkCheck] = []
    problem = sink_spec_problem(spec)
    checks.append(
        SinkCheck(
            sink=spec.name,
            check="config",
            ok=problem is None,
            detail="valid" if problem is None else problem,
        )
    )
    if problem is not None:
        return tuple(checks)

    if spec.type == "https":
        checks.append(_check_https_url(spec))
        checks.append(_check_token_refs(site, spec, env=env, keychain_probe=keychain_probe))
        return tuple(checks)

    if spec.type == "mnotify":
        recipient = spec.to or ""
        ok = bool(recipient.strip()) and "\n" not in recipient and "\r" not in recipient
        checks.append(
            SinkCheck(
                sink=spec.name,
                check="recipient",
                ok=ok,
                detail=(
                    f"mnotify mail to {recipient}"
                    if ok
                    else "no usable `to` recipient — alerts would fall back to stderr"
                ),
            )
        )
        return tuple(checks)

    # csv / jsonl: the path is a directory the agent must be able to write, a rotation the
    # writer has a rule for, and a target no other sink shares.
    path = Path(spec.path or "")
    directory = path.parent
    writable = directory.is_dir() and os.access(directory, os.W_OK)
    checks.append(
        SinkCheck(
            sink=spec.name,
            check="directory",
            ok=writable,
            detail=(
                f"{directory} is writable"
                if writable
                else f"{directory} is not writable (create it and give the agent write "
                "access before the first push)"
            ),
        )
    )
    checks.append(
        SinkCheck(
            sink=spec.name,
            check="rotation",
            ok=True,
            detail=spec.rotation or "none",
        )
    )
    clash = sorted({other for other in other_paths if other == spec.path})
    checks.append(
        SinkCheck(
            sink=spec.name,
            check="path-collision",
            ok=not clash,
            detail=(
                "unique"
                if not clash
                else f"collides with another sink on {spec.path!r} — two sinks writing one "
                "file interleave rows and neither sink's archive is readable"
            ),
        )
    )
    return tuple(checks)


def _check_https_url(spec: Any) -> SinkCheck:
    parts = urlsplit(spec.ref)
    ok = bool(parts.scheme and parts.netloc)
    return SinkCheck(
        sink=spec.name,
        check="url",
        ok=ok,
        detail=(
            f"{parts.scheme}://{parts.netloc} parses"
            if ok
            # The failing line names the sink in its own text, not only in the `sink`
            # column: an operator copies one line into a ticket, and "url does not parse"
            # without a subject is the line nobody can act on.
            else f"sink {spec.name!r}: url {spec.ref!r} does not parse to a scheme and host"
        ),
    )


def default_keychain_secret(service: str, account: str) -> Secret | None:
    """Read a bearer from a keychain item; `None` when it is missing or unreadable.

    The module-level seam for the PROBE's keychain rung, so a test replaces exactly this
    name and the suite never spawns `security`. Unlike the CHECK layer's probe (an
    attribute lookup, deliberately without `-w`), reading the value is legitimate here: a
    probe has to put the bearer in a header or it proves nothing. `with_comment=False`
    because each extra `security` invocation is another macOS ACL prompt.
    """
    from gateclerk.config import DeviceTarget, KeychainReader

    try:
        item = KeychainReader().read(
            DeviceTarget(host=account, site=account, keychain_service=service),
            with_comment=False,
        )
    except Exception:
        # `CredentialUnavailable` covers "item missing", "access denied" and "binary not
        # here" (a Linux agent host). The reader's own message names service/account and
        # never the value; the probe line does not need more than "not readable".
        return None
    return item.password or None


def _probe_token(
    site: Any,
    spec: Any,
    *,
    env: Mapping[str, str] | None,
    keychain: Callable[[str, str], Secret | None] | None,
):
    """The bearer the probe would send, or the ProbeResult saying which rungs came up empty.

    The probe resolves the token from the SINK's own references (`token_env` /
    `token_keychain`, falling back to the site defaults), the same rungs `check_sink`
    reports. Handing the transport the site default instead would be a different bug with a
    friendly face: a sink configured with its own env var would be probed with — and
    attributed to — some other credential, and a green probe would prove the wrong thing.

    A probe with no token refuses rather than sending: an unauthenticated POST comes back
    401 and the operator reads "reachable but UNAUTHENTICATED" as a problem at the ingest
    rather than a missing keychain item on their own machine. The token leaves here as a
    `Secret` and never becomes a string this module could print.
    """
    from gateclerk.secrets import Secret

    environ: Mapping[str, str] = os.environ if env is None else env
    read_secret = keychain if keychain is not None else default_keychain_secret
    account = site.name if isinstance(site.name, str) else str(site.name)
    attempted: list[str] = []
    for kind, name in _token_rungs(site.name, spec):
        if kind == "env":
            value = environ.get(name)
            if value:
                return Secret(value, label=f"env:{name}")
            attempted.append(f"env {name}: not set")
            continue
        secret = read_secret(name, account)
        if secret is not None and secret.reveal():
            return secret
        attempted.append(f"keychain {name}: item not readable")
    return ProbeResult(
        sink=spec.name,
        ok=False,
        summary=(
            "no bearer token to probe with ("
            + "; ".join(attempted)
            + ") — nothing was sent: an unauthenticated POST answers 401 and proves nothing"
        ),
    )


def default_keychain_probe(service: str, account: str) -> bool | None:
    """The probe used when a caller does not inject one (the module-level seam, so a test
    replaces exactly this name and `security` is never spawned by the suite).
    """
    return keychain_item_exists(service, account=account)


def _check_token_refs(
    site: Any,
    spec: Any,
    *,
    env: Mapping[str, str] | None,
    keychain_probe: Callable[[str, str], bool | None] | None,
) -> SinkCheck:
    """Name each rung a bearer would come from and whether it resolves. Values are not read.

    An env rung is checked with `in env` (presence), not by printing `env[name]`. The
    keychain rung is an attribute lookup without `-w`. `keychain_probe` is injectable so the
    suite never spawns `security`, exactly as `KeychainReader`'s `runner` seam exists for.
    """
    environ: Mapping[str, str] = os.environ if env is None else env
    account = site.name if isinstance(site.name, str) else str(site.name)
    resolved: list[str] = []
    for kind, name in _token_rungs(site.name, spec):
        if kind == "env":
            present = bool(environ.get(name))
            resolved.append(f"env {name}: {'set' if present else 'not set'}")
            if present:
                return SinkCheck(
                    sink=spec.name,
                    check="token-ref",
                    ok=True,
                    detail="; ".join(resolved),
                )
        else:
            probe = keychain_probe or default_keychain_probe
            exists = probe(name, account)
            label = (
                "item present"
                if exists is True
                else "item NOT FOUND"
                if exists is False
                else "keychain unavailable here"
            )
            resolved.append(f"keychain {name}: {label}")
            if exists is True:
                return SinkCheck(
                    sink=spec.name,
                    check="token-ref",
                    ok=True,
                    detail="; ".join(resolved),
                )
    return SinkCheck(
        sink=spec.name,
        check="token-ref",
        ok=False,
        detail="; ".join(resolved)
        + " — queued events stay queued until one rung answers (no attempts are burned)",
    )


def check_site_sinks(
    site: Any,
    *,
    env: Mapping[str, str] | None = None,
    keychain_probe: Callable[[str, str], bool | None] | None = None,
) -> tuple[SinkCheck, ...]:
    """Every sink of one site, checked. An unknown type still gets a named, failing check.

    `sink_spec_problem` refuses an unregistered type, and a site built in code (not from
    TOML) can carry one; the operator must be told WHICH sink is broken rather than get a
    traceback from the doctor.
    """
    sinks = site.effective_sinks
    paths = [spec.path for spec in sinks if spec.path]
    checks: list[SinkCheck] = []
    for spec in sinks:
        checks.extend(
            check_sink(
                site,
                spec,
                env=env,
                keychain_probe=keychain_probe,
                other_paths=[p for p in paths if p != spec.path],
            )
        )
    return tuple(checks)


# --- the probe `sink test` sends ----------------------------------------------------------------


#: How `sink test` explains the statuses a benign probe can come back with. The ingest's
#: own contract (functions/main.py `gateclerk_ingest`, mirrored in docs/P2-SITE-AGENT.md §3):
#: 200 accepted, 401/403 credential-or-site problem, 422 payload problem, 5xx the ingest's
#: own trouble (retryable), anything else unexpected. A probe sends an EMPTY batch, so a
#: 200 proves reachability + auth + the header contract without writing a punch anywhere.
_STATUS_TEXT: dict[int, tuple[bool, str]] = {
    200: (True, "reachable and authenticated: the ingest accepted an empty batch"),
    400: (False, "the ingest rejected the empty batch as malformed (expected a JSONL body)"),
    401: (False, "reachable but UNAUTHENTICATED: the bearer was absent or wrong"),
    403: (False, "reachable but refused: the token does not name this site"),
    404: (False, "reachable but the path is not the ingest endpoint (check the url)"),
    405: (False, "reachable but the method is not accepted (the ingest takes POST)"),
    422: (False, "reachable and authenticated; the ingest rejected the payload shape"),
    502: (False, "reachable, but the ingest's own upstream failed (retryable)"),
    503: (False, "reachable, but the ingest is not serving (retryable)"),
    504: (False, "reachable, but the ingest timed out upstream (retryable)"),
}


def probe_sink(
    site: Any,
    spec: Any,
    *,
    send: Callable[[str, str], int] | None = None,
    env: Mapping[str, str] | None = None,
    keychain: Any = None,
    client: Any = None,
) -> ProbeResult:
    """One benign probe. https: an EMPTY JSONL POST. csv/jsonl: a `.probe` file, removed.

    Empty-JSONL rather than a real punch on purpose: `sink test` must not be able to put a
    fake employee into a payroll archive, and the ingest's idempotency key is a fingerprint
    of the payload, so a second probe with the same fake line would be *replayed* and the
    test would report a success nobody earned. An empty batch still exercises the URL, TLS,
    the bearer, `Content-Type: application/jsonl` and the `X-GateClerk-Site` confirmation —
    which is everything the operator got wrong when the sink was configured.

    A file sink is probed by creating `<path>.probe` with `xb` (exclusive) then removing it:
    exclusive create proves the directory is writable AND that no stale probe is sitting
    there, and writing nothing at all proves it does not need to touch the real file.

    `send` is the seam (the suite must not open a socket; conftest's netoff would kill one
    anyway). Unwrapped exceptions become summary text, never a traceback, and carry only
    the exception's CLASS NAME and message — a transport message can quote a URL, and a URL
    is fine, a header value never is (the token is only ever inside `Secret`).
    """
    if spec.type == "https":
        return _probe_https(site, spec, send=send, env=env, keychain=keychain, client=client)
    if spec.type in ("csv", "jsonl"):
        return _probe_file(site, spec)
    if spec.type == "mnotify":
        return _probe_mnotify(spec)
    return ProbeResult(
        sink=spec.name,
        ok=False,
        summary=f"type {spec.type!r} is not registered, so nothing can be probed",
    )


def _probe_mnotify(spec: Any) -> ProbeResult:
    """A no-network `mnotify ... --dry-run --json` probe (the contract's own dry-run).

    The body still goes in a file (the real call's shape), the argv is still a list, and
    mnotify performs no token or network call. Exit 0 means the CLI accepted the target
    and config; a non-zero code is reported as the sink's problem, with the document's
    message when mnotify supplied one.
    """
    from gateclerk.agent_mnotify import MNOTIFY_BINARY

    if not spec.to:
        return ProbeResult(sink=spec.name, ok=False, summary="no `to` recipient configured")
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        prefix="gateclerk-sink-probe-",
        suffix=".md",
        delete=False,
    ) as handle:
        handle.write("gateclerk sink test (dry run; nothing is sent)\n")
        body_path = handle.name
    try:
        argv = [
            MNOTIFY_BINARY,
            "mail",
            "send",
            "--to",
            spec.to,
            "--subject",
            "gateclerk sink test",
            "--body-file",
            body_path,
            "--dry-run",
            "--json",
        ]
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell, mnotify's own CLI
                argv,
                capture_output=True,
                text=True,
                timeout=min(spec.timeout_s or 30.0, 30.0),
                check=False,
            )
        except FileNotFoundError:
            return ProbeResult(
                sink=spec.name,
                ok=False,
                summary=f"{MNOTIFY_BINARY!r} not found on PATH — alerts fall back to stderr",
            )
        except subprocess.TimeoutExpired:
            return ProbeResult(
                sink=spec.name, ok=False, summary="mnotify dry-run timed out; nothing was sent"
            )
        except OSError as exc:
            return ProbeResult(
                sink=spec.name,
                ok=False,
                summary=f"could not run {MNOTIFY_BINARY!r} ({type(exc).__name__}: {exc})",
            )
        if proc.returncode == 0:
            return ProbeResult(
                sink=spec.name,
                ok=True,
                summary="mnotify dry-run accepted the command (no token or network call)",
            )
        message = ""
        try:
            import json

            document = json.loads(proc.stdout) if proc.stdout.strip() else {}
            if isinstance(document, dict):
                message = str(document.get("message") or "")
        except ValueError:
            message = (proc.stderr or "").strip()
        detail = f"mnotify dry-run exited {proc.returncode}"
        return ProbeResult(
            sink=spec.name,
            ok=False,
            summary=f"{detail}: {' '.join(message.split()) or 'no message'}",
        )
    finally:
        with contextlib.suppress(OSError):
            Path(body_path).unlink(missing_ok=True)


def _probe_https(
    site: Any,
    spec: Any,
    *,
    send: Callable[[str, str], int] | None,
    env: Mapping[str, str] | None,
    keychain: Callable[[str, str], Secret | None] | None,
    client: Any = None,
) -> ProbeResult:
    """Send the empty batch through the real transport unless a `send` seam was injected.

    The transport is built, used once and closed here — a probe is not a long-lived client,
    and the httpx pool a transport opens would otherwise outlive the command that asked the
    question. `connect_timeout_s` is tighter than the pusher's: `sink test` is a human
    waiting at a terminal, and an unreachable host should say so in five seconds.

    The bearer is resolved HERE (`_probe_token`), against the sink's own references, and
    handed to the transport as the explicit token — the transport's own flag>env>keychain
    ladder is therefore never consulted, which is the point: the doctor and the probe must
    read the same rung or the check line and the probe line would describe different
    credentials.
    """
    if send is not None:
        try:
            return _map_status(spec, send(spec.ref, ""), sink=spec.name)
        except Exception as exc:
            return _probe_exception(spec, exc)

    from gateclerk.agent_push import https_transport

    token = _probe_token(site, spec, env=env, keychain=keychain)
    if isinstance(token, ProbeResult):
        return token

    built = https_transport(
        site.name,
        token=token,
        client=client,
        connect_timeout_s=5.0,
        read_timeout_s=10.0,
    )
    try:
        return _map_status(spec, built(spec.ref, ""), sink=spec.name)
    except Exception as exc:
        return _probe_exception(spec, exc, secret=token)
    finally:
        built.close()


def _map_status(spec: Any, status: int, *, sink: str) -> ProbeResult:
    ok, text = _STATUS_TEXT.get(
        status,
        (
            False,
            f"unexpected status {status} from the ingest"
            if status >= 400
            else f"status {status} (not the 200 the contract promises)",
        ),
    )
    return ProbeResult(sink=sink, ok=ok, summary=f"HTTP {status}: {text}")


def _probe_exception(spec: Any, exc: Exception, *, secret: Secret | None = None) -> ProbeResult:
    """A probe failure is data: class name plus message, and the message is scanned TWICE.

    Two belts, because they catch different things. `redact_b64` is the repo's existing
    detector for "a foreign string may sit next to a secret" (it is what `security` stderr
    goes through) and it catches base64-shaped blobs it can recognize on sight. It cannot
    catch THE token itself — a bearer shaped like `sInK-ClI-6f3d9a1b…` is not base64 and
    would sail through. `redact` removes the specific value this probe resolved, so an
    exception whose message quotes the credential the caller just handed the transport
    (a proxy error, a library that echoes headers into its own errors) cannot leak it.

    `sink test` is the command an operator pipes into a ticket, which is exactly why the
    stronger belt belongs here and not only in the pusher's logs.
    """
    from gateclerk.exceptions import redact_b64
    from gateclerk.secrets import redact

    return ProbeResult(
        sink=spec.name,
        ok=False,
        summary=(
            "no answer from the target ("
            f"{type(exc).__name__}: {redact_b64(redact(str(exc), secret)) or 'no message'})"
        ),
    )


def _probe_file(site: Any, spec: Any) -> ProbeResult:
    target = Path(spec.path or "")
    probe = target.parent / f"{target.name}.probe"
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with probe.open("xb") as handle:  # 'x': refuse a stale probe instead of clobbering
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        return ProbeResult(
            sink=spec.name,
            ok=False,
            summary=(
                f"{probe} already exists from an earlier probe — remove it, then re-run "
                "(a leftover means the probe was interrupted mid-write)"
            ),
        )
    except OSError as exc:
        return ProbeResult(
            sink=spec.name,
            ok=False,
            summary=(
                f"cannot write in {target.parent} ({type(exc).__name__}: {exc.strerror or exc})"
            ),
        )
    probe.unlink(missing_ok=True)
    return ProbeResult(
        sink=spec.name,
        ok=True,
        summary=f"wrote and removed {probe.name} in {target.parent} (the sink file itself "
        f"was not touched; rotation {spec.rotation})",
    )
