"""The `gateclerk sink` group: named typed sinks (SINKS-CORE / SINKS-CLI).

CLI-SPLIT-STRUCTURE moved this group verbatim out of `gateclerk.cli`; `gateclerk.cli` attaches
it with `sink_cmds.register(app)`. The RULES of sink editing live in `sink_cli.py` (which
stays typer-free and importable without a CLI); this module is only the Click surface —
resolve → call → render. One-way import law: `gateclerk.cli` imports this module; this module
imports `gateclerk.cli_shared`, never `gateclerk.cli`.

The one law every body here obeys: **print the REFERENCE, never the value.** A sink's
bearer token lives in an env var or a keychain item and sites.toml names only which;
`token_ref` is a name column and there is no column a value could go in. `sink_cli` never
resolves a token at all — not on `list`, not on `test` (which posts an empty batch through
the transport, so the value enters only the transport's own `Secret`, exactly as it does on
a real push).

Exit codes are p1-08's contract, unchanged: 2 covers every refusal here, including a
`sink test` that came back unhealthy. A failing test is nearly always the same class of
problem as a failing `creds test` — an install step nobody ran — and the summary text, not
a new number, is what says which.

    gateclerk sink list   --site S
    gateclerk sink add    --site S --name N --type https --url U [--token-env R]
                                                            [--token-keychain R]
    gateclerk sink remove --site S --name N
    gateclerk sink test   --site S --name N [--probe]
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

import typer

from gateclerk import config as cfg
from gateclerk import sink_cli
from gateclerk.cli_shared import (
    CONFIG_ERROR_EXIT,
    AgentConfigOpt,
    AgentSiteOpt,
    AgentStateRootOpt,
    OutputOpt,
    _config_exit,
)
from gateclerk.exceptions import ConfigError
from gateclerk.output import OutputFormat, make_console, render

# --- sink (SINKS-CORE / SINKS-CLI: named typed sinks) ---------------------------------
#
#     gateclerk sink list   --site S
#     gateclerk sink add    --site S --name N --type https --url U [--token-env R]
#                                                             [--token-keychain R]
#     gateclerk sink remove --site S --name N
#     gateclerk sink test   --site S --name N [--probe]
#
# `sink list` reads and never writes; `add`/`remove` edit sites.toml through
# `sink_cli`'s atomic, re-validated edit (the command body stays resolve → call → render,
# the same three steps `agent` and `migrate` use). The one law every body here obeys:
# **print the REFERENCE, never the value.** A sink's bearer token lives in an env var or a
# keychain item and sites.toml names only which; `token_ref` is a name column and there is
# no column a value could go in. `sink_cli` never resolves a token at all — not on `list`,
# not on `test` (which posts an empty batch through the transport, so the value enters only
# the transport's own `Secret`, exactly as it does on a real push).
#
# Exit codes are p1-08's contract, unchanged: 2 covers every refusal here, including a
# `sink test` that came back unhealthy. A failing test is nearly always the same class of
# problem as a failing `creds check` — an install step nobody ran — and the summary text,
# not a new number, is what says which.

sink_app = typer.Typer(
    name="sink",
    help=(
        "Delivery sinks (one site, N named targets): list them, edit the config safely, "
        "and check one is usable. Token references are printed; token values never are."
    ),
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)

SinkNameOpt = Annotated[
    str,
    typer.Option("--name", help="Sink name (letters, digits, underscore; `legacy` is reserved)."),
]
SinkTypeOpt = Annotated[
    str,
    typer.Option(
        "--type",
        help="Sink type: `https`, `csv`, `jsonl` or `mnotify` (the registered types).",
    ),
]
SinkUrlOpt = Annotated[
    str | None,
    typer.Option(
        "--url",
        help="An https sink's ingest URL (`https://…`, or the owner-authorized `stub://…`). "
        "Never a default endpoint.",
    ),
]
SinkPathOpt = Annotated[
    str | None,
    typer.Option(
        "--path",
        help="A csv/jsonl sink's ABSOLUTE file path (a relative path resolves against the "
        "service's working directory, which is deployment state, not config).",
    ),
]
SinkRotationOpt = Annotated[
    str | None,
    typer.Option("--rotation", help="File-sink rotation: `daily` (the default) or `monthly`."),
]
SinkToOpt = Annotated[
    str | None,
    typer.Option(
        "--to",
        help="An mnotify alert sink's mail recipient. mnotify owns the transport, "
        "credentials and allowlist; gateclerk only execs it.",
    ),
]
SinkTimeoutOpt = Annotated[
    float | None,
    typer.Option(
        "--timeout-s",
        help="An mnotify alert sink's hard exec timeout in seconds (default 300, the "
        "micro-notify mail budget).",
    ),
]
SinkTokenEnvOpt = Annotated[
    str | None,
    typer.Option(
        # The name is given explicitly: derived from the parameter, click would spell the
        # flag `--token_env` (an underscore in a flag name nobody would type).
        "--token-env",
        help="NAME of the environment variable holding this sink's bearer token. A "
        "REFERENCE only — a value-shaped string is refused and not echoed.",
    ),
]
SinkTokenKeychainOpt = Annotated[
    str | None,
    typer.Option(
        "--token-keychain",
        help="NAME of the keychain service holding this sink's bearer token (default: "
        "`gateclerk-ingest-<site>`). A REFERENCE only.",
    ),
]


def _sink_site(site: str, config: str | None, *, output: OutputFormat) -> cfg.SiteConfig:
    """Load one site block for a sink command; exit 2 on any refusal.

    The CLI surface, not the AGENT surface: `sink list` is a diagnostic an operator runs
    before the unit exists, and a missing `iana_tz` is not a reason it cannot answer a
    question about sinks. The sink blocks themselves are validated identically on both.
    """
    try:
        return cfg.site_from_args(site=site, config_path=config, surface=cfg.ConfigSurface.CLI)
    except ConfigError as exc:
        raise _config_exit(output, str(exc)) from exc


def _sink_cli_exit(output: OutputFormat, message: str) -> typer.Exit:
    """Report a sink refusal (exit 2) WITHOUT rich markup interpretation.

    Rich eats `[[...]]` as a markup tag, and sink text names the config key
    `[[site.sink]]` in the same sentences an operator needs to read: a refusal whose text
    was mangled is a refusal that cannot be acted on. `_config_exit` renders with markup on
    because it is shared by commands whose messages carry no TOML keys — this is the sink
    commands' own printer for exactly that reason, with the same payload shape and code.
    """
    if output is OutputFormat.JSON or output is OutputFormat.JSONL:
        render([{"error": message, "exit_code": CONFIG_ERROR_EXIT}], fmt=output.value)
    else:
        make_console().print(f"error: {message}", markup=False)
    return typer.Exit(code=CONFIG_ERROR_EXIT)


def _sink_store(site: cfg.SiteConfig, state_root: str | None) -> Any:
    """The site's store, with WRITES REFUSED by the connection (or None when absent).

    `PRAGMA query_only=ON` rather than a read-only URI: a WAL-mode store opened `mode=ro`
    still wants the shared-memory file, so the URI form fails on a healthy database for a
    reason that has nothing to do with the operator. `query_only` is the honest statement of
    the promise these commands make — "this listing changes nothing" — and sqlite raises
    `OperationalError` if a future edit of this path tries to write, instead of quietly
    producing a listing with side effects.

    A store that has never been created is "no backlog yet", not an error: `sink list` is
    also the command an operator runs before the first tick.
    """
    import sqlite3

    from gateclerk import agent_cli

    db_path = agent_cli.resolve_db_path(site, state_root)
    if not Path(db_path).exists():
        return None
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA query_only=ON")
    conn.row_factory = sqlite3.Row
    return conn


@sink_app.command("list")
def sink_list(
    site: AgentSiteOpt,
    config: AgentConfigOpt = None,
    state_root: AgentStateRootOpt = None,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Every sink of one site: name, type, target, token REFERENCE, pending, dead letters.

    Counts come from the site's store, grouped by `sink_name`, opened read-only. Rows whose
    sink is no longer in the config are shown on one `(unconfigured)` line rather than being
    dropped: `sink remove` keeps history by design, and a backlog nobody can attribute is
    the failure mode that law was written to prevent.

    No value is printed by this command — `token_ref` names the env var or the keychain
    service, and the resolver is never called (no keychain prompt is spent on a listing).
    """
    from gateclerk import sink_cli

    target = _sink_site(site, config, output=output)
    try:
        conn = _sink_store(target, state_root)
    except Exception as exc:  # a store we cannot open is a config-class problem
        raise _sink_cli_exit(output, f"cannot read the site store: {exc}") from exc
    try:
        rows = sink_cli.sink_rows(target, conn=conn)
    finally:
        if conn is not None:
            conn.close()
    render(rows, fmt=output.value, columns=sink_cli.SINK_COLUMNS)


@sink_app.command("add")
def sink_add(
    site: AgentSiteOpt,
    name: SinkNameOpt,
    sink_type: SinkTypeOpt,
    config: AgentConfigOpt = None,
    url: SinkUrlOpt = None,
    path: SinkPathOpt = None,
    rotation: SinkRotationOpt = None,
    token_env: SinkTokenEnvOpt = None,
    token_keychain: SinkTokenKeychainOpt = None,
    to: SinkToOpt = None,
    timeout_s: SinkTimeoutOpt = None,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Append one `site.sink` block to the site's config, atomically.

    `add` refuses before it writes: an unknown type, a bad or reserved name, a second sink
    with an existing name, a site that still declares `push_target` (two sources for one
    site's sinks would double-push every punch), and — the one that protects the operator
    from themselves — a token flag whose value looks like a SECRET rather than a name. That
    last refusal deliberately does not echo the string it rejected.

    The edit is temp-file + fsync + re-validate + rename, so the file an agent unit starts
    with is one the config layer already accepted, and a crash mid-edit leaves the old file.
    """
    from gateclerk import sink_cli

    target = _sink_site(site, config, output=output)
    config_path = config or cfg.DEFAULT_SITES_FILE
    try:
        edit = sink_cli.add_sink_block(
            config_path,
            site=target.name,
            name=name,
            sink_type=sink_type,
            url=url,
            path=path,
            rotation=rotation,
            token_env=token_env,
            token_keychain=token_keychain,
            to=to,
            timeout_s=timeout_s,
        )
    except sink_cli.SinkCliError as exc:
        raise _sink_cli_exit(output, str(exc)) from exc
    render(
        [
            {
                "config": edit.config,
                "site": edit.site,
                "sinks": ", ".join(edit.sink_names) or "(none)",
                "result": edit.detail,
            }
        ],
        fmt=output.value,
        columns=("config", "site", "result", "sinks"),
    )


@sink_app.command("remove")
def sink_remove(
    site: AgentSiteOpt,
    name: SinkNameOpt,
    config: AgentConfigOpt = None,
    state_root: AgentStateRootOpt = None,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Delete one `site.sink` block. Queue and dead-letter rows are KEPT.

    History is the reason: `push_queue.sink_name` and `dead_letter.sink_name` still name the
    sink, so a punch that failed against it stays attributable and `agent deadletter list`
    still shows it. This command therefore never opens the store for writing — it reports
    what it left behind so the operator knows the backlog is still there.
    """
    from gateclerk import sink_cli

    target = _sink_site(site, config, output=output)
    config_path = config or cfg.DEFAULT_SITES_FILE
    try:
        edit = sink_cli.remove_sink_block(config_path, site=target.name, name=name)
    except sink_cli.SinkCliError as exc:
        raise _sink_cli_exit(output, str(exc)) from exc
    left = _leftover_counts(target, state_root, name)
    render(
        [
            {
                "config": edit.config,
                "site": edit.site,
                "result": edit.detail,
                "queued_rows_kept": left[0],
                "dead_letter_rows_kept": left[1],
                "sinks": ", ".join(edit.sink_names) or "(none)",
            }
        ],
        fmt=output.value,
        columns=(
            "config",
            "site",
            "result",
            "queued_rows_kept",
            "dead_letter_rows_kept",
            "sinks",
        ),
    )


def _leftover_counts(site: cfg.SiteConfig, state_root: str | None, name: str) -> tuple[int, int]:
    """How many queue / dead-letter rows still carry this sink name (0,0 when no store)."""
    conn = _sink_store(site, state_root)
    if conn is None:
        return (0, 0)
    try:
        queued = conn.execute(
            "SELECT COUNT(*) FROM push_queue WHERE sink_name = ?", (name,)
        ).fetchone()[0]
        dead = conn.execute(
            "SELECT COUNT(*) FROM dead_letter WHERE sink_name = ?", (name,)
        ).fetchone()[0]
        return (int(queued), int(dead))
    except Exception:  # pragma: no cover - a store without the sink columns predates v5
        return (0, 0)
    finally:
        conn.close()


@sink_app.command("test")
def sink_test(
    site: AgentSiteOpt,
    name: SinkNameOpt,
    config: AgentConfigOpt = None,
    output: OutputOpt = OutputFormat.TABLE,
    probe: Annotated[
        bool,
        typer.Option(
            "--probe",
            help="Also send ONE benign probe: an empty JSONL POST for an https sink, an "
            "exclusive `.probe` file for a csv/jsonl sink (created and removed — the sink "
            "file itself is never touched).",
        ),
    ] = False,
) -> None:
    """Check one sink and say why it is or is not usable. Prints references, never values.

    Without `--probe` this is config + resolvability only: the url parses, the token
    REFERENCE names an env var that is set or a keychain item that exists (an attribute
    lookup — no `-w`, so no value is read and no keychain prompt is spent), the file sink's
    directory is writable, its rotation is a policy the writer has a rule for, and its path
    is not shared with another sink.

    The SINKS-WIRING card is what makes a csv/jsonl sink actually written and makes the drain
    fan out per sink; until that lands, `test` checks the config and the connectivity and
    says so in the same line it reports the verdict — it does not claim a delivery it cannot
    perform. The probe is the one thing that goes out: an empty batch, so no fake employee
    can ever reach an ingest (the ingest's idempotency key is a payload fingerprint, so a
    repeated fake line would also be *replayed* and report a success nobody earned).

    Exits 2 when any check fails — the same class as a failing `creds check`.
    """
    from gateclerk import sink_cli

    target = _sink_site(site, config, output=output)
    spec = next((s for s in target.effective_sinks if s.name == name), None)
    if spec is None:
        known = ", ".join(s.name for s in target.effective_sinks) or "(none declared)"
        raise _sink_cli_exit(
            output, f"site {target.name!r} has no sink named {name!r} (sinks: {known})"
        )

    paths = [s.path for s in target.effective_sinks if s.path]
    checks = list(
        sink_cli.check_sink(
            target,
            spec,
            other_paths=[p for p in paths if p != spec.path],
        )
    )
    if probe:
        checks.append(_sink_probe_check(target, spec))

    rows = [check.as_dict() for check in checks]
    healthy = all(check.ok for check in checks)
    render(rows, fmt=output.value, columns=("sink", "check", "ok", "detail"))
    if not healthy:
        # The summary is the actionable half; the table above already said which check.
        failing = ", ".join(check.check for check in checks if not check.ok)
        raise _sink_cli_exit(
            output, f"sink {name!r} is not usable (failing: {failing}) — see the detail column"
        )


def _sink_probe_check(site: cfg.SiteConfig, spec: Any) -> sink_cli.SinkCheck:
    """Run the probe and fold it into the same check table as the config checks.

    The `detail` carries the wiring caveat when the sink is a file sink: nothing writes
    csv/jsonl until SINKS-WIRING lands, so a green probe there means "this path is writable
    and will be written once the drain fans out", and the text says exactly that rather than
    implying a delivery that has not happened.
    """
    from gateclerk import sink_cli

    result = sink_cli.probe_sink(site, spec)
    detail = result.summary
    if result.ok and spec.type in ("csv", "jsonl"):
        detail += (
            " — NOTE: nothing writes this sink until the per-sink drain fan-out "
            "(SINKS-WIRING) lands; this proves the path, not a delivery"
        )
    return sink_cli.SinkCheck(sink=result.sink, check="probe", ok=result.ok, detail=detail)


def register(app: typer.Typer) -> None:
    """Attach the `sink` group to the root app.

    Called by `gateclerk.cli` at import time, in the position the group's `add_typer` used to
    sit, so the command order in `gateclerk --help` stays byte-identical.
    """
    app.add_typer(sink_app)
