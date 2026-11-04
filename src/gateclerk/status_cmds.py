"""The `gateclerk status` command: one screen that says whether the sites are healthy.

CLI-STATUS (parent CLI-VERBS-HELP). This is the FIRST command a new operator learns and
the one CI runs on every deploy, so its contract is "safe to run anywhere, exit code I
can branch on": per configured site it shows the state dir, the sqlite db size and last
drain age, the agent loop line (pidfile when the SERVICE card ships it, the §2e health
snapshot's age as the fallback — degrading to `unknown`, never to a false fail),
pending + dead-letter counts per push target read from the queue tables (per-sink rows
automatically, no new schema), the last push result (error CLASS and stamp only — the
dead-letter `payload` column is never selected; it carries person data), the last roster
push age from the artifact the roster leg leaves on disk, the device reachability line
from the CACHED probe only (status never contacts a device or the ingest — the offline
suite proves it), and the config-sanity note (`device_code` when an https sink needs it).

Every RULE lives in `gateclerk.status_cli` (typer-free, the `sink_cli` precedent the
split established): this module is resolve -> collect -> render, the same three steps
every cmd module is. One-way import law: `gateclerk.cli` imports this module; this module
imports `gateclerk.cli_shared`, never `gateclerk.cli`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

import typer

from gateclerk import config as cfg
from gateclerk import status_cli
from gateclerk.cli_shared import AgentConfigOpt, AgentStateRootOpt, OutputOpt, _config_exit
from gateclerk.exceptions import ConfigError
from gateclerk.output import OutputFormat, render

status_app = typer.Typer(
    name="status",
    help=(
        "One-screen health for every configured site: queue depth, dead letters, last "
        "push, roster age, agent loop, device (cached), config notes. Reads only — it "
        "never contacts the device or the ingest. Exit 0 only when nothing failed."
    ),
    no_args_is_help=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)

SiteFilterOpt = Annotated[
    str | None,
    typer.Option(
        "--site",
        help="Show only this site (default: every [[site]] block in sites.toml). "
        "An unknown name exits 2 with the list of configured sites.",
    ),
]
CheckOpt = Annotated[
    bool,
    typer.Option(
        "--check",
        help="CI mode: compact one-JSON-row-per-site output (like `-o json`), no table. "
        "Exit codes are identical either way — the codes are the convention, not a mode.",
    ),
]


def _now() -> datetime:
    """Clock seam for tests."""
    return datetime.now(UTC)


@status_app.callback(invoke_without_command=True)
def status_screen(
    output: OutputOpt = OutputFormat.TABLE,
    config: AgentConfigOpt = None,
    state_root: AgentStateRootOpt = None,
    site: SiteFilterOpt = None,
    check: CheckOpt = False,
) -> None:
    """One-screen health: site, state dir, db, drain age, agent loop, sinks, last push,
    roster age, cached device line, config notes. Exit 0 only when nothing failed.
    """
    _run_screen(output=output, config=config, state_root=state_root, site=site, check=check)


def _run_screen(
    *,
    output: OutputFormat,
    config: str | None,
    state_root: str | None,
    site: str | None,
    check: bool,
) -> None:
    """resolve -> collect -> render -> exit, in that order and only that order."""
    fmt = OutputFormat.JSON if check else output
    sites = _status_sites(config, site, output=output)
    now = _now()
    rows = [
        status_cli.collect_site_status(found, state_root=state_root, now=now) for found in sites
    ]
    render(rows, fmt=fmt.value, columns=status_cli.STATUS_COLUMNS)
    code = status_cli.exit_code_for_sites(rows)
    if code:
        raise typer.Exit(code=code)


def _status_sites(config: str | None, site: str | None, *, output: OutputFormat) -> list[Any]:
    """The site blocks this screen shows, loaded with the CLI surface."""
    try:
        sites = cfg.load_sites(config or cfg.DEFAULT_SITES_FILE, surface=cfg.ConfigSurface.CLI)
    except ConfigError as exc:
        raise _config_exit(output, str(exc)) from exc
    if site is not None:
        try:
            return [cfg.find_site(sites, site)]
        except ConfigError as exc:
            raise _config_exit(output, str(exc)) from exc
    return [sites[name] for name in sorted(sites)]


def register(app: typer.Typer) -> None:
    """Attach `gateclerk status` to the root app."""
    app.add_typer(status_app)
