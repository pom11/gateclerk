"""The `gateclerk agent` group: the commands the site unit runs (P2-07b).

CLI-SPLIT-STRUCTURE moved this group verbatim out of `gateclerk.cli` — the group
declarations and the four command bodies live here, and `gateclerk.cli` attaches them with
`agent_cmds.register(app)`. This is the shape `sink_cli.py` shipped as the precedent
(rules in the domain module; a CLI body is resolve → call → render). One-way import law:
`gateclerk.cli` imports this module; this module imports `gateclerk.cli_shared` for the shared
opts and the failure-to-exit mapping, and NEVER `gateclerk.cli`.

A NEW group only; nothing about the groups still in `cli.py` is touched. The bodies are
thin on purpose: every rule (the cadence, the walk, the UPSERT, the park, the backoff, the
dead letter) lives in the P2 module that shipped it and is imported, never re-expressed
here. `gateclerk.agent_cli` is imported inside the bodies, not at the top: it imports
P2-06's collector, which imports `cli._warn_tz_mismatch` back, and the CLI must stay
importable without the agent present.

These commands read the site with surface=AGENT (`config.ConfigSurface`): the agent refuses
a block with no explicit `iana_tz`, because site tz is payroll truth and the compiled-in
default is a site-a value (§2d). The CLI's own commands keep surface=CLI and are unaffected.

`agent run` is the systemd `ExecStart`: its CLI definition is golden-pinned by
`tests/test_cli_conventions.py::test_agent_run_definition_is_unchanged_from_the_baseline`.
Do not move a flag, a default, an order or a help word on it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from gateclerk import config as cfg
from gateclerk.cli_shared import (
    AgentConfigOpt,
    AgentCredentialsDirOpt,
    AgentPasswordOpt,
    AgentSiteOpt,
    AgentStateRootOpt,
    OutputOpt,
    _alias_group,
    _auth_exit,
    _config_exit,
    _fail,
)
from gateclerk.exceptions import ConfigError
from gateclerk.output import OutputFormat, render

# --- agent (P2-07b): the commands the site unit runs ----------------------------------------
#
# A NEW group only; nothing above this line is touched. `gateclerk agent run` is the process
# `deploy/gateclerk-agent@.service` starts, and `ack` / `deadletter` are the two owner commands
# the unit cannot do for itself. The bodies are thin on purpose: every rule (the cadence, the
# walk, the UPSERT, the park, the backoff, the dead letter) lives in the P2 module that shipped
# it and is imported, never re-expressed here. `gateclerk.agent_cli` is imported inside the
# bodies, not at the top: it imports P2-06's collector, which imports `cli._warn_tz_mismatch`
# back, and the CLI must stay importable without the agent present.
#
# These commands read the site with surface=AGENT (`config.ConfigSurface`): the agent refuses a
# block with no explicit `iana_tz`, because site tz is payroll truth and the compiled-in default
# is a site-a value (§2d). The CLI's own commands keep surface=CLI and are unaffected.

agent_app = typer.Typer(
    name="agent",
    help="The site agent itself (P2): serve one site, ack a parked device, triage dead letters.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
deadletter_app = typer.Typer(
    name="deadletter",
    help="Dead-letter triage (P2-04): the pushes that failed past the 24h bound.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
    # CLI-VERBS-HELP: `delete` was the pre-vocabulary spelling of the canonical `remove`
    # verb (docs/CLI-CONVENTIONS.md). The hidden alias means `agent deadletter delete` in
    # the operator's scripts, agent_cli's docstrings and deploy/ docs keeps working.
    cls=_alias_group(("agent", "deadletter")),
)
agent_app.add_typer(deadletter_app)


def _agent_site(site: str, config: str | None, *, output: OutputFormat) -> cfg.SiteConfig:
    """Load one site block on the AGENT surface (strict `iana_tz`); exit 2 on any refusal."""
    try:
        return cfg.site_from_args(site=site, config_path=config, surface=cfg.ConfigSurface.AGENT)
    except ConfigError as exc:
        raise _config_exit(output, str(exc)) from exc


@agent_app.command("run")
def agent_run(
    site: AgentSiteOpt,
    config: AgentConfigOpt = None,
    state_root: AgentStateRootOpt = None,
    credentials_dir: AgentCredentialsDirOpt = None,
    password: AgentPasswordOpt = None,
    once: Annotated[
        bool,
        typer.Option(
            "--once",
            help="One tick, then exit 0 — the smoke test (deploy/README.md step 3). NOT for the "
            "unit: under Restart=always that becomes a five-second poll of the device.",
        ),
    ] = False,
    max_ticks: Annotated[
        int | None,
        typer.Option("--max-ticks", help="Stop after N ticks (tests and dry runs)."),
    ] = None,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Serve one site: poll its devices, store, checkpoint, queue, push. The unit's ExecStart.

    Wiring only — P2-03's loop per device, P2-05's park gate around every tick (a refused tick
    sends ZERO requests), P2-02's store, P2-04's queue and drain, P2-06's health snapshot.
    Exits 2 on a config or credential problem (p1-08's contract) and 3 when the run ends with
    the site needing a human — a device parked unacked (terminal 401) or a transport
    circuit open — which `--once` is how an operator finds out (deploy/README.md step 3).
    """
    from gateclerk import agent_cli

    target = _agent_site(site, config, output=output)
    try:
        agent = agent_cli.build_site_agent(
            target,
            state_root=state_root,
            credentials_dir=credentials_dir,
            password=password,
        )
        try:
            report = agent.run(once=once, max_ticks=max_ticks)
        finally:
            agent.close()
    except Exception as exc:
        # `_fail` is p1-08's single mapping (config 2, terminal-auth 3, device 4). The agent
        # adds no codes of its own, so a script that knows the CLI's contract knows this one.
        raise _fail(output, exc) from exc
    payload = report.as_dict()
    if payload.pop("needs_human"):
        # The table form prints the report first: the counters are what the operator reads
        # to decide WHY. JSON forms stay one-document (the error object), like every other
        # exit path. The unit form never gets here — the loop never returns — so a park
        # cannot turn into a Restart=always crash loop against a door controller.
        if output not in (OutputFormat.JSON, OutputFormat.JSONL):
            render([payload], fmt=output.value, columns=tuple(payload))
        raise _auth_exit(
            output,
            f"site {target.name!r} needs a human: parked={list(report.parked)} "
            f"circuit_open={list(report.circuit_open)}",
        )
    render([payload], fmt=output.value, columns=tuple(payload))


@agent_app.command("ack")
def agent_ack(
    site: AgentSiteOpt,
    config: AgentConfigOpt = None,
    state_root: AgentStateRootOpt = None,
    device_serial: Annotated[
        str | None,
        typer.Option(
            "--device-serial",
            help="Ack ONE parked device (its serial). Omit to ack every park of this site.",
        ),
    ] = None,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Operator acknowledgement of a parked device (P2-05): open the re-probe grid.

    A park means the device answered a terminal 401 with a digest challenge — dead or wrong
    credentials, on a device that counts failed logins. Acking says "I fixed the credential, you
    may knock again", and the policy then allows ONE attempt per re-probe period, the first at
    ack + period (never immediately). Zero parks opened exits 2 rather than 0: an ack that found
    nothing must not look like it cleared one.
    """
    from gateclerk import agent_cli

    target = _agent_site(site, config, output=output)
    db_path = agent_cli.resolve_db_path(target, state_root)
    if not Path(db_path).exists():
        # No store yet = no park can exist: the same exit-2 "nothing to ack" as an empty
        # park dir, phrased so the operator sees WHY (a crash from sqlite cannot open on a
        # missing directory is not an answer to a command typed in good faith).
        raise _config_exit(
            output,
            f"no store at {db_path} for site {target.name!r}: nothing to ack "
            "(has `gateclerk agent run` ever run for this site?)",
        )
    try:
        conn = agent_cli.connect(db_path)
    except (ConfigError, OSError) as exc:
        raise _config_exit(output, str(exc)) from exc
    policy = agent_cli.AlertPolicy(
        site=target.name,
        cadence_s=target.cadence_s,
        conn=conn,
        park_dir=agent_cli.resolve_state_root(target, state_root) / agent_cli.PARK_DIR_NAME,
        # The ack stamps the re-probe grid from the AGENT's clock — the same `agent_cli._now`
        # indirection `agent run` threads through every seam. Production behaviour is
        # identical (the seam defaults to wall clock); it just keeps ack and run inside ONE
        # time universe for the suite and for an ops smoke test.
        now=agent_cli._now,
    )
    opened = policy.ack(target.name, device_serial)
    render(
        [{"site": target.name, "parks_opened": opened, "device_serial": device_serial or "all"}],
        fmt=output.value,
        columns=("site", "parks_opened", "device_serial"),
    )
    if opened == 0:
        raise _config_exit(
            output,
            f"no parked device for site {target.name!r}: nothing to ack "
            "(a typo'd --device-serial cannot clear a park)",
        )


@deadletter_app.command("list")
def deadletter_list(
    site: AgentSiteOpt,
    config: AgentConfigOpt = None,
    state_root: AgentStateRootOpt = None,
    limit: Annotated[
        int, typer.Option("--limit", help="Most dead letters to show (oldest outage first).")
    ] = 50,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """List this site's dead-lettered pushes — the triage list the owner reads.

    Rows are shown WITHOUT the payload: it carries punch data (an employee number and a name).
    The payload stays in the db until the owner deletes the row, which is the only way a dead
    letter ever leaves the table (§2b).
    """
    from gateclerk import agent_cli, agent_push

    target = _agent_site(site, config, output=output)
    conn = agent_cli.connect(agent_cli.resolve_db_path(target, state_root))
    rows = [
        {
            "id": row.id,
            "event_id": row.event_id,
            "endpoint": row.endpoint,
            "error_class": row.error_class,
            "attempts": row.attempts,
            "first_attempt_at": row.first_attempt_at,
            "last_attempt_at": row.last_attempt_at,
        }
        for row in agent_push.dead_letter_rows(conn, limit=limit)
    ]
    render(
        rows,
        fmt=output.value,
        columns=(
            "id",
            "event_id",
            "endpoint",
            "error_class",
            "attempts",
            "first_attempt_at",
            "last_attempt_at",
        ),
    )


@deadletter_app.command("remove")
def deadletter_remove(
    id_: Annotated[int, typer.Argument(help="dead_letter row id (from `agent deadletter list`).")],
    site: AgentSiteOpt,
    config: AgentConfigOpt = None,
    state_root: AgentStateRootOpt = None,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Remove ONE dead-letter row — the only code path that ever deletes one (§2b).

    Removing is a human call: the payload is the only copy of a punch that never reached the
    ingest, and a dead letter is never retried again once it is gone. An id that does not
    exist exits 2 — a typo must not read as a removal.

    The removal is recorded in the site's push ledger (`agent_cli.discard_dead_letter`):
    without that line the event row — still in the store, now unexcluded — would be re-queued
    and RE-PUSHED on the next pass, which would undo the owner's decision (§2b).

    CLI-VERBS-HELP: the canonical verb is `remove`; the old spelling `deadletter delete`
    remains as a hidden alias, and the exit-2 wording below keeps the word "deleted" so an
    operator reading a failed run sees the command they typed.
    """
    from gateclerk import agent_cli

    target = _agent_site(site, config, output=output)
    state_dir = agent_cli.resolve_state_root(target, state_root)
    conn = agent_cli.connect(agent_cli.resolve_db_path(target, state_root))
    ledger = agent_cli.PushLedger(state_dir / agent_cli.PUSH_LEDGER_FILE_NAME)
    removed = agent_cli.discard_dead_letter(conn, id_, ledger=ledger)
    if not removed:
        raise _config_exit(output, f"no dead_letter row with id {id_}: nothing was deleted")
    render([{"id": id_, "removed": True}], fmt=output.value, columns=("id", "removed"))


def register(app: typer.Typer) -> None:
    """Attach the `agent` group to the root app.

    Called by `gateclerk.cli` at import time, in the position the group's `add_typer` used to
    sit, so the command order in `gateclerk --help` stays byte-identical. The `deadletter`
    subgroup is attached to `agent_app` at module scope (above), where it was attached before.
    """
    app.add_typer(agent_app)
