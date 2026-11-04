"""The `gateclerk doctor` command: exhaustive read-only self-check (card t_0c1cf9fd).

One-way import law (`tests/test_cli_structure.py`): `gateclerk.cli` imports this module and
calls `doctor_cmds.register(app)`; this module imports `gateclerk.cli_shared` and
`gateclerk.doctor_cli`, never `gateclerk.cli`.
"""

from __future__ import annotations

from typing import Annotated

import typer

from gateclerk import config as cfg
from gateclerk import doctor_cli
from gateclerk.cli_shared import AgentConfigOpt, AgentStateRootOpt, OutputOpt
from gateclerk.output import OutputFormat, render

doctor_app = typer.Typer(
    name="doctor",
    help=(
        "Exhaustive read-only self-check per site: config, credential references (names "
        "only, never values), device reachability + clock skew, push target/sink TLS and "
        "writable paths, SQLite store integrity + queue/dead-letter counts, and runtime."
    ),
    no_args_is_help=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)

DoctorSiteOpt = Annotated[
    str | None,
    typer.Option(
        "--site",
        help="Check only this site block from sites.toml (default: check all configured sites).",
    ),
]


@doctor_app.callback(invoke_without_command=True)
def doctor_screen(
    output: OutputOpt = OutputFormat.TABLE,
    config: AgentConfigOpt = None,
    state_root: AgentStateRootOpt = None,
    site: DoctorSiteOpt = None,
    probe: Annotated[
        bool,
        typer.Option(
            "--probe",
            help="Probe the device through the SAME client factory the read commands build "
            "(cli_shared._client_for) instead of doctor's own construction. Read-only: "
            "the same two GETs (deviceInfo + System/time), nothing written, no restart.",
        ),
    ] = False,
) -> None:
    """Run the read-only self-check across configured sites and exit with the worst failure code."""
    prober = None
    if probe:
        # Imported here, not at module top: `doctor_cmds` must not grow an import edge that
        # pulls the whole read-command surface into `doctor --help`'s cold start, and the
        # one-way law tests/test_cli_structure.py pins stays exactly as it is.
        from gateclerk import cli_shared

        prober = cli_shared.default_device_prober
    rows, code = doctor_cli.run_doctor(
        config_path=config or cfg.DEFAULT_SITES_FILE,
        site=site,
        state_root=state_root,
        device_prober=prober,
    )
    render(
        [r.as_dict() for r in rows],
        fmt=output.value,
        columns=doctor_cli.DOCTOR_COLUMNS,
    )
    if code:
        raise typer.Exit(code=code)


def register(app: typer.Typer) -> None:
    """Attach `gateclerk doctor` to the root CLI app."""
    app.add_typer(doctor_app)
