"""The `gateclerk demo` group: offline demo surfaces (SYNTHETIC-ONLY data).

CLI-SPLIT-STRUCTURE moved this group verbatim out of `gateclerk.cli`; `gateclerk.cli` attaches
it with `demo_cmds.register(app)`. The fake device itself lives in `gateclerk.demo_device`;
this module is only its Click surface. One-way import law: `gateclerk.cli` imports this
module; this module imports `gateclerk.cli_shared`, never `gateclerk.cli`.

SYNTHETIC-ONLY LAW: everything `demo device serve` answers is synthetic (RFC 5737
addresses, `Demo*` identities, `DEMO-*` serials/cards) and it binds loopback only; the
envelope SHAPES are the recorded device's, so the client path a developer exercises here
is the path that runs on real hardware.
"""

from __future__ import annotations

from typing import Annotated

import typer

from gateclerk import demo_device as demo
from gateclerk.cli_shared import OutputOpt, _config_exit
from gateclerk.output import OutputFormat, render

demo_app = typer.Typer(
    name="demo",
    help="Offline demo surfaces (SYNTHETIC-ONLY data) — `demo device` runs a fake device.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
demo_device_app = typer.Typer(
    name="device",
    help="A local fake ISAPI device: loopback-only, digest-auth, synthetic fixtures only.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
demo_app.add_typer(demo_device_app)


@demo_device_app.command("serve")
def demo_device_serve(
    host: Annotated[
        str,
        typer.Option("--host", help="Bind host. Loopback only (SYNTHETIC-ONLY LAW)."),
    ] = "127.0.0.1",
    port: Annotated[
        int,
        typer.Option("--port", help="Bind port. 0 (default) picks a free ephemeral port."),
    ] = 0,
    seconds: Annotated[
        float | None,
        typer.Option(
            "--seconds",
            help="Stop after this many seconds (default: run until Ctrl-C).",
        ),
    ] = None,
    user: Annotated[
        str, typer.Option("--user", help="Digest username the box accepts.")
    ] = demo.DEMO_DEFAULT_USER,
    password: Annotated[
        str, typer.Option("--password", help="Digest password the box accepts.")
    ] = demo.DEMO_DEFAULT_PASSWORD,
) -> None:
    """Serve a fake device on loopback so `gateclerk` works with NO real hardware.

    Everything it answers is synthetic (RFC 5737 addresses, `Demo*` identities,
    `DEMO-*` serials/cards); the envelope SHAPES are the recorded device's, so the
    client path a developer exercises here is the path that runs on real hardware.
    """
    try:
        box = demo.DemoDevice(username=user, password=password, host=host, port=port)
    except ValueError as exc:  # the loopback-only rule, surfaced as a CLI refusal
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    box.start()
    demo.report_served_url(box.base_url)
    typer.echo(
        f"demo device on {box.base_url} (digest user={user} password={password!r}; "
        f"serial={demo.DEMO_SERIAL}; Ctrl-C to stop)"
    )
    try:
        box.wait(seconds)
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        pass
    finally:
        box.stop()


@demo_device_app.command("urls")
def demo_device_urls(
    port: Annotated[
        int,
        typer.Option("--port", help="Port to show in the printed URLs."),
    ] = 80,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Print the showcase ISAPI URLs (and the demo credential pair) for a site config.

    CLI-VERBS-HELP added `-o json` (docs/CLI-CONVENTIONS.md): the URL list is what a
    `sites.toml`-writing script needs, and it renders through the shared renderer. The digest
    PASSWORD is masked in the machine form — the CLI-wide `-o json` law is that JSON carries
    no credential value, and a script that learns to read `password` here will paste a real
    one in somewhere else. The human-facing table still shows the placeholder pair, because
    that is the screen README documents for pointing `--host 127.0.0.1` at the fake device.
    """
    base_url = f"http://{demo.DEMO_BIND_HOST}:{port}"
    urls = list(demo.demo_endpoint_urls(base_url))
    if output is OutputFormat.TABLE:
        typer.echo(base_url)
        for name, url in urls:
            typer.echo(f"  {name}: {url}")
        typer.echo(
            f"  digest: user={demo.DEMO_DEFAULT_USER} password={demo.DEMO_DEFAULT_PASSWORD!r}"
        )
        return
    render(
        [
            *[
                {"kind": "endpoint", "name": name, "url": url, "user": "", "password": ""}
                for name, url in urls
            ],
            {
                "kind": "credential",
                "name": "digest",
                "url": "",
                "user": demo.DEMO_DEFAULT_USER,
                "password": "***",
            },
        ],
        fmt=output.value,
        columns=("kind", "name", "url", "user", "password"),
    )


@demo_app.command("demo")
def demo_walkthrough_command(
    root: Annotated[
        str | None,
        typer.Option(
            "--root",
            help="Scratch tree for the run (config, state, csv, health). Default: a fresh "
            "temporary directory under the system temp dir.",
        ),
    ] = None,
    ticks: Annotated[
        int,
        typer.Option(
            "--ticks",
            min=1,
            help="How many agent ticks to run. One tick is already a full delivery; more "
            "ticks show the checkpoint law holding (no re-pull of delivered rows).",
        ),
    ] = 3,
    keep: Annotated[
        bool,
        typer.Option(
            "--keep",
            help="Leave the scratch tree in place so the csv, the health snapshot and the "
            "generated config can be read afterwards. Without it the tree is deleted.",
        ),
    ] = False,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Run the whole loop against synthetic peers, in your terminal. Read-only.

    One command, no door controller, no ingest deployment, no keychain item, no real
    credentials: the real `IsapiClient` polls a fake Hikvision device on loopback, the agent
    stores and queues the punches it reports, and the per-sink fan-out delivers them to two
    sinks — a local `csv` sink and a mock `https` ingest this command hosts itself. The
    printed loop is the evidence: events stored, then per tick the rows claimed and what each
    sink took; a final summary names the csv path, its row count and its tail.

    Nothing outside the scratch tree is touched, so there is nothing to undo and no `migrate`
    step. The credential pair used is the published `demo device` pair above, which documents
    a fake device and is therefore safe to name; the ingest bearer is a recognisable
    placeholder that exists only in the process.

    Needs `openssl` on PATH for the mock's throwaway certificate — without it this exits 2
    saying so, because a clear-text mock ingest would teach the wrong law.

    Exit: 0 ok - 2 missing `openssl`, an unusable `--root`, or a tick failure.
    """
    # Imported lazily, the way `agent_cmds` reaches `agent_cli`: the walkthrough pulls in
    # the agent surface, and a command module keeps that dependency out of `--help` time.
    from pathlib import Path

    from gateclerk import demo_walkthrough

    try:
        report = demo_walkthrough.run_demo_walkthrough(
            root=Path(root).expanduser() if root else None,
            ticks=ticks,
            keep=keep,
            out=typer.echo,
        )
    except (demo_walkthrough.DemoWalkthroughError, OSError, ValueError) as exc:
        # A demo refusal is a missing-tool / bad-`--root` failure — the configuration class
        # (exit 2), the same mapping `sink add` uses for a refused edit.
        raise _config_exit(output, str(exc)) from exc
    render([report.as_dict()], fmt=output.value)


def register(app: typer.Typer) -> None:
    """Attach the `demo` group (and its `device` subgroup) to the root app.

    Called by `gateclerk.cli` at import time, in the position the group's `add_typer` used to
    sit, so the command order in `gateclerk --help` stays byte-identical. `demo_device_app`
    hangs off `demo_app` at module scope (above), where it hung before.
    """
    app.add_typer(demo_app)
