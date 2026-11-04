"""The `gateclerk users` group: `list` (CLI-SEAM-MOVE).

One-way import law (`tests/test_cli_structure.py`): `gateclerk.cli` imports this module and
calls `users_cmds.register(app)`; this module imports `gateclerk.cli_shared`, never
`gateclerk.cli`.
"""

from __future__ import annotations

from typing import Annotated

import typer

from gateclerk import pipeline
from gateclerk.cli_shared import (
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    DEFAULT_TZ,
    ConfigOpt,
    CountOpt,
    HostArg,
    OutputOpt,
    PasswordOpt,
    PortOpt,
    SiteLabelOpt,
    SiteOpt,
    TimeoutOpt,
    UserOpt,
    VerboseOpt,
    _client_for,
    _context,
    _Guard,
    _logger_for,
    _print_count_crosscheck,
    _resolve_creds,
    _resolve_site,
    _valid_label,
)
from gateclerk.output import OutputFormat, render

__all__ = ["register", "users_app"]

users_app = typer.Typer(
    name="users",
    help="Employee roster reads.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)


@users_app.command("list")
def users_list(
    host: HostArg = None,
    site: SiteOpt = None,
    config: ConfigOpt = None,
    port: PortOpt = DEFAULT_PORT,
    user: UserOpt = None,
    password: PasswordOpt = None,
    timeout: TimeoutOpt = DEFAULT_TIMEOUT,
    output: OutputOpt = OutputFormat.TABLE,
    verbose: VerboseOpt = False,
    site_label: SiteLabelOpt = None,
    employee_no: Annotated[
        str | None,
        typer.Option(
            "--employee-no",
            help="Keep only this employee's roster entry. Applied CLIENT-side: "
            "UserInfo/Search has never been probed for a server-side employee filter, "
            "and OBSERVED.md's policy is to never trust one we have not probed.",
        ),
    ] = None,
    count: CountOpt = False,
) -> None:
    """Paged roster via POST /ISAPI/AccessControl/UserInfo/Search.

    Table columns are the card's: `employee_no`, `name`, `valid`. `valid` is the device's
    `Valid.enable` flag — `yes` / `no` / `unknown` when the device did not say, which is
    reported as its own value rather than folded into "no" (an absent claim is not a
    denial). `valid_from`/`valid_to` ride in `--output json`, verbatim and with no tz
    claim: the device sends them naive and we make none (DESIGN.md: keep the raw).

    The device sends a `password` hash per user (OBSERVED.md endpoint table: "strip it,
    never store"). `UserRecord.from_device_user` removes it before anything can serialize
    it, so it cannot reach this table, this json, or a jsonl file.
    """
    fmt = output
    site_config = _resolve_site(host=host, site=site, port=port, sites_file=config, output=fmt)
    target = site_config.target()
    creds = _resolve_creds(target, user=user, password=password, output=fmt)
    logger = _logger_for(verbose, creds)
    with _Guard(fmt):
        with _client_for(target, creds, timeout=timeout, output=fmt, logger=logger) as client:
            context = _context(
                site_config=site_config,
                site_label=site_label,
                site_tz=site_config.iana_tz or DEFAULT_TZ,
                max_records=None,
                logger=logger,
            )
            result = pipeline.fetch_users(client, context=context, with_count=count)
        records = [pipeline.user_record_from_device(u) for u in result.users]
        if employee_no is not None:
            records = [r for r in records if r.employee_no == employee_no]
        if fmt is OutputFormat.TABLE:
            render(
                [
                    {
                        "employee_no": r.employee_no,
                        "name": r.name,
                        "valid": _valid_label(r),
                    }
                    for r in records
                ],
                fmt="table",
                columns=("employee_no", "name", "valid"),
            )
        else:
            render([r.to_dict() for r in records], fmt=fmt.value)
        if count:
            _print_count_crosscheck(
                result.device_count, len(records), filtered=employee_no is not None
            )


def register(app: typer.Typer) -> None:
    """Attach the `users` group to the root CLI app."""
    app.add_typer(users_app)
