"""The `gateclerk users` group: `list` (CLI-SEAM-MOVE).

One-way import law (`tests/test_cli_structure.py`): `gateclerk.cli` imports this module and
calls `users_cmds.register(app)`; this module imports `gateclerk.cli_shared`, never
`gateclerk.cli`.
"""

from __future__ import annotations

from pathlib import Path
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
    _config_exit,
    _context,
    _Guard,
    _logger_for,
    _migrate_client,
    _print_count_crosscheck,
    _resolve_creds,
    _resolve_site,
    _valid_label,
)
from gateclerk.output import OutputFormat, render

__all__ = ["register", "users_app"]

users_app = typer.Typer(
    name="users",
    help="Employee roster reads and gated Excel enrollment.",
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


def _parse_map(pairs: list[str] | None) -> dict[str, str] | None:
    """Parse repeated ``--map SOURCE=HEADER`` values into a source->canonical map."""
    if not pairs:
        return None
    mapping: dict[str, str] = {}
    for pair in pairs:
        source, separator, target = pair.partition("=")
        if not separator or not source.strip() or not target.strip():
            raise typer.BadParameter(
                f"--map expects SOURCE=HEADER, got {pair!r} (e.g. --map 'Emp No=employeeNo')"
            )
        mapping[source.strip()] = target.strip()
    return mapping


@users_app.command("template")
def users_template(
    out: Annotated[
        Path,
        typer.Argument(help="Path of the blank .xlsx template to write."),
    ],
) -> None:
    """Write a blank Excel template with the accepted default header row.

    Headers are employeeNo, name, cardNo plus the optional cardType, validFrom and
    validTo. This is a local file write only — no device is contacted.
    """
    from gateclerk.users_import import ExcelExtraMissingError, UsersImportError, write_template

    try:
        target = write_template(out)
    except ExcelExtraMissingError as exc:
        _print_import_error(exc)
        raise typer.Exit(code=2) from exc
    except UsersImportError as exc:
        _print_import_error(exc)
        raise typer.Exit(code=2) from exc
    typer.echo(f"wrote blank users import template: {target}")


def _print_import_error(exc: Exception) -> None:
    typer.echo(f"error: {exc}", err=True)


@users_app.command("import")
def users_import(
    xlsx: Annotated[
        Path,
        typer.Argument(help="Excel file (.xlsx) with employeeNo, name and cardNo columns."),
    ],
    host: HostArg = None,
    site: SiteOpt = None,
    config: ConfigOpt = None,
    port: PortOpt = DEFAULT_PORT,
    user: UserOpt = None,
    password: PasswordOpt = None,
    timeout: TimeoutOpt = DEFAULT_TIMEOUT,
    output: OutputOpt = OutputFormat.TABLE,
    verbose: VerboseOpt = False,
    sheet: Annotated[
        str | None,
        typer.Option("--sheet", help="Sheet name to read (default: the first sheet)."),
    ] = None,
    map_pairs: Annotated[
        list[str] | None,
        typer.Option(
            "--map",
            help="Map a non-default header to a canonical field, e.g. --map 'Emp No=employeeNo' "
            "(repeatable; canonical fields are employeeNo, name, cardNo, cardType, validFrom, "
            "validTo).",
        ),
    ] = None,
    apply_writes: Annotated[
        bool,
        typer.Option(
            "--apply",
            help="Actually write the planned users/cards. Without it this is a zero-byte "
            "dry run that prints the exact plan and the device dialect verdict.",
        ),
    ] = False,
    journal: Annotated[
        str | None,
        typer.Option(
            "--journal",
            help="Append-only write journal (default: next to the workbook).",
        ),
    ] = None,
    results: Annotated[
        str | None,
        typer.Option(
            "--results",
            help="Per-row audit CSV, the only output with full card numbers (default: next "
            "to the workbook).",
        ),
    ] = None,
) -> None:
    """Import persons WITH CARDS from Excel as a gated device write.

    The device is read first (caps, then the full user and card rosters), every row is
    classified as add-user / add-card / skip-present / skip-update-needed / refuse, and
    ``--apply`` performs only the planned writes through the same journal and read-back
    seams as ``migrate apply``. Card numbers are masked in the plan; the audit CSV keeps
    the full values for the operator.
    """
    from gateclerk.users_import import (
        DialectRefusedError,
        ExcelExtraMissingError,
        ImportFileError,
        UsersImportError,
        default_journal_path,
        default_results_path,
        render_plan_rows,
        run_import,
    )

    fmt = output
    try:
        mapping = _parse_map(map_pairs)
    except typer.BadParameter as exc:
        raise _config_exit(fmt, str(exc)) from exc
    _site_config, client, client_factory = _migrate_client(
        host=host,
        site=site,
        port=port,
        config=config,
        user=user,
        password=password,
        timeout=timeout,
        fmt=fmt,
        verbose=verbose,
    )
    journal_path = Path(journal).expanduser() if journal else default_journal_path(xlsx)
    results_path = Path(results).expanduser() if results else default_results_path(xlsx)
    try:
        with _Guard(fmt), client:
            report = run_import(
                xlsx,
                client=client,
                client_factory=client_factory,
                sheet=sheet,
                mapping=mapping,
                apply=apply_writes,
                journal_path=journal_path,
                results_path=results_path,
            )
    except (ExcelExtraMissingError, ImportFileError, DialectRefusedError) as exc:
        raise _config_exit(fmt, str(exc)) from exc
    except UsersImportError as exc:  # pragma: no cover - future refusal classes
        raise _config_exit(fmt, str(exc)) from exc

    if apply_writes:
        from gateclerk.output import make_console

        console = make_console()
        console.print(f"users import applied: {report.plan.counts()}", markup=False)
        console.print(f"dialect: {report.plan.dialect.note}", markup=False)
        console.print(f"journal: {report.journal_path}", markup=False)
        console.print(f"results: {report.result_path}", markup=False)
        if report.aborted:
            console.print(f"ABORTED: {report.abort_reason}", markup=False)
    elif fmt is OutputFormat.TABLE:
        render(
            render_plan_rows(report.plan),
            fmt="table",
            columns=("line", "employeeNo", "cardNo", "action", "reason"),
        )
        typer.echo(f"dialect: {'confirmed' if report.plan.dialect.ok else 'REFUSED'}")
        typer.echo(report.plan.dialect.note)
        typer.echo(f"totals: {report.plan.counts()}")
        typer.echo(f"card capacity: {report.plan.card_capacity!r}")
        for note in report.plan.notes:
            typer.echo(f"note: {note}")
    else:
        render([report.summary()], fmt=fmt.value)

    if not report.clean:
        raise typer.Exit(code=report.exit_code())


def register(app: typer.Typer) -> None:
    """Attach the `users` group to the root CLI app."""
    app.add_typer(users_app)
