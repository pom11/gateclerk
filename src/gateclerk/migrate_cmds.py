"""The `gateclerk migrate` group: `probe`, `export`, `diff`, `apply`, `undo` (CLI-SEAM-MOVE),
plus GC-P16c's `clean` (GC-14's retention verb: report first, delete only with `--apply`).

One-way import law (`tests/test_cli_structure.py`): `gateclerk.cli` imports this module and
calls `migrate_cmds.register(app)`; this module imports `gateclerk.cli_shared`, never
`gateclerk.cli`.

The law the group's help text states in its own words — `apply` writes only with `--apply`,
`undo` removes only what a journal proved this run added — is
`docs/internal/ENROLLMENT-MIGRATION.md` §5a/§7.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Annotated, Any

import typer

from gateclerk import cli_shared
from gateclerk.cli_conventions import CONFIG_ERROR_EXIT
from gateclerk.cli_shared import (
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    DEFAULT_TZ,
    ConfigOpt,
    HostArg,
    OutputOpt,
    PasswordOpt,
    PortOpt,
    SiteOpt,
    TimeoutOpt,
    UserOpt,
    VerboseOpt,
    _config_exit,
    _Guard,
    _migrate_client,
    _migrate_seams,
    _read_target_state,
)
from gateclerk.output import OutputFormat, render

__all__ = [
    "ApplyOpt",
    "BundleOpt",
    "BundleRootOpt",
    "CarryTemplatesOpt",
    "OnConflictOpt",
    "migrate_app",
    "register",
]

migrate_app = typer.Typer(
    name="migrate",
    help=(
        "Enrollment migration: probe, export and diff are read-only; `apply` performs "
        "writes only with --apply, `undo` removes only what a journal proved this run "
        "added, and `clean` reports what a TTL purge would remove and deletes only with "
        "--apply."
    ),
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)

BundleRootOpt = Annotated[
    str | None,
    typer.Option(
        "--bundles-root",
        help="Private root for bundles, probes and run journals (default $GATECLERK_BUNDLE_ROOT, "
        "else ~/gateclerk/bundles). Never inside a git repo — the modules refuse that (§2).",
    ),
]
BundleOpt = Annotated[
    str,
    typer.Option("--bundle", help="Snapshot bundle directory to migrate FROM (export's output)."),
]
OnConflictOpt = Annotated[
    str,
    typer.Option(
        "--on-conflict",
        case_sensitive=False,
        help="What to do with a conflict: skip = report and skip (default), overwrite = "
        "write where the capture proves it safe, abort = refuse the run before it plans a "
        "single write. E1-02's own policy enum (§4), no new vocabulary.",
    ),
]
CarryTemplatesOpt = Annotated[
    bool,
    typer.Option(
        "--carry-templates",
        help="Carry custom plan-template numbers, and only those the target's own probe "
        "evidence lists (§1a). Off by default: an unlisted number is a write the target "
        "has never admitted.",
    ),
]
ApplyOpt = Annotated[
    bool,
    typer.Option(
        "--apply",
        help="Actually perform the phase writes. Without it this is a zero-byte dry run "
        "that reports which phases WOULD run (§4's default).",
    ),
]


@migrate_app.command("probe")
def migrate_probe(
    host: HostArg = None,
    site: SiteOpt = None,
    config: ConfigOpt = None,
    port: PortOpt = DEFAULT_PORT,
    user: UserOpt = None,
    password: PasswordOpt = None,
    timeout: TimeoutOpt = DEFAULT_TIMEOUT,
    output: OutputOpt = OutputFormat.TABLE,
    verbose: VerboseOpt = False,
    bundles_root: BundleRootOpt = None,
) -> None:
    """Read the site's whole capability matrix and persist it (§3). Read-only.

    Writes one file under ``<bundles-root>/probes/`` (0700 dir, 0600 file) and nothing
    else. Every later command is gated on it: ``diff`` and ``apply`` refuse a stale or
    missing probe (§4), which is why this command exists before them.
    """
    from gateclerk import migrate_apply as apply_mod
    from gateclerk.migrate_probe import probe_device, save_matrix

    fmt = output
    site_config, client, _client_factory = _migrate_client(
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
    root = apply_mod.bundle_root(bundles_root)
    with _Guard(fmt), client:
        matrix = probe_device(
            client,
            now=cli_shared._now(),
            site=site_config.name,
            host=site_config.host,
            site_tz=site_config.iana_tz or DEFAULT_TZ,
        )
        try:
            path = save_matrix(matrix, root)
        except ValueError as exc:
            raise _config_exit(fmt, str(exc)) from exc
    if fmt is OutputFormat.TABLE:
        render(
            [
                {"surface": "probe", "verdict": "saved", "note": str(path)},
                *[
                    {
                        "surface": row.key,
                        "verdict": str(row.verdict),
                        "note": row.note or "",
                    }
                    for row in matrix.surfaces
                ],
            ],
            fmt="table",
            columns=("surface", "verdict", "note"),
        )
        return
    payload = matrix.as_dict()
    payload["persisted_to"] = str(path)
    render([payload], fmt=fmt.value)


@migrate_app.command("export")
def migrate_export(
    host: HostArg = None,
    site: SiteOpt = None,
    config: ConfigOpt = None,
    port: PortOpt = DEFAULT_PORT,
    user: UserOpt = None,
    password: PasswordOpt = None,
    timeout: TimeoutOpt = DEFAULT_TIMEOUT,
    output: OutputOpt = OutputFormat.TABLE,
    verbose: VerboseOpt = False,
    bundles_root: BundleRootOpt = None,
    out: Annotated[
        str | None,
        typer.Option("--out", help="Bundle directory to create (it must not exist yet)."),
    ] = None,
) -> None:
    """Snapshot the site (users, cards, face + FP templates) into a private bundle (§2).

    Read-only, and the export module's own contract is "any read failing leaves no bundle
    at the final path" — a partial bundle must never read as a rollback source. The bundle
    is the diff's source AND the pre-run restore point §5b.1 sends people back to, which is
    why a run with no bundle is not a run.
    """
    from gateclerk import migrate_apply as apply_mod
    from gateclerk.migrate_export import export_full_bundle

    fmt = output
    site_config, client, _client_factory = _migrate_client(
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
    root = apply_mod.bundle_root(bundles_root)
    destination = Path(out).expanduser() if out else root / "bundles" / site_config.name
    with _Guard(fmt), client:
        result = export_full_bundle(
            destination,
            client=client,
            clock=lambda: cli_shared._now(),
            inter_page_delay=0.0,
            sleep=lambda _s: None,
        )
    if fmt is OutputFormat.TABLE:
        render(
            [{"bundle": str(result.bundle_dir), **{k: str(v) for k, v in result.counts.items()}}],
            fmt="table",
        )
        return
    from gateclerk.migrate_write import person_hash

    def _index(index: Any) -> dict[str, Any]:
        return {
            "state": index.state,
            "reason": index.reason,
            "entries": [
                {
                    "employee": person_hash(entry.employee_no),
                    "sha256": entry.sha256,
                    "length": entry.length,
                }
                for entry in index.entries
            ],
        }

    render(
        [
            {
                "schema": "gateclerk-migrate-export/1",
                "bundle": str(result.bundle_dir),
                "counts": result.counts,
                "people": sorted(result.people_hashes.values()),
                "faces": _index(result.faces),
                "fingerprints": _index(result.fingerprints),
                "termination": result.termination,
            }
        ],
        fmt=fmt.value,
    )


@migrate_app.command("diff")
def migrate_diff(
    bundle: BundleOpt,
    host: HostArg = None,
    site: SiteOpt = None,
    config: ConfigOpt = None,
    port: PortOpt = DEFAULT_PORT,
    user: UserOpt = None,
    password: PasswordOpt = None,
    timeout: TimeoutOpt = DEFAULT_TIMEOUT,
    output: OutputOpt = OutputFormat.TABLE,
    verbose: VerboseOpt = False,
    bundles_root: BundleRootOpt = None,
    on_conflict: OnConflictOpt = "skip",
    carry_templates: CarryTemplatesOpt = False,
) -> None:
    """Classify the bundle against a FRESH target read (§4). No write client is constructed.

    Exit codes are the diff's own (§4): 0 nothing pending, 1 writes pending, 2 conflicts
    with no writable path. ``--on-conflict=abort`` exits 2 there instead of planning past
    them. The classification table is reason codes verbatim from E1-02 — a code this tool
    does not recognise is reported, never folded into a neighbour.
    """
    from gateclerk import migrate_apply as apply_mod
    from gateclerk.migrate_bundle import read_bundle
    from gateclerk.migrate_probe import load_matrix, require_fresh

    fmt = output
    site_config, client, _client_factory = _migrate_client(
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
    root = apply_mod.bundle_root(bundles_root)
    policy = apply_mod.policy_for(
        on_conflict,
        carry_templates=carry_templates,
        site_tz=site_config.iana_tz or DEFAULT_TZ,
    )
    with _Guard(fmt), client:
        bundle_data = read_bundle(Path(bundle))
        probe = require_fresh(
            load_matrix(root, site_config.name, site_config.host), cli_shared._now()
        )
        seams = _migrate_seams(client, _client_factory, writable=False)
        planned = apply_mod.migrate_plan(
            bundle=bundle_data,
            seams=seams,
            policy=policy,
            probe=probe,
            now=cli_shared._now(),
            bundle_dir=Path(bundle),
        )
        if fmt is OutputFormat.TABLE:
            typer.echo(apply_mod.render_diff_report(planned.plan, fmt="table"), nl=False)
        else:
            render([_diff_payload(planned.plan)], fmt=fmt.value)
    raise typer.Exit(code=planned.plan.exit_code)


def _diff_payload(plan: Any) -> dict[str, Any]:
    import json as _json

    from gateclerk import migrate_apply as apply_mod

    return {
        "schema": "gateclerk-migrate-diff-cli/1",
        "exitCode": plan.exit_code,
        "diff": _json.loads(apply_mod.render_diff_report(plan, fmt="json")),
    }


@migrate_app.command("apply")
def migrate_apply(
    bundle: BundleOpt,
    host: HostArg = None,
    site: SiteOpt = None,
    config: ConfigOpt = None,
    port: PortOpt = DEFAULT_PORT,
    user: UserOpt = None,
    password: PasswordOpt = None,
    timeout: TimeoutOpt = DEFAULT_TIMEOUT,
    output: OutputOpt = OutputFormat.TABLE,
    verbose: VerboseOpt = False,
    bundles_root: BundleRootOpt = None,
    on_conflict: OnConflictOpt = "skip",
    carry_templates: CarryTemplatesOpt = False,
    apply_writes: ApplyOpt = False,
    run_dir: Annotated[
        str | None,
        typer.Option(
            "--run-dir",
            help="Where this run's per-phase journals go (default "
            "<bundles-root>/runs/<utc-stamp>).",
        ),
    ] = None,
) -> None:
    """Run §5 step 2's phase order (users → cards → fingerprints → faces) over the bundle.

    Without ``--apply``: a zero-byte dry run — no journal opened, no transport built, no
    write client constructed, because that is §4's default posture. With it: one journal
    per phase under the run dir, one budgeted transport per phase (§5.3), and the FIRST
    abort or disagreeing verify stops the run — no phase after it runs.

    Exit codes (§7): 0 clean, 2 a gate or conflict refusal (stale probe, clock skew,
    ``--on-conflict=abort`` with conflicts present) — nothing was planned to be written;
    1 the run stopped part-way. A stopped run still prints the composed report naming
    which records landed and which phases remain: a partial write must be legible
    (§5 step 4), never papered over by a nonzero status alone.
    """
    from gateclerk import migrate_apply as apply_mod
    from gateclerk.migrate_bundle import read_bundle
    from gateclerk.migrate_diff import DiffAbortedError, Plan
    from gateclerk.migrate_probe import load_matrix, require_fresh

    fmt = output
    site_config, client, _client_factory = _migrate_client(
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
    root = apply_mod.bundle_root(bundles_root)
    policy = apply_mod.policy_for(
        on_conflict,
        carry_templates=carry_templates,
        site_tz=site_config.iana_tz or DEFAULT_TZ,
    )
    now_val = cli_shared._now()
    journal_dir = (
        Path(run_dir).expanduser() if run_dir else apply_mod.default_journal_dir(now_val, root=root)
    )
    with _Guard(fmt), client:
        bundle_data = read_bundle(Path(bundle))
        probe = require_fresh(load_matrix(root, site_config.name, site_config.host), now_val)
        seams = _migrate_seams(client, _client_factory, writable=apply_writes)
        try:
            planned = apply_mod.migrate_plan(
                bundle=bundle_data,
                seams=seams,
                policy=policy,
                probe=probe,
                now=now_val,
                bundle_dir=Path(bundle),
            )
        except DiffAbortedError as exc:
            refused = apply_mod.BundleApplyReport(
                confirm=False,
                journal_dir=str(journal_dir),
                phases=(),
                would_run=apply_mod.phase_order(),
                stopped_at="plan",
                remaining=apply_mod.phase_order(),
                landed={},
                plan=Plan(items=tuple(exc.conflicts)),
                notes=(str(exc),),
            )
            _emit_apply(refused, fmt)
            raise typer.Exit(code=CONFIG_ERROR_EXIT) from exc
        report = apply_mod.apply_bundle(
            bundle=bundle_data,
            bundle_dir=Path(bundle),
            plan=planned.plan,
            target=_read_target_state(client),
            seams=seams,
            probe=probe,
            now=now_val,
            journal_dir=journal_dir,
            confirm=apply_writes,
            batch_delay=0.0,
            sleep=lambda _s: None,
            recheck=apply_mod.freshness_recheck(
                bundle_data, seams, policy, probe, now_val, bundle_dir=Path(bundle)
            ),
        )
        _emit_apply(report, fmt)
    raise typer.Exit(code=report.exit_code)


def _emit_apply(report: Any, fmt: OutputFormat) -> None:
    if fmt is OutputFormat.TABLE:
        typer.echo(report.render(fmt="table"), nl=False)
        return
    render([report.as_dict()], fmt=fmt.value)


@migrate_app.command("undo")
def migrate_undo(
    journal: Annotated[
        str,
        typer.Option("--journal", help="One phase's journal file from a run directory."),
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
    undo_journal_dir: Annotated[
        str | None,
        typer.Option(
            "--undo-journal",
            help="Where the undo's OWN journal goes (default beside the phase journal).",
        ),
    ] = None,
) -> None:
    """Undo what one journal PROVES this run added, dispatching on the journal's phase (§5a).

    The phase comes from the journal's own lines, never from the file name. Cards and faces
    have capture-proven targeted deletes and get them, each gated on proof-of-add and
    wrapped in §5b's count-delta guard by its own module; users and fingerprints have no
    such verb on this firmware (§5b.1) and get the owning module's report-only wording with
    zero bytes written — which is why a report-only undo needs no device flags at all.

    The undo journals into its own file: the phase journal stays append-only history (§5a).
    Exit: 0 clean or report-only (words are the outcome), 1 a refusal or an incident — both
    need a human.
    """
    from gateclerk import migrate_apply as apply_mod
    from gateclerk.migrate_write import JournalError

    fmt = output
    try:
        report = apply_mod.undo_journal(
            journal, undo_journal_dir=undo_journal_dir, sleep=lambda _s: None
        )
    except (FileNotFoundError, ValueError, JournalError, OSError) as exc:
        raise _config_exit(fmt, f"undo refused: {exc}") from exc
    if report.mode == "refused":
        _site, client, _client_factory = _migrate_client(
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
        seams = _migrate_seams(client, _client_factory, writable=True)
        with _Guard(fmt), client:
            report = apply_mod.undo_journal(
                journal,
                cards_transport_factory=seams.cards_transport_factory,
                cards_reader=seams.cards_reader,
                faces_transport_factory=seams.faces_transport_factory,
                undo_journal_dir=undo_journal_dir,
                sleep=lambda _s: None,
            )
    if fmt is OutputFormat.TABLE:
        typer.echo(apply_mod.render_undo_report(report, fmt="table"), nl=False)
    else:
        render([report.as_dict()], fmt=fmt.value)
    raise typer.Exit(code=report.exit_code)


@migrate_app.command("clean")
def migrate_clean(
    bundles_root: BundleRootOpt = None,
    older_than: Annotated[
        str,
        typer.Option("--older-than", help="Delete artifacts older than this age (e.g. 7d)."),
    ] = "7d",
    apply_writes: Annotated[
        bool,
        typer.Option("--apply", help="Actually delete. Without it this is a dry run."),
    ] = False,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Remove old enrollment bundles and run journals (dry-run by default).

    GC-14's retention answer: after a hardware swap is verified in the receiving system the
    local rollback copy has no remaining purpose, and a bundle is full names, card numbers
    and biometric templates sitting on a laptop. Two buckets are in scope — ``bundles/`` and
    ``runs/`` — and one is not: ``probes/`` stays put, because the probe cache is what lets
    ``diff`` and ``apply`` read at all (§3), not a copy of anyone's enrollment.

    The default is the report. Nothing is removed until the operator has read it and passed
    ``--apply``, which is the same review gate ``apply`` runs on (§4). Exit: 0 (an empty
    inventory is a healthy site, not a broken one), 2 for an unreadable ``--older-than``.
    """
    from gateclerk import migrate_apply as apply_mod
    from gateclerk import migrate_bundle as bundle_mod

    fmt = output
    try:
        days = int(older_than.strip().rstrip("d"))
        if days <= 0:
            raise ValueError("--older-than must be a positive number of days")
    except ValueError as exc:
        raise _config_exit(fmt, f"invalid --older-than {older_than!r}: use e.g. 7d") from exc
    root = apply_mod.bundle_root(bundles_root)
    now_val = cli_shared._now()
    cutoff = now_val - timedelta(days=days)
    report = bundle_mod.clean_artifacts(root, older_than=cutoff, apply=apply_writes, now=now_val)
    payload = {
        "root": str(report.root),
        "older_than": report.older_than.isoformat(),
        "apply": report.apply,
        "bundles": [str(p) for p in report.bundles],
        "runs": [str(p) for p in report.runs],
        "count": report.count,
    }
    if fmt is OutputFormat.TABLE:
        typer.echo(f"{'deleted' if report.apply else 'would delete'} {report.count} artifact(s)")
        for path in (*report.bundles, *report.runs):
            typer.echo(str(path))
        return
    render([payload], fmt=fmt.value)


def register(app: typer.Typer) -> None:
    """Attach the `migrate` group to the root CLI app."""
    app.add_typer(migrate_app)
