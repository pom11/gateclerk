"""The `gateclerk creds` group: `test`, `set`, `get`, `remove`, and `explain` (CLI-SEAM-MOVE).

One-way import law (`tests/test_cli_structure.py`): `gateclerk.cli` imports this module and
calls `creds_cmds.register(app)`; this module imports `gateclerk.cli_shared`, never
`gateclerk.cli`.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Annotated, Any

import typer

from gateclerk import config as cfg
from gateclerk import credentials
from gateclerk.cli_shared import (
    DEFAULT_PORT,
    ConfigOpt,
    HostArg,
    OutputOpt,
    PasswordOpt,
    PortOpt,
    SiteOpt,
    UserOpt,
    _alias_group,
    _config_exit,
    _resolve_creds,
    _resolve_site,
)
from gateclerk.exceptions import ConfigError, CredentialUnavailable
from gateclerk.output import OutputFormat, render

__all__ = ["CredentialsFileOpt", "CredsRefArg", "creds_app", "register"]

creds_app = typer.Typer(
    name="creds",
    help="Credential/config diagnostics. Never contacts the device.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
    cls=_alias_group(("creds",)),
)

CredentialsFileOpt = Annotated[
    str | None,
    typer.Option(
        "--credentials-file",
        help="Credential file to operate on (default: $GATECLERK_CREDENTIALS_FILE, else "
        "~/.config/gateclerk/credentials.json). Refused unless the file is mode 0600.",
    ),
]

CredsRefArg = Annotated[
    str,
    typer.Argument(
        help="Credential REF NAME — the portable address, e.g. gateclerk-site-a-192.0.2.10 "
        "for a device or gateclerk-ingest-site-a for an ingest bearer. The same name means "
        "the same secret on macOS and Linux; only the backend differs."
    ),
]


def _file_store_for(path: str | None, output: OutputFormat) -> Any:
    try:
        return credentials.resolve_file_store(path=path)
    except (CredentialUnavailable, ConfigError) as exc:
        raise _config_exit(output, str(exc)) from exc


@creds_app.command("test")
def creds_test(
    host: HostArg = None,
    site: SiteOpt = None,
    config: ConfigOpt = None,
    port: PortOpt = DEFAULT_PORT,
    user: UserOpt = None,
    password: PasswordOpt = None,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Resolve the credential for a device and report the SOURCE. No network, no device.

    This is the command the orchestrator uses to verify the live Keychain path once
    (card p1-02 DoD): it exercises flags, env and `security find-generic-password`,
    prints `admin@host via keychain`, and never prints the password. Exit 2 with the exact
    `security` command to run when resolution fails.

    CLI-VERBS-HELP: the canonical verb is `test` (it answers "does this resolve", with no
    side effect); the old spelling `creds check` remains as a hidden alias.
    """
    target = _resolve_site(
        host=host, site=site, port=port, sites_file=config, output=output
    ).target()
    creds = _resolve_creds(target, user=user, password=password, output=output)
    render(
        [
            {
                "site": target.site,
                "host": target.host,
                "port": target.port,
                "user": creds.user,
                "source": creds.source.value,
                "password": "***",
            }
        ],
        fmt=output.value,
        columns=("site", "host", "port", "user", "source", "password"),
    )


@creds_app.command("set")
def creds_set(
    ref: CredsRefArg,
    file: Annotated[
        str | None,
        typer.Option(
            "--file",
            help="Read the VALUE from this file (non-interactive, as the card requires). "
            "`--file -` reads it from stdin, for a pipe from a secret manager. The value "
            "is never an argv value, so it never lands in shell history.",
        ),
    ] = None,
    credentials_file: CredentialsFileOpt = None,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Store one credential ref in the 0600 credential file. Non-interactive only.

    The only writer this repo has for `~/.config/gateclerk/credentials.json`, which is the
    file backend a Linux host uses in place of the macOS Keychain. Writing is atomic and
    the file is created 0600; an existing file with looser permissions is REFUSED rather
    than quietly augmented, because augmenting a world-readable secret store is the
    accident, not the fix. Nothing here contacts a device and nothing prints the value:
    the row says `ref / backend / path / mode`, which is the whole safe answer.
    """
    if file is None:
        raise _config_exit(
            output,
            "creds set is non-interactive by design: pass --file <path> (or --file - to "
            "read the value from stdin). A prompt would put the secret in terminal "
            "scrollback, and an argv value puts it in shell history — the two places "
            "DESIGN.md's credential rules say a value must not be.\n"
            f"    example: my-secret-manager get {ref} | gateclerk creds set {ref} --file -",
        )
    value = _read_secret_argument(file, ref=ref, output=output)
    store = _file_store_for(credentials_file, output)
    try:
        existed = store.exists()
        store.write(ref, value)
    except (CredentialUnavailable, ConfigError) as exc:
        raise _config_exit(output, str(exc)) from exc
    render(
        [
            {
                "ref": ref,
                "backend": "file",
                "path": str(store.path),
                "mode": f"{store.mode():04o}" if store.mode() is not None else "?",
                "status": "updated" if existed else "created",
                "value": "***",
            }
        ],
        fmt=output.value,
        columns=("ref", "backend", "path", "mode", "status", "value"),
    )


def _read_secret_argument(spec: str, *, ref: str, output: OutputFormat) -> str:
    try:
        if spec == "-":
            raw = sys.stdin.read()
        else:
            raw = Path(spec).expanduser().read_text(encoding="utf-8")
    except OSError as exc:
        raise _config_exit(
            output, f"cannot read the value for {ref!r} from {spec!r}: {exc.strerror or exc}"
        ) from exc
    value = raw.rstrip("\r\n")
    if not value:
        raise _config_exit(
            output,
            f"the value read from {spec!r} is empty for {ref!r}. An empty credential is "
            "never valid — it would shadow the env and platform rungs with a blank.",
        )
    return value


@creds_app.command("get")
def creds_get(
    names: Annotated[
        list[str],
        typer.Argument(
            help="Ref name(s) to report. With no name, every ref the file carries. Only "
            "names are printed — never a value."
        ),
    ] = (),
    credentials_file: CredentialsFileOpt = None,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Report which refs EXIST and which backend answers. Prints no value, ever.

    A read of the file backend only — deliberately not a resolution: resolution goes to
    the macOS Keychain, and every `security` invocation can raise an ACL prompt, so a
    command whose whole job is "what is installed?" must not be able to pop a dialog.
    `creds check --host …` is the command that runs the real ladder and prints the source
    that won.

    Columns are ref / status / env-var / detail, where status is `present`, `absent` or
    `empty` — the third one because a ref stored with an empty value reads as absent to the
    resolver (an empty variable counts as unset everywhere here), and an operator told
    simply "no" has no way to discover they typed it wrong.
    """
    store = _file_store_for(credentials_file, output)
    try:
        wanted = list(names) if names else list(store.names())
        rows = [_cred_status(store, name) for name in wanted]
    except (CredentialUnavailable, ConfigError) as exc:
        raise _config_exit(output, str(exc)) from exc
    render(rows, fmt=output.value, columns=("ref", "status", "env_var", "detail"))


def _cred_status(store: Any, name: str) -> dict[str, str]:
    status = store.source_for(name)
    candidates = credentials.env_var_candidates(name)
    env_set = next((var for var in candidates if os.environ.get(var)), None)
    if env_set is not None:
        detail = f"{env_set} is set, so it wins the rung above the file"
    elif len(candidates) > 1:
        detail = f"none of {len(candidates)} possible env rungs is set (site/host split ambiguous)"
    elif candidates:
        detail = f"env rung {candidates[0]} is unset"
    else:
        detail = "no env rung names this ref"
    return {
        "ref": name,
        "status": status,
        "env_var": credentials.env_var_summary(name),
        "detail": detail,
        "value": "***",
    }


@creds_app.command("remove")
def creds_remove(
    ref: CredsRefArg,
    credentials_file: CredentialsFileOpt = None,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Drop one ref from the 0600 credential file. Idempotent; never a device write.

    Removing the last ref leaves an empty `{"refs": {}}` file rather than deleting it, so a
    deploy that expects the path to exist keeps working and `creds get` still reports the
    truth. An absent ref is `status=absent` with exit 0 — a re-runnable cleanup step should
    not fail a pipeline because it ran twice.
    """
    store = _file_store_for(credentials_file, output)
    try:
        removed = store.remove(ref)
    except (CredentialUnavailable, ConfigError) as exc:
        raise _config_exit(output, str(exc)) from exc
    render(
        [
            {
                "ref": ref,
                "backend": "file",
                "path": str(store.path),
                "status": "removed" if removed else "absent",
            }
        ],
        fmt=output.value,
        columns=("ref", "backend", "path", "status"),
    )


@creds_app.command("explain")
def creds_explain(
    host: str,
    port: PortOpt = DEFAULT_PORT,
    output: OutputOpt = OutputFormat.TABLE,
) -> None:
    """Print where this host's credential WOULD be looked for. Reads nothing, resolves nothing."""
    target = cfg.DeviceTarget(host=host, port=port)
    rows = [
        {
            "rung": 1,
            "source": "flag",
            "where": "--user / --password",
            "detail": "highest precedence; one-off debugging (lands in shell history)",
        },
        {
            "rung": 2,
            "source": "env",
            "where": ", ".join(cfg.env_var_names(host)[:2]),
            "detail": "per-host beats global",
        },
        {
            "rung": 3,
            "source": "env",
            "where": ", ".join(cfg.env_var_names(host)[2:]),
            "detail": "global fallback (a gitignored .env feeds this rung)",
        },
        {
            "rung": 4,
            "source": "keychain",
            "where": target.find_command(),
            "detail": "comment field carries user=<isapi_user>",
        },
        {
            "rung": 5,
            "source": "keychain",
            "where": target.add_command(),
            "detail": "creates the item; -w last so the password is prompted, not argv",
        },
        {
            "rung": 6,
            "source": str(credentials.CredentialSource.FILE.value),
            "where": str(credentials.default_credential_file()),
            "detail": (
                f"mode 0600 required, ref {credentials.device_ref(None, host)!r}; the Linux "
                "answer where there is no Keychain — write it with `gateclerk creds set`"
            ),
        },
    ]
    render(rows, fmt=output.value, columns=("rung", "source", "where", "detail"))


def register(app: typer.Typer) -> None:
    """Attach the `creds` group to the root CLI app."""
    app.add_typer(creds_app)
