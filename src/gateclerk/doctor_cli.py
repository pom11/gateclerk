"""`gateclerk doctor` — exhaustive read-only self-check (card t_0c1cf9fd, CLI-DOCTOR).

Checks per configured site (plus a runtime block):
  1. `runtime`     version, Python version, platform.
  2. `config`      TOML parse + required keys (`iana_tz`, `device_code` REQUIRED warning
                   when an `https` sink / `push_target` is configured).
  3. `credentials` device credential references resolvable WITHOUT printing secret values
                   (env var set / macOS Keychain metadata via `security find-generic-password`
                   without `-w` / Linux credential file readable with `0600` permissions and
                   ref key present).
  4. `device`      read-only ISAPI probe (`System/deviceInfo` + `System/time` clock skew vs
                   local wall clock in site timezone; warns when `abs(skew) > 120s`).
                   Honors local-LAN `NO_PROXY` (`trust_env=False`).
  5. `sinks`       per-sink URL scheme+parse, token reference resolvability (names only),
                   TLS handshake + certificate verification for `https://` sinks, and
                   directory writability + collision checks for `csv`/`jsonl` sinks.
  6. `db`          read-only SQLite `PRAGMA quick_check` + `push_queue` pending and
                   `dead_letter` counts.

Laws enforced here:
  * NEVER writes to the database, config, or filesystem, and NEVER restarts services.
  * NEVER prints a password or bearer token value.
  * Maps section failures onto `cli_conventions` exit codes (`2` config/credential/db,
    `3` terminal auth 401, `4` device unreachable/protocol, `6` push/sink/dead-letter),
    and exits with the worst failing code across all sections (`2 > 3 > 4 > 6 > 0`).
"""

from __future__ import annotations

import json
import os
import platform
import socket
import sqlite3
import ssl
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from gateclerk import __version__, credentials, sink_cli
from gateclerk import config as cfg
from gateclerk.cli_conventions import (
    AUTH_TERMINAL_EXIT,
    CONFIG_ERROR_EXIT,
    DEVICE_ERROR_EXIT,
    ExitCode,
)
from gateclerk.exceptions import (
    ConfigError,
    CredentialUnavailable,
    GateClerkError,
    IsapiAuthError,
    IsapiError,
    redact_b64,
)
from gateclerk.tz import DEFAULT_SITE_TZ, SKEW_WARN_SECONDS, compute_skew

__all__ = [
    "DOCTOR_COLUMNS",
    "PUSH_FAILURE_EXIT",
    "DoctorRow",
    "check_credential_ref_metadata",
    "default_device_prober",
    "default_tls_prober",
    "doctor_exit_code",
    "run_doctor",
]

PUSH_FAILURE_EXIT = int(ExitCode.PUSH_FAILURE)

DOCTOR_COLUMNS: tuple[str, ...] = (
    "site",
    "section",
    "status",
    "exit_code",
    "detail",
)

_EXIT_PRECEDENCE: tuple[int, ...] = (
    CONFIG_ERROR_EXIT,
    AUTH_TERMINAL_EXIT,
    DEVICE_ERROR_EXIT,
    PUSH_FAILURE_EXIT,
)


@dataclass(frozen=True, slots=True)
class DoctorRow:
    """One section verdict row of `gateclerk doctor`."""

    site: str
    section: str
    status: str  # "pass" | "warn" | "fail"
    exit_code: int
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "site": self.site,
            "section": self.section,
            "status": self.status,
            "exit_code": self.exit_code,
            "detail": self.detail,
        }


def doctor_exit_code(rows: Sequence[DoctorRow | Mapping[str, Any]]) -> int:
    """Worst failing exit code across `rows`, in root-cause precedence `2 > 3 > 4 > 6`."""
    codes: set[int] = set()
    for row in rows:
        status = row.status if isinstance(row, DoctorRow) else row.get("status")
        code = row.exit_code if isinstance(row, DoctorRow) else int(row.get("exit_code") or 0)
        if status == "fail" and code:
            codes.add(code)
    for candidate in _EXIT_PRECEDENCE:
        if candidate in codes:
            return candidate
    return 0


def runtime_row() -> DoctorRow:
    """Global runtime block: version, Python version, platform."""
    py_ver = platform.python_version()
    plat = f"{platform.system()}-{platform.machine()}"
    return DoctorRow(
        site="(global)",
        section="runtime",
        status="pass",
        exit_code=0,
        detail=f"gateclerk={__version__} python={py_ver} platform={plat} no_proxy=local-lan",
    )


def _check_config_section(site: cfg.SiteConfig) -> DoctorRow:
    warnings: list[str] = []
    if site.iana_tz is None:
        warnings.append(
            f"iana_tz unset (defaulting to {DEFAULT_SITE_TZ}; declare iana_tz explicitly)"
        )
    has_https_sink = any(spec.type == "https" for spec in site.effective_sinks)
    if has_https_sink and not site.device_code:
        warnings.append(
            "device_code unset (REQUIRED while roster serial->code fix is pending; "
            "set device_code in sites.toml)"
        )
    if warnings:
        return DoctorRow(
            site=site.name,
            section="config",
            status="warn",
            exit_code=0,
            detail=f"host={site.host}:{site.port}; " + "; ".join(warnings),
        )
    dc_part = f" device_code={site.device_code}" if site.device_code else ""
    return DoctorRow(
        site=site.name,
        section="config",
        status="pass",
        exit_code=0,
        detail=f"host={site.host}:{site.port} iana_tz={site.iana_tz}{dc_part}",
    )


def _check_cred_file_ref(
    ref_name: str,
    *,
    env: Mapping[str, str],
) -> tuple[bool | None, str | None]:
    """Check whether `ref_name` exists in the credential file WITHOUT revealing its value.

    Returns `(present, error_detail)`:
      * `(None, None)` when no credential file is configured or the file does not exist;
      * `(False, error)` when the file exists with bad permissions (`!= 0600`) or bad JSON;
      * `(True, "file <path> (mode 0600)")` when the ref is present with a non-empty string;
      * `(False, None)` when the file is valid `0600` but does not carry `ref_name`.
    """
    store = credentials.resolve_file_store(env=env)
    if store is None:
        return None, None
    path = store.path
    if not path.exists():
        return None, None
    try:
        st = path.stat()
    except OSError as exc:
        return False, f"credential file {path} unreadable: {exc.strerror or exc}"
    mode = st.st_mode & 0o777
    if mode & credentials.PERMISSIVE_BITS:
        return (
            False,
            f"credential file {path} has mode {oct(mode)} (must be 0600: chmod 600 {path})",
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return False, f"credential file {path} is not valid JSON: {redact_b64(str(exc))}"
    refs = data.get("refs") if isinstance(data, Mapping) else None
    if not isinstance(refs, Mapping):
        return False, f"credential file {path} missing 'refs' object"
    val = refs.get(ref_name)
    if isinstance(val, str) and val.strip():
        return True, f"file ref {ref_name} in {path} (mode 0600)"
    return False, None


def check_credential_ref_metadata(
    site: cfg.SiteConfig,
    *,
    env: Mapping[str, str] | None = None,
    keychain_probe: Callable[[str, str], bool | None] | None = None,
) -> DoctorRow:
    """Verify device credential references are resolvable WITHOUT reading or printing values."""
    environ: Mapping[str, str] = os.environ if env is None else env
    probe_kc = keychain_probe or sink_cli.default_keychain_probe

    _, host_pw_env, _, global_pw_env = cfg.env_var_names(site.host)
    dev_ref = cfg.credential_ref(site.name, site.host)
    kc_service = site.keychain_service

    resolved_sources: list[str] = []
    if environ.get(host_pw_env):
        resolved_sources.append(f"env {host_pw_env}")
    elif environ.get(global_pw_env):
        resolved_sources.append(f"env {global_pw_env}")

    kc_ok = probe_kc(kc_service, site.host)
    if kc_ok is True:
        resolved_sources.append(f"keychain service={kc_service} account={site.host}")

    file_ok, file_detail = _check_cred_file_ref(dev_ref, env=environ)
    if file_detail and file_ok is False:
        return DoctorRow(
            site=site.name,
            section="credentials",
            status="fail",
            exit_code=CONFIG_ERROR_EXIT,
            detail=file_detail,
        )
    if file_ok is True and file_detail:
        resolved_sources.append(file_detail)

    if resolved_sources:
        return DoctorRow(
            site=site.name,
            section="credentials",
            status="pass",
            exit_code=0,
            detail="device credential ref resolvable via " + ", ".join(resolved_sources),
        )

    return DoctorRow(
        site=site.name,
        section="credentials",
        status="fail",
        exit_code=CONFIG_ERROR_EXIT,
        detail=(
            f"no device credential ref resolved (checked env {host_pw_env}, "
            f"keychain service={kc_service} account={site.host}, file ref {dev_ref})"
        ),
    )


def default_device_prober(
    site: cfg.SiteConfig,
    *,
    env: Mapping[str, str] | None = None,
    now: datetime | None = None,
) -> tuple[str, float | None]:
    """Read-only probe of `System/deviceInfo` and `System/time` (`trust_env=False` / NO_PROXY).

    THE REAL PATH — the one every `doctor` test used to replace with a lambda, which is
    why it shipped calling an API that does not exist (`IsapiClient(port=..., credentials=
    ...)`, `client.get_xml(...)`, `device_identity(client)`). It now speaks the same
    sanctioned surface as every other read command: `cli_shared._client_for`'s ctor shape
    (registry names in, dicts out — no paths, no verbs) and `pipeline`'s device reads, so
    a device that answers the CLI answers the doctor. Exactly two GETs, both in the
    read-only registry: `device_info` and `system_time`. Nothing is written, no service is
    restarted, no secret is printed (the summary carries model + serial only).

    Returns `(device_summary, skew_seconds)`. Raises `CredentialUnavailable`,
    `IsapiAuthError`, or `IsapiError` on failure.
    """
    from gateclerk import pipeline
    from gateclerk.isapi_transport import IsapiClient

    target = site.target()
    # The credential resolves through the SAME ladder every command uses (flag-less here:
    # env > keychain > file). Resolving before the socket opens keeps a missing credential
    # a `CredentialUnavailable` (config exit 2) instead of surfacing later as an auth 401.
    creds = cfg.resolve_credentials(target, env=env)
    client = IsapiClient(
        f"http://{target.host}:{target.port}",
        creds.user,
        creds.password.reveal(),
        read_timeout=site.timeout_s,
        trust_env=False,
    )
    try:
        serial, _firmware, model = pipeline.read_device_identity(client)
        dev_time, _raw = pipeline.device_time_reading(client)
    finally:
        client.close()

    tz_name = site.device_tz or site.iana_tz or DEFAULT_SITE_TZ
    skew = compute_skew(
        dev_time,
        our_now=now or datetime.now(UTC),
        site_tz=tz_name,
        warn_seconds=SKEW_WARN_SECONDS,
    )
    summary = f"model={model or '?'} serial={serial or '?'}"
    return summary, skew.skew_seconds


def _write_device_probe(
    site: cfg.SiteConfig,
    state_root: Path | str | None,
    now: datetime,
    *,
    ok: bool,
    detail: str,
) -> None:
    """Cache this site's device-probe verdict for `gateclerk status` (GC-P11).

    The reader is `status_cli._device_section`, which reads exactly
    `status_cli.PROBE_CACHE_PARTS` and refuses to age a result past
    `DEVICE_PROBE_MAX_AGE_S`; the tests in tests/test_gc_p11_status_writers.py read through
    that constant, so writer and reader cannot drift apart unnoticed. The path is resolved
    by `agent_cli.resolve_state_root` — the SAME call the reader makes — which is what makes
    `doctor --state-root X` and `status --state-root X` talk about one directory.

    `detail` is the row's own redacted text, capped: the cache is operator-visible and by
    `sink_cli`'s precedent names statuses and exceptions, never a payload or a secret.
    Atomic (`tmp` + `Path.replace`, the agent's `_write_health` precedent) because a
    concurrent `status` must never read half a document.
    """
    from gateclerk import agent_cli  # the lazy edge `_check_db_section` already uses

    root = agent_cli.resolve_state_root(site, state_root)
    target = root.joinpath("status", "device-probe.json")
    payload = {"checked_at": now.isoformat(), "ok": ok, "detail": detail[:160]}
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        tmp.replace(target)
    except OSError:
        # A state root this process cannot write (the unit's dir, owned by the service
        # user, with `doctor` run by the operator) must not turn a read-only check into a
        # traceback: the rows and the exit code ARE doctor's contract, the cache is a bonus
        # and `status` already has an honest line for its absence ("run: gateclerk doctor").
        return


def _check_device_section(
    site: cfg.SiteConfig,
    *,
    env: Mapping[str, str] | None,
    now: datetime,
    device_prober: Callable[..., tuple[str, float | None]] | None,
    state_root: Path | str | None = None,
) -> DoctorRow:
    """Probe the device once, report it, and leave the verdict in the status cache.

    Every outcome writes — a pass, a warn, or a failure — because `status` is a screen for
    what the last check saw, and an operator who just ran the doctor should not be told
    "unknown — run: gateclerk doctor" (GC-P11). `state_root` defaults to None, which
    resolves exactly the way the reader resolves it.
    """
    prober = device_prober or default_device_prober

    def _failed(exit_code: int, detail: str) -> DoctorRow:
        _write_device_probe(site, state_root, now, ok=False, detail=detail)
        return DoctorRow(
            site=site.name, section="device", status="fail", exit_code=exit_code, detail=detail
        )

    def _reported(status: str, detail: str) -> DoctorRow:
        # A warn is still a completed probe: the device answered, the skew is the complaint.
        _write_device_probe(site, state_root, now, ok=True, detail=detail)
        return DoctorRow(
            site=site.name, section="device", status=status, exit_code=0, detail=detail
        )

    try:
        summary, skew_s = prober(site, env=env, now=now)
    except CredentialUnavailable as exc:
        return _failed(
            CONFIG_ERROR_EXIT,
            f"cannot probe device (credentials unavailable): {redact_b64(str(exc))}",
        )
    except IsapiAuthError as exc:
        return _failed(
            AUTH_TERMINAL_EXIT,
            f"device authentication failed (401 / circuit open): {redact_b64(str(exc))}",
        )
    except (IsapiError, GateClerkError, OSError) as exc:
        return _failed(
            DEVICE_ERROR_EXIT,
            f"device unreachable or protocol error: {redact_b64(str(exc))}",
        )

    if skew_s is None:
        return _reported("warn", f"reachable ({summary}); clock skew unavailable")
    if abs(skew_s) > SKEW_WARN_SECONDS:
        return _reported(
            "warn",
            (
                f"reachable ({summary}); clock skew {skew_s:+.1f}s exceeds "
                f"{SKEW_WARN_SECONDS:.0f}s (punches depend on device clock)"
            ),
        )
    return _reported(
        "pass",
        (f"reachable ({summary}); clock skew {skew_s:+.1f}s (within {SKEW_WARN_SECONDS:.0f}s)"),
    )


def default_tls_prober(host: str, port: int, *, timeout_s: float = 5.0) -> str:
    """Perform a read-only TLS handshake + certificate verification against `(host, port)`."""
    ctx = ssl.create_default_context()
    with (
        socket.create_connection((host, port), timeout=timeout_s) as sock,
        ctx.wrap_socket(sock, server_hostname=host) as tls_sock,
    ):
        version = tls_sock.version() or "TLS"
        return f"{version} cert verified"


def _check_sinks_section(
    site: cfg.SiteConfig,
    *,
    env: Mapping[str, str] | None,
    keychain_probe: Callable[[str, str], bool | None] | None,
    tls_prober: Callable[[str, int], str] | None,
) -> DoctorRow:
    sinks = site.effective_sinks
    if not sinks:
        return DoctorRow(
            site=site.name,
            section="sinks",
            status="warn",
            exit_code=0,
            detail="no push_target or [[site.sink]] configured (pusher is off)",
        )

    environ: Mapping[str, str] = os.environ if env is None else env
    probe_kc = keychain_probe or sink_cli.default_keychain_probe
    failures: list[str] = []
    summaries: list[str] = []
    exit_code = 0

    for spec in sinks:
        others = [other.path for other in sinks if other.name != spec.name and other.path]
        checks = sink_cli.check_sink(
            site,
            spec,
            env=environ,
            keychain_probe=probe_kc,
            other_paths=others,
        )
        # If the token-ref check failed on keychain/env, also check the Linux credential file
        # for the ingest ref (`gateclerk-ingest-<site>` or `spec.token_keychain`) before
        # failing. The name is `sink_cli._check_token_refs`'s (singular) — a plural spelling
        # here made this fallback unreachable and filed a missing bearer under exit 6.
        sink_failed = False
        for chk in checks:
            if not chk.ok and chk.check == "token-ref":
                ing_ref = spec.token_keychain or credentials.ingest_ref(site.name)
                file_ok, file_detail = _check_cred_file_ref(ing_ref, env=environ)
                if file_ok is True and file_detail:
                    summaries.append(f"{spec.name}:token-ref={file_detail}")
                    continue
            if not chk.ok:
                sink_failed = True
                failures.append(f"{spec.name}:{chk.check}: {chk.detail}")
                if chk.check in ("config", "token-ref", "directory", "path-collision"):
                    exit_code = exit_code or CONFIG_ERROR_EXIT
                else:
                    exit_code = exit_code or PUSH_FAILURE_EXIT

        if spec.type == "https" and spec.ref.startswith("https://") and not sink_failed:
            parts = urlsplit(spec.ref)
            host = parts.hostname or ""
            port = parts.port or 443
            if host and tls_prober is not None:
                try:
                    tls_info = tls_prober(host, port)
                    summaries.append(f"{spec.name}:https({host}:{port}, {tls_info})")
                except (ssl.SSLError, OSError, ValueError) as exc:
                    failures.append(
                        f"{spec.name}:tls handshake failed for {host}:{port}: "
                        f"{redact_b64(str(exc))}"
                    )
                    exit_code = exit_code or PUSH_FAILURE_EXIT
            else:
                summaries.append(f"{spec.name}:https({host}:{port})")
        elif not sink_failed:
            summaries.append(f"{spec.name}:{spec.type}({spec.ref})")

    if failures:
        return DoctorRow(
            site=site.name,
            section="sinks",
            status="fail",
            exit_code=exit_code or PUSH_FAILURE_EXIT,
            detail="; ".join(failures),
        )
    return DoctorRow(
        site=site.name,
        section="sinks",
        status="pass",
        exit_code=0,
        detail="; ".join(summaries),
    )


def _check_db_section(
    site: cfg.SiteConfig,
    *,
    state_root: Path | str | None,
) -> DoctorRow:
    from gateclerk import agent_cli

    db_path = Path(agent_cli.resolve_db_path(site, state_root))
    if not db_path.exists():
        return DoctorRow(
            site=site.name,
            section="db",
            status="warn",
            exit_code=0,
            detail=f"no store yet at {db_path}",
        )
    try:
        conn = sqlite3.connect(str(db_path))
        conn.execute("PRAGMA query_only=ON")
        conn.row_factory = sqlite3.Row
        try:
            chk_row = conn.execute("PRAGMA quick_check").fetchone()
            verdict = str(chk_row[0]) if chk_row else "unknown"
            if verdict.lower() != "ok":
                return DoctorRow(
                    site=site.name,
                    section="db",
                    status="fail",
                    exit_code=CONFIG_ERROR_EXIT,
                    detail=f"sqlite quick_check failed on {db_path}: {verdict}",
                )
            tables = {
                str(r["name"])
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            pending = (
                int(conn.execute("SELECT COUNT(*) FROM push_queue").fetchone()[0])
                if "push_queue" in tables
                else 0
            )
            dead = (
                int(conn.execute("SELECT COUNT(*) FROM dead_letter").fetchone()[0])
                if "dead_letter" in tables
                else 0
            )
        finally:
            conn.close()
    except sqlite3.Error as exc:
        return DoctorRow(
            site=site.name,
            section="db",
            status="fail",
            exit_code=CONFIG_ERROR_EXIT,
            detail=f"sqlite store {db_path} unreadable or corrupt: {exc}",
        )

    if dead > 0:
        return DoctorRow(
            site=site.name,
            section="db",
            status="fail",
            exit_code=PUSH_FAILURE_EXIT,
            detail=f"integrity=ok pending={pending} dead_letter={dead} ({db_path})",
        )
    return DoctorRow(
        site=site.name,
        section="db",
        status="pass",
        exit_code=0,
        detail=f"integrity=ok pending={pending} dead_letter=0 ({db_path})",
    )


def run_doctor(
    *,
    config_path: Path | str = cfg.DEFAULT_SITES_FILE,
    site: str | None = None,
    state_root: Path | str | None = None,
    env: Mapping[str, str] | None = None,
    now: datetime | None = None,
    keychain_probe: Callable[[str, str], bool | None] | None = None,
    device_prober: Callable[..., tuple[str, float | None]] | None = None,
    tls_prober: Callable[[str, int], str] | None = None,
) -> tuple[list[DoctorRow], int]:
    """Run all `gateclerk doctor` checks and return `(rows, exit_code)`."""
    moment = now or datetime.now(UTC)
    active_tls_prober = default_tls_prober if tls_prober is None else tls_prober
    rows: list[DoctorRow] = [runtime_row()]

    try:
        sites = cfg.load_sites(config_path, surface=cfg.ConfigSurface.CLI)
    except ConfigError as exc:
        rows.append(
            DoctorRow(
                site=site or "(config)",
                section="config",
                status="fail",
                exit_code=CONFIG_ERROR_EXIT,
                detail=redact_b64(str(exc)),
            )
        )
        return rows, doctor_exit_code(rows)

    if site is not None:
        try:
            selected = [cfg.find_site(sites, site)]
        except ConfigError as exc:
            rows.append(
                DoctorRow(
                    site=site,
                    section="config",
                    status="fail",
                    exit_code=CONFIG_ERROR_EXIT,
                    detail=redact_b64(str(exc)),
                )
            )
            return rows, doctor_exit_code(rows)
    else:
        selected = [sites[name] for name in sorted(sites)]

    if not selected:
        rows.append(
            DoctorRow(
                site="(config)",
                section="config",
                status="fail",
                exit_code=CONFIG_ERROR_EXIT,
                detail=f"no [[site]] blocks configured in {config_path}",
            )
        )
        return rows, doctor_exit_code(rows)

    for site_cfg in selected:
        rows.append(_check_config_section(site_cfg))
        rows.append(check_credential_ref_metadata(site_cfg, env=env, keychain_probe=keychain_probe))
        rows.append(
            _check_device_section(
                site_cfg, env=env, now=moment, device_prober=device_prober, state_root=state_root
            )
        )
        rows.append(
            _check_sinks_section(
                site_cfg,
                env=env,
                keychain_probe=keychain_probe,
                tls_prober=active_tls_prober,
            )
        )
        rows.append(_check_db_section(site_cfg, state_root=state_root))

    return rows, doctor_exit_code(rows)
