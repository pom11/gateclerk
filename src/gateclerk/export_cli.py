"""`gateclerk export config` — sites + devices inventory export (card t_7b62b44c).

Projects `sites.toml` to CSV or JSONL using a HARD allowlist of columns (deny-by-default):
  * site code, enabled flag, state_dir, db_path, db_warn_bytes
  * device host (hostname ONLY — any scheme, `user:pass@` userinfo, port or path stripped),
    port, isapi_user, device_code, serial
  * iana_tz, device_tz, timeout_s, page_delay_ms, cadence_s, overlap_s,
    push_dead_letter_after_s
  * credential REFERENCE names only — never values:
      - `device_cred_keychain_service` (keychain service name)
      - `device_cred_env_var`          (`GATECLERK_<HOST>_PASSWORD`)
      - `device_cred_ref`              (`gateclerk-<site>-<host>`)
      - `ingest_token_keychain_service` (`gateclerk-ingest-<site>`)
      - `ingest_token_env_var`          (`GATECLERK_INGEST_TOKEN_<SITE>`)
  * push_target and `[[site.sink]]` entries sanitized (userinfo/query/fragment stripped,
    only allowlisted sink keys kept, and `token_env` / `token_keychain` validated through
    `sink_cli.token_ref_problem` so a secret value mistakenly placed in a ref field is
    dropped and never echoed).

Any key not on the allowlist (at top level, in `[[site]]`, or in `[[site.sink]]`), as well
as any stripped credential userinfo or secret-shaped ref value, is DROPPED and counted in a
`dropped_keys` summary written to stderr.
"""

from __future__ import annotations

import csv
import io
import json
import re
import sys
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from gateclerk import config as cfg
from gateclerk.exceptions import ConfigError, redact_b64
from gateclerk.sink_cli import token_ref_problem

__all__ = [
    "ALLOWED_SINK_KEYS",
    "ALLOWED_SITE_KEYS",
    "CONFIG_EXPORT_COLUMNS",
    "EXPORT_FORMATS",
    "ConfigExportResult",
    "export_config_file",
    "format_dropped_keys_summary",
    "project_sites_toml",
    "render_config_export",
    "sanitize_host",
    "sanitize_target_url",
]

EXPORT_FORMATS: tuple[str, ...] = ("csv", "jsonl")

CONFIG_EXPORT_COLUMNS: tuple[str, ...] = (
    "site",
    "enabled",
    "state_dir",
    "db_path",
    "db_warn_bytes",
    "host",
    "port",
    "isapi_user",
    "device_code",
    "serial",
    "iana_tz",
    "device_tz",
    "timeout_s",
    "page_delay_ms",
    "cadence_s",
    "overlap_s",
    "push_dead_letter_after_s",
    "device_cred_keychain_service",
    "device_cred_env_var",
    "device_cred_ref",
    "push_target",
    "ingest_token_keychain_service",
    "ingest_token_env_var",
    "sinks",
)

ALLOWED_SITE_KEYS: frozenset[str] = frozenset(
    {
        "name",
        "enabled",
        "state_dir",
        "db_path",
        "db_warn_bytes",
        "host",
        "port",
        "isapi_user",
        "device_code",
        "serial",
        "serial_no",
        "serials",
        "iana_tz",
        "device_tz",
        "timeout_s",
        "page_delay_ms",
        "cadence_s",
        "overlap_s",
        "push_dead_letter_after_s",
        "keychain_service",
        "push_target",
        "sink",
    }
)

ALLOWED_SINK_KEYS: frozenset[str] = frozenset(
    {
        "name",
        "type",
        "url",
        "path",
        "rotation",
        "token_env",
        "token_keychain",
        "enabled",
    }
)


@dataclass(frozen=True, slots=True)
class ConfigExportResult:
    """Projected inventory rows plus the dropped-key audit list."""

    rows: tuple[dict[str, Any], ...]
    dropped_keys: tuple[str, ...]

    @property
    def dropped_count(self) -> int:
        return len(self.dropped_keys)


def _stdout_is_tty() -> bool:
    """Seam for tests: whether stdout is an interactive terminal."""
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


def sanitize_host(raw_host: object) -> tuple[str, list[str]]:
    """Extract ONLY the hostname from `raw_host`, stripping any userinfo/scheme/port/path.

    Returns `(hostname, dropped_markers)` where `dropped_markers` records if embedded
    credentials (`user:pass@`) or URL query/fragment components were stripped.
    """
    dropped: list[str] = []
    if not isinstance(raw_host, str):
        return "", dropped
    text = raw_host.strip()
    if not text:
        return "", dropped
    parsed = urlsplit(text if "://" in text else f"http://{text}")
    if parsed.username or parsed.password or "@" in parsed.netloc:
        dropped.append("site.host.userinfo")
    if parsed.query or parsed.fragment:
        dropped.append("site.host.query")
    hostname = parsed.hostname or ""
    return hostname.strip(), dropped


def sanitize_target_url(raw_url: object, *, prefix: str) -> tuple[str, list[str]]:
    """Sanitize a `push_target` or sink `url`, stripping userinfo, query and fragment.

    Only `https://` and `stub://` targets are kept; any other scheme or secret-looking
    value is dropped and recorded in `dropped_keys`.
    """
    dropped: list[str] = []
    if not isinstance(raw_url, str):
        return "", dropped
    text = raw_url.strip()
    if not text:
        return "", dropped
    if text.startswith("stub://"):
        rest = text[len("stub://") :]
        if "@" in rest:
            dropped.append(f"{prefix}.userinfo")
            rest = rest.rsplit("@", 1)[-1]
        if "?" in rest or "#" in rest:
            dropped.append(f"{prefix}.query")
            rest = re.split(r"[?#]", rest, maxsplit=1)[0]
        return f"stub://{rest}", dropped
    if not text.startswith("https://"):
        dropped.append(prefix)
        return "", dropped
    parsed = urlsplit(text)
    if parsed.username or parsed.password or "@" in parsed.netloc:
        dropped.append(f"{prefix}.userinfo")
    if parsed.query or parsed.fragment:
        dropped.append(f"{prefix}.query")
    host = parsed.hostname or ""
    if not host:
        dropped.append(prefix)
        return "", dropped
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    clean = urlunsplit(("https", netloc, parsed.path or "", "", ""))
    return clean, dropped


def _safe_ref_name(raw_ref: object, *, key_label: str, default: str = "") -> tuple[str, list[str]]:
    """Keep `raw_ref` only when it is a valid reference name, never a secret value."""
    if raw_ref is None:
        return default, []
    if not isinstance(raw_ref, str) or not raw_ref.strip():
        return default, [key_label]
    if token_ref_problem(raw_ref) is not None:
        return default, [key_label]
    return raw_ref.strip(), []


def _safe_scalar_ident(raw: object, *, key_label: str, default: str = "") -> tuple[str, list[str]]:
    """Sanitize a non-secret identifier (`name`, `device_code`, `serial`, `isapi_user`).

    Drops values that trigger `redact_b64` or look like a high-entropy bearer/secret.
    """
    if raw is None:
        return default, []
    if isinstance(raw, list | tuple):
        parts: list[str] = []
        dropped: list[str] = []
        for item in raw:
            val, item_dropped = _safe_scalar_ident(item, key_label=key_label, default="")
            if val:
                parts.append(val)
            dropped.extend(item_dropped)
        return ",".join(parts), dropped
    if not isinstance(raw, str):
        return default, [key_label]
    text = raw.strip()
    if not text:
        return default, []
    if redact_b64(text) != text:
        return default, [key_label]
    if "://" in text or "@" in text:
        return default, [key_label]
    # High-entropy mixed-case+digit single token >= 24 chars with no separator looks like a secret
    if (
        len(text) >= 24
        and re.match(r"^[A-Za-z0-9]+$", text)
        and any(c.islower() for c in text)
        and any(c.isupper() for c in text)
        and any(c.isdigit() for c in text)
    ):
        return default, [key_label]
    return text, []


def _ingest_env_name(site_name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9]", "_", site_name).strip("_").upper()
    return f"GATECLERK_INGEST_TOKEN_{sanitized}" if sanitized else ""


def _ingest_keychain_service(site_name: str) -> str:
    clean = site_name.strip()
    return f"gateclerk-ingest-{clean}" if clean else ""


def _project_sink(
    raw_sink: Mapping[str, Any], *, site_name: str
) -> tuple[dict[str, Any], list[str]]:
    dropped: list[str] = []
    for k in sorted(raw_sink):
        if k not in ALLOWED_SINK_KEYS:
            dropped.append(f"sink.{k}")

    name, d_name = _safe_scalar_ident(raw_sink.get("name"), key_label="sink.name", default="")
    dropped.extend(d_name)
    sink_type = (
        str(raw_sink.get("type", "")).strip() if isinstance(raw_sink.get("type"), str) else ""
    )
    if sink_type not in ("https", "csv", "jsonl", ""):
        dropped.append("sink.type")
        sink_type = ""

    url = ""
    if "url" in raw_sink:
        url, d_url = sanitize_target_url(raw_sink.get("url"), prefix="sink.url")
        dropped.extend(d_url)

    path = ""
    if "path" in raw_sink:
        raw_path = raw_sink.get("path")
        if isinstance(raw_path, str) and redact_b64(raw_path) == raw_path:
            path = raw_path.strip()
        else:
            dropped.append("sink.path")

    rotation = ""
    if "rotation" in raw_sink:
        raw_rot = raw_sink.get("rotation")
        if isinstance(raw_rot, str) and raw_rot.strip() in ("daily", "monthly"):
            rotation = raw_rot.strip()
        else:
            dropped.append("sink.rotation")

    default_env = _ingest_env_name(site_name) if sink_type == "https" else ""
    default_kc = _ingest_keychain_service(site_name) if sink_type == "https" else ""
    token_env, d_env = _safe_ref_name(
        raw_sink.get("token_env"), key_label="sink.token_env", default=default_env
    )
    dropped.extend(d_env)
    token_kc, d_kc = _safe_ref_name(
        raw_sink.get("token_keychain"), key_label="sink.token_keychain", default=default_kc
    )
    dropped.extend(d_kc)

    enabled_raw = raw_sink.get("enabled", True)
    enabled = enabled_raw if isinstance(enabled_raw, bool) else True

    return (
        {
            "name": name,
            "type": sink_type,
            "url": url,
            "path": path,
            "rotation": rotation,
            "token_env": token_env,
            "token_keychain": token_kc,
            "enabled": enabled,
        },
        dropped,
    )


def project_sites_toml(
    raw: bytes,
    *,
    origin: str = "sites.toml",
    site_filter: str | None = None,
    state_root: Path | str | None = None,
) -> ConfigExportResult:
    """Parse `raw` TOML bytes and project onto `CONFIG_EXPORT_COLUMNS` (deny-by-default)."""
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{origin} is not valid TOML: {redact_b64(str(exc))}") from exc

    dropped: list[str] = []
    for top_key in sorted(data):
        if top_key != "site":
            dropped.append(top_key)

    blocks = data.get("site")
    if blocks is None:
        blocks = []
    if not isinstance(blocks, list):
        raise ConfigError(f"{origin}: [[site]] must be an array of tables")

    rows: list[dict[str, Any]] = []
    found_filter = False
    for block in blocks:
        if not isinstance(block, Mapping):
            raise ConfigError(f"{origin}: a [[site]] entry is not a table")

        raw_name = block.get("name")
        site_name = raw_name.strip() if isinstance(raw_name, str) else ""
        if site_filter is not None and site_name != site_filter:
            continue
        found_filter = True

        for k in sorted(block):
            if k not in ALLOWED_SITE_KEYS:
                dropped.append(f"site.{k}")

        clean_name, d_name = _safe_scalar_ident(site_name, key_label="site.name", default="")
        dropped.extend(d_name)

        enabled_raw = block.get("enabled", True)
        enabled = enabled_raw if isinstance(enabled_raw, bool) else True

        host, d_host = sanitize_host(block.get("host", ""))
        dropped.extend(d_host)

        raw_port = block.get("port", cfg.DEFAULT_PORT)
        port = (
            raw_port
            if isinstance(raw_port, int) and not isinstance(raw_port, bool)
            else cfg.DEFAULT_PORT
        )

        isapi_user, d_user = _safe_scalar_ident(
            block.get("isapi_user"), key_label="site.isapi_user", default=cfg.DEFAULT_ISAPI_USER
        )
        dropped.extend(d_user)

        device_code, d_dc = _safe_scalar_ident(
            block.get("device_code"), key_label="site.device_code", default=""
        )
        dropped.extend(d_dc)

        raw_serial = (
            block.get("serial")
            if "serial" in block
            else (block.get("serial_no") if "serial_no" in block else block.get("serials"))
        )
        serial, d_serial = _safe_scalar_ident(raw_serial, key_label="site.serial", default="")
        dropped.extend(d_serial)

        iana_tz = block["iana_tz"].strip() if isinstance(block.get("iana_tz"), str) else ""
        device_tz = block["device_tz"].strip() if isinstance(block.get("device_tz"), str) else ""

        raw_timeout = block.get("timeout_s", cfg.DEFAULT_TIMEOUT_S)
        timeout_s = (
            float(raw_timeout)
            if isinstance(raw_timeout, int | float) and not isinstance(raw_timeout, bool)
            else cfg.DEFAULT_TIMEOUT_S
        )

        raw_delay = block.get("page_delay_ms", cfg.DEFAULT_PAGE_DELAY_MS)
        page_delay_ms = (
            raw_delay
            if isinstance(raw_delay, int) and not isinstance(raw_delay, bool)
            else cfg.DEFAULT_PAGE_DELAY_MS
        )

        raw_cadence = block.get("cadence_s", cfg.DEFAULT_CADENCE_S)
        cadence_s = (
            raw_cadence
            if isinstance(raw_cadence, int) and not isinstance(raw_cadence, bool)
            else cfg.DEFAULT_CADENCE_S
        )

        raw_overlap = block.get("overlap_s", cfg.DEFAULT_OVERLAP_S)
        overlap_s = (
            raw_overlap
            if isinstance(raw_overlap, int) and not isinstance(raw_overlap, bool)
            else cfg.DEFAULT_OVERLAP_S
        )

        raw_dl = block.get("push_dead_letter_after_s", cfg.DEFAULT_PUSH_DEAD_LETTER_AFTER_S)
        push_dead_letter_after_s = (
            raw_dl
            if isinstance(raw_dl, int) and not isinstance(raw_dl, bool)
            else cfg.DEFAULT_PUSH_DEAD_LETTER_AFTER_S
        )

        raw_warn = block.get("db_warn_bytes", cfg.DEFAULT_DB_WARN_BYTES)
        db_warn_bytes = (
            raw_warn
            if isinstance(raw_warn, int) and not isinstance(raw_warn, bool)
            else cfg.DEFAULT_DB_WARN_BYTES
        )

        raw_db_path = block.get("db_path")
        if (
            isinstance(raw_db_path, str)
            and raw_db_path.strip()
            and redact_b64(raw_db_path) == raw_db_path
        ):
            db_path = raw_db_path.strip()
        else:
            if raw_db_path is not None:
                dropped.append("site.db_path")
            db_path = cfg.DEFAULT_DB_PATH_TEMPLATE.format(site=clean_name or "site")

        raw_state_dir = block.get("state_dir")
        if state_root is not None:
            state_dir = str(state_root)
        elif (
            isinstance(raw_state_dir, str)
            and raw_state_dir.strip()
            and redact_b64(raw_state_dir) == raw_state_dir
        ):
            state_dir = raw_state_dir.strip()
        else:
            if raw_state_dir is not None:
                dropped.append("site.state_dir")
            state_dir = str(Path(db_path).parent)

        kc_service, d_kc = _safe_ref_name(
            block.get("keychain_service"),
            key_label="site.keychain_service",
            default=cfg.DEFAULT_KEYCHAIN_SERVICE,
        )
        dropped.extend(d_kc)

        cred_env_var = ""
        if host:
            try:
                cred_env_var = cfg.env_var_names(host)[1]
            except ConfigError:
                cred_env_var = ""
        cred_ref = ""
        if clean_name and host:
            try:
                cred_ref = cfg.credential_ref(clean_name, host)
            except ConfigError:
                cred_ref = ""

        push_target = ""
        if "push_target" in block:
            push_target, d_pt = sanitize_target_url(
                block.get("push_target"), prefix="site.push_target"
            )
            dropped.extend(d_pt)

        sinks_projected: list[dict[str, Any]] = []
        raw_sinks = block.get("sink")
        if isinstance(raw_sinks, list):
            for entry in raw_sinks:
                if isinstance(entry, Mapping):
                    s_row, d_sink = _project_sink(entry, site_name=clean_name)
                    sinks_projected.append(s_row)
                    dropped.extend(d_sink)
                else:
                    dropped.append("site.sink")
        elif raw_sinks is not None:
            dropped.append("site.sink")

        ingest_kc = ""
        ingest_env = ""
        if push_target:
            ingest_kc = _ingest_keychain_service(clean_name)
            ingest_env = _ingest_env_name(clean_name)
        else:
            for s_row in sinks_projected:
                if s_row.get("type") == "https":
                    ingest_kc = ingest_kc or str(s_row.get("token_keychain") or "")
                    ingest_env = ingest_env or str(s_row.get("token_env") or "")

        row: dict[str, Any] = {
            "site": clean_name,
            "enabled": enabled,
            "state_dir": state_dir,
            "db_path": db_path,
            "db_warn_bytes": db_warn_bytes,
            "host": host,
            "port": port,
            "isapi_user": isapi_user,
            "device_code": device_code,
            "serial": serial,
            "iana_tz": iana_tz,
            "device_tz": device_tz,
            "timeout_s": timeout_s,
            "page_delay_ms": page_delay_ms,
            "cadence_s": cadence_s,
            "overlap_s": overlap_s,
            "push_dead_letter_after_s": push_dead_letter_after_s,
            "device_cred_keychain_service": kc_service,
            "device_cred_env_var": cred_env_var,
            "device_cred_ref": cred_ref,
            "push_target": push_target,
            "ingest_token_keychain_service": ingest_kc,
            "ingest_token_env_var": ingest_env,
            "sinks": sinks_projected,
        }
        rows.append(row)

    if site_filter is not None and not found_filter:
        known = (
            ", ".join(
                sorted(
                    b.get("name", "").strip()
                    for b in blocks
                    if isinstance(b, Mapping) and isinstance(b.get("name"), str)
                )
            )
            or "(none configured)"
        )
        raise ConfigError(f"no site named {site_filter!r}; configured: {known}")

    return ConfigExportResult(rows=tuple(rows), dropped_keys=tuple(dropped))


def render_config_export(
    rows: Sequence[Mapping[str, Any]],
    *,
    fmt: str = "csv",
    bom: bool = False,
) -> str:
    """Format projected config rows as `csv` or `jsonl`."""
    norm = fmt.strip().lower()
    if norm == "json":
        norm = "jsonl"
    if norm not in EXPORT_FORMATS:
        raise ConfigError(
            f"unsupported export format {fmt!r} (expected one of: {', '.join(EXPORT_FORMATS)})"
        )
    if norm == "jsonl":
        lines = [
            json.dumps(
                {col: row.get(col) for col in CONFIG_EXPORT_COLUMNS},
                ensure_ascii=False,
                separators=(",", ":"),
            )
            for row in rows
        ]
        return ("\n".join(lines) + "\n") if lines else ""

    buf = io.StringIO()
    if bom:
        buf.write("\ufeff")
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(CONFIG_EXPORT_COLUMNS)
    for row in rows:
        csv_row: list[str] = []
        for col in CONFIG_EXPORT_COLUMNS:
            val = row.get(col)
            if col == "sinks":
                csv_row.append(
                    json.dumps(val, ensure_ascii=False, separators=(",", ":")) if val else "[]"
                )
            elif isinstance(val, bool):
                csv_row.append("true" if val else "false")
            elif val is None:
                csv_row.append("")
            else:
                csv_row.append(str(val))
        writer.writerow(csv_row)
    return buf.getvalue()


def format_dropped_keys_summary(dropped_keys: Sequence[str]) -> str:
    """Deterministic stderr audit line for dropped keys (names only, never values)."""
    count = len(dropped_keys)
    if count == 0:
        return "dropped_keys: 0"
    unique_sorted = ", ".join(sorted(set(dropped_keys)))
    return f"dropped_keys: {count} ({unique_sorted})"


def export_config_file(
    config_path: Path | str = cfg.DEFAULT_SITES_FILE,
    *,
    site: str | None = None,
    state_root: Path | str | None = None,
    fmt: str = "csv",
    output_path: Path | str | None = None,
    bom: bool = False,
    is_tty: bool | None = None,
) -> tuple[str, str]:
    """Run the config export and return `(stdout_payload, stderr_summary)`.

    When `output_path` is None and stdout is a TTY, raises `ConfigError` (exit 2) so an
    interactive run never dumps rows without an explicit `--output <path>` and never
    invents a surprise file path.
    """
    tty = _stdout_is_tty() if is_tty is None else is_tty
    if output_path is None and tty:
        raise ConfigError(
            "stdout is a TTY: pass --output <path> (or -o <path>) to write the export to a "
            "file, or pipe stdout (this command never invents a file path)."
        )

    path = Path(config_path)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise ConfigError(f"sites file {path} not found.") from None
    except OSError as exc:
        raise ConfigError(f"cannot read sites file {path}: {exc.strerror or exc}") from exc

    result = project_sites_toml(raw, origin=str(path), site_filter=site, state_root=state_root)
    payload = render_config_export(result.rows, fmt=fmt, bom=bom)
    summary = format_dropped_keys_summary(result.dropped_keys)

    if output_path is not None:
        out_file = Path(output_path)
        try:
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(payload, encoding="utf-8")
        except OSError as exc:
            raise ConfigError(
                f"cannot write export file {out_file}: {exc.strerror or exc}"
            ) from exc
        return "", f"wrote {len(result.rows)} row(s) to {out_file}; {summary}"

    return payload, summary
