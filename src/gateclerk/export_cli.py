"""`gateclerk export config` & `gateclerk export scans` (cards t_7b62b44c, t_5a0f39b2).

Three exports, one module:

1. `gateclerk export config` — projects `sites.toml` to CSV or JSONL using a HARD allowlist
   of columns (`CONFIG_EXPORT_COLUMNS`, deny-by-default):
     * site code, enabled flag, state_dir, db_path, db_warn_bytes
     * device host (hostname ONLY — any scheme, `user:pass@` userinfo, port or path
       stripped), port, isapi_user, device_code, serial
     * iana_tz, device_tz, timeout_s, page_delay_ms, cadence_s, overlap_s,
       push_dead_letter_after_s
     * credential REFERENCE names only — never values (`device_cred_keychain_service`,
       `device_cred_env_var`, `device_cred_ref`, `ingest_token_keychain_service`,
       `ingest_token_env_var`, plus sink `token_env` / `token_keychain` validated via
       `sink_cli.token_ref_problem`)
     * every sink field the parser honours: `type` (including the `mnotify` alert route),
       `url`, `path`, `rotation`, `enabled`, `to`, `timeout_s`, `accepts_roster` and
       `headers` as sorted `k=v` pairs — a reserved header name (`Authorization`,
       `X-GateClerk-Site`) or a secret-shaped value drops the whole header table
     * unknown keys and stripped userinfo/secrets are DROPPED and counted in a
       `dropped_keys` summary on stderr.

2. `gateclerk export scans` — streams stored attendance scans from the agent's local SQLite
   store (`events` table) in `(event_time_utc, serial_no)` order:
     * filters: `--site` (required when `> 1` site is configured), `--device`,
       `--employee`, `--since`, `--until`, `--direction` (`in|out|any`, stored fields
       only);
     * streaming: reads in bounded chunks via `cursor.fetchmany(SCAN_EXPORT_CHUNK_SIZE)`
       and writes chunk-by-chunk (never materializes the table into a list);
     * formats: `csv` (fixed header `SCAN_EXPORT_COLUMNS`, UTF-8, optional `--bom` for
       Excel on Windows) or `jsonl` (the agent's stored `EventRecord` lines verbatim);
     * personal-data law: refuses on an interactive TTY unless `--output <path>` is
       given; `--redact` drops `employee_no`, `cardNo`, and `name` columns (and strips
       those keys inside `raw` / JSONL).
3. `gateclerk export non-punches` (GC-P20 / E22) — the DISTINCT `fingerprint_hash` values of
   the events this site's poller recorded as pushed (`push-ledger.jsonl`) that were NOT
   granted punches, for BC-P30 to mark ignored and recalculate:
     * one output column (`NON_PUNCH_EXPORT_COLUMNS`) and nothing else — no employee number,
       name, card number or raw payload; the fingerprint goes out verbatim because it IS BC's
       dedupe key;
     * read-only by construction (`_open_read_only_store`): the store is opened `mode=ro`, the
       ledger is read through `PushLedger`, and BC is never contacted;
     * a missing ledger is an empty report with a note, not an error — nothing is known to be
       pushed, and guessing is not this command's job.
"""

from __future__ import annotations

import csv
import io
import json
import re
import sqlite3
import sys
import tomllib
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import urlsplit, urlunsplit

from gateclerk import config as cfg
from gateclerk.event_codes import NON_AUTH_VERIFY_MODES
from gateclerk.exceptions import ConfigError, EventBoundsError, redact_b64
from gateclerk.sink_cli import token_ref_problem
from gateclerk.tz import DEFAULT_SITE_TZ, parse_user_timestamp

__all__ = [
    "ALLOWED_SINK_KEYS",
    "ALLOWED_SITE_KEYS",
    "CONFIG_EXPORT_COLUMNS",
    "DIRECTION_CHOICES",
    "EXPORT_FORMATS",
    "NON_PUNCH_EXPORT_COLUMNS",
    "REDACTED_SCAN_FIELDS",
    "SCAN_EXPORT_CHUNK_SIZE",
    "SCAN_EXPORT_COLUMNS",
    "SCAN_EXPORT_REDACTED_COLUMNS",
    "ConfigExportResult",
    "export_config_file",
    "export_non_punch_fingerprints",
    "export_scans_stream",
    "format_dropped_keys_summary",
    "project_sites_toml",
    "render_config_export",
    "resolve_scan_store_path",
    "sanitize_host",
    "sanitize_target_url",
]

EXPORT_FORMATS: tuple[str, ...] = ("csv", "jsonl")
DIRECTION_CHOICES: tuple[str, ...] = ("any", "in", "out", "unknown")

#: Chunk size for streaming `events` rows out of SQLite (monkeypatchable in tests).
SCAN_EXPORT_CHUNK_SIZE: int = 256

#: Personal-data columns omitted from CSV headers/rows (and JSONL top-level) under `--redact`.
REDACTED_SCAN_FIELDS: frozenset[str] = frozenset({"employee_no", "cardNo", "name"})

#: Stable 28-column CSV header for `gateclerk export scans` (documented in docs/EXPORT-COLUMNS.md).
SCAN_EXPORT_COLUMNS: tuple[str, ...] = (
    "site",
    "device_serial",
    "serial_no",
    "employee_no",
    "cardNo",
    "name",
    "event_time_utc",
    "event_time_local",
    "tz_offset_min",
    "tz_offset_min_device",
    "tz_source",
    "iana_tz",
    "tz_unresolved",
    "tz_ambiguous",
    "tz_nonexistent",
    "tz_reason",
    "tz_offset_mismatch",
    "direction",
    "attendance_status",
    "direction_source",
    "verify_mode",
    "major",
    "minor",
    "outcome",
    "unknown_code",
    "encrypted_person_data",
    "raw",
    "captured_at",
)

SCAN_EXPORT_REDACTED_COLUMNS: tuple[str, ...] = tuple(
    col for col in SCAN_EXPORT_COLUMNS if col not in REDACTED_SCAN_FIELDS
)

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
        # Real `SinkSpec` fields (sinks.py): dropping them told the operator the site had
        # no alert route / no roster opt-out when it had both.
        "to",
        "timeout_s",
        "headers",
        "accepts_roster",
    }
)

#: The transport's own two header names. `sinks.py` refuses them in a configured
#: `headers` table — `Authorization` holds the bearer token (which has exactly one home,
#: the ref rungs) and `X-GateClerk-Site` confirms the site the token already determines.
#: An inventory that printed either would put a credential the config was not allowed to
#: hold into the export, so a table carrying one is dropped whole.
RESERVED_SINK_HEADERS: frozenset[str] = frozenset({"authorization", "x-gateclerk-site"})


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
    """Extract ONLY the hostname from `raw_host`, stripping any userinfo/scheme/port/path."""
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
    """Sanitize a `push_target` or sink `url`, stripping userinfo, query and fragment."""
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
    """Sanitize a non-secret identifier (`name`, `device_code`, `serial`, `isapi_user`)."""
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
    if (
        len(text) >= 24
        and re.match(r"^[A-Za-z0-9]+$", text)
        and any(c.islower() for c in text)
        and any(c.isupper() for c in text)
        and any(c.isdigit() for c in text)
    ):
        return default, [key_label]
    return text, []


def _safe_recipient(raw: object) -> tuple[str, list[str]]:
    """One mail address: text with `@`, no whitespace, no secret-shaped value.

    The `mnotify` alert sink's only routing field. A malformed recipient is dropped and
    counted rather than projected as if the site had a working alert route — the export is
    what an operator signs off on before a cutover.
    """
    if raw is None:
        return "", []
    if not isinstance(raw, str) or raw.count("@") != 1 or any(c.isspace() for c in raw):
        return "", ["sink.to"]
    text = raw.strip()
    return ("", ["sink.to"]) if redact_b64(text) != text else (text, [])


def _safe_headers(raw: object) -> tuple[str, list[str]]:
    """Sorted `k=v` pairs for inventory; a credential-carrying table is dropped whole.

    A header value is config, not a secret — except under the two names `RESERVED_SINK_HEADERS`
    lists, which is exactly why `sinks.py` refuses them in a config. Both the reserved name
    and the secret-shape check drop the WHOLE table: a partial header set in the inventory
    would be a second kind of lie.
    """
    if raw is None:
        return "", []
    if not isinstance(raw, dict):
        return "", ["sink.headers"]
    pairs: list[str] = []
    for key, value in sorted(raw.items(), key=lambda item: str(item[0])):
        if not isinstance(key, str) or not isinstance(value, str):
            return "", ["sink.headers"]
        if any(c in key + value for c in "\r\n"):
            return "", ["sink.headers"]
        if key.strip().lower() in RESERVED_SINK_HEADERS:
            return "", ["sink.headers"]
        if redact_b64(value) != value:
            return "", ["sink.headers"]
        pairs.append(f"{key}={value}")
    return ";".join(pairs), []


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
    if sink_type not in ("https", "csv", "jsonl", "mnotify", ""):
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

    # The four remaining `SinkSpec` fields: the alert route (`to`, `timeout_s`), the
    # roster opt-out (`accepts_roster`) and the extra request headers. Every one of them
    # was previously reported as an unknown key, which hid the site's alert route.
    to, d_to = _safe_recipient(raw_sink.get("to"))
    dropped.extend(d_to)

    timeout_raw = raw_sink.get("timeout_s")
    timeout_ok = (
        isinstance(timeout_raw, (int, float))
        and not isinstance(timeout_raw, bool)
        and timeout_raw > 0
    )
    timeout_s = timeout_raw if timeout_ok else None
    if timeout_raw is not None and not timeout_ok:
        dropped.append("sink.timeout_s")

    accepts_raw = raw_sink.get("accepts_roster", True)
    accepts_roster = accepts_raw if isinstance(accepts_raw, bool) else True
    if not isinstance(accepts_raw, bool):
        dropped.append("sink.accepts_roster")

    headers, d_headers = _safe_headers(raw_sink.get("headers"))
    dropped.extend(d_headers)

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
            "to": to,
            "timeout_s": timeout_s,
            "headers": headers,
            "accepts_roster": accepts_roster,
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
    """Run the config export and return `(stdout_payload, stderr_summary)`."""
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


# ---------------------------------------------------------------------------
# `gateclerk export scans` (card t_5a0f39b2)
# ---------------------------------------------------------------------------

_REDACTED_RAW_KEYS: frozenset[str] = frozenset(
    {"employeeNoString", "employeeNo", "employee_no", "cardNo", "card_no", "name"}
)


def _redact_raw_dict(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _redact_raw_dict(v) for k, v in obj.items() if k not in _REDACTED_RAW_KEYS}
    if isinstance(obj, list):
        return [_redact_raw_dict(item) for item in obj]
    return obj


def _extract_card_no(raw_json: str) -> str:
    if not raw_json:
        return ""
    try:
        parsed = json.loads(raw_json)
    except ValueError:
        return ""
    if not isinstance(parsed, Mapping):
        return ""
    for candidate in (
        parsed.get("cardNo"),
        parsed.get("card_no"),
        (parsed.get("AcsEvent") or {}).get("cardNo")
        if isinstance(parsed.get("AcsEvent"), Mapping)
        else None,
    ):
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
        if isinstance(candidate, int) and not isinstance(candidate, bool):
            return str(candidate)
    return ""


def resolve_scan_store_path(
    *,
    config_path: Path | str = cfg.DEFAULT_SITES_FILE,
    site: str | None = None,
    state_root: Path | str | None = None,
    db_path: Path | str | None = None,
) -> tuple[str | None, str, Path]:
    """Resolve `(site_name, site_tz, db_file)` for `gateclerk export scans`.

    Rules (card t_5a0f39b2):
      * If `db_path` is explicitly given, use it directly.
      * Otherwise read `sites.toml`:
          - if `> 1` site is configured and `--site` is omitted, refuse (`--site` is
            required when more than one site is configured);
          - if `== 1` site is configured and `--site` is omitted, use that single site;
          - if `--site` is given, look up that site in `sites.toml` (or, if `sites.toml`
            is absent and `state_root` is given, derive `<state_root>/gateclerk-<site>.sqlite3`).
    """
    if db_path is not None:
        resolved = Path(db_path)
        if not resolved.is_file():
            raise ConfigError(f"scan store database {resolved} not found.")
        return site, DEFAULT_SITE_TZ, resolved

    cfg_file = Path(config_path)
    if cfg_file.is_file():
        sites = cfg.load_sites(cfg_file, surface="cli")
        if site is None:
            if len(sites) == 0:
                raise ConfigError(f"no [[site]] blocks configured in {cfg_file}.")
            if len(sites) > 1:
                known = ", ".join(sorted(sites))
                raise ConfigError(
                    f"--site is required when more than one site is configured in {cfg_file} "
                    f"(configured: {known})."
                )
            site_cfg = next(iter(sites.values()))
        else:
            site_cfg = cfg.find_site(sites, site)
        raw_db = Path(site_cfg.db_path_resolved)
        resolved = (
            (Path(state_root) / raw_db)
            if (state_root is not None and not raw_db.is_absolute())
            else raw_db
        )
        if not resolved.is_file():
            raise ConfigError(
                f"scan store database {resolved} not found for site {site_cfg.name!r}."
            )
        return site_cfg.name, site_cfg.iana_tz or DEFAULT_SITE_TZ, resolved

    if site is not None:
        rel = Path(cfg.DEFAULT_DB_PATH_TEMPLATE.format(site=site))
        resolved = (Path(state_root) / rel) if state_root is not None else rel
        if resolved.is_file():
            return site, DEFAULT_SITE_TZ, resolved
        raise ConfigError(
            f"sites file {cfg_file} not found and scan store {resolved} does not exist."
        )

    raise ConfigError(f"sites file {cfg_file} not found (pass --config or --site).")


def _open_scan_cursor(conn: sqlite3.Connection, sql: str, params: Sequence[Any]) -> sqlite3.Cursor:
    """Seam for tests to wrap the SQLite cursor and verify chunked `fetchmany` streaming."""
    return conn.execute(sql, tuple(params))


def _iter_scan_chunks(
    cursor: sqlite3.Cursor, *, chunk_size: int | None = None
) -> Iterator[Sequence[sqlite3.Row]]:
    size = SCAN_EXPORT_CHUNK_SIZE if chunk_size is None else chunk_size
    if size <= 0:
        size = 1
    while True:
        batch = cursor.fetchmany(size)
        if not batch:
            break
        yield batch


def _format_bool_cell(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int):
        return "true" if val != 0 else "false"
    return str(val)


_BOOL_SCAN_COLS: frozenset[str] = frozenset(
    {
        "tz_unresolved",
        "tz_ambiguous",
        "tz_nonexistent",
        "tz_offset_mismatch",
        "unknown_code",
        "encrypted_person_data",
    }
)


def _scan_row_to_csv_cells(row: sqlite3.Row, *, columns: Sequence[str], redact: bool) -> list[str]:
    raw_text = str(row["raw"] or "{}")
    if redact:
        try:
            raw_text = json.dumps(
                _redact_raw_dict(json.loads(raw_text)),
                ensure_ascii=False,
                separators=(",", ":"),
            )
        except ValueError:
            raw_text = "{}"
    card_no = "" if redact else _extract_card_no(raw_text)
    cells: list[str] = []
    for col in columns:
        if col == "cardNo":
            cells.append(card_no)
        elif col == "raw":
            cells.append(raw_text)
        elif col in _BOOL_SCAN_COLS:
            cells.append(_format_bool_cell(row[col]))
        else:
            val = row[col]
            cells.append("" if val is None else str(val))
    return cells


def _scan_row_to_jsonl_line(row: sqlite3.Row, *, redact: bool) -> str:
    raw_line = str(row["jsonl"] or "").strip()
    if not redact:
        return raw_line
    try:
        payload = json.loads(raw_line)
    except ValueError:
        payload = {}
    if isinstance(payload, dict):
        for k in ("employee_no", "employeeNo", "employeeNoString", "cardNo", "card_no", "name"):
            payload.pop(k, None)
        if "raw" in payload:
            payload["raw"] = _redact_raw_dict(payload["raw"])
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def export_scans_stream(
    *,
    config_path: Path | str = cfg.DEFAULT_SITES_FILE,
    site: str | None = None,
    state_root: Path | str | None = None,
    db_path: Path | str | None = None,
    device: str | None = None,
    employee: str | None = None,
    since: str | None = None,
    until: str | None = None,
    direction: str = "any",
    fmt: str = "csv",
    output_path: Path | str | None = None,
    bom: bool = False,
    redact: bool = False,
    is_tty: bool | None = None,
    dest_stream: TextIO | None = None,
) -> tuple[int, str]:
    """Stream filtered scans from the local SQLite store to `output_path` or `dest_stream`.

    Returns `(row_count, stderr_message)`. Never calls `fetchall()` and never materializes
    the result set into a list.
    """
    tty = _stdout_is_tty() if is_tty is None else is_tty
    if output_path is None and tty:
        raise ConfigError(
            "stdout is a TTY: attendance scans are personal data — pass --output <path> "
            "(or -o <path>) to write to a file, or pipe stdout (never invents a file path)."
        )

    norm_fmt = fmt.strip().lower()
    if norm_fmt == "json":
        norm_fmt = "jsonl"
    if norm_fmt not in EXPORT_FORMATS:
        raise ConfigError(
            f"unsupported export format {fmt!r} (expected one of: {', '.join(EXPORT_FORMATS)})"
        )

    norm_dir = direction.strip().lower()
    if norm_dir not in DIRECTION_CHOICES:
        raise ConfigError(f"invalid --direction {direction!r} (expected one of: in, out, any)")

    resolved_site, site_tz, resolved_db = resolve_scan_store_path(
        config_path=config_path, site=site, state_root=state_root, db_path=db_path
    )

    since_utc: str | None = None
    until_utc: str | None = None
    if since is not None:
        since_dt = parse_user_timestamp(since, site_tz=site_tz, field_name="--since").value
        since_utc = since_dt.astimezone(UTC).isoformat()
    if until is not None:
        # Bare date YYYY-MM-DD for --until covers the full local day (23:59:59.999999)
        until_text = until.strip()
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", until_text):
            until_text = f"{until_text}T23:59:59.999999"
        until_dt = parse_user_timestamp(until_text, site_tz=site_tz, field_name="--until").value
        until_utc = until_dt.astimezone(UTC).isoformat()
    if since_utc is not None and until_utc is not None and since_utc > until_utc:
        raise EventBoundsError(
            f"--since ({since!r}) is after --until ({until!r}) — empty or inverted window"
        )

    site_filter = resolved_site or None
    device_filter = device.strip() if (device is not None and device.strip()) else None
    emp_filter = employee.strip() if (employee is not None and employee.strip()) else None
    dir_filter = None if norm_dir == "any" else norm_dir

    sql = (
        "SELECT id, jsonl, site, device_serial, serial_no, employee_no, name, "
        "event_time_utc, event_time_local, tz_offset_min, tz_offset_min_device, "
        "tz_source, iana_tz, tz_unresolved, tz_ambiguous, tz_nonexistent, "
        "tz_reason, tz_offset_mismatch, direction, attendance_status, "
        "direction_source, verify_mode, major, minor, outcome, unknown_code, "
        "encrypted_person_data, raw, captured_at "
        "FROM events "
        "WHERE (? IS NULL OR site = ?) "
        "AND (? IS NULL OR device_serial = ?) "
        "AND (? IS NULL OR employee_no = ?) "
        "AND (? IS NULL OR event_time_utc >= ?) "
        "AND (? IS NULL OR event_time_utc <= ?) "
        "AND (? IS NULL OR direction = ?) "
        "ORDER BY event_time_utc ASC, serial_no ASC, id ASC"
    )
    params: list[Any] = [
        site_filter,
        site_filter,
        device_filter,
        device_filter,
        emp_filter,
        emp_filter,
        since_utc,
        since_utc,
        until_utc,
        until_utc,
        dir_filter,
        dir_filter,
    ]

    columns = SCAN_EXPORT_REDACTED_COLUMNS if redact else SCAN_EXPORT_COLUMNS

    def _stream_into(writer_stream: TextIO) -> int:
        count = 0
        if norm_fmt == "csv" and bom:
            writer_stream.write("\ufeff")
        csv_writer = csv.writer(writer_stream, lineterminator="\n") if norm_fmt == "csv" else None
        if csv_writer is not None:
            csv_writer.writerow(columns)

        conn = sqlite3.connect(str(resolved_db))
        conn.row_factory = sqlite3.Row
        try:
            cursor = _open_scan_cursor(conn, sql, params)
            for batch in _iter_scan_chunks(cursor):
                if csv_writer is not None:
                    for row in batch:
                        csv_writer.writerow(
                            _scan_row_to_csv_cells(row, columns=columns, redact=redact)
                        )
                        count += 1
                else:
                    chunk_lines = [_scan_row_to_jsonl_line(row, redact=redact) for row in batch]
                    writer_stream.write("\n".join(chunk_lines) + "\n")
                    count += len(batch)
                writer_stream.flush()
        finally:
            conn.close()
        return count

    if output_path is not None:
        out_file = Path(output_path)
        try:
            out_file.parent.mkdir(parents=True, exist_ok=True)
            with out_file.open("w", encoding="utf-8", newline="") as fh:
                total = _stream_into(fh)
        except OSError as exc:
            raise ConfigError(
                f"cannot write scan export file {out_file}: {exc.strerror or exc}"
            ) from exc
        return total, f"wrote {total} scan row(s) to {out_file}"

    target_stream = sys.stdout if dest_stream is None else dest_stream
    total = _stream_into(target_stream)
    return total, ""


# --- `gateclerk export non-punches` (GC-P20 / E22) -------------------------------------------

#: The whole column set of the non-punch report — one name, and that is the design.
#:
#: `fingerprint_hash` is the key BC dedupes on (`model.fingerprint_key_hash`: the
#: `(employee_no, event_time_local, minor)` guard), so it is emitted VERBATIM; a second hash
#: would join to nothing on the other side. Every other column `events` has stays behind:
#: `employee_no`, `name` and `raw` are punch data BC already holds, and a diagnostics file
#: carrying them is a second, un-governed copy of them (R1: BC remains the store — this report
#: is a repair input for BC-P30, not a second record).
NON_PUNCH_EXPORT_COLUMNS: tuple[str, ...] = ("fingerprint",)

#: Ledger ids staged per `executemany`. The ledger is append-only and gains a line per pushed
#: event (GC-P16a), so a year of backlog is a year of ids: the insert cannot assume they all
#: fit in one statement.
_PUSHED_ID_CHUNK_ROWS = 1000

#: One `?` per non-auth verify mode — the modes themselves travel as bound parameters and are
#: typed exactly once, in `event_codes` (the same shape `agent_cli._PUNCH_CANDIDATE_SQL` uses).
_NON_PUNCH_MODE_MARKS = ", ".join("?" for _ in sorted(NON_AUTH_VERIFY_MODES))

#: GC-P01's punch rule read from the other side (E22): a scan that reached BC and was NOT a
#: granted authentication pass is what BC-P30 has to mark ignored.
#:
#: `COALESCE(<arms>, 0) = 0` rather than the plain `NOT (...)`, and the difference is
#: three-valued logic: with a bare NOT, a row whose `major`, `outcome` or `unknown_code` is
#: NULL makes the arm UNKNOWN, `NOT UNKNOWN` is UNKNOWN, and the row silently disappears from
#: the one report whose job is to name everything BC was handed. NULL in any punch arm means
#: "not provably a punch", which is a non-punch and belongs on the list — and it is also
#: exactly what the queue does with that row, since `_PUNCH_CANDIDATE_SQL` needs the arms TRUE
#: to queue it. Report and queue therefore stay complementary for EVERY row, NULLs included.
#: Pinned from both sides by
#: `tests/test_gc_p20_non_punch_report.py::test_report_is_the_complement_of_the_queue_rule`.
#:
#: Not an injection surface: the only interpolated text is `_NON_PUNCH_MODE_MARKS`, built once
#: at import from the frozen `NON_AUTH_VERIFY_MODES`; no caller-supplied value reaches the
#: query text (S608 reads the statement's text and cannot see that).
_NON_PUNCH_FINGERPRINT_SQL = f"""
SELECT DISTINCT fingerprint_hash
  FROM events
 WHERE id IN (SELECT event_id FROM temp.pushed_events)
   AND COALESCE(
         major = 5 AND outcome = 'granted' AND unknown_code = 0
     AND employee_no IS NOT NULL AND employee_no <> ''
     AND verify_mode IS NOT NULL
     AND lower(trim(verify_mode)) NOT IN ({_NON_PUNCH_MODE_MARKS})
   , 0) = 0
 ORDER BY fingerprint_hash
"""  # noqa: S608 - static query text; the only interpolation is the import-time placeholder list


def _open_read_only_store(db_path: Path | str) -> sqlite3.Connection:
    """The store, opened so that writing it is impossible rather than merely unintended.

    `mode=ro` rather than `PRAGMA query_only`, measured on this fleet's SQLite 3.50:
    `query_only` refuses TEMP tables too, and the ledger ids have to land in a TEMP table for
    the report to stay one streaming SELECT (the same trick `PushLedger.apply_exclusion` uses,
    for the same reason). A read-only URI keeps both halves: `UPDATE`/`DELETE` against the
    store raise `OperationalError`, `CREATE TEMP TABLE` / `INSERT` succeed — the temp database
    is not the store. And the store FILE is provably untouched: mtime, size and checksum all
    unmoved (`test_report_reads_the_store_without_writing`).

    What is NOT claimed: a WAL-mode store still grows its `-wal`/`-shm` sidecars while any
    reader is open, and a read-only one leaves them behind at close (measured: a 0-byte `-wal`
    and a 32 KiB `-shm`, neither carrying a committed byte of the store). A read-write reader
    would checkpoint them away and rewrite the store file in the process — which is precisely
    the incidental write this guard exists to refuse.

    The URI comes from `Path.as_uri()`, which percent-encodes `#`, `?`, `%` and spaces.
    Hand-concatenating the path would let one of those characters retarget the open silently
    (to another file, or to none) instead of failing loudly.
    """
    uri = f"{Path(db_path).resolve().as_uri()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


def _create_pushed_events_table(conn: sqlite3.Connection) -> None:
    """Empty TEMP holder for the ledger ids. It dies with this connection and never touches disk."""
    conn.execute("DROP TABLE IF EXISTS temp.pushed_events")
    conn.execute("CREATE TABLE temp.pushed_events (event_id INTEGER NOT NULL PRIMARY KEY)")


def _insert_pushed_event_ids_one_at_a_time(
    conn: sqlite3.Connection, chunk: Sequence[tuple[int, ...]]
) -> None:
    """The bounded fallback: one INSERT per row, inside one transaction.

    A transaction that writes only TEMP tables is legal on a read-only store connection
    (measured: BEGIN/COMMIT both succeed), and it keeps a 100-row chunk from becoming 100
    commits.
    """
    conn.execute("BEGIN")
    try:
        for row in chunk:
            conn.execute("INSERT OR IGNORE INTO temp.pushed_events VALUES (?)", row)
        conn.execute("COMMIT")
    except sqlite3.Error:
        conn.execute("ROLLBACK")
        raise


def _insert_pushed_event_ids(conn: sqlite3.Connection, event_ids: Sequence[int]) -> None:
    """Stage the ledger's ids into the TEMP table, in chunks, with a bounded fallback.

    Chunked because the ledger is unbounded by design. The fallback is for the one failure
    worth absorbing: a SQLite built with a small `SQLITE_MAX_VARIABLE_NUMBER` reporting the
    parameter limit. Any other `OperationalError` — a locked or corrupt file — is re-raised,
    because quietly switching to one-row-at-a-time would turn a real fault into a slow hang and
    hide the reason from the operator.
    """
    rows: list[tuple[int, ...]] = [(int(event_id),) for event_id in event_ids]
    for start in range(0, len(rows), _PUSHED_ID_CHUNK_ROWS):
        chunk = rows[start : start + _PUSHED_ID_CHUNK_ROWS]
        try:
            conn.executemany("INSERT OR IGNORE INTO temp.pushed_events VALUES (?)", chunk)
        except sqlite3.OperationalError as exc:
            if "parameter" not in str(exc).lower():
                raise
            _insert_pushed_event_ids_one_at_a_time(conn, chunk)


def _open_non_punch_cursor(conn: sqlite3.Connection, event_ids: Sequence[int]) -> sqlite3.Cursor:
    """Seam: the one statement of the report, with the ledger ids staged first.

    Separate for the same reason `_open_scan_cursor` is — a test can watch the real statement
    rather than a paraphrase of it.
    """
    _create_pushed_events_table(conn)
    _insert_pushed_event_ids(conn, event_ids)
    return conn.execute(_NON_PUNCH_FINGERPRINT_SQL, tuple(sorted(NON_AUTH_VERIFY_MODES)))


def export_non_punch_fingerprints(
    *,
    config_path: Path | str = cfg.DEFAULT_SITES_FILE,
    site: str | None = None,
    state_root: Path | str | None = None,
    fmt: str = "csv",
    output_path: Path | str | None = None,
    dest_stream: TextIO | None = None,
    is_tty: bool | None = None,
) -> tuple[int, str]:
    """Write DISTINCT fingerprints of pushed non-punch events; no PII columns.

    Answers one operator question — "which scans did this poller already hand to BC that were
    never granted punches?" — so BC-P30 can mark them ignored and recalculate. Everything
    comes from the local store; nothing is written anywhere (`_open_read_only_store` makes that
    structural, not a promise) and BC is never contacted: R1, BC remains the store.

    Two inputs decide the answer, and only those two:

    * the poller's own ledger (`PushLedger.sent_event_ids`, across every endpoint and sink,
      `gone` counting as pushed) — an event the ledger does not name is not known to have left
      the building, so it is not in the report. A missing ledger is therefore NOT "nothing was
      a punch" and NOT an error: it is "(0, here is why nothing is known)", exit 0.
    * the punch rule, negated (`_NON_PUNCH_FINGERPRINT_SQL`) — granted major-5 passes by a
      named employee with a real verify mode are punches and stay out.

    Streaming like `export scans` (`fetchmany` chunks, never `fetchall`). The TTY rule is the
    same rule with a different reason: `export scans` refuses an interactive terminal because
    scans are personal data; this report has none, and still refuses, because a repair input
    meant for another system belongs in a file and this command never invents a path.
    """
    tty = _stdout_is_tty() if is_tty is None else is_tty
    if output_path is None and tty:
        raise ConfigError(
            "stdout is a TTY: this report feeds BC-P30 — pass --output <path> (or -o <path>) "
            "to write it to a file, or pipe stdout (never invents a file path)."
        )

    norm_fmt = fmt.strip().lower()
    if norm_fmt == "json":
        norm_fmt = "jsonl"
    if norm_fmt not in EXPORT_FORMATS:
        raise ConfigError(
            f"unsupported export format {fmt!r} (expected one of: {', '.join(EXPORT_FORMATS)})"
        )

    # Local import: `agent_cli` pulls in the transport/poller stack, and this export needs two
    # names from it — the ledger's file name and the one accessor that answers "already
    # pushed?". Same precedent as agent_cli's own `make_console` import.
    from gateclerk import agent_cli

    _site, _site_tz, resolved_db = resolve_scan_store_path(
        config_path=config_path, site=site, state_root=state_root
    )
    ledger_path = Path(resolved_db).parent / agent_cli.PUSH_LEDGER_FILE_NAME
    if not ledger_path.is_file():
        # Not a failure: a site that has never pushed simply has nothing to account for.
        return (
            0,
            f"no {agent_cli.PUSH_LEDGER_FILE_NAME} at {ledger_path.parent}; "
            "nothing is known to be pushed",
        )
    event_ids = sorted(agent_cli.PushLedger(ledger_path).sent_event_ids())

    def _stream_into(writer_stream: TextIO) -> int:
        count = 0
        csv_writer = csv.writer(writer_stream, lineterminator="\n") if norm_fmt == "csv" else None
        if csv_writer is not None:
            csv_writer.writerow(NON_PUNCH_EXPORT_COLUMNS)
        conn = _open_read_only_store(resolved_db)
        try:
            cursor = _open_non_punch_cursor(conn, event_ids)
            for batch in _iter_scan_chunks(cursor):
                if csv_writer is not None:
                    for row in batch:
                        csv_writer.writerow((row["fingerprint_hash"],))
                        count += 1
                else:
                    lines = [
                        json.dumps(
                            {"fingerprint": row["fingerprint_hash"]},
                            ensure_ascii=False,
                            separators=(",", ":"),
                        )
                        for row in batch
                    ]
                    writer_stream.write("\n".join(lines) + "\n")
                    count += len(batch)
                writer_stream.flush()
        finally:
            conn.close()
        return count

    if output_path is not None:
        out_file = Path(output_path)
        try:
            out_file.parent.mkdir(parents=True, exist_ok=True)
            with out_file.open("w", encoding="utf-8", newline="") as fh:
                total = _stream_into(fh)
        except OSError as exc:
            raise ConfigError(
                f"cannot write non-punch report file {out_file}: {exc.strerror or exc}"
            ) from exc
        return total, f"wrote {total} fingerprint(s) to {out_file}"

    target_stream = sys.stdout if dest_stream is None else dest_stream
    total = _stream_into(target_stream)
    return total, ""
