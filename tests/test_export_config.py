"""Tests for `gateclerk export config` (card t_7b62b44c, EXPORT-CONFIG).

Verifies:
1. `sites.toml` projected to CSV and JSONL with the exact `CONFIG_EXPORT_COLUMNS` allowlist.
2. NEVER secrets: a fixture `sites.toml` carrying plaintext passwords, bearer tokens,
   userinfo credentials in `host`/`push_target`/sink `url`, query-string tokens, and
   secret-shaped strings stuffed into `token_env`/`token_keychain` never leaks a single
   secret byte to stdout, stderr, or `--output` file.
3. Reference names (`device_cred_keychain_service`, `device_cred_env_var`,
   `device_cred_ref`, `ingest_token_keychain_service`, `ingest_token_env_var`, and sink
   `token_env`/`token_keychain`) DO appear in the output.
4. `dropped_keys` stderr summary counts and lists every dropped key (deny-by-default).
5. TTY refusal: when stdout is a TTY and `--output` is omitted, exits 2 without writing any
   file; with `--output <path>`, writes only to `<path>` and reports path + count +
   `dropped_keys` on stderr.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from gateclerk import export_cli
from gateclerk.cli import CONFIG_ERROR_EXIT, app
from gateclerk.export_cli import CONFIG_EXPORT_COLUMNS

runner = CliRunner()

PLANTED_SECRETS: tuple[str, ...] = (
    "fake-device-secret-9911",
    "secret-bearer-token-8822",
    "fake-url-user-pass-7733",
    "secret-query-token-6644",
    "fake-sink-header-secret-5566",
    "dGhpcyBpcyBhIHNlY3JldCBiYXNlNjQgdG9rZW4=",
    "Ab9Xz2Kp7Qm4Rt8Wn3Yj6Vc1Lf5Hg0Ds",
)

DIRTY_SITES_TOML = """\
top_secret_global = "fake-device-secret-9911"

[[site]]
name = "demo-a"
enabled = true
host = "http://admin:fake-url-user-pass-7733@192.0.2.10:8080/isapi"
port = 80
isapi_user = "admin"
device_code = "DEMO-A-1"
serial = "DEMO-SN-001"
iana_tz = "Europe/Bucharest"
device_tz = "Europe/Bucharest"
timeout_s = 30.0
page_delay_ms = 100
cadence_s = 300
overlap_s = 300
push_dead_letter_after_s = 86400
db_warn_bytes = 2147483648
keychain_service = "gateclerk-hikvision"
password = "fake-device-secret-9911"
api_token = "secret-bearer-token-8822"

[[site.sink]]
name = "cloud"
type = "https"
url = "https://ingest:fake-url-user-pass-7733@ingest.example.invalid/v1/push?token=secret-query-token-6644#frag"
token_env = "GATECLERK_INGEST_TOKEN_DEMO_A"
token_keychain = "gateclerk-ingest-demo-a"
enabled = true
token = "secret-bearer-token-8822"
headers = { Authorization = "Bearer fake-sink-header-secret-5566" }

[[site.sink]]
name = "badref"
type = "https"
url = "https://ingest.example.invalid/v2/push"
token_env = "dGhpcyBpcyBhIHNlY3JldCBiYXNlNjQgdG9rZW4="
token_keychain = "Ab9Xz2Kp7Qm4Rt8Wn3Yj6Vc1Lf5Hg0Ds"
enabled = false

[[site]]
name = "demo-b"
enabled = false
host = "192.0.2.20"
device_code = "DEMO-B-1"
serials = ["DEMO-SN-002", "DEMO-SN-003"]
iana_tz = "Europe/Bucharest"
push_target = "https://admin:fake-url-user-pass-7733@ingest.example.invalid/legacy?secret=secret-query-token-6644"
"""


def test_secrets_never_appear_in_csv_or_jsonl_output_and_refs_do(tmp_path: Path) -> None:
    cfg_file = tmp_path / "sites.toml"
    cfg_file.write_text(DIRTY_SITES_TOML, encoding="utf-8")

    for fmt in ("csv", "jsonl"):
        res = runner.invoke(
            app,
            ["export", "config", "--config", str(cfg_file), "--format", fmt],
        )
        assert res.exit_code == 0, res.output
        combined = res.output + (getattr(res, "stderr", "") or "")
        for secret in PLANTED_SECRETS:
            assert secret not in combined, f"planted secret {secret!r} leaked in {fmt} output"

        # Reference names and sanitized hosts MUST appear.
        assert "gateclerk-hikvision" in res.stdout
        assert "GATECLERK_192_0_2_10_PASSWORD" in res.stdout
        assert "gateclerk-demo-a-192.0.2.10" in res.stdout
        assert "GATECLERK_INGEST_TOKEN_DEMO_A" in res.stdout
        assert "gateclerk-ingest-demo-a" in res.stdout
        assert "192.0.2.10" in res.stdout
        assert "DEMO-A-1" in res.stdout
        assert "DEMO-SN-001" in res.stdout


def test_csv_header_and_jsonl_columns_match_hard_allowlist(tmp_path: Path) -> None:
    cfg_file = tmp_path / "sites.toml"
    cfg_file.write_text(DIRTY_SITES_TOML, encoding="utf-8")

    csv_res = runner.invoke(app, ["export", "config", "--config", str(cfg_file), "--format", "csv"])
    assert csv_res.exit_code == 0, csv_res.output
    csv_lines = [
        line for line in csv_res.stdout.splitlines() if not line.startswith("dropped_keys:")
    ]
    reader = list(csv.reader(io.StringIO("\n".join(csv_lines))))
    assert tuple(reader[0]) == CONFIG_EXPORT_COLUMNS
    assert len(reader) == 3  # header + 2 sites

    row_a = dict(zip(reader[0], reader[1], strict=True))
    assert row_a["site"] == "demo-a"
    assert row_a["enabled"] == "true"
    assert row_a["host"] == "192.0.2.10"
    assert row_a["device_code"] == "DEMO-A-1"
    assert row_a["serial"] == "DEMO-SN-001"
    assert row_a["device_cred_keychain_service"] == "gateclerk-hikvision"
    assert row_a["device_cred_env_var"] == "GATECLERK_192_0_2_10_PASSWORD"
    assert row_a["device_cred_ref"] == "gateclerk-demo-a-192.0.2.10"

    jsonl_res = runner.invoke(
        app, ["export", "config", "--config", str(cfg_file), "--format", "jsonl"]
    )
    assert jsonl_res.exit_code == 0, jsonl_res.output
    json_lines = [
        json.loads(line) for line in jsonl_res.stdout.splitlines() if line.strip().startswith("{")
    ]
    assert len(json_lines) == 2
    for obj in json_lines:
        assert tuple(obj.keys()) == CONFIG_EXPORT_COLUMNS
    assert json_lines[0]["sinks"][0]["url"] == "https://ingest.example.invalid/v1/push"
    assert json_lines[1]["push_target"] == "https://ingest.example.invalid/legacy"
    assert json_lines[1]["serial"] == "DEMO-SN-002,DEMO-SN-003"
    assert json_lines[1]["enabled"] is False


def test_dropped_keys_summary_counts_and_names_every_dropped_key(tmp_path: Path) -> None:
    raw = DIRTY_SITES_TOML.encode("utf-8")
    result = export_cli.project_sites_toml(raw, origin="sites.toml")
    assert result.dropped_count == 12
    assert set(result.dropped_keys) == {
        "top_secret_global",
        "site.api_token",
        "site.password",
        "site.host.userinfo",
        "sink.headers",
        "sink.token",
        "sink.url.userinfo",
        "sink.url.query",
        "sink.token_env",
        "sink.token_keychain",
        "site.push_target.userinfo",
        "site.push_target.query",
    }
    summary = export_cli.format_dropped_keys_summary(result.dropped_keys)
    assert summary.startswith("dropped_keys: 12 (")
    for secret in PLANTED_SECRETS:
        assert secret not in summary


def test_tty_refuses_without_output_and_output_writes_file_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg_file = tmp_path / "sites.toml"
    cfg_file.write_text(DIRTY_SITES_TOML, encoding="utf-8")
    out_file = tmp_path / "export" / "inventory.csv"

    monkeypatch.setattr(export_cli, "_stdout_is_tty", lambda: True)

    refused = runner.invoke(app, ["export", "config", "--config", str(cfg_file)])
    assert refused.exit_code == CONFIG_ERROR_EXIT
    assert "TTY" in refused.output
    assert not out_file.exists()

    ok = runner.invoke(
        app,
        [
            "export",
            "config",
            "--config",
            str(cfg_file),
            "--output",
            str(out_file),
            "--site",
            "demo-a",
            "--bom",
        ],
    )
    assert ok.exit_code == 0, ok.output
    raw_bytes = out_file.read_bytes()
    assert raw_bytes.startswith(b"\xef\xbb\xbfsite,enabled,")
    for secret in PLANTED_SECRETS:
        assert secret.encode("utf-8") not in raw_bytes
    assert "wrote 1 row(s)" in ok.output
    assert "dropped_keys: 10" in ok.output
