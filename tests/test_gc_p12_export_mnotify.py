"""GC-P12 — `export config` keeps `mnotify` sinks and the valid `SinkSpec` keys.

`gateclerk export config` is the sanitized inventory an operator reads before a cutover.
Before this card it projected `type = "mnotify"` to `""` and named `to`, `timeout_s`,
`headers` and `accepts_roster` — all real `SinkSpec` fields the registry parses — as
`dropped_unknown_keys`, so the export lied about the site's alert route.

Pinned here:

1. `type = "mnotify"` survives, `to` / `timeout_s` / `accepts_roster` are projected and
   nothing is dropped.
2. `headers`, `accepts_roster` and `timeout_s` on an https sink are not dropped either.
3. An invalid value is dropped AND counted, never silently accepted.
4. Headers render as sorted `k=v` pairs (deterministic, diffable inventory).
5. Nothing secret is printed: a credential-shaped header value and the transport's own
   reserved header names are dropped instead of rendered — `sinks.py` refuses an
   `Authorization` header at parse time precisely because it holds a bearer, so the
   inventory must not print one either.

The allowlist stays deny-by-default: a sink key no `SinkSpec` field backs is still
reported as dropped.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from gateclerk import export_cli
from gateclerk.cli import app

runner = CliRunner()

#: Shape of a bearer/credential value (the same rule `_safe_scalar_ident` applies).
CRED_SHAPED = "Ab9Xz2Kp7Qm4Rt8Wn3Yj6Vc1Lf5Hg0Ds"
BASE64_SHAPED = "dGhpcyBpcyBhIHNlY3JldCBiYXNlNjQgdG9rZW4="

MNOTIFY_TOML = """\
[[site]]
name = "demo-a"
host = "192.0.2.10"
iana_tz = "Europe/Bucharest"

[[site.sink]]
name = "alerts"
type = "mnotify"
to = "alerts@example.invalid"
timeout_s = 300
accepts_roster = false
"""

HTTPS_KEYS_TOML = """\
[[site]]
name = "demo-b"
host = "192.0.2.11"
iana_tz = "Europe/Bucharest"

[[site.sink]]
name = "cloud"
type = "https"
url = "https://ingest.example.invalid/v1/push"
token_env = "GATECLERK_INGEST_TOKEN_DEMO_B"
token_keychain = "gateclerk-ingest-demo-b"
headers = { X-Trace = "on", X-Dept = "ops-floor-3" }
accepts_roster = false
timeout_s = 45
"""

GOOD_HEADERS_LINE = 'headers = { X-Trace = "on", X-Dept = "ops-floor-3" }'

SECRET_TOML = f"""\
[[site]]
name = "demo-a"
host = "192.0.2.10"
iana_tz = "Europe/Bucharest"

[[site.sink]]
name = "alerts"
type = "mnotify"
to = "alerts@example.invalid"
timeout_s = 300

[[site.sink]]
name = "cloud"
type = "https"
url = "https://ingest.example.invalid/v1/push"
headers = {{ X-Dept = "ops-floor-3" }}

[[site.sink]]
name = "leaky"
type = "https"
url = "https://ingest.example.invalid/v2/push"
headers = {{ Authorization = "Bearer {CRED_SHAPED}" }}

[[site.sink]]
name = "b64"
type = "https"
url = "https://ingest.example.invalid/v3/push"
headers = {{ X-Trace-Ref = "{BASE64_SHAPED}" }}
"""


def _project(text: str) -> export_cli.ConfigExportResult:
    return export_cli.project_sites_toml(text.encode("utf-8"), origin="sites.toml")


def _sink(result: export_cli.ConfigExportResult, name: str) -> dict[str, object]:
    for row in result.rows:
        for sink in row["sinks"]:
            if sink["name"] == name:
                return sink
    raise AssertionError(f"sink {name!r} missing from {[r['sinks'] for r in result.rows]}")


def test_mnotify_sink_type_survives_config_export() -> None:
    """The card's VERIFY block: the alert route must be readable from the inventory."""
    result = _project(MNOTIFY_TOML)
    assert result.dropped_keys == ()
    sink = _sink(result, "alerts")
    assert sink["type"] == "mnotify"
    assert sink["to"] == "alerts@example.invalid"
    assert sink["timeout_s"] == 300
    assert sink["accepts_roster"] is False


def test_valid_https_sink_keys_are_not_dropped() -> None:
    result = _project(HTTPS_KEYS_TOML)
    assert [key for key in result.dropped_keys if key.startswith("sink.")] == []
    sink = _sink(result, "cloud")
    assert sink["type"] == "https"
    assert sink["headers"] == "X-Dept=ops-floor-3;X-Trace=on"
    assert sink["accepts_roster"] is False
    assert sink["timeout_s"] == 45
    assert sink["token_env"] == "GATECLERK_INGEST_TOKEN_DEMO_B"


def test_invalid_recipient_is_dropped_and_counted() -> None:
    """A non-address is reported, not quietly projected as if it were a recipient."""
    raw = MNOTIFY_TOML.replace('to = "alerts@example.invalid"', 'to = "not-an-address"')
    result = _project(raw)
    assert set(result.dropped_keys) == {"sink.to"}
    assert result.dropped_count == 1
    sink = _sink(result, "alerts")
    assert sink["to"] == ""
    # The rest of the alert route is still reported.
    assert sink["type"] == "mnotify"
    assert sink["timeout_s"] == 300


@pytest.mark.parametrize(
    "bad_to",
    [
        pytest.param("two@at@example.invalid", id="two-at-signs"),
        pytest.param("has space@example.invalid", id="whitespace"),
        pytest.param("no-at-sign.example.invalid", id="no-at-sign"),
        pytest.param(CRED_SHAPED, id="credential-shaped"),
    ],
)
def test_every_malformed_recipient_is_counted(bad_to: str) -> None:
    raw = MNOTIFY_TOML.replace('to = "alerts@example.invalid"', f'to = "{bad_to}"')
    result = _project(raw)
    assert set(result.dropped_keys) == {"sink.to"}
    assert _sink(result, "alerts")["to"] == ""


def test_headers_are_rendered_as_sorted_pairs() -> None:
    raw = HTTPS_KEYS_TOML.replace(GOOD_HEADERS_LINE, 'headers = { X-B = "2", X-A = "1" }')
    assert _sink(_project(raw), "cloud")["headers"] == "X-A=1;X-B=2"


@pytest.mark.parametrize(
    ("bad_headers_line", "label"),
    [
        pytest.param('headers = "X-A=1"', "sink.headers", id="not-a-table"),
        pytest.param("headers = { X-A = 7 }", "sink.headers", id="non-string-value"),
        pytest.param('headers = { "X-A\\r\\nX-B" = "1" }', "sink.headers", id="header-injection"),
    ],
)
def test_malformed_header_table_is_dropped_and_counted(bad_headers_line: str, label: str) -> None:
    result = _project(HTTPS_KEYS_TOML.replace(GOOD_HEADERS_LINE, bad_headers_line))
    assert label in set(result.dropped_keys)
    assert _sink(result, "cloud")["headers"] == ""


@pytest.mark.parametrize(
    ("old_line", "new_line", "label"),
    [
        pytest.param(
            "timeout_s = 45", "timeout_s = 0", "sink.timeout_s", id="timeout-not-positive"
        ),
        pytest.param(
            "timeout_s = 45", 'timeout_s = "300"', "sink.timeout_s", id="timeout-not-a-number"
        ),
        pytest.param("timeout_s = 45", "timeout_s = true", "sink.timeout_s", id="timeout-is-bool"),
        pytest.param(
            "accepts_roster = false",
            'accepts_roster = "yes"',
            "sink.accepts_roster",
            id="roster-not-a-bool",
        ),
    ],
)
def test_invalid_scalar_sink_value_is_dropped_and_counted(
    old_line: str, new_line: str, label: str
) -> None:
    result = _project(HTTPS_KEYS_TOML.replace(old_line, new_line))
    assert label in set(result.dropped_keys)
    sink = _sink(result, "cloud")
    if label == "sink.timeout_s":
        assert sink["timeout_s"] is None
    else:
        assert sink["accepts_roster"] is True


def test_reserved_header_names_are_dropped_not_printed() -> None:
    """`Authorization` / `X-GateClerk-Site` are the transport's own headers (`sinks.py`
    refuses them at parse time), so the inventory must never render one."""
    for reserved in ("Authorization", "X-GateClerk-Site"):
        line = f'headers = {{ {reserved} = "Bearer plain-text-word" }}'
        result = _project(HTTPS_KEYS_TOML.replace(GOOD_HEADERS_LINE, line))
        assert set(result.dropped_keys) == {"sink.headers"}
        assert _sink(result, "cloud")["headers"] == ""


def test_no_secret_value_appears_in_the_export(tmp_path: Path) -> None:
    """The inventory keeps the config facts and loses the credential bytes."""
    result = _project(SECRET_TOML)

    # The config facts an operator needs are there.
    assert _sink(result, "alerts")["to"] == "alerts@example.invalid"
    assert _sink(result, "cloud")["headers"] == "X-Dept=ops-floor-3"
    # Every credential-carrying sink table is dropped and counted.
    assert set(result.dropped_keys) == {"sink.headers"}

    for fmt in ("csv", "jsonl"):
        rendered = export_cli.render_config_export(result.rows, fmt=fmt)
        rendered += export_cli.format_dropped_keys_summary(result.dropped_keys)
        assert "alerts@example.invalid" in rendered
        assert "X-Dept=ops-floor-3" in rendered
        assert CRED_SHAPED not in rendered
        assert BASE64_SHAPED not in rendered
        assert "Bearer" not in rendered

    cfg_file = tmp_path / "sites.toml"
    cfg_file.write_text(SECRET_TOML, encoding="utf-8")
    for fmt in ("csv", "jsonl"):
        res = runner.invoke(app, ["export", "config", "--config", str(cfg_file), "--format", fmt])
        assert res.exit_code == 0, res.output
        combined = res.output + (getattr(res, "stderr", "") or "")
        assert "alerts@example.invalid" in combined
        assert "X-Dept=ops-floor-3" in combined
        assert CRED_SHAPED not in combined
        assert BASE64_SHAPED not in combined


def test_unknown_sink_key_is_still_dropped() -> None:
    """The allowlist stays deny-by-default: a key no `SinkSpec` field backs is reported."""
    raw = HTTPS_KEYS_TOML.replace("timeout_s = 45", 'timeout_s = 45\napi_token = "x"')
    result = _project(raw)
    assert "sink.api_token" in set(result.dropped_keys)
    assert "sink.timeout_s" not in set(result.dropped_keys)


def test_mnotify_sink_survives_the_cli_export(tmp_path: Path) -> None:
    """End to end: the JSONL a cutover reviewer actually reads says `mnotify`."""
    cfg_file = tmp_path / "sites.toml"
    cfg_file.write_text(MNOTIFY_TOML, encoding="utf-8")
    res = runner.invoke(app, ["export", "config", "--config", str(cfg_file), "--format", "jsonl"])
    assert res.exit_code == 0, res.output
    line = next(ln for ln in res.stdout.splitlines() if ln.strip().startswith("{"))
    obj = json.loads(line)
    assert obj["sinks"][0]["type"] == "mnotify"
    assert obj["sinks"][0]["to"] == "alerts@example.invalid"
    assert obj["sinks"][0]["timeout_s"] == 300
    assert "dropped_keys: 0" in res.output
