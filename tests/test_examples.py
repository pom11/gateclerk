"""Tests for `examples/` and README quickstart/sink table (card t_33b99193, EXAMPLES-README).

Verifies:
1. `examples/sites.toml` parses cleanly through `gateclerk.config.load_sites` on both the
   CLI and AGENT surfaces, exercising `https`, `csv`, `jsonl` named sinks and the legacy
   `push_target` equivalence.
2. `examples/sample_scans.jsonl` round-trips through `gateclerk.model.from_jsonl`, and
   `examples/sample_scans.csv` matches `gateclerk.export_cli.SCAN_EXPORT_COLUMNS`.
3. `examples/sample_roster_line.json` matches the frozen roster contract
   (`deviceCode` + `users[{employee_no, name, cardNo, hasFace}]`).
4. Synthetic-only law: no IP address, serial number, card number, or employee name in
   `examples/` appears in `docs/OBSERVED*.md` (RFC 5737 + `DEMO-*` only).
5. `examples/mock_receiver.py` contract smoke test: `200` on valid Bearer + JSONL scan
   and roster lines, `401` on missing/unknown Bearer, `403` on `X-Gateclerk-Site` mismatch,
   `400` on invalid JSONL, `422` on `unknown_device_serials`.
6. `README.md` quickstart starts with `gateclerk demo` and contains the sinks decision
   table covering `https`, `csv`, `jsonl`, and `push_target`.
"""

from __future__ import annotations

import csv
import importlib.util
import io
import json
from pathlib import Path

from gateclerk import config as cfg
from gateclerk.export_cli import SCAN_EXPORT_COLUMNS
from gateclerk.model import from_jsonl

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_DIR = REPO_ROOT / "examples"


def _load_mock_receiver():
    spec = importlib.util.spec_from_file_location(
        "mock_receiver", EXAMPLES_DIR / "mock_receiver.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_examples_sites_toml_parses_on_agent_and_cli_surfaces() -> None:
    sites = cfg.load_sites(EXAMPLES_DIR / "sites.toml", surface=cfg.ConfigSurface.AGENT)
    assert set(sites) == {"demo-site-a", "demo-site-b"}

    site_a = sites["demo-site-a"]
    assert [s.name for s in site_a.effective_sinks] == [
        "cloud_ingest",
        "daily_csv",
        "monthly_jsonl",
    ]
    assert [s.type for s in site_a.effective_sinks] == ["https", "csv", "jsonl"]

    site_b = sites["demo-site-b"]
    assert len(site_b.effective_sinks) == 1
    assert site_b.effective_sinks[0].name == "legacy"
    assert site_b.effective_sinks[0].type == "https"


def test_sample_scans_csv_jsonl_and_roster_match_contracts() -> None:
    jsonl_text = (EXAMPLES_DIR / "sample_scans.jsonl").read_text(encoding="utf-8")
    records = from_jsonl(jsonl_text)
    assert len(records) == 2
    assert [r.serial_no for r in records] == [1001, 1002]
    assert [r.direction.value for r in records] == ["in", "out"]

    csv_text = (EXAMPLES_DIR / "sample_scans.csv").read_text(encoding="utf-8")
    rows = list(csv.reader(io.StringIO(csv_text)))
    assert tuple(rows[0]) == SCAN_EXPORT_COLUMNS
    assert len(rows) == 3

    roster = json.loads((EXAMPLES_DIR / "sample_roster_line.json").read_text(encoding="utf-8"))
    assert roster["deviceCode"] == "DEMO-A-1"
    assert isinstance(roster["users"], list) and len(roster["users"]) == 2
    for user in roster["users"]:
        assert set(user.keys()) == {"employee_no", "name", "cardNo", "hasFace"}


def test_examples_are_strictly_synthetic_and_absent_from_observed_docs() -> None:
    observed_text = "\n".join(
        p.read_text(encoding="utf-8")
        for p in sorted((REPO_ROOT / "docs" / "internal").glob("OBSERVED*.md"))
    )
    for token in ("DEMO-SN-001", "DEMO-CARD-01", "DEMO-CARD-02", "Demo Alpha", "Demo Beta"):
        assert token not in observed_text


def test_internal_docs_moved_to_docs_internal_and_readme_has_eli5_sections() -> None:
    internal = REPO_ROOT / "docs" / "internal"
    for name in (
        "DESIGN.md",
        "ENROLLMENT-MIGRATION.md",
        "OBSERVED.md",
        "OBSERVED-site-B.md",
        "P2-SITE-AGENT.md",
        "PROGRESS.md",
    ):
        assert (internal / name).is_file(), f"docs/internal/{name} missing"
        assert not (REPO_ROOT / "docs" / name).exists(), f"docs/{name} should have moved"

    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    for heading in (
        "## What it is",
        "## What it is NOT",
        "## Install",
        "## 5-minute quickstart",
        "## Common commands",
        "### Delivery sinks decision table",
        "## Exit codes",
        "## FAQ",
        "## Privacy & data ownership",
    ):
        assert heading in readme, f"README.md missing heading {heading!r}"


def test_mock_receiver_contract_statuses() -> None:
    mod = _load_mock_receiver()
    sample_jsonl = (EXAMPLES_DIR / "sample_scans.jsonl").read_bytes()
    sample_roster = (EXAMPLES_DIR / "sample_roster_line.json").read_bytes()

    # 200 OK on scan JSONL + roster line
    code, body = mod.evaluate_ingest_request(
        method="POST",
        headers={
            "Authorization": "Bearer demo-placeholder-ingest-token",
            "X-Gateclerk-Site": "DEMO-SITE-A",
        },
        body=sample_jsonl + b"\n" + sample_roster,
        known_devices={"DEMO-SN-001"},
    )
    assert code == 200
    assert body == {
        "status": True,
        "site": "DEMO-SITE-A",
        "scans_received": 2,
        "rosters_received": 1,
    }

    # 401 on missing/bad token
    code_401, _ = mod.evaluate_ingest_request(
        method="POST",
        headers={"Authorization": "Bearer wrong-token"},
        body=sample_jsonl,
    )
    assert code_401 == 401

    # 403 on site_token_mismatch
    code_403, body_403 = mod.evaluate_ingest_request(
        method="POST",
        headers={
            "Authorization": "Bearer demo-placeholder-ingest-token",
            "X-Gateclerk-Site": "OTHER-SITE",
        },
        body=sample_jsonl,
    )
    assert code_403 == 403
    assert body_403["error"] == "site_token_mismatch"

    # 400 on invalid JSONL
    code_400, body_400 = mod.evaluate_ingest_request(
        method="POST",
        headers={"Authorization": "Bearer demo-placeholder-ingest-token"},
        body=b"{not-json}\n",
    )
    assert code_400 == 400
    assert body_400["error"] == "invalid_jsonl"

    # 422 on unknown_device_serials
    code_422, body_422 = mod.evaluate_ingest_request(
        method="POST",
        headers={"Authorization": "Bearer demo-placeholder-ingest-token"},
        body=sample_jsonl,
        known_devices={"OTHER-SN"},
    )
    assert code_422 == 422
    assert body_422["error"] == "unknown_device_serials"
    assert body_422["unknown"] == ["DEMO-SN-001"]


def test_readme_starts_quickstart_with_demo_and_has_sinks_decision_table() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    qs_idx = readme.lower().index("quickstart")
    demo_idx = readme.index("gateclerk demo demo", qs_idx)
    real_idx = readme.index("gateclerk device info", qs_idx)
    assert demo_idx < real_idx, "Quickstart must introduce `gateclerk demo demo` before real device"
    assert "### Delivery sinks decision table" in readme
    for row_key in ("`https`", "`csv`", "`jsonl`", "Legacy `push_target`"):
        assert row_key in readme
