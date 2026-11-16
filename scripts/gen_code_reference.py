"""Regenerate the §3.1/§3.2 provenance tables in docs/internal/references/acs-event-codes.md.

The tables are GENERATED from the vendored catalogs
(tests/fixtures/vendor/*.json) plus gateclerk.event_codes.EVENT_CODE_TABLE so that the
doc, the fixtures and the code can never drift apart silently —
tests/test_event_codes.py re-derives the same rows and fails on any mismatch.

Usage:  uv run python scripts/gen_code_reference.py           # print block to stdout
        uv run python scripts/gen_code_reference.py --write    # splice into the doc
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from gateclerk.event_codes import EVENT_CODE_TABLE  # noqa: E402

VENDOR = ROOT / "tests/fixtures/vendor"
DOC = ROOT / "docs/internal/references/acs-event-codes.md"

START = "<!-- BEGIN GENERATED 3.1 (scripts/gen_code_reference.py) -->"
END = "<!-- END GENERATED 3.1 -->"


def load_catalogs() -> tuple[dict[int, str], dict[tuple[int, int], tuple[str, str]]]:
    nr = {}
    for e in json.loads((VENDOR / "node-red-MAJOR_EVENT-0x5.json").read_text()):
        v = e["Value"].strip()
        if " to " in v:  # the CUSTOM1..64 range entry
            continue
        nr[int(v, 16)] = e["ShortDescription"]
    mmi_raw = json.loads((VENDOR / "hikvision-acs-event-types.json").read_text())
    mmi: dict[tuple[int, int], tuple[str, str]] = {}
    for major, minors in mmi_raw.items():
        for minor, meta in minors.items():
            mmi[(int(major), int(minor))] = (meta["name"], meta["outcome"])
    return nr, mmi


#: Which catalog a `src:` token claims, and which catalog the identifier must resolve in.
#: The two catalogs use different naming conventions — node-red is `MINOR_UPPER_SNAKE`,
#: mmisobuj is `camelCase` — so a two-source row cites the node-red identifier (the vendor
#: hex name is the more canonical of the two) and `expected_src` encodes that convention
#: instead of leaving it to prose.
def expected_src(
    major: int,
    minor: int,
    nr: dict[int, str],
    mmi: dict[tuple[int, int], tuple[str, str]],
) -> str | None:
    """The ONLY `src:` a row may carry, computed from the fixtures.

    Not a hint — `audit_src` compares against this exactly, so a row cannot claim a
    catalog that does not contain the pair, nor cite an identifier the catalog does not
    use for it. Returns None when no catalog names the code at all (such a code must stay
    unnamed: info + unknown_code).
    """
    n = nr.get(minor) if major == 5 else None
    m = mmi.get((major, minor))
    if n and m:
        return f"nr+mmi:{n}"
    if n:
        return f"nr:{n}"
    if m:
        return f"mmi:{m[0]}"
    return None


def audit_src(
    table: dict[tuple[int, int], Any],
    nr: dict[int, str],
    mmi: dict[tuple[int, int], tuple[str, str]],
) -> list[str]:
    """Every way a row's provenance can be wrong, as human-readable strings.

    Empty means every shipped `src` is exactly what the vendored catalogs imply. This is
    what makes a fabricated citation impossible rather than merely discouraged: the
    identifier is resolved *inside the catalog the token names*, and the catalog set is
    recomputed from the fixtures rather than trusted from the row.
    """
    problems: list[str] = []
    for (major, minor), info in sorted(table.items()):
        want = expected_src(major, minor, nr, mmi)
        if want is None:
            problems.append(
                f"({major},{minor}) {info.name}: no catalog names this code — it must "
                "stay unnamed (info + unknown_code), not carry a src"
            )
            continue
        if info.src != want:
            prefix, _, ident = (info.src or "").partition(":")
            detail = (
                "row claims nothing"
                if not info.src
                else f"{prefix} has {(_lookup(prefix, major, minor, nr, mmi))!r} for this code"
            )
            problems.append(
                f"({major},{minor}) {info.name}: src={info.src!r} (identifier {ident!r}) "
                f"but the catalogs require {want!r} — {detail}"
            )
    return problems


def _lookup(
    prefix: str,
    major: int,
    minor: int,
    nr: dict[int, str],
    mmi: dict[tuple[int, int], tuple[str, str]],
) -> str | None:
    """What the claimed catalog actually says about this code (for the error message)."""
    if prefix.startswith("nr"):
        return nr.get(minor) if major == 5 else None
    if prefix == "mmi":
        m = mmi.get((major, minor))
        return m[0] if m else None
    return None


def require_clean_provenance(table: dict[tuple[int, int], Any]) -> None:
    """Refuse to generate a doc from provenance that does not resolve.

    Without this, `gen_code_reference.py --write` would launder a bad `src` into the
    reference doc — the doc is generated from the same string the row carries, so
    regeneration could otherwise make a fabricated citation look corroborated.
    """
    problems = audit_src(table, *load_catalogs())
    if problems:
        raise SystemExit(
            "refusing to write the reference: EVENT_CODE_TABLE provenance does not "
            "resolve against the vendored catalogs\n  " + "\n  ".join(problems)
        )


def build_block() -> str:
    nr, mmi = load_catalogs()
    rows = []
    deviations = []
    for (major, minor), info in sorted(EVENT_CODE_TABLE.items()):
        m = mmi.get((major, minor))
        n = nr.get(minor) if major == 5 else None
        rows.append(
            f"| {major} | {minor} | {n or '—'} | {m[0] if m else '—'} | "
            f"{m[1] if m else '—'} | {info.name} | {info.outcome.value} | `{info.src}` |"
        )
        if m and m[1] != info.outcome.value:
            deviations.append((major, minor, info, m))

    lines = [
        START,
        "### 3.1 Vendored per-code table (generated — do not hand-edit)",
        "",
        "Generated by `scripts/gen_code_reference.py` from the vendored catalogs",
        "`tests/fixtures/vendor/node-red-MAJOR_EVENT-0x5.json` (vendor hex names, major 5;",
        "fetched from `Supergiovane/node-red-contrib-hikvision-ultimate`, MIT) and",
        "`tests/fixtures/vendor/hikvision-acs-event-types.json` (decimal catalog with an",
        "explicit outcome per code, fetched from `mmisobuj/HikvisionIsupServer`).",
        "`tests/test_event_codes.py` re-derives these exact rows from the fixtures and",
        "fails if the code table, the fixtures or this table drift apart — including the",
        "`src:` provenance carried on every row of `EVENT_CODE_TABLE`.",
        "",
        "The only rows where the last two columns disagree with the mmisobuj outcome are",
        "deliberate and are listed with their reasons in §3.2; every other row imports",
        "the catalog outcome verbatim.",
        "",
        "| major | minor | node-red hex name | mmisobuj name | mmisobuj outcome | "
        "gateclerk name | gateclerk outcome | src |",
        "|---:|---:|---|---|---|---|---|---|",
        *rows,
        "",
        "### 3.2 Deliberate outcome deviations + corrections ledger (generated)",
        "",
        "| major | minor | mmisobuj | gateclerk | why |",
        "|---:|---:|---|---|---|",
    ]
    reasons = {
        (1, 1036): "majors 1/2 are never DENIED for us: an alarm is not a refused "
        "credential; a denied outcome would put fake auth failures on an attendance screen",
        (5, 9): "a rejected card IS a refused presentation for an attendance UI; "
        "the card table in §3 already treats it as an exception",
        (5, 12): "presentation refused (card not in multi-auth group) — denied for us",
        (5, 28): "door-left-open condition, not a refused credential — INFO for us",
    }
    for major, minor, info, m in deviations:
        why = reasons.get((major, minor))
        if why is None:
            msg = f"undeclared deviation ({major},{minor}) — add its reason in the script"
            raise SystemExit(msg)
        lines.append(f"| {major} | {minor} | {m[1]} | {info.outcome.value} | {why} |")
    lines += [
        "",
        "Corrections landed while adding provenance (review round 1: rows whose names no",
        "catalog contains were being shipped as if curated). Each left-side name existed",
        "in an earlier draft of `EVENT_CODE_TABLE` and appears in **neither** catalog:",
        "",
        "- (3,90) was `LOCAL_LOGOUT`; both catalogs name 90 `localUpgrade` — LOCAL_LOGOUT",
        "  is 81 (now both rows exist, correctly named).",
        "- (5,154) was `COMBINED_VERIFY_FAIL`; both catalogs name it **TIMEOUT** (0x9A).",
        "  It stays DENIED (a combined verification that expired) but the name is fixed.",
        "- (5,34) was `DOOR_OPEN_BY_REMOTE` → `MULTI_VERIFY_SUPERPASSWD_VERIFY_SUCCESS`",
        "  (GRANTED — the earlier INFO label was silently dropping a catalog-named pass).",
        "- (5,105) was `DEVICE_RECOVER_FORCE` → `PEOPLE_AND_IDCARD_COMPARE_PASS`",
        "  (GRANTED; same silent-drop class). Single-source row: mmisobuj only.",
        "- (5,29/30/31/32/33/35/36/37/49/51/104/112/114/115/142/193) carried invented",
        "  door/device names; now named per the catalogs, with outcome moves listed above",
        "  where they diverge.",
        END,
    ]
    return "\n".join(lines)


def main() -> None:
    # Loud before anything is written or printed: a row whose `src` does not resolve
    # against the fixtures must be fixed in event_codes.py, not laundered into the
    # reference doc by regenerating it (the doc is generated from the same string).
    require_clean_provenance(EVENT_CODE_TABLE)
    block = build_block()
    if "--write" not in sys.argv:
        print(block)
        return
    text = DOC.read_text()
    if START in text:
        new = re.sub(re.escape(START) + r".*?" + re.escape(END), block, text, flags=re.S)
    else:
        marker = "Alarms/exceptions worth surfacing"
        if marker not in text:
            raise SystemExit("anchor for the generated block not found")
        new = text.replace(marker, block + "\n" + marker, 1)
    DOC.write_text(new)
    print("doc updated")


if __name__ == "__main__":
    main()
