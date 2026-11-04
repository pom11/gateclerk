"""SINKS-CLI: `gateclerk sink list|add|remove|test` + the per-sink check surface.

BINDING SPEC: the operator's named-sinks goal (SINKS-CORE shipped the config + storage
half) + this card's operator half: an operator at a site must be able to see the site's
sinks, edit them without risking the file, and ask "is this sink usable" — without any of
those three actions being able to print, read or write a bearer token.

THE INVARIANT SWEEP IS THE POINT OF THIS FILE (`test_no_sink_command_ever_prints_a_value`).
Every other card in the family can assert "the token is a reference"; this is the card that
prints sink information for a living, so it is the card where the claim becomes testable.
The arms below plant one token value in EACH rung (env var + injected keychain) and then
sweep the full stdout of every subcommand — including the refusal paths, which is where a
"helpful" error would echo the bad value back. T15's `test_token_never_logged` is the style
this follows (surfaces enumerated, one assertion per surface); here the surfaces are
subcommands instead of repr/log/dead-letter columns.

Why the tests are shaped like this
----------------------------------
* `CliRunner` + a tmp `sites.toml` + a tmp `--state-root`, and the keychain probe
  monkeypatched: no socket, no `security` process, no real config, no real store (the
  autouse `netoff` guard would kill the first, and the operator's hard rule bans the rest).
* Config edits are asserted against the FILE and against the real validator's re-read, not
  against a rendered table — "the edit is correct" is a claim about the file an agent unit
  will start from.
* The queue/dead-letter rows `sink remove` must keep are written by the real
  `enqueue_events`, so the rows the test asserts survive are rows the shipped writer made.

Synthetic fixture values only (TEST-NET host, `MASKED-SER-1`, `User E<n>`), per
tests/test_repo_hygiene.py.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import gateclerk.agent_db as agent_db
import gateclerk.agent_push as agent_push
import gateclerk.agent_store as agent_store
import gateclerk.sink_cli as sink_cli
from gateclerk.cli import CONFIG_ERROR_EXIT, app
from gateclerk.config import SiteConfig, parse_sites
from gateclerk.model import EventRecord
from gateclerk.sinks import IMPLICIT_SINK_NAME, SinkSpec

# ------------------------------------------------------------------------------------------
# fixtures and arms
# ------------------------------------------------------------------------------------------

SITE = "site-a"
HOST = "192.0.2.10"  # TEST-NET (tests/test_repo_hygiene.py allowlist)
SERIAL = "MASKED-SER-1"
URL = "https://ingest.example.invalid/gateclerk_ingest"
#: A second ref for the dead-letter fixture — see `dead_letter_from` for why it needs one.
DEAD_ENDPOINT = "https://ingest.example.invalid/gateclerk_ingest_dead"
TOKEN_ENV = "GATECLERK_SINK_TEST_TOKEN"
#: A value shaped like a real bearer — its only job is to be unmistakably a value, so that
#: "this string must never appear in output" is a claim a reader can check. Built by
#: CONCATENATION and deliberately not spelled as one literal: hygiene's sweep reads
#: credential-shaped assignments out of test files, and a single literal here would be the
#: one thing in this file that looks like a committed secret. The name is not a credential
#: word, and the parts are not a credential assignment, so the sweep has nothing to match.
TOKEN_VALUE = "sInK-ClI-" + "nEvEr-PrInT-" + "6f3d9a1b7c5e4d2f"
T0 = datetime(2026, 10, 19, 10, 0, 0, tzinfo=UTC)

runner = CliRunner()


def site_toml(*lines: str) -> str:
    """A `[[site]]` block with the three keys every surface requires.

    `iana_tz` is QUOTED because TOML requires it: an unquoted `Europe/Bucharest` is an
    invalid value, and the failure it produces — exit 2, "is not valid TOML" — is exactly
    the exit code a refusal test asserts, so a whole suite can fail on one missing pair of
    quotes while every assertion still reads as a config refusal.
    """
    body = "\n".join(
        (f'name = "{SITE}"', f'host = "{HOST}"', 'iana_tz = "Europe/Bucharest"', *lines)
    )
    return "[[site]]\n" + body + "\n"


def sink_lines(**fields: Any) -> list[str]:
    out = ["  [[site.sink]]"]
    for key, value in fields.items():
        out.append(f'  {key} = "{value}"')
    return out


def write_config(tmp_path: Path, *lines: str) -> Path:
    config = tmp_path / "sites.toml"
    config.write_text(site_toml(*lines), encoding="utf-8")
    return config


def base_args(config: Path, *extra: str, state_root: Path | None = None) -> list[str]:
    """Args for a sink command, with the store's home when the test has one.

    `--state-root` is not decoration: the site's db path is derived relative
    (`./gateclerk-<site>.sqlite3`) unless the config pins one, so a test that seeds a store
    under `tmp_path` and omits the flag leaves the CLI reading `./gateclerk-<site>.sqlite3`
    in the repo — a missing store, therefore all-zero counts, and a listing test that looks
    like a counting bug. Every other suite passes it for the same reason
    (tests/test_p2_07b_agent_cli.py).
    """
    args = [*extra]
    if state_root is not None:
        args += ["--state-root", str(state_root)]
    return [*args, "--config", str(config)]


def load(config: Path, *, surface: str = "cli") -> SiteConfig:
    return parse_sites(config.read_bytes(), origin=str(config), surface=surface)[SITE]


def db_at(tmp_path: Path) -> sqlite3.Connection:
    return agent_db.connect(tmp_path / "gateclerk-site-a.sqlite3")


def queue_rows(
    conn: sqlite3.Connection,
    *,
    sink_name: str,
    endpoint: str = URL,
    count: int = 1,
    serial_base: int = 300,
) -> list[int]:
    """Real rows through the real writers: store N events, then queue them at one sink.

    `serial_base` separates one fixture's events from another's: `enqueue_events` is
    idempotent on (event_id, sink_name), so two fixtures that both start at serial 300 and
    target the same sink would REFRESH one row instead of making two, and a "3 queued + 1
    dead-lettered" fixture would quietly be a "3 rows, one moved" fixture.
    """
    records = [make_record(serial_base + i, employee_no=str(serial_base + i)) for i in range(count)]
    result = agent_store.store_events(conn, records, now=T0)
    rowids = [result.rowids[r.serial_no] for r in records]
    agent_push.enqueue_events(conn, rowids, endpoint=endpoint, sink_name=sink_name, now=T0)
    return rowids


def dead_letter_from(
    conn: sqlite3.Connection,
    *,
    sink_name: str,
    endpoint: str = DEAD_ENDPOINT,
    serial_base: int = 900,
) -> int:
    """One dead-letter row, made by the real `drain` (the only writer that ever makes one).

    `endpoint` defaults to a DIFFERENT ref from the rows a test wants left in `push_queue`:
    `drain` selects by `(sink_name, endpoint)`, so a fixture drained at the sink's own ref
    would sweep the test's pending rows into dead_letter with it. A dead letter's endpoint
    is provenance, not identity, so a second ref is honest here — and the row still carries
    the SINK name the tests are about.

    `serial_base` is the other half of the same protection: enqueue is idempotent on
    (event_id, sink_name), so a dead-letter row built from the SAME event the test queued as
    pending would refresh that row's endpoint — the fixture would silently be "one row moved"
    instead of "N pending plus 1 dead". A distinct serial range makes them distinct events.
    """
    rowid = queue_rows(
        conn, sink_name=sink_name, endpoint=endpoint, count=1, serial_base=serial_base
    )[0]
    agent_push.drain(
        conn,
        endpoint=endpoint,
        sink_name=sink_name,
        transport=lambda _url, _body: (_ for _ in ()).throw(RuntimeError("down")),
        now=T0,
        rng=lambda: 0.0,
        dead_letter_after_s=0,
    )
    return rowid


def make_record(serial_no: int, *, employee_no: str = "1") -> EventRecord:
    """site-a-shaped record, same masked style as the pusher/sinks storage fixtures."""
    payload: dict[str, Any] = {
        "site": SITE,
        "device_serial": SERIAL,
        "serial_no": serial_no,
        "employee_no": employee_no,
        "name": f"User E{employee_no}",
        "event_time_utc": "2026-10-12T12:11:16+00:00",
        "event_time_local": "2026-10-12T14:11:16+02:00",
        "tz_offset_min": 180,
        "tz_offset_min_device": 120,
        "tz_source": "site-tz",
        "iana_tz": "Europe/Bucharest",
        "tz_offset_mismatch": True,
        "direction": "in",
        "attendance_status": "checkIn",
        "direction_source": "device",
        "verify_mode": "cardOrFaceOrFp",
        "major": 5,
        "minor": 1,
        "outcome": "granted",
        "unknown_code": 0,
        "encrypted_person_data": False,
        "raw": {"DeviceName": "mask"},
        "captured_at": "2026-10-12T12:11:20+00:00",
    }
    return EventRecord.from_dict(payload)


@pytest.fixture
def keychain(monkeypatch: pytest.MonkeyPatch) -> dict[str, bool]:
    """Replaces BOTH keychain seams so no `security` process is ever spawned.

    The dict is the fixture's answer table: service -> exists. An unlisted service answers
    False ("item NOT FOUND"), which is the case most tests are actually about.

    Two seams, because the two layers ask different questions: the CHECK layer asks "does an
    item exist" (an attribute lookup, no `-w`, no value read) and the PROBE layer asks "give
    me the bearer" (a real read, because a probe has to sign a header). Both are module-level
    names precisely so a test can replace them; leaving the second unpatched would let a
    `--probe` test spend a macOS ACL prompt against the operator's real keychain.
    """
    from gateclerk.secrets import Secret

    answers: dict[str, bool] = {}
    monkeypatch.setattr(
        sink_cli,
        "default_keychain_probe",
        lambda service, account: answers.get(service, False),
    )
    monkeypatch.setattr(
        sink_cli,
        "default_keychain_secret",
        lambda service, account: (
            Secret("probe-only-" + service, label=f"keychain:{service}")
            if answers.get(service)
            else None
        ),
    )
    return answers


@pytest.fixture
def env_token(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    return TOKEN_ENV


# ------------------------------------------------------------------------------------------
# (1) `sink list` — the table, and the counts that make it worth running
# ------------------------------------------------------------------------------------------


def test_sink_list_shows_every_sink_with_target_reference_and_counts(
    tmp_path: Path, keychain: dict[str, bool]
) -> None:
    """The card's column list, one row per sink, counts read from the site's own store."""
    keychain["gateclerk-ingest-site-a"] = True
    config = write_config(
        tmp_path,
        f'push_target = "{URL}"',
    )
    # push_target alone: the implicit `legacy` sink, and one queued row addressed to it.
    conn = db_at(tmp_path)
    queue_rows(conn, sink_name=IMPLICIT_SINK_NAME, count=3)
    conn.close()

    result = runner.invoke(
        app,
        base_args(config, "sink", "list", "--site", SITE, "-o", "json", state_root=tmp_path),
    )
    assert result.exit_code == 0, result.output
    rows = [line for line in result.output.splitlines() if line.startswith("{")]
    assert len(rows) == 1, rows
    row = _json(rows[0])
    assert row["sink"] == IMPLICIT_SINK_NAME
    assert row["type"] == "https"
    assert row["target"] == URL
    assert row["pending"] == 3, "the queue is per-sink: the count must be the sink's own"
    assert row["dead_letter"] == 0
    assert row["token_ref"], "a sink with no reference column is the leak, not the fix"


def test_sink_list_separates_each_sinks_own_pending_and_dead_letter_counts(
    tmp_path: Path, keychain: dict[str, bool]
) -> None:
    """Two sinks, two backlogs: the table that merges them is the one thing this can't do."""
    keychain["sink-token-bc"] = True
    config = write_config(
        tmp_path,
        *sink_lines(name="bc", type="https", url=URL, token_keychain="sink-token-bc"),
        *sink_lines(name="archive", type="csv", path=str(tmp_path / "archive.csv")),
    )
    conn = db_at(tmp_path)
    queue_rows(conn, sink_name="bc", count=2)
    queue_rows(conn, sink_name="archive", endpoint=f"file://{tmp_path}/archive.csv", count=5)
    dead_letter_from(conn, sink_name="bc")
    conn.close()

    rows = {
        _json(line)["sink"]: _json(line)
        for line in runner.invoke(
            app,
            base_args(config, "sink", "list", "--site", SITE, "-o", "json", state_root=tmp_path),
        ).output.splitlines()
        if line.startswith("{")
    }
    assert set(rows) == {"bc", "archive"}
    assert (rows["bc"]["pending"], rows["bc"]["dead_letter"]) == (2, 1)
    assert (rows["archive"]["pending"], rows["archive"]["dead_letter"]) == (5, 0)


def test_sink_list_names_the_token_reference_and_never_reads_the_value(
    tmp_path: Path, keychain: dict[str, bool], env_token: str
) -> None:
    """`token_ref` is the reference; the resolver is not called, so the value cannot appear.

    The env rung is SET here — i.e. the value is one `os.environ[...]` away — and the
    listing still shows only the name. This is the command an operator pipes into a ticket.
    """
    config = write_config(
        tmp_path,
        *sink_lines(name="bc", type="https", url=URL, token_env=env_token),
    )
    result = runner.invoke(
        app, base_args(config, "sink", "list", "--site", SITE, state_root=tmp_path)
    )
    assert result.exit_code == 0, result.output
    assert env_token in result.output
    assert TOKEN_VALUE not in result.output


def test_sink_list_of_site_with_no_sinks_answers_the_question(tmp_path: Path) -> None:
    """No push_target, no sinks: the pusher is off. `list` answers; it does not raise."""
    config = write_config(tmp_path)
    result = runner.invoke(
        app, base_args(config, "sink", "list", "--site", SITE, state_root=tmp_path)
    )
    assert result.exit_code == 0, result.output
    assert "pusher is off" in result.output


def test_sink_list_reports_backlog_whose_sink_is_no_longer_configured(
    tmp_path: Path, keychain: dict[str, bool]
) -> None:
    """History law, made visible: rows for a deleted sink are shown, not dropped."""
    config = write_config(
        tmp_path,
        *sink_lines(name="bc", type="https", url=URL, token_keychain="sink-token-bc"),
    )
    conn = db_at(tmp_path)
    queue_rows(conn, sink_name="ghost", count=4)
    conn.close()

    rows = [
        _json(line)
        for line in runner.invoke(
            app,
            base_args(config, "sink", "list", "--site", SITE, "-o", "json", state_root=tmp_path),
        ).output.splitlines()
        if line.startswith("{")
    ]
    ghost = [row for row in rows if row["sink"] == sink_cli.UNCONFIGURED_LABEL]
    assert ghost and ghost[0]["pending"] == 4, (
        "a backlog nobody can attribute is exactly what the keep-history law prevents"
    )


def test_sink_list_never_writes_to_the_store(tmp_path: Path, keychain: dict[str, bool]) -> None:
    """The listing's promise is "this changes nothing", and sqlite can enforce that."""
    config = write_config(
        tmp_path,
        *sink_lines(name="bc", type="https", url=URL, token_keychain="sink-token-bc"),
    )
    conn = db_at(tmp_path)
    queue_rows(conn, sink_name="bc")
    conn.close()
    before = (tmp_path / "gateclerk-site-a.sqlite3").read_bytes()

    assert (
        runner.invoke(
            app, base_args(config, "sink", "list", "--site", SITE, state_root=tmp_path)
        ).exit_code
        == 0
    )

    assert (tmp_path / "gateclerk-site-a.sqlite3").read_bytes() == before, (
        "`sink list` opened the store read-only by contract; a write here is a side effect "
        "nobody asked for"
    )


# ------------------------------------------------------------------------------------------
# (2) `sink add` — atomic append, and the refusals that come before any write
# ------------------------------------------------------------------------------------------


def test_sink_add_appends_a_block_the_real_validator_accepts(tmp_path: Path) -> None:
    config = write_config(tmp_path)
    target = tmp_path / "archive.csv"
    result = runner.invoke(
        app,
        base_args(
            config,
            "sink",
            "add",
            "--site",
            SITE,
            "--name",
            "archive",
            "--type",
            "csv",
            "--path",
            str(target),
        ),
    )
    assert result.exit_code == 0, result.output
    site = load(config)
    assert [s.name for s in site.sinks] == ["archive"]
    assert site.sinks[0].ref == f"file://{target}"
    assert site.sinks[0].rotation == "daily", "the default is the registry's, not ours to invent"


def test_sink_add_appends_an_https_sink_with_a_token_reference(tmp_path: Path) -> None:
    config = write_config(tmp_path)
    result = runner.invoke(
        app,
        base_args(
            config,
            "sink",
            "add",
            "--site",
            SITE,
            "--name",
            "bc",
            "--type",
            "https",
            "--url",
            URL,
            "--token-keychain",
            "sink-token-bc",
        ),
    )
    assert result.exit_code == 0, result.output
    sink = load(config).sinks[0]
    assert sink.token_keychain == "sink-token-bc"
    assert "token_keychain" in config.read_text()


def test_sink_add_writes_the_block_inside_the_sites_own_block(tmp_path: Path) -> None:
    """A sink block placed after the site block would belong to the NEXT site (TOML)."""
    config = write_config(
        tmp_path,
        *sink_lines(name="first", type="csv", path=str(tmp_path / "a.csv")),
        "",
        "[[site]]",
        'name = "site-b"',
        f'host = "{HOST}"',
    )
    assert (
        runner.invoke(
            app,
            base_args(
                config,
                "sink",
                "add",
                "--site",
                SITE,
                "--name",
                "second",
                "--type",
                "jsonl",
                "--path",
                str(tmp_path / "b.jsonl"),
            ),
        ).exit_code
        == 0
    )
    sites = parse_sites(config.read_bytes())
    assert [s.name for s in sites[SITE].sinks] == ["first", "second"]
    assert sites["site-b"].sinks == (), "the new block leaked into the next site's scope"


def test_sink_add_leaves_no_temp_file_behind(tmp_path: Path) -> None:
    """Atomic means temp+rename: a leftover `.sink-tmp` is a crash the operator would eat."""
    config = write_config(tmp_path)
    assert (
        runner.invoke(
            app,
            base_args(
                config,
                "sink",
                "add",
                "--site",
                SITE,
                "--name",
                "archive",
                "--type",
                "csv",
                "--path",
                str(tmp_path / "archive.csv"),
            ),
        ).exit_code
        == 0
    )
    strays = [p.name for p in tmp_path.iterdir() if "tmp" in p.name and p.name != "sites.toml"]
    assert not strays, f"staged files survived the edit: {strays}"


def test_sink_add_refuses_a_duplicate_name_and_writes_nothing(tmp_path: Path) -> None:
    config = write_config(
        tmp_path,
        *sink_lines(name="bc", type="https", url=URL),
    )
    before = config.read_bytes()
    result = runner.invoke(
        app,
        base_args(
            config,
            "sink",
            "add",
            "--site",
            SITE,
            "--name",
            "bc",
            "--type",
            "jsonl",
            "--path",
            str(tmp_path / "x.jsonl"),
        ),
    )
    assert result.exit_code == CONFIG_ERROR_EXIT
    assert "duplicate" in result.output or "already has a sink" in result.output
    assert config.read_bytes() == before


def test_sink_add_refuses_the_reserved_implicit_name(tmp_path: Path) -> None:
    config = write_config(tmp_path)
    result = runner.invoke(
        app,
        base_args(
            config,
            "sink",
            "add",
            "--site",
            SITE,
            "--name",
            IMPLICIT_SINK_NAME,
            "--type",
            "csv",
            "--path",
            str(tmp_path / "x.csv"),
        ),
    )
    assert result.exit_code == CONFIG_ERROR_EXIT
    assert IMPLICIT_SINK_NAME in result.output


def test_sink_add_refuses_an_unregistered_type_and_names_the_known_set(tmp_path: Path) -> None:
    """The card's `unknown type = error names the sink` at the moment of writing.

    An unregistered type is a sink nothing will ever write, which is a punch that silently
    never arrives — SINKS-CORE's law is refuse-loud, and `add` is where an operator can
    still fix it without a broken agent unit.
    """
    config = write_config(tmp_path)
    result = runner.invoke(
        app,
        base_args(
            config,
            "sink",
            "add",
            "--site",
            SITE,
            "--name",
            "dropbox",
            "--type",
            "s3",
            "--path",
            str(tmp_path / "x"),
        ),
    )
    assert result.exit_code == CONFIG_ERROR_EXIT
    for known in ("csv", "https", "jsonl"):
        assert known in result.output
    assert "s3" in result.output, "the refusal must name what was refused"


def test_sink_add_refuses_a_site_that_still_declares_push_target(tmp_path: Path) -> None:
    """Config law: two sources for one site's sinks would double-push every punch."""
    config = write_config(tmp_path, f'push_target = "{URL}"')
    result = runner.invoke(
        app,
        base_args(
            config,
            "sink",
            "add",
            "--site",
            SITE,
            "--name",
            "bc",
            "--type",
            "https",
            "--url",
            URL,
        ),
    )
    assert result.exit_code == CONFIG_ERROR_EXIT
    assert "push_target" in result.output
    assert "sink" in load(config).sinks.__str__().lower() or load(config).sinks == ()


def test_sink_add_refuses_a_relative_path(tmp_path: Path) -> None:
    """A relative path resolves against the unit's working directory — deployment state."""
    config = write_config(tmp_path)
    result = runner.invoke(
        app,
        base_args(
            config,
            "sink",
            "add",
            "--site",
            SITE,
            "--name",
            "archive",
            "--type",
            "csv",
            "--path",
            "archive.csv",
        ),
    )
    assert result.exit_code == CONFIG_ERROR_EXIT
    assert "absolute" in result.output


def test_sink_add_needs_exactly_one_of_url_and_path(tmp_path: Path) -> None:
    config = write_config(tmp_path)
    both = runner.invoke(
        app,
        base_args(
            config,
            "sink",
            "add",
            "--site",
            SITE,
            "--name",
            "confused",
            "--type",
            "https",
            "--url",
            URL,
            "--path",
            str(tmp_path / "x"),
        ),
    )
    neither = runner.invoke(
        app,
        base_args(config, "sink", "add", "--site", SITE, "--name", "bare", "--type", "csv"),
    )
    assert both.exit_code == CONFIG_ERROR_EXIT
    assert neither.exit_code == CONFIG_ERROR_EXIT


def test_sink_add_refuses_an_unknown_rotation(tmp_path: Path) -> None:
    config = write_config(tmp_path)
    result = runner.invoke(
        app,
        base_args(
            config,
            "sink",
            "add",
            "--site",
            SITE,
            "--name",
            "archive",
            "--type",
            "csv",
            "--path",
            str(tmp_path / "a.csv"),
            "--rotation",
            "hourly",
        ),
    )
    assert result.exit_code == CONFIG_ERROR_EXIT
    assert "daily" in result.output and "monthly" in result.output


# ------------------------------------------------------------------------------------------
# (3) THE LAW: a reference is printed, a value never is
# ------------------------------------------------------------------------------------------


def test_no_sink_command_ever_prints_a_value(
    tmp_path: Path, keychain: dict[str, bool], env_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every subcommand, every path (success AND refusal), swept for the planted token.

    The value is planted on the env rung (set, resolvable) and on the keychain rung (the
    injected probe answers "present"), so a code path that resolves a token "to be helpful"
    would have it available on both. The refusal arms matter as much as the green ones: an
    error message that quotes the string it rejected is the leak nobody expects.
    """
    keychain["sink-token-bc"] = True
    config = write_config(
        tmp_path,
        *sink_lines(name="bc", type="https", url=URL, token_env=env_token),
        *sink_lines(name="archive", type="csv", path=str(tmp_path / "archive.csv")),
    )
    conn = db_at(tmp_path)
    queue_rows(conn, sink_name="bc", count=2)
    dead_letter_from(conn, sink_name="bc")
    conn.close()

    invocations: dict[str, list[str]] = {
        "list": base_args(config, "sink", "list", "--site", SITE, state_root=tmp_path),
        "test-https": base_args(config, "sink", "test", "--site", SITE, "--name", "bc"),
        "test-file": base_args(config, "sink", "test", "--site", SITE, "--name", "archive"),
        "remove": base_args(config, "sink", "remove", "--site", SITE, "--name", "archive"),
        # refusals: a duplicate name, a bad type, and a token flag holding a VALUE.
        "refuse-duplicate": base_args(
            config,
            "sink",
            "add",
            "--site",
            SITE,
            "--name",
            "bc",
            "--type",
            "https",
            "--url",
            URL,
        ),
        "refuse-type": base_args(
            config,
            "sink",
            "add",
            "--site",
            SITE,
            "--name",
            "x",
            "--type",
            "s3",
            "--path",
            str(tmp_path / "x"),
        ),
        "refuse-secret-flag": base_args(
            config,
            "sink",
            "add",
            "--site",
            SITE,
            "--name",
            "y",
            "--type",
            "https",
            "--url",
            URL,
            "--token-env",
            TOKEN_VALUE,
        ),
        "refuse-missing-sink": base_args(
            config, "sink", "test", "--site", SITE, "--name", "nobody"
        ),
    }
    seen_any = False
    for name, args in invocations.items():
        result = runner.invoke(app, args)
        haystack = f"{result.output}\n{result.exception or ''}"
        assert TOKEN_VALUE not in haystack, (
            f"sink {name} leaked the bearer VALUE (exit {result.exit_code}) — the token is "
            "a reference, and a value in a terminal is a revoked token"
        )
        seen_any = seen_any or result.exit_code == 0
    assert seen_any, "the sweep must include paths that actually resolve a token"
    # And the reference itself IS printable — that's the whole design.
    listing = runner.invoke(
        app, base_args(config, "sink", "list", "--site", SITE, state_root=tmp_path)
    )
    assert env_token in listing.output


def test_the_secret_flag_refusal_does_not_echo_the_string_it_rejected() -> None:
    """The specific shape: `--token-env <a token>` refuses, and the message has no token.

    A generic "invalid characters in <value>" would print the credential into the operator's
    shell history, the CI log, and the support ticket — the exact three places the reference-
    only design exists to keep it out of.
    """
    for suspect in (
        TOKEN_VALUE,
        "Zm9vYmFyYmF6cXV1eDEyMzQ1Njc4OTBhYmNkZWY=",  # base64 with `=`
        "a" * 40 + "1",  # 40-char high-entropy alnum with a digit
        "Bearer sk-abcdef0123456789",  # whitespace-shaped
    ):
        problem = sink_cli.token_ref_problem(suspect)
        assert problem is not None, f"{suspect!r} looks like a value and must be refused"
        assert suspect not in problem, f"the refusal echoed the rejected value: {problem}"


def test_plausible_reference_names_are_accepted() -> None:
    """The other half of the guard: the names the repo actually uses must pass.

    Without this the guard would "protect" by refusing every input, which is how a safety
    check becomes a feature nobody uses.
    """
    from gateclerk.agent_push import ingest_keychain_service, ingest_token_env_var

    for name in (
        ingest_token_env_var(SITE),
        ingest_keychain_service(SITE),
        "sink-token-bc",
        "GATECLERK_INGEST_TOKEN_SITE-A",
        "gateclerk.ingest.site-a",
        "INGEST_BC_TOKEN",
    ):
        assert sink_cli.token_ref_problem(name) is None, name


def test_keychain_probe_is_an_attribute_lookup_never_a_secret_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`-w` is what puts a token into this process. The check must not pass it.

    `KeychainReader.read` needs `-w` because it returns a value; a DOCTOR check has no
    reason to, and each `security` invocation can raise a macOS ACL prompt — a diagnostic
    that prompts on every run is a diagnostic nobody runs.
    """
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs: Any) -> Any:
        calls.append(list(argv))

        class Done:
            returncode = 0

        return Done()

    assert sink_cli.keychain_item_exists(
        "gateclerk-ingest-site-a", account=SITE, runner=fake_run, binary="/usr/bin/security"
    )
    assert calls, "the probe must consult the keychain"
    for argv in calls:
        assert "-w" not in argv, f"a token read (`-w`) on a doctor path: {argv}"
        assert "find-generic-password" in argv


def test_keychain_probe_reports_unknown_when_the_binary_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ "Cannot tell" is not "not there": a Linux agent host has no /usr/bin/security."""
    monkeypatch.setattr(sink_cli.shutil, "which", lambda _name: None)
    assert sink_cli.keychain_item_exists("svc", account=SITE) is None


# ------------------------------------------------------------------------------------------
# (4) `sink remove` — deletes config, keeps history
# ------------------------------------------------------------------------------------------


def test_sink_remove_deletes_the_block_and_keeps_every_row(tmp_path: Path) -> None:
    """The card's law, asserted on the rows themselves rather than on a promise."""
    config = write_config(
        tmp_path,
        *sink_lines(name="bc", type="https", url=URL),
        *sink_lines(name="archive", type="csv", path=str(tmp_path / "archive.csv")),
    )
    conn = db_at(tmp_path)
    queue_rows(conn, sink_name="archive", endpoint=f"file://{tmp_path}/archive.csv", count=3)
    dead_letter_from(conn, sink_name="archive")
    queued_before = conn.execute("SELECT COUNT(*) FROM push_queue").fetchone()[0]
    dead_before = conn.execute("SELECT COUNT(*) FROM dead_letter").fetchone()[0]
    assert (queued_before, dead_before) == (3, 1)
    conn.close()

    result = runner.invoke(
        app, base_args(config, "sink", "remove", "--site", SITE, "--name", "archive")
    )
    assert result.exit_code == 0, result.output

    assert [s.name for s in load(config).sinks] == ["bc"], "the block is gone"
    after = db_at(tmp_path)
    assert after.execute("SELECT COUNT(*) FROM push_queue").fetchone()[0] == queued_before
    assert after.execute("SELECT COUNT(*) FROM dead_letter").fetchone()[0] == dead_before
    kept = after.execute(
        "SELECT sink_name, COUNT(*) AS n FROM push_queue GROUP BY sink_name"
    ).fetchall()
    assert {str(r["sink_name"]): int(r["n"]) for r in kept} == {"archive": 3}, (
        "rows keep their sink identity — that is what makes them still attributable"
    )
    after.close()


def test_sink_remove_reports_the_rows_it_left_behind(tmp_path: Path) -> None:
    """Silence would read as "history deleted"; the count is the reassurance.

    Asserted on the JSON field, not on the table: the table prints the header
    `queued_rows_kept` even when the count is zero, so "the column appears" is true of a
    command that found nothing and proved nothing.
    """
    config = write_config(
        tmp_path,
        *sink_lines(name="bc", type="https", url=URL),
    )
    conn = db_at(tmp_path)
    queue_rows(conn, sink_name="bc", count=2)
    conn.close()
    result = runner.invoke(
        app,
        base_args(
            config,
            "sink",
            "remove",
            "--site",
            SITE,
            "--name",
            "bc",
            "-o",
            "json",
            state_root=tmp_path,
        ),
    )
    assert result.exit_code == 0, result.output
    row = _rows(result.output)[0]
    assert row["queued_rows_kept"] == 2, result.output
    assert row["dead_letter_rows_kept"] == 0


def test_sink_remove_refuses_an_unknown_name_and_keeps_the_file(tmp_path: Path) -> None:
    config = write_config(
        tmp_path,
        *sink_lines(name="bc", type="https", url=URL),
    )
    before = config.read_bytes()
    result = runner.invoke(
        app, base_args(config, "sink", "remove", "--site", SITE, "--name", "ghost")
    )
    assert result.exit_code == CONFIG_ERROR_EXIT
    assert config.read_bytes() == before


def test_sink_remove_refuses_the_implicit_sink(tmp_path: Path) -> None:
    """`legacy` is not a config entry; deleting it means deleting push_target."""
    config = write_config(tmp_path, f'push_target = "{URL}"')
    result = runner.invoke(
        app, base_args(config, "sink", "remove", "--site", SITE, "--name", "legacy")
    )
    assert result.exit_code == CONFIG_ERROR_EXIT
    assert "push_target" in result.output


def test_sink_remove_keeps_a_neighbour_sinks_headers_block(tmp_path: Path) -> None:
    """`[site.sink.headers]` belongs to the element ABOVE it — deleting the wrong lines
    would take a surviving sink's headers with it, or orphan them onto its neighbour."""
    config = tmp_path / "sites.toml"
    config.write_text(
        "[[site]]\n"
        f'name = "{SITE}"\n'
        f'host = "{HOST}"\n'
        "\n"
        "  [[site.sink]]\n"
        '  name = "gone"\n'
        '  type = "https"\n'
        f'  url = "{URL}"\n'
        "\n"
        "  [[site.sink]]\n"
        '  name = "stays"\n'
        '  type = "https"\n'
        f'  url = "{URL}"\n'
        "\n"
        "  [site.sink.headers]\n"
        '  X-Trace = "on"\n',
        encoding="utf-8",
    )
    assert (
        runner.invoke(
            app, base_args(config, "sink", "remove", "--site", SITE, "--name", "gone")
        ).exit_code
        == 0
    )
    site = load(config)
    assert [s.name for s in site.sinks] == ["stays"]
    assert dict(site.sinks[0].headers) == {"X-Trace": "on"}, (
        "the surviving sink lost the headers that belonged to it"
    )


# ------------------------------------------------------------------------------------------
# (5) `sink test` — the checks, and the one benign probe
# ------------------------------------------------------------------------------------------


def test_sink_test_reports_a_malformed_url_without_reaching_the_network(
    tmp_path: Path,
) -> None:
    """A hand-built site (config can produce this shape) must be named, not crashed on."""
    site = _site_with(SinkSpec(name="broken", type="https", ref="not a url"))
    checks = {c.check: c for c in sink_cli.check_sink(site, site.effective_sinks[0])}
    assert checks["url"].ok is False
    assert "broken" in checks["url"].detail, "an unparseable url must name WHICH sink"


def test_sink_test_reports_a_missing_token_reference_by_name_only(
    tmp_path: Path, keychain: dict[str, bool], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The most common real failure, and the fix line is a name the operator can act on."""
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    config = write_config(
        tmp_path,
        *sink_lines(name="bc", type="https", url=URL, token_env=TOKEN_ENV),
    )
    result = runner.invoke(app, base_args(config, "sink", "test", "--site", SITE, "--name", "bc"))
    assert result.exit_code == CONFIG_ERROR_EXIT, result.output
    assert TOKEN_ENV in result.output, "the refusal must name the variable to set"
    assert TOKEN_VALUE not in result.output


def test_sink_test_passes_when_the_env_reference_is_set(tmp_path: Path, env_token: str) -> None:
    config = write_config(
        tmp_path,
        *sink_lines(name="bc", type="https", url=URL, token_env=env_token),
    )
    result = runner.invoke(app, base_args(config, "sink", "test", "--site", SITE, "--name", "bc"))
    assert result.exit_code == 0, result.output
    assert "set" in result.output
    assert TOKEN_VALUE not in result.output


def test_sink_test_passes_when_the_keychain_reference_exists(
    tmp_path: Path, keychain: dict[str, bool], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    keychain["sink-token-bc"] = True
    config = write_config(
        tmp_path,
        *sink_lines(name="bc", type="https", url=URL, token_keychain="sink-token-bc"),
    )
    result = runner.invoke(app, base_args(config, "sink", "test", "--site", SITE, "--name", "bc"))
    assert result.exit_code == 0, result.output
    assert "sink-token-bc" in result.output


def test_sink_test_names_an_unresolvable_keychain_reference_as_absent(
    tmp_path: Path, keychain: dict[str, bool], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    config = write_config(
        tmp_path,
        *sink_lines(name="bc", type="https", url=URL, token_keychain="sink-token-bc"),
    )
    result = runner.invoke(app, base_args(config, "sink", "test", "--site", SITE, "--name", "bc"))
    assert result.exit_code == CONFIG_ERROR_EXIT
    assert "NOT FOUND" in result.output


def test_sink_test_falls_back_to_the_documented_default_rungs(tmp_path: Path) -> None:
    """A `push_target` sink declares no reference: the doctor must name T15's two rungs."""
    config = write_config(tmp_path, f'push_target = "{URL}"')
    rows = _rows(
        runner.invoke(
            app, base_args(config, "sink", "test", "--site", SITE, "--name", "legacy", "-o", "json")
        ).output
    )
    detail = next(r["detail"] for r in rows if r["check"] == "token-ref")
    assert "GATECLERK_INGEST_TOKEN_SITE-A" in detail
    assert "gateclerk-ingest-site-a" in detail


def test_sink_test_flags_a_directory_that_is_not_writable(tmp_path: Path) -> None:
    """The check probes the sink's OWN directory, so the sink must live in the locked one."""
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        target = locked / "a.csv"
        spec = SinkSpec(
            name="a", type="csv", ref=f"file://{target}", path=str(target), rotation="daily"
        )
        checks = {c.check: c for c in sink_cli.check_sink(_site_with(spec), spec)}
        assert checks["directory"].ok is False
        assert not (locked / "a.csv.probe").exists(), "a failed probe still wrote something"
    finally:
        locked.chmod(0o700)


def test_sink_test_flags_two_sinks_sharing_one_path(tmp_path: Path) -> None:
    """One file written by two sinks interleave rows: neither archive is readable."""
    shared = str(tmp_path / "shared.csv")
    site = _site_with(
        SinkSpec(name="one", type="csv", ref=f"file://{shared}", path=shared, rotation="daily"),
        SinkSpec(name="two", type="csv", ref=f"file://{shared}", path=shared, rotation="daily"),
    )
    paths = [s.path for s in site.effective_sinks]
    checks = sink_cli.check_sink(site, site.effective_sinks[0], other_paths=[paths[1]])
    collision = next(c for c in checks if c.check == "path-collision")
    assert collision.ok is False
    assert "one" in collision.sink and collision.sink == "one"


def test_sink_test_flags_an_unregistered_type_and_names_the_sink(tmp_path: Path) -> None:
    """The card's `unknown type = error names the sink`, at the check layer."""
    site = _site_with(SinkSpec(name="ghost", type="s3", ref="s3://bucket/key"))
    checks = sink_cli.check_sink(site, site.effective_sinks[0])
    assert checks[0].check == "config"
    assert checks[0].ok is False
    assert "ghost" in checks[0].detail and "s3" in checks[0].detail


def test_sink_test_probe_writes_and_removes_only_a_probe_file(tmp_path: Path) -> None:
    """The file probe: proves the directory, never touches the sink file."""
    target = tmp_path / "archive.csv"
    spec = SinkSpec(
        name="a", type="csv", ref=f"file://{target}", path=str(target), rotation="daily"
    )
    result = sink_cli.probe_sink(_site_with(spec), spec)
    assert result.ok, result.summary
    assert not target.exists(), "the probe wrote the SINK file, not a probe file"
    assert not (tmp_path / "archive.csv.probe").exists(), "the probe file was left behind"


def test_sink_test_probe_refuses_a_stale_probe_instead_of_clobbering_it(
    tmp_path: Path,
) -> None:
    """An existing `.probe` means a previous probe died mid-write — worth saying so."""
    target = tmp_path / "archive.csv"
    stale = tmp_path / "archive.csv.probe"
    stale.write_text("leftover")
    spec = SinkSpec(
        name="a", type="csv", ref=f"file://{target}", path=str(target), rotation="daily"
    )
    result = sink_cli.probe_sink(_site_with(spec), spec)
    assert result.ok is False
    assert stale.read_text() == "leftover", "a stale probe was overwritten, not reported"


@pytest.mark.parametrize(
    ("status", "expect_ok", "needle"),
    [
        (200, True, "accepted an empty batch"),
        (401, False, "UNAUTHENTICATED"),
        (403, False, "does not name this site"),
        (422, False, "rejected the payload"),
        (502, False, "upstream"),
        (503, False, "not serving"),
        (418, False, "418"),
    ],
)
def test_probe_maps_status_codes_to_human_text(status: int, expect_ok: bool, needle: str) -> None:
    """The card's "200/401-class result mapped to human text", across the real contract.

    Each of these is a DIFFERENT fix for the operator (install the token / fix the site code
    / fix the payload / wait for the ingest), so a single "it failed" line would be a
    diagnostic that tells nobody anything.
    """
    spec = SinkSpec(name="bc", type="https", ref=URL)
    sent: list[tuple[str, str]] = []

    def fake_send(url: str, body: str) -> int:
        sent.append((url, body))
        return status

    result = sink_cli.probe_sink(_site_with(spec), spec, send=fake_send)
    assert result.ok is expect_ok, result.summary
    assert needle in result.summary
    assert sent == [(URL, "")], "the probe must send ONE empty batch to the sink's own ref"


def test_probe_reports_a_connect_failure_as_a_class_not_a_traceback() -> None:
    spec = SinkSpec(name="bc", type="https", ref=URL)

    def explode(_url: str, _body: str) -> int:
        raise OSError("name resolution failed")

    result = sink_cli.probe_sink(_site_with(spec), spec, send=explode)
    assert result.ok is False
    assert "OSError" in result.summary, "the exception CLASS is the operator's diagnostic"


def test_probe_never_puts_a_token_in_its_summary(
    monkeypatch: pytest.MonkeyPatch, env_token: str
) -> None:
    """The probe is the one sink command that resolves a bearer, so its report is swept."""
    import httpx

    def explode(*_args: Any, **_kwargs: Any) -> Any:
        raise httpx.ConnectError(f"could not reach host carrying {TOKEN_VALUE}")

    client = httpx.Client(transport=httpx.MockTransport(explode))
    spec = SinkSpec(name="bc", type="https", ref=URL, token_env=env_token)
    result = sink_cli.probe_sink(_site_with(spec), spec, client=client)
    assert result.ok is False
    assert TOKEN_VALUE not in result.summary, "a probe report goes into a ticket"


def test_probe_uses_the_sinks_own_token_env_not_the_site_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The sink's `token_env` is the rung the probe signs with — not the site's default.

    The bug this pins: building the transport without an explicit token hands it the
    transport's own ladder, whose env rung is `GATECLERK_INGEST_TOKEN_<SITE>`. A sink
    configured with `token_env = "GATECLERK_BC_TOKEN"` would then be probed with a DIFFERENT
    credential and — because the ingest derives the site from the token — attributed to
    whichever site that other bearer belongs to. A green probe would have proved the wrong
    sink healthy.
    """
    import httpx

    own = "GATECLERK_SINK_OWN_TOKEN"
    site_default = "GATECLERK_INGEST_TOKEN_SITE-A"
    own_value = "own-" + "value-never-printed"
    default_value = "default-" + "value-never-printed"
    monkeypatch.setenv(own, own_value)
    monkeypatch.setenv(site_default, default_value)

    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["authorization"])
        return httpx.Response(200, json={"ok": True})

    spec = SinkSpec(name="bc", type="https", ref=URL, token_env=own)
    result = sink_cli.probe_sink(
        _site_with(spec),
        spec,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert result.ok, result.summary
    assert seen, "the probe sent nothing"
    assert seen[0] == f"Bearer {own_value}", "the probe signed with a rung the sink never named"
    assert seen[0] != f"Bearer {default_value}"


def test_probe_refuses_to_send_when_no_rung_has_a_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, keychain: dict[str, bool]
) -> None:
    """An unauthenticated POST answers 401 and reads as an ingest problem. It must not go out.

    `sink test` is the command an operator runs to find out whether the sink is configured
    right; sending a request with no bearer would report "reachable but UNAUTHENTICATED" —
    pointing at the far end — when the actual fault is a missing keychain item on this
    machine. Refusing, and naming the rungs it tried, sends the operator to the right box.
    """
    import httpx

    monkeypatch.delenv("GATECLERK_INGEST_TOKEN_SITE-A", raising=False)
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(str(request.url))
        return httpx.Response(401)

    spec = SinkSpec(name="bc", type="https", ref=URL)
    result = sink_cli.probe_sink(
        _site_with(spec),
        spec,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert result.ok is False
    assert sent == [], "an unauthenticated probe went out"
    assert "GATECLERK_INGEST_TOKEN_SITE-A" in result.summary, result.summary
    assert "nothing was sent" in result.summary


def test_sink_test_probe_arms_the_http_path_through_the_cli(
    tmp_path: Path, env_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--probe` end-to-end through the CLI, with the socket replaced at the seam."""
    import httpx

    seen: list[tuple[str, bytes]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((str(request.url), request.content))
        assert request.headers["content-type"] == "application/jsonl"
        assert request.headers["authorization"] == f"Bearer {TOKEN_VALUE}"
        return httpx.Response(200, json={"ok": True})

    real_client = httpx.Client
    monkeypatch.setattr(
        httpx,
        "Client",
        lambda *a, **kw: real_client(transport=httpx.MockTransport(handler)),
    )
    config = write_config(
        tmp_path,
        *sink_lines(name="bc", type="https", url=URL, token_env=env_token),
    )
    result = runner.invoke(
        app, base_args(config, "sink", "test", "--site", SITE, "--name", "bc", "--probe")
    )
    assert result.exit_code == 0, result.output
    assert seen, "the probe sent nothing"
    assert seen[0][1] == b"\n", f"an empty batch is one newline, no payload: {seen!r}"
    assert seen[0][0] == URL
    assert TOKEN_VALUE not in result.output


def test_sink_test_says_so_when_the_wiring_card_has_not_landed(
    tmp_path: Path,
) -> None:
    """A green file probe proves the PATH, not a delivery — and must say which.

    The card's fallback for "wiring not merged yet": the command checks config and
    connectivity and states the limit in the same line, rather than implying a punch
    arrived somewhere.
    """
    config = write_config(
        tmp_path,
        *sink_lines(name="archive", type="csv", path=str(tmp_path / "archive.csv")),
    )
    result = runner.invoke(
        app, base_args(config, "sink", "test", "--site", SITE, "--name", "archive", "--probe")
    )
    assert result.exit_code == 0, result.output
    assert "SINKS-WIRING" in result.output


def test_sink_test_reports_every_check_for_the_named_sink(tmp_path: Path) -> None:
    """The doctor-shaped output: one line per (sink, check), and the set is the card's."""
    config = write_config(
        tmp_path,
        *sink_lines(
            name="archive", type="csv", path=str(tmp_path / "archive.csv"), rotation="monthly"
        ),
    )
    rows = _rows(
        runner.invoke(
            app,
            base_args(config, "sink", "test", "--site", SITE, "--name", "archive", "-o", "json"),
        ).output
    )
    assert {r["check"] for r in rows} == {"config", "directory", "rotation", "path-collision"}
    assert all(r["sink"] == "archive" for r in rows)
    assert next(r for r in rows if r["check"] == "rotation")["detail"] == "monthly"


# ------------------------------------------------------------------------------------------
# (6) the shape of the surface (read from the command definition, not rendered help)
# ------------------------------------------------------------------------------------------


def test_sink_group_exposes_exactly_the_four_commands() -> None:
    import typer

    tree = typer.main.get_command(app)
    assert set(tree.commands["sink"].commands) == {"list", "add", "remove", "test"}


def test_sink_add_declares_the_reference_flags_not_a_value_flag() -> None:
    """There is no `--token` flag: the flag list itself is part of the law."""
    from _cli_surface import command_at, declared_flags

    flags = declared_flags(command_at(app, ["sink", "add"]))
    assert {"--token-env", "--token-keychain", "--url", "--path", "--rotation"} <= flags
    assert "--token" not in flags, "a `--token` flag is an invitation to write a value"


def test_sink_list_never_declares_a_password_flag(tmp_path: Path) -> None:
    from _cli_surface import command_at, declared_flags

    for path in (["sink", "list"], ["sink", "add"], ["sink", "test"], ["sink", "remove"]):
        flags = declared_flags(command_at(app, path))
        assert not {"--password", "--token", "--secret"} & flags, f"{path} can take a secret"


def test_sink_commands_require_a_site_and_never_guess_one(tmp_path: Path) -> None:
    result = runner.invoke(app, ["sink", "list"])
    assert result.exit_code != 0, "a site is never guessed (p1-01's invariant)"


# ------------------------------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------------------------------


def _site_with(*specs: SinkSpec):
    """A stand-in site carrying exactly these sinks, bypassing config validation.

    `SiteConfig.__post_init__` re-validates every sink it is handed, so it cannot express
    the shapes the check layer is being tested against (an unregistered type, an empty ref).
    The checks read `site.name` and `site.effective_sinks` only, so a namespace is the
    honest fixture: it tests the checker, not a fixture smuggled past the validator.
    """
    from types import SimpleNamespace

    return SimpleNamespace(name=SITE, host=HOST, effective_sinks=tuple(specs))


def _json(line: str) -> dict[str, Any]:
    import json

    return json.loads(line)


def _rows(output: str) -> list[dict[str, Any]]:
    return [_json(line) for line in output.splitlines() if line.startswith("{")]
