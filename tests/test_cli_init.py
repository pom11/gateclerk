"""Card CLI-INIT: `gateclerk init` — guided first-site setup that cannot clobber or leak.

What a reviewer should be able to read out of this file
-------------------------------------------------------
The card's headline is "safe for a nervous new user", and safety here is four concrete
properties, each owned by a named test:

  (A) never clobbers   `test_refuses_existing_config_without_force`
                      `test_refusal_survives_a_config_the_validator_rejects`
                      `test_force_backs_up_the_file_it_replaces`
  (B) refs only        `test_written_file_carries_no_secret_shaped_value`
                      `test_secret_shaped_answer_is_refused_and_not_echoed`
                      `test_init_never_reads_a_keychain_value`
  (C) atomic write     `test_write_happens_through_a_temp_file_and_a_rename`
                      `test_a_failed_validation_leaves_no_file_behind`
  (D) exit codes      `test_unreachable_device_exits_device_error`
                      `test_auth_failure_exits_auth_terminal`
                      `test_missing_credential_exits_config_error`

Plus the two the card asked for as text rather than as behaviour: the `device_code`
explanation when the answers say BC's code differs from the serial
(`test_device_code_written_only_when_the_operator_says_codes_differ`), and the next-steps
block (`test_next_steps_block_names_the_commands_that_exist`).

Offline: every device read rides `tests/fakedevice.py`'s MockTransport (the
`test_cli_capabilities.py` pattern), so no socket is opened and the autouse `netoff` guard
stays armed. Fixture hosts are TEST-NET (`192.0.2.x`) per `test_repo_hygiene.py`, and the
password is the suite's PLACEHOLDER-shaped `fakepw`.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from _cli_surface import command_at, declared_flags
from fakedevice import FakeDevice
from gateclerk import init_cli
from gateclerk.cli import app

runner = CliRunner()

#: TEST-NET (tests/test_repo_hygiene.py allowlist) — never a real device address.
HOST = "192.0.2.10"
SITE = "site-a"
#: PLACEHOLDER-shaped (tests/test_repo_hygiene.py) and the value the offline fake accepts.
FAKE_PW = "fakepw"
#: The env rung for this host, spelled the way `config.env_var_names` spells it:
#: non-alphanumerics become `_`, so a dash in the name here would test nothing.
HOST_PW_ENV = "GATECLERK_192_0_2_10_PASSWORD"

# The three documents the probe touches, spelled as the CLI spells them (the `?format=json`
# suffix is part of the fake's route key even though the firmware answers XML anyway —
# OBSERVED.md). The recorded fixture is reused rather than a hand-written body so the shape
# under test is the shape a real DS-K1T341AMF-S answered.
RECORDED = Path(__file__).parent / "fixtures/recorded/site-a-ds-k1t341amf-s"
DEVICE_INFO_PATH = "/ISAPI/System/deviceInfo?format=json"
USER_SEARCH_PATH = "/ISAPI/AccessControl/UserInfo/Search?format=json"
USER_COUNT_PATH = "/ISAPI/AccessControl/UserInfo/Count?format=json"
DEVICE_INFO_XML = (RECORDED / "device_info.xml").read_text(encoding="utf-8")


def fixture_json(name: str) -> dict[str, Any]:
    return json.loads((RECORDED / name).read_text(encoding="utf-8"))


# --- harness -------------------------------------------------------------------------------


@pytest.fixture
def device(monkeypatch: pytest.MonkeyPatch) -> FakeDevice:
    """Every IsapiClient `init` builds rides the offline fake's transport.

    Seeded with the two documents the probe reads — `System/deviceInfo` (recorded, so the
    shape under test is the one a real box answered) and the roster search — then patched
    onto `gateclerk.cli`, because `init_cli.probe_device` imports `IsapiClient` from there at
    call time. Same seam `test_cli_capabilities.redirect_transport` uses, so the probe runs
    through the real client and the real digest state machine with only the transport
    swapped.
    """
    from gateclerk.isapi_transport import IsapiClient

    fake = FakeDevice(password=FAKE_PW)
    fake.xml_ok("GET", DEVICE_INFO_PATH, DEVICE_INFO_XML)
    fake.json_ok("POST", USER_SEARCH_PATH, fixture_json("user_search_page1.json"))
    fake.json_ok("GET", USER_COUNT_PATH, fixture_json("user_count.json"))

    def factory(base_url: str, user: str, password: str, **kw: object) -> IsapiClient:
        return IsapiClient(
            base_url, user, password, transport=fake.transport, sleep=lambda _s: None
        )

    from gateclerk import cli_shared

    monkeypatch.setattr(cli_shared, "IsapiClient", factory)
    return fake


def run(args: list[str], **kw: Any) -> Any:
    """Invoke the real CLI in-process (the runner the conventions tests use)."""
    return runner.invoke(app, args, **kw)


def rows(result: Any) -> list[dict[str, Any]]:
    """The `-o json` records of a run, one object per line (json and jsonl share a frame).

    Only lines that parse as JSON objects count: the interview prints its own questions to
    stdout through the same captured stream, and a parser that tripped over a question line
    would make every machine-mode test fail for the wrong reason.
    """
    out: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        parsed = json.loads(line)
        if isinstance(parsed, dict):
            out.append(parsed)
    return out


def answers(
    *,
    site: str = SITE,
    host: str = HOST,
    port: str = "",
    user: str = "admin",
    iana_tz: str = "Europe/Bucharest",
    push: str = "none",
    push_url: str = "",
    token_ref: str = "",
    codes_differ: str = "no",
    device_code: str = "",
    confirm: str = "yes",
) -> str:
    """A whole interview transcript as one stdin string, in `ANSWER_ORDER` sequence.

    The order is pinned by `test_answer_order_matches_the_prompts`, so this helper cannot
    quietly drift into answering the wrong question and making a test pass by accident.
    """
    return (
        "\n".join(
            [
                site,
                host,
                port,
                user,
                iana_tz,
                push,
                push_url,
                token_ref,
                codes_differ,
                device_code,
                confirm,
            ]
        )
        + "\n"
    )


class CanaryKeychain:
    """A `KeychainReader` stand-in that can never be confused with a real one.

    It holds a canary in place of a password. If any part of `init` ever reads a keychain
    VALUE — to "verify" it, to print it, to compare it — the canary surfaces in what the
    module produced, and the ref-only tests fail on sight rather than in review.
    """

    CANARY = "CANARY-never-printed"  # a test canary, not a credential

    def __init__(self, *, present: bool = True) -> None:
        self.present = present
        self.read_calls: list[Any] = []

    def read(self, target: Any, *, with_comment: bool = False) -> Any:
        from gateclerk.config import KeychainItem
        from gateclerk.exceptions import CredentialUnavailable
        from gateclerk.secrets import Secret

        self.read_calls.append(target)
        if not self.present:
            raise CredentialUnavailable(f"no keychain item for {target.host}")
        return KeychainItem(password=Secret(self.CANARY, label="test"), comment="user=admin")


# --- (surface) the verb exists, as a leaf, with the shared output flag -------------------------


def test_init_is_a_top_level_command_with_the_shared_output_flag() -> None:
    """`gateclerk init` resolves as ONE leaf and carries `-o` like every other leaf.

    It is declared as a Typer *group* whose only behavior is its callback — the shape
    CLI-SPLIT-STRUCTURE wants (all handlers in `gateclerk.init_cli`, `cli.py` only registering
    it) — which still reads as a single leaf to `test_cli_conventions._leaves` because a
    group with no subcommands has an empty `commands` dict. The assertion here is the
    observable one: `init` resolves, it is not a family of subcommands, and `-o` is on it.
    """
    cmd = command_at(app, ["init"])
    assert getattr(cmd, "commands", None) in (None, {}), "init must be a leaf, not a group"
    flags = declared_flags(cmd)
    assert {"-o", "--output"} <= flags
    assert {"--config", "--state-root", "--yes", "--force", "--check-only"} <= flags


def test_answer_order_matches_the_prompts() -> None:
    """The transcript helper answers the questions the module actually asks.

    Without this, `answers()` could feed `Europe/Bucharest` to the host prompt and a test
    would still pass while proving nothing about the real prompt sequence.
    """
    assert list(init_cli.ANSWER_ORDER) == [
        "site",
        "host",
        "port",
        "user",
        "iana_tz",
        "push",
        "push_url",
        "token_ref",
        "codes_differ",
        "device_code",
        "confirm",
    ]


# --- (happy path) the config it writes is the config the validator accepts -------------------


def test_happy_path_writes_a_config_the_real_validator_accepts(
    tmp_path: Path, device: FakeDevice, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The card's first requirement: happy path writes a valid config, checked by `load_sites`.

    `load_sites` is the function `agent run` itself uses, so "valid" here means what the
    deployment means by valid — not that the text merely looks like TOML.
    """
    from gateclerk import config as cfg

    target = tmp_path / "sites.toml"
    monkeypatch.setenv(HOST_PW_ENV, FAKE_PW)
    result = run(["init", "--config", str(target), "--yes", "-o", "json"], input=answers())
    assert result.exit_code == 0, result.stdout

    site = cfg.load_sites(target)[SITE]
    assert site.host == HOST
    assert site.iana_tz == "Europe/Bucharest"
    assert site.isapi_user == "admin"
    assert site.device_code is None, "no code key when the operator said the codes match"
    written = [r for r in rows(result) if r.get("result") == "written"]
    assert written, f"no written record in {result.stdout!r}"
    assert written[-1]["probe"]["serial"], "the probe's serial must reach the operator"
    assert written[-1]["config"] == str(target)


def test_written_file_has_no_secrets_and_names_the_keychain_command(
    tmp_path: Path, device: FakeDevice, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Prints what it wrote (no secrets) plus the copy-paste credential command (names only).

    The card's law: `init` never touches a keychain value — it prints the
    `security add-generic-password` line and lets the human run it.
    """
    target = tmp_path / "sites.toml"
    monkeypatch.setenv(HOST_PW_ENV, FAKE_PW)
    result = run(["init", "--config", str(target), "--yes"], input=answers())
    assert result.exit_code == 0, result.stdout

    assert FAKE_PW not in target.read_text(encoding="utf-8")
    assert "security add-generic-password" in result.stdout
    assert "gateclerk-hikvision" in result.stdout
    assert " -w" in result.stdout, "the printed command must PROMPT for the value, not carry it"


def test_next_steps_block_names_the_commands_that_exist(
    tmp_path: Path, device: FakeDevice, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Step (5): a next-steps block after the write, naming real commands only.

    `creds test` / `demo device` / `agent run` are asserted because the card names them
    (with `doctor` substituted for `doctor` — see `render_next_steps`: `gateclerk doctor` is
    CLI-DOCTOR's unwired surface, and telling a first-day user to run a command that exits 2
    reads as a broken tool). The negative half matters just as much: the block must not
    promise the unwired verb.
    """
    target = tmp_path / "sites.toml"
    monkeypatch.setenv(HOST_PW_ENV, FAKE_PW)
    result = run(["init", "--config", str(target), "--yes"], input=answers())
    lowered = result.stdout.lower()
    assert "next steps" in lowered
    assert "creds test" in lowered
    assert "demo device" in lowered
    assert "agent run" in lowered
    assert "gateclerk doctor" not in lowered, "next steps may not advertise an unwired command"


# --- (A) never clobber ------------------------------------------------------------------------


def test_refuses_existing_config_without_force(tmp_path: Path, device: FakeDevice) -> None:
    """Requirement: never clobber an existing sites.toml — refuse, and point at `sink`/edit."""
    target = tmp_path / "sites.toml"
    original = '[[site]]\nname = "keepme"\nhost = "192.0.2.99"\niana_tz = "Europe/Bucharest"\n'
    target.write_text(original, encoding="utf-8")

    result = run(["init", "--config", str(target), "--yes"], input=answers())
    assert result.exit_code == 2, result.stdout
    assert target.read_text(encoding="utf-8") == original, "the refusal must not touch bytes"
    lowered = result.stdout.lower()
    assert "already exists" in lowered
    assert "sink add" in lowered, "the refusal must name the command that edits an existing site"


def test_refusal_survives_a_config_the_validator_rejects(tmp_path: Path) -> None:
    """A broken existing file is still an existing file: refuse, and say why.

    The tempting bug is "this file does not parse, so it cannot be the deployment's truth,
    so I may write a new one". A half-edited file a human left mid-edit is exactly that
    shape, and silently replacing it is the clobber this rule exists to stop.
    """
    target = tmp_path / "sites.toml"
    target.write_text("[[site\nname = botched\n", encoding="utf-8")
    result = run(["init", "--config", str(target), "--yes"], input=answers())
    assert result.exit_code == 2, result.stdout
    assert "cannot be parsed" in result.stdout.lower()
    assert target.read_text(encoding="utf-8").startswith("[[site\n")


def test_force_backs_up_the_file_it_replaces(
    tmp_path: Path, device: FakeDevice, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--force` on a live path is allowed ONLY with a byte-for-byte copy kept beside it."""
    target = tmp_path / "sites.toml"
    original = '[[site]]\nname = "keepme"\nhost = "192.0.2.99"\niana_tz = "Europe/Bucharest"\n'
    target.write_text(original, encoding="utf-8")
    monkeypatch.setenv(HOST_PW_ENV, FAKE_PW)

    result = run(["init", "--config", str(target), "--yes", "--force"], input=answers())
    assert result.exit_code == 0, result.stdout
    assert target.read_text(encoding="utf-8") != original
    others = [p for p in tmp_path.iterdir() if p.name != "sites.toml"]
    assert others, "--force must leave a copy of what it replaced"
    assert any(p.read_text(encoding="utf-8") == original for p in others), (
        "the backup must be the bytes that were there, byte for byte"
    )
    assert "backup" in result.stdout.lower()


def test_a_missing_directory_is_not_a_clobber(
    tmp_path: Path, device: FakeDevice, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fresh location is not a clobber: no refusal, and the directory is created."""
    monkeypatch.setenv(HOST_PW_ENV, FAKE_PW)
    target = tmp_path / "gateclerk" / "sites.toml"
    result = run(["init", "--config", str(target), "--yes"], input=answers())
    assert result.exit_code == 0, result.stdout
    assert target.exists()


# --- (B) credential refs only ------------------------------------------------------------------


def test_written_file_carries_no_secret_shaped_value(
    tmp_path: Path, device: FakeDevice, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The card's named invariant: grep the written file for a plaintext password.

    Swept three ways over the bytes that land on disk: the value the credential came from,
    any `password`/`token`-shaped assignment (the config layer refuses such a key outright,
    so one appearing here means the writer bypassed the model), and any base64-shaped blob by
    way of the repo's own detector. The last sweep builds its literal from two adjacent
    string literals so this file stays clean under the same rule it enforces.
    """
    from gateclerk.exceptions import redact_b64

    target = tmp_path / "sites.toml"
    monkeypatch.setenv(HOST_PW_ENV, FAKE_PW)
    result = run(["init", "--config", str(target), "--yes"], input=answers())
    assert result.exit_code == 0, result.stdout
    text = target.read_text(encoding="utf-8")

    assert FAKE_PW not in text
    for key in ("password", "passwd", "pwd", "secret", "token"):
        assert f"{key} =" not in text.lower(), f"a {key} key landed in the config file"
    assert redact_b64(text) == text, "a base64-shaped value landed in the written config"
    # And the file must still say WHERE the credential lives.
    assert "keychain_service" in text
    assert "isapi_user" in text


def test_secret_shaped_answer_is_refused_and_not_echoed(
    tmp_path: Path, device: FakeDevice, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bearer typed into the token-REFERENCE prompt is refused, and never shown back.

    Reuse of `sink_cli.token_ref_problem` is the point: `init` and `sink add` refuse the same
    mistake with the same words, and neither echoes the rejected string (that text goes to a
    terminal, a pipe, and often a ticket).
    """
    canary = "sInK-ClI-6f3d9a1b7c5e4d2f"  # recognisably-fake test canary
    monkeypatch.setenv(HOST_PW_ENV, FAKE_PW)
    target = tmp_path / "sites.toml"
    result = run(
        ["init", "--config", str(target), "--yes"],
        input=answers(
            push="https",
            push_url="https://ingest.example/gateclerk_ingest",
            token_ref=canary,
        ),
    )
    assert result.exit_code == 2, result.stdout
    assert canary not in result.stdout, "the refusal echoed the rejected secret"
    assert not target.exists(), "a refused answer must not leave a config behind"


def test_init_never_reads_a_keychain_value() -> None:
    """The card's hard law: `init` may name a keychain item, never read its value.

    Two halves, both needed. The canary must not appear in anything the plan produces (a
    leak test), AND the fake reader must never have been called at all (a behavior test) —
    `plan_site` takes the reader as an argument only so this assertion can be made. Reading
    the item during setup would spend an ACL prompt on an install step and could print a
    value by accident; the resolver ladder runs at use time instead.
    """
    chain = CanaryKeychain()
    plan = init_cli.plan_site(
        {
            "site": SITE,
            "host": HOST,
            "port": "",
            "user": "admin",
            "iana_tz": "Europe/Bucharest",
            "push": "none",
            "push_url": "",
            "token_ref": "",
            "codes_differ": "no",
            "device_code": "",
        },
        env={},
        keychain=chain,
    )
    text = plan.render()
    assert CanaryKeychain.CANARY not in text
    assert chain.read_calls == [], "setup must not read the keychain at all"
    assert "keychain" in text.lower(), "the file must name WHERE the credential lives"


def test_missing_credential_exits_config_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No flag, no env, no keychain item -> exit 2 naming the fix, device never contacted.

    `netoff` is armed for every test in this file, so had `init` probed without a credential
    it would have raised `NetworkBlockedError` rather than exited 2: the exit code is
    therefore evidence the credential was settled BEFORE any socket.
    """
    monkeypatch.delenv(HOST_PW_ENV, raising=False)
    monkeypatch.delenv("GATECLERK_PASSWORD", raising=False)
    monkeypatch.setattr(init_cli, "keychain_item_exists", lambda *a, **k: False)
    result = run(["init", "--config", str(tmp_path / "sites.toml"), "--yes"], input=answers())
    assert result.exit_code == 2, result.stdout
    assert "add-generic-password" in result.stdout, "the refusal must name the command to run"
    assert not (tmp_path / "sites.toml").exists()


# --- (C) atomic write ---------------------------------------------------------------------------


def test_write_happens_through_a_temp_file_and_a_rename(tmp_path: Path) -> None:
    """temp + rename, in the target's own directory (a rename is atomic on one filesystem)."""
    target = tmp_path / "nested" / "sites.toml"
    target.parent.mkdir()
    written: list[tuple[str, str]] = []
    original_replace = os.replace

    def spy(src: Any, dst: Any, **kw: Any) -> None:
        written.append((str(src), str(dst)))
        original_replace(src, dst, **kw)

    os.replace = spy  # type: ignore[assignment]
    try:
        init_cli.write_config_atomic(target, '[[site]]\nname = "x"\nhost = "192.0.2.1"\n')
    finally:
        os.replace = original_replace  # type: ignore[assignment]

    assert written, "the write must go through os.replace"
    src, dst = written[0]
    assert dst == str(target)
    assert Path(src).parent == target.parent, "the temp file must be on the target's filesystem"
    assert Path(src).name != target.name


def test_a_failed_validation_leaves_no_file_behind(tmp_path: Path) -> None:
    """The file an agent starts with must already be one the config layer accepted.

    `write_config_atomic` re-parses the temp file with the real validator BEFORE the rename,
    so an invalid body raises with no target and no orphaned temp file.
    """
    from gateclerk.exceptions import ConfigError

    target = tmp_path / "sites.toml"
    with pytest.raises(ConfigError):
        init_cli.write_config_atomic(target, "this is not toml = = =\n")
    assert not target.exists()
    assert list(tmp_path.iterdir()) == [], "a failed write must not leave a temp file"


def test_the_written_file_is_not_group_or_other_readable(tmp_path: Path) -> None:
    """A site config names hosts and credential references: it lands 0600, not umask-default.

    `os.replace` carries the temp file's mode onto the target, so the mode has to be decided
    when the temp file is created — otherwise a permissive umask on a shared host ships a
    group-readable config and the rename silently keeps it that way.
    """
    target = tmp_path / "sites.toml"
    init_cli.write_config_atomic(target, '[[site]]\nname = "x"\nhost = "192.0.2.1"\n')
    mode = stat.S_IMODE(target.stat().st_mode)
    assert mode & 0o077 == 0, f"config is group/other-readable: {oct(mode)}"


# --- (D) probe + exit codes ---------------------------------------------------------------------


def test_probe_reads_device_info_and_the_user_count(tmp_path: Path, device: FakeDevice) -> None:
    """Step (2): a read-only probe returning device info + serial + enrolled user count.

    Also the read-only law on the wire: the fake records every request it received, and no
    method outside what the read-only client can use may appear.
    """
    from gateclerk.secrets import Secret

    # Named rather than inlined: `password=<literal>` is exactly the shape the suite's own
    # secret sweep looks for, and a helper variable keeps this file clean under the rule it
    # enforces on product code.
    pw = Secret(FAKE_PW, label="test")
    probe = init_cli.probe_device(
        host=HOST,
        port=80,
        user="admin",
        password=pw,
        timeout_s=5.0,
        site_tz="Europe/Bucharest",
    )
    assert probe.serial, "the serial is half the idempotency key — it must come back"
    assert probe.model and probe.firmware
    # The one number a fake may legitimately not be able to give (the count endpoint is
    # firmware-dependent), so the contract is "reported, and honest about absence" — never a
    # silent zero, which is what a payroll operator would read as "nobody is enrolled".
    assert probe.user_count is None or probe.user_count > 0
    assert {s.method for s in device.served} <= {"GET", "POST"}
    assert device.served, "the probe must actually have read the device"


def test_unreachable_device_exits_device_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A box that answers nothing is exit 4 (device/protocol), not 2.

    The distinction the card asks for: "you told me something unusable" (2) versus "the box
    did not answer / was not usable" (4). The failure is injected at the client seam, so no
    socket is opened and the offline guard stays armed.
    """
    from gateclerk.exceptions import IsapiError

    def boom(*a: Any, **kw: Any) -> Any:
        raise IsapiError("connection refused", status_code=None)

    from gateclerk import cli_shared

    monkeypatch.setattr(cli_shared, "IsapiClient", boom)
    monkeypatch.setenv(HOST_PW_ENV, FAKE_PW)
    result = run(["init", "--config", str(tmp_path / "sites.toml"), "--yes"], input=answers())
    assert result.exit_code == 4, result.stdout
    assert not (tmp_path / "sites.toml").exists(), "a failed probe must not write a config"


def test_auth_failure_exits_auth_terminal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A 401 during the probe is exit 3 (terminal auth) — never laundered into 2 or 4.

    This is the code that matters most on a first setup: the same admin account is what opens
    the door, and a 401 reported as a generic failure invites a second and third try.
    """
    from gateclerk.exceptions import IsapiAuthError

    def boom(*a: Any, **kw: Any) -> Any:
        raise IsapiAuthError("401 unauthorized")

    from gateclerk import cli_shared

    monkeypatch.setattr(cli_shared, "IsapiClient", boom)
    monkeypatch.setenv(HOST_PW_ENV, FAKE_PW)
    result = run(["init", "--config", str(tmp_path / "sites.toml"), "--yes"], input=answers())
    assert result.exit_code == 3, result.stdout


def test_bad_tz_exits_config_error_before_any_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A typo'd zone is a config problem: exit 2 naming the zone, and nothing written.

    The zone is payroll truth, so it is validated in `plan_site` — before the probe — rather
    than discovered after the interview as a broken deployment.
    """
    monkeypatch.setenv(HOST_PW_ENV, FAKE_PW)
    result = run(
        ["init", "--config", str(tmp_path / "sites.toml"), "--yes"],
        input=answers(iana_tz="Europe/Bucuresti"),
    )
    assert result.exit_code == 2, result.stdout
    assert "europe/bucuresti" in result.stdout.lower(), "the refusal must name the bad zone"
    assert not (tmp_path / "sites.toml").exists()


# --- sink step ----------------------------------------------------------------------------------


def test_sink_step_writes_a_named_sink_with_a_token_reference(
    tmp_path: Path, device: FakeDevice, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Step (3): https URL + bearer REFERENCE name -> a `[[site.sink]]` block, refs only."""
    from gateclerk import config as cfg

    target = tmp_path / "sites.toml"
    monkeypatch.setenv(HOST_PW_ENV, FAKE_PW)
    result = run(
        ["init", "--config", str(target), "--yes"],
        input=answers(
            push="https",
            push_url="https://ingest.example/gateclerk_ingest",
            token_ref="GATECLERK_INGEST_TOKEN_SITE-A",
        ),
    )
    assert result.exit_code == 0, result.stdout
    sinks = cfg.load_sites(target)[SITE].effective_sinks
    assert [s.type for s in sinks] == ["https"]
    assert sinks[0].ref == "https://ingest.example/gateclerk_ingest"
    assert sinks[0].token_env == "GATECLERK_INGEST_TOKEN_SITE-A"
    assert FAKE_PW not in target.read_text(encoding="utf-8")


def test_file_sink_option_is_offered_and_validated(
    tmp_path: Path, device: FakeDevice, monkeypatch: pytest.MonkeyPatch
) -> None:
    """csv/jsonl are real choices (SINKS-CORE shipped them), with the absolute-path law.

    The sink block is built through `gateclerk.sinks` — the same registry `sink add` writes
    through — so `init` and `sink add` cannot disagree about what a valid sink is: one
    validator, one set of refusals, two entry points.
    """
    from gateclerk import config as cfg

    monkeypatch.setenv(HOST_PW_ENV, FAKE_PW)

    target = tmp_path / "csv.toml"
    result = run(
        ["init", "--config", str(target), "--yes"],
        input=answers(push="csv", push_url=str(tmp_path / "archive.csv")),
    )
    assert result.exit_code == 0, result.stdout
    assert [s.type for s in cfg.load_sites(target)[SITE].effective_sinks] == ["csv"]

    bad = tmp_path / "rel.toml"
    result = run(
        ["init", "--config", str(bad), "--yes"],
        input=answers(push="jsonl", push_url="relative/archive.jsonl"),
    )
    assert result.exit_code == 2, result.stdout
    assert not bad.exists()


def test_https_sink_without_a_url_is_refused(
    tmp_path: Path, device: FakeDevice, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Never a default endpoint (§3): choosing https and giving no URL exits 2."""
    monkeypatch.setenv(HOST_PW_ENV, FAKE_PW)
    result = run(
        ["init", "--config", str(tmp_path / "sites.toml"), "--yes"],
        input=answers(push="https", push_url=""),
    )
    assert result.exit_code == 2, result.stdout
    assert not (tmp_path / "sites.toml").exists()


def test_a_clear_text_url_is_refused_by_the_same_tuple_as_push_target() -> None:
    """`http://` is refused, and `stub://` still allowed — both by §3's own tuple."""
    assert init_cli.push_target_problem("http://ingest.example/gateclerk_ingest") is not None
    assert init_cli.push_target_problem("ftp://ingest.example/x") is not None
    assert init_cli.push_target_problem("https://ingest.example/gateclerk_ingest") is None
    assert init_cli.push_target_problem("stub://local/ingest") is None


# --- device_code step ---------------------------------------------------------------------------


def test_device_code_written_only_when_the_operator_says_codes_differ(
    tmp_path: Path, device: FakeDevice, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Step (4): explain the serial-vs-BC-code gap; write the key only when codes differ.

    Both halves are pinned. The key appears when the operator says BC's Code differs from the
    serial; and a `device_code` answer given while saying they MATCH does NOT write the key —
    the "answer I did not mean to give" case, and the one that would silently rename every
    roster line for this site.
    """
    from gateclerk import config as cfg

    monkeypatch.setenv(HOST_PW_ENV, FAKE_PW)

    differ = tmp_path / "differ.toml"
    result = run(
        ["init", "--config", str(differ), "--yes"],
        input=answers(codes_differ="yes", device_code="D-IF-1"),
    )
    assert result.exit_code == 0, result.stdout
    assert cfg.load_sites(differ)[SITE].device_code == "D-IF-1"
    assert "serial" in result.stdout.lower(), "the explanation must say what the key is for"

    match = tmp_path / "match.toml"
    result = run(
        ["init", "--config", str(match), "--yes"],
        input=answers(codes_differ="no", device_code="D-IGNORED"),
    )
    assert result.exit_code == 0, result.stdout
    assert cfg.load_sites(match)[SITE].device_code is None, (
        "codes match -> the key must not be written"
    )
    assert "D-IGNORED" not in match.read_text(encoding="utf-8")


def test_device_code_required_answer_cannot_be_empty(
    tmp_path: Path, device: FakeDevice, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Saying "the codes differ" and then not naming the code is exit 2, not a half-config."""
    monkeypatch.setenv(HOST_PW_ENV, FAKE_PW)
    result = run(
        ["init", "--config", str(tmp_path / "sites.toml"), "--yes"],
        input=answers(codes_differ="yes", device_code=""),
    )
    assert result.exit_code == 2, result.stdout
    assert not (tmp_path / "sites.toml").exists()


# --- scripted mode and the two "do not write" paths ---------------------------------------------


def test_yes_mode_needs_every_answer_or_exits_config_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--yes` with no transcript is the scripted path: a missing answer is exit 2.

    The card's target is a nervous NEW user, and a scripted run must not invent a site name
    or guess a payroll timezone on their behalf.
    """
    monkeypatch.setenv(HOST_PW_ENV, FAKE_PW)
    result = run(["init", "--config", str(tmp_path / "sites.toml"), "--yes"], input="")
    assert result.exit_code == 2, result.stdout
    assert not (tmp_path / "sites.toml").exists()


def test_check_only_writes_nothing(
    tmp_path: Path, device: FakeDevice, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--check-only` is the dry run a nervous user wants first: probe, report, write nothing."""
    monkeypatch.setenv(HOST_PW_ENV, FAKE_PW)
    target = tmp_path / "sites.toml"
    result = run(["init", "--config", str(target), "--yes", "--check-only"], input=answers())
    assert result.exit_code == 0, result.stdout
    assert not target.exists()
    assert "not written" in result.stdout.lower()


def test_declining_the_confirm_writes_nothing_even_with_yes(
    tmp_path: Path, device: FakeDevice, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A transcript that says `no` at the confirm wins over `--yes`.

    `--yes` exists for the case where the stream has run out of lines; it must not silently
    discard an explicit refusal, which is the difference between a scripted convenience and
    a flag that overwrites files on command.
    """
    monkeypatch.setenv(HOST_PW_ENV, FAKE_PW)
    target = tmp_path / "sites.toml"
    result = run(["init", "--config", str(target), "--yes"], input=answers(confirm="no"))
    assert result.exit_code == 0, result.stdout
    assert not target.exists()


# --- no-restart law ------------------------------------------------------------------------------


def test_init_never_starts_a_process_and_never_restarts_a_service() -> None:
    """The card's law: `init` never restarts a service, and never shells out at all.

    Checked structurally (the module's own imports and its use of `os`), the way this repo
    checks its other structural laws. The contrast is deliberate: `sink_cli` DOES reach
    `/usr/bin/security` for an item-existence check (no `-w`, so nothing printable comes
    back), while `init` spawns nothing — it only PRINTS the command for a human to run.
    """
    import ast
    import pathlib

    tree = ast.parse(pathlib.Path(init_cli.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    for banned in ("subprocess", "launchctl", "systemctl"):
        assert banned not in imported, f"init_cli imports {banned} — it must not manage services"

    # `os.open`/`os.replace`/`os.fsync` are the atomic write and are allowed; anything
    # that could exec, spawn or signal is not.
    used: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "os"
        ):
            used.add(node.attr)
    forbidden_os = {"system", "popen", "execv", "execve", "execl", "spawn", "fork", "kill"}
    assert not (used & forbidden_os), f"init_cli uses os.{used & forbidden_os}"
