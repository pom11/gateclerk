"""Pins for the static deploy templates in `deploy/` (docs/P2-SITE-AGENT.md §2d, §6(d)).

What these tests are FOR: a committed deploy artifact is the one place in this repo whose
whole job is to name where a service runs, which makes it the likeliest place for a real
device address or a real credential to be pasted in. So the pins are of two kinds:

1. **Structure.** The systemd unit is a template-per-site (`gateclerk-agent@<site>.service`)
   with `LoadCredential=` carrying the `gateclerk-<site>-<host>` reference name, the pinned
   restart policy and the pinned hardening lines; the launchd file parses with `plistlib`,
   carries `KeepAlive`, uses the same reference naming, and says out loud that it is an
   EXAMPLE (§2d: agents run on Linux/Windows, macOS is the dev box).
2. **Hygiene.** A regex scan over every byte of the deploy surface for secret shapes and
   for addresses outside the RFC 5737 documentation ranges — the same policy
   `tests/test_repo_hygiene.py` enforces on test material, widened to `deploy/`.

What these tests are deliberately NOT: they do not import any deploy-rendering module and
they do not shell out to `systemd-analyze` or `launchctl`. This card owns *static templates
only*; the renderer, the `gateclerk agent` CLI and the credential-file reader are P2-07b, and
the spec names no renderer for the templates at all (`§6(d)` fixes only the naming
convention). Parsing is therefore done here, against the checked-in bytes, with the tiny
unit-file reader below — so a green run means the file on disk is what the spec requires,
not that some code agrees with itself.

The per-site "render" these tests exercise is plain placeholder substitution (`render()`
below), which is exactly what an operator does by hand and what a future renderer must
implement. The angle-bracket tokens are NOT systemd specifiers: systemd expands only `%i`
(the instance name = the site name), so anything left un-substituted fails at `ExecStart`
loudly rather than running a wrong agent.
"""

from __future__ import annotations

import ipaddress
import plistlib
import re
from pathlib import Path

import pytest

from gateclerk.config import PUSH_TARGET_SCHEMES, credential_ref

REPO_ROOT = Path(__file__).resolve().parents[1]
DEPLOY = REPO_ROOT / "deploy"

UNIT_TEMPLATE = DEPLOY / "gateclerk-agent@.service"
PLIST_TEMPLATE = DEPLOY / "gateclerk-agent.plist"
README = DEPLOY / "README.md"

#: The whole surface this card owns — a fourth file here is scope creep (card rule).
OWNED_FILES = (UNIT_TEMPLATE, PLIST_TEMPLATE, README)

#: The device hosts used anywhere in the deploy surface must be documentation-range
#: placeholders (RFC 5737 TEST-NET), same allowlist as tests/test_repo_hygiene.py.
TEST_NET_1 = "192.0.2.10"
TEST_NET_2 = "192.0.2.11"
DOC_RANGES = tuple(
    ipaddress.ip_network(net) for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)

#: Where the 0600 credential *source* files live (persistent, NOT /run — see the unit).
CREDENTIAL_DIR = "/etc/gateclerk/credentials"

#: Substitution values used to "render" a site out of the template in these tests. The
#: values are arbitrary: the tests pin that the template *names* these places, not that it
#: picks any particular one (there is deliberately no default endpoint or default path in
#: the product, so the template must not invent one either).
STATE_ROOT = "/srv/gateclerk-state"
CONFIG_PATH = "/etc/gateclerk/sites.toml"
EXEC_START = "/opt/gateclerk/venv/bin/gateclerk"
PYTHON_BIN = "/opt/gateclerk/venv/bin/python"

# --- the scans every deploy file must survive -----------------------------------------

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

#: An assignment-shaped secret — a unit/ini/plist line that would carry a value. Prose
#: about passwords ("the password never appears here") is not a finding; `password=` is.
SECRET_ASSIGNMENT = re.compile(
    r"(?im)^\s*(?:environment\s+)?[\"']?"
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|authorization)[\"']?\s*[:=]"
)
#: A quoted key/value pair shaped like a credential (the JSON/plist/ini shape).
SECRET_QUOTED = re.compile(
    r"(?i)[\"'](password|passwd|pwd|secret|token|api[_-]?key|authorization)[\"']\s*[:=]\s*"
    r"[\"'][^\"']+[\"']"
)
#: A pasted private key.
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
#: Hostname-shaped literals. The allowlist is the repo's own URL plus Apple's DTD URL and
#: the RFC 2606 documentation domains — a real site's host or a real ingest endpoint is not.
HOSTNAME = re.compile(
    r"\b[a-z0-9][a-z0-9_-]*(?:\.[a-z0-9][a-z0-9_-]*)+\.(?:com|net|org|io|dev|local|"
    r"internal|intranet|lan|corp|home)\b"
)
ALLOWED_HOSTNAMES = frozenset(
    {
        "github.com",  # Documentation= URL / repo links
        "www.apple.com",  # the plist DTD declaration
        "example.com",
        "www.example.com",
        "example.org",
        "example.net",
    }
)


def _allowed_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_loopback or any(ip in net for net in DOC_RANGES)


def deploy_text(path: Path) -> str:
    assert path.is_file(), f"missing deploy artifact: {path.relative_to(REPO_ROOT)}"
    text = path.read_text(encoding="utf-8")
    assert text.strip(), f"empty deploy artifact: {path.relative_to(REPO_ROOT)}"
    return text


@pytest.fixture(scope="module")
def unit_template() -> str:
    return deploy_text(UNIT_TEMPLATE)


@pytest.fixture(scope="module")
def plist_template() -> str:
    return deploy_text(PLIST_TEMPLATE)


@pytest.fixture(scope="module")
def readme() -> str:
    return deploy_text(README)


# --- the two tiny readers these tests need (unit file, plist) --------------------------


def unit_directives(text: str) -> dict[str, list[tuple[str, str]]]:
    """Active `Key=value` pairs of a unit file, grouped by `[Section]`.

    Comments (`#`, `;`) and blank lines are dropped, because in this repo the prose IS the
    documentation and half of the unit file is comments. Any active line that is neither a
    section header nor a `Key=value` pair is a template bug — prose leaking out of a comment
    would otherwise silently become a directive, and a typo'd directive is a unit that
    either fails to load or quietly does the wrong thing.
    """
    parsed: dict[str, list[tuple[str, str]]] = {}
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            parsed.setdefault(section, [])
            continue
        if "=" not in line:
            raise AssertionError(
                f"unit file line outside a directive/comment form: {line!r} "
                f"(every active line must be `[Section]` or `Key=value`)"
            )
        key, _, value = line.partition("=")
        parsed.setdefault(section, []).append((key.strip(), value.strip()))
    return parsed


def only(parsed: dict[str, list[tuple[str, str]]], section: str, key: str) -> str:
    """The single value of `Key` in `[Section]` — asserting it appears exactly once."""
    hits = [value for name, value in parsed.get(section, []) if name == key]
    assert len(hits) == 1, f"expected exactly one {key}= in [{section}], found {len(hits)}: {hits}"
    return hits[0]


def values(parsed: dict[str, list[tuple[str, str]]], section: str, key: str) -> list[str]:
    return [value for name, value in parsed.get(section, []) if name == key]


def render(text: str, *, site: str, host: str, **overrides: str) -> str:
    """The per-site substitution the template expects: every `<TOKEN>` gets a value.

    `<SITE>`/`<HOST>` are the two that the spec makes per-site (`gateclerk-<site>-<host>`);
    the rest are the install-time choices the README documents. A token with no value here
    stays in the output, which is how the "no placeholder left behind" test bites.
    """
    tokens = {
        "<SITE>": site,
        "<HOST>": host,
        "<STATE_ROOT>": STATE_ROOT,
        "<CONFIG_PATH>": CONFIG_PATH,
        "<EXEC_START>": EXEC_START,
        "<PYTHON_BIN>": PYTHON_BIN,
        "<CREDENTIAL_DIR>": CREDENTIAL_DIR,
    }
    tokens.update(overrides)
    for token, value in tokens.items():
        text = text.replace(token, value)
    return text


REMAINING_PLACEHOLDER = re.compile(r"<[A-Z][A-Z0-9_]*>")


# --- 0. the surface is exactly the three static files this card owns -------------------


def test_deploy_dir_holds_only_the_three_static_artifacts() -> None:
    assert DEPLOY.is_dir(), "deploy/ must exist (this card owns it)"
    found = sorted(p.name for p in DEPLOY.iterdir() if p.is_file())
    assert found == ["README.md", "gateclerk-agent.plist", "gateclerk-agent@.service"], (
        f"deploy/ must hold exactly the templates + README, found {found}"
    )


def test_deploy_surface_ships_no_runtime_code() -> None:
    """This card is templates only: no Python may hide under deploy/.

    `gateclerk agent run` (the command ExecStart names) exists from P2-07b; a renderer or a
    credential reader smuggled in here would be runtime code this card does not own, and
    would make the "nothing imports the templates" property untestable.
    """
    strays = sorted(p.relative_to(REPO_ROOT).as_posix() for p in DEPLOY.rglob("*.py"))
    assert not strays, f"deploy/ must be static; found Python: {strays}"


# --- 1. the systemd unit: template-per-site shape --------------------------------------


def test_unit_is_a_template_unit_instanced_per_site(unit_template: str) -> None:
    # systemd's template-unit convention: the file name ends in `@.service` and the
    # instance (the site name) arrives as the `%i` specifier.
    assert UNIT_TEMPLATE.name == "gateclerk-agent@.service"
    parsed = unit_directives(unit_template)
    assert set(parsed) >= {"Unit", "Service", "Install"}, f"sections: {sorted(parsed)}"
    exec_start = only(parsed, "Service", "ExecStart")
    assert "--site %i" in exec_start, (
        f"ExecStart must bind the unit instance to the site it serves, got {exec_start!r}"
    )
    assert " agent run " in f" {exec_start} ", f"ExecStart must run the agent: {exec_start!r}"
    # `--once` under Restart=always is a five-second poll of a door controller.
    assert "--once" not in exec_start, "the unit must run the long-lived form, never --once"


def test_unit_exec_start_is_config_referenced_and_state_is_per_site(unit_template: str) -> None:
    parsed = unit_directives(unit_template)
    exec_start = only(parsed, "Service", "ExecStart")
    assert "<CONFIG_PATH>" in exec_start, (
        "ExecStart must name the sites.toml it reads (a config file of refs only) — "
        f"got {exec_start!r}"
    )
    assert exec_start.startswith("<EXEC_START>"), (
        f"the entry point must be a documented placeholder, not a baked-in path: {exec_start!r}"
    )
    working = only(parsed, "Service", "WorkingDirectory")
    assert working == "<STATE_ROOT>", f"WorkingDirectory must be the state root: {working!r}"
    assert "<STATE_ROOT>" in only(parsed, "Service", "ReadWritePaths"), (
        "the single writable path must live under the working state root"
    )


def test_unit_restart_policy_is_pinned(unit_template: str) -> None:
    """§2d: Restart=always + RestartSec=5 — a dead agent means silent punch loss."""
    parsed = unit_directives(unit_template)
    assert only(parsed, "Service", "Restart") == "always"
    assert only(parsed, "Service", "RestartSec") == "5"


def test_unit_hardening_lines_are_pinned(unit_template: str) -> None:
    """The read-only promise expressed as mount policy (§1.8: no device writes ever)."""
    parsed = unit_directives(unit_template)
    assert only(parsed, "Service", "NoNewPrivileges") == "yes"
    assert only(parsed, "Service", "ProtectSystem") == "strict"
    writable = values(parsed, "Service", "ReadWritePaths")
    assert len(writable) == 1, f"exactly one writable location: {writable}"
    assert writable[0].startswith("<STATE_ROOT>/"), (
        f"the one writable path must be the site's own state dir: {writable[0]!r}"
    )
    for key, want in (
        ("ProtectHome", "yes"),
        ("PrivateTmp", "yes"),
        ("User", "gateclerk"),
    ):
        assert only(parsed, "Service", key) == want


def test_unit_load_credential_carries_the_reference_name_and_never_a_value(
    unit_template: str,
) -> None:
    """§2d naming: `LoadCredential=gateclerk-<site>-<host>:<path>`, names only.

    One active line only (the template carries one device; a second device is a drop-in),
    it must point into the persistent credential dir, and there must be no `SetCredential=`
    anywhere: unit files are world-readable, so a literal there is a published secret.
    """
    parsed = unit_directives(unit_template)
    lines = values(parsed, "Service", "LoadCredential")
    assert len(lines) == 1, f"expected one rendered credential reference, found {lines}"
    name, _, source = lines[0].partition(":")
    assert name == "gateclerk-<SITE>-<HOST>", (
        f"credential name must be the §2d convention, got {name!r}"
    )
    assert source.startswith(f"{CREDENTIAL_DIR}/gateclerk-<SITE>-<HOST>"), (
        f"source file must live in the persistent credential dir, got {source!r}"
    )
    assert source.endswith(".txt")
    assert not values(parsed, "Service", "SetCredential"), (
        "SetCredential= would put a literal secret in a world-readable unit file"
    )
    assert not values(parsed, "Service", "Environment"), (
        "no Environment= line: the value arrives via the credentials directory or the "
        "resolver's own env rung, never via this file"
    )
    # ...and the naming convention must be the one the runtime resolver uses.
    assert credential_ref("site-a", TEST_NET_1) == "gateclerk-site-a-192.0.2.10"


def test_unit_documents_the_drop_in_credential_placement(unit_template: str) -> None:
    """The template unit cannot know the device host (%i is the site only), so both install
    paths are written in the file itself: render the line, or drop in a per-site
    `10-credentials.conf`. An operator must not have to read the README to find this.
    """
    comments = "\n".join(
        line for line in unit_template.splitlines() if line.strip().startswith("#")
    )
    assert "LoadCredential=" in comments, "the credential rule must be explained, not just coded"
    assert "credential_ref" in comments, (
        "the unit must name the helper that produces the reference, so the naming cannot "
        "drift from the resolver"
    )
    assert "gateclerk-agent@<SITE>.service.d/10-credentials.conf" in comments
    assert "install -m 0600" in comments, "the source file's mode must be documented"
    assert "%i" in comments, "the unit must say that %i is the site and NOT the device host"


def test_unit_credentials_are_not_sourced_from_tmpfs(unit_template: str) -> None:
    """/run is tmpfs: a credential placed there is gone at the next reboot and
    `Restart=always` would then restart the unit into a missing credential forever."""
    parsed = unit_directives(unit_template)
    for line in values(parsed, "Service", "LoadCredential"):
        assert ":/run/" not in line and ":/tmp/" not in line, f"tmpfs credential source: {line!r}"


def test_unit_hardening_comment_lines_cannot_become_directives(unit_template: str) -> None:
    """Guard the reader that the other tests rely on: every non-comment line is a directive.

    The unit file is heavily commented on purpose; if a comment lost its `#`, systemd would
    read it as a directive (or fail to load the unit). This pins the invariant, so a future
    edit cannot turn prose into configuration.
    """
    for raw in unit_template.splitlines():
        line = raw.strip()
        if not line:
            continue
        assert (
            line.startswith("#") or line.startswith(";") or line.startswith("[") or "=" in line
        ), f"uncommented prose in the unit file: {line!r}"


# --- 2. per-site render: the placeholders must actually substitute ---------------------


@pytest.mark.parametrize(
    ("site", "host"),
    [("site-a", TEST_NET_1), ("site-b", TEST_NET_2), ("office.1", "198.51.100.7")],
)
def test_rendered_unit_leaves_no_placeholder_behind(
    unit_template: str, site: str, host: str
) -> None:
    """A token left in place is a broken agent; better the test fails than the box."""
    rendered = render(unit_template, site=site, host=host)
    left = sorted(set(REMAINING_PLACEHOLDER.findall(rendered)))
    assert not left, f"un-substituted placeholders after a per-site render: {left}"


@pytest.mark.parametrize(
    ("site", "host"),
    [("site-a", TEST_NET_1), ("site-b", TEST_NET_2)],
)
def test_rendered_unit_names_this_site_and_nothing_else(
    unit_template: str, site: str, host: str
) -> None:
    """One unit = one site = one store: the rendered file must not be able to reach a
    neighbouring site's state or credentials."""
    other_site, other_host = ("site-b", TEST_NET_2) if site == "site-a" else ("site-a", TEST_NET_1)
    rendered = render(unit_template, site=site, host=host)
    parsed = unit_directives(rendered)

    assert only(parsed, "Service", "ExecStart").startswith(EXEC_START)
    # `%i` stays as-is: systemd expands the instance name at start time, so the operator
    # substitutes the *paths* and systemd supplies the site.
    assert "--site %i" in only(parsed, "Service", "ExecStart")
    assert f"--config {CONFIG_PATH}" in only(parsed, "Service", "ExecStart")
    assert only(parsed, "Service", "ReadWritePaths") == f"{STATE_ROOT}/{site}"

    credential = only(parsed, "Service", "LoadCredential")
    assert credential == (
        f"{credential_ref(site, host)}:{CREDENTIAL_DIR}/{credential_ref(site, host)}.txt"
    ), "the rendered credential name must be exactly config.credential_ref(site, host)"
    assert other_site not in rendered, f"rendered unit leaked the neighbouring site {other_site}"
    assert other_host not in rendered, f"rendered unit leaked the neighbouring host {other_host}"


def test_two_sites_on_one_box_get_two_independent_units(unit_template: str) -> None:
    """§1.5: N sites = 1 codebase + configs. Two renders differ ONLY in site-scoped text,
    so a box running both sites has two stores, two parks and two credential sets."""
    a = render(unit_template, site="site-a", host=TEST_NET_1)
    b = render(unit_template, site="site-b", host=TEST_NET_2)
    diff = [(x, y) for x, y in zip(a.splitlines(), b.splitlines(), strict=True) if x != y]
    assert diff, "two sites must not render byte-identical units"
    for left, right in diff:
        assert ("site-a" in left) or ("192.0.2.10" in left), (
            f"non-site-scoped line differs between sites: {left!r} != {right!r}"
        )


# --- 3. the launchd file: an EXAMPLE that still parses ---------------------------------


def test_plist_is_parseable_by_plistlib(plist_template: str) -> None:
    """A plist with one unclosed tag is a job that never loads, silently."""
    payload = plistlib.loads(plist_template.encode("utf-8"))
    assert isinstance(payload, dict)


def test_plist_declares_itself_an_example(plist_template: str) -> None:
    """§2d: agents run on Linux/Windows; macOS is the dev box, so this file is EXAMPLE
    material. A reader must not mistake it for a supported install path.

    Pinned on the file's OWN words, not on a mention of this test suite: "EXAMPLE" alone is
    too weak (a comment about these tests would satisfy it), so the header must also say it
    is not a product.
    """
    head = "\n".join(plist_template.splitlines()[:60])
    assert "EXAMPLE" in head, (
        "the EXAMPLE marking must be in the first screenful of the file "
        "(§2d: macOS is the dev box, this file is not a supported install path)"
    )
    assert "NOT A PRODUCT" in head.upper(), (
        "the header must disclaim product status in its own words, not merely say 'example'"
    )


def test_plist_keep_alive_matches_the_restart_semantics(plist_template: str) -> None:
    payload = plistlib.loads(plist_template.encode("utf-8"))
    assert "KeepAlive" in payload, "launchd's Restart=always equivalent is KeepAlive"
    assert payload["ThrottleInterval"] == 5, "launchd's RestartSec=5 equivalent is ThrottleInterval"


def test_plist_runs_the_same_agent_command_for_one_site(plist_template: str) -> None:
    payload = plistlib.loads(plist_template.encode("utf-8"))
    args = [str(arg) for arg in payload["ProgramArguments"]]
    assert "agent" in args and "run" in args, f"ProgramArguments: {args}"
    assert args[args.index("--site") + 1] == "SITE_LABEL", (
        "the job must be per-site, named the way the systemd instance is"
    )
    assert args[args.index("--config") + 1] == "CONFIG_PATH"
    assert "--once" not in args, "KeepAlive + --once would hammer the device every few seconds"
    assert payload["WorkingDirectory"] == "STATE_DIR"
    for arg in args:
        assert not REMAINING_PLACEHOLDER.search(arg), f"angle-bracket token in {arg!r}"


def test_plist_credential_block_carries_refs_only(plist_template: str) -> None:
    """launchd has no `LoadCredential=`. The example therefore names the reference (same
    `gateclerk-<site>-<host>` convention) and carries NO value: a secret in a plist is
    plaintext to the whole user session."""
    begin = plist_template.index("gateclerk-credential-refs-begin")
    end = plist_template.index("gateclerk-credential-refs-end")
    assert begin < end, "credential-ref markers are out of order"
    block = plist_template[begin:end]
    assert "gateclerk-SITE_LABEL-HOST" in block, (
        "the plist must use the same credential reference naming as the systemd unit"
    )
    payload = plistlib.loads(plist_template.encode("utf-8"))
    env = payload.get("EnvironmentVariables", {})
    for name, value in env.items():
        assert not re.search(r"(?i)password|secret|token", str(name)), (
            f"credential-shaped environment key {name!r} in a plist"
        )
        assert not re.search(r"(?i)password|secret|token", str(value)), (
            f"credential-shaped environment value for {name!r} in a plist"
        )


def test_plist_render_substitutes_the_site(plist_template: str) -> None:
    """The example's tokens substitute cleanly for a real dev-box site."""
    rendered = (
        plist_template.replace("SITE_LABEL", "site-a")
        .replace("STATE_DIR", STATE_ROOT + "/site-a")
        .replace("CONFIG_PATH", CONFIG_PATH)
        .replace("PYTHON_BIN", PYTHON_BIN)
        .replace("HOST", TEST_NET_1)
    )
    payload = plistlib.loads(rendered.encode("utf-8"))
    assert payload["Label"] == "com.gateclerk.agent.site-a"
    args = [str(a) for a in payload["ProgramArguments"]]
    assert args[args.index("--site") + 1] == "site-a"
    assert "gateclerk-site-a-192.0.2.10" in rendered


# --- 4. the README: the walkthrough the templates cannot carry --------------------------

REQUIRED_README_TOPICS = (
    "gateclerk-agent@.service",
    "LoadCredential=",
    "gateclerk-<site>-<host>",
    "10-credentials.conf",
    f"{CREDENTIAL_DIR}/",
    "systemd-run",
    "systemctl daemon-reload",
    "systemd-creds",
    "agent run --site",
    "--config",
    "WorkingDirectory",
    "ReadWritePaths",
    "RestartSec",
    "KeepAlive",
    "launchd",
    "Windows",
    "TEST-NET",
    "stub://",
    "https://",
)


@pytest.mark.parametrize("topic", REQUIRED_README_TOPICS)
def test_readme_documents_the_install_walkthrough(readme: str, topic: str) -> None:
    """Where the credential goes, how the unit gets rendered without a renderer, and how
    to prove the install worked — the three things a template file cannot say about itself."""
    assert topic in readme, f"deploy/README.md must document {topic!r}"


def test_readme_states_there_is_no_default_endpoint(readme: str) -> None:
    """§3 / config.PUSH_TARGET_SCHEMES: refs only, never a default push endpoint."""
    assert PUSH_TARGET_SCHEMES == ("stub://", "https://")
    lowered = readme.lower()
    assert "never a default" in lowered or "no default endpoint" in lowered
    assert "sites.toml" in readme


def test_readme_documents_the_drop_in_credential_placement(readme: str) -> None:
    """The card's binding rule: WorkingDirectory + --config path + drop-in credential
    placement, all documented. Pinned as *shapes an operator can copy*, not as prose: a
    drop-in whose directory is renamed, or a LoadCredential= line that does not follow the
    §2d naming, both leave an operator with a unit that silently has no credential."""
    assert (
        "gateclerk-agent@<site>.service.d/" in readme or "gateclerk-agent@.service.d/" in readme
    ), "the drop-in directory must be named in its real systemd form"
    assert "LoadCredential=gateclerk-" in readme, "the credential line shape must be shown"
    # ...and at least one fully rendered instance of it, naming site AND host the way
    # credential_ref does, because that is what an operator actually pastes.
    rendered_cred = re.search(
        r"LoadCredential=gateclerk-[a-z0-9._-]+-[0-9]{1,3}(?:\.[0-9]{1,3}){3}"
        r":/etc/gateclerk/credentials/gateclerk-[a-z0-9._-]+-[0-9]{1,3}(?:\.[0-9]{1,3}){3}\.txt",
        readme,
    )
    assert rendered_cred, (
        "the README must show at least one fully rendered LoadCredential= line "
        "(gateclerk-<site>-<host>:<credential dir>/gateclerk-<site>-<host>.txt)"
    )
    assert "0600" in readme
    # ...and the copy-pasteable command itself must target that directory, not merely have
    # the directory named somewhere in the prose.
    assert re.search(
        r"/etc/systemd/system/gateclerk-agent@[a-z0-9._-]+\.service\.d/10-credentials\.conf",
        readme,
    ), "the README's own install command must write the drop-in to the real drop-in dir"


def test_readme_points_at_the_command_the_unit_runs(readme: str) -> None:
    """`gateclerk agent run` lands in P2-07b. The README must say so rather than implying
    today's CLI has it — a template that names a command nobody shipped is a dead unit."""
    assert "P2-07b" in readme, "the README must name where `agent run` comes from"
    # ...and it must be stated in the render/install section, not only in the introduction,
    # so a reader jumping straight to the commands cannot miss that the command does not
    # exist yet.
    step2 = readme[readme.index("## 2. Render") : readme.index("## 3.")]
    assert "P2-07b" in step2, (
        "the render/install section must flag that `agent run` arrives in P2-07b"
    )


# --- 5. hygiene scan over the whole deploy surface (card rule: no real hosts/IPs) -------


@pytest.mark.parametrize("path", OWNED_FILES, ids=lambda p: p.name)
def test_no_address_outside_documentation_ranges(path: Path) -> None:
    text = deploy_text(path)
    offenders = sorted({ip for ip in IPV4.findall(text) if not _allowed_ip(ip)})
    assert not offenders, (
        f"{path.relative_to(REPO_ROOT)} names a non-documentation address {offenders}: "
        "a device host is config (sites.toml), never a committed template"
    )


@pytest.mark.parametrize("path", OWNED_FILES, ids=lambda p: p.name)
def test_no_secret_shaped_assignment(path: Path) -> None:
    text = deploy_text(path)
    offenders = sorted({m.group(0).strip() for m in SECRET_ASSIGNMENT.finditer(text)})
    offenders += sorted({m.group(0).strip() for m in SECRET_QUOTED.finditer(text)})
    assert not offenders, (
        f"{path.relative_to(REPO_ROOT)} carries a secret-shaped assignment {offenders}: "
        "these files carry references (LoadCredential=, credential_ref), never values"
    )


@pytest.mark.parametrize("path", OWNED_FILES, ids=lambda p: p.name)
def test_no_private_key_material(path: Path) -> None:
    assert not PRIVATE_KEY.search(deploy_text(path))


@pytest.mark.parametrize("path", OWNED_FILES, ids=lambda p: p.name)
def test_no_unexpected_hostname_literals(path: Path) -> None:
    """Placeholder hosts / documentation domains only (card rule)."""
    text = deploy_text(path)
    offenders = sorted(
        {m.group(0) for m in HOSTNAME.finditer(text.lower()) if m.group(0) not in ALLOWED_HOSTNAMES}
    )
    assert not offenders, (
        f"{path.relative_to(REPO_ROOT)} names a real-looking host {offenders}: only the repo "
        "URL, Apple's DTD URL and the RFC 2606 example domains may appear here"
    )


@pytest.mark.parametrize("path", OWNED_FILES, ids=lambda p: p.name)
def test_files_are_utf8_and_newline_terminated(path: Path) -> None:
    raw = path.read_bytes()
    assert raw.endswith(b"\n"), f"{path.relative_to(REPO_ROOT)} must end with a newline"
    assert b"\r\n" not in raw, f"{path.relative_to(REPO_ROOT)} must not carry CRLF"
    raw.decode("utf-8")  # a template with a stray byte is a broken unit file
