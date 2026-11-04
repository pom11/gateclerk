"""CLI conventions — the single source for verbs, aliases, and exit codes.

Why a module
------------
Before this existed the exit-code contract lived as four bare integers at the top of
``gateclerk/cli.py``, the verb vocabulary lived nowhere, and the "-o json is PII-free" rule
lived in a docstring in a third file. A convention that lives in three places drifts; this
module is the one place each of them lives, so a new command imports a name instead of
re-deciding a number.

Nothing here builds a CLI — no click or typer import — so a test can read the conventions
without constructing one. The click subclass that *enforces* ``ALIASES`` is
``cli._AliasGroup``, next to the groups it is applied to.

Verb vocabulary
---------------
One canonical verb per kind of generic operation. A command whose operation IS one of
these verbs is named with the canonical spelling; a superseded spelling keeps working as
a hidden alias (``ALIASES``) so no existing script or operator muscle breaks.

  ``list``    enumerate records, no identifying argument        ``users list``, ``sink list``
  ``get``     read one named thing                              (see exception 1)
  ``status``  report the condition of something running         (no command yet — the
              self-check surface is CLI-DOCTOR's, not this module's)
  ``test``    answer "does this resolve / work", no side effects ``creds test``, ``sink test``
  ``add``     create a record                                   ``sink add``
  ``remove``  delete a record the operator already named         ``agent deadletter remove``,
                                                              ``sink remove``

Two exception classes, deliberate rather than accidental:

1. **A read of a specific document keeps the document's noun.** ``device info``,
   ``device time`` and ``device capabilities`` each read a *different* ISAPI document from
   the same device (``System/deviceInfo``, ``System/time``, ``System/capabilities``).
   Renaming ``info`` to ``get`` would leave ``device get`` / ``device time`` / ``device
   capabilities`` — one verb and two nouns for three sibling reads of the same shape,
   which is less coherent than what it replaces, and ``device get-time`` invents a
   hyphenated dialect no other group uses. These are ``get``-class reads; the name is the
   document. Recorded because it is the one place the vocabulary is visibly not applied.

2. **A domain pipeline keeps its stage names.** ``migrate probe|export|diff|apply|undo``
   are the five steps of docs/ENROLLMENT-MIGRATION.md §7 *in order*, and ``agent run`` is a
   systemd ``ExecStart``. Calling ``apply`` "add" costs the operator the §7 numbering that
   the docs, the ``apply --apply`` review gate and the undo journal all speak. The
   vocabulary governs generic verbs; it does not rename a domain's own nouns.

``remove`` is canonical over ``delete`` for one reason beyond taste: the read-only invariant
(DESIGN.md) is enforced by a help-prose tripwire that forbids the word "delete" in
read-only commands' help, so a vocabulary that reaches for ``remove`` cannot accidentally
advertise a write in the wrong group.

Exit codes
----------
The numbers are the **shipped p1-08 contract** and they are load-bearing: ~200 assertions
in ``tests/`` import these names and the live site-a launchd unit plus operator cron
wrappers branch on them. Card CLI-VERBS-HELP proposed a different numbering (2 usage,
3 config, 4 credential, 5 unreachable, 6 push). Adopting it would renumber config from 2
to 3 — a silent break for every wrapper already deployed, which that same card forbids
("no behavior churn"). So the shipped numbers stay authoritative, and the proposal is
recorded here as what each code *means*, merged where the classes genuinely coincide::

  0  OK                       everything worked
  1  generic error            unexpected failure. Currently unraised on purpose: every
                              path in this CLI is classified, and an unclassified
                              exception is allowed to crash with a traceback rather than
                              be laundered into a number an operator would read as
                              "expected and branchable"
  2  usage / config /         the operator has not told the CLI how to reach the thing,
     credential / bad input   or what they told it is unusable. MERGED deliberately:
                              click already exits 2 on a usage error and p1-08 already
                              exits 2 on a config error, so no script can distinguish
                              them today either way; splitting them means changing one of
                              the two numbers, which is a behavior change, not a
                              refactor
  3  terminal auth            401, circuit opened to avoid an account lockout; a human
                              must verify the credential (``gateclerk creds test``). p1-01's
                              NOT_IMPLEMENTED_EXIT was also 3, which made "not built yet"
                              and "authenticated and refused" the same number; every stub
                              is implemented, so 3 means terminal-auth and nothing else
  4  device / protocol        the box answered and was not usable, or the host name never
                              made it to the resolver at all (unresolvable, or unencodable:
                              `[Errno 8]`, `UnicodeError`/`idna.IDNAError` from the idna
                              step — the transport classifies an unresolvable name as
                              transport, and test_cli_idna_hosts.py pins it). Includes the
                              proposal's "5 device unreachable"
  5  runaway paging           the device kept saying MORE past the paging cap
  6  push failure             RESERVED for the push lane (the proposal's 6). No command
                              emits it yet: ``agent run`` maps a parked device / open
                              circuit to 3 today and that is pinned by test, so wiring 6
                              in means moving that pin deliberately, not as a side effect

Order matters in :func:`exit_code_for`: ``IsapiAuthError`` is an ``IsapiError``, and the
search errors are ``GateClerkError``s, so the specific classes are tested before the general
ones — the same order ``cli._fail`` documented, now in one importable place.
"""

from __future__ import annotations

from enum import IntEnum

from gateclerk.exceptions import (
    ConfigError,
    CredentialUnavailable,
    EventBoundsError,
    GateClerkError,
    IsapiAuthError,
    IsapiError,
    SearchProtocolError,
    SearchRunawayError,
)
from gateclerk.tz import TimestampInputError

__all__ = [
    "ALIASES",
    "AUTH_TERMINAL_EXIT",
    "CONFIG_ERROR_EXIT",
    "DEVICE_ERROR_EXIT",
    "RUNAWAY_EXIT",
    "VERBS",
    "ExitCode",
    "exit_code_for",
    "resolve_alias",
]


class ExitCode(IntEnum):
    """Every exit code this CLI can return, named. See the table in the module docstring."""

    OK = 0
    ERROR = 1
    USAGE_OR_CONFIG = 2
    AUTH_TERMINAL = 3
    DEVICE = 4
    RUNAWAY = 5
    PUSH_FAILURE = 6


#: p1-08's shipped names, kept as plain ints because other cards' tests import them from
#: `gateclerk.cli`. The enum above is the source; these are handles onto it.
CONFIG_ERROR_EXIT = int(ExitCode.USAGE_OR_CONFIG)
AUTH_TERMINAL_EXIT = int(ExitCode.AUTH_TERMINAL)
DEVICE_ERROR_EXIT = int(ExitCode.DEVICE)
RUNAWAY_EXIT = int(ExitCode.RUNAWAY)

#: The canonical verbs, in the docstring's order. `tests/test_cli_conventions.py` reads
#: this so the documented list and the list a test enforces cannot drift apart.
VERBS: tuple[str, ...] = ("list", "get", "status", "test", "add", "remove")

#: ``{group_path: {alias: canonical_subcommand}}``.
#:
#: Hidden on purpose: an alias resolves on the command line but never enters
#: ``Group.commands``, so `--help` shows one spelling per operation (a surface with
#: `delete` AND `remove` listed teaches the operator nothing) while every pinned
#: "the surface is exactly these commands" test keeps its meaning, and every existing
#: script keeps working.
#:
#: Only spellings whose canonical target exists are listed — an alias to a missing command
#: would silently turn a typo into a different operation.
ALIASES: dict[tuple[str, ...], dict[str, str]] = {
    ("creds",): {"check": "test"},
    ("agent", "deadletter"): {"delete": "remove"},
}


def resolve_alias(group_path: tuple[str, ...], name: str) -> str | None:
    """The canonical subcommand `name` stands for inside `group_path`, else None.

    Separate from the click subclass so the resolution rule is testable without a CLI.
    """
    return ALIASES.get(group_path, {}).get(name)


def exit_code_for(exc: BaseException) -> int:
    """Map an exception onto its documented exit code — the CLI's single mapping.

    Raises ``KeyError`` for a class that is not classified, and the caller re-raises: an
    unclassified bug must not be laundered into a number that reads as a known failure.
    """
    if isinstance(exc, IsapiAuthError):
        return int(ExitCode.AUTH_TERMINAL)
    if isinstance(exc, SearchRunawayError):
        return int(ExitCode.RUNAWAY)
    if isinstance(
        exc, ConfigError | CredentialUnavailable | TimestampInputError | EventBoundsError
    ):
        return int(ExitCode.USAGE_OR_CONFIG)
    if isinstance(exc, SearchProtocolError | IsapiError):
        return int(ExitCode.DEVICE)
    if isinstance(exc, GateClerkError):
        return int(ExitCode.DEVICE)
    raise KeyError(f"unclassified exception {type(exc).__name__!r} — no exit code defined")
