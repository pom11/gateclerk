# CLI conventions — verbs, aliases, exit codes, `-o json`

Single source: `src/gateclerk/cli_conventions.py`. This page is the operator-facing
version of it; if the two disagree, the module wins and this file is a bug.

Card CLI-VERBS-HELP normalized the surface. Nothing here changes what a working
script does: every command that worked before still works, with the same flags and
the same exit codes.

## Verbs

One canonical verb per generic operation. A command that *is* one of these operations
spells it this way; superseded spellings keep working as hidden aliases.

| verb     | means                                                   | command |
|----------|---------------------------------------------------------|---------|
| `list`   | enumerate records; no identifying argument               | `users list`, `agent deadletter list`, `sink list` |
| `get`    | read one named thing                                     | (see exception 1) |
| `status` | report the condition of something that is running        | `status` |
| `test`   | answer "does this resolve / work", with no side effect   | `creds test`, `sink test` |
| `add`    | create a record                                          | `sink add` |
| `remove` | delete a record the operator already named               | `agent deadletter remove`, `sink remove` |

Hidden aliases (`gateclerk.cli_conventions.ALIASES`):

| old spelling              | canonical                 |
|---------------------------|---------------------------|
| `gateclerk creds check`     | `gateclerk creds test`      |
| `gateclerk agent deadletter delete` | `gateclerk agent deadletter remove` |

Hidden means: the alias resolves on the command line but is not declared as a
command, so `--help` lists one spelling per operation. That is deliberate — printing
`delete` and `remove` side by side tells the operator nothing about which to type, and
a surface test that must allow both spellings stops catching real additions. The
alias is resolved only *after* the real command lookup misses, so an alias can never
shadow a command and a typo still exits 2.

### Two exception classes, on purpose

1. **A read of a specific document keeps the document's noun.** `device info`,
   `device time` and `device capabilities` read three different ISAPI documents
   (`System/deviceInfo`, `System/time`, `System/capabilities`) from one device. They
   are all `get`-class operations, but renaming only `info` to `get` would leave
   `device get` next to `device time` and `device capabilities` — one verb plus two
   nouns for three sibling reads, which is less coherent than what it replaced. The
   name here is the document, as it is in the ISAPI spec.

2. **A domain pipeline keeps its stage names, and a process command keeps its process
   verb.** `migrate probe|export|diff|apply|undo` are the five steps of
   `docs/ENROLLMENT-MIGRATION.md` §7 *in order*, and `agent run` / `demo device serve` start
   a long-lived process rather than reading or writing a record — neither is a generic CRUD
   verb, so neither is renamed to one. Calling `apply` "add" would cost the operator the §7
   numbering that the docs, the `apply --apply` review gate and the undo journal all refer
   to. The vocabulary governs generic verbs; it does not rename a domain's own nouns.

`remove` is canonical over `delete` for a reason beyond taste: this connector must
never grow a write surface, and that rule is enforced by a test that forbids the word
"delete" in read-only help prose. A vocabulary that reaches for `remove` cannot
accidentally advertise a write in the wrong group.

## Exit codes

The numbers are p1-08's shipped contract and are load-bearing — the live site-a
launchd unit and operator cron wrappers branch on them, and roughly two hundred test
assertions import these names. Card CLI-VERBS-HELP proposed a different numbering;
adopting it would renumber "config error" from 2 to 3, silently breaking every
wrapper already deployed, which the same card forbids. So the shipped numbers stand
and the proposed classes are recorded here merged where they coincide.

| code | class | what it means |
|------|-------|---------------|
| 0 | ok | everything worked |
| 1 | generic error | unexpected failure. **Currently never returned**: every path is classified, and an unclassified exception is allowed to crash with a traceback rather than be laundered into a number an operator would read as expected-and-branchable |
| 2 | usage / config / credential / bad input | you have not told the CLI how to reach the thing, or what you told it is unusable |
| 3 | terminal auth | 401, circuit opened to avoid an account lockout. A human must verify the credential (`gateclerk creds test`) |
| 4 | device / protocol | the box answered and was not usable, or the host name never resolved |
| 5 | runaway paging | the device kept saying MORE past the paging cap |
| 6 | push failure | **reserved for the push lane**: `gateclerk doctor` returns it when its push probe fails (push-lane failure — a failed sink/TLS check or dead-letter rows; see `src/gateclerk/doctor_cli.py`). No other command may return it without updating this file first |

Two decisions worth stating plainly:

- **2 is merged on purpose.** Click already exits 2 on a usage error and p1-08 already
  exits 2 on a config error, so no script can distinguish them today either way.
  Splitting them means changing one of the two numbers, which is a behavior change
  rather than a refactor. See "Left" in the card handoff.
- **6 is reserved for the push lane and `doctor` wires it.** `gateclerk doctor` returns
  6 when its push probe fails (a failed sink/TLS check or dead-letter rows; see
  `src/gateclerk/doctor_cli.py`). `agent run` maps a parked device or an open circuit to
  3 today and a test pins that. Only the push lane owns 6: no other command may return it
  without updating this file first.

Mapping is one function — `cli_conventions.exit_code_for` — and `cli._fail` delegates
to it, so a command body cannot pick a different number for the same failure. The
order inside it matters: `IsapiAuthError` *is an* `IsapiError`, and the search errors
*are* `GateClerkError`s, so specific classes are tested before general ones.

## `-o json`

Every read command takes `--output/-o` with `table` (default, human) | `json` |
`jsonl`, through the single `OutputOpt` in `gateclerk/cli.py` and the single renderer
`gateclerk/output.py`. `jsonl` is a documented synonym of `json` at that layer: both are
one compact object per line, which is what `gateclerk.model.from_jsonl()` consumes, and
one renderer keeps the framing (separators, `ensure_ascii`, trailing newline) from
drifting into a stream that parses but is subtly different.

`events` additionally accepts `--format` as a second spelling of `-o`, because that is
the flag p1-08's contract names.

The `-o json` PII law (the rule `migrate -o json` was built on, applied CLI-wide):
JSON on stdout carries **no credential value and no personal data**. `creds test`
prints the resolution *source* and `password: "***"`, never the secret. `tests/test_cli_conventions.py`
holds a guard that fails if any leaf command loses `-o`, and the existing per-command
PII sweeps (`test_e1_07_cli.py` and friends) keep their own.

One exemption, asserted as an exact set so it cannot quietly grow: `demo device serve`
starts a process and prints no records, so there is nothing to frame. It is the only
name in `NO_OUTPUT_FLAG_LEAVES`, and the guard fails if that list and the surface ever
disagree — adding a read command to it is a visible review act, not a way around the rule.

`demo device urls` gained `-o json` on this card — the only flag this card added. Its
machine form masks the demo digest password even though that value is a placeholder: the
rule being protected is "a JSON record has no `password` you can read", because a script
author trained on the demo will do the same thing with a real one. The human table still
prints the pair, which is what `README.md` documents copying into `sites.toml`.

## Adding a command

1. Take `output: OutputOpt = OutputFormat.TABLE` and render through `render(...)` — do
   not print JSON by hand.
2. Raise a `GateClerkError` subclass; let `_Guard`/`_fail` map it. Do not raise
   `typer.Exit(code=N)` with a literal number — add the class to
   `cli_conventions.exit_code_for` instead.
3. Name it with a verb from the table, or add the verb to the table *and this page* in
   the same commit if it is genuinely a new operation.
4. If you rename a verb, add the old spelling to `ALIASES` in the same commit. Never
   remove an alias that shipped.
