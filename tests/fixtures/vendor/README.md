# Vendored vendor catalogs (root of trust for event-code provenance)

These two files are the authority `gateclerk.event_codes` and
`docs/internal/references/acs-event-codes.md` §3 are checked against. They are vendored so the
provenance guard in `tests/test_event_codes.py` runs offline (CI has no device and no
network) and so a later upstream edit cannot silently rename a code under us.

Fetched 2026-10-16 from the URLs recorded in `docs/internal/references/acs-event-codes.md`
"Sources". Nothing here is hand-transcribed: `scripts/gen_code_reference.py` builds the
doc tables from these files.

| file | upstream | what it gives us |
|---|---|---|
| `node-red-MAJOR_EVENT-0x5.json` | `Supergiovane/node-red-contrib-hikvision-ultimate` → `nodes/utils/AccessControlEvents/MAJOR_EVENT-0x5.json` (MIT) | vendor **hex-named** minor table for major 5 (`0x4B` → `MINOR_FACE_VERIFY_PASS`). Names only — no outcome. |
| `hikvision-acs-event-types.json` | `mmisobuj/HikvisionIsupServer` → `config/acs-event-types.json` | decimal major/minor catalog, **the only source that states an `outcome` per code** (`granted`/`denied`/`info`). |

## Trust boundary — read this before trusting a row

The fixtures are the root of trust: no test can prove a catalog is *correct*, only that
our table agrees with it. Two consequences are deliberate and pinned by tests:

1. **We do not import `outcome` blindly.** mmisobuj's `outcome` is name-matched and wrong
   in places (it stamps a firmware upgrade `(5,175)` as `granted`, and majors 1/2 alarms
   as `denied`). `test_granted_rows_are_catalog_pass_or_success_codes` and
   `test_alarms_and_exceptions_are_never_granted_or_denied` keep that contamination out
   of the punch rule, and every remaining disagreement is declared with its reason in
   the doc's §3.2 table.
2. **A code no catalog names stays unnamed** (`info` + `unknown_code`, still stored)
   rather than getting a plausible label. That is the card's "no guessed codes" rule, and
   it is why this directory exists.

Editing either file changes what the classifier is allowed to say, so treat a diff here
as a code change: it needs the same review as `event_codes.py`, and the recorded fetch
date above is what a reviewer compares against upstream.
