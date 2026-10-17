# t_a3521d8a — P1-03b transport: survive device nonce retirement mid-backfill

STATUS: COMPLETE (fix + tests + docs committed). Live device NEVER contacted; all work
offline against FakeDevice / httpx.MockTransport.

## Task restatement

`gateclerk events --chunk 1h` over a long backfill dies with 401 (CORRECT password) at
the ~190th request; exit 3; device stays unlocked. Reading: the device retires a digest
nonce after N uses and our transport does not survive the re-challenge. Mechanism is
OPEN (we never captured the 401 itself): three possible shapes

  (a) 401 + `WWW-Authenticate` with `stale="true"` + fresh nonce
  (b) 401 + `WWW-Authenticate` with `stale="false"` + fresh nonce
  (c) 401 with the ISAPI error envelope and NO `WWW-Authenticate`

Step 1: reproduce each shape offline against the CURRENT transport and see which one
reproduces the exit-3-at-request-N failure. Step 2: fix the transport's 401 path with a
bounded recovery budget. Step 3: keep the wrong-password lockout invariant green.

## Findings so far

### F1 — the mechanism is shape (c): 401 + error envelope + NO `WWW-Authenticate` (MECHANISM DETERMINED, offline)

Probe: `FakeDevice.retire_after=N` (new repeatable use-cap seam) driven through the
CURRENT, unmodified `IsapiClient` for all three shapes (`n=5`, 14 GETs each). Real
device never contacted.

```
shape=stale_true     -> 14/14 calls OK, died_at=None, circuit=False, req=17, retirements=2
shape=stale_false    -> 14/14 calls OK, died_at=None, circuit=False, req=17, retirements=2
shape=envelope_only  -> dies on call 6 (= N+1), circuit_open=True, req=7, retirements=1
```

Why: `httpx.DigestAuth.auth_flow` (`.venv/.../httpx/_auth.py:201-222`) re-pays **any**
401 that carries a `WWW-Authenticate: Digest` header — it never reads `stale` at all
(gotchas §1.5 said this; now re-confirmed against 0.28.1). So shapes (a) and (b) are
already survivable today, stale-flag spelling notwithstanding: the replay costs ONE
extra request per retirement and the walk continues.

Shape (c) is the repro: with no `WWW-Authenticate`, `auth_flow` returns at `_auth.py:201`
without re-paying, so the 401 reaches `_call`, which takes the
`isinstance(error, IsapiAuthError)` branch (`isapi_transport.py:323-327`) → `_open_circuit()`
→ raise. Exit 3 at exactly request N+1 with a CORRECT password and the device unlocked
— i.e. the live symptom, reproduced deterministically offline.

Second-order detail that makes (c) a *permanent* failure rather than a hiccup, and is
the reason a naive "just resend the request" cannot work: `_last_challenge` still holds
the DEAD nonce after a no-challenge 401, so the next request re-presents it with a
climbing `nc` and 401s forever (gotchas §1.7a "worked for an hour, then 401 forever
until restart"). The recovery must therefore **drop the auth state**, not just resend.

### F2 — consequence for the fix

(a)/(b) need no new transport behaviour beyond "do not open the circuit on a 401 that
was survived" (they never reach our error path). (c) needs the auth-state reset + one
re-bootstrap. Both must stay inside one bounded budget so a wrong password still costs
exactly the p1-03 attempt budget.


## Implementation (shipped)

`IsapiClient._call` now distinguishes the two 401 families with `_offers_digest_challenge`
and, for the challenge-less one only, drops digest state (`_reset_auth_state`) and re-issues
the byte-identical request. Budget: `auth_recovery_budget` (default 1, per *logical call*)
and `auth_recovery_streak` (default 2, consecutive recoveries with no intervening 200).
Locked-account 401s are terminal (F3). Wrong passwords never reach the recovery (F4).

### F3 — the recovery must NOT fire on a locked account

`isapi_response.py` parses `lockStatus`/`retryLoginTime` off the 401 envelope. A locked
account answers with a challenge-less 401 too, so the shape discriminator alone would
re-cover it. `IsapiAuthError.locked` gates the recovery: locked → terminal + circuit, no
re-bootstrap (re-presenting credentials while the account is locked is exactly what the
device's lockout accounting counts against you; OBSERVED.md "lockout accounting"). Pinned by
`test_locked_account_is_never_treated_as_a_retired_nonce`.

### F4 — a wrong password still costs exactly the p1-03 budget

Bad credentials come back WITH a challenge → httpx spends its one re-auth → the 401 that
reaches `_call` is challenge-*offered* → discriminator returns False → terminal. The
recovery counter stays 0. Pinned against all three shapes.

## Tests (tests/test_isapi_transport_nonce_recovery.py — 27 cases)

Fixtures `nonce_retired_{stale_true,stale_false,envelope_only}_401.txt` recorded under
`site-a-ds-k1t341amf-s/`, all three labelled INVENTED (mechanism still OPEN live — we
never captured the real 401), README table updated + `test_corpus_matches_the_readme_table`
green. Covers: shape-(c) repro, per-call budget, streak cap binds independently, streak
resets on intervening 200, budget is per-call not per-client, circuit stays CLOSED on a
survived retirement but OPENS on exhaustion, locked terminal, wrong-password budget, a
full paging walk (no loss/dup, retirement count pinned), and the discriminator cross-checked
against httpx's own header scan (recorded challenge, no-challenge, basic-only, digest-
mentioned-in-Basic, two-headers, lowercase).

Full suite: **1031 passed, 4 skipped** (was 1003 pre-card). ruff check + format clean.

## Mutation probes (offline, restore-by-copy)

M1 drop discriminator → KILLED (7). M2 drop locked guard → KILLED. M3 drop streak guard →
KILLED. M5 no reset (resend dead nonce) → KILLED. M6 circuit-on-survived → KILLED (5).
M7 streak never resets → KILLED (3). M8 per-call cap removed → KILLED.
**M4 (clear `_last_challenge` only, keep DigestAuth) SURVIVED — EQUIVALENT MUTANT, proven
not a test gap:** httpx's `auth_flow` sets `_nonce_count = 1` itself when it parses a new
challenge (`_auth.py:201` region, confirmed by scratch `m4_equivalence.py`), so a partial
reset and a full rebuild are observably identical to the device. That in turn corrected two
comments that had claimed rebuilding DigestAuth is *what* forgets `nc` — httpx forgets it on
the next challenge either way; we rebuild to also drop the stale challenge+response cache.

## Still OPEN (handoff)

Mechanism is DETERMINED OFFLINE but never confirmed against the live box (OBSERVED.md keeps
it OPEN; debug offline, no re-probes — lockout accounting). When the owner next captures a
real retirement 401, check it against `nonce_retired_envelope_only_401.txt`; if it instead
carries a challenge, shapes (a)/(b) apply and the transport recovery is inert-but-harmless.
