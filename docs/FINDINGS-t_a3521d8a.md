# t_a3521d8a — P1-03b transport: survive device nonce retirement mid-backfill

STATUS: IN PROGRESS (diagnosis phase). Live device NEVER contacted; all work offline
against FakeDevice / httpx.MockTransport.

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


## Plan / next steps

1. Read httpx DigestAuth + auth_flow source to pin exactly what the library spends.
2. Reproduce shapes (a)/(b)/(c) offline against current transport; record the 401s as
   labelled fixtures under tests/fixtures/recorded/site-a-ds-k1t341amf-s/.
3. Implement the recovery in isapi_transport.py `_call`'s IsapiAuthError branch.
4. Tests: walk pin, shape-(c) pin, wrong-password pin, circuit pin. ruff + pytest.
