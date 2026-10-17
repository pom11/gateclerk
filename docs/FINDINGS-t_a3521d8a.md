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

(none yet — appended as they land)

## Plan / next steps

1. Read httpx DigestAuth + auth_flow source to pin exactly what the library spends.
2. Reproduce shapes (a)/(b)/(c) offline against current transport; record the 401s as
   labelled fixtures under tests/fixtures/recorded/site-a-ds-k1t341amf-s/.
3. Implement the recovery in isapi_transport.py `_call`'s IsapiAuthError branch.
4. Tests: walk pin, shape-(c) pin, wrong-password pin, circuit pin. ruff + pytest.
