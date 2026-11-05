# DECISION — the IsapiClient credential-provider seam (card t_514870e8)

Status: **DECIDED 2026-11-05 (architect). Outcome (b): the seam is wanted — completed
in its smallest form, in three slices. The (a)-outcome prose corrections ride in
Slice 1 regardless of whether Slices 2/3 ever merge.**

Surfaced by PR #81 (card t_a063374a), which rewrote `default_device_prober` to
resolve eagerly and exposed that the lazy seam `gateclerk.config.credential_provider`
promises has no consumer.

## The measured situation (all line refs against origin/main 282bda0)

1. `credential_provider` (src/gateclerk/config.py:934) returns
   `lambda: resolve_credentials(...)` — a callable whose docstring promises
   re-resolution ("a digest nonce can expire minutes into a paged pull, and at that
   moment the client asks for a credential instead of reaching for one it cached").
2. `IsapiClient.__init__` (src/gateclerk/isapi_transport.py:145) takes positional
   `(base_url, username, password)` and builds `httpx.DigestAuth(username, password)`
   once (isapi_transport.py:174), stashing `self._auth_user` / `self._auth_secret`
   (isapi_transport.py:201-202) and rebuilding from those same cached strings on
   nonce retirement (`_reset_auth_state` at isapi_transport.py:356, rebuild line
   :375). There is no
   seam through which a provider could be re-consulted.
3. **Production consumers of `credential_provider`: zero.** `git grep` on main finds
   only the definition and three unit tests (tests/test_config_credentials.py:580,
   :594, :635). Every one of the five real construction sites resolves eagerly and
   passes plaintext values:
   - src/gateclerk/cli_shared.py:325 (`_client_for`, shared by every read command;
     `--verbose` then wraps the built client in `pipeline.LoggedClient`),
   - src/gateclerk/agent_loop.py:1018 (`build_device_loop` fallback),
   - src/gateclerk/agent_cli.py:1349 (`_client_for_host` default factory),
   - src/gateclerk/init_cli.py:324 (probe),
   - src/gateclerk/doctor_cli.py:294 (the PR #81 prober — deliberately eager: a
     pre-socket resolve keeps a missing credential a `CredentialUnavailable` exit 2
     instead of a later auth 401, and a 2-GET probe never needs re-resolution).
   The three tests prove the *provider* re-resolves; none of them proves the
   *client* consumes a provider, because no client call site can.
4. Two doc claims are therefore FALSE as written, both directions of the same lie:
   - config.py:13-16 "The client therefore cannot hold a plaintext password,
     cannot log one, and P2's site agent can hand it a systemd-credential provider
     without touching ISAPI code" — the client holds plaintext strings today, and
     the agent hands it values, not a provider.
   - DESIGN.md:378 "The client receives a credential *callable*, never a baked-in
     source" — every shipped call site bakes the source in before construction.

## Why not the honest outcome (a) (dead weight + corrected prose)

Re-resolution on *digest nonce retirement* alone would indeed be dead weight: when
the nonce retires (~190 uses, docs/internal/OBSERVED.md "Digest nonce use-cap"),
the SAME password still works — which is exactly why the t_a3521d8a recovery
succeeds today from cached values. If that were the only consumer, (a) would be
correct.

It is not the only consumer. The one real consumer is **credential rotation inside
the long-lived site agent**, and the code contradicts a shipped spec claim on it:

- `agent run` builds every device client ONCE at SiteAgent construction
  (agent_cli.py:1180 → `_client_for_host` → eager `resolve_credentials` at
  agent_cli.py:1336) and holds it for the process lifetime; `SiteAgent.run()` never
  rebuilds clients, and nothing in `src/` calls `IsapiClient.reset_circuit()`.
- P2-SITE-AGENT.md §2c (docs/internal/P2-SITE-AGENT.md:126) chose the slow-re-probe
  park **because** "a transient creds rotation self-heals without a site visit" —
  the comment at agent_alert.py:429 repeats the claim.
- Today it cannot self-heal: the parked agent's 30-minute re-probe knocks with the
  STALE password the client cached at construction. The device answers a rotated
  password WITH a challenge, httpx re-pays it with the same stale `DigestAuth`, and
  the terminal-401 path re-parks (module docstring, isapi_transport.py:32-46; the
  challenge-less recovery loop at :481 cannot see rotation at all). So the shipped
  design pays the cost of the re-probe grid without buying the self-heal that
  justified it — and burns the device's lockout budget (OBSERVED.md "lockout
  accounting") once per episode while promising operators they don't need to visit.
- `Restart=always` does not cover this: a parked agent never crashes, so there is
  no restart to re-resolve through.

The spec therefore requires the capability; the code is missing its second half.
YAGNI does not delete a requirement the spec itself states.

## The decision — smallest form, staged

Naming and shape are DECIDED here and bind all three slices; no slice may re-decide
them.

**Slice 1 — truth first (docs/prose only, must merge even if 2/3 never do).**
Correct config.py:13-16, config.py:677 (the `CredentialProvider` comment), config.py
:934-947 (`credential_provider` docstring) and DESIGN.md:378 to state what is true:
every shipped call site resolves eagerly; `credential_provider` exists for
callers that want lazy re-resolution; until Slice 3 lands, **nothing** consumes it.
Do not delete the symbol: it is public API (`__all__`) and deleting it buys nothing
the prose does not. The three tests at tests/test_config_credentials.py:580/:594/
:635 stay green untouched — they test the provider as a provider.

**Slice 2 — the seam on the client (no behavior change for existing callers).**

- `IsapiClient.__init__` gains keyword-only
  `credentials: CredentialProvider | None = None`. Type-only import
  (`if TYPE_CHECKING`) of `gateclerk.config.CredentialProvider` — at runtime the
  client duck-types `provider() -> Credentials`, so `isapi_transport` keeps its
  config-free import graph (it imports none of config today; keep that).
- Exactly-one-source rule, `ValueError` naming both, following the base_url
  precedent (isapi_transport.py:170-173): `credentials=None` requires non-empty
  `username`+`password`; `credentials` given requires both positionals empty.
  This tightens `IsapiClient(url, "", "")` from silent-accept to refusal — an
  intentional side effect with its own test (the resolver already refuses an empty
  password at config.py:890-895; the ctor was the hole).
- **When the client may call the provider — exactly three points, all
  failure- or lifetime-triggered, never per request and never per page:**
  1. once in `__init__` (fail-fast: preserves the pre-socket
     `CredentialUnavailable`-→-exit-2 law of doctor/`_client_for`; those call sites
     already wrap construction and must add `CredentialUnavailable` to the same
     `except` that maps `ValueError` today);
  2. inside `_reset_auth_state()` (isapi_transport.py:356) — the existing rebuild
     point, already budget-gated at 1 per logical call / streak ≤2
     (DEFAULT_AUTH_RECOVERY_BUDGET/STREAK), so worst case ≈ one resolve per ~190
     requests on the canary;
  3. the first request after the auth circuit has been open and expired
     (`_call`'s `circuit_open()` gate, isapi_transport.py:413-418): rebuild the
     `DigestAuth` from `provider()` once at circuit expiry. This is the point that
     delivers §2c's self-heal: without it, the first post-park request re-presents
     the stale secret to a rotated device, httpx absorbs the challenge with the
     same stale auth, and the episode repeats — rotation is invisible to the
     challenge-less recovery loop by design.
  A provider raising `CredentialUnavailable` at (2)/(3) propagates unchanged (the
  resolver's law: the message names the fix command); the already-spent recovery
  counters stay spent — do not restructure the loop for that edge.
- The client still holds the last revealed plaintext while its `DigestAuth` lives
  (httpx requires the strings). Say exactly that in the docstring — replacing one
  false claim ("cannot hold a plaintext password") with another ("never holds
  plaintext even with a provider") is not the fix.
- `LoggedClient` gains NOTHING: constructor kwargs are invisible to it
  (construction happens in `cli_shared._client_for` before wrapping), and
  `__getattr__` (pipeline.py:692) already covers attribute reachability. The
  documented trap (isapi_transport.py:244-251, the `post` AttributeError) is about
  *method* surface; Slice 2 adds no methods, and its test suite must include one
  arm asserting a provider-built client survives the `--verbose` wrap.
- Do not touch `client_factory: Callable[[str, str, str], IsapiClient]`
  (agent_cli.py:1087/:1318) — widening it is Slice 3's decision, and injected
  factories keep receiving eager values so existing tests are untouched.

**Slice 3 — the one real consumer (agent rotation self-heal).**
`agent_cli._client_for_host` passes `credentials=cfg.credential_provider(target,
env=env, keychain=keychain)` to the ctor when no `client_factory` override was
injected. This is what makes P2-SITE-AGENT.md §2c's claim true. Test shape
(offline, no canary): a fake keychain reader whose value changes between ticks —
tick 1 good, rotate, tick 2 terminal-401 park, ack, circuit expiry, tick 3 must
re-read the source and self-heal WITHOUT a process restart; plus a call-count arm
pinning "one resolve per episode, none per request" (the keychain-prompt budget —
each `security` invocation can raise a macOS ACL prompt, config.py KeychainReader
docstring).

**Explicitly NOT part of this seam:** per-request resolution (a keychain prompt
per page on macOS); a provider-based `httpx.Auth` subclass (httpx.DigestAuth takes
strings; the rebuild at the reset points is the sanctioned refresh); any change to
doctor's prober (eager is correct there — PR #81's docstring already states why).

## Proof harness

`tests/test_doctor_real_prober.py` (15 arms, demo fake device behind the UNMODIFIED
real probers) plus the FakeDevice retire-after-N arms in `tests/test_isapi_transport.py`
are the offline proof. Slice 2 adds a counting-fake-provider arm asserting exactly:
ctor call once, +1 per nonce retirement, +1 per circuit episode, zero per ordinary
request. No canary access is required or permitted for any slice.
