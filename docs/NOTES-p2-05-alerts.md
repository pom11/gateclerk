# P2-05 notes — alerts + park-on-bad-creds (in progress)

Card: t_4c2ab984. BINDING SPEC: docs/P2-SITE-AGENT.md §2c (DECIDED verbatim).
Branch wt/p2-05-alerts, built on origin/main + the two released parents merged in
locally (origin/wt/p2-03-scheduler, origin/wt/p2-04-pusher — both OPEN PRs #30/#31
awaiting orchestrator merge; this branch contains their heads so the loop result
objects exist to hook).

## Status

- [ ] failing-first tests written (RED proven)
- [ ] agent_alert.py implemented
- [ ] gate green + ruff

## Findings so far

- The loop's `TickResult` (agent_loop.py) carries everything the policy needs:
  `skipped` (circuit-open, ZERO requests), `circuit_open`, `exception` (typed).
  No loop edit needed — the card's "BLOCK if a hook is missing" does not fire.
- Transport exposes `circuit_open()`, `reset_circuit()`, `auth_recoveries`
  (isapi_transport.py:203/248/251) and `IsapiAuthError.locked` / `.unlock_time`
  (exceptions.py:147-153) — all read-only seams.
- `TickResult.error` embeds `str(exc)` — and transport exception messages DO embed
  the base URL (isapi_transport.py:410 `request to {base_url} failed`). P2-05 must
  never forward those strings to the sink ("NEVER log ... hosts beyond site
  label"): the default line is authored from safe pieces only (exception CLASS
  name, site label, device serial), pinned by a test.
- No config key exists for the stall multiplier (config.py `_KNOWN_KEYS`), so per
  the card: module constant k=3 with a comment pointing at the spec (DESIGN OQ4).
