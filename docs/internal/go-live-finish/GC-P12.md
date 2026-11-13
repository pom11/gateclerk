# GC-P12 — `export config` keeps `mnotify` sinks and valid sink keys

BOARD: gateclerk   DEPENDS ON: —   GATED: no   COVERS: GC-13 / —

## WHY

`gateclerk export config` is the sanitized inventory an operator uses before a cutover. It
drops `type = "mnotify"` to an empty string and reports valid `SinkSpec` keys (`to`,
`timeout_s`, `headers`, `accepts_roster`) as `dropped_unknown_keys`. The export then lies
about the site's alert route. R2: the alert route is part of the production install.

## VERIFY

```bash
uv run --frozen python - <<'PY'
from gateclerk.export_cli import project_sites_toml
raw = b'''[[site]]
name = "demo-a"
host = "192.0.2.10"
iana_tz = "Europe/Bucharest"

[[site.sink]]
name = "alerts"
type = "mnotify"
to = "alerts@example.invalid"
timeout_s = 300
accepts_roster = false
'''
r = project_sites_toml(raw)
print("sink type:", r.rows[0]["sinks"])
print("dropped:", r.dropped_keys)
PY
```

Still broken while the projected sink has `"type": ""` and `dropped` names `sink.type`,
`sink.to`, `sink.timeout_s`, `sink.accepts_roster`.

## FILES

- `src/gateclerk/export_cli.py:174-185` — `ALLOWED_SINK_KEYS` omits `to`, `timeout_s`,
  `headers`, `accepts_roster`.
- `src/gateclerk/export_cli.py:310-325` — `_project_sink` rejects any type outside
  `("https", "csv", "jsonl", "")`:
  ```python
  if sink_type not in ("https", "csv", "jsonl", ""):
      dropped.append("sink.type")
      sink_type = ""
  ```
- `src/gateclerk/sinks.py:137-180` — `SinkSpec` fields: `token_env`, `token_keychain`,
  `headers`, `rotation`, `path`, `accepts_roster`, `to`, `timeout_s`.
- `src/gateclerk/sinks.py:426-445` — the registry parses `headers`, `accepts_roster`,
  `to` and `timeout_s` for the `mnotify` type.
- `tests/test_export_config.py:160` — the existing dropped-keys test to extend.

## CHANGE

1. Add the four keys to `ALLOWED_SINK_KEYS`:
   ```python
   ("to",)
   ("timeout_s",)
   ("headers",)
   ("accepts_roster",)
   ```
2. Allow `"mnotify"` in `_project_sink`:
   ```python
   if sink_type not in ("https", "csv", "jsonl", "mnotify", ""):
   ```
3. Project the new values. Add two small validators near `_safe_scalar_ident`:
   ```python
   def _safe_recipient(raw: object) -> tuple[str, list[str]]:
       """One mail address: text with `@`, no whitespace, no secret-shaped value."""
       if raw is None:
           return "", []
       if not isinstance(raw, str) or raw.count("@") != 1 or any(c.isspace() for c in raw):
           return "", ["sink.to"]
       text = raw.strip()
       return ("", ["sink.to"]) if redact_b64(text) != text else (text, [])


   def _safe_headers(raw: object) -> tuple[str, list[str]]:
       """Sorted `k=v` pairs for inventory; header values are config, never secrets."""
       if raw is None:
           return "", []
       if not isinstance(raw, dict):
           return "", ["sink.headers"]
       pairs = []
       for key, value in sorted(raw.items()):
           if not isinstance(key, str) or not isinstance(value, str):
               return "", ["sink.headers"]
           if any(c in key + value for c in "\r\n"):
               return "", ["sink.headers"]
           pairs.append(f"{key}={value}")
       return ";".join(pairs), []
   ```
4. In `_project_sink`, build the four values and add them to the returned dict:
   ```python
   to, d_to = _safe_recipient(raw_sink.get("to"))
   dropped.extend(d_to)
   timeout_raw = raw_sink.get("timeout_s")
   timeout_s = timeout_raw if isinstance(timeout_raw, (int, float)) and timeout_raw > 0 else None
   if timeout_raw is not None and timeout_s is None:
       dropped.append("sink.timeout_s")
   accepts_raw = raw_sink.get("accepts_roster", True)
   accepts_roster = accepts_raw if isinstance(accepts_raw, bool) else True
   if not isinstance(accepts_raw, bool):
       dropped.append("sink.accepts_roster")
   headers, d_headers = _safe_headers(raw_sink.get("headers"))
   dropped.extend(d_headers)
   ```
   Return them as `"to": to`, `"timeout_s": timeout_s`, `"headers": headers`,
   `"accepts_roster": accepts_roster`. The CSV/JSONL sink field is the `sinks` JSON
   column; its shape is not otherwise changed.

What must NOT change:

- The deny-by-default allowlist for site keys and unknown sink keys.
- `sanitize_target_url` and the secret-shaped value checks.
- `mnotify` remains an alert-only sink (`SiteConfig.event_sinks` excludes it); this card
  only fixes the inventory.
- No secret value is ever printed.

## TESTS

Write `tests/test_gc_p12_export_mnotify.py` first and run:

```bash
uv run --frozen pytest -q tests/test_gc_p12_export_mnotify.py
```

Copy `tests/test_export_config.py:121` (header/allowlist) and `:160` (dropped keys).

Tests:

- `test_mnotify_sink_type_survives_config_export` — type is `"mnotify"`, `to` and
  `timeout_s` are present, `dropped_keys` is empty.
- `test_valid_https_sink_keys_are_not_dropped` — `headers`, `accepts_roster`, `timeout_s`
  on an https sink; no `sink.*` dropped keys.
- `test_invalid_recipient_is_dropped_and_counted` — `to = "not-an-address"`; only
  `sink.to` is dropped.
- `test_headers_are_rendered_as_sorted_pairs` — `{"X-B": "2", "X-A": "1"}` becomes
  `"X-A=1;X-B=2"`.
- `test_no_secret_value_appears_in_the_export` — a header value and a recipient are
  present in the output; a credential-shaped string is not.

## GATE

```bash
uv run --frozen pytest -q
uv run --frozen ruff check src/gateclerk
```

## ACCEPT

- [ ] `type = "mnotify"` survives.
- [ ] `to`, `timeout_s`, `headers`, `accepts_roster` are no longer `dropped_unknown_keys`.
- [ ] Invalid values are dropped and counted, not silently accepted.
- [ ] The export still contains no secret values.
- [ ] Full pytest and ruff are green.

## OUT

`src/gateclerk/sink_cli.py` (the editor), `src/gateclerk/sinks.py` (the parser),
`src/gateclerk/agent_mnotify.py`, and the scan export (`export scans`).

## HANDOFF

Branch base `origin/main`; PR target `INTEGRATION_BRANCH` (`INDEX.md` § Conventions; the literal name is in your card).

1. Run the GATE.
2. Open the PR against `INTEGRATION_BRANCH`.
3. When the gate is green and the PR is mergeable, run `gh pr merge <number> --squash`
   yourself.
4. Never merge into `main`/`master`; never force-push.
5. If the PR is not mergeable (conflict), rebase on `origin/INTEGRATION_BRANCH`, re-run
   the GATE, then merge. If that fails twice, stop and report `LEFT:`.

The card is complete only after the merge.

DONE: PR URL and merge commit.
LEFT: anything not merged, with the reason.
