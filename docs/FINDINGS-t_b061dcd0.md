# t_b061dcd0 — flatten_xml drops XML attributes: findings log

## Task
fix(isapi): implement `@`-prefix key convention in `flatten_xml`
( adjudicated convention from round-1 review on t_a8cdd1a9 — apply as written )

## Defect (verified on HEAD of this worktree)
`flatten_xml(parse_isapi_xml('<Transaction><maxResults max="30" min="1"/></Transaction>'))`
→ `{'maxResults': None}` — attributes silently dropped.

## Evidence gathered so far
- `src/gateclerk/isapi_response.py:128-158` — `flatten_xml` iterates children, uses only
  `len(child)` and `child.text`; `child.attrib` is never read. Root cause confirmed.
- Consumers: `parse_body()` (isapi_response.py:187) → `isapi_transport.py:239` and
  `parse_envelope()`; `tz.read_system_time` uses `parse_isapi_xml` + its own `_xml_text`
  walk (unaffected — reads `.text`, not flatten output).
- JSON fixtures under `tests/fixtures/recorded/site-a-ds-k1t341amf-s/acs_capabilities.json`
  already use `@min`/`@max`/`@opt` — target spelling confirmed for JSON/XML agreement.
- Recorded XML fixtures (`device_info.xml`, `system_time.xml`) carry attributes ONLY on
  the root element (`version="2.0"`, `xmlns=...`); `flatten_xml` starts at children, so
  the recorded pins cannot change unless the convention is applied too broadly. Baseline
  snapshot saved: scratch/t_b061dcd0_snapshot.py (rerun after change, diff must be empty).

## Plan
1. flatten_xml: attributes → `@`-prefixed str keys on the element's dict.
2. Leaf with attrs AND text → `{"@…": …, "#text": text}`; text-only leaf stays a bare str;
   attribute-less empty leaf stays `None`; repeated-tag collection unchanged.
3. Pins: capability-shaped repro pin + attrs+text pin in tests/test_isapi_response.py.
4. Fixture byte-identical check via snapshot diff; ruff + pytest green; PR flow.

## Status
- [x] implementation — `_flatten_element` + `TEXT_KEY = "#text"` exported
- [x] pins — repro pin, attrs+text pin, parent-attrs pin, over-application guard
- [x] fixture diff empty — snapshot before/after byte-identical (`FIXTURE_FLAT_IDENTICAL`)
- [x] mutation probe — dropping `el.attrib` fails exactly the 3 new attr pins, restored
- [x] ruff check + format green; pytest 528 passed, 1 deselected (offline)
- [x] committed + PR (sha + URL in kanban comment)

## Notes for the reviewer
- Root attributes (root `version`/`xmlns`) still do NOT appear in flatten output:
  `flatten_xml` walks children of the root only — same as before, pins unchanged.
- Mixed content on an element that HAS children still drops the leading text (unchanged
  pre-existing behaviour, out of adjudicated scope; documented in `_flatten_element`).
- Envelope fields with attributes on the value element (e.g. `<statusString a="1">x`)
  would now yield a dict where `_as_str`/`_as_int` return None. No observed envelope
  child carries attributes; the envelope pins all pass. If p1-04 ever sees a capability
  under an envelope it reads `[@key]`/`[#text]` — same spelling as the JSON fixtures.
