# GC-P05 — Hourly roster push carries card numbers

BOARD: gateclerk   DEPENDS ON: GC-P04   GATED: no   COVERS: GC-04 / E02, E03, E04

## WHY

The hourly `device_users` line is built from `UserInfo/Search` only. On the probed firmware
that response carries `numOfCard` but not `cardNo`, so BC Table 70605 `"Card No."` is always
blank and the `Nelegați` linking workflow cannot match a card to a person. R2: linking is
done through BC; the roster is its input.

## VERIFY

```bash
uv run --frozen python - <<'PY'
import json
from pathlib import Path
p = Path("tests/fixtures/recorded/site-a-ds-k1t341amf-s/user_search_page1.json")
page = json.loads(p.read_text(encoding="utf-8"))
users = page["UserInfoSearch"]["UserInfo"]
print("UserInfo has cardNo:", any("cardNo" in u for u in users))
print("UserInfo has numOfCard:", any("numOfCard" in u for u in users))
PY
grep -n "card_info_search" src/gateclerk/agent_loop.py
```

Still broken while the output is `UserInfo has cardNo: False`, `UserInfo has numOfCard:
True`, and `grep` finds nothing in `agent_loop.py`.

## FILES

- `src/gateclerk/agent_loop.py:781-799` — `_read_roster` walks only
  `_search_reader(self.client, "user_info_search")` and maps `user_record_from_device`.
- `src/gateclerk/agent_push.py:1364-1381` — `_roster_user` reads
  `raw.get("cardNo", raw.get("card_no"))`; it is correct, but `raw` never has the key.
- `src/gateclerk/paging.py:851-880` — `card_info_search(reader, *, limits=None, ...)`
  returns a `PagedSearch` whose `.collect({})` yields `CardInfo` records. Each record
  carries `employeeNo` and `cardNo` (see
  `tests/fixtures/recorded/site-a-ds-k1t341amf-s/enrollment/cardinfo_setup_readback.json`).
- `src/gateclerk/migrate_export.py:313-325` — the existing example of walking
  `card_info_search` with the same limits and `_search_reader(client, "card_info_search")`.
- `tests/fakedevice.py:1562-1626` — the fake's CardInfo/Search route, for tests.

## CHANGE

1. In `src/gateclerk/agent_loop.py`, import `card_info_search` from `gateclerk.paging`
   beside `iter_users`, and `replace` from `dataclasses` if not already imported.

2. Add a deterministic primary-card rule near the roster code. Pin it in the docstring:
   numeric card numbers compare numerically, everything else compares as text; the lowest
   value wins when one employee has several cards.
   ```python
   def _primary_card(card_numbers: Sequence[str]) -> str:
       def key(value: str) -> tuple[int, int, str]:
           text = value.strip()
           return (0, int(text), text) if text.isdigit() else (1, 0, text)

       return min((c for c in card_numbers if c.strip()), key=key)
   ```

3. Replace the body of `_read_roster` after the user walk with a single conditional card
   walk. Keep the existing `_roster` injection shortcut before it. `numOfCard` may be an
   int or a numeric string on sibling firmware, so normalise it:
   ```python
   def _card_count(user: Any) -> int:
       value = user.raw.get("numOfCard")
       if isinstance(value, int) and not isinstance(value, bool):
           return value
       return int(value) if isinstance(value, str) and value.isdigit() else 0


   users: list[Any] = [user_record_from_device(raw) for raw in iter_users(reader, limits=limits)]
   if any(_card_count(user) > 0 for user in users):
       cards_reader = _search_reader(self.client, "card_info_search")
       by_employee: dict[str, list[str]] = {}
       for card in card_info_search(cards_reader, limits=limits).collect({}):
           employee = card.get("employeeNo", card.get("employeeNoString"))
           number = card.get("cardNo")
           if employee is None or number is None:
               continue
           by_employee.setdefault(str(employee).strip(), []).append(str(number))
       users = [
           replace(
               user,
               raw={**user.raw, "cardNo": _primary_card(by_employee[user.employee_no])},
           )
           if by_employee.get(user.employee_no)
           else user
           for user in users
       ]
   return users
   ```

4. Keep the roster line shape unchanged: `device_users_line` still emits exactly
   `employee_no`, `name`, `cardNo`, `hasFace`. Do not add `numOfCard`, `userType` or the
   card's `cardType` to the wire.

What must NOT change:

- `device_users_line` and `_roster_user` in `agent_push.py`; the four-key privacy boundary.
- The hourly cadence (`DEFAULT_DEVICE_USERS_INTERVAL_S`) and the one-client rule.
- The `password` stripping in `user_record_from_device`.
- No card number in logs or warnings.

## TESTS

Write `tests/test_gc_p05_roster_cards.py` first and run:

```bash
uv run --frozen pytest -q tests/test_gc_p05_roster_cards.py
```

Copy the `FakeDevice` enrollment setup from `tests/test_e1_05_cards_phase.py:231` and the
roster line expectations from `tests/test_t15_push_https.py:406`.

Tests:

- `test_roster_joins_card_info_and_fills_card_no` — seed `UserInfo` records with
  `numOfCard: 1` and no `cardNo`, plus a `CardInfo` row for the same employee. Call
  `loop._read_roster()`; assert the matching user's `raw["cardNo"]` is the card number and
  `device_users_line(...)` emits it (not `null`).
- `test_user_with_no_card_stays_null` — `numOfCard: 0`; no CardInfo walk is needed; the
  line carries `"cardNo": null`.
- `test_multiple_cards_pick_the_lowest_numeric_card` — cards `"1002"`, `"900"`, `"A-7"`;
  assert `"900"` wins; pin the rule.
- `test_card_walk_is_skipped_when_no_user_has_a_card` — count `CardInfo/Search` requests
  on the fake; assert zero.

## GATE

```bash
uv run --frozen pytest -q
uv run --frozen ruff check src/gateclerk
```

## ACCEPT

- [ ] `_read_roster` calls `card_info_search` only when a user has `numOfCard > 0`.
- [ ] `cardNo` reaches `device_users_line` for users with a card.
- [ ] A user with no card still emits `"cardNo": null`.
- [ ] Multiple cards choose the pinned lowest numeric value.
- [ ] The four-key roster shape and hourly cadence are unchanged.
- [ ] Full pytest and ruff are green.

## OUT

`src/gateclerk/agent_push.py` (`_roster_user` and the wire shape), `src/gateclerk/paging.py`,
`src/gateclerk/pipeline.py`, the BC `Nelegați` pages (BC-P06), and the existing roster
tests. Do not send model, firmware or card type on this line.

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
