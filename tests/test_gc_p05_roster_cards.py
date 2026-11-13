"""GC-P05 — the hourly roster carries card numbers (BC Table 70605 "Card No.").

The probed firmware's `UserInfo/Search` answers `numOfCard` but NOT `cardNo`
(pinned below against the committed capture), so a roster built from that one walk
has an empty "Card No." column and BC's `Nelegati` workflow has nothing to match a
card against. The fix is a join: walk `CardInfo/Search` too, group by `employeeNo`,
and hand the winning card number into the record's `raw` as `cardNo` — which is the
key `agent_push._roster_user` already reads.

Proof layers, each named after the rule it locks:

* the join is real (not an injected roster): every case here walks a `FakeDevice`
  through the loop's ONE client, so a regression that re-inlines a fake roster dies;
* the four-key privacy boundary (`employee_no`, `name`, `cardNo`, `hasFace`) is
  asserted on the wire of every case that pushes, and `numOfCard` — which the device
  DID send — is asserted absent, because the card forbids it on the line;
* the card walk is conditional: `numOfCard == 0` everywhere must cost ZERO
  `CardInfo/Search` requests (the ~190-use nonce budget, docs/OBSERVED.md, is why the
  roster is hourly and why a second walk has to be earned);
* the primary-card rule is pinned by the card: numeric cards compare numerically,
  everything else as text, lowest wins.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fakedevice import BASE_URL, FakeDevice
from gateclerk.agent_loop import DeviceLoop, _primary_card
from gateclerk.agent_push import device_users_line
from gateclerk.isapi_transport import IsapiClient

SITE = "site-a"
PASSWORD = "fake" + "pw"  # placeholder policy (tests/test_repo_hygiene.py)
DEVICE_CODE = "D-IF-1"

USER_SEARCH_PATH = "/ISAPI/AccessControl/UserInfo/Search?format=json"
CARD_SEARCH_PATH = "/ISAPI/AccessControl/CardInfo/Search?format=json"


# --- fixtures ----------------------------------------------------------------------------


def user_row(no: str, *, cards: int, name: str | None = None, faces: int = 0) -> dict[str, Any]:
    """One `UserInfo/Search` row in the SHAPE THE FIRMWARE ANSWERS.

    `numOfCard` present, `cardNo` absent — that asymmetry is the bug this card fixes and
    it is asserted against the recorded capture in
    `test_recorded_userinfo_answers_numofcard_not_cardno`. The `password` key rides along
    because the real device sends one and `user_record_from_device` must still strip it.
    """
    return {
        "employeeNo": no,
        "name": name if name is not None else f"User E{no}",
        "userType": "normal",
        "doorRight": "1",
        "RightPlan": [{"doorNo": 1, "planTemplateNo": "1"}],
        "localUIRight": True,
        "numOfCard": cards,
        "numOfFP": 0,
        "numOfFace": faces,
        "password": "fake" + "hash",
    }


def card_row(employee_no: str, card_no: str) -> dict[str, Any]:
    """One `CardInfo/Search` row, verbatim shape of the captured read-back."""
    return {
        "employeeNo": employee_no,
        "cardNo": card_no,
        "leaderCard": "",
        "cardType": "normalCard",
    }


_T0 = datetime(2026, 10, 19, 10, 0, tzinfo=UTC)
INGEST_TARGET = "https://ingest.example/gateclerk_ingest"


def roster_loop(
    device: FakeDevice,
    *,
    warn: Any = None,
    push_to: str | None = None,
    sent: list[Any] | None = None,
) -> DeviceLoop:
    """A loop whose roster is the REAL walk over `device` — no injected roster.

    The `roster=` seam exists so other tests can skip the walk; using it here would
    prove nothing about the join, so this builds the loop the agent builds and lets
    `_read_roster` walk the fake's two search routes itself. `push_to` wires a recording
    transport for the cases that push a whole roster line.
    """
    client = IsapiClient(
        BASE_URL, "admin", PASSWORD, transport=device.transport, sleep=lambda _s: None
    )
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    return DeviceLoop(
        client=client,
        conn=conn,
        site=SITE,
        site_tz="Europe/Bucharest",
        cadence_s=300,
        overlap_s=300,
        now=lambda: _T0,
        monotonic=lambda: 0.0,
        sleep=lambda _s: None,
        warn=warn if warn is not None else (lambda _s: None),
        push_target=push_to,
        push_transport=_recorder(sent) if sent is not None else None,
        device_code=DEVICE_CODE if push_to else None,
    )


def _recorder(sent: list[Any]) -> Any:
    """A push transport that records (ref, line) and answers 200."""

    def send(ref: str, line: str) -> int:
        sent.append((ref, line))
        return 200

    return send


def roster_of(*, users: list[dict[str, Any]], cards: list[dict[str, Any]]) -> list[Any]:
    device = FakeDevice(password=PASSWORD)
    device.seed_enrollment(users=users, cards=cards)
    return roster_loop(device)._read_roster()


def wire_users(users: list[Any]) -> list[dict[str, Any]]:
    """The `users` array of the roster line the agent would send for these records."""
    line = device_users_line(device_code=DEVICE_CODE, users=users)
    assert line.endswith("\n") and line.count("\n") == 1
    parsed = json.loads(line)
    assert parsed["kind"] == "device_users" and parsed["deviceCode"] == DEVICE_CODE
    return parsed["users"]


# --- the device truth this card is built on ----------------------------------------------


def test_recorded_userinfo_answers_numofcard_not_cardno() -> None:
    """The premise, from the committed capture — not from the card's prose.

    If a future firmware starts answering `cardNo` inside `UserInfo/Search`, this is the
    test that says the join may become redundant; the fake's rows above mirror the same
    asymmetry on purpose so the join stays exercised either way.
    """
    page = json.loads(
        (
            Path(__file__).parent / "fixtures/recorded/site-a-ds-k1t341amf-s/user_search_page1.json"
        ).read_text(encoding="utf-8")
    )
    rows = page["UserInfoSearch"]["UserInfo"]
    assert rows and not any("cardNo" in r for r in rows)
    assert any("numOfCard" in r for r in rows)


# --- the join ----------------------------------------------------------------------------


def test_roster_joins_card_info_and_fills_card_no() -> None:
    """A user the device says holds a card gets its number onto the roster line.

    The `cardNo` lands in the record's `raw` (the key `_roster_user` reads) and reaches
    the wire — which is the whole point: BC 70605's "Card No." column is filled and
    `Nelegati` has something to link.
    """
    users = roster_of(
        users=[user_row("1", cards=1, faces=1), user_row("2", cards=0)],
        cards=[card_row("1", "1001")],
    )

    by_no = {u.employee_no: u for u in users}
    assert by_no["1"].raw["cardNo"] == "1001"
    assert "cardNo" not in by_no["2"].raw

    emitted = wire_users(users)
    assert emitted[0] == {
        "employee_no": "1",
        "name": "User E1",
        "cardNo": "1001",
        "hasFace": True,
    }
    # `numOfCard` is what the device sent, and it stays home: the four keys are the
    # whole privacy boundary of this line (card: "Do not add numOfCard ... to the wire").
    for user in emitted:
        assert set(user) == {"employee_no", "name", "cardNo", "hasFace"}


def test_user_with_no_card_stays_null() -> None:
    """`numOfCard: 0` -> `"cardNo": null`, not an empty string and not a missing key.

    The function's classifier tolerates null; an absent key or `""` would make "no card"
    and "card we failed to read" indistinguishable in BC.
    """
    users = roster_of(users=[user_row("7", cards=0, faces=0)], cards=[])

    assert users[0].raw.get("cardNo") is None
    assert wire_users(users) == [
        {"employee_no": "7", "name": "User E7", "cardNo": None, "hasFace": False}
    ]


def test_multiple_cards_pick_the_lowest_numeric_card() -> None:
    """The pinned primary-card rule: numeric beats lexicographic, lowest wins.

    Lexicographic order would name "1002" (it sorts before "900") and BC would link the
    wrong card to the person — a silent payroll misattribution, not a cosmetic choice.
    A non-numeric card loses to every numeric one, which is what makes the rule
    deterministic when a site mixes formats.
    """
    users = roster_of(
        users=[user_row("1", cards=3)],
        cards=[card_row("1", "1002"), card_row("1", "900"), card_row("1", "A-7")],
    )

    assert users[0].raw["cardNo"] == "900"
    assert wire_users(users)[0]["cardNo"] == "900"


def test_primary_card_rule_is_pinned_as_documented() -> None:
    """The rule itself, key-for-key, including the cases the device has not shown yet.

    Numeric: numeric value, then the text (so "0900" and "900" still order). Non-numeric:
    plain text order, and it never outranks a numeric card. Blank entries are ignored
    rather than becoming the "lowest" card.
    """
    assert _primary_card(["1002", "900", "A-7"]) == "900"
    assert _primary_card(["A-7", "A-10"]) == "A-10"  # text order, pinned
    assert _primary_card(["A-7", "12"]) == "12"
    assert _primary_card(["", "  ", "12"]) == "12"
    assert _primary_card(["0900", "900"]) == "0900"


def test_card_walk_is_skipped_when_no_user_has_a_card() -> None:
    """Zero cards on the box => zero `CardInfo/Search` requests.

    A second walk costs device nonces against the ~190-use cap (docs/OBSERVED.md), so
    the join has to be earned by a user who actually holds a card. The fake's request
    ledger is the independent witness — a mock counting itself would prove nothing.
    """
    device = FakeDevice(password=PASSWORD)
    device.seed_enrollment(users=[user_row("1", cards=0), user_row("2", cards=0)], cards=[])

    roster_loop(device)._read_roster()

    assert device.requests_to("POST", USER_SEARCH_PATH) >= 1
    assert device.requests_to("POST", CARD_SEARCH_PATH) == 0


def test_card_walk_happens_once_even_with_several_card_holders() -> None:
    """One conditional walk, not one per user: the join is a dict, not a nested request.

    N card-holders must still cost a single (paged) `CardInfo/Search` walk, or the
    hourly roster scales with the roster size against a capped nonce budget.
    """
    device = FakeDevice(password=PASSWORD)
    device.seed_enrollment(
        users=[user_row("1", cards=1), user_row("2", cards=1), user_row("3", cards=0)],
        cards=[card_row("1", "1001"), card_row("2", "1002")],
    )

    users = roster_loop(device)._read_roster()

    assert {u.employee_no: u.raw.get("cardNo") for u in users} == {
        "1": "1001",
        "2": "1002",
        "3": None,
    }
    assert device.requests_to("POST", CARD_SEARCH_PATH) == 1


def test_a_card_that_belongs_to_nobody_and_a_row_without_a_number_are_both_ignored() -> None:
    """A `CardInfo` row naming an unknown employee is dropped, and a numberless row too.

    Neither may raise: the roster is re-derivable from the device and an orphan card
    (enrolled, person since deleted) is normal site drift, not a reason to withhold the
    whole roster. A row whose `cardNo` is absent or blank must also never reach BC as the
    literal text `"None"` or `""` — that would look like a real card number.
    """
    device = FakeDevice(password=PASSWORD)
    device.seed_enrollment(
        users=[user_row("1", cards=3), user_row("2", cards=1)],
        cards=[
            card_row("999", "5555"),  # no such employee on the box
            {"employeeNo": "1", "cardNo": None},  # the firmware's other "no number"
            {"employeeNo": "2"},  # key absent entirely
            card_row("1", ""),  # a number that is only whitespace
            card_row("1", "1001"),
        ],
    )

    users = roster_loop(device)._read_roster()

    by_no = {u.employee_no: u for u in users}
    assert by_no["1"].raw["cardNo"] == "1001"
    assert by_no["1"].raw["cardNo"] not in ("None", "")
    assert "cardNo" not in by_no["2"].raw  # every row for E2 named a number

    emitted = wire_users(users)
    assert [u["cardNo"] for u in emitted] == ["1001", None]


def test_password_stays_stripped_and_no_card_number_reaches_a_warning() -> None:
    """The two redaction rules of this line, on the real push path.

    `user_record_from_device` owns the password strip and GC-P05 must not weaken it by
    rebuilding `raw`; and the card forbids a card number in logs. Both are asserted
    against the loop's own `warn` sink while a roster is actually pushed.
    """
    device = FakeDevice(password=PASSWORD)
    device.seed_enrollment(users=[user_row("1", cards=1)], cards=[card_row("1", "1001")])

    warnings: list[str] = []
    sent: list[tuple[str, str]] = []
    loop = roster_loop(device, warn=warnings.append, push_to=INGEST_TARGET, sent=sent)

    result = loop.push_device_users()

    assert result is not None and result.ok is True and result.users == 1
    body = json.loads(sent[0][1])
    assert body["users"][0]["cardNo"] == "1001"
    assert "password" not in json.dumps(body)
    assert not any("1001" in w or "fake" in w for w in warnings)
