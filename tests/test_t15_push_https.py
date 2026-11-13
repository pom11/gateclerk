"""Card T15 (plan Task 15): the agent's real push target — HTTPS + keychain bearer.

BINDING CONTRACT: the merged `gateclerk_ingest` function (upstream `functions/main.py`,
commit c9f93fa) and its own frozen test docstring (`functions/test_gateclerk_ingest.py`),
plus the orch comment on this card. This file codes against THAT text verbatim; nothing
here invents an endpoint, a header name, or a line shape:

  POST <push_target>            Content-Type: application/jsonl
  Authorization: Bearer <per-site ingest token>     401 absent/unknown/revoked
  X-GateClerk-Site: <SITE>                            CONFIRMS the token's site only;
                                                    a contradicting claim is 403
                                                    site_token_mismatch, zero BC traffic

  scan line   = model.EventRecord.to_json() (byte-verbatim, the send buffer's bytes)
  roster line = {"kind":"device_users","deviceCode":...,"users":[{"employee_no",
                 "name","cardNo","hasFace"}]}                        (hourly, Task 15)

  200 {"status":true,"site":...,"scans":{accepted,inserted,replayed,skipped},
       "deviceUsers":{upserted}}   ·  422 unknown_device_serials  ·  502 bc_unavailable

The three DoD cases the card dictates by name are `test_https_transport_sends_bearer`,
`test_device_users_line_shape` and `test_token_never_logged`; the rest pin the frozen
contract's failure shapes onto the machinery P2-04 already owns (backoff, dead-letter,
replay) so it is visible that T15 changed the transport, not the retry policy.

Offline by construction: the real `httpx.Client` is handed an `httpx.MockTransport`, so
no socket opens (conftest.netoff would kill one anyway) while the request the agent would
actually put on the wire — method, URL, headers, body bytes — is captured verbatim. The
token is a placeholder by the repo's hygiene policy (`fake-ingest-token-*`); every
credential-shaped value in this file is recognisably fake and every host is TEST-NET or
an `.invalid` name, never a real address.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

import gateclerk.agent_db as agent_db
import gateclerk.agent_push as agent_push
import gateclerk.agent_store as agent_store
from gateclerk.model import EventRecord, UserRecord, to_jsonl

SITE = "site-a"
SERIAL = "MASKED-SER-1"
HTTPS_TARGET = "https://ingest.example.invalid/gateclerk_ingest"

#: Placeholder by tests/test_repo_hygiene.py's PLACEHOLDER policy (recognisably fake).
TOKEN = "fake-ingest-token-site-a"
#: A second placeholder so "which token was sent" is a real assertion, not a tautology.
OTHER_TOKEN = "fake-ingest-token-site-b"

T0 = datetime(2026, 10, 19, 10, 0, 0, tzinfo=UTC)
BOUND = 86400


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def make_record(**over: Any) -> EventRecord:
    """One site-a-shaped record (masked names, TEST-NET-era serial: hygiene policy)."""
    payload: dict[str, Any] = {
        "site": SITE,
        "device_serial": SERIAL,
        "serial_no": 5742,
        "employee_no": "1",
        "name": "User E1",
        "event_time_utc": "2026-10-12T12:11:16+00:00",
        "event_time_local": "2026-10-12T14:11:16+02:00",
        "tz_offset_min": 180,
        "tz_offset_min_device": 120,
        "tz_source": "site-tz",
        "iana_tz": "Europe/Bucharest",
        "direction": "in",
        "attendance_status": "checkIn",
        "direction_source": "device",
        "verify_mode": "cardOrFaceOrFp",
        "major": 5,
        "minor": 75,
        "outcome": "granted",
        "raw": {"major": 5, "minor": 75, "serialNo": 5742},
        "captured_at": "2026-10-19T10:00:00+00:00",
    }
    payload.update(over)
    return EventRecord.from_dict(payload)


def one_line(record: EventRecord) -> str:
    return to_jsonl([record])[:-1]


class Capture:
    """The MockTransport's notebook: exactly what would have gone on the wire."""

    def __init__(self, *outcomes: int | Exception) -> None:
        self.outcomes = list(outcomes)
        self.requests: list[httpx.Request] = []

    @property
    def transport(self) -> httpx.BaseTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            if not self.outcomes:
                raise AssertionError("the scripted ingest ran out of outcomes")
            outcome = self.outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return httpx.Response(
                outcome,
                json={"status": outcome == 200, "site": SITE},
                headers={"Content-Type": "application/json"},
            )

        return httpx.MockTransport(handler)

    @property
    def headers(self) -> httpx.Headers:
        assert self.requests, "the transport sent nothing"
        return self.requests[0].headers

    @property
    def body(self) -> bytes:
        assert self.requests, "the transport sent nothing"
        return self.requests[0].content


def client_for(*outcomes: int | Exception) -> tuple[httpx.Client, Capture]:
    capture = Capture(*outcomes)
    return httpx.Client(transport=capture.transport), capture


class FakeKeychain:
    """A KeychainReader stand-in with the real `read(target, with_comment=...)` seam."""

    def __init__(self, *, items: dict[str, str] | None = None, fail: bool = False) -> None:
        self.items = items or {}
        self.fail = fail
        self.reads: list[tuple[str, bool]] = []

    def read(self, target: Any, *, with_comment: bool = True) -> Any:
        from gateclerk.secrets import Secret

        self.reads.append((target.keychain_service, with_comment))
        if self.fail:
            from gateclerk.config import CredentialUnavailable

            raise CredentialUnavailable(f"no item for service {target.keychain_service!r}")
        value = self.items.get(target.keychain_service)
        if value is None:
            from gateclerk.config import CredentialUnavailable

            raise CredentialUnavailable(
                f"keychain item missing for service {target.keychain_service!r}"
            )
        return type(
            "Item",
            (),
            {"password": Secret(value, label=f"keychain:{target.keychain_service}")},
        )()


@pytest.fixture
def db(tmp_path):
    """A fresh agent db (connect = pragmas + migrations), same seam as P2-04's suite."""
    conn = agent_db.connect(tmp_path / "agent.sqlite3")
    yield conn
    conn.close()


def stored(db: sqlite3.Connection, record: EventRecord) -> int:
    result = agent_store.store_events(db, [record], now=T0)
    assert result.inserted == 1
    # `rowids` is the store's own serial_no -> rowid map (StoreResult); a bare
    # `SELECT id FROM events` would hand back the FIRST row for every call once a
    # test stores more than one event, and the drain would queue one event twice.
    rowids = result.rowids or {}
    assert record.serial_no is not None and record.serial_no in rowids
    return rowids[record.serial_no]


class Rng:
    """A pinned rng (one draw per failed row), the same class test_p2_04_pusher uses."""

    def __init__(self, *values: float) -> None:
        self.seq = list(values)
        self.calls = 0

    def __call__(self) -> float:
        self.calls += 1
        return self.seq.pop(0) if self.seq else 1.0


# =====================================================================================
# DoD 1 — test_https_transport_sends_bearer: the wire shape the function expects
# =====================================================================================


def test_https_transport_sends_bearer() -> None:
    """The request on the wire: bearer header, jsonl content-type, verbatim body, 200.

    This is the whole T15 contract in one assertion set. Every piece is the function's
    own text: `Authorization: Bearer <token>` (401 without it), `Content-Type:
    application/jsonl` (the frozen test docstring pins that media type), the body is the
    buffered line byte-for-byte plus its newline (the function `splitlines()`s it), and
    the target URL is used exactly as configured — no path is invented here.
    """
    client, capture = client_for(200)
    transport = agent_push.https_transport(SITE, token=TOKEN, client=client)

    status = transport(HTTPS_TARGET, one_line(make_record()))

    assert status == 200
    assert len(capture.requests) == 1
    request = capture.requests[0]
    assert request.method == "POST"
    assert str(request.url) == HTTPS_TARGET
    assert capture.headers["authorization"] == f"Bearer {TOKEN}"
    assert capture.headers["content-type"] == "application/jsonl"
    # The site travels as a CONFIRMATION only (contract 1): uppercase, because the
    # function uppercases the claim before comparing it to the token's site.
    assert capture.headers["x-gateclerk-site"] == SITE.upper()
    assert capture.body.decode("utf-8") == one_line(make_record()) + "\n"


def test_https_transport_is_a_transport_the_existing_drain_accepts(db: sqlite3.Connection) -> None:
    """The new transport plugs into `drain` with NO change to the queue machinery.

    `Transport` is the callable `(url, body) -> status` P2-04 defined; a successful push
    must DELETE the buffer row and leave the event in the store (spec §2b: the queue is
    a transient buffer, the store is the truth). Pinning the integration here is what
    keeps "the existing retry/dead-letter replay must stay safe" honest rather than
    asserted in prose.
    """
    event_id = stored(db, make_record())
    agent_push.enqueue_events(db, [event_id], endpoint=HTTPS_TARGET, now=T0)
    client, capture = client_for(200)
    transport = agent_push.https_transport(SITE, token=TOKEN, client=client)

    result = agent_push.drain(db, endpoint=HTTPS_TARGET, transport=transport, now=T0, rng=Rng(1.0))

    assert result.push_ok == 1 and result.push_failed == 0
    assert agent_push.queue_depth(db) == 0
    assert agent_push.dead_letter_depth(db) == 0
    assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    assert json.loads(capture.body.decode("utf-8").strip())["serial_no"] == 5742


def test_bearer_resolves_from_the_site_keychain_item_not_a_global_fallback() -> None:
    """Contract 1: the token DETERMINES the site, so it is resolved PER SITE.

    A shared "one ingest token" rung would let site-a's agent authenticate as whichever
    site the resolver happened to find first — the exact confusion the function refuses
    with 403 site_token_mismatch. The item is the keychain service named in the card,
    `gateclerk-ingest-<site>`, and it is read with `with_comment=False`: a second
    `security` call is a second macOS ACL prompt for a comment this transport cannot use.
    """
    keychain = FakeKeychain(
        items={f"gateclerk-ingest-{SITE}": TOKEN, "gateclerk-ingest-site-b": OTHER_TOKEN}
    )
    client, capture = client_for(200)
    transport = agent_push.https_transport(SITE, keychain=keychain, client=client)

    assert transport(HTTPS_TARGET, one_line(make_record())) == 200
    assert capture.headers["authorization"] == f"Bearer {TOKEN}"
    assert keychain.reads == [(f"gateclerk-ingest-{SITE}", False)]


def test_bearer_resolves_from_env_when_no_token_is_passed() -> None:
    """The env rung mirrors the function's own `GATECLERK_INGEST_TOKEN_<SITE>` naming.

    Same variable name on both ends on purpose: the operator sets one name per site and
    it works in the agent's environment and in the Cloud Run function's. Lowercase site
    names are uppercased for the lookup because the function uppercases its site codes.
    """
    client, capture = client_for(200)
    transport = agent_push.https_transport(
        SITE, env={"GATECLERK_INGEST_TOKEN_SITE-A": TOKEN}, client=client
    )

    assert transport(HTTPS_TARGET, one_line(make_record())) == 200
    assert capture.headers["authorization"] == f"Bearer {TOKEN}"


def test_precedence_is_token_then_env_then_keychain() -> None:
    """p1-02's rung order, kept: explicit token > env > keychain, nothing else."""
    keychain = FakeKeychain(items={f"gateclerk-ingest-{SITE}": "fake-keychain-token"})
    client, capture = client_for(200, 200)
    from_env = agent_push.https_transport(
        SITE,
        env={"GATECLERK_INGEST_TOKEN_SITE-A": TOKEN},
        keychain=keychain,
        client=client,
    )
    assert from_env(HTTPS_TARGET, "x\n") == 200
    assert capture.headers["authorization"] == f"Bearer {TOKEN}"

    explicit = agent_push.https_transport(
        SITE,
        token="fake-explicit-token",
        env={"GATECLERK_INGEST_TOKEN_SITE-A": TOKEN},
        keychain=keychain,
        client=client,
    )
    assert explicit(HTTPS_TARGET, "x\n") == 200
    assert capture.requests[1].headers["authorization"] == "Bearer fake-explicit-token"
    assert keychain.reads == [], "an explicit token must not touch the keychain"


def test_a_missing_token_is_a_loud_refusal_naming_the_keychain_command() -> None:
    """No token is never "send without a header": that is a 401 and a lost punch.

    The refusal names the keychain SERVICE (never a value) so the owner's fix is one
    copy-pasted `security add-generic-password`.
    """
    client, capture = client_for(200)
    transport = agent_push.https_transport(
        SITE, env={}, keychain=FakeKeychain(items={}), client=client
    )

    with pytest.raises(agent_push.IngestTokenUnavailableError) as excinfo:
        transport(HTTPS_TARGET, "x\n")

    message = str(excinfo.value)
    assert f"gateclerk-ingest-{SITE}" in message
    assert "add-generic-password" in message
    assert capture.requests == []


def test_https_transport_refuses_a_target_it_cannot_secure() -> None:
    """`stub://` and plain `http://` are refused: a bearer must never cross clear text,

    and a bearer transport aimed at a local stub would let a test go green by writing to
    disk while believing it authenticated to the ingest.
    """
    client, capture = client_for(200)
    transport = agent_push.https_transport(SITE, token=TOKEN, client=client)

    for target in (
        "stub://ingest/lines.jsonl",
        "http://ingest.example.invalid/gateclerk_ingest",
        "HTTPS://ingest.example.invalid/gateclerk_ingest",
        "ftp://ingest.example.invalid/x",
        "ingest.example.invalid/gateclerk_ingest",
    ):
        with pytest.raises(agent_push.PushTargetError):
            transport(target, "x\n")
    assert capture.requests == []


def test_tls_verification_stays_on() -> None:
    """`verify=False` is banned in this repo (gotchas §4.1): an ingest over TLS with
    verification off is a bearer token handed to whoever answers the DNS."""
    client, _capture = client_for(200)
    transport = agent_push.https_transport(SITE, token=TOKEN, client=client)
    assert transport.verify is True  # type: ignore[attr-defined]

    # The default client this factory builds (no injected client) must verify too.
    default = agent_push.https_transport(SITE, token=TOKEN)
    assert default.verify is True  # type: ignore[attr-defined]
    assert default.timeout is not None  # explicit timeouts, not httpx's defaults


# =====================================================================================
# DoD 2 — test_device_users_line_shape: the hourly roster line, verbatim
# =====================================================================================


def roster_users() -> list[UserRecord]:
    """Three device users, including the shapes the function's classifier keys on.

    E2 has no name on the device (encrypted/blank); E3 carries a card and no face. A
    diacritic name pins `ensure_ascii=False`, because the function compares the raw
    string and an escaped name would arrive as `\\u021b`.
    """
    return [
        UserRecord.from_dict(
            {
                "employee_no": "1",
                "name": "User E1",
                "user_type": "normal",
                "valid_from": "2000-01-01T00:00:00",
                "valid_to": "2037-12-31T23:59:59",
                "valid_enabled": True,
                "raw": {"employeeNo": "1", "numOfFace": 1, "numOfCard": 1, "cardNo": "1001"},
            }
        ),
        UserRecord.from_dict({"employee_no": "2", "raw": {"employeeNo": "2", "numOfFace": 0}}),
        UserRecord.from_dict(
            {
                "employee_no": "3",
                "name": "User E3 ✓",
                "raw": {"employeeNo": "3", "numOfFace": 0, "cardNo": "1003"},
            }
        ),
    ]


def test_device_users_line_shape() -> None:
    """The roster line is the function's own shape — key-for-key, no extras.

    `functions/main.py` classifies a line by `kind == "device_users"`, needs a non-empty
    `deviceCode` and a `users` LIST, and per user reads `employee_no` (empty -> 400
    invalid_user_line), `name`, `cardNo` (or `card_no`) and `hasFace` (or `has_face`).
    Everything else the function ignores, so everything else is payroll data with no
    reason to cross the wire: validity windows and the device PIN stay home.
    """
    line = agent_push.device_users_line(device_code="D-IF-1", users=roster_users())

    parsed = json.loads(line)
    assert parsed["kind"] == "device_users"
    assert parsed["deviceCode"] == "D-IF-1"
    assert [u["employee_no"] for u in parsed["users"]] == ["1", "2", "3"]
    assert parsed["users"][0] == {
        "employee_no": "1",
        "name": "User E1",
        "cardNo": "1001",
        "hasFace": True,
    }
    # A user the device gave no name to is still a roster row: `employee_no` is the key
    # the function demands, `name` is decoration it tolerates as null.
    assert parsed["users"][1] == {
        "employee_no": "2",
        "name": None,
        "cardNo": None,
        "hasFace": False,
    }
    assert parsed["users"][2]["hasFace"] is False
    assert parsed["users"][2]["cardNo"] == "1003"
    # Exactly the four keys per user — nothing else may ride along.
    for user in parsed["users"]:
        assert set(user) == {"employee_no", "name", "cardNo", "hasFace"}
    assert set(parsed) == {"kind", "deviceCode", "users"}


def test_device_users_line_is_one_compact_newline_terminated_jsonl_record() -> None:
    """Compact separators + `ensure_ascii=False` + exactly one trailing newline.

    The function `splitlines()`s the body and `json.loads`es each piece: a pretty-printed
    roster would arrive as a batch of broken lines, and a newline-free payload would be
    glued to whatever the agent sends next if the ingest ever appends.
    """
    line = agent_push.device_users_line(device_code="D-IF-1", users=roster_users())

    assert line.endswith("\n") and line.count("\n") == 1
    assert '", "' not in line, "must be compact, not indented"
    assert "\\u" not in line, "ensure_ascii=False: diacritics stay readable"
    assert "✓" in line


def test_device_users_line_names_the_device_the_bc_registry_knows() -> None:
    """`deviceCode` is the BC code when configured, else the serial.

    The function resolves serial -> code through `gateclerkDevices` and accepts either
    (a serial already in the registry answers 200), so the agent sends its own serial by
    default and the owner configures `device_code` only where BC's page 70602 carries a
    different code. An unknown one comes back 422 with the actionable list.
    """
    by_serial = json.loads(agent_push.device_users_line(device_code=SERIAL, users=roster_users()))
    assert by_serial["deviceCode"] == SERIAL

    by_code = json.loads(agent_push.device_users_line(device_code="D-IF-1", users=roster_users()))
    assert by_code["deviceCode"] == "D-IF-1"


def test_device_users_line_carries_no_credential_and_no_validity_window() -> None:
    """The PIN never existed here (UserRecord strips `password` at read time) and the
    roster's purpose is BC's Nelegati list — who is on a device — not who may in when.
    """
    line = agent_push.device_users_line(device_code="D-IF-1", users=roster_users())
    lowered = line.lower()
    for banned in ("password", "valid_from", "valid_to", "user_type", "raw", "pin"):
        assert banned not in lowered, f"{banned} must not reach the ingest"


# =====================================================================================
# DoD 3 — test_token_never_logged: the token is a credential, not a log field
# =====================================================================================


def test_token_never_logged(tmp_path: Path) -> None:
    """The card's own DoD name. Every surface a token could leak through is checked.

    The surfaces are the real ones: the transport's repr (a debugger, a `--verbose` dump,
    a pytest assertion diff), the drain's log sink (which journald collects), the
    dead-letter row sqlite keeps forever, the exception text a failed push raises, and
    the roster-push report. A token that reaches any of them is a revoked token, and the
    owner then has to know which site's credential leaked where.
    """
    client, _capture = client_for(502, 502)
    transport = agent_push.https_transport(SITE, token=TOKEN, client=client)
    assert TOKEN not in repr(transport)
    assert TOKEN not in str(transport)

    logs: list[str] = []
    db = agent_db.connect(tmp_path / "agent.sqlite3")
    event_id = stored(db, make_record())
    agent_push.enqueue_events(db, [event_id], endpoint=HTTPS_TARGET, now=T0)

    # Fail it past the 24 h bound so the row lands in dead_letter, then replay it.
    for moment in (T0, at(BOUND), at(BOUND + 1)):
        agent_push.drain(
            db,
            endpoint=HTTPS_TARGET,
            transport=transport,
            now=moment,
            rng=Rng(1.0),
            log=logs.append,
        )
    rows = agent_push.dead_letter_rows(db)
    assert rows, "the fixture must produce a dead-letter row to inspect"
    replayed = agent_push.replay_dead_letter(db, rows[0].id, now=at(BOUND + 2))
    assert replayed > 0

    haystacks = {
        "repr": repr(transport),
        "str": str(transport),
        "logs": "\n".join(logs),
        "dead_letter": "\n".join(f"{row.error_class}|{row.payload}|{row.endpoint}" for row in rows),
        "pending": "\n".join(
            f"{row.last_error_class}|{row.endpoint}" for row in agent_push.pending_rows(db)
        ),
        "token_label": str(getattr(transport, "token_label", "")),
    }
    for name, text in haystacks.items():
        assert TOKEN not in text, f"the bearer leaked into {name}"


def test_a_failing_ingest_exception_carries_no_token() -> None:
    """`drain` stores the exception's CLASS NAME and the dead-letter keeps the payload —
    but an owner running `--verbose` sees the message, so the message is checked too.

    The transport must not wrap httpx errors into its own class (the class name is the
    owner's diagnostic: `ConnectError` vs `ReadTimeout` are different fixes), so this
    pins the leak property on the exception that actually escapes.
    """
    client, _capture = client_for(
        httpx.ConnectError("dns refused"), httpx.ReadTimeout("read timed out")
    )
    transport = agent_push.https_transport(SITE, token=TOKEN, client=client)

    with pytest.raises(httpx.ConnectError) as first:
        transport(HTTPS_TARGET, "x\n")
    with pytest.raises(httpx.ReadTimeout) as second:
        transport(HTTPS_TARGET, "x\n")

    for excinfo in (first, second):
        assert TOKEN not in str(excinfo.value)
        assert TOKEN not in repr(excinfo.value)


def test_the_authorization_header_value_is_never_in_a_dead_letter_error_class(
    db: sqlite3.Connection,
) -> None:
    """A 401 must read as `HttpStatus401`, not as anything carrying the credential.

    P2-04's `_error_class` folds the status into the class name (so an owner can tell
    "wait for the ingest" from "fix our payload"); this pins that the new transport does
    not smuggle the response body or the request headers into that column.
    """
    event_id = stored(db, make_record())
    agent_push.enqueue_events(db, [event_id], endpoint=HTTPS_TARGET, now=T0)
    client, _capture = client_for(401)
    transport = agent_push.https_transport(SITE, token=TOKEN, client=client)

    agent_push.drain(
        db, endpoint=HTTPS_TARGET, transport=transport, now=T0, rng=Rng(1.0), log=lambda _s: None
    )

    row = db.execute("SELECT last_error_class FROM push_queue").fetchone()
    assert row["last_error_class"] == "HttpStatus401"


# =====================================================================================
# The frozen contract's failure shapes, mapped onto P2-04's existing policy
# =====================================================================================


def test_bc_unavailable_502_backs_off_then_a_replay_is_accepted(db: sqlite3.Connection) -> None:
    """Contract 4: 502 bc_unavailable -> back off and retry; idempotency is server-side.

    The replay safety is the function's (BC dedups on the fingerprint, a replay answers
    `inserted:false` and still 200), which is exactly why the agent may re-send the same
    bytes without a second thought. P2-04's ladder (1 s then the cap, 24 h to dead-letter)
    is unchanged by T15 — this test exists to prove that.
    """
    event_id = stored(db, make_record())
    agent_push.enqueue_events(db, [event_id], endpoint=HTTPS_TARGET, now=T0)
    client, capture = client_for(502, 200)
    transport = agent_push.https_transport(SITE, token=TOKEN, client=client)

    first = agent_push.drain(db, endpoint=HTTPS_TARGET, transport=transport, now=T0, rng=Rng(1.0))
    assert first.push_failed == 1 and agent_push.queue_depth(db) == 1
    due = db.execute("SELECT next_attempt_at FROM push_queue").fetchone()["next_attempt_at"]
    assert due > T0.isoformat(timespec="seconds"), "a 502 must be backed off, not re-hit"

    second = agent_push.drain(
        db,
        endpoint=HTTPS_TARGET,
        transport=transport,
        now=datetime.fromisoformat(due),
        rng=Rng(1.0),
    )
    assert second.push_ok == 1
    assert agent_push.queue_depth(db) == 0
    assert capture.requests[1].content == capture.requests[0].content, "same bytes replayed"


def test_unknown_device_serial_422_dead_letters_then_replays(db: sqlite3.Connection) -> None:
    """Contract 3's 422 is a PAYLOAD answer: GC-P08 dead-letters it on the first failure.

    The T15-era text of this test pinned the opposite ("422 stays retryable") and the reasoning
    was sound for its time: the fix for `unknown_device_serials` really is BC-side (register the
    serial on page 70602), and a queue that retried the refused line for 24 h at least kept the
    punch. GC-P08 moves that payload somewhere the owner can SEE it — `dead_letter`, holding the
    full JSONL line, `HttpStatus422` and `attempts = 1` — instead of spending the site's request
    budget on a line the ingest will never accept.

    The two claims that were always the point of this test stay pinned: a refusal is NEVER
    counted as a send, and the payload survives intact. What changed is the recovery — one
    operator step (`agent_push.replay_dead_letter`, which carries the attempt count and outage
    clock over) replaces an automatic retry, and the row then goes out with the same bytes.
    """
    event_id = stored(db, make_record())
    agent_push.enqueue_events(db, [event_id], endpoint=HTTPS_TARGET, now=T0)
    client, capture = client_for(422, 200)
    transport = agent_push.https_transport(SITE, token=TOKEN, client=client)

    first = agent_push.drain(db, endpoint=HTTPS_TARGET, transport=transport, now=T0, rng=Rng(1.0))
    assert first.push_ok == 0 and first.push_failed == 1
    assert first.dead_lettered == (event_id,) and first.retried == ()
    assert len(capture.requests) == 1, "a line the ingest will never accept is sent once"

    dead = db.execute("SELECT * FROM dead_letter").fetchall()
    assert len(dead) == 1, "the refused payload must be kept where an owner can list it"
    assert dead[0]["attempts"] == 1 and dead[0]["error_class"] == "HttpStatus422"
    assert db.execute("SELECT COUNT(*) FROM push_queue").fetchone()[0] == 0

    # The serial gets registered on the BC page and the owner replays: the SAME line is
    # accepted, and a success clears both the queue row and the dead-letter row.
    agent_push.replay_dead_letter(db, dead[0]["id"], now=T0)
    second = agent_push.drain(db, endpoint=HTTPS_TARGET, transport=transport, now=T0, rng=Rng(1.0))
    assert second.push_ok == 1
    assert json.loads(capture.requests[1].content.decode("utf-8"))["site"] == SITE
    assert db.execute("SELECT COUNT(*) FROM dead_letter").fetchone()[0] == 0


def test_site_token_mismatch_403_is_recorded_as_a_failure_not_a_send(
    db: sqlite3.Connection,
) -> None:
    """Contract 1's 403: our token and our claimed site disagree. The agent's own `site`
    field is what the function compares, so this is a config error worth surfacing —
    the queue must not silently keep it as "sent".
    """
    event_id = stored(db, make_record(site="site-b"))
    agent_push.enqueue_events(db, [event_id], endpoint=HTTPS_TARGET, now=T0)
    client, capture = client_for(403, 200)
    transport = agent_push.https_transport(SITE, token=TOKEN, client=client)

    result = agent_push.drain(db, endpoint=HTTPS_TARGET, transport=transport, now=T0, rng=Rng(1.0))
    assert result.push_ok == 0
    assert capture.requests[0].headers["x-gateclerk-site"] == SITE.upper()
    assert (
        db.execute("SELECT last_error_class FROM push_queue").fetchone()["last_error_class"]
        == "HttpStatus403"
    )


def test_site_confirmation_header_can_be_turned_off_for_a_site_that_omits_it() -> None:
    """The header is OPTIONAL on the function side (it falls back to the line's `site`
    field), so the agent must be able to send no claim at all rather than a wrong one.
    """
    client, capture = client_for(200)
    transport = agent_push.https_transport(SITE, token=TOKEN, client=client, confirm_site=False)

    assert transport(HTTPS_TARGET, "x\n") == 200
    assert "x-gateclerk-site" not in capture.headers


# =====================================================================================
# The hourly roster leg (agent_loop)
# =====================================================================================


class RosterClient:
    """A device stand-in: the roster walk, counted, so the hourly rule is observable."""

    def __init__(self, users: list[UserRecord] | None = None) -> None:
        self.users = users if users is not None else roster_users()
        self.calls = 0

    def search(self, name: str, body: dict[str, Any]) -> dict[str, Any]:  # pragma: no cover
        raise AssertionError(f"unexpected search {name!r}")


def loop_for(
    *,
    transport: Any = None,
    roster: Any = None,
    device_code: str | None = None,
    interval_s: int = 3600,
    now: datetime = T0,
):
    from gateclerk.agent_loop import DeviceLoop

    clock = {"value": now}

    loop = DeviceLoop(
        client=_SilentClient(),
        conn=_null_conn(),
        site=SITE,
        site_tz="Europe/Bucharest",
        cadence_s=300,
        overlap_s=300,
        now=lambda: clock["value"],
        monotonic=lambda: 0.0,
        sleep=lambda _s: None,
        warn=lambda _s: None,
        push_target=HTTPS_TARGET,
        push_transport=transport,
        device_users_interval_s=interval_s,
        device_code=device_code,
        roster=roster if roster is not None else (lambda: RosterClient().users),
    )
    # The roster runs in a loop that HAS ticked at least once: the bootstrap read
    # deviceInfo once and the serial is the roster's fallback deviceCode. Setting it
    # here says exactly that; the no-serial refusal is pinned by its own test below.
    loop.device_serial = SERIAL
    return loop, clock


class _SilentClient:
    """Only what the roster leg must not touch: the device walk stays unexercised."""

    def circuit_open(self) -> bool:
        return False

    def close(self) -> None:
        return None


def _null_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    return conn


def test_roster_push_goes_over_the_same_https_transport() -> None:
    """`agent_loop` "also pushes the device-user list hourly" (card), over T15's leg.

    One roster push = one POST with the roster line and the same bearer. This is the
    wiring the card asks for: the roster travels the same authenticated channel as the
    punches, and the loop owns the clock so the rule is testable without sleeping.
    """
    client, capture = client_for(200)
    transport = agent_push.https_transport(SITE, token=TOKEN, client=client)
    loop, _clock = loop_for(transport=transport)

    result = loop.push_device_users()

    assert result.ok is True and result.status == 200 and result.users == 3
    assert capture.requests[0].url.path == "/gateclerk_ingest"
    assert json.loads(capture.body.decode("utf-8").strip())["kind"] == "device_users"
    assert capture.headers["authorization"] == f"Bearer {TOKEN}"


def test_roster_push_is_hourly_not_every_tick() -> None:
    """3600 s is the card's cadence for this leg; a per-tick roster walk would spend the
    device's ~190-use nonce budget re-reading a list that changes when someone is
    enrolled (OBSERVED.md: `UserInfo/Search` is paged and its body carries no window).
    """
    client, capture = client_for(200, 200, 200)
    transport = agent_push.https_transport(SITE, token=TOKEN, client=client)
    loop, clock = loop_for(transport=transport, interval_s=3600)

    first = loop.push_device_users_if_due()
    clock["value"] = T0 + timedelta(seconds=1800)
    second = loop.push_device_users_if_due()
    clock["value"] = T0 + timedelta(seconds=3601)
    third = loop.push_device_users_if_due()

    assert first is not None and first.ok is True
    assert second is None, "30 min later the roster is not due"
    assert third is not None and third.ok is True
    assert len(capture.requests) == 2


def test_roster_push_failure_warns_and_retries_next_hour_without_touching_the_queue() -> None:
    """A roster is RE-DERIVABLE from the device at any time; a punch is not.

    So the roster leg deliberately does not use `push_queue`/`dead_letter` (`event_id`
    there is an FK to a stored event — a roster row has no event to point at) and a
    failure is a warning plus a retry on the next hour. The punches' durability is
    untouched by this leg.
    """
    client, capture = client_for(502, 502)
    transport = agent_push.https_transport(SITE, token=TOKEN, client=client)
    warns: list[str] = []
    loop, clock = loop_for(transport=transport)
    loop._warn = warns.append  # the injected stderr funnel (same seam the loop warns on)

    result = loop.push_device_users()
    assert result.ok is False and result.status == 502
    assert warns and TOKEN not in "\n".join(warns)
    assert _null_conn() is not None  # (no db involved in this leg at all)
    assert len(capture.requests) == 1

    clock["value"] = T0 + timedelta(seconds=3601)
    retry = loop.push_device_users_if_due()
    assert retry is not None and retry.status == 502
    assert len(capture.requests) == 2


def test_roster_push_is_skipped_when_no_push_target_is_configured() -> None:
    """§3: no target, no push. `push_device_users_if_due` is the loop's only roster leg
    and it must be a no-op rather than a crash for the (default) pusher-off site.
    """
    from gateclerk.agent_loop import DeviceLoop

    loop = DeviceLoop(
        client=_SilentClient(),
        conn=_null_conn(),
        site=SITE,
        site_tz="Europe/Bucharest",
        cadence_s=300,
        overlap_s=300,
        now=lambda: T0,
        monotonic=lambda: 0.0,
        sleep=lambda _s: None,
        warn=lambda _s: None,
    )
    assert loop.push_device_users_if_due() is None
    assert loop.push_device_users() is None


# =====================================================================================
# The fingerprint twin (contract 2) — the agent's digest must match the function's
# =====================================================================================


def _function_fingerprint(employee_no: str | None, local_text: str | None, minor: Any) -> str:
    """The function's OWN re-implementation (its test file hashes the same way).

    Pinned from the other side rather than asserted with our own helper: `main.py`
    builds `json.dumps({...}, sort_keys=True, separators=(",", ":"),
    ensure_ascii=False)` and sha256s it. If either side drifts, this test is where it
    shows up, before a silently-split punch reaches payroll.
    """
    canon = json.dumps(
        {
            "employee_no": employee_no,
            "event_time_local": local_text,
            "minor": minor,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def test_fingerprint_is_the_functions_own_digest_for_a_normal_line() -> None:
    from gateclerk.model import fingerprint_key_hash

    record = make_record()
    assert fingerprint_key_hash(
        record.employee_no, record.event_time_local, record.minor
    ) == _function_fingerprint(record.employee_no, record.event_time_local, record.minor)


def test_fingerprint_divergence_for_a_missing_minor_is_pinned() -> None:
    """The review's bounded caveat, pinned rather than discovered in payroll.

    The function coerces a non-int `minor` (None included) to 0 BEFORE hashing, while
    `model.fingerprint_key_hash` hashes the null. For an attributed line with no `minor`
    the two digests therefore differ, and a replay of such a line would insert a second
    row instead of being recognised. Recorded here as the known boundary: the agent's
    classifier always sets an int `minor` for an attributed device event, so this is a
    shape that should not occur — and if it ever does, this test says which side wins.
    """
    from gateclerk.model import fingerprint_key_hash

    agent_digest = fingerprint_key_hash("1", "2026-10-12T14:11:16+02:00", None)
    function_digest = _function_fingerprint("1", "2026-10-12T14:11:16+02:00", 0)

    assert agent_digest != function_digest
    # ...and the agent's own digest for the SAME line is stable, which is what the store
    # keys on: the risk is a silent split, not a crash.
    assert agent_digest == fingerprint_key_hash("1", "2026-10-12T14:11:16+02:00", None)


def test_scan_lines_are_still_eventrecord_bytes_and_batch_under_the_function_cap(
    db: sqlite3.Connection,
) -> None:
    """Contract 5: the function caps a batch at 5000 lines; the agent's drain caps at 200.

    A drain is therefore always inside the cap, and what goes out per row is still the
    stored `EventRecord.to_json()` bytes (the store's line is the wire's line — the
    fingerprint depends on that identity).
    """
    assert agent_push.DEFAULT_PUSH_BATCH_LIMIT <= 5000
    ids = [stored(db, make_record(serial_no=5700 + n, employee_no=str(n))) for n in range(3)]
    agent_push.enqueue_events(db, ids, endpoint=HTTPS_TARGET, now=T0)
    client, capture = client_for(200, 200, 200)
    transport = agent_push.https_transport(SITE, token=TOKEN, client=client)

    agent_push.drain(db, endpoint=HTTPS_TARGET, transport=transport, now=T0, rng=Rng(1.0))

    assert len(capture.requests) == 3
    for request, event_id in zip(capture.requests, ids, strict=True):
        stored_line = db.execute("SELECT jsonl FROM events WHERE id = ?", (event_id,)).fetchone()[
            "jsonl"
        ]
        assert request.content.decode("utf-8") == stored_line + "\n"


def test_sites_toml_example_documents_the_https_target_and_the_keychain_item() -> None:
    """The example config is the operator's only instruction sheet; it must carry the
    real shape (`https://…/gateclerk_ingest`) and the item name that holds the token,
    with a TEST-NET/example host — never a real deploy URL, which is config.
    """
    text = (Path(__file__).resolve().parents[1] / "sites.toml.example").read_text(encoding="utf-8")
    assert "gateclerk_ingest" in text
    assert "gateclerk-ingest-" in text
    assert "push_target" in text
