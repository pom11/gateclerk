"""GC-P08 — a 401/403 drops the cached bearer; a permanent 4xx does not burn 24 h.

Two failure modes this pins, one per half of the card:

1. **The bearer was cached for the life of the process.** `HttpsIngestTransport._resolve_token`
   memoises the secret (correctly: every macOS `security` call can raise an ACL prompt, so a
   drain must not re-ask per row) but nothing ever dropped that cache. Rotating the ingest
   token on the site host therefore left EVERY push failing with 401/403 until the agent was
   restarted — R2's "the agent must recover without a restart" is unmet by a memo with no
   expiry. The fix is one rung deep: an auth rejection clears the cached secret so the NEXT
   send walks the ladder again (rotated token, wrong site, credential file just installed).
   It deliberately does NOT retry the same row inside the same drain pass: one row gets one
   POST per drain, and a row that just failed is already rescheduled.

2. **A rejected payload was retried for 24 hours.** `drain` decided dead-letter from elapsed
   time alone, so a 400 (malformed line) or 422 (unknown device serial) hammered the site's
   request budget for a full day before an operator saw it. 400/422 say "this payload will
   never be accepted", so they dead-letter on the FIRST failure. 401/403 are excluded on
   purpose — they are credential/config problems a re-read can fix, and dead-lettering them
   would throw away the punches of a site mid-rotation.

The machinery under test is not re-invented here: the fake HTTP client and the drain/backoff
harness are IMPORTED from the suites that own them (`test_t15_push_https`, `test_p2_04_pusher`),
so a drift in either shows up as a failure in both places rather than as a fork that quietly
keeps passing (precedent: GC-P03 imported `test_p2_03_scheduler`'s `LoopHarness` for the same
reason). Offline by construction — `conftest.netoff`, an `httpx.MockTransport`, and an injected
transport callable; no socket opens and no keychain is read.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

import gateclerk.agent_db as agent_db
import gateclerk.agent_push as agent_push
import gateclerk.agent_store as agent_store
from gateclerk.agent_push import PERMANENT_REJECT_STATUSES, ingest_token_env_var
from gateclerk.model import EventRecord
from gateclerk.sinks import IMPLICIT_SINK_NAME
from test_p2_04_pusher import ENDPOINT, Rng, dead_rows, make_record, queue_rows
from test_t15_push_https import HTTPS_TARGET, client_for

SITE = "site-a"

#: Recognisably fake placeholders (tests/test_repo_hygiene.py policy) and distinct per read,
#: so "the second send used the re-read token" is a real assertion and not a tautology.
OLD_TOKEN = "fake-ingest-token-old"
NEW_TOKEN = "fake-ingest-token-new"

#: The card's §2c bound, named here so the "did not burn the 24 h clock" test says what it
#: measures instead of hiding a magic 86400 inside an assertion.
BOUND_S = agent_push.DEFAULT_PUSH_DEAD_LETTER_AFTER_S

T0 = datetime(2026, 10, 19, 10, 0, 0, tzinfo=UTC)


class NoKeychain:
    """A reader that must never be consulted: the env rung answers first here.

    Asserting rather than returning None matters — a rung that is silently skipped would let
    a transport resolve from somewhere the test never configured (conftest turns the ambient
    credential file off, so a pass like that is invisible otherwise).
    """

    def read(self, target: Any, *, with_comment: bool = True) -> Any:
        raise AssertionError(
            f"the keychain must not be consulted, asked for {target.keychain_service!r}"
        )


@pytest.fixture
def db(tmp_path):
    """A fresh agent db (connect = pragmas + migrations), the same seam as P2-04's suite."""
    conn = agent_db.connect(tmp_path / "agent.sqlite3")
    yield conn
    conn.close()


@pytest.fixture
def queued(db) -> int:
    """One stored event, queued for `ENDPOINT`, due at T0 — the row every drain test needs."""
    record: EventRecord = make_record()
    result = agent_store.store_events(db, [record], now=T0)
    assert record.serial_no is not None, "the fixture record carries a serial"
    rowid = result.rowids[record.serial_no]
    agent_push.enqueue_events(db, [rowid], endpoint=ENDPOINT, now=T0)
    return rowid


def due_row(conn: sqlite3.Connection) -> sqlite3.Row:
    rows = queue_rows(conn)
    assert len(rows) == 1, "the row must still be queued"
    return rows[0]


def due_at(row: sqlite3.Row) -> datetime:
    return datetime.fromisoformat(row["next_attempt_at"])


# =====================================================================================
# (1) token refresh: an auth rejection drops the cached bearer
# =====================================================================================


def assert_second_send_uses_the_new_token(status: int) -> None:
    """Shared shape of the 401 and 403 cases.

    Kept as a helper rather than a parametrisation because the two statuses mean different
    things on the wire (expired/revoked vs. site/token mismatch) and each gets its own named
    test in the card's DoD list; both, however, must do exactly one thing to the cache.
    """
    env = {ingest_token_env_var(SITE): OLD_TOKEN}
    client, capture = client_for(status, 200)
    transport = agent_push.https_transport(SITE, env=env, keychain=NoKeychain(), client=client)

    assert transport(HTTPS_TARGET, "x\n") == status
    # The operator rotates the token on the site host. Nothing restarts; no config reload is
    # signalled. The only thing the transport may do to notice is walk the ladder again.
    env[ingest_token_env_var(SITE)] = NEW_TOKEN
    assert transport(HTTPS_TARGET, "x\n") == 200

    assert capture.requests[0].headers["authorization"] == f"Bearer {OLD_TOKEN}"
    assert capture.requests[1].headers["authorization"] == f"Bearer {NEW_TOKEN}", (
        f"a {status} must drop the cached bearer so the next send re-reads the credential"
    )
    transport.close()


def test_401_clears_the_cached_bearer_and_the_next_send_re_resolves() -> None:
    """401 = the bearer the site no longer accepts. Re-read it; do not restart the agent."""
    assert_second_send_uses_the_new_token(401)


def test_403_clears_the_cached_bearer() -> None:
    """403 = our token and our claimed site disagree — a credential-state answer too."""
    assert_second_send_uses_the_new_token(403)


def test_a_200_and_a_5xx_leave_the_cached_bearer_alone() -> None:
    """The refresh is scoped to auth rejections.

    A transport that cleared the cache on 200 would re-read the keychain once per accepted
    punch (an ACL prompt per row — the exact thing the memoisation exists for); on 5xx it
    would blame the credential for the ingest's own outage.
    """
    env = {ingest_token_env_var(SITE): OLD_TOKEN}
    client, capture = client_for(200, 503, 500, 200)
    transport = agent_push.https_transport(SITE, env=env, keychain=NoKeychain(), client=client)

    assert [transport(HTTPS_TARGET, "x\n") for _ in range(3)] == [200, 503, 500]
    env[ingest_token_env_var(SITE)] = NEW_TOKEN
    assert transport(HTTPS_TARGET, "x\n") == 200
    assert {r.headers["authorization"] for r in capture.requests} == {f"Bearer {OLD_TOKEN}"}, (
        "only 401/403 may invalidate the cached bearer"
    )
    transport.close()


# =====================================================================================
# (2) permanent payload rejections dead-letter on the first failure
# =====================================================================================


def test_400_dead_letters_on_the_first_failure(db: sqlite3.Connection, queued: int) -> None:
    """A malformed line will never be accepted: one attempt, then the operator's queue."""
    log: list[str] = []
    rng = Rng(1.0)

    result = agent_push.drain(
        db,
        endpoint=ENDPOINT,
        transport=_status_transport(400),
        now=T0,
        rng=rng,
        log=log.append,
    )

    assert result.dead_lettered == (queued,)
    assert result.retried == () and result.sent == ()
    dead = dead_rows(db)
    assert len(dead) == 1
    assert dead[0]["attempts"] == 1, "a permanent rejection must not collect attempts"
    assert dead[0]["error_class"] == "HttpStatus400"
    assert queue_rows(db) == [], "no backoff row may remain behind the dead-letter"
    assert rng.calls == 0, "a dead-lettered row draws no jitter — it is not scheduled again"
    # §2e's parser partitions on this exact prefix, so the permanent path rides the SAME line.
    assert log == [
        f"push drain: sink={IMPLICIT_SINK_NAME} sent=0 retried=0 dead_lettered=1 ids={[queued]}"
    ], log[0]


def test_422_dead_letters_on_the_first_failure(db: sqlite3.Connection, queued: int) -> None:
    """422 (unknown device serial) is a payload answer too — see the note on the T15 test."""
    agent_push.drain(db, endpoint=ENDPOINT, transport=_status_transport(422), now=T0, rng=Rng(1.0))
    dead = dead_rows(db)
    assert len(dead) == 1 and dead[0]["attempts"] == 1
    assert dead[0]["error_class"] == "HttpStatus422"
    assert queue_rows(db) == []


def test_the_permanent_set_names_400_and_422_and_deliberately_not_the_auth_statuses() -> None:
    """The exclusion is the design decision, so it is pinned rather than commented.

    If 401/403 ever join this set, a token rotation silently dead-letters the backlog of a
    site that was one `security add-generic-password` away from working again.
    """
    assert frozenset({400, 422}) == PERMANENT_REJECT_STATUSES
    assert not PERMANENT_REJECT_STATUSES & {401, 403}


# =====================================================================================
# (3) transient failures keep the ladder and the 24 h bound exactly as P2-04 shipped them
# =====================================================================================


def test_503_still_retries_with_backoff(db: sqlite3.Connection, queued: int) -> None:
    """The ingest's own outage is not our payload's fault: back off, keep the row."""
    rng = Rng(1.0)

    result = agent_push.drain(
        db, endpoint=ENDPOINT, transport=_status_transport(503), now=T0, rng=rng
    )

    assert result.retried == (queued,) and result.dead_lettered == ()
    row = due_row(db)
    assert row["attempts"] == 1
    assert due_at(row) > T0, "a failed row must not be due again in this same second"
    assert row["last_error_class"] == "HttpStatus503"
    assert dead_rows(db) == []
    assert rng.calls == 1, "the ladder draws the jitter exactly once per failed row"


def test_a_network_failure_still_backs_off_and_keeps_the_24h_bound(
    db: sqlite3.Connection, queued: int
) -> None:
    """A raised exception is 'not accepted' with a class, never a permanent rejection."""
    raised = ConnectionError("the site host is unreachable")

    result = agent_push.drain(
        db, endpoint=ENDPOINT, transport=_raising_transport(raised), now=T0, rng=Rng(1.0)
    )

    assert result.retried == (queued,) and result.dead_lettered == ()
    assert due_row(db)["last_error_class"] == "ConnectionError"
    assert dead_rows(db) == []

    # And the bound still catches it: one drain past 24 h of continuous failure moves it.
    late = agent_push.drain(
        db,
        endpoint=ENDPOINT,
        transport=_raising_transport(raised),
        now=T0 + timedelta(seconds=BOUND_S),
        rng=Rng(1.0),
    )
    assert late.dead_lettered == (queued,)
    assert dead_rows(db)[0]["error_class"] == "ConnectionError"


def test_a_401_does_not_dead_letter_and_does_not_burn_the_24h_clock(
    db: sqlite3.Connection, queued: int
) -> None:
    """An auth failure is an install step in progress, not a dead payload.

    The row keeps its backoff and its outage clock, and a drain nearly a day later is STILL a
    retry: the only thing that may dead-letter a 401 is the 24 h bound, never its status.
    """
    first = agent_push.drain(
        db, endpoint=ENDPOINT, transport=_status_transport(401), now=T0, rng=Rng(1.0)
    )

    assert first.retried == (queued,) and first.dead_lettered == ()
    row = due_row(db)
    assert row["attempts"] == 1
    assert row["last_error_class"] == "HttpStatus401"
    assert row["first_failed_at"] is not None, "the outage clock still starts on the first miss"
    assert due_at(row) > T0
    assert dead_rows(db) == []

    near_the_bound = agent_push.drain(
        db,
        endpoint=ENDPOINT,
        transport=_status_transport(401),
        now=T0 + timedelta(seconds=BOUND_S - 1),
        rng=Rng(1.0),
    )
    assert near_the_bound.retried == (queued,)
    assert near_the_bound.dead_lettered == (), "a 401 must not dead-letter on its own status"
    assert len(queue_rows(db)) == 1


# --- injected transports -------------------------------------------------------------------
# The card's drain cases need a scripted STATUS (not the real https transport), so they use
# the same shape as `test_p2_04_pusher.Flaky` through these two one-line factories: the
# transport seam is `Callable[[str, str], int]` and that is all `drain` knows about.


def _status_transport(*statuses: int) -> Any:
    calls: list[tuple[str, str]] = []

    def transport(url: str, body: str) -> int:
        calls.append((url, body))
        assert statuses, "the scripted transport ran out of statuses"
        return statuses[0]

    transport.calls = calls  # type: ignore[attr-defined]
    return transport


def _raising_transport(exc: Exception) -> Any:
    def transport(url: str, body: str) -> int:
        raise exc

    return transport
