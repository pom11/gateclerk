"""GC-P07 — a sink's ingest bearer resolves LAZILY, through the credential provider.

The bug this pins: `build_https_sink_transport()` used to resolve the bearer up front. A sink
that declared `token_keychain` therefore ran a `security` read at agent STARTUP, on a machine
where nothing has been queued yet — and on headless Linux (no `security` binary) that read
raises, so the agent died at build time even though the same token was sitting in
`~/.config/gateclerk/credentials.json`. The whole point of `resolve_ingest_token`'s ladder is
that the file rung answers where the Keychain cannot; an eager read forfeits that.

Four claims, one per failure mode:

1. building the transport touches NO keychain (the crash this card exists for);
2. the first send resolves from the 0600 credential file when there is no keychain at all
   (R2: the Linux production agent);
3. a sink's own `token_env` ref still outranks the site's derived env var;
4. a missing token is reported on the first send — build succeeds, `token_available()` is
   False (so the pusher keeps the rows queued instead of burning the dead-letter clock), and
   the send raises this module's install-step class.

Everything is offline (`tests/conftest.py`'s `netoff`) and keychain-free: the Keychain is a
duck-typed fake and the credential file is a tmp path — `conftest`'s autouse
`no_ambient_credential_file` fixture turns the ambient store off, so each test that wants the
file rung names its own file.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from gateclerk.agent_push import (
    IngestTokenUnavailableError,
    ingest_keychain_service,
    ingest_token_env_var,
)
from gateclerk.config import CredentialUnavailable, KeychainReader
from gateclerk.credentials import CREDENTIALS_FILE_ENV, ingest_ref
from gateclerk.sink_writers import build_https_sink_transport
from gateclerk.sinks import SinkSpec
from test_t15_push_https import HTTPS_TARGET, client_for

SITE = "demo-a"

#: The sink's declared keychain SERVICE, deliberately equal to the site's own portable ref:
#: `ingest_ref(site) == ingest_keychain_service(site)` is this repo's portability rule, so a
#: sink that names its service is naming the SAME name the Linux file rung keys on.
SINK_SERVICE = "gateclerk-ingest-demo-a"

#: Recognisably fake (tests/test_repo_hygiene.py's PLACEHOLDER) and distinct per rung, so a
#: wrong rung shows up as the WRONG STRING rather than as a passing equality.
FROM_FILE = "fake-file-token"
FROM_SINK_ENV = "fake-sink-env-token"
FROM_SITE_ENV = "fake-site-env-token"


# --- fakes ----------------------------------------------------------------------------


class HeadlessKeychain:
    """What `KeychainReader` answers on a Linux host: the rung is unavailable, not empty.

    `config.KeychainReader.read` short-circuits to `CredentialUnavailable` when
    `/usr/bin/security` is not on PATH, which is the rung miss that lets the file below it
    answer. Raising anything else here (an `AssertionError`, say) would test a Linux that
    crashes instead of a Linux that falls through.
    """

    def __init__(self) -> None:
        self.services: list[str] = []

    def read(self, target: Any, *, with_comment: bool = True) -> Any:
        self.services.append(target.keychain_service)
        raise CredentialUnavailable(
            "the macOS Keychain is unavailable here (/usr/bin/security not found)"
        )


class NoKeychain:
    """A reader that must never be consulted (an env rung answered first)."""

    def read(self, target: Any, *, with_comment: bool = True) -> Any:
        raise AssertionError(
            f"the keychain must not be consulted, asked for {target.keychain_service!r}"
        )


class RecordingKeychain:
    """A macOS-style reader that records WHICH SERVICE it was asked for."""

    def __init__(self, items: dict[str, str]) -> None:
        self.items = items
        self.services: list[str] = []

    def read(self, target: Any, *, with_comment: bool = True) -> Any:
        from gateclerk.secrets import Secret

        self.services.append(target.keychain_service)
        if target.keychain_service not in self.items:
            raise CredentialUnavailable(
                f"keychain item missing for service {target.keychain_service!r}"
            )
        return type(
            "Item",
            (),
            {
                "password": Secret(self.items[target.keychain_service], label="keychain"),
                "comment": None,
            },
        )()


def write_store(tmp_path: Path, refs: dict[str, str], name: str = "credentials.json") -> Path:
    """A credential file the documented way: the shape AND the 0600 mode."""
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"refs": refs}), encoding="utf-8")
    path.chmod(0o600)
    return path


def sink(**over: Any) -> SinkSpec:
    params: dict[str, Any] = {"name": "bc", "type": "https", "ref": HTTPS_TARGET}
    params.update(over)
    return SinkSpec(**params)


# --- 1. building must not touch the keychain ------------------------------------------


def test_building_a_sink_transport_does_not_read_the_keychain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The crash this card exists for: a declared `token_keychain` must not cost a read.

    `KeychainReader.read` is patched at the CLASS so every construction site is covered —
    the eager one that used to live in `sink_writers` and the lazy one inside the transport.
    A builder that still resolved the token would raise here before returning.
    """
    reads: list[str] = []

    def boom(self: Any, target: Any, *, with_comment: bool = True) -> Any:
        reads.append(target.keychain_service)
        raise AssertionError(f"keychain read at build time: {target.keychain_service!r}")

    monkeypatch.setattr(KeychainReader, "read", boom)
    client, _capture = client_for(200)

    transport = build_https_sink_transport(
        SITE,
        sink(token_keychain=SINK_SERVICE),
        env={CREDENTIALS_FILE_ENV: "off"},
        client=client,
    )

    assert transport is not None
    assert reads == [], "the builder resolved a bearer; the read must happen on the first send"


# --- 2. the Linux path: the file rung answers on the first send -----------------------


def test_first_send_resolves_the_sink_token_from_the_credential_file(tmp_path: Path) -> None:
    """R2: a headless agent with no `security` binary still delivers, from the 0600 file.

    The sink declares `token_keychain`, the keychain reports itself unavailable, and the
    token lives only in `credentials.json` — the exact production shape that used to kill the
    agent at startup. The header must carry the file's value and the label must name the
    file rung, because "which rung answered" is what the operator is told.
    """
    path = write_store(tmp_path, {ingest_ref(SITE): FROM_FILE})
    keychain = HeadlessKeychain()
    client, capture = client_for(200)

    transport = build_https_sink_transport(
        SITE,
        sink(token_keychain=SINK_SERVICE),
        env={CREDENTIALS_FILE_ENV: str(path)},
        keychain=keychain,
        client=client,
    )

    assert transport(HTTPS_TARGET, "{}\n") == 200
    assert capture.headers["authorization"] == f"Bearer {FROM_FILE}"
    assert transport.token_label == f"file:{ingest_ref(SITE)}"
    assert keychain.services == [SINK_SERVICE], "the sink's own service was tried, and missed"


# --- 3. the sink's own refs still win --------------------------------------------------


def test_sink_env_ref_wins_over_the_site_env(tmp_path: Path) -> None:
    """`spec.token_env` names a DIFFERENT variable than the site's derived one and wins.

    Both rungs are populated, so a resolver that ignored the sink's ref would answer with
    the other string rather than fail — which is exactly why the two values differ.
    """
    client, capture = client_for(200)
    env = {
        "CUSTOM_INGEST_TOKEN": FROM_SINK_ENV,
        ingest_token_env_var(SITE): FROM_SITE_ENV,
        CREDENTIALS_FILE_ENV: "off",
    }

    transport = build_https_sink_transport(
        SITE,
        sink(token_env="CUSTOM_INGEST_TOKEN"),
        env=env,
        keychain=NoKeychain(),
        client=client,
    )

    assert transport(HTTPS_TARGET, "{}\n") == 200
    assert capture.headers["authorization"] == f"Bearer {FROM_SINK_ENV}"
    assert ingest_token_env_var(SITE) != "CUSTOM_INGEST_TOKEN"


def test_sink_keychain_ref_wins_over_the_site_service(tmp_path: Path) -> None:
    """The keychain twin of the env case: the sink's SERVICE is asked for, not the site's."""
    keychain = RecordingKeychain({"sink-vault": "fake-keychain-token"})
    client, capture = client_for(200)

    transport = build_https_sink_transport(
        SITE,
        sink(token_keychain="sink-vault"),
        env={CREDENTIALS_FILE_ENV: "off"},
        keychain=keychain,
        client=client,
    )

    assert transport(HTTPS_TARGET, "{}\n") == 200
    assert capture.headers["authorization"] == "Bearer fake-keychain-token"
    assert keychain.services == ["sink-vault"], "the sink's service, not the site default"
    assert ingest_keychain_service(SITE) != "sink-vault"


def test_the_implicit_sink_still_uses_the_sites_own_rungs(tmp_path: Path) -> None:
    """Upgrade law: a sink declaring neither ref (the implicit `legacy` sink) resolves
    through the SITE's env var and keychain service — no new keychain item at upgrade."""
    client, capture = client_for(200)

    transport = build_https_sink_transport(
        SITE,
        sink(name="legacy"),
        env={ingest_token_env_var(SITE): FROM_SITE_ENV, CREDENTIALS_FILE_ENV: "off"},
        keychain=NoKeychain(),
        client=client,
    )

    assert transport(HTTPS_TARGET, "{}\n") == 200
    assert capture.headers["authorization"] == f"Bearer {FROM_SITE_ENV}"


# --- 4. a missing token is a first-SEND problem --------------------------------------


def test_missing_token_is_reported_on_first_send_not_at_build(tmp_path: Path) -> None:
    """Build succeeds, the probe says False, the send names the install step.

    The three assertions are the agent's whole law in one place: startup survives, the push
    step asks `token_available()` and skips the cycle so the rows STAY QUEUED (the 24 h
    dead-letter clock measures outages, and a token nobody installed is not an outage), and
    the class is this module's `IngestTokenUnavailableError` so the error column reads
    "install step" rather than "outage".
    """
    store = write_store(tmp_path, {"gateclerk-some-other-ref": FROM_FILE})
    client, capture = client_for(200)

    transport = build_https_sink_transport(
        SITE,
        sink(token_keychain=SINK_SERVICE),
        # The file exists but carries no ingest ref, and the keychain is unavailable: every
        # rung misses, which is the case that used to be a startup crash.
        env={CREDENTIALS_FILE_ENV: str(store)},
        keychain=HeadlessKeychain(),
        client=client,
    )

    assert transport.token_available() is False
    with pytest.raises(IngestTokenUnavailableError) as excinfo:
        transport(HTTPS_TARGET, "{}\n")
    assert capture.requests == [], (
        "a bearer-less POST is a 401 by contract — nothing left the building"
    )
    assert FROM_FILE not in str(excinfo.value), "a value from an adjacent ref may never be echoed"
