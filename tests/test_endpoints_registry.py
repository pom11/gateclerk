"""The read-only guarantee, enforced by CI rather than by a comment (docs/DESIGN.md).

If someone adds a mutating endpoint to the registry, these tests fail — which is the
whole point of the registry existing.
"""

from __future__ import annotations

import pytest

from gateclerk.endpoints import (
    REGISTRY,
    SEARCH_ENDPOINTS,
    Endpoint,
    HttpMethod,
    allowed_methods_for,
    endpoint_for,
)

# Verbs that mutate: never allowed, under any name. POST is NOT in this set — it is
# allowed for exactly the two stateless search endpoints, which is what the tests
# above pin down. POST-as-a-verb is not the risk; POST-to-a-write-path is.
FORBIDDEN_METHODS = frozenset({"PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"})


def test_registry_is_not_empty() -> None:
    assert REGISTRY, "the endpoint registry must list what the connector may call"


def test_every_registered_method_is_get_or_an_advertised_search_post() -> None:
    """The invariant from DESIGN.md: method is GET, or one of the two search POSTs."""
    for name, ep in REGISTRY.items():
        if ep.method is HttpMethod.GET:
            continue
        assert name in SEARCH_ENDPOINTS, (
            f"{name} is a {ep.method} but is not an allowed stateless search endpoint"
        )
    assert set(REGISTRY) >= SEARCH_ENDPOINTS, "search endpoint names must exist in REGISTRY"


def test_exactly_the_advertised_search_post_endpoints() -> None:
    """The POST allowlist, pinned by name. Adding one is a reviewed decision.

    Three: the two searches the paging engine walks, plus `AcsEventTotalNum`, the advisory
    count probe card p1-08's `--count` flag asks for. p1-05's handoff named that split
    explicitly ("3rd POST is a reviewed registry decision … belongs with p1-08 --count"), so
    the count endpoint arrives with the flag that consumes it rather than being folded into
    the engine that never calls it. All three take a stateless search-shaped body; none
    mutates device state (OBSERVED.md VERIFIED for the count probe: it returns `{totalNum}`
    for a window and nothing else).
    """
    posts = {name for name, ep in REGISTRY.items() if ep.method is HttpMethod.POST}
    assert posts == {"user_info_search", "acs_event_search", "acs_event_total_num"}


def test_no_forbidden_verbs_anywhere_in_the_registry() -> None:
    """A defence in depth read of the enum itself: nothing may carry a mutating verb."""
    used = {ep.method.value for ep in REGISTRY.values()}
    assert not used & FORBIDDEN_METHODS, f"mutating verbs in registry: {used & FORBIDDEN_METHODS}"


def test_http_method_enum_cannot_even_spell_a_write() -> None:
    """HttpMethod only offers GET/POST, so 'PUT' is not expressible by construction."""
    assert {m.value for m in HttpMethod} == {"GET", "POST"}


@pytest.mark.parametrize("name", sorted(REGISTRY))
def test_every_endpoint_documents_its_purpose(name: str) -> None:
    ep: Endpoint = REGISTRY[name]
    assert ep.purpose.strip(), f"{name} has no recorded reason for being callable"
    assert ep.path.startswith("/ISAPI/"), f"{name} path looks wrong: {ep.path}"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("device_info", "/ISAPI/System/deviceInfo?format=json"),
        ("acs_event_capabilities", "/ISAPI/AccessControl/AcsEvent/capabilities?format=json"),
    ],
)
def test_url_path_appends_format_json(name: str, expected: str) -> None:
    assert endpoint_for(name).url_path == expected


def test_url_path_never_double_appends_format_json() -> None:
    for ep in REGISTRY.values():
        assert ep.url_path.count("format=json") == 1


def test_unknown_endpoint_raises_a_helpful_keyerror() -> None:
    with pytest.raises(KeyError) as excinfo:
        endpoint_for("delete_every_user")
    assert "unknown endpoint" in str(excinfo.value)
    assert "device_info" in str(excinfo.value), "the error must list what is available"


def test_allowed_methods_are_a_single_method_per_endpoint() -> None:
    for name in REGISTRY:
        assert allowed_methods_for(name) == {REGISTRY[name].method}


def test_registry_is_exactly_the_documented_surface() -> None:
    """THE read-only guard: a closed allowlist, not a heuristic.

    Method+name heuristics cannot prove a call is read-only — a write path registered
    as GET (say /ISAPI/AccessControl/UserInfo/Update) is indistinguishable from a read
    by those rules, and passes them. So the surface is pinned by enumeration: adding any
    endpoint means editing the set below, which makes every new callable path a named,
    reviewed decision rather than a silent addition.
    """
    actual = {(ep.name, ep.method.value, ep.path) for ep in REGISTRY.values()}
    assert actual == {
        ("device_info", "GET", "/ISAPI/System/deviceInfo"),
        ("system_time", "GET", "/ISAPI/System/time"),
        ("acs_event_capabilities", "GET", "/ISAPI/AccessControl/AcsEvent/capabilities"),
        # Added by card p1-04 (capability discovery), together with the DESIGN.md
        # endpoint table entry: AccessControl-wide caps, GET, advisory.
        ("access_control_capabilities", "GET", "/ISAPI/AccessControl/capabilities"),
        ("user_info_count", "GET", "/ISAPI/AccessControl/UserInfo/Count"),
        ("user_info_search", "POST", "/ISAPI/AccessControl/UserInfo/Search"),
        ("acs_event_search", "POST", "/ISAPI/AccessControl/AcsEvent"),
        # Added by card p1-08 (the `--count` cross-check), together with the DESIGN.md
        # invariant wording that had to name it: the call table already documented this POST,
        # and OBSERVED.md VERIFIED it. Advisory display only — never a loop bound.
        ("acs_event_total_num", "POST", "/ISAPI/AccessControl/AcsEventTotalNum"),
    }, (
        "the callable surface changed. If this is a NEW read endpoint: update the set here "
        "and docs/DESIGN.md's endpoint table together. If it is a WRITE: stop — this repo "
        "is read-only against the device (DESIGN.md 'Constraints / invariants')."
    )


def test_no_mutating_looking_paths_are_registered() -> None:
    """A POST to a path that reads like a write is the actual failure mode."""
    smells = ("/reboot", "/shutdown", "/upgrade", "/delete", "/add", "/set", "/clear", "/import")
    for name, ep in REGISTRY.items():
        low = ep.path.lower()
        assert not any(s in low for s in smells), f"{name} registers a write-ish path: {ep.path}"


def test_endpoints_are_immutable() -> None:
    """Frozen dataclass: a caller cannot rewrite a GET into a write at runtime."""
    ep = endpoint_for("device_info")
    with pytest.raises(Exception):  # noqa: B017 - frozen dataclass raises FrozenInstanceError
        ep.path = "/ISAPI/System/reboot"  # type: ignore[misc]
