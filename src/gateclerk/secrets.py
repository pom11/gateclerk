"""Secret handling: a value that cannot accidentally print itself.

The rule this module exists for (docs/DESIGN.md "Constraints / invariants"): a device
password must never appear in a repr, a log line, or an exception message. Two of those
are a matter of discipline, which does not survive contact with a debugger, a `--verbose`
flag, or a pytest assertion diff — so the password is wrapped here and the wrapper is
what every other module sees.

Two pieces:

  Secret   a read-only holder. repr/str are fixed `Secret(***)`; the value comes out
           only through `.reveal()`.
  redact   substitute every occurrence of each secret in a string. For the places that
           build a message out of pieces we do not control (an httpx exception quoting
           a URL, a device echoing our own request body back in an error envelope).
"""

from __future__ import annotations

__all__ = ["MASK", "Secret", "redact"]

#: What a secret looks like once this module has had it.
MASK = "***"


class Secret:
    """Hold a password so the common accident — `f"{obj}"`, `repr()`, a log formatter,
    an assertion diff — yields `Secret(***)` instead of the credential.

    Deliberately not a dataclass with value equality: pytest rewrites
    `assert resolved == expected` into a diff of both operands, and value-based `__eq__`
    plus a value-carrying repr is exactly how a password reaches a CI log. Identity
    equality is enough here (one Secret per resolution).

    `.reveal()` is the only sanctioned way out, so `grep -rn reveal src/` finds every
    consumer of a plaintext password in this codebase — the seam p1-03's transport
    consumes, and nothing else.
    """

    __slots__ = ("_value", "label")

    def __init__(self, value: str, *, label: str = "secret") -> None:
        # `label` is what we can safely say about the value ("keychain:192.0.2.10"), and
        # is the only thing besides the mask that can ever be printed.
        object.__setattr__(self, "_value", value)
        object.__setattr__(self, "label", label)

    def __setattr__(self, name: str, value: object) -> None:
        raise TypeError(f"{type(self).__name__} is immutable; resolve a new one")

    def __delattr__(self, name: str) -> None:
        raise TypeError(f"{type(self).__name__} is immutable")

    def reveal(self) -> str:
        """The plaintext. Call it at the last possible moment, at the transport seam."""
        return self._value

    # repr/str are the whole reason this class exists: they must never contain the value.
    def __repr__(self) -> str:
        return f"Secret({MASK}, label={self.label!r})"

    def __str__(self) -> str:
        return MASK

    def __bool__(self) -> bool:
        # `if password:` should read as "is there a password", so an empty one is falsy.
        return bool(self._value)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secret):
            return NotImplemented
        return self is other

    def __hash__(self) -> int:
        return object.__hash__(self)


def redact(text: str, *secrets: Secret | str | None) -> str:
    """Replace every occurrence of each non-empty secret in `text` with MASK.

    Longer secrets are masked first, so a secret that happens to be a substring of
    another cannot leave a fragment of the longer one behind.
    """
    values: set[str] = set()
    for item in secrets:
        if item is None:
            continue
        value = item.reveal() if isinstance(item, Secret) else item
        if value:
            values.add(value)
    out = text
    for value in sorted(values, key=len, reverse=True):
        out = out.replace(value, MASK)
    return out
