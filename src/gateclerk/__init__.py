"""gateclerk — read-only Hikvision attendance connector.

P1 scope: read punch events off a Hikvision access terminal over ISAPI and emit them
in a normalized form. See docs/DESIGN.md — it is the contract.

Two things every module in this package must respect:
  * read-only against the device (see gateclerk.endpoints, enforced by a test);
  * timestamps are payroll data — never discard the device's raw time string.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
