"""Built-in and explicitly installed trusted scanner modules."""

from importlib.metadata import entry_points

from racs.checks.common import finding
from racs.checks.headers import Headers
from racs.checks.idor import IDOR
from racs.checks.sqli import SQLI
from racs.checks.xss import XSS

CHECKS = {check.metadata.name: check for check in (Headers(), XSS(), SQLI(), IDOR())}
for entry in entry_points(group="racs.checks"):
    check = entry.load()()
    if check.metadata.name in CHECKS:
        raise RuntimeError("Duplicate installed check name")
    CHECKS[check.metadata.name] = check

__all__ = ["CHECKS", "finding"]
