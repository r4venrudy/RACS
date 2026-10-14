import pytest
from pydantic import ValidationError

from racs.models import Finding


def finding():
    return dict(
        id="headers.test",
        type="example",
        severity="info",
        confidence="low",
        confidence_rationale="Insufficient evidence",
        verification_status="observation",
        affected_url="https://example.com/",
        affected_parameter=None,
        evidence="fixture",
        reproduction_steps=["Read fixture"],
        remediation="Review configuration",
        sample_fix_snippet="Example only",
    )


def test_strict_finding():
    assert Finding(**finding()).severity == "info"
    for field, value in [
        ("severity", "severe"),
        ("confidence", 0.99),
        ("evidence", "x" * 4097),
        ("affected_url", "file:///etc/passwd"),
        ("reproduction_steps", []),
        ("extra", True),
    ]:
        with pytest.raises(ValidationError):
            Finding(**(finding() | {field: value}))
    data = finding()
    del data["sample_fix_snippet"]
    with pytest.raises(ValidationError):
        Finding(**data)
