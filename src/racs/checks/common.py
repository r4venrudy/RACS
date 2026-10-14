"""Verified observations and narrowly controlled active checks."""

import hashlib

from racs.models import CheckOutcome, Finding


def finding(
    kind,
    url,
    parameter,
    evidence,
    remediation,
    fix,
    *,
    severity="medium",
    status="verified",
    confidence="high",
    rationale="Reproduced with independent controls",
    steps=None,
):
    identity = hashlib.sha256(f"{kind}|{url}|{parameter}".encode()).hexdigest()[:20]
    return Finding(
        id=f"{kind}.{identity}",
        type=kind,
        severity=severity,
        confidence=confidence,
        confidence_rationale=rationale,
        verification_status=status,
        affected_url=url,
        affected_parameter=parameter,
        evidence=evidence,
        reproduction_steps=steps
        or [
            "Use the declared read-only test endpoint and supplied synthetic accounts only.",
            evidence,
        ],
        remediation=remediation,
        sample_fix_snippet=fix,
    )


def outcome(name, found, detail, *, uncertain=False):
    return CheckOutcome(
        check=name,
        status="findings" if found else ("inconclusive" if uncertain else "no_finding"),
        detail=detail,
        findings=found,
    )


def digest(body):
    return hashlib.sha256(body).hexdigest()[:16]
