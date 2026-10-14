"""Redact sensitive values at the final persistence boundary."""

import re


def scrub(value, secrets=()):
    if isinstance(value, dict):
        return {k: scrub(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v, secrets) for v in value]
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, "[redacted]")
        value = re.sub(r"(?i)(bearer\s+)[a-z0-9._~+/=-]+", r"\1[redacted]", value)
        value = re.sub(r"racs-v1=[A-Za-z0-9_-]+", "[verification token redacted]", value)
        return value
    return value
