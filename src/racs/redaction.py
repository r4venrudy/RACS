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
        # Basic credentials are only base64, so they are as sensitive as the password itself
        value = re.sub(r"(?i)(basic\s+)[a-z0-9+/]{8,}={0,2}", r"\1[redacted]", value)
        # session cookies quoted in evidence (Cookie: / Set-Cookie:) would let a reader take over the session
        # (Set-Cookie carries one cookie; its Path/Domain attributes stay readable)
        value = re.sub(
            r"(?im)^((set-)?cookie:\s*)(.*)$",
            lambda m: m.group(1)
            + re.sub(
                r"(^|;\s*)([^=;\s]+)=[^;]*",
                r"\1\2=[redacted]",
                m.group(3),
                count=1 if m.group(2) else 0,
            ),
            value,
        )
        value = re.sub(r"racs-v1=[A-Za-z0-9_-]+", "[verification token redacted]", value)
        return value
    return value
