import re

from racs.checks.common import finding, outcome
from racs.models import CheckOutcome
from racs.plugins import Metadata


class Headers:
    metadata = Metadata("headers", "web", "Repeated security-header observations")

    async def run(self, ctx):
        first, second = await ctx.get_root(), await ctx.get_root()
        if any(
            r.status != 200 or "text/html" not in r.headers.get("content-type", "").lower()
            for r in (first, second)
        ):
            return CheckOutcome(
                check="headers",
                status="not_performed",
                detail="Header profile applies only to successful HTML responses.",
            )
        findings = []
        policies = {
            "content-security-policy": (
                "Content Security Policy absent",
                "Set an enforcing policy after testing required resources.",
                "response.headers['Content-Security-Policy'] = \"default-src 'self'; object-src 'none'; base-uri 'self'\"",
            ),
            "x-content-type-options": (
                "MIME sniffing protection absent",
                "Send the correct Content-Type and nosniff.",
                "response.headers['X-Content-Type-Options'] = 'nosniff'",
            ),
            "strict-transport-security": (
                "HSTS absent",
                "After confirming HTTPS for the whole host, enable HSTS. Do not preload blindly.",
                "response.headers['Strict-Transport-Security'] = 'max-age=31536000'",
            ),
        }
        for name, (title, advice, fix) in policies.items():
            if all(not r.headers.get(name) for r in (first, second)):
                findings.append(
                    finding(
                        "headers." + name,
                        ctx.origin + ctx.plan.header_path,
                        None,
                        f"{title}: absent on two independent 200 HTML responses. This is a configuration observation, not proof of an exploit.",
                        advice,
                        fix,
                        severity="low",
                        status="observation",
                        rationale="High confidence in repeated absence; exploitability is not established.",
                    )
                )

        def framed(r):
            csp = r.headers.get("content-security-policy", "").lower()
            # "frame-ancestors *" allows every embedder, so it is not a framing restriction
            ancestors = re.findall(r"(?:^|[;,])\s*frame-ancestors\s+([^;,]*)", csp)
            return r.headers.get("x-frame-options", "").strip().lower() in ("deny", "sameorigin") or any(
                "*" not in sources.split() for sources in ancestors
            )

        if not framed(first) and not framed(second):
            findings.append(
                finding(
                    "headers.framing",
                    ctx.origin + ctx.plan.header_path,
                    None,
                    "Neither a recognized X-Frame-Options value nor a frame-ancestors directive was present on two HTML responses. No clickjacking exploit was attempted.",
                    "Define allowed framing origins through CSP.",
                    "response.headers['Content-Security-Policy'] = \"frame-ancestors 'none'\"",
                    severity="low",
                    status="observation",
                    rationale="Repeated absence of framing policy; business impact depends on this page.",
                )
            )
        return outcome(
            "headers",
            findings,
            "Two HTML responses checked; absence is reported separately from exploitable vulnerabilities.",
        )
