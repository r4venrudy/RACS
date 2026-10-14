import secrets
from urllib.parse import urlencode

from racs.browser_verify import proves_execution
from racs.checks.common import digest, finding, outcome
from racs.models import CheckOutcome
from racs.plugins import Metadata


class XSS:
    metadata = Metadata("xss", "web", "Reflected XSS with isolated browser execution")

    async def run(self, ctx):
        if not ctx.plan.probes:
            return CheckOutcome(
                check="xss",
                status="not_performed",
                detail="Supply a read-only endpoint and query parameter; no crawling or guessing is performed.",
            )
        found, uncertain = [], False
        for probe in ctx.plan.probes:
            baseline = await ctx.get(probe.path, {probe.parameter: probe.baseline})
            if (
                baseline.status != 200
                or "text/html" not in baseline.headers.get("content-type", "").lower()
            ):
                uncertain = True
                continue
            confirmed = []
            for _ in range(2):
                marker = "racs" + secrets.token_hex(12)
                payload = f"<svg onload=\"document.documentElement.setAttribute('data-racs-proof','{marker}')\"></svg>"
                response = await ctx.get(probe.path, {probe.parameter: payload})
                if marker.encode() not in response.body:
                    break
                try:
                    url = ctx.origin + probe.path + "?" + urlencode({probe.parameter: payload})
                    proof = await proves_execution(response, url, marker)
                    if proof is None:
                        uncertain = True
                    if not proof:
                        break
                except Exception:
                    uncertain = True
                    break
                ctx.check_cancelled()
                confirmed.append(digest(response.body))
            if len(confirmed) == 2:
                found.append(
                    finding(
                        "reflected-xss",
                        ctx.origin + probe.path,
                        probe.parameter,
                        "Two fresh injected markers executed in isolated captured-response replay with the original enforcing CSP preserved. Response hashes: "
                        + ", ".join(confirmed)
                        + ". No target session, external resource or cookie was used.",
                        "Use context-appropriate output encoding and safe text APIs. Avoid raw HTML insertion. Add CSP as defense in depth.",
                        "from html import escape\nreturn '<p>' + escape(user_input, quote=True) + '</p>'",
                        severity="high",
                        steps=[
                            f"GET {probe.path} with query parameter {probe.parameter} set to a harmless baseline.",
                            "URL-encode this probe, replacing MARKER with a fresh random value: <svg onload=\"document.documentElement.setAttribute('data-racs-proof','MARKER')\"></svg>",
                            "Replay the captured 200 HTML response with original CSP and no external resources. Require the html element data-racs-proof attribute to equal MARKER. Repeat with a different marker; both must execute.",
                        ],
                        rationale="Two independent browser executions confirm this reflected HTML context. Only dependency-free captured HTML is verified; pages requiring blocked resources are inconclusive.",
                    )
                )
        return outcome(
            "xss",
            found,
            "Only twice-reproduced execution is a finding. Escaped/CSP-blocked reflection is not flagged. Coverage is limited to the declared HTML context.",
            uncertain=uncertain,
        )
