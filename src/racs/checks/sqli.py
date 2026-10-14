import json
import secrets

from racs.checks.common import digest, finding, outcome
from racs.models import CheckOutcome
from racs.plugins import Metadata


def signature(response):
    if (
        response.status != 200
        or "application/json" not in response.headers.get("content-type", "").lower()
    ):
        return None
    try:
        value = json.loads(response.body)
    except (ValueError, UnicodeError):
        return None
    # Restrict generic SQL probing to structured result arrays, avoiding reflected
    # strings, error pages and arbitrary response-length heuristics.
    rows = (
        value if isinstance(value, list) else value.get("data") if isinstance(value, dict) else None
    )
    if not isinstance(rows, list):
        return None
    return json.dumps(rows, sort_keys=True, separators=(",", ":"))


class SQLI:
    metadata = Metadata("sqli", "web", "Repeated AND-only boolean SQL indicators")

    async def run(self, ctx):
        if not ctx.plan.probes:
            return CheckOutcome(
                check="sqli",
                status="not_performed",
                detail="Supply a read-only query endpoint returning a JSON result array (or data array).",
            )
        found, applicable = [], False
        for probe in ctx.plan.probes:
            baseline = signature(await ctx.get(probe.path, {probe.parameter: probe.baseline}))
            repeat = signature(await ctx.get(probe.path, {probe.parameter: probe.baseline}))
            if baseline is None or baseline == "[]" or baseline != repeat:
                continue
            applicable = True
            control = signature(
                await ctx.get(probe.path, {probe.parameter: probe.baseline + "racscontrol"})
            )
            if control != "[]":
                continue
            for style in (probe.sql_context,):
                verified = 0
                for _ in range(2):
                    nonce = "r" + secrets.token_hex(6)
                    number = secrets.randbelow(900000) + 100000
                    if style == "string":
                        yes = probe.baseline + f"' AND '{nonce}'='{nonce}"
                        no = probe.baseline + f"' AND '{nonce}'='not{nonce}"
                    elif style == "numeric":
                        yes = probe.baseline + f" AND {number}={number}"
                        no = probe.baseline + f" AND {number}={number + 1}"
                    else:
                        yes = probe.baseline + f"%' AND 17=17 AND '{nonce}' LIKE '{nonce}"
                        no = probe.baseline + f"%' AND 17=18 AND '{nonce}' LIKE '{nonce}"
                    true = signature(await ctx.get(probe.path, {probe.parameter: yes}))
                    false = signature(await ctx.get(probe.path, {probe.parameter: no}))
                    fresh = signature(await ctx.get(probe.path, {probe.parameter: probe.baseline}))
                    if true != baseline or false != "[]" or fresh != baseline:
                        break
                    verified += 1
                if verified == 2:
                    found.append(
                        finding(
                            "sql-injection-indicator",
                            ctx.origin + probe.path,
                            probe.parameter,
                            f"Two independent {style}-context AND true/false pairs preserved the stable baseline for true and produced empty arrays for false. A benign invalid control was empty. Baseline digest: {digest(baseline.encode())}. No extra rows, database metadata, writes or delays were requested.",
                            "Bind parameters instead of interpolating input into SQL. Verify the query implementation to establish the database-specific cause.",
                            "cursor.execute('SELECT id, name FROM items WHERE id = ?', (user_input,))",
                            severity="high",
                            status="indicator",
                            steps=[
                                f"GET {probe.path}, parameter {probe.parameter}, baseline {probe.baseline!r}; require stable nonempty JSON data arrays.",
                                f"URL-encode true value {yes!r} and false value {no!r}; repeat with a fresh equal/unequal predicate. True must match the baseline and false must be empty.",
                                "A benign invalid suffix must also be empty; repeat the untouched baseline between pairs. Stop on server errors/rate limits. This verifies a differential, not the SQL root cause.",
                            ],
                            rationale="High confidence in a repeated boolean differential. HTTP behavior alone cannot prove that SQL executed; source review is needed for that conclusion.",
                        )
                    )
                    break
        if not applicable:
            return CheckOutcome(
                check="sqli",
                status="not_performed",
                detail="No stable nonempty JSON result-array baseline; no speculative SQL finding emitted.",
            )
        return outcome(
            "sqli",
            found,
            "Only stable baseline/control/two-pair differentials are reported. Unsupported HTML, noisy responses and errors are not SQL findings.",
        )
