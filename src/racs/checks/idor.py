import json

from racs.checks.common import digest, finding, outcome
from racs.models import CheckOutcome
from racs.plugins import Metadata


class IDOR:
    metadata = Metadata("idor", "web", "Known-object cross-principal access verification")

    async def run(self, ctx):
        if not ctx.plan.access_cases:
            return CheckOutcome(
                check="idor",
                status="not_performed",
                detail="Two test principals, identity endpoint and a known private synthetic object/marker are required. No enumeration is performed.",
            )
        found, tested = [], 0

        def obj(response):
            if response.status != 200:
                return None
            try:
                value = json.loads(response.body)
                return value if isinstance(value, dict) else None
            except (ValueError, UnicodeError):
                return None

        for case in ctx.plan.access_cases:
            owner_token, other_token = (
                ctx.credentials.get(case.owner_principal),
                ctx.credentials.get(case.other_principal),
            )
            if (
                not owner_token
                or not other_token
                or owner_token == other_token
                or case.owner_identity == case.other_identity
                or case.private_marker in owner_token
                or case.private_marker in other_token
            ):
                continue
            first = obj(await ctx.get(case.identity_path, principal=case.owner_principal))
            second = obj(await ctx.get(case.identity_path, principal=case.other_principal))
            if (
                not first
                or not second
                or "id" not in first
                or "id" not in second
                or str(first.get("id")) != case.owner_identity
                or str(second.get("id")) != case.other_identity
            ):
                continue

            def matches(value):
                return (
                    bool(value)
                    and case.json_field in value
                    and case.marker_field in value
                    and isinstance(value[case.json_field], (str, int))
                    and not isinstance(value[case.json_field], bool)
                    and str(value[case.json_field]) == case.expected_value
                    and value.get(case.marker_field) == case.private_marker
                )

            control = obj(await ctx.get(case.path, principal=case.owner_principal))
            if not matches(control):
                continue
            tested += 1
            cross1 = obj(await ctx.get(case.path, principal=case.other_principal))
            cross2 = obj(await ctx.get(case.path, principal=case.other_principal))
            if matches(cross1) and matches(cross2):
                found.append(
                    finding(
                        "broken-object-authorization",
                        ctx.origin + case.path,
                        None,
                        "Two verified distinct test identities were used. The declared forbidden identity retrieved the exact private synthetic object and protected marker twice, matching the authorized control. Marker digest: "
                        + digest(case.private_marker.encode())
                        + ". Credentials and object content are omitted.",
                        "Enforce object authorization on every request using the authenticated principal. Never rely on unguessable object identifiers.",
                        "item = db.query(Item).filter(Item.id == item_id, Item.owner_id == current_user.id).first()\nif item is None:\n    raise HTTPException(status_code=404)",
                        severity="high",
                        steps=[
                            f"Confirm distinct identities at GET {case.identity_path} using the supplied {case.owner_principal} and {case.other_principal} test profiles (tokens omitted).",
                            f"GET {case.path} under the owner profile; verify the known object and independent private synthetic marker.",
                            "Repeat that exact read twice under the identity declared forbidden. Both responses must contain the same object and private marker; do not enumerate other objects.",
                        ],
                        rationale="Repeated disclosure of a known private test marker under a separately verified forbidden identity; applies only to this declared object/policy.",
                    )
                )
        if not tested:
            return CheckOutcome(
                check="idor",
                status="not_performed",
                detail="Identity or authorized-object controls could not be established; no clean result is implied.",
            )
        return outcome(
            "idor",
            found,
            f"{tested} of {len(ctx.plan.access_cases)} owner-declared private object cases tested; identities and protected markers checked, without enumeration.",
        )
