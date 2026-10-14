"""Durable, authorized, bounded scan execution and memory-only credentials."""

import asyncio
import contextlib
import time
from urllib.parse import urlencode

import h11

from racs.models import CheckOutcome, ScanPlan
from racs.scope import PolicyError, Scope, validate_path


class TrafficPolicy:
    def __init__(self, store, outbound, interval=1.0):
        self.store, self.outbound = store, outbound
        self.interval = interval
        self.locks, self.next_at, self.failures = {}, {}, {}
        self.slots = (
            outbound._slots
            if isinstance(getattr(outbound, "_slots", None), asyncio.Semaphore)
            else asyncio.Semaphore(2)
        )

    async def request(self, owner, scan_id, path, params=None, token=None):
        session = self.store.session(owner, scan_id)
        origin = session["origin"]
        validate_path(path)
        async with self.locks.setdefault(origin, asyncio.Lock()), self.slots:
            self.store.active(owner, scan_id)
            if self.store.distress(origin):
                raise PolicyError(
                    "Target distress stop is latched; acknowledge recovery before another scan"
                )
            await asyncio.sleep(max(0, self.next_at.get(origin, 0) - time.monotonic()))
            self.store.active(owner, scan_id)
            self.next_at[origin] = time.monotonic() + self.interval
            try:
                async with asyncio.timeout(10):
                    scope = Scope.parse(origin, allow_lab=bool(self.outbound.lab_ca))
                    addresses = await self.outbound.addresses(scope)
                    self.store.active(owner, scan_id)
                    suffix = "?" + urlencode(params) if params else ""
                    request = asyncio.create_task(
                        self.outbound._get(
                            scope, addresses[0], path + suffix, token=token, body_limit=262144
                        )
                    )
                    try:
                        while not request.done():
                            await asyncio.wait({request}, timeout=0.05)
                            self.store.active(owner, scan_id)
                        response = await request
                    finally:
                        if not request.done():
                            request.cancel()
                            with contextlib.suppress(asyncio.CancelledError):
                                await request
                    self.store.active(owner, scan_id)
                    self.next_at[origin] = time.monotonic() + self.interval
            except (OSError, TimeoutError, h11.RemoteProtocolError):
                self.failures[origin] = self.failures.get(origin, 0) + 1
                if self.failures[origin] >= 3:
                    self.store.distress(origin, "Three network/protocol failures")
                raise PolicyError("Network request failed; no automatic retry") from None
            if response.status == 429 or response.status >= 500:
                self.store.distress(origin, f"HTTP {response.status}; stop instead of retrying")
                raise PolicyError("Target signalled distress; scan stopped without retries")
            if 300 <= response.status < 400:
                raise PolicyError(
                    "Redirects are not followed; declare the final origin/path explicitly"
                )
            return response

    async def root(self, owner, scan_id):
        return await self.request(owner, scan_id, "/")


class Context:
    def __init__(self, policy, owner, scan_id, plan, credentials):
        self.policy, self.owner, self.scan_id = policy, owner, scan_id
        self.plan, self.credentials = plan, credentials
        self.origin = policy.store.session(owner, scan_id)["origin"]
        self.requests = 0
        self.allowed = {plan.header_path}
        self.allowed.update(p.path for p in plan.probes)
        self.allowed.update(c.path for c in plan.access_cases)
        self.allowed.update(c.identity_path for c in plan.access_cases)

    def check_cancelled(self):
        self.policy.store.active(self.owner, self.scan_id)

    async def get(self, path, params=None, principal=None):
        self.check_cancelled()
        if path not in self.allowed:
            raise PolicyError("Path is outside the owner-declared plan")
        if not self.plan.read_only_confirmed:
            raise PolicyError("Explicit read-only scope confirmation is required")
        self.requests += 1
        if self.requests > 96:
            raise PolicyError("96-request scan budget exhausted")
        token = self.credentials.get(principal) if principal else None
        if principal and not token:
            raise PolicyError("Test principal is unavailable; credentials are not persisted")
        return await self.policy.request(self.owner, self.scan_id, path, params, token)

    async def get_root(self):
        return await self.get(self.plan.header_path)


async def execute(store, policy, job, credentials):
    from racs.checks import CHECKS
    from racs.redaction import scrub

    owner, scan_id = job["owner"], job["id"]
    raw = store.plan(owner, scan_id)
    if not raw:
        store.finish(
            owner,
            scan_id,
            "not_performed",
            "Legacy session: enqueue with an explicit read-only plan",
        )
        return
    plan = ScanPlan.model_validate(raw)
    ctx = Context(policy, owner, scan_id, plan, credentials)
    try:
        async with asyncio.timeout(180):
            for name in dict.fromkeys(plan.checks):
                ctx.check_cancelled()
                try:
                    outcome = await CHECKS[name].run(ctx)
                except (PolicyError, ValueError, OSError) as exc:
                    outcome = CheckOutcome(check=name, status="inconclusive", detail=str(exc)[:500])
                payload = scrub(outcome.model_dump(mode="json"), list(credentials.values()))
                store.save_outcome(owner, scan_id, payload)
                if store.distress(ctx.origin):
                    raise PolicyError("Target distress stop; remaining checks not performed")
            store.finish(
                owner,
                scan_id,
                "completed",
                f"{ctx.requests} bounded requests; inspect per-check coverage",
            )
    except TimeoutError:
        store.finish(
            owner,
            scan_id,
            "failed",
            "180-second scan deadline reached; report contains partial results",
        )
    except PolicyError as exc:
        store.finish(owner, scan_id, "failed", str(exc))


async def worker(store, stop, outbound=None, vault=None, interval=1.0):
    from racs.network import Outbound

    store.recover()
    vault = vault if vault is not None else {}
    policy = TrafficPolicy(store, outbound or Outbound(), interval)
    while not stop.is_set():
        for expired_id in store.inactive_ids(list(vault)):
            vault.pop(expired_id, None)
        job = store.claim()
        if job:
            try:
                await execute(store, policy, job, vault.pop(job["id"], {}))
            except Exception:
                store.finish(
                    job["owner"],
                    job["id"],
                    "failed",
                    "Check execution failed; no clean result implied",
                )
        try:
            await asyncio.wait_for(stop.wait(), timeout=0.25)
        except TimeoutError:
            pass
