"""Durable queue foundation. Step 1 consumes jobs without making scan requests."""

import asyncio
import time

from racs.network import Outbound
from racs.scope import PolicyError, Scope


class TrafficPolicy:
    """Single-process aggregate per-origin throttling and persistent-in-process stops."""

    def __init__(self, store, outbound: Outbound):
        self.store = store
        self.outbound = outbound
        self.locks = {}
        self.next_at = {}
        self.failures = {}
        self.stopped = set()
        self.slots = asyncio.Semaphore(2)

    async def root(self, owner, scan_id):
        session = self.store.session(owner, scan_id)
        origin = session["origin"]
        lock = self.locks.setdefault(origin, asyncio.Lock())
        async with lock, self.slots:
            self.store.active(owner, scan_id)
            if origin in self.stopped:
                raise PolicyError("Target distress stop is latched; restart after investigating")
            await asyncio.sleep(max(0, self.next_at.get(origin, 0) - time.monotonic()))
            self.store.active(owner, scan_id)
            self.next_at[origin] = time.monotonic() + 2
            try:
                async with asyncio.timeout(10):
                    scope = Scope.parse(origin)
                    addresses = await self.outbound.addresses(scope)
                    self.store.active(owner, scan_id)
                    response = await self.outbound._get(scope, addresses[0], "/")
                    self.store.active(owner, scan_id)
            except (OSError, TimeoutError):
                self.failures[origin] = self.failures.get(origin, 0) + 1
                if self.failures[origin] >= 3:
                    self.stopped.add(origin)
                raise
            if response.status == 429 or response.status >= 500:
                self.stopped.add(origin)
                raise PolicyError("Target signalled distress; no retries will be sent")
            return response


async def worker(store, stop: asyncio.Event):
    store.recover()
    while not stop.is_set():
        job = store.claim()
        if job:
            # No check execution until the next implementation stage. Empty results
            # must never masquerade as a successful security assessment.
            store.finish(
                job["owner"], job["id"], "not_performed", "Step 1: no scanner checks installed"
            )
        try:
            await asyncio.wait_for(stop.wait(), timeout=0.25)
        except TimeoutError:
            pass
