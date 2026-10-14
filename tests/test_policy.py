from unittest.mock import AsyncMock

import pytest

from racs.engine import TrafficPolicy
from racs.network import Response
from racs.scope import PolicyError, Scope
from racs.storage import Store


@pytest.mark.parametrize("status", [429, 500, 503])
async def test_distress_latches_across_sessions(tmp_path, status):
    store = Store(tmp_path / "policy.sqlite3")
    scope = Scope.parse("example.com")
    c = store.issue("alice", scope, "dns")
    store.complete_proof("alice", c["id"], [c["token"]])
    one = store.enqueue("alice", scope)
    store.claim()
    two = store.enqueue("alice", scope)
    store.claim()
    outbound = AsyncMock()
    outbound.addresses.return_value = ["8.8.8.8"]
    outbound._get.return_value = Response(status, b"")
    policy = TrafficPolicy(store, outbound)
    for job in [one, two]:
        with pytest.raises(PolicyError):
            await policy.root("alice", job["id"])
    outbound._get.assert_awaited_once()


async def test_cancelled_job_never_reaches_network(tmp_path):
    store = Store(tmp_path / "policy.sqlite3")
    scope = Scope.parse("example.com")
    c = store.issue("alice", scope, "dns")
    store.complete_proof("alice", c["id"], [c["token"]])
    job = store.enqueue("alice", scope)
    store.claim()
    store.cancel("alice", job["id"])
    outbound = AsyncMock()
    with pytest.raises(PolicyError):
        await TrafficPolicy(store, outbound).root("alice", job["id"])
    outbound.addresses.assert_not_called()
