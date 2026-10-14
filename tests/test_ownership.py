import asyncio
import hashlib
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from racs.app import create_app
from racs.engine import worker
from racs.scope import PolicyError, Scope, public_ip
from racs.storage import CHALLENGE_TTL, GRANT_TTL, QUEUE_LIMIT, Store


@pytest.fixture
def store(tmp_path):
    clock = [1000.0]
    result = Store(tmp_path / "test.sqlite3", clock=lambda: clock[0])
    result.test_clock = clock
    return result


def grant(store, owner="alice", target="example.com", method="dns"):
    scope = Scope.parse(target)
    challenge = store.issue(owner, scope, method)
    store.begin_proof(owner, challenge["id"])
    store.complete_proof(owner, challenge["id"], [challenge["token"]])
    return scope, challenge


@pytest.mark.parametrize(
    "target",
    [
        "http://example.com",
        "https://example.com:8443",
        "127.0.0.1",
        "[::1]",
        "2130706433",
        "https://user@example.com",
        "https://example.com/a",
        "https://example.com?",
        "https://example.com#",
        "https://example.com\\@localhost",
        "localhost",
        "a.local",
        "a.internal",
        "https://example.com\n",
        "example.com.",
    ],
)
def test_invalid_scopes(target):
    with pytest.raises(PolicyError):
        Scope.parse(target)


def test_canonical_scope():
    assert Scope.parse("HTTPS://Example.COM:443/").origin == "https://example.com"


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "192.0.2.1",
        "::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "::ffff:8.8.8.8",
        "2002:0808:0808::1",
        "2001:db8::1",
    ],
)
def test_non_public_ip(address):
    with pytest.raises(PolicyError):
        public_ip(address)


def test_challenge_secret_and_scope(store):
    scope, challenge = grant(store)
    assert len(challenge["token"]) > 40
    assert challenge["token"].encode() not in store.path.read_bytes()
    assert store.enqueue("alice", scope)["status"] == "queued"
    for owner, target in [
        ("bob", "example.com"),
        ("alice", "sub.example.com"),
        ("alice", "other.com"),
    ]:
        with pytest.raises(PolicyError):
            store.enqueue(owner, Scope.parse(target))
    with pytest.raises(PolicyError):
        store.complete_proof("alice", challenge["id"], [challenge["token"]])


def test_expiry_and_revocation(store):
    scope, _ = grant(store)
    job = store.enqueue("alice", scope)
    store.test_clock[0] += GRANT_TTL
    assert store.claim() is None
    assert store.session("alice", job["id"])["status"] == "cancelled"
    scope, _ = grant(store)
    job = store.enqueue("alice", scope)
    store.claim()
    store.revoke("alice", scope)
    with pytest.raises(PolicyError):
        store.active("alice", job["id"])
    store.finish("alice", job["id"], "completed", "Must not overwrite cancellation")
    assert store.session("alice", job["id"])["status"] == "cancelled"


def test_wrong_proof_expiration_and_requester(store):
    challenge = store.issue("alice", Scope.parse("example.com"), "https")
    assert challenge["location"] == "https://example.com/.well-known/racs-verify.txt"
    for owner in ["bob", "alice"]:
        with pytest.raises(PolicyError):
            store.complete_proof(owner, challenge["id"], ["wrong"])
    store.test_clock[0] += CHALLENGE_TTL
    with pytest.raises(PolicyError):
        store.complete_proof("alice", challenge["id"], [challenge["token"]])


def test_revocation_during_proof(store):
    scope = Scope.parse("example.com")
    c = store.issue("alice", scope, "dns")
    store.begin_proof("alice", c["id"])
    store.revoke("alice", scope)
    with pytest.raises(PolicyError):
        store.complete_proof("alice", c["id"], [c["token"]])


def test_attempt_limits_persist_and_reissue_does_not_skip_throttle(store):
    scope = Scope.parse("example.com")
    c = store.issue("alice", scope, "dns")
    store.begin_proof("alice", c["id"])
    store = Store(store.path, clock=store.clock)
    c = store.issue("alice", scope, "dns")
    with pytest.raises(PolicyError, match="Wait"):
        store.begin_proof("alice", c["id"])


def test_atomic_queue_capacity_and_recovery(store):
    scope, _ = grant(store)

    def enqueue(_):
        try:
            return store.enqueue("alice", scope)
        except PolicyError:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(enqueue, range(40)))
    assert sum(r is not None for r in results) == QUEUE_LIMIT
    job = store.claim()
    Store(store.path, store.clock).recover()
    assert store.session("alice", job["id"])["status"] == "interrupted"


async def test_worker_does_not_claim_security_success(store):
    scope, _ = grant(store)
    job = store.enqueue("alice", scope)
    stop = asyncio.Event()
    task = asyncio.create_task(worker(store, stop))
    await asyncio.sleep(0.02)
    stop.set()
    await task
    assert store.session("alice", job["id"])["status"] == "not_performed"


@pytest.mark.parametrize("method", ["dns", "https"])
def test_api_flow(store, method):
    token = "a" * 43
    outbound = AsyncMock()
    client = TestClient(create_app(store, token, outbound), base_url="http://127.0.0.1:8765")
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/health").json()["checks_installed"] == 4
    assert (
        client.post("/api/challenges", json={"target": "example.com", "method": method}).status_code
        == 401
    )
    assert (
        client.post(
            "/api/scans",
            headers=headers,
            json={"target": "example.com", "plan": {"read_only_confirmed": True}},
        ).status_code
        == 400
    )
    r = client.post(
        "/api/challenges", headers=headers, json={"target": "example.com", "method": method}
    )
    assert r.status_code == 201, r.text
    c = r.json()
    outbound.proof.return_value = [c["token"]]
    assert (
        client.post(f"/api/challenges/{c['id']}/verify", headers=headers, json={}).status_code
        == 200
    )
    job = client.post(
        "/api/scans",
        headers=headers,
        json={"target": "example.com", "plan": {"read_only_confirmed": True}},
    ).json()
    assert job["owner"] == hashlib.sha256(token.encode()).hexdigest()
    assert (
        client.post(f"/api/scans/{job['id']}/cancel", headers=headers, json={}).json()["status"]
        == "cancelled"
    )
    assert (
        client.post(
            "/api/targets/revoke",
            headers=headers,
            json={"target": "example.com", "plan": {"read_only_confirmed": True}},
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/api/scans",
            headers=headers,
            json={"target": "example.com", "plan": {"read_only_confirmed": True}},
        ).status_code
        == 400
    )
    assert client.delete("/api/data", headers=headers).status_code == 200


def test_api_local_security(store):
    client = TestClient(create_app(store, "a" * 43), base_url="http://127.0.0.1:8765")
    assert client.get("/", headers={"Host": "evil.com"}).status_code == 400
    assert client.get("/", headers={"Origin": "https://evil.com"}).status_code == 403
    assert client.get("/", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert client.post("/api/challenges", content="bad").status_code == 415
    assert (
        client.post(
            "/api/challenges", content="x" * 9000, headers={"Content-Type": "application/json"}
        ).status_code
        == 413
    )
    assert client.get("/").headers["content-security-policy"].startswith("default-src 'self'")
