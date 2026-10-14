import asyncio
import os
import subprocess
import sys
import time
from io import BytesIO
from pathlib import Path

import pytest
from pypdf import PdfReader

from racs.checks import CHECKS
from racs.engine import Context, TrafficPolicy, execute
from racs.models import ScanPlan
from racs.network import Outbound
from racs.reporting import html_report, pdf_report
from racs.scope import PolicyError, Scope
from racs.storage import Store

pytestmark = pytest.mark.practice


@pytest.fixture(scope="session")
def practice_root(tmp_path_factory):
    supplied = os.environ.get("RACS_PRACTICE_ROOT")
    if supplied:
        yield Path(supplied).resolve()
        return
    root = tmp_path_factory.mktemp("practice")
    process = subprocess.Popen(
        [sys.executable, "tests/practice/server.py", "--root", str(root)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            if (root / "lab-cert.pem").exists():
                time.sleep(0.3)
                break
            if process.poll() is not None:
                raise RuntimeError("Practice fixture did not start")
            time.sleep(0.1)
        yield root
    finally:
        process.terminate()
        process.wait(timeout=10)


async def context(tmp_path, root, plan):
    store = Store(tmp_path / "test.sqlite3")
    scope = Scope.parse("https://racs-lab.localhost:9443", allow_lab=True)
    net = Outbound(lab_ca=root / "lab-cert.pem")
    c = store.issue("alice", scope, "https")
    (root / "proof.txt").write_text(c["token"])
    store.begin_proof("alice", c["id"])
    proof = await net.proof(scope, "https")
    store.complete_proof("alice", c["id"], proof)
    job = store.enqueue("alice", scope, plan.model_dump())
    store.claim()
    creds = {"alice": "practice-alice-token", "bob": "practice-bob-token"}
    return Context(TrafficPolicy(store, net, interval=0.01), "alice", job["id"], plan, creds)


@pytest.mark.parametrize("route,expected", [("/vulnerable/headers", 4), ("/safe/headers", 0)])
async def test_live_headers(tmp_path, practice_root, route, expected):
    ctx = await context(
        tmp_path, practice_root, ScanPlan(header_path=route, read_only_confirmed=True)
    )
    result = await CHECKS["headers"].run(ctx)
    assert len(result.findings) == expected
    assert all(f.verification_status == "observation" for f in result.findings)


@pytest.mark.parametrize(
    "route,expected", [("/vulnerable/xss", 1), ("/safe/xss", 0), ("/csp/xss", 0), ("/json/xss", 0)]
)
async def test_live_xss(tmp_path, practice_root, route, expected):
    plan = ScanPlan(
        probes=[{"path": route, "parameter": "q", "baseline": "hello"}], read_only_confirmed=True
    )
    result = await CHECKS["xss"].run(await context(tmp_path, practice_root, plan))
    assert len(result.findings) == expected, result.model_dump()
    assert all(f.confidence == "high" for f in result.findings)


@pytest.mark.parametrize("route,expected", [("/vulnerable/sqli", 1), ("/safe/sqli", 0)])
async def test_live_sql(tmp_path, practice_root, route, expected):
    plan = ScanPlan(
        probes=[{"path": route, "parameter": "q", "baseline": "1"}], read_only_confirmed=True
    )
    result = await CHECKS["sqli"].run(await context(tmp_path, practice_root, plan))
    assert len(result.findings) == expected, result.model_dump()
    assert all(f.verification_status == "indicator" for f in result.findings)


def access_case(route):
    return {
        "path": route,
        "owner_principal": "alice",
        "other_principal": "bob",
        "json_field": "id",
        "expected_value": "alpha",
        "identity_path": "/identity",
        "owner_identity": "alice",
        "other_identity": "bob",
        "marker_field": "private_test_marker",
        "private_marker": "synthetic-private-marker-49328",
    }


@pytest.mark.parametrize(
    "route,expected",
    [("/vulnerable/object/alpha", 1), ("/safe/object/alpha", 0), ("/echo/object/alpha", 0)],
)
async def test_live_idor(tmp_path, practice_root, route, expected):
    plan = ScanPlan(access_cases=[access_case(route)], read_only_confirmed=True)
    result = await CHECKS["idor"].run(await context(tmp_path, practice_root, plan))
    assert len(result.findings) == expected, result.model_dump()


async def test_live_worker_reports_and_no_credentials_at_rest(tmp_path, practice_root):
    plan = ScanPlan(
        checks=["headers", "xss", "sqli", "idor"],
        header_path="/vulnerable/headers",
        probes=[
            {"path": "/vulnerable/xss", "parameter": "q", "baseline": "hello"},
            {"path": "/vulnerable/sqli", "parameter": "q", "baseline": "1"},
        ],
        access_cases=[access_case("/vulnerable/object/alpha")],
        read_only_confirmed=True,
    )
    ctx = await context(tmp_path, practice_root, plan)
    store = ctx.policy.store
    await execute(store, ctx.policy, store.session("alice", ctx.scan_id), ctx.credentials)
    report = store.report("alice", ctx.scan_id)
    assert report["session"]["status"] == "completed"
    assert len(report["findings"]) == 7, report
    html = html_report(report)
    pdf = pdf_report(report)
    assert "Sample fix" in html
    text = "".join(page.extract_text() for page in PdfReader(BytesIO(pdf)).pages)
    assert "Sample fix" in text and "Remediation" in text
    assert b"practice-alice-token" not in store.path.read_bytes()
    assert b"practice-bob-token" not in store.path.read_bytes()
    (tmp_path / "report.pdf").write_bytes(pdf)


async def test_revocation_closes_pending_request(tmp_path, practice_root):
    ctx = await context(tmp_path, practice_root, ScanPlan(read_only_confirmed=True))
    cancelled = asyncio.Event()

    async def waiting(*args, **kwargs):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    ctx.policy.outbound._get = waiting
    task = asyncio.create_task(ctx.get("/"))
    await asyncio.sleep(0.05)
    ctx.policy.store.revoke("alice", Scope.parse(ctx.origin, allow_lab=True))
    with pytest.raises(PolicyError):
        await task
    assert cancelled.is_set()
