import asyncio
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError
from pypdf import PdfReader

from racs.browser_verify import proves_execution
from racs.checks import CHECKS, finding
from racs.models import AccessCase, ScanPlan
from racs.network import Outbound, Response
from racs.redaction import scrub
from racs.reporting import html_report, pdf_report
from racs.scope import PolicyError, Scope, validate_path
from racs.storage import Store


def case(**overrides):
    data = {
        "path": "/object/alpha",
        "owner_principal": "alice",
        "other_principal": "bob",
        "identity_path": "/identity",
        "owner_identity": "alice",
        "other_identity": "bob",
        "json_field": "id",
        "expected_value": "alpha",
        "marker_field": "private_marker",
        "private_marker": "independent-private-test-marker",
    }
    return data | overrides


@pytest.mark.parametrize(
    "overrides",
    [
        {"marker_field": "id"},
        {"expected_value": "independent-private-test-marker"},
        {"path": "/independent-private-test-marker"},
        {"other_principal": "alice"},
        {"other_identity": "alice"},
    ],
)
def test_idor_independent_marker(overrides):
    with pytest.raises(ValidationError):
        AccessCase(**case(**overrides))


@pytest.mark.parametrize(
    "path",
    [
        "//example.com",
        "/%2e%2e/",
        "/a/../b",
        "/logout",
        "/delete/item",
        "/x?q=1",
        "https://example.com",
        "/a\\b",
    ],
)
def test_request_path_boundary(path):
    with pytest.raises(PolicyError):
        validate_path(path)


async def test_lab_is_disabled_by_default():
    with pytest.raises(PolicyError):
        Scope.parse("https://racs-lab.localhost:9443")
    scope = Scope.parse("https://racs-lab.localhost:9443", allow_lab=True)
    with pytest.raises(PolicyError):
        await Outbound().addresses(scope)


async def test_multiple_csp_header_policies_suppress_framing():
    response = Response(
        200,
        b"<html></html>",
        {
            "content-type": "text/html",
            "content-security-policy": "default-src 'self', frame-ancestors 'none'",
            "x-content-type-options": "nosniff",
            "strict-transport-security": "max-age=123",
        },
    )
    ctx = SimpleNamespace(
        origin="https://example.com", plan=ScanPlan(), get_root=AsyncMock(return_value=response)
    )
    result = await CHECKS["headers"].run(ctx)
    assert not result.findings


async def test_xss_resource_dependent_replay_is_inconclusive():
    response = Response(
        200, b'<html><script src="/sanitizer.js"></script></html>', {"content-type": "text/html"}
    )
    assert await proves_execution(response, "https://example.com/", "test") is None


async def test_idor_missing_id_is_not_evidence():
    access = AccessCase(**case(expected_value="None"))
    ctx = SimpleNamespace(
        origin="https://example.com",
        plan=ScanPlan(access_cases=[access]),
        credentials={"alice": "one", "bob": "two"},
        get=AsyncMock(
            side_effect=[
                Response(200, b'{"id":"alice"}'),
                Response(200, b'{"id":"bob"}'),
                Response(200, b'{"private_marker":"independent-private-test-marker"}'),
            ]
        ),
    )
    result = await CHECKS["idor"].run(ctx)
    assert result.status == "not_performed"
    assert not result.findings


async def test_sql_dynamic_or_reflected_results_are_not_findings():
    ctx = SimpleNamespace(
        origin="https://example.com",
        plan=ScanPlan(probes=[{"path": "/query", "parameter": "q"}]),
        get=AsyncMock(
            side_effect=[
                Response(200, b'{"data":[1]}', {"content-type": "application/json"}),
                Response(200, b'{"data":[2]}', {"content-type": "application/json"}),
            ]
        ),
    )
    assert (await CHECKS["sqli"].run(ctx)).status == "not_performed"


def test_reports_escape_untrusted_data_and_redact():
    f = finding(
        "fixture",
        "https://example.com/",
        None,
        "<script>alert(1)</script>",
        "Use <safe> output",
        '<img src="file:///secret">',
    ).model_dump(mode="json")
    report = {
        "session": {
            "id": "test",
            "origin": "https://example.com",
            "status": "completed",
            "detail": "<untrusted>",
        },
        "findings": [f],
        "outcomes": [],
    }
    html = html_report(report)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    pdf = pdf_report(report)
    assert "Sample fix" in "".join(page.extract_text() for page in PdfReader(BytesIO(pdf)).pages)
    assert scrub({"evidence": "Bearer abc123 racs-v1=proof anotherSecret"}, ["anotherSecret"]) == {
        "evidence": "Bearer [redacted] [verification token redacted] [redacted]"
    }


def test_schema_migration_and_expired_vault_ids(tmp_path):
    import sqlite3

    store = Store(tmp_path / "db.sqlite3", clock=lambda: 1000)
    # Simulate a real version-1 database, then verify in-place migration.
    with sqlite3.connect(store.path) as db:
        db.execute("ALTER TABLE scans DROP COLUMN plan")
        db.execute("PRAGMA user_version=1")
    store = Store(store.path, clock=lambda: 1000)
    scope = Scope.parse("example.com")
    c = store.issue("alice", scope, "dns")
    store.complete_proof("alice", c["id"], [c["token"]])
    job = store.enqueue("alice", scope)
    store.clock = lambda: 100000
    assert store.inactive_ids([job["id"]]) == [job["id"]]
    assert store.session("alice", job["id"])["status"] == "cancelled"


async def test_aggregate_interval(tmp_path, monkeypatch):
    from racs.engine import TrafficPolicy

    store = Store(tmp_path / "db.sqlite3")
    scope = Scope.parse("example.com")
    c = store.issue("alice", scope, "dns")
    store.complete_proof("alice", c["id"], [c["token"]])
    jobs = [store.enqueue("alice", scope) for _ in range(2)]
    store.claim()
    store.claim()
    times = []

    async def response(*args, **kwargs):
        times.append(asyncio.get_running_loop().time())
        return Response(200, b"ok")

    net = SimpleNamespace(lab_ca=None, addresses=AsyncMock(return_value=["8.8.8.8"]), _get=response)
    policy = TrafficPolicy(store, net, interval=0.05)
    await asyncio.gather(*(policy.root("alice", j["id"]) for j in jobs))
    assert times[1] - times[0] >= 0.045


def header_ctx(headers):
    response = Response(200, b"<html></html>", {"content-type": "text/html"} | headers)
    return SimpleNamespace(
        origin="https://example.com", plan=ScanPlan(), get_root=AsyncMock(return_value=response)
    )


async def test_framing_value_whitespace_and_wildcard_ancestors():
    padded = await CHECKS["headers"].run(header_ctx({"x-frame-options": " DENY "}))
    assert "headers.framing" not in {f.type for f in padded.findings}
    repeated = await CHECKS["headers"].run(header_ctx({"x-frame-options": "DENY, DENY"}))
    assert "headers.framing" not in {f.type for f in repeated.findings}
    conflicting = await CHECKS["headers"].run(header_ctx({"x-frame-options": "DENY, SAMEORIGIN"}))
    assert "headers.framing" not in {f.type for f in conflicting.findings}
    obsolete = await CHECKS["headers"].run(header_ctx({"x-frame-options": "ALLOW-FROM https://a.example"}))
    assert "headers.framing" in {f.type for f in obsolete.findings}
    wildcard = await CHECKS["headers"].run(
        header_ctx({"content-security-policy": "default-src 'self'; frame-ancestors *"})
    )
    assert "headers.framing" in {f.type for f in wildcard.findings}


async def test_hsts_max_age_zero_counts_as_absent():
    disabled = await CHECKS["headers"].run(header_ctx({"strict-transport-security": "max-age=0"}))
    assert "headers.strict-transport-security" in {f.type for f in disabled.findings}
    enabled = await CHECKS["headers"].run(header_ctx({"strict-transport-security": "max-age=600"}))
    assert "headers.strict-transport-security" not in {f.type for f in enabled.findings}


def test_scrub_basic_auth_and_cookie_values():
    text = "Authorization: Basic YWxpY2U6c2VjcmV0\nCookie: session=abc123; theme=dark"
    assert scrub(text) == "Authorization: Basic [redacted]\nCookie: session=[redacted]; theme=[redacted]"
    assert scrub("Set-Cookie: sid=xyz; Path=/; HttpOnly") == "Set-Cookie: sid=[redacted]; Path=/; HttpOnly"


def test_cli_version(capsys):
    from racs.cli import main

    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.startswith("RACS 0.")
