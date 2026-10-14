import asyncio
import contextlib
import hashlib
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from racs.engine import worker
from racs.models import ChallengeRequest, ScanRequest, ScanSession
from racs.network import Outbound
from racs.scope import PolicyError, Scope

NOTICE = "Only test systems you own or are explicitly authorized to test. Proof of control is required and does not replace legal authorization. RACS never modifies a target."


def create_app(store, api_token: str, outbound=None, port=8765):
    if len(api_token) < 32:
        raise ValueError("A cryptographically random local API token is required")
    owner = hashlib.sha256(api_token.encode()).hexdigest()
    outbound = outbound or Outbound()
    vault = {}

    def parse_scope(value):
        return Scope.parse(value, allow_lab=bool(outbound.lab_ca))

    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    allowed_origins = {f"http://{host}" for host in allowed_hosts}

    @asynccontextmanager
    async def lifespan(app):
        stop = asyncio.Event()
        task = asyncio.create_task(worker(store, stop, outbound, vault))
        app.state.worker = task
        try:
            yield
        finally:
            stop.set()
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            vault.clear()

    app = FastAPI(
        title="RACS",
        version="0.2.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.middleware("http")
    async def local_boundary(request: Request, call_next):
        if request.headers.get("host", "") not in allowed_hosts:
            return JSONResponse({"detail": "Invalid local Host"}, status_code=400)
        if request.headers.get("origin") and request.headers["origin"] not in allowed_origins:
            return JSONResponse({"detail": "Cross-origin requests are forbidden"}, status_code=403)
        if request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse({"detail": "Cross-site requests are forbidden"}, status_code=403)
        if request.method in ("POST", "PUT", "PATCH"):
            if request.headers.get("content-type", "").split(";")[0] != "application/json":
                return JSONResponse({"detail": "JSON required"}, status_code=415)
            size = 0
            chunks = []
            try:
                async with asyncio.timeout(5):
                    async for chunk in request.stream():
                        size += len(chunk)
                        if size > 8192:
                            return JSONResponse({"detail": "Body too large"}, status_code=413)
                        chunks.append(chunk)
            except TimeoutError:
                return JSONResponse({"detail": "Request body timed out"}, status_code=408)
            request._body = b"".join(chunks)
        response = await call_next(request)
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
                "Referrer-Policy": "no-referrer",
            }
        )
        return response

    async def authenticated(request: Request):
        supplied = request.headers.get("authorization", "")
        if not secrets.compare_digest(supplied.encode(), f"Bearer {api_token}".encode()):
            raise HTTPException(401, "Local bearer token required")
        return owner

    @app.exception_handler(PolicyError)
    async def policy_error(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=400)

    @app.get("/", response_class=HTMLResponse)
    def home():
        return (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")

    @app.get("/health")
    def health():
        return {
            "status": "degraded"
            if getattr(app.state, "worker", None) is not None and app.state.worker.done()
            else "ok",
            "stage": 5,
            "checks_installed": 4,
            "local_practice_enabled": bool(outbound.lab_ca),
        }

    @app.post("/api/challenges", status_code=201)
    def challenge(body: ChallengeRequest, user=Depends(authenticated)):
        return store.issue(user, parse_scope(body.target), body.method)

    @app.post("/api/challenges/{challenge_id}/verify")
    async def verify(challenge_id: str, user=Depends(authenticated)):
        challenge = store.begin_proof(user, challenge_id)
        try:
            records = await outbound.proof(parse_scope(challenge["origin"]), challenge["method"])
        except (OSError, TimeoutError) as exc:
            raise HTTPException(400, "Verification network request failed") from exc
        return store.complete_proof(user, challenge_id, records)

    @app.post("/api/targets/revoke")
    def revoke(body: ScanRequest, user=Depends(authenticated)):
        store.revoke(user, parse_scope(body.target))
        for job in store.history(user):
            if job["origin"] == parse_scope(body.target).origin:
                vault.pop(job["id"], None)
        return {"status": "revoked"}

    @app.post("/api/scans", status_code=202, response_model=ScanSession)
    async def enqueue(body: ScanRequest, user=Depends(authenticated)):
        from racs.checks import CHECKS

        if any(name not in CHECKS for name in body.plan.checks):
            raise HTTPException(400, "Unknown installed check")
        if not body.plan.read_only_confirmed:
            raise HTTPException(400, "Confirm that every declared path is authorized and read-only")
        job = store.enqueue(user, parse_scope(body.target), body.plan.model_dump())
        vault[job["id"]] = body.credentials
        return job

    @app.get("/api/scans/{scan_id}", response_model=ScanSession)
    def session(scan_id: str, user=Depends(authenticated)):
        return store.session(user, scan_id)

    @app.post("/api/scans/{scan_id}/cancel")
    def cancel(scan_id: str, user=Depends(authenticated)):
        store.cancel(user, scan_id)
        vault.pop(scan_id, None)
        return store.session(user, scan_id)

    @app.delete("/api/data")
    def purge(user=Depends(authenticated)):
        store.purge(user)
        vault.clear()
        return {"status": "deleted"}

    @app.get("/api/scans")
    def history(user=Depends(authenticated)):
        return store.history(user)

    @app.get("/api/scans/{scan_id}/report")
    def report(scan_id: str, user=Depends(authenticated)):
        return store.report(user, scan_id)

    @app.get("/api/scans/{scan_id}/report.{format}")
    def export(scan_id: str, format: str, user=Depends(authenticated)):
        from racs.reporting import html_report, pdf_report

        report = store.report(user, scan_id)
        if format not in ("html", "pdf"):
            raise HTTPException(404)
        data = html_report(report) if format == "html" else pdf_report(report)
        return Response(
            data,
            media_type="text/html" if format == "html" else "application/pdf",
            headers={"Content-Disposition": f'attachment; filename="racs-{scan_id}.{format}"'},
        )

    @app.post("/api/targets/recover")
    def recover_target(body: ScanRequest, user=Depends(authenticated)):
        store.clear_distress(user, parse_scope(body.target))
        return {"status": "recovery acknowledged"}

    app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
    return app
