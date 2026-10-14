import asyncio
import hashlib
import secrets
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

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
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    allowed_origins = {f"http://{host}" for host in allowed_hosts}

    @asynccontextmanager
    async def lifespan(app):
        stop = asyncio.Event()
        task = asyncio.create_task(worker(store, stop))
        yield
        stop.set()
        await task

    app = FastAPI(
        title="RACS",
        version="0.1.0",
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
                "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
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
        return f"<!doctype html><html lang='en'><meta charset='utf-8'><title>RACS</title><h1>RACS</h1><h2>Rudy Advanced Cybersecurity Scanner</h2><p><strong>{NOTICE}</strong></p><p>Step 1 foundation: ownership verification and persistent scan sessions. No vulnerability checks or reports are installed.</p></html>"

    @app.get("/health")
    def health():
        return {"status": "ok", "stage": 1, "checks_installed": 0}

    @app.post("/api/challenges", status_code=201)
    def challenge(body: ChallengeRequest, user=Depends(authenticated)):
        return store.issue(user, Scope.parse(body.target), body.method)

    @app.post("/api/challenges/{challenge_id}/verify")
    async def verify(challenge_id: str, user=Depends(authenticated)):
        challenge = store.begin_proof(user, challenge_id)
        try:
            records = await outbound.proof(Scope.parse(challenge["origin"]), challenge["method"])
        except (OSError, TimeoutError) as exc:
            raise HTTPException(400, "Verification network request failed") from exc
        return store.complete_proof(user, challenge_id, records)

    @app.post("/api/targets/revoke")
    def revoke(body: ScanRequest, user=Depends(authenticated)):
        store.revoke(user, Scope.parse(body.target))
        return {"status": "revoked"}

    @app.post("/api/scans", status_code=202, response_model=ScanSession)
    def enqueue(body: ScanRequest, user=Depends(authenticated)):
        return store.enqueue(user, Scope.parse(body.target))

    @app.get("/api/scans/{scan_id}", response_model=ScanSession)
    def session(scan_id: str, user=Depends(authenticated)):
        return store.session(user, scan_id)

    @app.post("/api/scans/{scan_id}/cancel")
    def cancel(scan_id: str, user=Depends(authenticated)):
        store.cancel(user, scan_id)
        return store.session(user, scan_id)

    @app.delete("/api/data")
    def purge(user=Depends(authenticated)):
        store.purge(user)
        return {"status": "deleted"}

    return app
