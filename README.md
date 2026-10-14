# RACS — Rudy Advanced Cybersecurity Scanner

**Authorized use only. You are responsible for testing only systems you own or
are explicitly authorized to test. RACS requires proof of control before a scan
can be queued. Proof does not replace legal authorization. RACS finds, reports,
and advises; it never modifies a target.**

RACS is a modular Python/FastAPI security tooling project with SQLite storage.
This release implements **Step 1: the ownership and repository foundation**.
No vulnerability checks, report generator, or category workflow are installed yet.

## What works

- Expiring DNS TXT or HTTPS-file ownership challenges with single-use proofs.
- Exact-host HTTPS scope, bounded grants, revocation, and requester isolation.
- Public-address validation, pinned TLS connections, no proxies or redirects.
- Authenticated local API, persistent bounded scan sessions, cancellation and
  restart recovery. Jobs end as `not_performed` because there are no checks yet.
- Strict finding schema and an async plugin contract for later modules.

## Run locally

Requires Python 3.12 or newer. From this directory on Windows:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\racs.exe
```

On macOS/Linux, use `.venv/bin/python` and `.venv/bin/racs`. The service binds to
`http://127.0.0.1:8765`; there is intentionally no public-interface option.
Only one process may use a runtime directory. The default Windows runtime folder
is `%LOCALAPPDATA%\RACS`; on other systems it is `~/.local/share/RACS`.
Keep its `api-token` file private. The launcher prints its path, never its value.
Use `--data-dir` to select another **local, private** runtime directory.

The API expects `Authorization: Bearer <contents of api-token>` and
`Content-Type: application/json`. Do not place the token in a URL or commit it.

| Request | Purpose |
| --- | --- |
| `GET /health` | Stage and health status; no authentication needed |
| `POST /api/challenges` | Body: `{"target":"https://your-domain.tld","method":"dns"}` (or `https`) |
| `POST /api/challenges/{id}/verify` | Body: `{}`; check the issued proof at its returned location |
| `POST /api/scans` | Body: `{"target":"https://your-domain.tld"}`; requires a current grant |
| `GET /api/scans/{id}` | Read the persistent session |
| `POST /api/scans/{id}/cancel` | Body: `{}`; cancel a queued/running session |
| `POST /api/targets/revoke` | Body: `{"target":"https://your-domain.tld"}`; revoke and cancel |
| `DELETE /api/data` | Delete this operator's sessions, grants and challenges |

Publish the returned challenge token yourself as a TXT record at the returned
name, or as the content of the HTTPS file. RACS never writes to your target.
Challenges expire after ten minutes; grants after 24 hours. Scope currently permits
only the exact HTTPS host, port 443 and root path. Subdomains need separate proof.
HTTPS verification rejects every redirect, including redirects to `www`.

## Development

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests
```

Tests use synthetic proofs and mocked DNS/TLS streams and block external network
connections. `requirements-dev.lock` records the exact validated environment;
install it before the editable package for a reproducible development setup.
The [architecture notes](docs/architecture.md) distinguish implemented protections
from future scan-engine and reporting requirements. This is local development
software; it is not ready for a public or multi-user service.

## Next stages

1. **Implemented:** foundation, ownership verification, repository hygiene.
2. Missing-security-header check.
3. HTML and PDF reports.
4. Plain HTML/CSS/JavaScript category UI; Network and Cloud marked coming soon.
5. Reflected XSS, SQL-injection indicators, then owner-scoped access-control checks.

Each stage is implemented and tested separately. Indicators must remain distinct
from verified vulnerabilities, and confidence must explain the evidence.

## License

MIT. See [LICENSE](LICENSE).
