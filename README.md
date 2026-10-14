# RACS - Rudy Advanced Cybersecurity Scanner

**Authorized use only. Test only systems you own or are explicitly authorized to
assess. Proof of control is mandatory and does not replace legal permission.
Every scan needs a declared read-only scope. RACS never modifies the target.**

RACS is a local Python/FastAPI application with SQLite history, four Web checks,
a plain HTML/CSS/JavaScript interface and detailed HTML/PDF reports. Network and
Cloud categories are visible as coming soon.

## Evidence before findings

| Check | Confirmation rule | Meaning of a positive |
| --- | --- | --- |
| Security headers | Missing on two successful HTML responses; respects CSP framing alternatives | High-confidence configuration observation, not proof of exploitation |
| Reflected XSS | Two fresh harmless markers execute in isolated, dependency-free captured HTML with the original enforcing CSP preserved | High-confidence execution in the tested reflected HTML context |
| SQL injection indicators | Stable nonempty JSON result array, benign invalid control, two true/false AND predicate pairs, repeated untouched baselines | High-confidence boolean differential; SQL as the root cause still needs code review |
| Object access control | Two distinct verified test identities; known private object and independent protected marker disclosed twice to the identity declared forbidden | High-confidence disclosure for that exact test object and policy |

Missing inputs, unstable responses and unsupported contexts are marked
`not_performed` or `inconclusive`. A completed job is not a clean bill of health.
No crawling, object enumeration, OR/UNION expansion, stacked SQL, time delays,
credential guessing, persistence or target writes are performed.

## Run locally

Python 3.12+ is required. On Windows:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m playwright install chromium
.\.venv\Scripts\racs.exe
```

On macOS/Linux use `.venv/bin/python` and `.venv/bin/racs`. The launcher binds only
`127.0.0.1:8765` and takes a single-process runtime lock. Its private `api-token`
file is in `%LOCALAPPDATA%\RACS` on Windows or `~/.local/share/RACS` elsewhere.
Paste that token into the local UI; it stays only in page memory. Keep the runtime
folder private and outside network/synchronized folders. Do not expose this app
as a public or multi-user service.

1. Enter an exact HTTPS origin and request a DNS TXT or HTTPS-file challenge.
2. Publish the returned token yourself, then check the proof. Challenges expire
   after ten minutes; grants expire after 24 hours and can be revoked immediately.
3. Select checks and declare exact read-only paths/parameters. SQL probing needs
   the known query context (`string`, `like`, or `numeric`) and a nonempty JSON
   result-array baseline. Access-control testing needs two synthetic test accounts,
   an identity endpoint returning top-level `id`, and a known private test marker.
4. Run the scan and review per-check coverage, confidence rationale, evidence,
   reproduction instructions, remediation and sample fix code. Export HTML/PDF.

Production targets remain exact-host HTTPS on port 443. Subdomains need separate
proof. Redirects, IP literals and private/reserved destinations are rejected.
Browser XSS replay never directly browses the target and carries no credentials.
Pages with resource dependencies or replay errors are inconclusive; DOM-only,
stored, authenticated and resource-dependent XSS are outside current coverage.
IDOR currently supports bearer-token principals and top-level JSON fields.

## Test and practice

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pytest -q --run-practice
.\.venv\Scripts\python.exe -m ruff check src tests
```

The second command starts an isolated TLS practice target on loopback port 9443
and runs vulnerable/safe controls through the real transport and Chromium. Keep
that port free. The target deliberately contains flaws and must never be deployed.
Its certificate and runtime files are temporary. CI runs the practice tests too.
See [validation](docs/validation.md) for the exact coverage and additional local
OWASP Juice Shop validation. The dependency lock records the tested environment.

For manual practice, start `tests/practice/server.py --root <private-directory>`
with the project Python, then launch RACS with `--lab-ca <private-directory>/lab-cert.pem`.
This explicit launcher option permits **only** `https://racs-lab.localhost:9443`,
pinned to `127.0.0.1` with the provided CA. It does not disable ownership proof,
TLS checks or public-target SSRF defenses. Publish the proof token yourself in
`<private-directory>/proof.txt`. The ordinary launcher has no local-target exception.

## Architecture and API

See [architecture and safety boundaries](docs/architecture.md). API actions use
`Authorization: Bearer <local token>` and JSON. Main endpoints: `/api/challenges`,
`/api/challenges/{id}/verify`, `/api/scans`, `/api/scans/{id}/report`,
`/api/scans/{id}/report.html`, `/api/scans/{id}/report.pdf`,
`/api/scans/{id}/cancel`, `/api/targets/revoke` and `/api/targets/recover`.
Authenticated `DELETE /api/data` removes the operator's grants, jobs and results.

Plugins are trusted installed Python code with metadata and an async contract.
New packages may register a factory in the `racs.checks` entry-point group without
changing the engine. There is no plugin upload or remote code loader. Built-ins
are separate modules under `src/racs/checks`.

## License

MIT. See [LICENSE](LICENSE).
