# Safety architecture

RACS is a single-user local tool. Its random bearer token identifies the operator;
any local process able to read it has equivalent authority. The launcher binds to
loopback, disables forwarded headers and takes an OS file lock. The API checks
Host/Origin, rejects cross-site requests, requires JSON and limits request bodies
to 8 KiB / five seconds. It provides no public-host deployment mode.

## Ownership and outbound requests

A 256-bit challenge is bound to the operator, exact canonical HTTPS origin and
proof method. Only its SHA-256 digest is stored. Challenges expire in ten minutes,
allow five attempts and are consumed after success. Per-origin proof attempts
are spaced by ten seconds. Grants expire in 24 hours; replacing a grant invalidates
old queued jobs. Revocation cancels jobs and removes pending proofs.

Production scope is an exact DNS host/HTTPS/443 origin plus explicitly declared
read-only paths. No implicit subdomains, redirects, credentials-in-URLs, queries
in paths, traversal, encoded paths or common state-changing route names are accepted.
GET alone is not considered safe; the owner must confirm the route semantics.

Both proof methods validate every A/AAAA address. HTTPS connects to one approved
numeric address, preserves the original TLS hostname, validates certificates and
checks the actual peer. No second resolution, environment proxy, redirect follow,
cookie jar or retry is used. Non-public/reserved/multicast and common IPv6 mapped,
transition and translation addresses are denied. DNS uses the system recursive
resolver with search suffixes disabled. DNSSEC is not implemented. OS routing,
trust stores and recursive resolvers are trusted infrastructure.

The optional CLI-only local practice allowance recognizes exactly
`racs-lab.localhost:9443`, pins it to 127.0.0.1 and uses an explicitly supplied CA.
It requires ordinary HTTPS ownership proof and does not authorize any other private
host or port. The API cannot enable this exception. Default startup rejects it.

## Execution and persistence

SQLite schema version 2 migrates version 1 in place. Parameterized, short immediate
transactions and a five-second busy timeout serialize queue and grant updates.
No network request holds a transaction. Unknown schema versions fail closed.
The persistent queue allows 32 active jobs. The single worker rechecks grants when
claiming and before/after every request, and polls active requests every 50 ms for
expiry/revocation/cancellation. Closing the task closes its socket. Restart marks
running jobs interrupted; old queued jobs remain ownership-gated.

Each scan allows 180 seconds and 96 requests, with two outbound slots and at least
one second between successive per-origin responses/requests. Locks aggregate
across sessions. Requests have a ten-second deadline and 256 KiB body limit;
proofs use 4 KiB. HTTP parsing and wire limits are bounded; compression is rejected.
429/5xx latches a persistent target distress stop; three transport failures do too.
A 429 causes a hard stop, so no request is retried before Retry-After. Recovery must
be explicitly acknowledged by a verified operator. Browser replay is also bounded.

Credentials supplied for IDOR stay in a memory-only per-job vault; they are removed
on execution, cancellation, revocation, expiry or shutdown. They are never saved
in the scan plan. After restart, credential-dependent checks are not performed
unless credentials are supplied in a new job. Synthetic object metadata is stored
in the plan; do not use personal or production data as test markers.

Each check produces a bounded validated outcome and strict findings. Deterministic
finding IDs include type, URL and parameter; distinct endpoints remain distinct.
Results are saved per check, so interrupted sessions retain earlier evidence and
report missing checks explicitly. Secrets are redacted again before persistence.
No captured body, cookie, bearer token or plaintext ownership proof is stored.

`DELETE /api/data` removes jobs/results/grants/challenges for the local operator.
Throttle/distress state remains to prevent delete/retry abuse. This is logical
deletion, not secure erasure of SQLite free pages or external backups.

## Confidence and reports

Headers are repeated configuration observations. XSS requires two fresh execution
markers in dependency-free HTML replay; original CSP is preserved. Chromium uses
its sandbox, a fresh credential-free context, no service workers/downloads/popups,
blocked HTTP/WebSocket routes, a dead local proxy and disabled direct WebRTC UDP.
Additional CSP restricts frames, workers and connections. Resource dependencies
and script errors invalidate the proof. This deliberately sacrifices coverage for
confidence; it is not full equivalence to arbitrary live application execution.

SQL results require stable JSON arrays and independently repeated AND-only
true/false controls. Even a repeatable differential is labelled an indicator:
HTTP cannot establish the database implementation. IDOR needs independently
verified identities, explicit forbidden access expectations, an exact known object
and a separate private marker never sent in the request. There is no enumeration.

HTML is escaped, UI rendering uses textContent, and PDF generation uses only
ReportLab text primitives. Reports cannot load local files or remote resources.
Tokens are not placed in URLs or persisted in browser storage. Exported documents
contain scope, outcome limitations, confidence, evidence, reproduction and fixes.

Plugins run as trusted installed code; Python is not a sandbox. No upload or
remote discovery is allowed. Core policy is the supported path for all traffic.
