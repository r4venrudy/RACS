# Foundation and safety boundary

Step 1 is an ownership service and queue foundation, not a vulnerability scanner.
The application has no installed checks. Accepted sessions are persisted and end
as `not_performed`; this never means the target is safe.

## Trust and scope

The operator is identified by a SHA-256 digest of a random local bearer token.
Processes that can read the private runtime token have the operator's privileges.
This is a single-user local application, not a hosted multi-tenant service.

Only ASCII DNS hostnames and HTTPS on port 443 are accepted. International names
must use IDNA form. Scope is the exact canonical origin and root path `/` only
for the future first check. The well-known file is a separate fixed verification
endpoint. No subdomains, arbitrary paths, credentials, query strings, fragments,
IP literals or redirects are authorized. Shared-hosting users who cannot prove
control of that origin cannot authorize a subdirectory.

Challenges have 256 random bits, a ten-minute lifetime, and an operator, origin
and method binding. Only their SHA-256 digest is stored. DNS proofs use
`_racs-verify.<hostname>`; HTTPS proofs use `/.well-known/racs-verify.txt`.
Proofs match exactly, allowing surrounding whitespace in HTTPS files. Success
consumes the challenge and grants 24 hours. Reverification replaces the grant
generation, so old jobs cannot revive. Revocation deletes grants and challenges
and cancels active jobs.

Both proof methods validate every A/AAAA result. DNS uses the machine's configured
recursive resolver with search suffixes disabled, never target-supplied DNS
servers. The resolver and system certificate store are trusted infrastructure.
DNSSEC validation is not implemented. HTTPS connects to a validated numeric IP
with the original hostname for SNI/certificate verification, then checks the
connected peer. No second DNS lookup, environment proxy, redirect follow, cookie,
authentication forwarding or retry is used. DNS errors fail closed. Non-public,
reserved, multicast, mapped and common IPv6 transition/translation addresses are
rejected. Custom routing and transparent interception remain outside this trust
boundary.

Verification has two concurrent slots, a ten-second network deadline,
three-second DNS deadlines, a four-second TLS handshake limit, a 4 KiB body cap,
a 64 KiB wire cap, and a 16 KiB incomplete-header cap. Compression is rejected.
Five attempts per challenge and one attempt per target per ten seconds are
allowed. At most 128 pending challenges and 32 active scan sessions are stored.

## Storage and lifecycle

SQLite schema version 1 is initialized transactionally with `user_version`;
unknown versions fail closed. Short `BEGIN IMMEDIATE` transactions and a
five-second busy timeout serialize queue checks and claims. Network operations
never hold database transactions. The launcher takes an OS file lock and starts
one worker. Do not deploy the app factory through a separate multi-worker server
or put its runtime database on a network/synchronized drive.

Transitions are queued to running to not_performed in Step 1, or cancelled by
the operator, expiry, replaced proof or revocation. Startup marks previously
running jobs interrupted. Queued jobs survive restarts and are rechecked at claim.
Completion cannot overwrite cancellation. Models reserve failed/completed for
future execution.

Expired challenges are cleaned on issue. Session history stays local until
`DELETE /api/data` deletes the operator's sessions, grants and challenges. The
non-secret per-origin throttle remains to prevent purge/retry abuse. This is
logical deletion, not secure erasure of database free pages or backups. Response
evidence and plaintext challenge tokens are not persisted in this stage.

## Plugins and future execution

Plugins are trusted installed Python code with metadata and an async
`run(context)` contract. There is no remote discovery, code loading or upload.
`Finding` rejects extra fields and requires severity, confidence, rationale,
verification status, affected URL/parameter, bounded evidence, reproduction,
remediation and a sample fix. Confidence labels are not probabilities.

`TrafficPolicy` is tested scaffolding for future root-only requests: shared
per-origin locking, two global slots, two-second spacing, ten-second requests,
authorization checks, no retries, a stop on 429/5xx, and a stop after three network
failures. It is **not wired to the Step 1 worker**. A hard stop on 429 is stricter
than waiting for Retry-After: no more traffic is attempted. Stops are in-process.
Before installing checks, add a complete scan deadline, active socket cancellation
on revocation, persisted distress stops, bounded finding persistence/deduplication,
and explicit safe-route controls. GET alone does not prove safety. The current
worker sends no scan traffic.

## API and later reports

The launcher binds only 127.0.0.1. Mutations require a bearer token and JSON;
Host/Origin are allowlisted, cross-site requests rejected and CORS disabled.
Bodies are capped at 8 KiB with a five-second deadline. Homepage/health expose
only public status. Tokens never appear in URLs, cookies, frontend HTML or logs.
Proxy forwarding headers are disabled. Keep the runtime directory private using
normal user-profile filesystem permissions.

HTML/PDF reports and the category UI are later stages. Escape all findings in
HTML; prohibit PDF local-file and remote-resource fetching. Add evidence redaction
and retention before storing target responses. Reflection, errors, HTTP status or
missing headers alone must not be described as exploitable vulnerabilities.
