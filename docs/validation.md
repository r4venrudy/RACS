# Validation record

The deterministic practice application in `tests/practice/server.py` contains
independently implemented vulnerable and protected routes. It runs only on
127.0.0.1:9443 with a generated TLS certificate and is never packaged into RACS.
Tests provision a real HTTPS proof file, verify ownership through the pinned
transport, and then call the same check implementations used by the worker.

| Check | Vulnerable control | Safe / negative controls |
| --- | --- | --- |
| Headers | HTML without policy headers | HTML with CSP/frame-ancestors, nosniff and HSTS; multiple CSP headers |
| Reflected XSS | Unescaped server-rendered input; two browser marker executions | HTML escaping, enforcing script-src none, JSON reflection, resource-dependent replay |
| SQL indicators | SQLite string-interpolated read-only SELECT | Parameter-bound SELECT, unstable results; structured-array requirement |
| IDOR | Known synthetic object returned to the wrong verified principal | Ownership-filtered 403, ID-only echo, absent identity/object keys, invalid/private-marker controls |

The full worker test confirms seven expected findings (four header observations
plus XSS, SQL indicator and access-control disclosure), all with confidence and
remediation, and verifies HTML/PDF exports. Other tests cover scope validation,
DNS rebinding prevention, bounded bodies, revocation, request cancellation,
persistent distress stops, migrations, queue limits, redaction and report escaping.
The Chromium tests run only with `--run-practice`; the default suite reports these
as skipped, not as passed. CI explicitly installs Chromium and runs them.

## Additional OWASP Juice Shop check

Local validation also uses official OWASP Juice Shop v20.3.0, Windows Node24 build.
Pinned archive SHA256:
`a25fc33b3b3565aae52381f63e6c9727790f67e8443ead02803a8eec7bdb7f57`.
It is kept outside Git, restricted to loopback and accessed through the TLS practice
bridge, which permits only its root and product-search endpoints. The bridge
neither follows redirects nor uses environment proxies. No public Juice Shop
instance is scanned.

Search baseline `Apple` at `/rest/products/search`, with the owner-declared `like`
context, is compared against repeated AND-only predicates. True preserves the
baseline result set, false yields an empty array, and a benign invalid control is
empty. No extra rows, schema metadata, writes, delays or OR/UNION payloads are used.
The headers test must not flag Juice Shop's existing nosniff or framing headers.
HSTS observations concern the local TLS bridge, not Juice Shop's internal HTTP.

Juice Shop's tracking XSS needs Angular to render JSON as HTML. This release does
not claim to detect that DOM-dependent case; the directly server-rendered practice
XSS pair establishes the implemented reflected-XSS capability.

Sources: [official installation guide](https://pwning.owasp-juice.shop/companion-guide/latest/part1/running.html),
[pinned release](https://github.com/juice-shop/juice-shop/releases/tag/v20.3.0),
[search implementation](https://github.com/juice-shop/juice-shop/blob/v20.3.0/routes/search.ts).
