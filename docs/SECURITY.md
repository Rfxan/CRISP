# Public demo security

Hosted Render/Vercel instances default to public interactive sandboxes. A signed,
encrypted, Secure/HttpOnly/SameSite=Strict cookie selects a randomly generated
browser workspace, never the owner's local workspace. Each browser can upload
data, edit assets/controls, configure its own integrations and run scenarios.
Cookies and data expire after 24 hours; expired documents are removed when the
next rate-limited request arrives. Mutation audit records remain append-only.
Origin checks reject cross-site writes. Tenant selection headers are ignored.

Each workspace starts empty. The Ingestion screen offers an explicit synthetic
sample dataset button for evaluation. Workspaces allow up to 200 assets and 500
findings; public guest workspaces do not run background sync jobs. Integration
sync is on demand and uses only that browser's saved credentials. Server API
keys and connector passwords are not available to guests. AI uses structured
deterministic responses unless the visitor supplies their own provider key.

Set `CRISP_ACCESS_MODE=public_demo` to retain the optional read-only allowlist
policy. The interactive mode is `public_sandbox`; it never enables shared local
editing in production. Anonymous workspace isolation is not enterprise login
or tenant membership. Use demonstration data; private enterprise dashboards
need authenticated access. Clearing cookies loses access to the workspace.

## Request limits

Rate counters are stored in PostgreSQL on hosted deployments, with atomic
updates across processes/instances. SQLite implements the same contract locally;
development may use in-memory counters. Expired counters are removed and only
hashed peer identifiers are retained. Quotas use fixed one-minute windows:

| Environment variable | Default | Scope |
| --- | ---: | --- |
| `CRISP_RATE_GLOBAL` | 600 | All non-health requests |
| `CRISP_RATE_PEER` | 120 | Each server-observed peer |
| `CRISP_RATE_COMPUTE_GLOBAL` | 40 | Expensive requests across peers |
| `CRISP_RATE_COMPUTE_PEER` | 20 | Expensive requests for each peer |

Expensive requests include simulations, optimization, sensitivity, Pareto,
forced recomputations, and mutations. Rate rejection returns `429` and
`Retry-After`. Quota storage failure returns `503`; it does not silently disable
protection. Health remains available without opening a database connection.

Raw forwarding headers are not trusted for peer identity. Render/Vercel proxy
connections can share a peer quota. This conservative default avoids spoofed
headers but can limit multiple legitimate visitors together. Fixed windows can
permit bursts across a window boundary. A trusted edge rate limiter/WAF is still
needed for volumetric denial-of-service protection and accurate visitor quotas.

Middleware accepts at most 512 KiB of JSON or 10 MiB of multipart data, including
chunked requests without Content-Length, and times out body receipt after 15
seconds. Compressed bodies are rejected. At most eight non-health requests are
processed concurrently per API process, with two concurrent expensive requests;
Uvicorn also caps concurrent connections
and disables untrusted proxy headers and its version header. These are request
limits, not hard CPU execution deadlines for numerical models.

## Integration security

Credential-bearing Wazuh/Keycloak and LLM requests verify TLS certificates and
do not follow redirects. Production requires HTTPS and an exact server-managed
origin allowlist for custom integrations:

```text
CRISP_OUTBOUND_ORIGINS=https://YOUR-WAZUH-HOST:55000,https://YOUR-IAM-HOST
```

Known LLM provider origins are allowed for visitor-configured provider calls.
Private integration addresses additionally require
`CRISP_ALLOW_PRIVATE_OUTBOUND=1`. Loopback, link-local/metadata, multicast,
reserved, and unspecified addresses remain forbidden. Self-signed integrations
must use `CRISP_INTEGRATION_CA_BUNDLE` pointing to a trusted CA file installed on
the server. Certificate checks are never disabled. Laptop localhost URLs cannot
be used by the deployed service. A network egress firewall is recommended as an
additional boundary, especially against DNS changes after validation.

## Additional safeguards

* XML imports use `defusedxml`, rejecting declared entities.
* CSV evidence exports neutralize spreadsheet formulas; HTML reports escape
  imported text.
* Validation errors omit submitted secret values. Server/upstream failures use
  generic messages, and Gemini API keys are sent in headers rather than URLs.
* Vercel serves a Content Security Policy restricting scripts/connections to
  the same origin, with explicit Google font sources. Inline styles are retained
  for the existing React UI. API responses have a separate restrictive policy.
* Framing is denied; MIME sniffing, unnecessary browser permissions, caching of
  API responses, and insecure production transport are restricted by headers.
* The backend container runs as an unprivileged user. Persistent encryption keys
  and hosted PostgreSQL remain required. No credentials belong in frontend code.
* GitHub Actions runs dependency audits, high-severity static analysis, frontend
  builds, and backend tests on pushes/PRs and weekly. Actions are pinned to commit
  hashes and use read-only repository permissions. Passing checks are not proof
  that every vulnerability is absent.

## Verification and remaining limits

Validated on 2026-10-02: 108 backend tests passed; four isolated PostgreSQL
integration tests skipped without a test database. The frontend production
build and both Vercel configuration schemas passed. npm audits (root and
frontend) and the resolved Python runtime requirements audit reported zero
known vulnerabilities. Static analysis reported no high-severity findings;
the remaining lower-severity findings were reviewed as described below. A
subsequent focused run covers all 13 security tests, including local API docs
compatibility; production API docs remain disabled.

Tests cover default-deny administration, read-only persistence, concurrent shared
quotas, spoofed forwarding headers, global quotas, fail-closed protection,
streaming upload limits, error redaction, integration allowlisting/TLS/redirects,
XML entity rejection, and spreadsheet export safety. PostgreSQL integration
tests require an isolated `CRISP_TEST_DATABASE_URL` and skip without one.

Dependency audits report known advisories as of the run date; they cannot detect
unknown flaws. Static analysis was reviewed for intentional container binding,
non-security simulation randomness, XML element type imports, and legacy
fallback handling. No blanket claim of an unhackable website is made. Cloud
account MFA, provider firewall rules, secret rotation, monitoring, database
backups/lifetime, and independent security testing remain operational tasks.

References: [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html),
[OWASP secure review](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html).
