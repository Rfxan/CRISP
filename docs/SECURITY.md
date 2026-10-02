# Public demo security

Hosted Render/Vercel instances are public read-only demos. Production cannot
enable local editing through an environment variable. The API uses an explicit
allowlist: analytics, compliance exports, health, capabilities, and bounded
counterfactual simulation/optimization are public. All other routes are denied,
including uploads, reset/seed, asset/control changes, raw snapshots, audit logs,
connection settings/tests, AI configuration, and paid AI calls. Public requests
roll back workspace changes; the UI hides administration and saved edits.

Local development retains editing for preparing data. Do not expose a
development-mode API to the internet. This change does not implement private
enterprise authentication or tenant membership; those are required before
offering a private dashboard. Never publish confidential business/telemetry data
in a public demo. The current empty dataset is retained, not auto-seeded.

## Request limits

Rate counters are stored in PostgreSQL on hosted deployments, with atomic
updates across processes/instances. SQLite implements the same contract locally;
development may use in-memory counters. Expired counters are removed and only
hashed peer identifiers are retained. Quotas use fixed one-minute windows:

| Environment variable | Default | Scope |
| --- | ---: | --- |
| `CRISP_RATE_GLOBAL` | 600 | All non-health requests |
| `CRISP_RATE_PEER` | 120 | Each server-observed peer |
| `CRISP_RATE_COMPUTE_GLOBAL` | 20 | Expensive requests across peers |
| `CRISP_RATE_COMPUTE_PEER` | 6 | Expensive requests for each peer |

Expensive requests include simulations, optimization, sensitivity, Pareto,
forced recomputations, and local mutations. Rate rejection returns `429` and
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
processed concurrently per API process; Uvicorn also caps concurrent connections
and disables untrusted proxy headers and its version header. These are request
limits, not hard CPU execution deadlines for numerical models.

## Integration security

Credential-bearing Wazuh/Keycloak and LLM requests verify TLS certificates and
do not follow redirects. Production requires HTTPS and an exact server-managed
origin allowlist for custom integrations:

```text
CRISP_OUTBOUND_ORIGINS=https://YOUR-WAZUH-HOST:55000,https://YOUR-IAM-HOST
```

Known LLM provider origins are allowed for provider calls; public AI routes are
blocked. Private integration addresses additionally require
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
the remaining lower-severity findings were reviewed as described below.

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
