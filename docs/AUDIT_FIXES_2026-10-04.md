# CRISP audit fixes — 4 October 2026

This report records the fixes and local verification for the 14 findings in the 3–4 October platform audit. The frontend and backend changes must be deployed together; the local validation below does not certify the hosted deployments.

| Finding | Change | Verification |
| --- | --- | --- |
| F01 — Service identity and inventory corruption | Canonical `id` and compatible `service_id` aliases; legacy duplicate normalization; CSV and CRUD resolve the same service. Deleting an asset preserves independent business services and their dependency/financial context. | Seed → add → update → delete restores the original service records and EAL. CSV ingestion after seed succeeds. |
| F02 — Sparse expected shortfall | Tail loss is the weighted mean of the worst 5% of simulated years, including fractional boundary observations and ties. | 960 zeros plus 40 losses of 1,000 produces EAL 40, VaR95 0 and expected shortfall 800. Constant and fractional-tail cases tested. |
| F03 — Exceedance curve | Unique numeric thresholds carry empirical `P(loss > threshold)`. Overview and scenario charts use numeric axes and step curves; scenario curves share numeric thresholds. | Zero threshold probability is 4% in the sparse fixture; no duplicate contradictory thresholds; deterministic bounded curve checks pass. |
| F04 — Failed saved connectors and sync feedback | Saved endpoints are retried even after a failed check. Connector outcomes update their saved status. Overall sync reports degradation. Last successful Manager measurements and success timestamps remain available separately from failed attempts. | Saved failed connection actually attempts retrieval and reports failure rather than `NOT_CONFIGURED`. Historical success timestamp and measurements are preserved. |
| F05 — Feed freshness and false success | Per-feed live/cached/stale/unavailable counts determine the outcome. Queried CVEs and changed records are separate counts. Unavailable KEV retrieval does not erase previous membership; missing EPSS is not invented. | Controlled feed failure reports `FAILED`/error, with unavailable provenance. UI displays partial outcomes and actual counts. |
| F06 — Overlapping calculations | Browser requests serialize, duplicate read/simulation/optimization effects share requests, and bounded retries honor `Retry-After` for 429/503. Existing backend request quotas and capacity limits remain enabled. | Request tests cover serialization, independent response bodies, failure recovery and exactly three attempts. DOM test injects 503s and verifies recovery. |
| F07 — Network requests under a database lock | Durable tenant-scoped background jobs retrieve into detached state outside the DB lock, then commit briefly. Concurrent workspace or credential changes supersede the result. API sync routes and the scheduled worker use the same job machinery. | Normal tenant reads complete while retrieval is blocked. Cross-tenant job lookup returns 404. Concurrent edits and cancellation prevent stale results from being applied. |
| F08 — Backup control mismatch | Scenario choices come from the controls catalog, including `CTRL-BKP-01`. | DOM shows all 16 catalog controls and verifies a successful backup simulation response containing that exact target. |
| F09 — Unverified “Real Lab” claims | Assets have explicit manual/uploaded/synthetic/unknown origins; uploads and declarations do not certify a lab. Header and data-quality output distinguish declared context and synthetic data. | Real XML upload is labeled uploaded; legacy flags cannot automatically claim verification. |
| F10 — Mobile overflow | Responsive navigation, shrinking grids, wrapping headers and contained tables. | Every one of the eight views has document width 390 at viewport width 390, using populated XML data. |
| F11 — Keyboard controls | Sidebar, scenario cards and provider cards are native buttons; selected states and visible focus are exposed. Budget responds to keyboard changes; key forms have accessible labels. | Keyboard Enter opens a sidebar section. Native control semantics and catalog selection verified in DOM. This is not a full accessibility certification. |
| F12 — Generic API errors | Shared request handling retains safe server/field details, HTTP status and retry information. Safe domain validation messages are returned in production. Requests have a deadline covering response-body retrieval. | Validation and busy-response tests; existing production security/error-redaction tests pass. |
| F13 — Misreported scan serialization | OpenVAS-compatible CSV, JSON and XML are reported as distinct detected formats while retaining the matching parser. | Scan intake/parser suite and actual XML ingestion pass. |
| F14 — Pending optimizer results | Visible calculating state replaces fabricated zeros. Previous completed results are identified during budget updates. Stale responses cannot replace newer results; Pareto failures have visible retry controls. | DOM verifies calculating → completed portfolio, injected Pareto failure → visible error → successful retry. |

## Validation results

- Backend: **165 passed, 4 skipped, 0 failed**, approximately 225 seconds. Tests ran in a disposable source/data copy, excluding personal credentials and deployment state.
- Skipped tests require `CRISP_TEST_POSTGRES_URL`: PostgreSQL persistence/rollback/isolation, append-only audit, concurrent processes/worker deduplication, and API persistence across clients.
- Frontend request tests: **4 passed**, using Node's built-in test runner (`npm test` in `frontend`).
- Production frontend build: passed. The existing approximately 864 KB JavaScript bundle warning remains a performance consideration, not a build failure.
- npm audit: **0 known dependency vulnerabilities** reported during this verification.
- Chrome DOM: user's `many_vuln.xml` imported as **33 distinct findings** and one asset. Financial context was a separately uploaded, explicitly controlled test assumption. Eight populated views, loading/retry states, backup simulation, keyboard navigation and connector refresh were checked. **No browser page errors** were recorded.

The original failed first-pass checks were a disposable-copy documentation omission and an old test that required exactly 50 percentile points. The documentation was copied into the test environment and the curve assertion was updated to validate the new unique, bounded, deterministic empirical curve. The full suite was then rerun successfully.

## Sync contract and limits

Start a job with `POST /api/sync/jobs?kind=all|connections|intel|wazuh|indexer|iam`. The response is HTTP 202 with a job ID. Poll `GET /api/sync/jobs/{id}`; cancel with `DELETE /api/sync/jobs/{id}`. These routes are scoped to the requesting workspace. Legacy HTTP sync routes now enqueue jobs when durable workspace storage is active; internal function calls remain reusable.

Two workers and four admitted jobs per process bound concurrent work. One active job per workspace prevents competing syncs. Restarted/interrupted jobs become a visible failure after their stale-job deadline; they are not silently reported as successful. Retrieval has a 180-second budget and processes at most 25 CVEs per batch. Pending CVEs are reported; a persisted cursor continues the next batch instead of repeating the first CVEs. Cancellation prevents application of results, although an already-running external HTTP call may finish before it observes cancellation.

Snapshot and credential comparisons before commit protect concurrent user edits. A superseded result asks the user to sync again rather than overwriting their new input. Connector checks still enforce existing public HTTPS, certificate, address-validation and credential-encryption protections. No SIEM hostname or password was hardcoded.

The loss engine version is now `crisp-risk-2.1`, which invalidates cached calculations from the earlier formulas. Financial outputs remain planning estimates with configurable assumptions, not empirically calibrated forecasts.

Successful authentication against real SIEM/IAM services and paid model providers was not retested using personal credentials. Upstream failure and lock/concurrency checks used controlled responses. These fixes resolve the reproduced audit findings; they do not establish that every possible security flaw or operating condition has been eliminated.
