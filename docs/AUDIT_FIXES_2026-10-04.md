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

## Follow-up: Indexer-only telemetry and refresh continuity

Screenshots after deployment exposed an Overview display that ignored a successful Indexer connection and a forced analytics refresh that unmounted the active view. Freshness output now exposes the Indexer independently, with measured alert and completed-window counts. Manager agent coverage and Indexer alert telemetry have separate labels; unconfigured Manager/IAM connections do not imply zero agents or measured zero MFA. Disconnecting the Indexer clears its successful status.

The current assessment stays mounted during refresh, with a visible refresh notice. Sync phases identify Manager, Indexer, IAM and threat-intelligence retrieval. Completion or partial-failure feedback survives the analytics refresh and remains visible until the next sync. A forced refresh requested during an existing fetch runs afterwards so a mutation cannot silently retain an earlier summary.

Validation: 31 relevant backend tests passed, including independent Indexer freshness and disconnect lifecycle checks; four frontend request tests and the production build passed. Chrome DOM checks used controlled Indexer-only and partial-feed-failure fixtures, paused the summary response during refresh, verified that the Overview and feedback remained visible, and checked a 390-pixel viewport. No browser page errors occurred. Personal connector credentials were not used.

## Follow-up: first threat-intelligence refresh

A fresh durable workspace has no saved `intel_cursor`. The detached worker staged that missing document as `null`, and enrichment attempted to read its dictionary fields. This caused an `AttributeError` before enrichment and produced the generic threat-intelligence failure during an otherwise successful telemetry sync. A new isolated guest on the deployed backend reproduced the same warning before the fix.

The worker now initializes the missing cursor, and enrichment also tolerates a legacy null cursor. Unexpected enrichment exceptions are logged internally while retaining the safe public error message. Existing connector results and measurements remain independent of the intelligence refresh.

Validation: **34 relevant backend tests passed**. Regression checks use actual background jobs for both intelligence-only and combined sync, verify first and repeated sync in a fresh workspace, and verify continuation through 30 controlled CVEs with an empty or null cursor. External feed unavailability still reports its actual degraded/failed status; this fix does not guarantee upstream availability.

The hosted verification then exposed a second issue: the legacy CISA `/files/json/` catalog URL returns HTTP 404. The current `/files/feeds/` URL returned HTTP 200 with 1,733 catalog entries during verification. The connector now uses that current URL, with the [CISA-maintained GitHub catalog](https://github.com/cisagov/kev-data) as a bounded fallback. Responses must contain a valid nonempty vulnerability list before replacing the cache; cached and enriched records retain the actual source URL.

Combined validation: **49 tests passed**, including primary feed HTTP errors, timeout, invalid catalog, official mirror recovery, cache provenance, offline fallback and the background-job checks above. A direct connector check downloaded the real current catalog successfully. This checks retrieval behavior, not the truth of any particular finding on an uploaded asset.

## Follow-up: complete OpenVAS CVE references and sync counts

Overview sync enriches findings already imported into the workspace; it does not run a new vulnerability scan or retrieve the Wazuh vulnerability inventory. The OpenVAS importer previously retained only the first CVE in a result. The earlier audit's 21-CVE figure counted retained primary identifiers, not all references in the source file. The unchanged `many_vuln.xml` actually has **44 result rows and 46 distinct referenced CVEs**.

XML intake now collects all direct CVE tags, CVE references and cross-references; CSV and JSON intake also retain all distinct valid identifiers. Each CVE occurrence becomes a canonical finding with the original scan attributes. Rows without a CVE remain non-CVE findings. Distinct named non-CVE findings on the same asset and port no longer overwrite each other. Finding IDs remain unique when re-uploading into a legacy workspace, and existing matching IDs stay stable. Missing references discarded by earlier imports require re-uploading the report; sync cannot reconstruct them from the truncated stored data.

The unchanged file now produces **76 distinct findings, including 46 unique CVE identifiers**, with no skipped rows. The extra finding count reflects multiple CVE references per scan result and the restoration of previously collapsed non-CVE findings. Repeat upload preserves that count and unique finding IDs.

Ingestion shows the imported unique-CVE total separately from the number of available EPSS scores. Combined sync returns total, queried and pending CVE counts, and Overview distinguishes a healthy unfinished batch from an upstream failure. A batch checks at most 25 CVEs within the existing time limit. For 46 imported identifiers, the controlled test checks 25 with 21 pending, then checks the remaining 21 with zero pending. The imported total stays 46 throughout; actual network deadlines can yield smaller batches.

Validation: **43 backend tests passed**, covering parser formats, complete reference extraction, repeat upload, legacy merge/ID collisions, real background sync continuation, risk integrity and deterministic calculations. Three background-job checks passed again after the response cleanup. Four frontend request tests and the production build passed. Chrome DOM used the unchanged XML and actual local API jobs with explicitly controlled external-feed responses and declared business assumptions. It verified both sync batches, the separate imported/EPSS counts, and a 390-pixel viewport with no browser page errors. Personal saved connectors and credentials were not used.

## Follow-up: Vendor Wizard Auto Suggest

The structure inspector selected the most frequent XML element. In `many_vuln.xml`, that meant 159 nested reference entries rather than the 44 finding records, leaving only `@id` and `@type` available to the wizard. Auto Suggest therefore filled nothing. Substring matching also allowed unrelated fields such as `Description` to match `ip`.

Inspection now ranks finding records by their mappable asset, severity and CVE/issue fields before considering frequency. The backend suggests mappings using whole field names and sampled values, including camel-case names, repeated CVE reference attributes, nested JSON envelopes, namespace-qualified XML, and CSV headers with whitespace or a UTF-8 BOM. The generic connector reads the same paths and retains every valid CVE rather than only the first. Zero severity remains a valid informational rating.

The button displays which required fields were matched or still need manual selection. Configuration reports select non-CVE mode when appropriate. Issue/check mapping is visible for mixed reports as well. Changing a mapping invalidates its preview; a failed replacement upload cannot reuse the previous file's inspection.

Validation: **31 relevant backend tests passed**, including inspect, preview, save and subsequent ingestion against an isolated workspace. Four frontend request tests and the production build passed. Chrome DOM exercised the full wizard with the unchanged XML, CSV and nested configuration JSON, including re-suggestion after manual changes, preview invalidation, saving, ambiguous fields and an empty replacement file. No browser page errors occurred. The generic wizard preserves all **46 referenced CVEs** from the sample; it explicitly skips **two rows without the required severity**, yielding 74 findings. This differs from the built-in OpenVAS import, which supports that scanner's severity fallback and imports 76 findings. Personal credentials and saved connectors were not accessed.

## Follow-up: AI-assisted vendor mapping

The wizard now offers **Suggest with AI**, which calls the model saved in the current workspace's existing AI Model Settings. Ordinary upload still applies field matches without a provider call, and **Use field matches** remains available. The AI settings dialog is accessible within the wizard. Successful suggestions identify the provider and model; missing configuration and failed or invalid model responses are reported without labeling a rule-based fallback as AI.

The AI request contains the inspected field paths, types and aggregate coverage/semantic counts, not sample values, finding descriptions, hosts, request bodies or credentials. A bounded, user-triggered completion returns a structured field mapping. Each proposed path must occur in the actual export; observed CVE, severity and numeric-score properties are validated before applying the result. Containers, invented paths, unsupported canonical keys and CVSS vectors used as numeric scores are rejected. Preview remains mandatory before saving.

The non-CVE toggle now describes findings without CVE identifiers instead of assuming every such export is a configuration scanner. Generic parsing recognizes the information severity used in the Detectify sample, skips unsupported severity values explicitly, and treats out-of-range CVSS values as unavailable.

Validation: **39 relevant backend tests passed**, including workspace-scoped model configuration, prompt data minimization, invalid model outputs, provider failure, and the existing provider SDK with controlled HTTP completion transport. Four frontend request tests and the production build passed. Chrome DOM used the uploaded Detectify JSON and real local workspace/API flow with explicitly controlled provider responses. It verified model setup, nested CVSS/reference mapping, preview, removal of AI attribution when switching to field matches, rejection of invalid model output, and a 390-pixel viewport with no browser page errors. These checks do not claim a live paid model call; personal API keys were not used.

## Follow-up: one Wazuh integration

Connectors now presents one **Wazuh — Agents & Alerts** card with shared configure, test, save and disconnect actions. Agent status and alert telemetry each retain their own connection status and feedback. Both services can be configured together, or either can be used alone. Existing saved Manager and Indexer settings are loaded through the existing API; no credential migration or backend changes are required. Manager status still comes from the Manager API, and alerts still come from the Indexer, using their respective endpoints and credentials.

Saves run sequentially against the shared credential store. A partial failure preserves the successful service and leaves the failed service editable; retry saves only the failed service. Blank saved passwords retain the existing backend behavior. Cancel clears unsaved passwords. Shared controls are disabled during operations, and disconnect reports individual failures rather than claiming the whole integration was removed.

Validation: **nine Chrome DOM checks passed** with controlled connection API responses, covering existing Indexer-only settings, shared tests with distinct credentials, partial saves and retry, password retention, cancellation, preventing silent clearing of saved endpoints, partial disconnect and retry, standalone Indexer configuration, shared refresh, and a 390-pixel viewport without horizontal overflow or page errors. Four frontend request tests and the production build passed. No personal saved connectors or credentials were used in validation; controlled responses do not claim a live Wazuh connectivity test. The existing large frontend bundle warning remains.
