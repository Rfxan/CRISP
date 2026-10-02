**CRISP functional and hardcoded-data audit — 30 September 2026**

**Verdict: the existing test suite passes, but the application does not pass the expanded behavioral audit. Hardcoded assumptions, demo fixtures, and fabricated fallback evidence remain.** Application source was reviewed and tested as found, including the user's existing uncommitted changes. No application fixes were made.

**Executed checks**

| Check | Result | Evidence |
| --- | --- | --- |
| Existing backend suite | 64 passed, 2 warnings | [pytest output](../scratch/audit_20260930/pytest-output.txt), [JUnit XML](../scratch/audit_20260930/pytest-results.xml) |
| Additional behavioral checks | 30 passed, 19 failed, 49 total | [audit tests](../scratch/audit_20260930/audit_checks.py), [output](../scratch/audit_20260930/audit-output.txt), [JUnit XML](../scratch/audit_20260930/audit-results.xml) |
| Frontend production build | Passed; JavaScript bundle approximately 821 KB uncompressed / 220 KB gzip; bundle-size warning | Built assets under `scratch/audit_20260930/frontend-dist` |
| Headless Edge browser | Landing page, empty dashboard/compliance, all 8 seeded dashboard views, mobile view, and AI API request exercised; no uncaught JavaScript exceptions or HTTP errors during this navigation sequence | [browser results](../scratch/audit_20260930/browser-results.json), [browser harness](../scratch/audit_20260930/browser_smoke.mjs) |
| Additional API diagnostics | Seeded CSV/HTML reports, Pareto, convergence, connection/config views, sync-state, business-unit view and provenance endpoints returned 200 | [diagnostics](../scratch/audit_20260930/diagnostics.json) |
| Docker | Compose configuration validated; frontend image built; backend image build stopped after timeout during dependency downloads. Full container runtime was not verified. | [Docker results](../scratch/audit_20260930/docker-results.json), [backend build log](../scratch/audit_20260930/docker-backend-build.txt), [frontend build log](../scratch/audit_20260930/docker-frontend-build.txt) |

The 19 failed checks are assertions, not 19 independent defects. Several assertions reproduce the same underlying problem in different workflows. Browser navigation success does not establish correctness of displayed financial values or test every button.

Backend tests ran against an isolated copy without live connector credentials or `.env` files. The initial run hit sandbox temporary-file permissions and a missing copied documentation directory. After copying that document and rerunning outside the sandbox, the unchanged existing suite passed. The frontend initially hit esbuild `spawn EPERM`; the permitted rerun passed. These environment failures are excluded from the final application-failure count.

**Confirmed failures, ordered by impact**

| Priority | Finding | Reproduction / observed result | Source |
| --- | --- | --- | --- |
| High | Report evidence can come from demo data rather than the submitted snapshot | Directly generating a SEBI report for an empty snapshot with no controls produced 55 supporting-finding references from the seed fixture. These are references, not 55 distinct findings. | `backend/app/compliance/evidence_report.py:72` |
| High | Missing evidence becomes 60% control coverage | A snapshot with a finding but no control state produced 60% coverage for mapped controls. A missing run ID also becomes `RUN-42-AUDIT`. | `backend/app/compliance/evidence_report.py:93`, `:130` |
| High | Fresh-install report export crashes | `GET /api/compliance/sebi/evidence-report` and `/api/report/sebi` returned 500. Default controls have `coverage_pct=None`, causing `float(None)`. Seeded report exports passed. | `backend/app/compliance/evidence_report.py:130` |
| High | What-if crashes on empty data and after patching the last finding | `POST /api/simulate` returned 500 in both cases. The engine returns absent EAL, then the simulator subtracts `None`. This also prevents replaying the entire recommended ₹1 crore portfolio when it patches all seed findings. | `backend/app/engine/whatif.py:73` |
| High | Optimizer and simulator disagree on identical actions | On the seed snapshot, a ₹10 lakh budget selects five patches. Optimizer reduction: ₹292,394,863.98 (₹29.24 crore). Simulator reduction for those exact finding IDs: ₹549,855,124.35 (₹54.99 crore). | `backend/app/engine/optimizer.py:141`; diagnostics JSON |
| High | Benchmark benefits depend on the strategy name even when actions are identical | With no controls available and enough budget to patch all eight findings, all three strategies spend ₹16 lakh and patch all findings. Reported reductions are ₹27.45 crore (CVSS), ₹33.55 crore (EPSS), and ₹30.50 crore (CRISP). Fixed 45%, 55%, and 50% factors cause the difference. | `backend/app/engine/optimizer.py:298`, `:302` |
| High | Some material changes are invisible to automatic recomputation | Changing internet exposure, service revenue, risk appetite, or scenario TEF leaves the state signature unchanged. Changing appetite from ₹12 crore to ₹1 kept ₹12 crore in the automatic result; forced recalculation showed ₹1. | `backend/app/api/routes.py:419` |
| High | Uploading the same scan twice duplicates findings | The same OpenVAS XML uploaded twice increased active findings from 1 to 2. The ingestion path appends findings; identical technical evidence can be counted repeatedly. | `backend/app/api/routes.py:1314` |
| Medium | CSPM import can create findings without assets | One valid Prowler FAIL finding was accepted, but its resource ARN was absent from the asset inventory. A fresh installation consequently has findings that cannot be quantified until corresponding assets are supplied. | `backend/app/api/routes.py:1902` |
| Medium | Asset risk drilldown is truncated | Seed inventory has 120 assets; `/api/risk/entities?level=asset` returned only 15 and reported 15 as its total. | `backend/app/engine/fair_engine.py:426`, `backend/app/api/routes.py:814` |
| Medium | Invalid requests are accepted | Negative optimizer budget returned 200 instead of validation failure; unsupported simulation action returned 200 as a silent no-op. | `backend/app/api/routes.py:687`, `:691`; `backend/app/engine/whatif.py` |
| Medium | Compliance summary disagrees with its rows | Setting all control coverage to 72% produced a SEBI summary count of 12 compliant controls, while zero rows were marked Compliant. Summary uses 70%, rows use 75%. | `backend/app/compliance/framework_engine.py:67`, `:77` |
| Medium | Documented cost setting does not control actual loss | Increasing `settings.COST_PER_RECORD_INR` tenfold left EAL exactly ₹610,044,096.93. The engine samples literal PERT values instead. | `backend/app/core/config.py:28`, `backend/app/engine/fair_engine.py:275` |

**Hardcoded-data inventory**

| Location | What is fixed | Assessment |
| --- | --- | --- |
| `backend/app/data/seed_snapshot.json` | Fictional organization, 120 assets, 8 findings, 6 services | Appropriate as an explicitly selected fixture. Risky when used implicitly for reports. |
| `backend/app/api/routes.py:369` | Generated anomaly baseline when no SIEM connection exists | Demo source is explicitly labeled. This is synthetic telemetry, not live observations. |
| `backend/app/api/routes.py:1487` and `:1766` | Wazuh/IAM simulated counts | Explicit `simulate=true` paths. Additional tests confirmed default disconnected sync does not invent control coverage. |
| `backend/app/compliance/evidence_report.py:20` | Specific demo asset IDs and CVEs in evidence matching | Evidence correlation is coupled to the sample organization. |
| `backend/app/engine/fair_engine.py:227` | Missing EPSS defaults to 0.2 | A modeling prior, not a fetched observation; should be exposed as such. |
| `backend/app/engine/fair_engine.py:266` | Incident-response costs, per-record costs, penalties, churn and other numeric assumptions | Assumptions are not inherently wrong, but several are embedded in implementation rather than driven by the assumptions ledger. The per-record setting test confirms this disconnect. |
| `backend/app/engine/optimizer.py` | Default patch costs, effectiveness priors, benefit caps, benchmark factors | Directly affect investment recommendations. The benchmark and portfolio tests demonstrate inconsistent results. |
| `backend/app/api/routes.py:824` | Three banking business-unit names selected from service-name/ID heuristics | These are not business units supplied by the organization. |
| `backend/app/api/routes.py:1154` | Fixed data-quality baseline/weights and literal feed-freshness strings | A heuristic readiness score; strings such as `Live FIRST API` are not evidence of successful fresh ingestion. |
| `frontend/src/components/Navbar.jsx:36`, `TechnicalDrilldown.jsx:313` | Apex FinCorp labels | UI remains tied to the sample organization. |
| `frontend/src/components/TechnicalDrilldown.jsx:295` | `OpenVAS Scanner` fallback source label | Risk drivers do not carry source through from findings, so the fallback can mislabel findings imported from other scanners. The displayed “LOO delta reduction” is also a heuristic contribution, not a measured removal-and-rerun delta. |
| `frontend/src/components/DataIngestionHub.jsx:738` | Fallback MFA/EDR implementation and annual costs | Unprovided costs can appear as fixed values; `||` also treats an explicitly supplied zero as missing. |
| `frontend/src/components/ExecutiveView.jsx:380`, `WhatIfSimulator.jsx:135` | “10,000 trials” text | Active snapshot engine is constructed with 5,000 trials in `routes.py:251`; display should use returned run metadata. |
| `backend/tests/test_connections_verification.py:20`, `test_optimizer_benchmark.py:68` | Absolute Ryan-specific local paths | Tests are not fully portable. The standalone verification script is not collected as a test function by pytest. |

No blanket claim of “no hardcoded data” is supportable. Some fixed values are legitimate method parameters and demo fixtures; the critical problems are values that become unearned evidence, misleading live-data labels, or inconsistent financial benefits.

**What did work in the exercised paths**

- Deterministic risk-engine checks, existing optimizer budget checks, anomaly tests, control-state deduplication, deletion tests, and mocked/local-server connector tests passed.
- The additional Nessus upload parsed the supplied CVE correctly; malformed scan input was rejected; unknown framework IDs returned 404.
- Zero-action simulation on populated data produced zero reduction. Tested nonnegative budgets stayed within their spending limits and reported loss-reduction bounds.
- Increasing business record counts increased EAL, demonstrating that the main financial output is calculated from inputs rather than simply a constant dashboard number.
- All six framework exports passed with the seed snapshot. The AI endpoint returned a grounded deterministic fallback response without an LLM key.
- Every dashboard tab rendered in the tested desktop browser session. The mobile screenshot shows a cramped layout with the fixed sidebar consuming much of the screen; mobile usability needs attention.

**Additional implementation concerns observed, not separately certified by the passing checks**

- The risk engine averages the shared threat-intensity samples before Poisson sampling, so the documented shared per-trial incident-frequency correlation is not preserved (`fair_engine.py:246`).
- The sensitivity chart's “Cost Per Breached Record” changes record counts, and its penalty variation also changes record counts; those experiments do not isolate the named parameter (`engine/sensitivity.py`).
- `App.jsx` initially loads dashboard metrics and refreshes through explicit callbacks; it does not subscribe/poll for new risk summaries. A background backend sync does not itself guarantee an updated displayed EAL.
- The active snapshot is in process memory. Starting another `SnapshotStore` starts empty; local connector/history persistence is not durable storage of the uploaded asset/finding snapshot.
- API requests exercised here require no application login, including mutation routes. Authentication, authorization, tenant separation, and production security were not comprehensively audited.
- The backend Dockerfile copies the whole backend directory; the original project has a backend `.env`. The audit build deliberately excluded credentials. Production build-context exclusions need review.
- The existing optimizer test asserts a required outperformance margin; it does not independently validate equivalent portfolios with a common loss model. Existing evidence-report tests permit findings from the demo fixture. These tests can pass while the behaviors above remain defective.

**Limits and preservation**

Live Wazuh/Keycloak deployments, cloud accounts, paid LLM providers, and real external-feed freshness were not verified with production credentials. Connector tests use fixtures, patched responses, or local test servers. Regulatory clause accuracy, statistical calibration against actual losses, penetration testing, and load/endurance testing were outside this functional audit.

The Docker backend build reached `pip install` and downloaded dependencies slowly; its last visible download was SciPy. The five-minute build limit expired. The remaining audit-specific build subprocess was stopped, and no application containers were created. This is an incomplete deployment check, not proof of a backend Dockerfile defect. The frontend image remains available as `crisp-audit-1790778115741-frontend:latest`. The unlocked Python lower-bound requirements also caused the image build to resolve different package versions from the locally tested environment.

No application source fixes or production credential changes were made. Tests, screenshots, copied code, logs, and build artifacts are under `scratch/audit_20260930`. That directory is ignored by Git in this checkout; the report is under `docs`. Hash comparison found application sources and stored connector configuration unchanged; `backend/data/sync_state.json` changed during the audit, consistent with runtime state activity, and was not overwritten or restored. Existing uncommitted work remains in place.

**Reproduction**

From `scratch/audit_20260930/backend`, with `PYTHON_DOTENV_DISABLED=1` and `PYTHONPATH` set to that directory, run `python -m pytest tests -q`. From `scratch/audit_20260930`, run `python -m pytest audit_checks.py -q -p no:cacheprovider` with the same dotenv setting and `PYTHONPATH` pointing to the copied backend. The added checks intentionally fail against the current implementation and should become regression tests when the defects are fixed.
