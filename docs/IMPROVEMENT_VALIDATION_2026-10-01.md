# Improvement implementation and validation — 2026-10-01

Historical validation record: application access-token authentication and role enforcement were subsequently removed at the user’s request on 2026-10-02. Current behavior is documented in RISK_MODEL_AND_DEPLOYMENT.md.

The implementation replaces inconsistent portfolio calculations with one shared counterfactual engine. It also adds explicit likelihood assumptions, paired patch benefits, null-safe financial outputs, evidence-bound compliance reviews, tenant-bound persistence/authentication, and inspectable financial explanations.

| Requested improvement | Implemented behavior |
| --- | --- |
| Optimizer/simulator agreement | Same action interpreter, cloned snapshot, seed and risk engine; optimizer UI can replay the portfolio and compare residual EAL |
| Fair benchmarks | CVSS, EPSS, same-action-universe greedy and ILP selections are evaluated identically; fixed outperformance claim removed; reproducible CLI and metadata included |
| Likelihood model | Explicit exposure/scenario relevance; EPSS is not annualized or floored; per-trial shared intensity retained |
| Driver benefits | Composite asset/finding IDs; removal-and-rerun for screened candidates; unevaluated benefits remain unknown |
| Missing data | Never-scanned, completed-empty and remediated states distinguished; excluded assets remain visible with null financial values; final patch supported |
| Evidence-based compliance | Separate mapping/observed/evidence/assessed metrics; source/version/applicability/reviewer metadata; measured reporting exercises; stale or changed evidence invalidates review |
| Deployment safeguards | Bearer-token roles, tenant isolation, SQLite transactions, audit records, separate worker, mandatory production encryption key, credential exclusions in Docker build context |
| Inspectable figures | Explanation panel and API, business inputs, assumptions, timestamps, exclusions, loss components and model metadata; server-validated AI numerical claims |

Validation used a copied backend under `scratch/improvement_validation`, excluding live credentials, with explicit synthetic fixtures and mocked enterprise connectors.

- Full backend suite: **84 passed**, two dependency warnings.
- Follow-up checks after the final evidence/demo-isolation changes: **20 passed**, including one new test. These overlap the full suite; they are not 20 additional distinct tests.
- Production frontend build: passed. Vite still reports a large bundle warning (approximately 830 kB before gzip).
- Headless Edge: all eight dashboard tabs, empty-state compliance, explanation panel, optimizer replay, AI response and mobile rendering exercised. The completed smoke pass had no JavaScript exceptions or failed HTTP requests; portfolio replay matched residual EAL exactly.
- Multi-process tests confirmed no lost concurrent document updates and only one synchronization execution across two simultaneous workers. Authenticated API tests confirmed role enforcement, organization isolation, persisted restart state, audit records and optimizer/simulator equality.
- Invalid numerical AI claims and unsupported metric references were rejected; missing exposure was not described as zero.
- Tests verified that increased shared intensity variation changes tail loss while preserving expected intensity within Monte Carlo tolerance.

Artifacts: `tests-final.txt`, `tests-followup.txt`, `browser-results.json`, `browser-backend.txt`, browser screenshots and the production frontend build under `scratch/improvement_validation`. The scripts in `backend/tests` are the maintained regression tests; scratch harnesses are local validation artifacts.

The final browser pass was repeated after correcting the simulator chart to plot each curve at its own loss amounts and clearing previous-tenant display data on session changes. It again completed without browser exceptions or failed HTTP requests.

## Reproduced synthetic benchmark

`backend/scripts/benchmark.py` was executed with `backend/app/data/seed_snapshot.json`, budget INR 10,000,000, seed 42 and 5,000 trials. The complete result, including actions, assumptions and snapshot hash, is `scratch/improvement_validation/reproducible-benchmark.json`.

| Strategy | Spend (INR) | Annual reduction (INR) | Residual EAL (INR) |
| --- | ---: | ---: | ---: |
| CVSS patches | 1,600,000 | 3,736,738.81 | 607,944.31 |
| EPSS patches | 1,600,000 | 3,736,738.81 | 607,944.31 |
| Greedy, same action universe | 9,550,000 | 4,094,996.51 | 249,686.61 |
| ILP surrogate | 9,900,000 | 4,032,368.01 | 312,315.11 |

Greedy beats the additive ILP on simulated portfolio benefit in this example. CVSS and EPSS select the same patch set at this budget, so equal results are correct. No test requires any strategy to win, and the UI no longer claims a guaranteed nonlinear optimum.

Limits: Docker was unavailable in the final environment, so updated container startup was not verified. Enterprise connectors and paid AI providers were not exercised against live accounts. SQLite is a single-host baseline with serialized writers, not a multi-host architecture. The model remains judgment-based and requires organization calibration/backtesting. Framework mappings are curated subsets requiring independent source/applicability review; no regulatory certification is claimed. Demo fixtures and configurable model priors intentionally remain and are identified as such—this is not a claim that the repository contains no fixed inputs.
