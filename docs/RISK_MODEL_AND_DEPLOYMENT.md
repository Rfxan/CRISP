# Risk model and deployment contract

## Quantification and interpretation

Model `crisp-risk-2.0` uses 5,000 trials in the API by default and an explicit seed. A run records the model version, snapshot hash, resolved assumptions and trial count. Inspect these values in the executive dashboard's explanation panel or `GET /api/risk/explanation`.

EPSS is a global 30-day exploitation signal, not an asset compromise probability. CRISP does not annualize it or impose a 5% floor. The current **uncalibrated planning model** combines the signal with asset exposure, scenario relevance and a KEV multiplier. Annual threat-event frequency comes from each scenario's PERT inputs. A separate background susceptibility allows residual risk after remediation. See [FIRST's EPSS explanation](https://www.first.org/epss/faq.html).

Each Monte Carlo trial shares a mean-one lognormal threat-intensity draw across assets and scenarios. Incident counts use that trial's rate, retaining systemic variation. Asset/scenario random streams are stable by identifier so removal scenarios can be paired against the baseline. Losses combine downtime, incident response, data loss, a configurable penalty assumption and reputational churn. The penalty ceiling is a model parameter, not an assessed legal liability.

Annual-loss P95/P99 describe modeled variability, not a ceiling or a confidence interval on expected loss. Input PERT ranges and sensitivity analysis expose assumption uncertainty separately; they are not empirically calibrated confidence intervals. Missing business inputs, excluded assets and sources are visible in the explanation panel. Real incident/loss data and expert elicitation are still needed for organization-specific calibration and backtesting.

No findings without completed-scan evidence means **unknown**. A completed scan with no findings and a snapshot whose findings were remediated are distinct states; both can retain background risk. Missing financial values stay null through the API, AI and currency formatting.

## Portfolios and benchmarks

The ILP selects a portfolio using an additive approximation to single-action benefits. This is not a guarantee of globally optimal nonlinear risk reduction. Every selected portfolio is applied to a cloned snapshot and evaluated through the same engine used by the what-if simulator. Per-action selection coefficients are not allocated realized savings.

CVSS and EPSS select patches; the benefit-per-rupee baseline and ILP share the patch-and-control action universe. All strategies use identical evaluation assumptions, seed and trials. Benchmark responses record the snapshot, dataset size, budget and model. Outperformance may be positive, zero or negative. The displayed investment curve contains evaluated selections, not a proven optimal frontier.

Patch benefit is baseline EAL minus EAL after removing a specific asset/finding pair. By default the engine evaluates the top 20 screened findings; unevaluated findings have null marginal benefit and are excluded from patch selection. The excluded-candidate count is reported. Configure `driver_limit` through `PUT /api/model/assumptions` if a larger evaluation set is needed. Patch costs and control catalog costs are explicit planning inputs, not measured quotations.

Use **Replay portfolio in simulator** to check agreement. A changed snapshot requires optimization again. The estimate assumes immediate implementation; the cost-of-delay metric divides annual avoided loss by 52 under constant exposure.

To reproduce the synthetic example from `backend`, run `python scripts/benchmark.py app/data/seed_snapshot.json --budget 10000000 --seed 42 --trials 5000 --output benchmark.json`. Supply your own snapshot file for a real dataset. The JSON includes selected actions and assumptions for every strategy; it contains business-sensitive data and should be handled accordingly.

## Evidence and AI

Framework mappings are curated subsets. Mapping coverage, observed control coverage, evidence completeness and assessed compliance are separate quantities. Evidence must have an actual source, coverage and a timestamp within 90 days; simulated and assumed controls cannot establish assessed compliance. A reviewer decision is bound to the reviewed evidence and becomes unassessed if that evidence changes. The coverage threshold is consistently 75%. Applicability and source/version metadata are included in evidence reports.

Reporting readiness uses recorded incident, detection, escalation and reporting times from recent exercises. The six-hour target is an exercise configuration requiring independent applicability review; tool coverage cannot demonstrate reporting readiness.

The AI selects structured metric references and exact values. The server validates them against computed facts and renders numerical statements from its own templates. Invalid replies fall back to deterministic facts. This restricts narrative flexibility; it is not a general guarantee against every kind of misleading answer. Natural-language arbitrary scenario/action extraction is not implemented. Use the simulator for explicit actions; the current MFA shortcut evaluates 100% MFA coverage.

## Running locally

Install `backend/requirements.txt`, then run these in separate terminals from `backend`:

```text
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
python -m app.worker
```

Run `npm install` and `npm run dev` from `frontend`. Alternatively use `docker compose up --build`. Compose binds published ports to localhost, stores transactional state in the `crisp-state` volume, and runs synchronization in a separate worker. Demo data must be loaded explicitly. API processes do not start ingestion schedulers.

## Single-workspace deployment

The access-token sign-in feature was removed at the user's request. The dashboard and API open directly into the existing `local` workspace. There is no application-level login, role enforcement or user identity verification. All people able to reach the API have the same access. For a network deployment, restrict access at a trusted gateway; the bundled Compose ports remain bound to localhost.

`CRISP_DATABASE_URL` selects hosted PostgreSQL for multi-host operation and takes precedence over the local `CRISP_DATABASE_PATH` SQLite file. API and worker must use the same state database and persistent `CRISP_ENCRYPTION_KEY`. `CRISP_ENV=production` requires that key for stored connector and AI credentials; Vercel production and preview environments additionally require PostgreSQL and enforce production credential handling automatically. Preserve the key across restarts and backups. `CRISP_CORS_ORIGINS` configures frontend origins. Old token environment settings are no longer read. See [Vercel deployment](VERCEL_DEPLOYMENT.md) for service routing and provider setup.

Snapshots, configurations and history persist in transactional storage. Existing local data is retained. Legacy organization partitions are not deleted or merged into the local workspace. Audit records identify actions as `local-workspace`, not as an authenticated person. The worker still coordinates synchronization using transactions to prevent simultaneous duplicate jobs.

SQLite remains a single-host baseline with serialized writers. PostgreSQL coordinates workspace transactions and worker due checks with transaction-scoped advisory locks across hosts. An always-running worker must be hosted separately from Vercel functions, or replaced with scheduled jobs/queues. Audit rows are append-only within either database; independently controlled audit storage is needed for stronger integrity. Organization-specific model calibration and independent framework applicability review remain necessary.

## Validation

Tests cover paired portfolio equality, every benchmark's shared evaluation, final-finding remediation, duplicate CVEs across assets, missing values, exposure/scenario relevance, evidence validity, AI claim rejection, production encryption-key enforcement, direct workspace access, restart persistence and multi-process update/sync behavior. Test with `PYTHON_DOTENV_DISABLED=1` and `CRISP_TESTING=1`; production ignores the in-memory test bypass. Run tests against an isolated copy without live connector credentials.
