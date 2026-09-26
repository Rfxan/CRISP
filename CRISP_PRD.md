PRODUCT REQUIREMENTS DOCUMENT

CRISP

Continuous Risk & Investment Simulation Platform

AI-Powered Continuous Cyber Risk Quantification & Investment Optimization Platform

"Not a risk score. A budget decision, with the proof."

Problem Statement ID

SIH 26105

Document Type

Product Requirements Document (PRD)

Version

1.0

Status

Draft — for team build & submission

Team Size

3–4 members

Build Window

1–2 weeks (14-day plan)

Primary Data

Real Wazuh + OpenVAS lab, plus public threat-intel feeds (NVD, EPSS, CISA KEV)

Table of Contents

1. Executive Summary

2. Problem Statement & Background

3. Objectives

4. Scope

5. Target Users & Personas

6. Competitive Landscape & Differentiation

7. Product Requirements — Functional

8. Data Model

9. System Architecture

10. Core Models & Formulas

11. API Contract

12. Non-Functional Requirements

13. Compliance & Framework Mapping

14. Success Metrics / KPIs

15. Risks & Mitigations

16. Assumptions & Constraints

17. Team, Roles & Timeline

18. Testing & Validation Plan

19. Demo, Deliverables & Submission Checklist

20. Out of Scope / Future Work

21. Appendix: Reference Sources

1. Executive Summary

CRISP (Continuous Risk & Investment Simulation Platform) is an AI-assisted cyber risk quantification and investment-optimization platform built for Problem Statement 26105. It continuously ingests real vulnerability scan data (OpenVAS), endpoint and security telemetry (Wazuh), and public threat intelligence (NVD, EPSS, CISA KEV), combines this with a business asset model, and runs a FAIR-style Monte Carlo simulation engine to express cyber risk in rupees, with uncertainty ranges rather than a single misleading number.

The platform answers the question boards and executives actually ask: “We have ₹1 crore to spend on security — what should we buy, and how much loss does it remove?” A budget-constrained optimizer (Integer Linear Programming) selects the best combination of patches and controls, and a live benchmark proves this beats the common “patch by CVSS severity” approach, under the exact same underlying model.

Every output is explainable and traceable: numbers carry a run ID, assumptions are versioned and cited, and risk is mapped to ISO/IEC 27001, NIST Cybersecurity Framework, CIS Controls, the RBI Cyber Security Framework, and SEBI's Cybersecurity and Cyber Resilience Framework (CSCRF) — producing evidence exportable for audits and regulatory reporting.

This PRD defines what is being built, for whom, why, and exactly how — covering functional requirements, data model, architecture, formulas, API contract, non-functional requirements, risks, team structure, and the submission plan.

2. Problem Statement & Background

2.1 Background

Enterprises and institutions invest heavily in cybersecurity tools, compliance programs, and risk management initiatives, yet cyber risk is still predominantly communicated using qualitative ratings such as ‘Low’, ‘Medium’, or ‘High’. These coarse categories fail to express potential financial impact, making it difficult for senior management, boards, and regulators to evaluate whether current cyber investments are adequate or optimally allocated.

Cyber risk is inherently dynamic: new vulnerabilities emerge, threat actors change tactics, business services are added or retired, and security controls mature over time. Most current risk assessment practices rely on periodic, manual exercises, resulting in stale risk registers and limited visibility into an organization's real-time cyber exposure. This gap leads to suboptimal prioritization of remediation efforts, under- or over-spending on security controls, and weak alignment between technical risk metrics and business decision-making.

2.2 Problem Statement (as given)

Design and develop an AI-powered platform that continuously quantifies cyber risk in monetary terms by correlating technical security telemetry with business asset criticality and control effectiveness. The platform must estimate the likelihood and financial impact of cyber incidents, identify key risk drivers, and recommend cost-effective mitigation strategies under explicit budget constraints. The solution should bridge the gap between technical cybersecurity metrics and business language, enabling CISOs, risk officers, and executive leadership to make informed, data-driven decisions about cyber risk and security investment.

2.3 Why This Matters

The language gap: security teams speak in CVSS scores and CVE IDs; boards speak in rupees and quarterly budgets. Nothing in most tools translates between the two.

The staleness gap: annual or quarterly risk assessments are already outdated by the time they're presented, because vulnerabilities and threats change daily.

The prioritization gap: “patch everything Critical” is not a strategy when budget and engineering time are limited — organizations need to know which specific fixes remove the most expected loss per rupee spent.

The regulatory gap: Indian regulations (DPDP Act, SEBI CSCRF, RBI guidelines) now carry real financial and reporting consequences, and organizations need continuous, evidence-backed readiness — not a once-a-year audit binder.

3. Objectives

3.1 Primary Objective

Turn cyber risk from a vague qualitative label into a specific, continuously-updated rupee figure, so that security budget decisions can be made with evidence instead of guesswork.

3.2 Core Objectives (from the problem statement)

Quantify risk in monetary terms, not categories — replace Critical/High/Medium/Low with Expected Annual Loss (EAL) and Value at Risk (VaR95), at organization, business-unit, service, and asset levels.

Estimate both likelihood and financial impact — probability of an incident, and the range of what it would cost (downtime, data breach, regulatory penalty, reputational loss).

Connect technical findings to business importance — weight vulnerabilities by the business criticality and service dependencies of the asset they're on.

Recommend what to spend money on — given a fixed budget, identify the specific set of patches/controls that maximizes risk reduction.

Make it usable by non-technical stakeholders — plain-English Q&A and what-if scenario simulation for CISOs, risk officers, and boards.

Support governance and compliance — map risk posture to ISO 27001, NIST CSF, CIS, RBI, and SEBI CSCRF, and produce audit-ready evidence.

Make risk visibility continuous — not a once-a-year exercise, but a living, refreshing picture.

3.3 Build-Specific Objectives (how this PRD approaches delivery)

Ground everything in real data — real OpenVAS scans and Wazuh telemetry from an owned lab, plus live public threat feeds, rather than fabricated figures.

Prove the approach, don't just claim it — a live, reproducible benchmark showing the optimizer beating naive prioritization on identical data and budget.

Be honest about uncertainty — express every risk figure as a distribution (via Monte Carlo simulation), and maintain a versioned, cited assumptions ledger.

Be demo-reliable — a deterministic engine and replayable data snapshots so the same inputs always reproduce the same outputs, and a live lab failure cannot sink the demo.

Be explicit about scope — clearly state what is built with real integrations versus what is intentionally simplified or mocked, rather than overselling.

4. Scope

4.1 In Scope (build with real integrations)

Real vulnerability scanning via OpenVAS/Greenbone against an owned lab of 3–5 target machines.

Real endpoint/security telemetry via Wazuh (agent status, alerts, auth failures, file-integrity monitoring).

Live public threat intelligence: NVD CVE API, FIRST EPSS, CISA KEV catalog.

A FAIR-style Monte Carlo risk engine producing EAL, VaR95, tail loss, and a loss exceedance curve.

An asset dependency graph modeling how risk on one asset propagates to dependent business services.

A budget-constrained ILP optimizer recommending the best set of patches/controls, with a Pareto (investment vs. risk-reduction) curve.

A live benchmark comparing the optimizer against “patch by CVSS” and “patch by EPSS” baselines on identical data.

What-if scenario simulation (e.g., “what if MFA is enabled everywhere”) and a cost-of-delay metric.

A grounded natural-language Q&A interface (tool-calling only, no hallucinated numbers) with a rule-based offline fallback.

Compliance mapping and evidence reports for ISO 27001, NIST CSF, CIS Controls, RBI, and SEBI CSCRF.

Executive and technical dashboards, containerized via Docker Compose for one-command deployment.

4.2 In Scope (simulated / mocked, explicitly labeled)

IAM data (MFA coverage, privileged account counts) — mock connector, clearly tagged “SIMULATED”.

The wider fictional organization (~100–200 assets, revenue figures, customer records) — realistic but authored data, not a real enterprise.

Optional: a lightweight ML model recalibrating exploit likelihood (only if time allows after the core engine and optimizer are done).

4.3 Out of Scope for this build

Real SIEM, EDR, or CSPM enterprise integrations (e.g., Splunk, CrowdStrike, native AWS/Azure security posture tools) — too heavy for the build window; a pluggable connector interface is shown instead.

Deep predictive ML for emerging threats — replaced with an honestly-labeled simple trend projection (linear/exponential smoothing).

Regulator-certified compliance mappings — mappings are labeled indicative, not certification-grade.

Full copula-based correlated-loss modeling — approximated via a single global threat-intensity factor.

Multi-tenant, production-grade security hardening, and horizontal scaling infrastructure.

5. Target Users & Personas

Persona

Who they are

What they need from CRISP

CISO / Security Lead

Runs the security team day-to-day; deeply technical

Drill-down into which assets/CVEs drive the most risk; a prioritized, budget-aware remediation plan

Risk Officer

Enterprise-wide risk management; financially literate, not necessarily technical

Risk expressed in ₹ with uncertainty; comparison to risk appetite; trend over time

Executive Leadership / Board

Approves budgets; accountable to regulators and shareholders; non-technical

One clear number (EAL/VaR) and a simple budget-allocation recommendation with proof it works

Compliance / Audit Team

Prepares evidence for regulators and auditors

Exportable, framework-mapped evidence reports (ISO, NIST, CIS, RBI, SEBI CSCRF)

Security Analyst (drill-down user)

Investigates and remediates specific findings

Ranked findings by marginal ₹ contribution, with source/evidence links

6. Competitive Landscape & Differentiation

6.1 Commercial Platforms

Vendor

What they are

Notes

SAFE (Safe Security)

Market-leading CRQ platform; acquired RiskLens (2023) and Balbix (Nov 2025)

Continuous, FAIR-aligned; enterprise SaaS

Kovrr

Israeli CRQ vendor, FAIR-aligned Monte Carlo, strong in insurance workflows

On-demand quantification

Balbix

AI-native exposure management with CRQ; now part of SAFE

Some reviewers describe scoring as a “black box” (competitor claim — treat with care)

Axio, ThreatConnect

Longer-standing quantification and risk platforms

Enterprise-focused

CRISP cannot out-integrate or out-scale these vendors. It differentiates on transparency, India-specific regulatory context, and a demonstrable, provable optimization result within a short live demo.

6.2 Differentiation Table

#

Typical / Competitor Approach

CRISP

1

Single risk score

Full distribution: EAL, VaR95, tail loss, loss exceedance curve, confidence bands

2

CVSS severity drives likelihood

EPSS + CISA KEV + exposure + control coverage drive likelihood; CVSS only informs severity

3

Assets treated independently

Asset dependency graph — risk propagates to dependent business services

4

Sort findings by severity

Budget-constrained ILP optimizer + Pareto curve of investment vs. risk reduction

5

No proof of effectiveness

Live benchmark: optimizer vs. patch-by-CVSS vs. patch-by-EPSS, same model

6

LLM invents or recalls numbers

NL interface only calls tools into the deterministic engine; every answer cites a run ID

7

Generic, global framing

India context: ₹/crore, DPDP penalty exposure, SEBI CSCRF & RBI mapping, 6-hour reporting readiness

8

Static, point-in-time snapshot

Live event demo (new KEV entry updates exposure); cost-of-delay metric per action

9

Hidden assumptions

Versioned assumptions ledger, sensitivity analysis, data-quality score

10

Score shown with no context

Exposure vs. board risk appetite line (headroom)

7. Product Requirements — Functional

Requirements are grouped into modules matching the platform's core capabilities. Each requirement includes an ID for traceability.

7.1 Risk Quantification Engine (FR-RQE)

ID

Requirement

Priority

FR-RQE-01

System shall continuously aggregate and normalize data from vulnerability scans, endpoint telemetry, asset inventory, and threat intel feeds into versioned JSON snapshots.

Must

FR-RQE-02

System shall estimate annual incident likelihood per asset-scenario pair using threat event frequency and vulnerability exploitability (EPSS/KEV-informed).

Must

FR-RQE-03

System shall estimate financial loss magnitude per incident, decomposed into downtime, incident response, data breach, regulatory penalty, and reputational components.

Must

FR-RQE-04

System shall run a Monte Carlo simulation (≥10,000 trials) to compute Expected Annual Loss (EAL), Value at Risk (VaR95, VaR99), Tail Loss, and a loss exceedance curve.

Must

FR-RQE-05

System shall compute risk metrics at organization, business-unit, service, and asset levels.

Must

FR-RQE-06

System shall model asset criticality and business-service dependencies, propagating impact from an asset to dependent services.

Must

FR-RQE-07

System shall model control effectiveness using measured telemetry coverage and an effect-size prior per control-scenario pair.

Must

FR-RQE-08

System shall rank top risk drivers by marginal EAL contribution (leave-one-out method).

Must

FR-RQE-09

System shall compute a 0–100 risk score and risk-appetite headroom (appetite minus VaR95).

Should

FR-RQE-10

System may optionally recalibrate exploit likelihood using a lightweight ML model, clearly labeled as such.

Could

7.2 AI Decision Support Layer (FR-AI)

ID

Requirement

Priority

FR-AI-01

System shall provide a natural-language query interface answering business questions using only real computed values (no hallucinated numbers).

Must

FR-AI-02

The NL layer shall select from a fixed set of tools (get_top_risks, get_asset_risk, top_vulnerabilities_by_eal, simulate, optimize, compliance_gaps, explain) rather than generating numbers itself.

Must

FR-AI-03

Every NL answer shall cite a run ID and assumptions version for traceability.

Must

FR-AI-04

System shall provide a rule-based fallback for a fixed set of demo questions if the LLM/API is unavailable.

Must

FR-AI-05

System shall support what-if scenario simulation (e.g., control changes, patching actions) re-run on the same seed for comparability.

Must

FR-AI-06

System shall compute a cost-of-delay metric for recommended actions (expected loss increase per week of inaction).

Should

FR-AI-07

System shall show a simple trend/projection (30/60/90-day) of EAL and open KEV-listed findings, labeled as a simple projection, not deep learning.

Should

7.3 Investment Optimization Module (FR-OPT)

ID

Requirement

Priority

FR-OPT-01

System shall recommend a set of controls/remediations that maximizes risk reduction under a specified budget, using Integer Linear Programming.

Must

FR-OPT-02

System shall provide a secondary greedy-marginal-ROSI solver as a cross-check against the ILP result.

Should

FR-OPT-03

System shall compute ROSI (Return on Security Investment) and cost-benefit metrics per recommended action.

Must

FR-OPT-04

System shall generate a Pareto curve (budget vs. EAL reduction) across a budget sweep, marking the point of diminishing returns.

Must

FR-OPT-05

System shall benchmark its optimizer's output against “patch by CVSS” and “patch by EPSS” baselines under an identical model and budget, and display the comparison.

Must

7.4 Dashboards (FR-UI)

ID

Requirement

Priority

FR-UI-01

System shall provide an executive dashboard showing EAL, VaR95, loss exceedance curve, risk-appetite headroom, and trend.

Must

FR-UI-02

System shall provide a technical drill-down view showing control-level and asset-level findings and remediation backlog.

Must

FR-UI-03

System shall provide a what-if simulator screen showing delta EAL/VaR with confidence bands for a chosen scenario.

Must

FR-UI-04

System shall provide an optimizer screen showing the recommended action set, ROSI, the Pareto curve, and the benchmark comparison.

Must

FR-UI-05

System shall provide an NL Q&A screen.

Must

FR-UI-06

System shall provide a compliance/reports screen showing framework coverage %, gaps, and export options.

Must

FR-UI-07

System shall clearly and visibly label all simulated (non-real) data in the UI.

Must

7.5 Compliance & Framework Mapping (FR-COMP)

ID

Requirement

Priority

FR-COMP-01

System shall maintain an internal control catalog of ~25–35 controls mapped to CIS Controls v8, NIST CSF 2.0, ISO/IEC 27001:2022 Annex A, RBI Cyber Security Framework, and SEBI CSCRF.

Must

FR-COMP-02

System shall compute per-framework coverage percentage from control-state evidence.

Must

FR-COMP-03

System shall generate a gap report listing unmet controls, the risk they leave, and the cheapest fix (from the optimizer).

Must

FR-COMP-04

System shall include India-specific regulatory readiness checks (e.g., 6-hour incident-reporting readiness for SEBI CSCRF; DPDP breach-notification and safeguards items).

Must

FR-COMP-05

System shall export an evidence report (PDF/HTML) per framework.

Must

FR-COMP-06

All framework mappings shall be labeled “indicative” with cited source documents; the system shall not claim certification-grade accuracy.

Must

8. Data Model

The following is the minimum viable schema. Every table exists because a screen or a formula needs it — nothing is speculative.

Table

Fields

assets

id, name, type, owner, business_service_id, environment, internet_facing, data_classification, records_count, revenue_per_hour, criticality_1_5

services

id, name, revenue_per_hour, rto_hours, depends_on[] — business services

findings

id, asset_id, cve_id, cvss, severity, port, first_seen, last_seen, source

cve_intel

cve_id, epss, epss_percentile, in_kev, exploit_public, published

controls_catalog

id, name, category, annual_cost, capex, effectiveness_dist, mitigates[scenario ids], frameworks{iso, nist, cis, rbi, sebi}

control_state

control_id, asset_scope, coverage_pct, evidence_ref, last_checked

scenarios

id, name, threat_type, attack_techniques[], loss_params{...}

risk_snapshots

ts, entity_type, entity_id, eal, var95, tail, drivers[], data_quality

runs

run_id, ts, params_hash, snapshot_id, seed, result_ref — for citations

9. System Architecture

9.1 Layers

Sources: OpenVAS/GVM (scans), Wazuh (alerts), Asset CSV (inventory), NVD/EPSS/KEV (threat feeds), IAM mock (posture).

Ingest & Enrich: one connector per source, a normalizer, an enricher (attaches EPSS/KEV context to findings), and a snapshot store writing versioned JSON.

Database: Postgres (or SQLite for dev) storing risk-snapshot history and run records.

Core Engine: asset dependency graph (NetworkX), likelihood model, FAIR loss model, control model, Monte Carlo runner, and the ILP optimizer — exposed as a pure function.

API: FastAPI, acting as the single contract between the engine and the frontend.

Experience: React + Vite dashboards — executive view, technical drill-down, what-if simulator, optimizer/Pareto view, NL Q&A, and compliance/reports.

9.2 Design Principles

Pure, deterministic engine: run(snapshot, params, seed) → RiskResult. Identical inputs always produce identical outputs — this makes testing, what-if analysis, and demo reproducibility trivial.

Snapshots everywhere: every ingestion cycle produces a replayable JSON snapshot, so a live demo can continue even if the lab or internet connection fails.

API-contract-first: the API contract is agreed on day 1; frontend development proceeds against mock JSON in parallel with engine development.

9.3 Tech Stack

Layer

Choice

Language

Python 3.11+

API

FastAPI

Database

SQLite for development; PostgreSQL in Docker Compose if time allows

Numerics

NumPy, SciPy (PERT via Beta distribution), pandas

Graph

NetworkX

Optimization

PuLP (CBC solver) or Google OR-Tools

ML (optional)

scikit-learn or XGBoost

Frontend

React + Vite + Recharts

Scheduling

APScheduler or a simple cron loop

Reports

HTML-to-PDF (WeasyPrint) or Markdown/HTML export

Packaging

Docker Compose — one command starts API, DB, UI, and replay mode

10. Core Models & Formulas

10.1 Scenario Structure

Define 6–8 loss scenarios, for example: ransomware on a service, data breach of customer PII, credential compromise of a privileged account, web application compromise, insider misuse, DDoS/outage, and third-party compromise. Each scenario has a threat-frequency prior, applicable vulnerability types, optional ATT&CK techniques, and loss components.

10.2 Likelihood (Annual Event Frequency)

For each asset-scenario pair:

λ(a,s) = TEF(s) × P_vuln(a,s)

TEF(s): threat event frequency per year, modeled as a PERT distribution (min/likely/max) from published threat-report data. Source and assumption must be documented.

P_vuln(a,s): probability a threat event succeeds, built from open findings on the asset. For each finding, p_v is derived from its EPSS score (a 30-day exploitation probability), crudely annualized as 1 − (1 − p30)^12, with the independence assumption stated explicitly.

Uplifts: if a CVE is listed in CISA KEV, its p_v is raised to a high floor or multiplied by an uplift factor (tested via sensitivity analysis); internet-facing assets receive an exposure multiplier; compensating controls are applied per Section 10.4.

Combining findings: P_vuln = 1 − Π_v (1 − p_v) — i.e., any single exploitable finding suffices (a simplification, stated as such).

Sampling: annual event count N ~ Poisson(λ) is drawn per Monte Carlo trial.

Optional ML angle: a lightweight gradient-boosted model may recalibrate exploit likelihood using features such as EPSS, KEV membership, CVSS vector, finding age, and exposure, evaluated by AUC/precision-recall against CVSS-only ranking. This is optional and only pursued once the core FAIR engine and optimizer are complete.

10.3 Loss Magnitude

Per simulated event, each component below is sampled from a distribution (never treated as a constant) and then summed:

Component

Modeling approach

Downtime

outage_hours × revenue_per_hour(service) × impact_fraction; outage_hours drawn from a PERT distribution bounded by the service's recovery time objective (RTO)

Incident response & forensics

PERT range, scaled by asset criticality

Data breach cost

records_affected × cost_per_record, with cost_per_record taken from a cited public breach-cost report

Regulatory penalty

Conditional on personal data being involved: P(penalty | breach) × penalty_size, with DPDP ceilings (up to ₹250 crore) used only as an upper bound, never as the expected value

Reputational / churn

customer_loss_fraction × customer_lifetime_value, kept as its own labeled component with wide uncertainty

Loss components use lognormal or PERT distributions with fat tails; every number is a distribution, not a constant.

10.4 Control Effectiveness

Modeled in two layers:

Measured coverage from telemetry — e.g., % of endpoints with an active Wazuh agent (proxy for EDR/monitoring coverage), % patched within SLA (from scan data), MFA coverage (from the IAM mock or a real identity source), and backup/segmentation flags from the asset inventory.

Effect size e(c,s) — how much control c reduces the probability or impact of scenario s, modeled as a Beta distribution to reflect uncertainty, with priors seeded from CTID's control-to-ATT&CK mappings. Priors are explicitly labeled as judgment-based and are sensitivity-tested.

Residual likelihood:

P_residual(a,s) = P_vuln(a,s) × Π_c (1 − e(c,s) × coverage(c,a))

This multiplicative combination assumes independence between controls and can over-credit overlapping controls; this limitation is stated explicitly, and the optimizer uses a conservative “best control wins” rule (Section 10.7) to avoid double-counting.

10.5 Asset Criticality & Propagation

A directed graph models asset → service → business process relationships.

Business impact of losing an asset includes the revenue of dependent services: impact(a) = own_impact(a) + Σ (over services depending on a) of w × service_revenue_loss.

Choke points — assets with high betweenness or many dependents — are surfaced explicitly (e.g., “fixing this one server removes exposure for 4 services”).

For correlated losses (e.g., a ransomware wave hitting many assets at once), a global threat-intensity factor G ~ LogNormal(0, σ) is applied to all λ values within each trial, fattening the loss tail without requiring a full copula model.

10.6 Aggregation & Outputs

Per trial (10,000 trials total): draw G, sample events per asset-scenario pair, sample losses, and sum to L_k at asset, service, business-unit, and organization level.

EAL      = mean(L_k)VaR95    = 95th percentile of L_k   (99th also reported)TailLoss = mean of L_k above VaR95  (expected shortfall)Loss exceedance curve: P(L > x) vs xRisk score (0-100) = log-scaled EAL relative to risk appetite or revenueRisk appetite headroom = appetite − VaR95

Risk drivers are ranked by marginal EAL contribution using a leave-one-out method (recomputing with a given finding or asset removed); Shapley-style sampling is a stretch goal if time allows.

10.7 Investment Optimizer

Actions are either remediations (patch CVE v on a set of assets) or controls (deploy MFA, network segmentation, EDR coverage, etc.), each with a one-time and/or annual cost, effort, and prerequisites.

A. Exact ILP (PuLP or OR-Tools) — “best control wins” per scenario, conservative:

maximize    Σ_s  base_EAL_s × r_ssubject to  r_s ≤ Σ_c e_(c,s) × y_(c,s)     (reduction achieved in scenario s)            Σ_c y_(c,s) ≤ 1                 (only the strongest selected control counts)            y_(c,s) ≤ x_c                     (control must be purchased)            Σ_c cost_c × x_c ≤ Budget            x_c ≤ x_d                         (prerequisite constraints)            x_c ∈ {0,1},  0 ≤ r_s ≤ 1

Individual vulnerability patches are near-additive and are added as extra binary actions, with reduction equal to that finding's EAL contribution.

B. Greedy marginal-ROSI solver (sanity check):

Uses the full multiplicative model, re-evaluating after each pick. Significant disagreement between the greedy and ILP results is treated as a signal to investigate the model, not to trust one blindly.

ROSI (Return on Security Investment):

ROSI = (EAL_reduction − annual_cost) / annual_cost

For multi-year comparisons, Net Present Value (NPV) is used; a single formula is kept for presentation purposes.

Pareto / diminishing-returns curve: the ILP is solved across a sweep of budgets (₹10 lakh to ₹5 crore), plotting budget against EAL reduction and marking the “knee” — the point where marginal reduction per rupee drops below a threshold.

Benchmark panel (the core proof): at the same budget, three plans are evaluated under the identical Monte Carlo model — (1) patch by CVSS descending, (2) patch by EPSS descending, (3) the CRISP optimizer. EAL reduction and reduction-per-rupee are reported for all three. This benchmark must be built and validated by day 8 of the build plan; if the optimizer does not clearly win, the model or data is fixed — results are never fabricated.

10.8 What-If Analysis & Cost of Delay

A what-if run clones the current snapshot, modifies control_state or removes findings, and re-runs the engine with the same random seed, showing the delta in EAL/VaR with confidence bands. Examples: “MFA on all privileged accounts,” “patch all KEV-listed findings,” “segment the payments database.”

Cost of delay is computed as EAL(after delay) − EAL(now), using either time-varying inputs (exploit likelihood rising once a public exploit or KEV entry appears) or a simpler daily_EAL × days approximation with the assumption stated. Displayed as “₹X lakh per week of delay” next to each recommendation.

10.9 Trend & Light Prediction

A risk_snapshots row is stored each cycle. A 30/60/90-day trend projection is shown using a simple method (linear or exponential smoothing) on EAL and on the count of open KEV-listed findings. This is explicitly labeled a simple projection, not deep learning — an honest, modest forecast is prioritized over a fabricated “fancy” one.

11. API Contract

Agreed on day 1 of the build so that frontend and engine development can proceed in parallel, with the frontend initially mocking against this exact shape.

GET  /risk/summary            -> EAL, VaR95, tail, score, appetite headroom, trendGET  /risk/entities?level=    -> org | business_unit | service | asset, with EAL and driversGET  /risk/drivers            -> top contributors by marginal EALGET  /risk/curve              -> loss exceedance pointsPOST /simulate                -> {actions[], scope} -> delta EAL/VaR with bandsPOST /optimize                -> {budget, constraints} -> plan, ROSI, comparison vs baselinesGET  /pareto                  -> budget vs reduction pointsGET  /compliance/{framework}  -> coverage %, gaps, evidence linksGET  /report/{framework}      -> PDF/HTML evidence reportPOST /ask                     -> {question} -> answer + run_id + sourcesPOST /demo/inject-event       -> replay a KEV/exploit event (demo trigger)GET  /health/data-quality     -> freshness, coverage, simulated-vs-real ratio

Example RiskResult payload

{  "run_id": 123, "ts": "...", "seed": 42, "assumptions_version": 4,  "org": {"eal": 41200000, "var95": 168000000, "tail": 240000000, "score": 71,          "appetite": 120000000, "headroom": -48000000, "data_quality": 0.82},  "drivers": [{"type": "finding", "id": "CVE-XXXX-YYYY", "asset": "pay-db-01",               "marginal_eal": 9100000}],  "curve": [[0, 1.0], [1e6, 0.93]]}

(Figures shown are placeholders for illustration only.)

12. Non-Functional Requirements

Category

Requirement

Determinism

The engine must be a pure function: run(snapshot, params, seed) always produces identical output for identical input. No hidden randomness or side effects.

Reproducibility

Every ingestion cycle produces a versioned, replayable JSON snapshot; the system must be able to run entirely from a saved snapshot with no live lab or internet connection.

Performance

Monte Carlo simulation (10,000 trials) must be vectorized (NumPy) and complete within an interactive time budget; results are cached per snapshot hash.

Deployability

The entire stack (API, database, UI, replay mode) must start with a single command via Docker Compose.

Transparency

Every numeric output must be traceable to a run ID and an assumptions version; all cited figures must reference a source; all estimated figures must be labeled as assumptions.

Data honesty

All simulated or mocked data must be visibly labeled as such, in both the UI and the README — never presented as real.

Explainability

The optimizer and risk engine must produce human-readable justifications (e.g., marginal EAL contribution) rather than opaque scores.

Extensibility

New data connectors must be addable behind a single Connector interface (fetch() -> list[Finding|Asset|State]) without touching engine internals.

Security of the lab

Only owned or explicitly authorized machines are scanned; the lab runs on an isolated network.

Usability

Executive-facing screens must express risk in ₹/crore with plain-language framing; technical screens may retain CVE/CVSS-level detail.

13. Compliance & Framework Mapping

Framework mapping is a first-class output, not an afterthought, and is treated as indicative rather than certification-grade.

13.1 Frameworks Covered

ISO/IEC 27001:2022 — Annex A controls

NIST Cybersecurity Framework (CSF) 2.0 — subcategories

CIS Controls v8 — safeguards

RBI Cyber Security Framework — domains

SEBI Cybersecurity and Cyber Resilience Framework (CSCRF) — goals/areas, including the 6-hour incident-reporting requirement

13.2 Approach

Maintain a single internal control catalog (~25–35 controls: patch management, MFA, EDR coverage, logging/SIEM, backup, segmentation, access reviews, VAPT cadence, incident response, etc.), each mapped to the five frameworks above in a single JSON/YAML file.

Compute per-framework coverage percentage from control_state evidence (e.g., “patching within SLA: 62%”, derived from real scan data).

Generate a gap report: unmet controls, the risk they leave exposed (quantified by the engine), and the cheapest fix (from the optimizer).

Include India-specific regulatory readiness checks that are cheap to compute and high-signal, e.g., “can we detect and report an incident within the SEBI CSCRF 6-hour window?” tied to logging/monitoring coverage evidence, plus DPDP breach-notification and safeguards checklist items.

Label all mappings “indicative” and cite source documents. The system does not claim certification-grade accuracy.

Seed control-effectiveness priors from the CTID (MITRE Engenuity) Mappings Explorer (NIST 800-53 to ATT&CK), cross-referenced against the NIST/ISO tags already assigned.

13.3 Regulatory Context (India-specific)

Regulation

Key relevance to CRISP

DPDP Act & Rules 2025

Penalty ceilings up to ₹250 crore for failing reasonable security safeguards, and up to ₹200 crore for breach-notification failure. Modeled as a bounded penalty component in the loss model — ceilings used only as an upper bound, never as an expected value.

SEBI CSCRF

Circular dated 20 Aug 2024, built on NIST CSF; mandates 6-hour incident reporting. CRISP tracks readiness for this window via a dedicated checklist tied to logging/monitoring coverage.

RBI Cyber Security Framework

Guidelines for regulated financial entities; mapped as one of the five compliance frameworks (clause-level detail to be verified against current RBI publications before quoting).

14. Success Metrics / KPIs

Because CRISP is a hackathon build, success is measured both by what it demonstrates technically and by how convincingly it proves its central claim.

Metric

Target / Definition

Optimizer benchmark win

CRISP's ILP-recommended plan must achieve a clearly higher EAL-reduction-per-₹ than both the patch-by-CVSS and patch-by-EPSS baselines, on identical data and budget.

Engine determinism

Identical (snapshot, params, seed) inputs produce bit-identical EAL/VaR/curve outputs across repeated runs.

Cross-validation accuracy

A simple scenario built in CRISP's engine and in the open-source pyfair library should agree within Monte Carlo error.

Monte Carlo convergence

EAL must visibly stabilize as trial count increases toward 10,000, demonstrated in the README/demo.

Data-quality score

Reported share of assets with fresh scans, share of fields real vs. simulated, and feed age — visible via /health/data-quality.

Demo reliability

The full demo script (Section 19) must complete end-to-end from a replayed snapshot with zero dependency on live internet or a live lab.

Framework coverage reporting

At least 3 of the 5 compliance frameworks must produce a working, exportable evidence report by the freeze date.

NL Q&A accuracy

All 5 fixed demo questions (Section 10.9-related NL tools) must be answered correctly, with a working rule-based fallback if the LLM is unavailable.

15. Risks & Mitigations

Risk

Mitigation

Lab (Wazuh/OpenVAS) is slow or breaks during build or demo

Snapshot-and-replay mode; scans and feed syncs started on day 1; a second machine/VM kept on standby

Optimizer fails to beat the baseline

Discover this by day 8 (the benchmark gate); tune scenario/control effect sizes honestly, add interaction effects, or revisit the formulation — never fabricate results

Integration complexity across ingestion, engine, and UI

API contract frozen on day 1; mock endpoints live by day 2; a dedicated integration checkpoint on day 4

Scope creep late in the build

A predefined cut list (Section 17.4); all features frozen after day 11

Judges question calibration of loss/probability priors

Maintain a versioned assumptions ledger; run sensitivity analysis; cross-check against pyfair; state explicitly that priors are judgment-based and would be recalibrated with real client incident history

NL/LLM layer is flaky or offline during demo

A rule-based keyword fallback covers the fixed set of demo questions; answers are cached

Monte Carlo performance at 10,000 trials

Vectorize with NumPy; cache results per snapshot hash

Team bottleneck on a single person/module

Pair-program on the engine and optimizer; shared documentation; mandatory code review on merge to main

16. Assumptions & Constraints

16.1 Assumptions

A real Wazuh + OpenVAS lab can be stood up with 3–5 owned/authorized target machines within the build window.

Public feed APIs (NVD, EPSS, CISA KEV) remain accessible and within documented rate limits throughout the build.

The team can source and cite realistic loss-cost figures (e.g., cost per breached record) from public breach-cost reports; where no citable figure exists, the number is explicitly labeled an assumption.

Judges/evaluators will accept a clearly-labeled simulated organization (fictional NBFC) layered on top of real lab data, provided the mix is disclosed honestly.

A 3–4 person team has combined familiarity with Python, basic optimization libraries, and React; ramp-up time for unfamiliar tools is accounted for in the day-by-day plan.

16.2 Constraints

Build window: 1–2 weeks (14-day plan; see Section 17.3).

Team size: 3–4 people.

Compute: Wazuh and Greenbone/OpenVAS are memory-hungry (~8 GB each recommended) and should not run on the same machine as development tools.

No live internet dependency permitted during the judged demo — everything must be replayable from a cached snapshot.

Only machines the team owns or has explicit permission to test may be scanned; the lab must run on an isolated network.

16.3 Verification Status of Key Facts

The table below distinguishes facts already verified from public sources versus items the team should verify independently before quoting in the final submission.

Verified from public sources

Verify independently before quoting

DPDP Act penalty ceilings (up to ₹250 crore for safeguard failures; up to ₹200 crore for breach-notification failure); DPDP Rules notified Nov 2025, phased in over 18 months

RBI Cyber Security Framework clause-level details

SEBI CSCRF issued 20 Aug 2024, built on NIST CSF, with 6-hour incident reporting and later clarification circulars

Exact loss-cost figures used in the model (breach cost per record, downtime cost) — cite a source for each

CTID (MITRE Engenuity) publishes open NIST 800-53 to ATT&CK mappings (6,300+) via Mappings Explorer

API details and current rate limits of NVD, EPSS, and CISA KEV

Existing open-source FAIR libraries and commercial CRQ vendor positioning (Section 6)

The exact PS-26105 deliverables list and format limits on the submission portal

17. Team, Roles & Timeline

17.1 Work Split — Four People

Role

Owns

“Done” means

A: Risk Engine Lead

Likelihood, loss, control, Monte Carlo, sensitivity, propagation, tests

engine.run(snapshot, params, seed) is deterministic, unit-tested, cross-checked against pyfair on a simple scenario, and outputs EAL/VaR/curve/drivers at all levels

B: Data & Infra Lead

Lab, connectors, normalizer, enrichment, DB, scheduler, snapshots, Docker Compose

Real scan/alert data flows into a snapshot on a schedule; docker compose up works; replay mode works; POST /demo/inject-event works

C: Frontend Lead

All screens, charts, what-if UI, report export, visual polish

Executive view, drill-down, what-if, optimizer/Pareto, compliance and NL screens consuming the API contract; functional from mock JSON by day 2

D: Optimizer, AI, Compliance & Story

ILP, greedy, baselines, Pareto, NL tools and fallback, control catalog and framework mapping, docs, deck and video

Optimizer beats baselines with a saved benchmark; 6 demo questions answered correctly; 3 framework reports export; README, architecture doc, deck and video complete

17.2 Work Split — Three People (merge role D)

A also owns the optimizer and baselines.

B also owns the NL tool layer and fallback.

C also owns framework mapping and reports.

Everyone shares documentation; a single “demo director” (C or A) owns the video and deck.

17.3 Interfaces (to avoid integration hell)

A and B agree on the snapshot schema (Section 8) by end of day 1.

A and C agree on the API contract (Section 11) by end of day 1; A publishes a mock endpoint returning the example RiskResult by day 2.

D consumes A's engine as a library and adds /optimize, /ask, /compliance.

A daily 15-minute sync; merges to main at least daily; feature branches; one owner per file.

17.4 Day-by-Day Plan (14 Days)

Day

Goal

Checkpoint

1

Repo, schema, API contract, assumptions-file skeleton. Start the Greenbone feed sync. Decide the demo organization.

Everyone can run a “hello world” of their part

2

Engine v0 on a synthetic snapshot; UI skeleton on mock JSON; lab VMs up; NVD/EPSS/KEV fetchers.

UI shows mock EAL; engine prints EAL

3–4

Engine: likelihood + loss + Monte Carlo + curve; connectors for OpenVAS and Wazuh; first real snapshot.

Integration checkpoint (day 4): real snapshot in, EAL/VaR out, shown in UI

5

Control model and what-if; asset graph and propagation; executive dashboard view.

What-if changes EAL on screen

6–7

Optimizer (ILP), baselines, Pareto curve; drill-down screens; control catalog v1.

Benchmark table exists (even if rough)

8

Benchmark gate: optimizer must clearly beat patch-by-CVSS. If not, fix model/data. Sensitivity analysis and assumptions ledger.

Go/no-go decision on the headline claim

9

NL tools plus fallback; live-event injection; cost of delay.

Live event visibly moves exposure on screen

10

Framework mapping and coverage; report export; risk appetite and headroom.

Report PDF generated for one framework

11

Feature freeze. Bug bash, data-quality view, visual polish.

No new features added after today

12

Write README and 2-page architecture doc; take screenshots; record demo dry runs.

Docs draft complete

13

Record final video; finalize 5-slide deck; test a fresh-clone setup on another machine.

Video and deck done

14

Buffer for slippage; submission; rehearse Q&A.

Submitted

17.5 Cut List (if behind schedule)

If the team falls behind, cut in this order:

Predictive trend projection

ATT&CK-level priors (fall back to a simple lookup table)

Extra frameworks (keep NIST CSF, CIS, and ISO 27001, plus one of RBI/SEBI)

NL layer's LLM component (keep the rule-based fallback)

PostgreSQL (keep SQLite)

Never cut: the Monte Carlo engine, the optimizer benchmark, real data ingestion, and the live-event demo.

18. Testing & Validation Plan

Determinism test: the same seed must produce identical results across repeated runs.

Cross-validation: the same simple scenario is built independently in CRISP's engine and in the open-source pyfair library; results must agree within Monte Carlo error, with the comparison documented in the README.

Sanity tests: doubling an asset's value must increase EAL; adding a control must never increase EAL; a budget of ₹0 must yield no risk reduction; a larger budget must never decrease total reduction (monotonic Pareto curve).

Sensitivity analysis: a tornado chart showing EAL sensitivity to the top 5 assumptions. If the top-3 recommended actions remain stable across ±30% variation on these assumptions, this is reported as a strength; if not, this is reported honestly.

Convergence check: EAL must be shown stabilizing as the trial count increases (10,000 trials is expected to be sufficient; this is demonstrated visually).

Data-quality score: share of assets with fresh scans, share of fields real vs. simulated, and feed age, all exposed via the /health/data-quality endpoint.

19. Demo, Deliverables & Submission Checklist

19.1 Three-Minute Live Demo Script

(0:00) Board view: EAL, VaR95, loss exceedance curve, risk-appetite line (shown as currently exceeded), and trend.

(0:30) Ask in plain English: “What is our highest financial cyber risk today?” — a grounded answer is returned with a run ID.

(0:50) Drill into the top risk driver: a real finding from the lab on the payments database, propagating to the payments service; show its marginal ₹ contribution.

(1:10) What-if: “MFA on all privileged accounts” — show the resulting delta EAL with confidence band.

(1:30) Enter a ₹1 crore budget: show the optimizer's plan, ROSI per action, the Pareto curve with the knee marked, and the benchmark panel (“CRISP vs. patch-by-CVSS: +X% more reduction”).

(2:10) Live event: inject a new KEV-listed CVE affecting an asset. Exposure jumps on screen; a new top recommendation appears with its cost of delay.

(2:40) Export the SEBI CSCRF (or RBI) evidence report; show coverage and gaps.

(2:55) Close: “Not a risk score. A budget decision, with the proof.”

19.2 Two-Minute Video Structure

Same narrative, compressed: problem (10s), solution (10s), demo steps 1, 5, 6, and 7 above (80s), architecture and honest limitations (15s), close (5s). Voiceover and captions throughout; no dead time.

19.3 Five-Slide Deck Structure

Problem: qualitative ratings fail boards and regulators — quote the original statement's gap.

Solution and differentiation table (Section 6.2).

Architecture and models: one diagram covering FAIR Monte Carlo, the dependency graph, and the ILP optimizer.

Results: benchmark table, Pareto curve, cross-validation, sensitivity analysis.

India impact, roadmap, and honest limitations.

19.4 Two-Page Architecture Document

Page 1: architecture diagram, data flow, components, and a clear split of real vs. simulated data. Page 2: models and formulas, optimizer design, validation approach, assumptions and limitations.

19.5 Submission Checklist

Source code link (GitHub or Drive), clean and runnable

README with setup instructions (docker compose up), screenshots, and demo credentials if applicable

Architecture document (max 2 pages)

Demo video (max 2 minutes)

Technical presentation (max 5 slides)

Confirm the exact PS-26105 deliverables list and format limits on the submission portal before final submission

19.6 Do / Don't

Do

Don't

Express everything in ₹/crore, with ranges

Multiply CVSS by asset value and call it “risk”

Show uncertainty: percentiles, bands, a tornado chart

Let the LLM compute or recall numbers itself

Keep every number traceable via a versioned assumptions.yaml with source and date

Claim regulator-certified mappings or “real-time” if the refresh loop runs every N minutes

Label all simulated data as simulated, everywhere

Present made-up loss numbers as facts — cite sources or call them assumptions

Make the engine deterministic and testable; make what-if a simple re-run

Integrate more real tools than can be finished (SIEM/EDR/CSPM are out of scope — say so)

Build the benchmark early; build the demo path first, then edge cases

Add features after day 11

Keep a replayable snapshot so the demo cannot fail on a flaky VM

Scan systems the team does not own or have permission to test

Write the README as if a stranger will run it tomorrow

Leave the demo dependent on live internet or a live lab

Rehearse the demo at least three times with a timer

Hide limitations — state them and show what comes next

20. Out of Scope / Future Work

Beyond the hackathon build window, the following represent a credible roadmap and should be communicated as “what we'd do next,” not as gaps to hide:

Real, production-grade SIEM, EDR, and CSPM integrations (e.g., Splunk, CrowdStrike, native cloud security posture tools).

Full copula-based correlated-loss modeling, replacing the current single global threat-intensity factor approximation.

Recalibration of loss and likelihood priors using a real client's historical incident data (moving from judgment-based priors to empirically calibrated ones).

Certification-grade compliance mapping, potentially validated with a qualified auditor or the framework owners themselves.

Multi-tenant architecture, enterprise-scale streaming ingestion, and a proper data warehouse for very large asset counts.

A more sophisticated predictive ML layer for emerging threats, beyond the current simple trend projection.

Shapley-value-based risk driver attribution, replacing the current leave-one-out approximation.

21. Appendix: Reference Sources

21.1 Open-Source References

Reference

Used for

Hive-Systems/pyfair (formerly Derive-Risk/pyfair)

Python FAIR model with Monte Carlo and PERT inputs; used to cross-validate the engine

Netflix-Skunkworks/riskquant

Simple probability + low/high loss range baseline model; CSV scenario input design idea

Krishcalin/Cyber-Risk-Quantification (CRQ Engine)

FAIR, PERT sampling, loss exceedance curves, control ROI, HTML report — output format reference

pyCRQ (PyPI)

Open FAIR library with a ScenarioBuilder — API design reference

lauravoicu/Risk-Modelling

Bayesian (PyMC) cyber risk models — idea for Bayesian updating of priors from observed incidents

center-for-threat-informed-defense/mappings-explorer (CTID)

Open control-to-ATT&CK mappings — data source for control-effectiveness priors

21.2 Live Data Feeds

Feed

Data provided

OpenVAS / Greenbone

Vulnerabilities per host, CVE, CVSS, port, detection time (via GMP / python-gvm / gvm-tools, or XML/CSV report export)

Wazuh

Agent inventory and status, alerts (auth failures, file-integrity monitoring, rootcheck), its own vulnerability-detector output (via REST API or alerts.json/indexer queries)

NVD CVE API 2.0

CVE descriptions, CVSS vectors, CWE

FIRST EPSS

Exploit prediction probability and percentile (API or daily CSV)

CISA KEV Catalog

Known-exploited vulnerabilities (JSON feed)

21.3 Regulatory & Market Sources

DPDP Rules 2025 — PIB release dated 17 Nov 2025 and the MeitY notification.

SEBI CSCRF — Circular SEBI/HO/ITD-1/ITD_CSC_EXT/P/CIR/2024/113, dated 20 Aug 2024, and later clarification circulars.

CTID Mappings Explorer — github.com/center-for-threat-informed-defense/mappings-explorer and ctid.mitre.org.

Commercial CRQ landscape — SAFE Security, Kovrr, Balbix, Axio, ThreatConnect (reviewed for differentiation, not replication).

21.4 One-Page Summary (for the team wall)

Build one deterministic engine; everything else calls it.

Real data flows in from the lab; the rest is labeled simulated.

Answers are distributions in ₹, with uncertainty and sources.

The optimizer wins a benchmark against patch-by-CVSS — that is the headline.

A live event in the demo proves “continuous.”

India context (₹, DPDP, SEBI, RBI) makes it feel real.

Freeze features on day 11; spend the last three days on docs, video, and rehearsal.