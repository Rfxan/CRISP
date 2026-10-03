# CRISP — Continuous Risk & Investment Simulation Platform
> **Cyber risk estimates and investment scenarios with inspectable assumptions.**  
> *Developed for Problem Statement SIH 26105: AI-Powered Continuous Cyber Risk Quantification & Investment Optimization Platform*

[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg)](https://react.dev/)
[![Tests](https://img.shields.io/badge/Tests-Passing-success.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

---

## Current model and deployment

For the Vercel frontend connected to the Render backend, see [Vercel deployment](docs/VERCEL_DEPLOYMENT.md). Both repository-root and `frontend`-root Vercel projects proxy `/api` requests to Render.

For a separate Render backend, see [Render deployment](docs/RENDER_DEPLOYMENT.md). The root Blueprint configures a free Docker web service and a free PostgreSQL evaluation database that expires after 30 days.

[Deploy backend and database to Render](https://render.com/deploy?repo=https%3A%2F%2Fgithub.com%2FRfxan%2FCRISP)

Hosted deployments are public interactive sandboxes: each browser gets its own
24-hour workspace without signing in. Uploads, saved assumptions, scenarios and
integration configuration stay isolated between visitors. Sample data is loaded
only on request. See [security configuration and limits](docs/SECURITY.md).

Read [Risk model and deployment contract](docs/RISK_MODEL_AND_DEPLOYMENT.md) for calculation assumptions, evidence rules, direct workspace access, persistent transactional storage, worker setup and remaining limits. Financial estimates are uncalibrated planning estimates; curated mappings are not regulatory certification. The API no longer starts background schedulers: run `python -m app.worker` separately.

For real alert-based anomaly detection, configure **Alert Telemetry (Wazuh Indexer)** under Connectors as well as the Manager connection. See [Wazuh Indexer setup](docs/WAZUH_INDEXER.md) for credentials, networking and the hourly baseline.

## 1. Executive Summary

Enterprises invest heavily in cybersecurity, yet risk is still reported in qualitative labels (*High, Medium, Low*) or isolated CVSS numbers that board members and financial officers cannot translate into budget decisions. 

**CRISP** continuously quantifies cyber risk in **Indian Rupees (₹)**:
1. **Continuous Telemetry Ingestion**: Correlates real vulnerability scans (OpenVAS), endpoint agent telemetry (Wazuh), and live threat intelligence (FIRST EPSS, CISA KEV).
2. **FAIR Monte Carlo Engine**: Runs a configurable seeded simulation (5,000 trials in the API) simulating downtime, incident response, customer PII data breaches, DPDP statutory penalties (bounded at ₹250 Cr), and reputational churn.
3. **Integer Linear Programming (ILP) Optimizer**: Selects investments using an additive ILP approximation. Evaluates every strategy through the same counterfactual simulator and reports reproducible, dataset-specific benefits; outperformance is not guaranteed.
4. **Counterfactual What-If Sandbox**: Tests control investments on the same random seed and computes a **Cost of Delay** metric (₹ Lakhs per week of inaction).
5. **Indian Regulatory Compliance Hub**: Tracks readiness for the **SEBI CSCRF 6-hour incident reporting mandate**, DPDP Act 2025 safeguards, and exports audit evidence reports.
6. **Grounded AI Decision Support**: Selects structured metric references and values, validates them against computed results, and renders server-controlled numerical statements. Invalid model output falls back to computed facts.

---

## 2. Quick Start Guide

### Option A: One-Command Deployment (Docker Compose)
Ensure Docker and Docker Compose are installed, then run:
```bash
docker-compose up --build
```
- **Web Dashboard**: [http://localhost:5173](http://localhost:5173)
- **FastAPI Interactive Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

### Option B: Local Development Setup

#### 1. Start Backend (FastAPI)
```bash
# In project root
python -m pip install -r backend/requirements.txt
python -m uvicorn app.main:app --app-dir backend --reload --port 8000
```
*Backend runs on http://localhost:8000.*

#### 2. Start Frontend (React + Vite)
```bash
# In frontend directory
cd frontend
npm install
npm run dev
```
*Frontend runs on http://localhost:5173.*

#### 3. Run Automated Validation Test Suite
```bash
python -m pytest backend/tests -v
```

---

## 3. The 3-Minute Live Demo Script (PRD Section 19.1)

Follow this step-by-step path to demonstrate CRISP:

| Timestamp | Screen | Action & What to Demonstrate |
| :--- | :--- | :--- |
| **0:00 - 0:30** | **Executive Overview** | Point to the Hero KPIs: **EAL** and **VaR95** in Rupees. Highlight the **Board Risk Appetite Alert** (exposure exceeds tolerance). Review the **Loss Exceedance Curve** and 30/60/90-day trajectory. |
| **0:30 - 0:50** | **AI Decision Support** | Click the suggested chip: *"What is our highest financial cyber risk today?"* Inspect the validated metric references and **Run ID** in the response. |
| **0:50 - 1:10** | **Technical Drill-Down** | Inspect **High-Centrality Choke Points** on the dependency graph (`pay-db-primary`). Review the **Vulnerability Remediation Backlog** sorted by **Marginal EAL (₹)** with EPSS and CISA KEV badges. |
| **1:10 - 1:30** | **What-If Sandbox** | Click *"Enforce MFA on All Privileged & DB Accounts"*. Watch EAL drop by ~₹45 Crore on the identical seed. Point out the **Cost of Delay Metric** (*"₹86.9 Lakhs lost per week of inaction"*). |
| **1:30 - 2:10** | **Investment Optimizer** | Set budget slider to **₹1 Crore**. Point to the **Headline Benchmark Panel**: Compare simulated residual EAL across all strategies, inspect the dataset/assumptions/seed, and replay the selected actions. The investment curve is a sampled set of portfolios, not a guaranteed optimal frontier. |
| **2:10 - 2:40** | **Live 0-Day Event Demo** | Click the red button in topbar: **"⚡ Demo 0-Day Injection"**. Ingest a new KEV-listed zero-day onto the Payment Gateway. Watch exposure surge instantly, triggering a live recalibration alert! |
| **2:40 - 3:00** | **Compliance Hub** | Open Compliance view. Check the **SEBI CSCRF 6-Hour Reporting Readiness gauge** (81.5% READY). Click **"Export Audit Evidence Report"** to open a print-ready audit document. Conclude: *"Not a risk score. A budget decision, with the proof."* |

---

## 4. API Contract Summary (PRD Section 11)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/risk/summary` | Returns EAL, VaR95, VaR99, risk score, appetite headroom, and trend |
| `GET` | `/api/risk/entities?level=asset` | Returns risk breakdown per asset, service, or business unit |
| `GET` | `/api/risk/drivers` | Returns top risk drivers ranked by marginal EAL contribution |
| `GET` | `/api/risk/curve` | Returns 50 loss exceedance curve coordinates $P(L > x)$ |
| `POST` | `/api/simulate` | Clones snapshot, applies counterfactual actions, and computes delta & cost of delay |
| `POST` | `/api/optimize` | Solves budget-constrained ILP and returns recommended actions & baseline benchmark |
| `GET` | `/api/pareto` | Sweeps budgets from ₹10L to ₹5Cr and identifies diminishing-returns knee point |
| `GET` | `/api/compliance/{framework}` | Returns coverage %, gaps, and SEBI 6-hour & DPDP readiness |
| `GET` | `/api/report/{framework}` | Exports audit-ready printable HTML evidence report |
| `POST` | `/api/ask` | Grounded tool-calling Q&A interface citing Run ID and assumptions |
| `POST` | `/api/demo/inject-event` | Injects zero-day vulnerability onto asset and updates exposure dynamically |
| `GET` | `/api/health/data-quality` | Reports telemetry freshness and real-vs-simulated data ratio |

---

## 5. Data Transparency & Honesty Split

In accordance with PRD Section 4.2 & 12:
- **Real Lab Data**: Vulnerability scan reports from OpenVAS / Greenbone Community Edition; endpoint telemetry and active agents (114 nodes) from Wazuh Manager; threat feeds from FIRST EPSS and CISA KEV.
- **Simulated Organization**: Fictional Indian NBFC (*Apex FinCorp Ltd.*) with ~120 assets, ₹450 Cr revenue, customer PII records, and IAM coverage numbers. All simulated elements are explicitly labeled with orange **"SIMULATED"** badges in the UI.

---

## 6. Architecture & Deliverables

- **2-Page Architecture Document**: [`CRISP_Architecture_Document.md`](file:///c:/Users/RYAN/Documents/CRISP/CRISP_Architecture_Document.md)
- **Original PRD Reference**: [`CRISP_PRD.docx`](file:///c:/Users/RYAN/Documents/CRISP/CRISP_PRD.docx) & [`CRISP_PRD.md`](file:///c:/Users/RYAN/Documents/CRISP/CRISP_PRD.md)
- **Automated Test Suite**: [`backend/tests/`](file:///c:/Users/RYAN/Documents/CRISP/backend/tests)
