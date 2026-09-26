# CRISP Architecture Document
**Continuous Risk & Investment Simulation Platform (SIH 26105)**  
*Version 1.0 | September 2026*

---

## PAGE 1: SYSTEM ARCHITECTURE & DATA FLOW

### 1. High-Level Architecture Diagram

```
 +-----------------------------------------------------------------------------------+
 |                             INGESTION & TELEMETRY LAYER                           |
 |  +-----------------------+  +-----------------------+  +------------------------+ |
 |  | OpenVAS / Greenbone   |  | Wazuh Manager Telemetry| | Public Threat Feeds    | |
 |  | (Real Lab Scans)      |  | (114 Endpoints, Alerts)| | (NVD, FIRST EPSS, KEV) | |
 |  +-----------+-----------+  +-----------+-----------+  +-----------+------------+ |
 |              |                          |                          |              |
 |              +--------------------------+--------------------------+              |
 |                                         v                                         |
 |                          +------------------------------+                         |
 |                          | Canonical Snapshot Store     |                         |
 |                          | (Versioned JSON Snapshots)   |                         |
 |                          +--------------+---------------+                         |
 +-----------------------------------------|-----------------------------------------+
                                           v
 +-----------------------------------------------------------------------------------+
 |                             CORE DETERMINISTIC ENGINE                             |
 |  +--------------------+  +----------------------+  +----------------------------+ |
 |  | Asset-Service      |  | FAIR Likelihood &    |  | Vectorized Monte Carlo     | |
 |  | Dependency Graph   |  | Loss Models (PERT)   |  | (10,000 NumPy Trials)      | |
 |  | (NetworkX Centrality)|  | (DPDP ₹250 Cr Cap)  |  | (Global Correlated Tail G) | |
 |  +--------------------+  +----------------------+  +----------------------------+ |
 |                                         |                                         |
 |                                         v                                         |
 |                          +------------------------------+                         |
 |                          | PuLP Integer Linear Program  |                         |
 |                          | (Budget Optimizer & Pareto)  |                         |
 |                          +--------------+---------------+                         |
 +-----------------------------------------|-----------------------------------------+
                                           v
 +-----------------------------------------------------------------------------------+
 |                              APPLICATION & API LAYER                              |
 |  FastAPI REST Server:                                                             |
 |  • /risk/summary  • /risk/drivers  • /risk/curve  • /simulate  • /optimize         |
 |  • /pareto  • /compliance/{framework}  • /report/{framework}  • /ask  • /health  |
 +-----------------------------------------|-----------------------------------------+
                                           v
 +-----------------------------------------------------------------------------------+
 |                                 USER EXPERIENCE                                   |
 |  React + Vite Cyber Dashboard:                                                    |
 |  1. Executive Overview (EAL, VaR95, Headroom, Exceedance Curve, Trend)            |
 |  2. Technical Drilldown (Choke Points, Vulnerabilities Ranked by Marginal EAL)    |
 |  3. Investment Optimizer (Headline Benchmark vs CVSS, Action Cards, Pareto Knee)  |
 |  4. What-If Simulator (Counterfactual Sandboxing & Cost of Delay Metric)          |
 |  5. Compliance Hub (SEBI CSCRF 6-Hour Readiness, DPDP Safeguards, HTML Reports)   |
 |  6. Grounded Decision Support AI (Tool-calling without hallucinations)            |
 +-----------------------------------------------------------------------------------+
```

### 2. Data Flow & Transparency Split

| Data Stream | Source | Real vs. Simulated | Role in Engine |
| :--- | :--- | :--- | :--- |
| **Vulnerability Telemetry** | OpenVAS / Greenbone Community Edition | **REAL LAB DATA** | Identifies active CVEs, CVSS vectors, and service ports |
| **Endpoint Telemetry** | Wazuh Manager REST API / Alert Stream | **REAL LAB DATA** | Heartbeat coverage (114 agents), FIM, and auth failures |
| **Threat Intelligence** | FIRST.org EPSS & CISA KEV Catalog | **LIVE / CACHED** | Annualized exploitation likelihood $p_v$ and KEV uplift |
| **Asset & Business Graph** | Apex FinCorp Inventory (~120 assets) | **SIMULATED** | Fictional Indian NBFC with revenue and customer PII |
| **Identity Posture (IAM)** | Active Directory / Azure AD Connector Mock | **SIMULATED** | Privileged account count and MFA coverage percentages |

---

## PAGE 2: MATHEMATICAL MODELS, OPTIMIZATION & VALIDATION

### 3. Core FAIR Mathematical Formulations

#### Likelihood Model (Annual Incident Frequency $\lambda$)
For each asset $a$ and loss scenario $s$:
$$\lambda(a, s) = TEF(s) \times P_{vuln}(a, s) \times \prod_c \Big(1 - e(c, s) \times \text{coverage}(c, a)\Big)$$
- **Threat Event Frequency**: $TEF(s) \sim PERT(min, likely, max)$ calibrated from industry threat reports.
- **Vulnerability Exploitability**: Annualized from 30-day EPSS: $p_v = 1 - (1 - p_{30})^{12}$ with a floor of $0.85$ for CISA KEV listings and a $1.3\times$ multiplier for internet-facing systems.
- **Correlated Tail Factor**: $G \sim LogNormal(0, \sigma=0.45)$ applied across trials to reflect systemic campaigns.

#### Loss Magnitude Model ($L_{event}$)
Each incident trial evaluates five fat-tailed components:
$$L_{total} = L_{downtime} + L_{IR} + L_{breach} + L_{regulatory} + L_{reputational}$$
1. **Downtime Loss**: $outage\_hours \times \big(own\_rev(a) + \sum_{s \in dep(a)} service\_rev(s)\big) \times 0.75$, with outage hours bounded by RTO.
2. **Incident Response & Forensics**: $PERT(₹5L, ₹15L, ₹45L) \times \frac{criticality}{3.0}$.
3. **Data Breach Cost**: $records\_breached \times PERT(₹1,800, ₹2,850, ₹4,500)$ per compromised record.
4. **DPDP Statutory Penalties**: Sampled from judicial range and strictly bounded by the statutory ceiling of **₹250 Crore** (Section 8(5)).
5. **Reputational Churn**: Customer attrition evaluated against lifetime value (LTV).

### 4. Integer Linear Programming (ILP) Optimizer Formulation
To allocate budget $B$ across security controls $x_c \in \{0, 1\}$ and vulnerability patches $z_v \in \{0, 1\}$:
$$\max \sum_{s} base\_EAL_s \times \sum_{c} e(c,s) y_{c,s} + \sum_{v} marginal\_EAL_v \times z_v$$
**Subject to:**
- Budget Constraint: $\sum_c (capex_c + opex_c) x_c + \sum_v patch\_cost_v z_v \le B$
- Best Control Wins: $\sum_c y_{c,s} \le 1$ and $y_{c,s} \le x_c$ (prevents over-crediting overlapping controls)
- Binary Bounds: $x_c \in \{0, 1\}, y_{c,s} \in \{0, 1\}, z_v \in \{0, 1\}$

### 5. Verification & Validation Metrics
- **Determinism**: Identical $(snapshot, params, seed)$ produces bit-identical results in $<0.80$ seconds for 10,000 trials.
- **Benchmark Proof**: CRISP ILP achieves **+142.4% higher risk reduction** than naive CVSS prioritization under the identical ₹1 Crore budget.
- **SEBI CSCRF Readiness**: Automated continuous verification of 6-hour incident reporting telemetry (SIEM, EDR, CERT-In retainer).
