# CRISP Modeling Choices: Architecture & Methodology Rationales

This document outlines the design decisions and quantitative principles governing CRISP. It directly answers the question: **"Where is Machine Learning used, where is it deliberately excluded, and why?"**

---

### Core Principle
> **"ML where ML is the right tool; calibrated statistics where data is sparse."**

---

### 1. Loss Quantification: FAIR + Monte Carlo (Why Not Deep Learning?)

CRISP deliberately avoids end-to-end deep neural networks or black-box regression for enterprise loss quantification ($EAL$ and $VaR_{95}$).

1. **Extreme Data Sparsity**: 
   - An individual enterprise experiences major cybersecurity breach events infrequently ($0$ to $2$ catastrophic incidents per decade).
   - High-capacity neural networks trained on sparse enterprise loss datasets drastically overfit, memorizing noise and hallucinating precision.
2. **Auditability & Explainability (Open FAIR Standard)**:
   - Financial regulators (e.g., SEBI CSCRF, RBI Cyber Security Framework, SEC Form 8-K) and corporate boards require auditable causal decomposition.
   - The Open FAIR (Factor Analysis of Information Risk) standard decomposes cyber risk into explicit, inspectable components:
     $$\text{Risk} = \text{Loss Event Frequency (LEF)} \times \text{Loss Magnitude (LM)}$$
     Where:
     - $\text{LEF} = f(\text{Threat Event Frequency}, \text{Threat Capability}, \text{Control Resistance})$
     - $\text{LM} = \text{Primary Loss} + \text{Secondary Loss} = f(\text{Productivity Loss}, \text{Response Cost}, \text{Replacement Cost}, \text{Fines}, \text{Reputation})$
   - Every input parameter (PERT distribution minima, modes, maxima) is traceable to verifiable business context (e.g., revenue/hr, records count, asset criticality).
3. **Seeded Determinism & Exact Reproducibility**:
   - Neural inference introduces non-deterministic sampling drift across deployments.
   - CRISP's Monte Carlo engine runs with an explicitly seeded pseudo-random generator (`seed=42`, $5,000$ trials).
   - Re-running the engine on the exact same snapshot reproduces every percentile ($EAL$, $VaR_{95}$, $VaR_{99}$) to the exact paisa/cent.

---

### 2. Where Machine Learning Genuinely Is Used

Machine learning is deployed exclusively where high-volume, empirical training telemetry exists and objective ground truth is observable:

1. **FIRST EPSS (Exploit Prediction Scoring System)**:
   - **Model**: Regularized Logistic Regression model trained and maintained by the FIRST EPSS Special Interest Group (*Jacobs et al., 2021*).
   - **Data Ground Truth**: Real-world threat intelligence telemetry aggregated from millions of network sensors, honeypots, and CISA KEV detections.
   - **Role in CRISP**: Rather than guessing vulnerability weaponization, CRISP ingests live EPSS scores to empirically scale threat exploitability priors ($p \in [0.0, 1.0]$).
2. **Isolation Forest Behavioral Anomaly Detector (`backend/app/ai/anomaly.py`)**:
   - **Model**: Unsupervised tree ensemble (`IsolationForest` via `scikit-learn`).
   - **Features per Time Window**: 3-dimensional per-agent vector:
     1. `event_volume`: Raw event throughput per observation window.
     2. `auth_failure_rate`: $\frac{\text{auth\_failures}}{\max(1, \text{event\_volume})}$.
     3. `alert_severity_mix`: $\frac{\text{high\_severity\_alerts}}{\max(1, \text{total\_alerts})}$.
   - **Honest Cold-Start Handling**: With fewer than 5 observation windows, the model refrains from scoring and honestly reports `"insufficient baseline data"` rather than emitting specious outlier flags.
   - **Signal Layer Boundary**: Kept strictly **OUT** of the deterministic FAIR loss engine core. It operates exclusively as an emerging-threat signal layer in the Ingestion Hub and Risk Drivers, explicitly labeled:
     > *"unsupervised anomaly (IsolationForest), not a confirmed incident"*

---

### 3. LLM Governance Boundary: Explanation-Only, Never Calculation

The Large Language Model (LLM) layer in CRISP is an **interactive natural language explanatory interface**, strictly isolated from the quantitative computation path.

#### Grounding Mechanism
- The LLM does not perform math. It is provided a structured, read-only payload containing the computed engine run (`run_id`, $EAL$, $VaR_{95}$, top 3 risk drivers, control catalog metadata, and PuLP optimizer allocations).
- Every statement generated cites the deterministic `run_id` and underlying parameter values.

#### Forbidden Actions (Hard System Constraints)
The LLM is strictly prohibited from:
- **Calculating or modifying numbers**: It cannot compute, invent, or adjust $EAL$, $VaR$, or control costs.
- **Inventing threats or vulnerabilities**: It cannot hallucinate CVEs, MITRE ATT&CK techniques, or asset criticality ratings.
- **Modifying optimization allocations**: Recommended mitigation bundles are solved exclusively via Mixed Integer Linear Programming (PuLP/CBC solver); the LLM only translates the solver output into executive narratives.
- **Overriding compliance evaluations**: Compliance statuses (`PASS`, `FAIL`, `PARTIAL`) are determined strictly by rule-based evaluation matrices against SEBI/NIST controls.

---

### 4. Architecture Modeling Summary

| Platform Component | Underlying Methodology | Justification |
| :--- | :--- | :--- |
| **Loss Quantification** | Open FAIR + Monte Carlo ($5,000$ trials, `seed=42`) | Solves data sparsity; guarantees mathematical auditability and seeded reproducibility. |
| **Vulnerability Weaponization** | FIRST EPSS (Empirical Logistic Regression) | Utilizes global telemetry from real exploitation sensors instead of subjective severity scores. |
| **Telemetry Anomaly Detection** | Isolation Forest (Unsupervised Ensemble) | Identifies operational deviations in high-frequency SIEM/EDR logs without requiring labeled breach data. |
| **Remediation Optimization** | Mixed-Integer Linear Programming (PuLP / CBC Branch-and-Cut) | Mathematical guarantee of globally optimal risk reduction within strict budgetary limits. |
| **Risk Trajectory (30/60/90d)** | Holt's Linear Exponential Smoothing + 95% CI | Fits historical engine run epochs ($N \ge 3$); falls back to linear trend ($N=2$) or insufficient history ($N < 2$). Never fabricates curves. |
| **Executive AI Co-Pilot** | `run_id`-Grounded LLM Prompt Pipeline | Constrained to narrative explanation; forbidden from computing or modifying numeric state. |
