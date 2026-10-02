# CRISP modeling choices

The current calculation and deployment contract is documented in [Risk model and deployment contract](RISK_MODEL_AND_DEPLOYMENT.md). It supersedes prior claims of calibrated asset probabilities, guaranteed nonlinear optimization or prompt-only numerical guarantees.

| Component | Method | Interpretation |
| --- | --- | --- |
| Financial loss | Seeded Monte Carlo with explicit frequency, susceptibility and loss assumptions | Judgment-based planning estimates requiring organization calibration |
| Exploitation signal | FIRST EPSS and CISA KEV inputs | Global signals, combined with exposure and scenario relevance; not asset-compromise probabilities |
| Systemic risk | Per-trial shared lognormal intensity | Preserves modeled dependence across incidents |
| Finding benefit | Paired removal simulations for a screened candidate set | A specific asset/finding benefit; interactions prevent simple additivity |
| Investment selection | Additive ILP surrogate | Budget feasible; portfolio benefit evaluated by the shared simulator |
| Anomaly detection | Isolation Forest | An unsupervised signal, not a confirmed incident or calibrated loss predictor |
| Natural language | Validated structured metric selection and server-rendered facts | Rejects unknown references and mismatched numbers; does not promise unrestricted narrative accuracy |
| Compliance | Evidence freshness, applicability and reviewer decisions | Curated requirement subsets; separate from mapping and telemetry coverage |

Annual-loss percentiles describe modeled annual variability. Input ranges, sensitivity results and Monte Carlo error are distinct from a calibrated confidence interval on expected loss. Reproducibility depends on the same snapshot, model, assumptions, seed, trial count and compatible numerical dependencies.
