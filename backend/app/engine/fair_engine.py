import json
import numpy as np
from typing import Dict, Any, List, Tuple
from app.core.config import settings, DATA_DIR
from app.core.graph import DependencyGraph
from app.engine.distributions import sample_pert, sample_poisson, sample_lognormal

# Judgment-based placeholder exploitability priors for findings without CVE IDs (e.g., CSPM / cloud misconfigurations).
# Calibrated as transparent baseline assumptions consistent with how TEF, RTO, and loss priors are documented as
# traceable assumptions elsewhere in the CRISP codebase — these are judgment-based priors, not claimed as EPSS-equivalent precision.
SEVERITY_EXPLOITABILITY_PRIORS = {
    "Critical": 0.60,
    "High": 0.40,
    "Medium": 0.20,
    "Low": 0.05,
    "Info": 0.01
}

class FAIREngine:
    def __init__(self, trials: int = settings.DEFAULT_TRIALS, seed: int = settings.DEFAULT_SEED):
        self.trials = trials
        self.seed = seed

    def _empty_result(self, status: str, message: str, seed: int, org_meta: dict, risk_appetite: float) -> Dict[str, Any]:
        """Returns a structured empty-state result when there is insufficient data to simulate."""
        return {
            "status": status,
            "message": message,
            "eal": None,
            "var95": None,
            "var99": None,
            "tail": None,
            "score": None,
            "drivers": [],
            "curve": [],
            "run_id": None,
            "ts": None,
            "seed": seed,
            "trials": 0,
            "assumptions_version": settings.ASSUMPTIONS_VERSION,
            "org": {
                "name": org_meta.get("name", "Not Configured"),
                "eal": None,
                "var95": None,
                "var99": None,
                "tail": None,
                "score": None,
                "appetite": risk_appetite,
                "headroom": None,
                "data_quality": 0.0
            },
            "loss_breakdown": {},
            "scenario_eals": {},
            "assets": [],
            "services": [],
            "choke_points": [],
            "excluded_assets": [],
            "excluded_assets_count": 0
        }

    def run(self, snapshot: Dict[str, Any], params: Dict[str, Any] = None, seed: int = None) -> Dict[str, Any]:
        """
        Pure, deterministic FAIR Monte Carlo simulation.
        run(snapshot, params, seed) -> RiskResult

        Returns a structured NO_DATA or NO_FINDINGS response if the snapshot
        has no assets or no findings, rather than silently producing ₹0 results.
        """
        active_seed = seed if seed is not None else self.seed
        rng = np.random.default_rng(active_seed)
        num_trials = params.get("trials", self.trials) if params else self.trials

        assets = snapshot.get("assets", [])
        services = snapshot.get("services", [])
        findings = snapshot.get("findings", [])
        cve_intel = snapshot.get("cve_intel", {})
        control_states = snapshot.get("control_state", [])
        scenarios = snapshot.get("scenarios", [])
        org_meta = snapshot.get("organization") or {}
        risk_appetite = org_meta.get("risk_appetite_var95", settings.DEFAULT_RISK_APPETITE)

        # ── Empty-state guards ───────────────────────────────────────────
        # Zero risk and no-data-yet are meaningfully different things.
        # Return a clear structured status instead of running the simulation
        # on empty data or producing misleading ₹0.00 results.
        if len(assets) == 0:
            return self._empty_result(
                status="NO_DATA",
                message="No assets have been ingested yet. Upload an asset inventory to begin risk analysis.",
                seed=active_seed, org_meta=org_meta, risk_appetite=risk_appetite
            )

        if len(findings) == 0:
            return self._empty_result(
                status="NO_FINDINGS",
                message="Assets are loaded, but no vulnerability findings have been ingested yet. Upload a scan report to compute risk.",
                seed=active_seed, org_meta=org_meta, risk_appetite=risk_appetite
            )
        # ─────────────────────────────────────────────────────────────────

        # Build Dependency Graph
        dep_graph = DependencyGraph(services, assets)

        # Build Map of Asset -> Findings
        asset_findings: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            a_id = f["asset_id"]
            if a_id not in asset_findings:
                asset_findings[a_id] = []
            asset_findings[a_id].append(f)

        # Build Control Effectiveness Map: scenario_id -> coverage factor
        # control_reduction = prod_c (1 - e(c,s) * coverage(c))
        control_map = {cs["control_id"]: cs.get("coverage_pct", 0.0) / 100.0 for cs in control_states}

        # Global systemic threat intensity factor G ~ LogNormal(0, 0.45)
        G = sample_lognormal(mean_log=0.0, sigma_log=0.45, size=num_trials, rng=rng)

        # Precompute Base Likelihood & Loss for each asset-scenario pair
        # We accumulate trial loss vectors
        total_trial_losses = np.zeros(num_trials, dtype=np.float64)
        asset_trial_losses: Dict[str, np.ndarray] = {(a.get("id") or a.get("asset_id")): np.zeros(num_trials, dtype=np.float64) for a in assets}
        service_trial_losses: Dict[str, np.ndarray] = {(s.get("id") or s.get("service_id")): np.zeros(num_trials, dtype=np.float64) for s in services}
        scenario_trial_losses: Dict[str, np.ndarray] = {sc["id"]: np.zeros(num_trials, dtype=np.float64) for sc in scenarios}

        # Controls catalog from snapshot or default
        controls_catalog = snapshot.get("controls_catalog")
        if not controls_catalog:
            cat_path = DATA_DIR / "controls_catalog.json"
            if cat_path.exists():
                with open(cat_path, "r", encoding="utf-8") as f:
                    controls_catalog = json.load(f)
            else:
                controls_catalog = []

        # Loss breakdown across categories
        breakdown_totals = {
            "downtime": 0.0,
            "incident_response": 0.0,
            "data_breach": 0.0,
            "regulatory_penalty": 0.0,
            "reputational": 0.0
        }

        # ── Exclude assets with no declared business context (Approach A) ────────
        # Assets auto-created by scan ingestion or missing criticality_1_5 have no
        # known business value. Silently defaulting criticality to 1.0 or assuming
        # revenue would artificially inflate EAL (e.g. ₹20L on unassigned IPs).
        # We strictly identify these assets, exclude them from loss magnitude computation,
        # and surface them in the response for UI transparency.
        excluded_assets = []
        for a in assets:
            a_id = a.get("id") or a.get("asset_id")
            crit_val = a.get("criticality_1_5")
            has_ctx = a.get("has_business_context")
            # Distinct from a genuinely-declared 0 or 1: check for actual None / missing
            if crit_val is None or has_ctx is False:
                excluded_assets.append({
                    "asset_id": a_id,
                    "name": a.get("name", a_id),
                    "criticality": None,
                    "reason": "Missing business context (criticality not declared)"
                })
        excluded_asset_ids = {item["asset_id"] for item in excluded_assets}

        # Simulation Loop over Scenarios and Assets with aligned per-scenario RNG
        for sc_idx, sc in enumerate(scenarios):
            sc_id = sc["id"]
            sc_seed = int((active_seed * 10007 + sc_idx * 9973) % (2**31 - 1))
            rng_sc = np.random.default_rng(sc_seed)

            tef_params = sc.get("tef_params", {"low": 0.1, "likely": 0.3, "high": 0.8})
            tef_samples = sample_pert(tef_params["low"], tef_params["likely"], tef_params["high"], size=num_trials, rng=rng_sc)
            
            # Apply G to correlated TEF
            effective_tef = tef_samples * G

            # Dynamic Control Mitigation from controls_catalog and control_map:
            # Multiplicative reduction based on controls mitigating this scenario
            control_mitigation = 1.0
            for ctrl in controls_catalog:
                if sc_id in ctrl.get("mitigates", []):
                    c_id = ctrl["id"]
                    eff = ctrl.get("effectiveness_dist", {}).get("mean", 0.75)
                    cov = control_map.get(c_id, 0.0)
                    control_mitigation *= (1.0 - (eff * cov))

            # If no specific controls in catalog map to this scenario, default to 1.0 (unmitigated)
            control_mitigation = np.clip(control_mitigation, 0.05, 1.0)

            for a_idx, asset in enumerate(assets):
                a_id = asset.get("id") or asset.get("asset_id")

                # Approach A: Skip loss magnitude computation entirely for assets with no declared business context
                if a_id in excluded_asset_ids:
                    continue

                pair_seed = int((active_seed * 10007 + sc_idx * 9973 + a_idx * 137) % (2**31 - 1))
                rng_pair = np.random.default_rng(pair_seed)

                crit = float(asset["criticality_1_5"])
                is_pub = bool(asset.get("internet_facing") is True)
                svc_id = asset.get("business_service_id")
                raw_records = asset.get("records_count")
                records = int(raw_records) if raw_records is not None else 0

                # Compute asset exploitability P_vuln
                f_list = asset_findings.get(a_id, [])
                if not f_list:
                    # Baseline background exploitability
                    p_vuln_base = 0.02 if not is_pub else 0.08
                else:
                    p_unexploited = 1.0
                    for f in f_list:
                        cve = f.get("cve_id")
                        if cve:
                            intel = cve_intel.get(cve, {})
                            epss_30 = float(intel.get("epss", 0.2))
                            in_kev = intel.get("in_kev", False)
                        else:
                            sev = f.get("severity", "Medium")
                            epss_30 = SEVERITY_EXPLOITABILITY_PRIORS.get(sev, 0.20)
                            in_kev = False

                        # Annualize EPSS
                        p_ann = 1.0 - (1.0 - epss_30) ** 12
                        p_ann = np.clip(p_ann, 0.05, 0.99)
                        if in_kev:
                            p_ann = max(p_ann, 0.85)
                        if is_pub:
                            p_ann = min(0.999, p_ann * 1.3)
                        p_unexploited *= (1.0 - p_ann)
                    p_vuln_base = 1.0 - p_unexploited

                # Residual likelihood for asset-scenario pair
                p_residual = p_vuln_base * control_mitigation
                lambda_pair = float(np.mean(effective_tef)) * p_residual

                # Sample incident count per trial using dedicated pair RNG
                n_events = sample_poisson(lam=lambda_pair, size=num_trials, rng=rng_pair)

                # Compute loss magnitude components
                effective_hourly_rev = dep_graph.compute_asset_effective_revenue_impact(a_id)
                rto = 0.0
                if svc_id:
                    for s in services:
                        if (s.get("id") or s.get("service_id")) == svc_id:
                            rto = float(s.get("rto_hours", 4.0))
                            break

                if rto > 0 and effective_hourly_rev > 0:
                    outage_hours = sample_pert(max(0.5, 0.5 * rto), rto, 3.0 * rto, size=num_trials, rng=rng_pair)
                    downtime_loss = n_events * outage_hours * effective_hourly_rev * 0.75
                else:
                    downtime_loss = np.zeros(num_trials, dtype=np.float64)

                ir_base = sample_pert(500000.0, 1500000.0, 4500000.0, size=num_trials, rng=rng_pair)
                ir_loss = n_events * ir_base * (crit / 3.0)

                data_loss = np.zeros(num_trials, dtype=np.float64)
                reg_penalty = np.zeros(num_trials, dtype=np.float64)
                churn_loss = np.zeros(num_trials, dtype=np.float64)

                if records > 0 and sc_id in ["data_breach", "ransomware", "insider_misuse"]:
                    frac_breached = sample_pert(0.05, 0.20, 0.60, size=num_trials, rng=rng_pair)
                    cost_per_rec = sample_pert(1800.0, 2850.0, 4500.0, size=num_trials, rng=rng_pair)
                    data_loss = n_events * (records * frac_breached) * cost_per_rec

                    penalty_sample = sample_pert(10000000.0, 50000000.0, 350000000.0, size=num_trials, rng=rng_pair)
                    reg_penalty = np.minimum(n_events * penalty_sample, settings.DPDP_PENALTY_CEILING)

                    churn_loss = n_events * (records * frac_breached) * 450.0

                pair_loss = downtime_loss + ir_loss + data_loss + reg_penalty + churn_loss
                total_trial_losses += pair_loss
                asset_trial_losses[a_id] += pair_loss
                scenario_trial_losses[sc_id] += pair_loss
                if svc_id and svc_id in service_trial_losses:
                    service_trial_losses[svc_id] += pair_loss

                # Track breakdown means
                breakdown_totals["downtime"] += float(np.mean(downtime_loss))
                breakdown_totals["incident_response"] += float(np.mean(ir_loss))
                breakdown_totals["data_breach"] += float(np.mean(data_loss))
                breakdown_totals["regulatory_penalty"] += float(np.mean(reg_penalty))
                breakdown_totals["reputational"] += float(np.mean(churn_loss))

        # Core Metrics Aggregation
        eal = float(np.mean(total_trial_losses))
        var95 = float(np.percentile(total_trial_losses, 95))
        var99 = float(np.percentile(total_trial_losses, 99))
        tail_losses = total_trial_losses[total_trial_losses >= var95]
        tail_loss = float(np.mean(tail_losses)) if len(tail_losses) > 0 else var95

        # Headroom vs Risk Appetite
        headroom = float(risk_appetite - var95)

        # Risk Score (0-100): Log scale normalized relative to risk appetite
        # 100 = catastrophic (> 2x appetite), 50 = at appetite, 0 = negligible
        ratio = var95 / max(1.0, risk_appetite)
        score = int(np.clip(np.round(50.0 + 35.0 * np.log2(max(0.1, ratio))), 0, 100))

        # Loss Exceedance Curve Points: P(Loss > x) vs x
        sorted_losses = np.sort(total_trial_losses)
        percentile_levels = np.linspace(0.01, 0.99, 50)
        curve_points = []
        for p in percentile_levels:
            val = float(np.percentile(sorted_losses, p * 100))
            prob_exceed = round(1.0 - p, 4)
            curve_points.append([round(val, 2), prob_exceed])

        # Leave-One-Out (LOO) Marginal EAL for Top Vulnerability Risk Drivers
        drivers = []
        for f in findings:
            f_cve = f.get("cve_id")
            f_asset_id = f.get("asset_id")
            intel = cve_intel.get(f_cve, {}) if f_cve else {}
            # Marginal contribution approximation based on asset share and exploitability
            asset_eal = float(np.mean(asset_trial_losses.get(f_asset_id, np.zeros(1))))
            f_sev = f.get("severity")
            epss_val = intel.get("epss") if intel else None
            if epss_val is None:
                epss_val = SEVERITY_EXPLOITABILITY_PRIORS.get(f_sev, 0.20) if f_sev else 0.20
            in_kev = intel.get("in_kev", False)
            weight = epss_val * (1.5 if in_kev else 1.0)
            marginal_eal = round(asset_eal * min(0.9, weight * 0.75), 2)
            # For non-CVE findings (e.g. CSPM / cloud misconfigurations), use the finding's own 'id' field
            driver_id = f_cve or f.get("id") or "UNKNOWN-FINDING"
            raw_cvss = f.get("cvss")
            cvss_val = float(raw_cvss) if raw_cvss is not None else 0.0
            drivers.append({
                "type": "finding",
                "id": driver_id,
                "finding_id": f.get("id"),
                "asset_id": f_asset_id,
                "asset_name": next((a.get("name") or a.get("id") for a in assets if (a.get("id") or a.get("asset_id")) == f_asset_id), f_asset_id),
                "cvss": cvss_val,
                "severity": f.get("severity", "High"),
                "epss": epss_val,
                "in_kev": in_kev,
                "marginal_eal": marginal_eal
            })

        drivers.sort(key=lambda x: x["marginal_eal"], reverse=True)

        # Asset-level summary
        asset_summaries = []
        for a in assets:
            a_id = a.get("id") or a.get("asset_id")
            a_loss = asset_trial_losses.get(a_id, np.zeros(1))
            a_eal = float(np.mean(a_loss))
            is_excluded = a_id in excluded_asset_ids
            if a_eal > 0 or a.get("is_real_lab_asset", False) or is_excluded:
                asset_summaries.append({
                    "asset_id": a_id,
                    "name": a.get("name", a_id),
                    "criticality": a.get("criticality_1_5"),
                    "service_id": a.get("business_service_id"),
                    "eal": round(a_eal, 2),
                    "var95": round(float(np.percentile(a_loss, 95)), 2),
                    "is_real_lab_asset": a.get("is_real_lab_asset", False),
                    "excluded_from_eal": is_excluded,
                    "has_business_context": not is_excluded
                })
        asset_summaries.sort(key=lambda x: x["eal"], reverse=True)

        # Service-level summary
        service_summaries = []
        for s in services:
            s_id = s.get("id") or s.get("service_id")
            s_loss = service_trial_losses.get(s_id, np.zeros(1))
            service_summaries.append({
                "service_id": s_id,
                "name": s["name"],
                "revenue_per_hour": float(s.get("revenue_per_hour") or 0.0),
                "eal": round(float(np.mean(s_loss)), 2),
                "var95": round(float(np.percentile(s_loss, 95)), 2)
            })
        service_summaries.sort(key=lambda x: x["eal"], reverse=True)

        # Choke Points
        choke_points = dep_graph.identify_choke_points(top_n=5)

        # Data quality score: Real lab asset ratio and scan freshness
        real_assets_count = sum(1 for a in assets if a.get("is_real_lab_asset", False))
        data_quality = round((real_assets_count / max(1, len(assets)) * 0.4) + 0.55, 2)

        # Scenario-level exact EAL mapping
        scenario_eals = {
            sc_id: round(float(np.mean(sc_losses)), 2)
            for sc_id, sc_losses in scenario_trial_losses.items()
        }

        return {
            "run_id": f"RUN-{active_seed}-{int(np.sum(total_trial_losses[:5])) % 100000:05d}",
            "ts": snapshot.get("timestamp"),
            "seed": active_seed,
            "trials": num_trials,
            "assumptions_version": settings.ASSUMPTIONS_VERSION,
            "org": {
                "name": org_meta.get("name", "Apex FinCorp Ltd."),
                "eal": round(eal, 2),
                "var95": round(var95, 2),
                "var99": round(var99, 2),
                "tail": round(tail_loss, 2),
                "score": score,
                "appetite": risk_appetite,
                "headroom": round(headroom, 2),
                "data_quality": data_quality
            },
            "loss_breakdown": {k: round(v, 2) for k, v in breakdown_totals.items()},
            "scenario_eals": scenario_eals,
            "drivers": drivers,
            "curve": curve_points,
            "assets": asset_summaries[:15],
            "services": service_summaries,
            "choke_points": choke_points,
            "excluded_assets": excluded_assets,
            "excluded_assets_count": len(excluded_assets)
        }
