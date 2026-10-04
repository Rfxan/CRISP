import copy
import json
import numpy as np
from app.core.config import settings, DATA_DIR
from app.core.graph import DependencyGraph
from app.engine.loss_metrics import expected_shortfall, exceedance_curve
from app.engine.distributions import sample_pert, sample_poisson
from app.engine.model import MODEL_VERSION, assumptions, digest, stable_seed, finding_key

SEVERITY_EXPLOITABILITY_PRIORS = {"Critical": .10, "High": .05, "Medium": .02, "Low": .005, "Info": .001}


class FAIREngine:
    def __init__(self, trials=settings.DEFAULT_TRIALS, seed=settings.DEFAULT_SEED):
        self.trials, self.seed = trials, seed

    def _empty_result(self, status, message, seed, org, appetite):
        return {"status": status, "message": message, "eal": None, "var95": None, "var99": None,
            "tail": None, "score": None, "drivers": [], "curve": [], "run_id": None, "ts": None,
            "seed": seed, "trials": 0, "model_version": MODEL_VERSION, "assumptions_version": "5.0",
            "org": {"name": org.get("name", "Not Configured"), "eal": None, "var95": None, "var99": None,
                    "tail": None, "score": None, "appetite": appetite, "headroom": None, "data_quality": 0},
            "loss_breakdown": {}, "scenario_eals": {}, "assets": [], "services": [],
            "choke_points": [], "excluded_assets": [], "excluded_assets_count": 0}

    @staticmethod
    def relevance(finding, scenario, config):
        if "scenario_ids" in finding:
            return float(scenario["id"] in finding["scenario_ids"])
        kind = finding.get("vulnerability_type") or finding.get("issue_type")
        return 1. if kind and kind in scenario.get("applicable_vulns", []) else config["unknown_scenario_relevance"]

    def run(self, snapshot, params=None, seed=None):
        params = params or {}
        seed = self.seed if seed is None else seed
        trials = int(params.get("trials", self.trials))
        if not 1 <= trials <= 100000:
            raise ValueError("Trials must be between 1 and 100000")
        cfg = assumptions(snapshot)
        org = snapshot.get("organization") or {}
        appetite = org.get("risk_appetite_var95", settings.DEFAULT_RISK_APPETITE)
        assets = sorted(snapshot.get("assets", []), key=lambda a: str(a.get("id") or a.get("asset_id")))
        if params.get("asset_scope") is not None:
            assets = [a for a in assets if (a.get("id") or a.get("asset_id")) == params["asset_scope"]]
        findings = [f for f in snapshot.get("findings", []) if not f.get("is_patched")]
        scan_status = snapshot.get("assessment_state", {}).get("status")
        if not assets:
            return self._empty_result("NO_DATA", "No assets have been ingested.", seed, org, appetite)
        if not findings and scan_status not in ("completed", "remediated"):
            return self._empty_result("NO_FINDINGS", "No completed scan evidence is available.", seed, org, appetite)
        services = snapshot.get("services", [])
        scenarios = sorted(snapshot.get("scenarios", []), key=lambda s: s["id"])
        if not scenarios:
            return self._empty_result("NO_SCENARIOS", "No incident scenarios are configured.", seed, org, appetite)
        catalog = snapshot.get("controls_catalog")
        if catalog is None:
            with open(DATA_DIR / "controls_catalog.json", encoding="utf-8") as f:
                catalog = json.load(f)
        controls = {c["control_id"]: c for c in snapshot.get("control_state", [])}
        graph = DependencyGraph(services, assets)
        excluded = [{"asset_id": a.get("id") or a.get("asset_id"), "name": a.get("name"), "criticality": None,
                     "reason": "Missing declared business context"}
                    for a in assets if a.get("criticality_1_5") is None or a.get("has_business_context") is False]
        excluded_ids = {a["asset_id"] for a in excluded}
        if len(excluded_ids) == len(assets):
            r = self._empty_result("INSUFFICIENT_CONTEXT", "All assets lack business context; exposure is unknown.", seed, org, appetite)
            r.update(excluded_assets=excluded, excluded_assets_count=len(excluded))
            r["assets"] = [{"asset_id": a.get("id") or a.get("asset_id"), "name": a.get("name"),
                "criticality": None, "eal": None, "var95": None, "excluded_from_eal": True,
                "has_business_context": False} for a in assets]
            return r
        rng = np.random.default_rng(stable_seed(seed, "systemic"))
        sigma = cfg["systemic_sigma"]
        systemic = rng.lognormal(-sigma*sigma/2, sigma, trials)
        asset_losses = {(a.get("id") or a.get("asset_id")): np.zeros(trials) for a in assets}
        service_losses = {(s.get("id") or s.get("service_id")): np.zeros(trials) for s in services}
        scenario_losses = {s["id"]: np.zeros(trials) for s in scenarios}
        breakdown = {k: 0. for k in ("downtime", "incident_response", "data_breach", "regulatory_penalty", "reputational")}
        by_asset = {}
        for f in findings:
            by_asset.setdefault(f["asset_id"], []).append(f)
        service_map = {(s.get("id") or s.get("service_id")): s for s in services}
        likelihood_inputs = []
        for sc in scenarios:
            srng = np.random.default_rng(stable_seed(seed, sc["id"], "frequency"))
            tef = sample_pert(**sc.get("tef_params", {"low": .1, "likely": .3, "high": .8}), size=trials, rng=srng)
            mitigation = 1.
            for ctrl in catalog:
                if sc["id"] not in ctrl.get("mitigates", []):
                    continue
                state = controls.get(ctrl["id"], {})
                cov = (state.get("coverage_pct") or 0)/100
                if state.get("evidence_ref") == "Not Connected" and not state.get("is_user_assumed"):
                    cov = 0
                eff = np.clip(ctrl.get("effectiveness_dist", {}).get("mean", .75)*cfg["control_effectiveness_multiplier"], 0, 1)
                mitigation *= 1-eff*np.clip(cov, 0, 1)
            for asset in assets:
                aid = asset.get("id") or asset.get("asset_id")
                if aid in excluded_ids:
                    continue
                exposure = asset.get("exposure_probability")
                if exposure is None:
                    exposure = cfg["public_exposure"] if asset.get("internet_facing") else cfg["internal_exposure"]
                if not 0 <= exposure <= 1:
                    raise ValueError("Asset exposure_probability must be between 0 and 1")
                remaining = 1.
                for f in by_asset.get(aid, []):
                    intel = snapshot.get("cve_intel", {}).get(f.get("cve_id"), {})
                    epss = intel.get("epss")
                    signal = cfg["missing_epss_prior"] if epss is None else float(epss)
                    if not f.get("cve_id"):
                        signal = SEVERITY_EXPLOITABILITY_PRIORS.get(f.get("severity"), cfg["missing_epss_prior"])
                    # EPSS is a global 30-day signal. TEF is annual; this susceptibility
                    # mapping is explicit and uncalibrated, not annualized EPSS.
                    weight = np.clip(signal*exposure*self.relevance(f, sc, cfg)*(cfg["kev_multiplier"] if intel.get("in_kev") else 1), 0, 1)
                    remaining *= 1-weight
                susceptibility = 1-(1-cfg["background_probability"]*exposure)*remaining
                rate = tef*systemic*susceptibility*mitigation*cfg["likelihood_multiplier"]
                events = sample_poisson(rate, trials, np.random.default_rng(stable_seed(seed, sc["id"], aid, "events")))
                prng = np.random.default_rng(stable_seed(seed, sc["id"], aid, "magnitude"))
                svc = service_map.get(asset.get("business_service_id"), {})
                rto = float(svc.get("rto_hours") or 0)
                downtime = events*sample_pert(.5*rto, rto, 3*rto, trials, rng=prng)*graph.compute_asset_effective_revenue_impact(aid)*cfg["downtime_fraction"]
                response = events*sample_pert(**cfg["incident_response"], size=trials, rng=prng)*float(asset["criticality_1_5"])/3
                data = np.zeros(trials); penalty = np.zeros(trials); churn = np.zeros(trials)
                records = max(0, int(asset.get("records_count") or 0))
                if records and sc["id"] in ("data_breach", "ransomware", "insider_misuse"):
                    breached = records*sample_pert(**cfg["breached_fraction"], size=trials, rng=prng)
                    data = events*breached*sample_pert(**cfg["cost_per_record"], size=trials, rng=prng)
                    penalty = np.minimum(events*sample_pert(**cfg["penalty"], size=trials, rng=prng)*(prng.random(trials)<cfg["penalty_probability"]), cfg["penalty_ceiling"])
                    churn = events*breached*cfg["churn_per_record"]
                pair = np.zeros(trials)
                for key,values in zip(breakdown, (downtime, response, data, penalty, churn)):
                    values = values*cfg["loss_multiplier"]
                    pair += values; breakdown[key] += float(values.mean())
                asset_losses[aid] += pair; scenario_losses[sc["id"]] += pair
                if asset.get("business_service_id") in service_losses:
                    service_losses[asset["business_service_id"]] += pair
                likelihood_inputs.append({"asset_id": aid, "scenario_id": sc["id"], "exposure": exposure,
                    "susceptibility": float(susceptibility), "control_survival": float(mitigation), "mean_annual_event_rate": float(rate.mean())})
        total = sum(asset_losses.values(), np.zeros(trials))
        eal = float(total.mean()); var95,var99 = np.percentile(total, [95,99])
        fingerprint = digest({"snapshot": snapshot, "assumptions": cfg, "model": MODEL_VERSION, "seed": seed, "trials": trials})
        drivers = []
        if params.get("calculate_drivers", True):
            ranked = sorted(findings, key=lambda f: float(asset_losses.get(f["asset_id"], np.zeros(1)).mean()), reverse=True)
            for index,f in enumerate(ranked):
                aid = f["asset_id"]; marginal = None
                asset_mean = float(asset_losses.get(aid, np.zeros(1)).mean())
                if index < cfg["driver_limit"] and aid not in excluded_ids:
                    modified = copy.deepcopy(snapshot)
                    modified["findings"] = [x for x in findings if finding_key(x) != finding_key(f)]
                    modified["assessment_state"] = {"status": "remediated"}
                    after = self.run(modified, {"calculate_drivers": False, "trials": trials, "asset_scope": aid}, seed)
                    if after["org"]["eal"] is not None:
                        marginal = round(asset_mean-after["org"]["eal"], 2)
                intel = snapshot.get("cve_intel", {}).get(f.get("cve_id"), {})
                drivers.append({"type": "finding", "id": finding_key(f), "finding_id": f.get("id"), "cve_id": f.get("cve_id"),
                    "asset_id": aid, "asset_name": next((a.get("name", aid) for a in assets if (a.get("id") or a.get("asset_id"))==aid), aid),
                    "cvss": f.get("cvss") or 0, "severity": f.get("severity"), "epss": intel.get("epss"), "in_kev": intel.get("in_kev", False),
                    "source": f.get("source", "Unknown source"), "marginal_eal": marginal, "screening_estimate": round(asset_mean,2),
                    "benefit_method": "paired_removal_simulation" if marginal is not None else "not_evaluated",
                    "exploitability_label": "Global 30-day EPSS signal" if intel.get("epss") is not None else "Assumed susceptibility prior"})
            drivers.sort(key=lambda d: (d["marginal_eal"] is not None, d["marginal_eal"] or 0), reverse=True)
        return {"status": "PARTIAL" if excluded else ("REMEDIATED" if scan_status=="remediated" and not findings else "READY"),
            "run_id": "RUN-"+fingerprint[:20], "snapshot_hash": digest(snapshot), "model_version": MODEL_VERSION,
            "assumptions_version": cfg["version"], "ts": snapshot.get("timestamp"), "seed": seed, "trials": trials,
            "org": {"name": org.get("name", "Not Configured"), "eal": round(eal,2), "var95": round(float(var95),2), "var99": round(float(var99),2),
                    "tail": round(expected_shortfall(total),2), "score": int(np.clip(round(50+35*np.log2(max(.1,var95/max(1,appetite)))),0,100)),
                    "appetite": appetite, "headroom": round(appetite-float(var95),2), "data_quality": round((len(assets)-len(excluded))/len(assets),2)},
            "loss_breakdown": {k:round(v,2) for k,v in breakdown.items()}, "scenario_eals": {k:round(float(v.mean()),2) for k,v in scenario_losses.items()},
            "drivers": drivers, "curve": exceedance_curve(total),
            "assets": [{"asset_id": a.get("id") or a.get("asset_id"), "name": a.get("name"), "criticality": a.get("criticality_1_5"),
                        "service_id": a.get("business_service_id"),
                        "eal": None if (a.get("id") or a.get("asset_id")) in excluded_ids else round(float(asset_losses[a.get("id") or a.get("asset_id")].mean()),2),
                        "var95": None if (a.get("id") or a.get("asset_id")) in excluded_ids else round(float(np.percentile(asset_losses[a.get("id") or a.get("asset_id")],95)),2),
                        "excluded_from_eal": (a.get("id") or a.get("asset_id")) in excluded_ids,
                        "has_business_context": (a.get("id") or a.get("asset_id")) not in excluded_ids, "is_real_lab_asset": a.get("is_real_lab_asset",False)} for a in assets],
            "services": [{"service_id": s.get("id") or s.get("service_id"), "name": s["name"], "business_unit": s.get("business_unit"),
                          "revenue_per_hour": s.get("revenue_per_hour") or 0, "rto_hours": s.get("rto_hours"),
                          "eal": round(float(service_losses[s.get("id") or s.get("service_id")].mean()),2),
                          "var95": round(float(np.percentile(service_losses[s.get("id") or s.get("service_id")],95)),2)} for s in services],
            "choke_points": graph.identify_choke_points(5), "excluded_assets": excluded, "excluded_assets_count": len(excluded),
            "explanation": {"assumptions": cfg, "business_inputs": assets, "services": services,
                "source_timestamps": [{"finding_id": f.get("id"), "asset_id": f["asset_id"], "source": f.get("source"), "last_seen": f.get("last_seen")} for f in findings],
                "likelihood_inputs": likelihood_inputs, "annual_loss_percentiles": {"p95": float(var95), "p99": float(var99)},
                "parameter_uncertainty": {"method": "Input PERT ranges; not a confidence interval on EAL", "calibrated": False},
                "monte_carlo_standard_error_eal": float(total.std()/np.sqrt(trials)),
                "limitations": ["EPSS mapping is an uncalibrated planning assumption.", "Totals exclude assets without business context.", "VaR is an annual-loss percentile, not a loss ceiling."]}}
