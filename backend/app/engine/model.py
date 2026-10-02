"""Explicit planning assumptions, not empirically calibrated incident probabilities."""
import copy
import hashlib
import json
from app.core.config import settings

MODEL_VERSION = "crisp-risk-2.0"
DEFAULTS = {
    "version": "5.0", "source": "Judgment-based priors; organization calibration required",
    "epss_reference": "https://www.first.org/epss/faq.html",
    "missing_epss_prior": .02, "public_exposure": .8, "internal_exposure": .2,
    "unknown_scenario_relevance": .25, "background_probability": .01,
    "kev_multiplier": 1.5, "systemic_sigma": .45,
    "cost_per_record": {"low": 1800., "likely": 2850., "high": 4500.},
    "incident_response": {"low": 500000., "likely": 1500000., "high": 4500000.},
    "breached_fraction": {"low": .05, "likely": .20, "high": .60},
    "penalty": {"low": 0., "likely": 5000000., "high": 35000000.},
    "penalty_probability": .2, "penalty_ceiling": 2500000000.,
    "churn_per_record": 450., "downtime_fraction": .75,
    "likelihood_multiplier": 1., "loss_multiplier": 1., "control_effectiveness_multiplier": 1.,
    "driver_limit": 20,
}


def assumptions(snapshot):
    values = copy.deepcopy(DEFAULTS)
    scale = settings.COST_PER_RECORD_INR / DEFAULTS["cost_per_record"]["likely"]
    values["cost_per_record"] = {k: v*scale for k,v in values["cost_per_record"].items()}
    for key,value in snapshot.get("model_assumptions", {}).items():
        if key not in values:
            raise ValueError(f"Unknown model assumption: {key}")
        values[key] = copy.deepcopy(value)
    for key in ("cost_per_record", "incident_response", "breached_fraction", "penalty"):
        d = values[key]
        if not isinstance(d, dict) or set(d) != {"low", "likely", "high"} or not all(isinstance(v, (int,float)) and not isinstance(v,bool) for v in d.values()):
            raise ValueError(f"Expected numeric low, likely and high: {key}")
        if not 0 <= d["low"] <= d["likely"] <= d["high"] < float("inf"):
            raise ValueError(f"Invalid PERT distribution: {key}")
    for key in ("missing_epss_prior", "public_exposure", "internal_exposure", "unknown_scenario_relevance",
                "background_probability", "penalty_probability", "downtime_fraction"):
        if not isinstance(values[key], (int,float)) or isinstance(values[key],bool) or not 0 <= values[key] <= 1:
            raise ValueError(f"{key} must be between 0 and 1")
    for key in ("systemic_sigma", "kev_multiplier", "churn_per_record", "penalty_ceiling",
                "likelihood_multiplier", "loss_multiplier", "control_effectiveness_multiplier"):
        if not isinstance(values[key], (int,float)) or isinstance(values[key],bool) or not 0 <= values[key] < float("inf"):
            raise ValueError(f"{key} must be finite and nonnegative")
    if values["breached_fraction"]["high"] > 1:
        raise ValueError("Breached fraction cannot exceed one")
    if values["systemic_sigma"] > 3:
        raise ValueError("Systemic sigma must be at most 3 for numerical stability")
    if type(values["driver_limit"]) is not int or not 0 <= values["driver_limit"] <= 1000:
        raise ValueError("Driver limit must be an integer between 0 and 1000")
    return values


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str, allow_nan=False).encode()).hexdigest()


def stable_seed(seed, *parts):
    return int(digest([seed, *parts])[:16], 16)


def finding_key(finding):
    return json.dumps([finding.get("asset_id"), finding.get("id")], separators=(",", ":"))
