from datetime import datetime, timezone, timedelta
from app.engine.model import digest


def evidence_fingerprint(state):
    return digest({k: (state or {}).get(k) for k in ('coverage_pct', 'evidence_ref',
        'supporting_finding_ids', 'is_simulated', 'is_user_assumed')})


def parse_time(value):
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result if result.tzinfo else result.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError, AttributeError):
        return None


def assess_control(state, review=None):
    """Telemetry coverage, evidence completeness and reviewer conclusion are separate."""
    state, review = state or {}, review or {}
    timestamp = parse_time(state.get("last_checked"))
    now = datetime.now(timezone.utc)
    fresh = bool(timestamp and now-timedelta(days=90) <= timestamp <= now)
    source = state.get("evidence_ref")
    observed = state.get("coverage_pct")
    evidence = bool(source and source != "Not Connected" and fresh and observed is not None
                    and not state.get("is_simulated") and not state.get("is_user_assumed"))
    reviewed_at = parse_time(review.get("reviewed_at"))
    assessed = bool(evidence and review.get("reviewer") and reviewed_at and
                    now-timedelta(days=90) <= reviewed_at <= now and
                    review.get("evidence_fingerprint") == evidence_fingerprint(state))
    decision = review.get("decision") if assessed else None
    status = {"compliant": "Compliant", "partial": "Partially Compliant", "non_compliant": "Non-Compliant"}.get(decision, "Not assessed")
    if review.get("applicability") != "applicable":
        status = "Not applicable" if assessed and review.get("applicability") == "not_applicable" else "Not assessed"
    # A favorable review cannot bypass the same coverage threshold used in summaries.
    if status == "Compliant" and observed < 75:
        status = "Partially Compliant" if observed >= 50 else "Non-Compliant"
    return {"status": status, "observed_coverage_pct": observed if evidence else None,
            "evidence_complete": evidence, "evidence_timestamp": state.get("last_checked"),
            "evidence_source": source if evidence else None, "reviewer_decision": decision,
            "reviewer": review.get("reviewer"), "reviewed_at": review.get("reviewed_at"),
            "evidence_fresh": fresh, "coverage_threshold_pct": 75}


def reporting_readiness(exercises):
    results = []
    now = datetime.now(timezone.utc)
    for exercise in exercises or []:
        times = [parse_time(exercise.get(k)) for k in ("incident_at", "detected_at", "escalated_at", "reported_at")]
        valid = (all(times) and times == sorted(times) and times[-1] <= now
                 and times[0] >= now-timedelta(days=90) and bool(exercise.get("evidence_ref")))
        if not valid:
            continue
        minutes = [(times[i]-times[0]).total_seconds()/60 for i in range(1,4)]
        results.append({"exercise_id": exercise.get("id"), "detection_minutes": minutes[0],
                        "escalation_minutes": minutes[1], "reporting_minutes": minutes[2],
                        "evidence_ref": exercise["evidence_ref"], "pass": minutes[2] <= 360})
    score = round(100*sum(r["pass"] for r in results)/len(results),1) if results else None
    return {"requirement": "Six-hour incident-reporting exercise target (verify entity applicability)",
            "readiness_score_pct": score, "status": "NOT VERIFIED" if score is None else ("READY" if score==100 else "AT RISK"),
            "checklist": [{"item": "Recent measured incident-reporting exercise", "coverage_pct": score, "pass": score==100}],
            "exercises": results, "target_minutes": 360,
            "recommendation": "Record detection, escalation and reporting timestamps with exercise evidence; coverage alone does not prove readiness."}
