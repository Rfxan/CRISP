"""
Unsupervised Machine Learning Telemetry Anomaly Detection.
Uses scikit-learn IsolationForest over per-agent Wazuh telemetry features:
1. Event Volume (total event/alert throughput in window)
2. Authentication Failure Rate (auth_failures / max(1, event_volume))
3. Alert Severity Mix (high_severity_alerts / max(1, total_alerts))

ARCHITECTURAL PRINCIPLE:
Kept strictly OUT of the deterministic FAIR loss quantification core.
Operates purely as an independent emerging-threat signal layer.
"""

from typing import Dict, Any, List, Optional, Tuple
import logging
import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

logger = logging.getLogger(__name__)

# Minimum baseline observation windows required before unsupervised scoring is permitted
MIN_BASELINE_SAMPLES = 5
ANOMALY_LABEL = "unsupervised anomaly (IsolationForest), not a confirmed incident"


class TelemetryAnomalyDetector:
    """
    Unsupervised Isolation Forest detector for host and network agent telemetry.
    Flags statistical deviations without assuming prior attack labels.
    """

    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.model: Optional[Any] = None
        self.is_fitted = False

    @staticmethod
    def extract_features(record: Dict[str, Any]) -> Tuple[float, float, float]:
        """
        Extracts normalized 3-dimensional feature tuple from a telemetry window:
        1. event_volume
        2. auth_failure_rate
        3. alert_severity_mix
        """
        vol = float(record.get("event_volume", 0.0))
        auth_fails = float(record.get("auth_failures", 0.0))
        total_alerts = float(record.get("total_alerts", 0.0) or record.get("recent_alerts_24h", 0.0) or vol)
        high_alerts = float(record.get("high_severity_alerts", 0.0) or record.get("high_severity_alerts_24h", 0.0))

        # 1. Raw event volume
        event_volume = max(0.0, vol)

        # 2. Auth failure rate relative to total activity
        auth_rate = (auth_fails / max(1.0, event_volume)) if event_volume > 0 else 0.0
        # If rate is already provided directly in record, prioritize it
        if "auth_failure_rate" in record and record["auth_failure_rate"] is not None:
            auth_rate = float(record["auth_failure_rate"])

        # 3. Alert severity mix: proportion of high/critical alerts
        severity_mix = (high_alerts / max(1.0, total_alerts)) if total_alerts > 0 else 0.0
        if "alert_severity_mix" in record and record["alert_severity_mix"] is not None:
            severity_mix = float(record["alert_severity_mix"])

        return event_volume, auth_rate, severity_mix

    def detect_anomalies(
        self,
        telemetry_records: List[Dict[str, Any]],
        current_observation: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Fits IsolationForest over telemetry records and identifies anomalous windows.
        Honest cold-start behavior: returns 'insufficient baseline data' if records < MIN_BASELINE_SAMPLES.
        """
        if not SKLEARN_AVAILABLE:
            return {
                "status": "error",
                "message": "scikit-learn is not installed. Unsupervised anomaly detection unavailable.",
                "anomalies_detected": 0,
                "signals": [],
                "label": ANOMALY_LABEL
            }

        all_records = list(telemetry_records or [])
        if current_observation:
            all_records.append(current_observation)

        # 1. Cold-start check: honest insufficient baseline data state
        if len(all_records) < MIN_BASELINE_SAMPLES:
            return {
                "status": "insufficient_baseline_data",
                "message": f"insufficient baseline data: minimum {MIN_BASELINE_SAMPLES} observation windows required (received {len(all_records)})",
                "total_windows": len(all_records),
                "anomalies_detected": 0,
                "signals": [],
                "model": "IsolationForest (scikit-learn)",
                "label": ANOMALY_LABEL,
                "is_insufficient": True
            }

        # 2. Extract feature matrix X
        feature_list = []
        for rec in all_records:
            feat = self.extract_features(rec)
            feature_list.append(feat)

        X = np.array(feature_list, dtype=np.float64)

        # 3. Fit Isolation Forest
        # Contamination defines the expected proportion of outliers in the data set
        effective_contamination = min(0.4, max(0.01, self.contamination))
        clf = IsolationForest(
            n_estimators=100,
            contamination=effective_contamination,
            random_state=self.random_state
        )
        clf.fit(X)
        self.model = clf
        self.is_fitted = True

        # 4. Score samples:
        # decision_function: positive for inliers, negative for outliers
        # We invert so higher positive score = more anomalous
        raw_decision = clf.decision_function(X)
        predictions = clf.predict(X)  # -1 = anomaly, 1 = normal

        # Normalize score into [0.0, 1.0] range for intuitive interpretability
        # where ~0.1-0.4 is typical baseline and 0.7-1.0 is extreme anomaly
        scores = []
        min_dec = float(np.min(raw_decision))
        max_dec = float(np.max(raw_decision))
        dec_range = max(1e-6, max_dec - min_dec)

        for dec in raw_decision:
            # lower decision function -> higher anomaly score
            norm_score = round(float(1.0 - ((dec - min_dec) / dec_range)), 3)
            scores.append(norm_score)

        signals = []
        for idx, (rec, pred, score) in enumerate(zip(all_records, predictions, scores)):
            is_anomaly = (pred == -1)
            if is_anomaly:
                agent_id = rec.get("agent_id") or rec.get("agent_name") or f"agent-{idx+1:03d}"
                agent_name = rec.get("agent_name") or agent_id
                timestamp = rec.get("timestamp") or rec.get("last_sync") or "recent_window"
                vol, auth_rate, sev_mix = feature_list[idx]

                signals.append({
                    "agent_id": agent_id,
                    "agent_name": agent_name,
                    "window_timestamp": timestamp,
                    "anomaly_score": score,
                    "is_anomalous": True,
                    "label": ANOMALY_LABEL,
                    "features": {
                        "event_volume": int(vol),
                        "auth_failure_rate": round(float(auth_rate), 4),
                        "alert_severity_mix": round(float(sev_mix), 4)
                    },
                    "reason": (
                        f"Statistical anomaly on {agent_name} (Score: {score}): "
                        f"throughput={int(vol)} events, auth_failure_rate={round(auth_rate * 100, 1)}%, "
                        f"severity_mix={round(sev_mix * 100, 1)}%."
                    )
                })

        # Sort signals by highest anomaly score first
        signals.sort(key=lambda s: s["anomaly_score"], reverse=True)

        return {
            "status": "scored",
            "model": "IsolationForest (scikit-learn)",
            "total_windows": len(all_records),
            "anomalies_detected": len(signals),
            "signals": signals,
            "label": ANOMALY_LABEL,
            "is_insufficient": False,
            "baseline_summary": {
                "mean_event_volume": round(float(np.mean(X[:, 0])), 1),
                "mean_auth_rate": round(float(np.mean(X[:, 1])), 4),
                "mean_severity_mix": round(float(np.mean(X[:, 2])), 4)
            }
        }
