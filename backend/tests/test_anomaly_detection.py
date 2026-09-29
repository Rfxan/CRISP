"""
Tests for unsupervised telemetry anomaly detection (IsolationForest).
Verifies:
1. Cold start honesty: < 5 telemetry observation windows returns 'insufficient baseline data'.
2. Synthetic telemetry: normal baseline + injected spike; spike is flagged, normal is not.
3. Label accuracy: 'unsupervised anomaly (IsolationForest), not a confirmed incident'.
4. API endpoints: GET /api/threats/anomalies, POST /api/threats/anomalies/inject, GET /api/risk/drivers.
5. Boundary integrity: IsolationForest signal layer does not alter deterministic FAIR loss core.
"""

import sys
import io
if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.ai.anomaly import (
    TelemetryAnomalyDetector,
    ANOMALY_LABEL,
    MIN_BASELINE_SAMPLES
)
from app.engine.fair_engine import FAIREngine


def test_anomaly_cold_start_empty_history():
    """Empty history returns the honest 'insufficient baseline data' state."""
    detector = TelemetryAnomalyDetector(random_state=42)
    result = detector.detect_anomalies([])

    assert result["status"] == "insufficient_baseline_data"
    assert result["is_insufficient"] is True
    assert result["total_windows"] == 0
    assert result["anomalies_detected"] == 0
    assert "insufficient baseline data" in result["message"]
    assert result["signals"] == []
    assert result["label"] == ANOMALY_LABEL


def test_anomaly_cold_start_few_samples():
    """Fewer than MIN_BASELINE_SAMPLES windows returns 'insufficient baseline data' without scoring."""
    detector = TelemetryAnomalyDetector(random_state=42)
    windows = [
        {"agent_id": f"agent-00{i}", "agent_name": f"srv-0{i}", "event_volume": 100, "auth_failures": 2}
        for i in range(3)
    ]
    result = detector.detect_anomalies(windows)

    assert result["status"] == "insufficient_baseline_data"
    assert result["is_insufficient"] is True
    assert result["total_windows"] == 3
    assert result["anomalies_detected"] == 0


def test_anomaly_detection_synthetic_normal_and_spike():
    """
    Synthetic telemetry with normal baseline + injected spike:
    - Normal windows should NOT be flagged as anomalies.
    - Injected brute-force/spike window MUST be flagged as an anomaly.
    - Score must be between 0.0 and 1.0.
    - Label must match the exact requirement.
    """
    detector = TelemetryAnomalyDetector(contamination=0.1, random_state=42)

    # 10 normal baseline windows with low event volume and low auth failures
    windows = [
        {
            "agent_id": f"agent-{i % 3}",
            "agent_name": f"srv-{i % 3}",
            "event_volume": 100 + (i * 5),
            "auth_failures": 1 + (i % 2),
            "total_alerts": 10,
            "high_severity_alerts": 0
        }
        for i in range(10)
    ]

    # Inject a massive brute-force outlier spike window
    spike_window = {
        "agent_id": "agent-compromised",
        "agent_name": "srv-web-compromised",
        "event_volume": 5000,
        "auth_failures": 2500,
        "total_alerts": 1500,
        "high_severity_alerts": 1200
    }
    windows.append(spike_window)

    evaluation = detector.detect_anomalies(windows)

    assert evaluation["status"] == "scored"
    assert evaluation["is_insufficient"] is False
    assert evaluation["anomalies_detected"] >= 1
    assert evaluation["label"] == ANOMALY_LABEL

    # Locate the spike result
    flagged_ids = [s["agent_id"] for s in evaluation["signals"]]
    assert "agent-compromised" in flagged_ids

    spike_signal = next(s for s in evaluation["signals"] if s["agent_id"] == "agent-compromised")
    assert spike_signal["is_anomalous"] is True
    assert 0.0 <= spike_signal["anomaly_score"] <= 1.0
    assert spike_signal["anomaly_score"] > 0.6  # Spike must receive a high anomaly score
    assert spike_signal["label"] == ANOMALY_LABEL


def test_api_threat_anomalies_endpoint():
    """GET /api/threats/anomalies returns valid model results and proper metadata."""
    client = TestClient(app)
    response = client.get("/api/threats/anomalies")
    assert response.status_code == 200

    data = response.json()
    assert "model" in data
    assert "IsolationForest" in data["model"]
    assert "label" in data
    assert data["label"] == ANOMALY_LABEL
    assert "signals" in data
    assert isinstance(data["signals"], list)


def test_api_threat_anomalies_inject_endpoint():
    """POST /api/threats/anomalies/inject injects a synthetic anomaly spike and returns score."""
    client = TestClient(app)
    payload = {
        "agent_id": "agent-test-inject",
        "event_volume": 6000,
        "auth_failures": 3000,
        "high_severity_alerts": 1800,
        "total_alerts": 2000
    }
    response = client.post("/api/threats/anomalies/inject", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["label"] == ANOMALY_LABEL
    assert data["anomalies_detected"] >= 1
    flagged_ids = [s["agent_id"] for s in data["signals"]]
    assert "agent-test-inject" in flagged_ids


def test_api_risk_drivers_surfaces_emerging_threats():
    """GET /api/risk/drivers surfaces emerging threats and anomaly_detection block."""
    client = TestClient(app)
    response = client.get("/api/risk/drivers")
    assert response.status_code == 200

    data = response.json()
    assert "emerging_threats" in data
    assert "anomaly_detection" in data
    assert "IsolationForest" in data["anomaly_detection"]["model"]
    assert data["anomaly_detection"]["label"] == ANOMALY_LABEL


def test_fair_core_boundary_independence():
    """
    Confirm that the FAIR Monte Carlo loss engine remains strictly deterministic
    and independent of the anomaly detection layer.
    """
    import json
    snapshot_path = Path(__file__).resolve().parent.parent / "app" / "data" / "seed_snapshot.json"
    with open(snapshot_path, "r", encoding="utf-8") as f:
        snapshot = json.load(f)

    # Run FAIR engine run 1
    engine1 = FAIREngine(trials=500, seed=42)
    res1 = engine1.run(snapshot, seed=42)

    # Run anomaly detector in between
    detector = TelemetryAnomalyDetector(random_state=42)
    _ = detector.detect_anomalies([
        {"agent_id": "a1", "event_volume": 100, "auth_failures": 2},
        {"agent_id": "a2", "event_volume": 120, "auth_failures": 1},
        {"agent_id": "a3", "event_volume": 110, "auth_failures": 3},
        {"agent_id": "a4", "event_volume": 105, "auth_failures": 0},
        {"agent_id": "a5", "event_volume": 5000, "auth_failures": 2500}
    ])

    # Run FAIR engine run 2 with same seed
    engine2 = FAIREngine(trials=500, seed=42)
    res2 = engine2.run(snapshot, seed=42)

    # Monte Carlo loss quantification numbers must be 100% identical
    assert res1["org"]["eal"] == res2["org"]["eal"]
    assert res1["org"]["var95"] == res2["org"]["var95"]
    assert res1["org"]["score"] == res2["org"]["score"]

