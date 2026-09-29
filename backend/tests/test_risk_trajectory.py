import pytest
from pathlib import Path
import json
import tempfile
from fastapi.testclient import TestClient
from app.main import app
from app.core.run_history import RunHistoryManager, run_history_manager
from app.api.routes import store


@pytest.fixture
def temp_history_file(tmp_path):
    return tmp_path / "test_run_history.jsonl"


def test_run_history_persistence_append_only(temp_history_file):
    mgr = RunHistoryManager(temp_history_file)
    assert mgr.get_history() == []

    # Append run 1
    r1 = mgr.append_run(
        run_id="RUN-42-00001",
        timestamp="2026-03-29T10:00:00Z",
        eal=1500000.0,
        var95=2800000.0,
        asset_count=5,
        finding_count=10,
        assumptions_version="1.0"
    )
    assert r1["run_id"] == "RUN-42-00001"
    assert r1["eal"] == 1500000.0

    # Append run 2
    r2 = mgr.append_run(
        run_id="RUN-42-00002",
        timestamp="2026-03-29T11:00:00Z",
        eal=1800000.0,
        var95=3200000.0,
        asset_count=5,
        finding_count=12,
        assumptions_version="1.0"
    )

    history = mgr.get_history()
    assert len(history) == 2
    assert history[0]["run_id"] == "RUN-42-00001"
    assert history[1]["run_id"] == "RUN-42-00002"

    # Verify append-only line structure in file
    with open(temp_history_file, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
    assert len(lines) == 2
    parsed1 = json.loads(lines[0])
    assert parsed1["run_id"] == "RUN-42-00001"
    assert parsed1["var95"] == 2800000.0
    assert parsed1["assumptions_version"] == "1.0"


def test_trajectory_insufficient_history_with_0_and_1_point(temp_history_file):
    mgr = RunHistoryManager(temp_history_file)

    # 0 points
    t0 = mgr.compute_trajectory(history=[])
    assert t0["status"] == "insufficient_history"
    assert t0["method"] == "insufficient_history"
    assert t0["points_count"] == 0
    assert t0["projection_30d"] is None
    assert t0["projection_60d"] is None
    assert t0["projection_90d"] is None
    assert t0["confidence_band"] is None
    assert "insufficient history" in t0["tooltip"]

    # 1 point
    mgr.append_run(
        run_id="RUN-42-00001",
        timestamp="2026-03-29T10:00:00Z",
        eal=2000000.0,
        var95=3800000.0,
        asset_count=4,
        finding_count=8
    )
    t1 = mgr.compute_trajectory()
    assert t1["status"] == "insufficient_history"
    assert t1["method"] == "insufficient_history"
    assert t1["points_count"] == 1
    assert t1["projection_30d"] is None
    assert t1["confidence_band"] is None
    assert t1["tooltip"] == "trend from 1 run, insufficient history"


def test_trajectory_linear_fallback_with_2_points(temp_history_file):
    mgr = RunHistoryManager(temp_history_file)

    mgr.append_run(
        run_id="RUN-42-00001",
        timestamp="2026-03-29T10:00:00Z",
        eal=1000000.0,
        var95=2000000.0,
        asset_count=4,
        finding_count=5
    )
    mgr.append_run(
        run_id="RUN-42-00002",
        timestamp="2026-03-29T11:00:00Z",
        eal=1200000.0,
        var95=2400000.0,
        asset_count=4,
        finding_count=7
    )

    t2 = mgr.compute_trajectory()
    assert t2["status"] == "ok"
    assert t2["method"] == "linear_trend"
    assert t2["points_count"] == 2
    assert t2["tooltip"] == "trend from 2 runs, linear"
    assert t2["projection_30d"] is not None
    assert t2["projection_60d"] is not None
    assert t2["projection_90d"] is not None
    # Slope is +200,000 per step
    assert t2["projection_30d"] > 1200000.0
    assert t2["projection_60d"] > t2["projection_30d"]
    assert t2["projection_90d"] > t2["projection_60d"]
    # Check confidence band
    assert t2["confidence_band"] is not None
    assert t2["confidence_band"]["label"] == "95% Confidence Band"
    assert len(t2["confidence_band"]["30d"]) == 2
    assert t2["confidence_band"]["30d"][0] <= t2["projection_30d"] <= t2["confidence_band"]["30d"][1]


def test_trajectory_exponential_smoothing_with_3_plus_points(temp_history_file):
    mgr = RunHistoryManager(temp_history_file)

    # Add 3 runs with increasing EAL
    mgr.append_run("RUN-1", "2026-03-29T08:00:00Z", 1000000.0, 2000000.0, 3, 5)
    mgr.append_run("RUN-2", "2026-03-29T09:00:00Z", 1200000.0, 2400000.0, 3, 7)
    mgr.append_run("RUN-3", "2026-03-29T10:00:00Z", 1500000.0, 3000000.0, 3, 10)

    t3 = mgr.compute_trajectory()
    assert t3["status"] == "ok"
    assert t3["method"] == "exponential_smoothing"
    assert t3["points_count"] == 3
    assert t3["tooltip"] == "trend from 3 runs, exp. smoothing"
    assert t3["projection_30d"] > 1500000.0
    assert t3["projection_60d"] > t3["projection_30d"]
    assert t3["projection_90d"] > t3["projection_60d"]
    assert t3["confidence_band"] is not None
    assert "95%" in t3["confidence_band"]["label"]

    # Now add run 4 with a sharp mitigation drop (differing data changes trajectory accordingly)
    mgr.append_run("RUN-4", "2026-03-29T11:00:00Z", 800000.0, 1600000.0, 3, 2)
    t4 = mgr.compute_trajectory()
    assert t4["points_count"] == 4
    assert t4["tooltip"] == "trend from 4 runs, exp. smoothing"
    # The downward drop must pull down the projected trajectory
    assert t4["projection_30d"] < t3["projection_30d"]


def test_api_risk_summary_returns_method_and_points_count(monkeypatch, tmp_path):
    # Isolated test history file
    isolated_history = tmp_path / "api_run_history.jsonl"
    test_mgr = RunHistoryManager(isolated_history)
    monkeypatch.setattr("app.api.routes.run_history_manager", test_mgr)

    client = TestClient(app)

    # 1 run in history
    test_mgr.append_run("RUN-TEST-1", "2026-03-29T10:00:00Z", 2500000.0, 4800000.0, 2, 4)

    res1 = client.get("/api/risk/summary")
    assert res1.status_code == 200
    data1 = res1.json()
    assert "trend" in data1
    assert data1["trend"]["method"] == "insufficient_history"
    assert data1["trend"]["points_count"] == 1
    assert data1["trend"]["tooltip"] == "trend from 1 run, insufficient history"
    assert data1["trend"]["projection_30d"] is None

    # Add 2 more runs (total 3 runs)
    test_mgr.append_run("RUN-TEST-2", "2026-03-29T11:00:00Z", 2700000.0, 5100000.0, 2, 6)
    test_mgr.append_run("RUN-TEST-3", "2026-03-29T12:00:00Z", 2950000.0, 5600000.0, 2, 8)

    res3 = client.get("/api/risk/summary")
    assert res3.status_code == 200
    data3 = res3.json()
    assert data3["trend"]["method"] == "exponential_smoothing"
    assert data3["trend"]["points_count"] == 3
    assert data3["trend"]["tooltip"] == "trend from 3 runs, exp. smoothing"
    assert data3["trend"]["projection_30d"] is not None
    assert data3["trend"]["confidence_band"] is not None
