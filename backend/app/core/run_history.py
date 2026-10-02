from app.core.tenancy import active, read_document, write_document
from app.core.deployment import production
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import json
import logging
import math

import tempfile

logger = logging.getLogger(__name__)


def _resolve_run_history_path() -> Path:
    backend_root = Path(__file__).resolve().parent.parent.parent
    if production():
        return backend_root / "data" / "run_history.jsonl"
    candidates = [
        backend_root / "data" / "run_history.jsonl",
        Path.home() / ".crisp" / "run_history.jsonl",
        Path(tempfile.gettempdir()) / "crisp_run_history.jsonl"
    ]
    for candidate in candidates:
        try:
            candidate.parent.mkdir(parents=True, exist_ok=True)
            test_file = candidate.parent / f".perm_check_{candidate.name}"
            with open(test_file, "w", encoding="utf-8") as f:
                f.write("ok")
            test_file.unlink(missing_ok=True)
            return candidate
        except Exception:
            continue
    fallback = Path(tempfile.gettempdir()) / "crisp_run_history.jsonl"
    fallback.parent.mkdir(parents=True, exist_ok=True)
    return fallback


class RunHistoryManager:
    """
    Manages persistence of engine run summaries to backend/data/run_history.jsonl (append-only)
    and fits risk trajectories to historical EAL values:
    - With < 2 runs: states 'insufficient_history' (never fabricates a curve).
    - With 2 runs: falls back to linear trend.
    - With 3+ runs: fits Holt's linear exponential smoothing with a 95% confidence band.
    - Backfills nothing: history accumulates strictly from live engine runs.
    """

    def __init__(self, history_file: Optional[Path] = None):
        backend_root = Path(__file__).resolve().parent.parent.parent
        self.default_data_path = backend_root / "data" / "run_history.jsonl"
        self._is_custom = history_file is not None
        self.history_file = Path(history_file) if history_file else _resolve_run_history_path()
        if not production() or self._is_custom:
            self.history_file.parent.mkdir(parents=True, exist_ok=True)

    def append_run(
        self,
        run_id: str,
        timestamp: Optional[str],
        eal: Optional[float],
        var95: Optional[float],
        asset_count: int,
        finding_count: int,
        assumptions_version: str = "1.0"
    ) -> Dict[str, Any]:
        """
        Appends a run summary to backend/data/run_history.jsonl in an append-only format.
        """
        if not timestamp:
            timestamp = datetime.now(timezone.utc).isoformat()

        record = {
            "run_id": str(run_id),
            "timestamp": str(timestamp),
            "eal": round(float(eal), 2) if eal is not None else None,
            "var95": round(float(var95), 2) if var95 is not None else None,
            "asset_count": int(asset_count),
            "finding_count": int(finding_count),
            "assumptions_version": str(assumptions_version)
        }

        if active() and not self._is_custom:
            history = read_document("run_history", [])
            if not history or history[-1]["run_id"] != record["run_id"]:
                history.append(record)
                write_document("run_history", history)
            return record

        # Write to primary history file
        try:
            with open(self.history_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:
            logger.error(f"Failed to append run {run_id} to {self.history_file}: {e}")

        # Mirror write to default_data_path if different and not a custom test path
        if not self._is_custom and self.history_file != self.default_data_path:
            try:
                self.default_data_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.default_data_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record) + "\n")
            except Exception:
                pass

        return record

    def get_history(self) -> List[Dict[str, Any]]:
        """
        Reads and returns all historical run records.
        """
        if active() and not self._is_custom:
            return read_document("run_history", [])
        # Determine source path
        target_path = self.history_file
        if not self._is_custom:
            if self.default_data_path.exists() and self.default_data_path.stat().st_size > 0:
                target_path = self.default_data_path
            elif self.history_file.exists():
                target_path = self.history_file
            else:
                target_path = self.default_data_path

        if not target_path.exists():
            return []

        history = []
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            history.append(json.loads(line))
                        except Exception:
                            continue
        except Exception as e:
            logger.error(f"Failed to read run history from {target_path}: {e}")
            return []

        return history

    def _parse_iso(self, ts_str: Optional[str]) -> Optional[datetime]:
        if not ts_str:
            return None
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            return None

    def compute_trajectory(
        self,
        history: Optional[List[Dict[str, Any]]] = None,
        current_eal: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Builds the 30 / 60 / 90-day trajectory by fitting historical EAL values:
        - With < 2 data points: returns insufficient_history status (null projections).
        - With 2 data points: falls back to linear trend with confidence band.
        - With 3+ data points: fits Holt's linear exponential smoothing with 95% confidence band.
        """
        if history is None:
            history = self.get_history()

        # Filter for points with valid numeric EAL
        valid_points = [
            pt for pt in history
            if pt.get("eal") is not None and isinstance(pt.get("eal"), (int, float))
        ]

        n = len(valid_points)

        # Determine effective current EAL
        if current_eal is None and n > 0:
            current_eal = valid_points[-1]["eal"]

        # CASE 1: < 2 points -> Insufficient History
        if n < 2:
            return {
                "status": "insufficient_history",
                "method": "insufficient_history",
                "points_count": n,
                "label": "Insufficient History (< 2 runs)",
                "tooltip": f"trend from {n} run{'s' if n != 1 else ''}, insufficient history",
                "message": f"Insufficient history (requires at least 2 runs to establish trend — currently {n} run{'s' if n != 1 else ''} recorded). Projections are not fabricated.",
                "current_eal": current_eal,
                "projection_30d": None,
                "projection_60d": None,
                "projection_90d": None,
                "projection_30d_lower": None,
                "projection_30d_upper": None,
                "projection_60d_lower": None,
                "projection_60d_upper": None,
                "projection_90d_lower": None,
                "projection_90d_upper": None,
                "confidence_band": None,
                "historical": valid_points
            }

        y_vals = [float(pt["eal"]) for pt in valid_points]

        # Determine forecast horizon step scaling
        t_first = self._parse_iso(valid_points[0].get("timestamp"))
        t_last = self._parse_iso(valid_points[-1].get("timestamp"))

        total_days = 0.0
        if t_first and t_last and t_last > t_first:
            total_days = (t_last - t_first).total_seconds() / 86400.0

        if total_days >= 2.0:
            avg_days_per_run = max(0.1, total_days / (n - 1))
            h30 = 30.0 / avg_days_per_run
            h60 = 60.0 / avg_days_per_run
            h90 = 90.0 / avg_days_per_run
        else:
            # Runs triggered on same day / fast intervals / unit tests -> treat each nominal step as 30d
            h30 = 1.0
            h60 = 2.0
            h90 = 3.0

        # CASE 2: 2 points -> Linear Trend Fallback
        if n == 2:
            y0, y1 = y_vals[0], y_vals[1]
            slope = y1 - y0

            p30 = max(0.0, y1 + slope * h30)
            p60 = max(0.0, y1 + slope * h60)
            p90 = max(0.0, y1 + slope * h90)

            # Prior uncertainty for confidence band
            s_e = max(abs(slope) * 0.25, y1 * 0.05, 1000.0)
            z = 1.96

            w30 = z * s_e * math.sqrt(h30)
            w60 = z * s_e * math.sqrt(h60)
            w90 = z * s_e * math.sqrt(h90)

            p30_lower = max(0.0, p30 - w30)
            p30_upper = p30 + w30
            p60_lower = max(0.0, p60 - w60)
            p60_upper = p60 + w60
            p90_lower = max(0.0, p90 - w90)
            p90_upper = p90 + w90

            return {
                "status": "ok",
                "method": "linear_trend",
                "points_count": 2,
                "label": "Linear Trend (2 runs)",
                "tooltip": "trend from 2 runs, linear",
                "message": "Linear trend projected from 2 recorded runs.",
                "current_eal": current_eal if current_eal is not None else y1,
                "projection_30d": round(p30, 2),
                "projection_60d": round(p60, 2),
                "projection_90d": round(p90, 2),
                "projection_30d_lower": round(p30_lower, 2),
                "projection_30d_upper": round(p30_upper, 2),
                "projection_60d_lower": round(p60_lower, 2),
                "projection_60d_upper": round(p60_upper, 2),
                "projection_90d_lower": round(p90_lower, 2),
                "projection_90d_upper": round(p90_upper, 2),
                "confidence_band": {
                    "label": "95% Confidence Band",
                    "confidence_level": 0.95,
                    "30d": [round(p30_lower, 2), round(p30_upper, 2)],
                    "60d": [round(p60_lower, 2), round(p60_upper, 2)],
                    "90d": [round(p90_lower, 2), round(p90_upper, 2)]
                },
                "historical": valid_points
            }

        # CASE 3: 3+ points -> Holt's Linear Exponential Smoothing
        alpha = 0.4
        beta = 0.2

        # Initialize level and trend
        level = y_vals[0]
        trend = y_vals[1] - y_vals[0]

        residuals = []
        for t in range(1, n):
            y_t = y_vals[t]
            pred_y = level + trend
            residuals.append(y_t - pred_y)

            prev_level = level
            level = alpha * y_t + (1.0 - alpha) * (level + trend)
            trend = beta * (level - prev_level) + (1.0 - beta) * trend

        # Residual standard error
        if len(residuals) > 0:
            mse = sum(r * r for r in residuals) / len(residuals)
            s_e = math.sqrt(mse)
        else:
            s_e = 0.0

        min_uncertainty = max(abs(level) * 0.03, 1000.0)
        s_e = max(s_e, min_uncertainty)

        # Forecast horizons
        p30 = max(0.0, level + h30 * trend)
        p60 = max(0.0, level + h60 * trend)
        p90 = max(0.0, level + h90 * trend)

        # Holt confidence band formula: sigma_h = s_e * sqrt(1 + (h - 1) * alpha^2)
        z = 1.96
        w30 = z * s_e * math.sqrt(max(1.0, 1.0 + (h30 - 1.0) * (alpha ** 2)))
        w60 = z * s_e * math.sqrt(max(1.0, 1.0 + (h60 - 1.0) * (alpha ** 2)))
        w90 = z * s_e * math.sqrt(max(1.0, 1.0 + (h90 - 1.0) * (alpha ** 2)))

        p30_lower = max(0.0, p30 - w30)
        p30_upper = p30 + w30
        p60_lower = max(0.0, p60 - w60)
        p60_upper = p60 + w60
        p90_lower = max(0.0, p90 - w90)
        p90_upper = p90 + w90

        tooltip_text = f"trend from {n} runs, exp. smoothing"

        return {
            "status": "ok",
            "method": "exponential_smoothing",
            "points_count": n,
            "label": f"Exponential Smoothing ({n} runs)",
            "tooltip": tooltip_text,
            "message": f"Exponential smoothing fit across {n} historical runs with 95% confidence intervals.",
            "current_eal": current_eal if current_eal is not None else y_vals[-1],
            "projection_30d": round(p30, 2),
            "projection_60d": round(p60, 2),
            "projection_90d": round(p90, 2),
            "projection_30d_lower": round(p30_lower, 2),
            "projection_30d_upper": round(p30_upper, 2),
            "projection_60d_lower": round(p60_lower, 2),
            "projection_60d_upper": round(p60_upper, 2),
            "projection_90d_lower": round(p90_lower, 2),
            "projection_90d_upper": round(p90_upper, 2),
            "confidence_band": {
                "label": "95% Confidence Band",
                "confidence_level": 0.95,
                "30d": [round(p30_lower, 2), round(p30_upper, 2)],
                "60d": [round(p60_lower, 2), round(p60_upper, 2)],
                "90d": [round(p90_lower, 2), round(p90_upper, 2)]
            },
            "historical": valid_points
        }


# Singleton instance
run_history_manager = RunHistoryManager()
