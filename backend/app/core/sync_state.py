from app.core.tenancy import active, read_document, write_document
"""
CRISP Telemetry Synchronization State Manager.
Persists the timestamp, source, counts (assets/findings/agents), and status (ok/error)
of all background APScheduler and on-demand synchronization jobs to backend/data/sync_state.json.
Survives server restarts and provides real-time freshness telemetry to the executive dashboard.
"""

import json
import logging
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def _iso_now() -> str:
    """Returns current UTC ISO-8601 formatted timestamp string."""
    return datetime.now(timezone.utc).isoformat()


def _resolve_sync_state_path() -> Path:
    """
    Resolves a writable path for sync_state.json.
    Tries backend/data/sync_state.json, then backend/app/data/sync_state.json,
    then ~/.crisp/sync_state.json, then system tempdir.
    """
    backend_root = Path(__file__).resolve().parents[2]
    candidates = [
        backend_root / "data" / "sync_state.json",
        Path(__file__).resolve().parent.parent / "data" / "sync_state.json",
        Path.home() / ".crisp" / "sync_state.json",
        Path(tempfile.gettempdir()) / "crisp_sync_state.json"
    ]
    for candidate in candidates:
        try:
            candidate.parent.mkdir(parents=True, exist_ok=True)
            # Test actual writeability
            test_file = candidate.parent / f".perm_check_{candidate.name}"
            test_file.write_text("ok", encoding="utf-8")
            test_file.unlink(missing_ok=True)
            return candidate
        except Exception:
            continue

    fallback = Path(tempfile.gettempdir()) / "crisp_sync_state.json"
    fallback.parent.mkdir(parents=True, exist_ok=True)
    return fallback


class SyncStateManager:
    """
    Manages persistent record of all data and telemetry synchronization jobs.
    """

    def __init__(self, storage_path: Optional[Path] = None):
        self.file_path = storage_path or _resolve_sync_state_path()
        self._secondary_paths = [
            Path(__file__).resolve().parents[2] / "data" / "sync_state.json",
            Path.home() / ".crisp" / "sync_state.json"
        ]
        self._state: Dict[str, Any] = {}
        self._load()

    def _load(self):
        """Loads sync_state.json from disk if present."""
        if active():
            self._state = read_document("sync_state", {})
            return
        if self.file_path.exists():
            try:
                with open(self.file_path, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    self._state = json.loads(content) if content else {}
            except Exception as e:
                logger.warning(f"Could not read sync state from {self.file_path}: {e}")
                self._state = {}
        else:
            # Check secondary paths if primary is empty
            for sp in self._secondary_paths:
                if sp.exists() and sp != self.file_path:
                    try:
                        with open(sp, "r", encoding="utf-8") as f:
                            content = f.read().strip()
                            if content:
                                self._state = json.loads(content)
                                return
                    except Exception:
                        pass
            self._state = {}

    def _save(self):
        """Persists current sync state dictionary to disk and mirrors to secondary paths."""
        if active():
            write_document("sync_state", self._state)
            return
        try:
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.file_path, "w", encoding="utf-8") as f:
                json.dump(self._state, f, indent=2)
        except Exception as e:
            logger.warning(f"Could not persist sync state to {self.file_path}: {e}")

        # Mirror write to secondary paths if possible
        for sp in self._secondary_paths:
            if sp != self.file_path:
                try:
                    sp.parent.mkdir(parents=True, exist_ok=True)
                    with open(sp, "w", encoding="utf-8") as f:
                        json.dump(self._state, f, indent=2)
                except Exception:
                    pass

    def record_sync(
        self,
        job_name: str,
        source: str,
        counts: Dict[str, Any],
        status: str,
        message: str = "",
        extra: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Records the outcome of a sync job.
        job_name: canonical key ('wazuh', 'iam', 'threat_intel', etc.)
        source: human-readable feed title ('Wazuh Live API', 'Keycloak Admin API')
        counts: dictionary of entity numbers ({'total_agents': 10, 'active_agents': 9})
        status: 'ok' or 'error'
        message: detail description or error message
        extra: optional arbitrary metadata
        """
        if active():
            self._load()
        now = _iso_now()
        entry: Dict[str, Any] = {
            "job": job_name,
            "source": source,
            "last_sync_at": now,
            "status": status,
            "message": message,
            "counts": counts
        }
        if extra:
            entry.update(extra)

        self._state[job_name] = entry
        self._save()
        return entry

    def get_state(self) -> Dict[str, Any]:
        """Returns the full sync state map."""
        # Ensure latest disk state
        self._load()
        return dict(self._state)

    def get_job(self, job_name: str) -> Optional[Dict[str, Any]]:
        """Returns sync status for a specific job."""
        if active():
            self._load()
        return self._state.get(job_name)

    def get_freshness_summary(self) -> Dict[str, Any]:
        """
        Returns a high-level summary suitable for displaying in executive headers.
        Extracts primary telemetry stats (Wazuh agents, IAM MFA coverage, last sync timestamps).
        """
        self._load()
        wazuh = self._state.get("wazuh", {})
        iam = self._state.get("iam", {})
        intel = self._state.get("threat_intel", {})

        wazuh_counts = wazuh.get("counts", {})
        iam_counts = iam.get("counts", {})

        return {
            "wazuh": {
                "source": wazuh.get("source", "Wazuh EDR/SIEM"),
                "last_sync_at": wazuh.get("last_sync_at"),
                "status": wazuh.get("status", "pending"),
                "message": wazuh.get("message", "Awaiting initial sync"),
                "agents_active": wazuh_counts.get("active_agents") or wazuh.get("agents_active", 0),
                "agents_total": wazuh_counts.get("total_agents") or wazuh.get("agents_total", 0),
                "coverage_pct": wazuh.get("agent_coverage_pct", 0.0)
            },
            "iam": {
                "source": iam.get("source", "Keycloak IAM"),
                "last_sync_at": iam.get("last_sync_at"),
                "status": iam.get("status", "pending"),
                "message": iam.get("message", "Awaiting initial sync"),
                "mfa_coverage_pct": iam.get("mfa_coverage_pct", 0.0),
                "privileged_accounts": iam_counts.get("privileged_accounts", 0),
                "is_simulated": iam.get("is_simulated", False)
            },
            "threat_intel": {
                "source": intel.get("source", "CISA KEV / NVD / EPSS"),
                "last_sync_at": intel.get("last_sync_at"),
                "status": intel.get("status", "pending"),
                "message": intel.get("message", "Awaiting initial sync")
            }
        }


# Singleton instance for backend use
sync_state_manager = SyncStateManager()
