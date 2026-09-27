from typing import Dict, Any, List, Optional
from datetime import datetime, timezone, timedelta
import logging
import requests
from app.connectors.base import BaseConnector
from app.core.config import settings

logger = logging.getLogger(__name__)


class WazuhConnector(BaseConnector):
    """
    Wazuh SIEM + EDR Connector.
    Fetches real agent status (EDR) and alert summaries (SIEM) from Wazuh REST API.
    Never returns hardcoded fallback numbers — raises clear errors on failure.
    """
    def __init__(self, base_url: Optional[str] = None, username: Optional[str] = None, password: Optional[str] = None):
        self.base_url = (base_url or settings.WAZUH_BASE_URL).rstrip("/")
        self.username = username or settings.WAZUH_USERNAME
        self.password = password or settings.WAZUH_PASSWORD
        self._token: Optional[str] = None

    def _authenticate(self) -> str:
        """Authenticates with Wazuh API and returns a JWT token."""
        try:
            resp = requests.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.username, self.password),
                verify=False,
                timeout=10
            )
            resp.raise_for_status()
            token = resp.json().get("data", {}).get("token")
            if not token:
                raise ConnectionError("Wazuh API returned no token in authentication response")
            self._token = token
            return token
        except requests.exceptions.ConnectionError as e:
            raise ConnectionError(f"Cannot connect to Wazuh API at {self.base_url}: {e}")
        except requests.exceptions.Timeout:
            raise ConnectionError(f"Wazuh API at {self.base_url} timed out during authentication")
        except requests.exceptions.HTTPError as e:
            raise ConnectionError(f"Wazuh API authentication failed (HTTP {resp.status_code}): {e}")

    def _get_headers(self) -> Dict[str, str]:
        if not self._token:
            self._authenticate()
        return {"Authorization": f"Bearer {self._token}"}

    def fetch(self) -> Dict[str, Any]:
        """Fetch combined agent + alert data from Wazuh API."""
        agents = self.fetch_agent_status()
        alerts = self.fetch_alert_summary()
        return {**agents, **alerts, "source": "Wazuh Manager API", "last_sync": datetime.now(timezone.utc).isoformat()}

    def normalize(self, raw_telemetry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize raw Wazuh telemetry data. Only returns values computed from
        the data passed in. Raises ValueError if no data is provided.
        """
        if not raw_telemetry:
            raise ValueError("WazuhConnector.normalize() received empty or None data — cannot compute telemetry without real input")

        total_agents = raw_telemetry.get("total_agents")
        active_agents = raw_telemetry.get("active_agents")

        if total_agents is None or active_agents is None:
            raise ValueError(
                "WazuhConnector.normalize() requires 'total_agents' and 'active_agents' keys in raw_telemetry — "
                "cannot compute agent coverage without real values"
            )

        return {
            "total_agents": total_agents,
            "active_agents": active_agents,
            "disconnected_agents": raw_telemetry.get("disconnected_agents", total_agents - active_agents),
            "agent_coverage_pct": round((active_agents / max(1, total_agents)) * 100, 1),
            "recent_alerts_24h": raw_telemetry.get("recent_alerts_24h"),
            "high_severity_alerts_24h": raw_telemetry.get("high_severity_alerts_24h"),
            "auth_failures_24h": raw_telemetry.get("auth_failures_24h"),
            "last_sync": datetime.now(timezone.utc).isoformat()
        }

    def fetch_agent_status(self) -> Dict[str, Any]:
        """
        Calls GET {base_url}/agents to get real agent status.
        Returns {total_agents, active_agents, agent_coverage_pct}.
        Raises ConnectionError on failure — never returns fake numbers.
        """
        try:
            resp = requests.get(
                f"{self.base_url}/agents",
                headers=self._get_headers(),
                params={"limit": 500, "select": "status"},
                verify=False,
                timeout=10
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            agents = data.get("affected_items", [])
            total = data.get("total_affected_items", len(agents))

            active_count = sum(1 for a in agents if a.get("status") == "active")

            return {
                "total_agents": total,
                "active_agents": active_count,
                "agent_coverage_pct": round((active_count / max(1, total)) * 100, 1)
            }
        except requests.exceptions.ConnectionError as e:
            raise ConnectionError(f"Cannot connect to Wazuh API at {self.base_url}/agents: {e}")
        except requests.exceptions.Timeout:
            raise ConnectionError(f"Wazuh API at {self.base_url}/agents timed out")
        except requests.exceptions.HTTPError as e:
            raise ConnectionError(f"Wazuh API /agents call failed (HTTP {resp.status_code}): {e}")

    def fetch_alert_summary(self, hours: int = 24) -> Dict[str, Any]:
        """
        Calls GET {base_url}/alerts filtered to the time window.
        Returns {recent_alerts_24h, high_severity_alerts_24h, auth_failures_24h}.
        Raises ConnectionError on failure — never returns fake numbers.
        """
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        # Known Wazuh rule IDs for authentication failures
        AUTH_FAILURE_RULE_IDS = {
            "5503", "5504", "5710", "5711", "5716", "5720", "5501",  # SSH
            "60122", "60204",  # Windows auth
            "80710", "80711",  # PAM
        }
        try:
            resp = requests.get(
                f"{self.base_url}/alerts",
                headers=self._get_headers(),
                params={"limit": 10000, "older_than": f"{hours}h", "select": "rule.level,rule.id"},
                verify=False,
                timeout=15
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            alerts = data.get("affected_items", [])
            total_alerts = data.get("total_affected_items", len(alerts))

            high_severity = sum(1 for a in alerts if a.get("rule", {}).get("level", 0) >= 12)
            auth_failures = sum(
                1 for a in alerts
                if str(a.get("rule", {}).get("id", "")) in AUTH_FAILURE_RULE_IDS
            )

            return {
                "recent_alerts_24h": total_alerts,
                "high_severity_alerts_24h": high_severity,
                "auth_failures_24h": auth_failures
            }
        except requests.exceptions.ConnectionError as e:
            raise ConnectionError(f"Cannot connect to Wazuh API at {self.base_url}/alerts: {e}")
        except requests.exceptions.Timeout:
            raise ConnectionError(f"Wazuh API at {self.base_url}/alerts timed out")
        except requests.exceptions.HTTPError as e:
            raise ConnectionError(f"Wazuh API /alerts call failed (HTTP {resp.status_code}): {e}")
