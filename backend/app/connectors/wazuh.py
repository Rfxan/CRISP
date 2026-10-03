from typing import Dict, Any, Optional
from datetime import datetime, timezone
import requests
from app.core.outbound import integration_request
from app.connectors.base import BaseConnector
from app.core.config import settings

class WazuhConnector(BaseConnector):
    """
    Wazuh SIEM + EDR Connector.
    Fetches real agent status from the Wazuh manager API; indexed alert counts remain unavailable.
    Never returns hardcoded fallback numbers — raises clear errors on failure.
    """
    def __init__(self, base_url: Optional[str] = None, username: Optional[str] = None, password: Optional[str] = None):
        from app.core.guest_workspace import is_guest
        guest = is_guest()
        self.base_url = (base_url or settings.WAZUH_BASE_URL).rstrip("/")
        self.username = username or ("" if guest else settings.WAZUH_USERNAME)
        self.password = password or ("" if guest else settings.WAZUH_PASSWORD)
        self._token: Optional[str] = None

    def _authenticate(self) -> str:
        """Authenticates with Wazuh API and returns a JWT token."""
        try:
            resp = integration_request("post",
                f"{self.base_url}/security/user/authenticate",
                auth=(self.username, self.password),
                timeout=10
            )
            resp.raise_for_status()
            token = resp.json().get("data", {}).get("token")
            if not token:
                raise ConnectionError("Wazuh API returned no token in authentication response")
            self._token = token
            return token
        except requests.exceptions.SSLError:
            raise ConnectionError("Wazuh HTTPS certificate could not be verified. Use a certificate trusted by CRISP that matches the endpoint hostname.") from None
        except requests.exceptions.ConnectTimeout:
            raise ConnectionError("Wazuh API connection timed out. Check the API port mapping and Oracle/Ubuntu firewall rules for access from Render.") from None
        except requests.exceptions.ConnectionError:
            raise ConnectionError("Cannot reach the Wazuh API. Check that the API is running and the endpoint and firewall rules allow access from Render.") from None
        except requests.exceptions.Timeout:
            raise ConnectionError("Wazuh API did not respond before the timeout. Check API health and retry.") from None
        except requests.exceptions.HTTPError as e:
            if resp.status_code in (401, 403):
                raise ConnectionError(f"Wazuh API authentication failed (HTTP {resp.status_code}). Use API_USERNAME and API_PASSWORD, not the dashboard login.") from None
            raise ConnectionError(f"Wazuh API authentication failed (HTTP {resp.status_code})") from None

    def _get_headers(self) -> Dict[str, str]:
        if not self._token:
            self._authenticate()
        return {"Authorization": f"Bearer {self._token}"}

    def fetch(self) -> Dict[str, Any]:
        """Fetch agent data and disclose that indexed alert counts are unavailable."""
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
            "alert_status": raw_telemetry.get("alert_status"),
            "alert_detail": raw_telemetry.get("alert_detail"),
            "last_sync": datetime.now(timezone.utc).isoformat()
        }

    def fetch_agent_status(self) -> Dict[str, Any]:
        """
        Calls GET {base_url}/agents to get real agent status.
        Excludes the manager itself (agent 000) when enrolled endpoint agents exist.
        Returns {total_agents, active_agents, agent_coverage_pct, agent_names}.
        Raises ConnectionError on failure — never returns fake numbers.
        """
        try:
            resp = integration_request("get",
                f"{self.base_url}/agents",
                headers=self._get_headers(),
                params={"limit": 500, "select": "status,id,name"},
                timeout=10
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            agents = data.get("affected_items", [])
            
            # Filter out manager node (id == '000') so enrolled endpoint agents are measured
            endpoint_agents = [a for a in agents if a.get("id") != "000"]
            eval_agents = endpoint_agents if endpoint_agents else agents
            total = len(eval_agents)
            active_count = sum(1 for a in eval_agents if a.get("status") == "active")
            agent_names = [a.get("name") for a in eval_agents]

            return {
                "total_agents": total,
                "active_agents": active_count,
                "agent_coverage_pct": round((active_count / max(1, total)) * 100, 1),
                "agent_names": agent_names,
                "agents": [
                    {
                        "id": str(a.get("id", "")),
                        "name": str(a.get("name") or a.get("id") or ""),
                        "status": str(a.get("status", ""))
                    }
                    for a in eval_agents
                ]
            }
        except requests.exceptions.ConnectionError as e:
            raise ConnectionError(f"Cannot connect to Wazuh API at {self.base_url}/agents: {e}")
        except requests.exceptions.Timeout:
            raise ConnectionError(f"Wazuh API at {self.base_url}/agents timed out")
        except requests.exceptions.HTTPError as e:
            raise ConnectionError(f"Wazuh API /agents call failed (HTTP {resp.status_code}): {e}")

    def fetch_alert_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Manager API cannot supply a rolling alert search; this needs the indexer.

        Daily manager processing statistics are not equivalent to indexed alerts
        in the last 24 hours. Keep these measurements unknown, never zero.
        """
        return {
            "recent_alerts_24h": None,
            "high_severity_alerts_24h": None,
            "auth_failures_24h": None,
            "alert_status": "unavailable",
            "alert_detail": "Agent telemetry synced. Alert counts require a separate Wazuh indexer connection; the manager API does not provide alert searches."
        }
