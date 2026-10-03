"""Read-only alert aggregation through the Wazuh Indexer (OpenSearch) API."""
from datetime import datetime, timedelta, timezone
import requests
from app.core.outbound import integration_request


class WazuhIndexerConnector:
    # Fixed query shape: callers cannot supply arbitrary indices or search scripts.
    INDEX = "wazuh-alerts-*"
    MAX_PAGES = 20

    def __init__(self, base_url, username, password):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password

    def _search(self, body):
        try:
            response = integration_request(
                "post", f"{self.base_url}/{self.INDEX}/_search",
                auth=(self.username, self.password), json=body, timeout=15,
                params={"allow_no_indices": "false", "ignore_unavailable": "false"},
            )
            if response.status_code in (401, 403):
                raise ConnectionError("Wazuh Indexer authentication or search permission denied. Use Indexer credentials with read access to wazuh-alerts-*, not Manager API credentials.")
            if response.status_code == 404:
                raise ConnectionError("Wazuh alert indices are unavailable. Check the Indexer endpoint and whether Filebeat has indexed alerts.")
            if response.status_code != 200:
                raise ConnectionError(f"Wazuh Indexer search failed (HTTP {response.status_code}).")
            result = response.json()
            if result.get("timed_out") or result.get("_shards", {}).get("failed", 0):
                raise ConnectionError("Wazuh Indexer returned an incomplete search; measurements were not updated.")
            return result
        except requests.exceptions.SSLError:
            raise ConnectionError("Wazuh Indexer certificate could not be verified. Use a trusted HTTPS endpoint matching its hostname.") from None
        except requests.exceptions.Timeout:
            raise ConnectionError("Wazuh Indexer search timed out.") from None
        except requests.exceptions.ConnectionError:
            raise ConnectionError("Cannot reach the Wazuh Indexer endpoint.") from None
        except (ValueError, KeyError, TypeError):
            raise ConnectionError("Wazuh Indexer returned an invalid search response.") from None

    def test_connection(self):
        result = self._search({"size": 0, "track_total_hits": True, "query": {"match_all": {}}})
        total = result.get("hits", {}).get("total")
        count = total.get("value") if isinstance(total, dict) else total
        if not isinstance(count, int):
            raise ConnectionError("Endpoint did not return a valid Wazuh Indexer search response.")
        return {"success": True, "detail": f"Indexer search succeeded: {count:,} indexed alerts accessible. Hourly anomaly history is loaded on save or refresh."}

    def fetch_alert_windows(self, now=None):
        """Last 24 completed UTC hours, grouped by agent and hour (not sync calls).

        Only buckets containing indexed alerts become observations. Missing hours
        are not manufactured as zero activity. Alert volume is not raw log volume.
        """
        end = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
        start = end - timedelta(hours=24)
        query = {"range": {"timestamp": {"gte": start.isoformat(), "lt": end.isoformat()}}}
        filters = {
            "auth_failures": {"filter": {"term": {"rule.groups": "authentication_failed"}}},
            "high_severity": {"filter": {"range": {"rule.level": {"gte": 12}}}},
        }
        windows, totals, after = [], None, None
        for _ in range(self.MAX_PAGES):
            composite = {"size": 200, "sources": [
                {"agent": {"terms": {"field": "agent.id"}}},
                {"window": {"date_histogram": {"field": "timestamp", "fixed_interval": "1h"}}},
            ]}
            if after:
                composite["after"] = after
            result = self._search({"size": 0, "track_total_hits": True, "query": query, "aggs": {
                **filters, "windows": {"composite": composite, "aggs": filters},
            }})
            try:
                aggs = result["aggregations"]
                hits = result["hits"]["total"]
                if isinstance(hits, dict) and hits.get("relation") != "eq":
                    raise ValueError("Inexact alert count")
                if totals is None:
                    totals = (hits["value"] if isinstance(hits, dict) else hits,
                              aggs["auth_failures"]["doc_count"], aggs["high_severity"]["doc_count"])
                    if any(not isinstance(n, int) or isinstance(n, bool) or n < 0 for n in totals) or any(n > totals[0] for n in totals[1:]):
                        raise ValueError("Invalid aggregate counts")
                for bucket in aggs["windows"]["buckets"]:
                    timestamp = datetime.fromtimestamp(bucket["key"]["window"] / 1000, timezone.utc)
                    if not start <= timestamp < end:
                        raise ValueError("Window outside requested range")
                    volume = bucket["doc_count"]
                    if not isinstance(volume, int) or isinstance(volume, bool) or volume <= 0:
                        raise ValueError("Invalid alert count")
                    for key in ("auth_failures", "high_severity"):
                        count = bucket[key]["doc_count"]
                        if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= volume:
                            raise ValueError("Invalid category count")
                    windows.append({
                        "agent_id": str(bucket["key"]["agent"]),
                        "timestamp": timestamp.isoformat(), "window_end": (timestamp + timedelta(hours=1)).isoformat(),
                        "window_seconds": 3600, "event_volume": volume, "total_alerts": volume,
                        "auth_failures": bucket["auth_failures"]["doc_count"],
                        "high_severity_alerts": bucket["high_severity"]["doc_count"],
                        "source": "Wazuh Indexer API", "is_demo": False,
                    })
                next_after = aggs["windows"].get("after_key")
                if not next_after or not aggs["windows"]["buckets"]:
                    break
                if next_after == after:
                    raise ValueError("Repeated pagination cursor")
                after = next_after
            except (KeyError, TypeError, ValueError, OverflowError):
                raise ConnectionError("Wazuh Indexer returned incomplete or invalid alert aggregations.") from None
        else:
            raise ConnectionError("Alert history exceeds the aggregation limit; narrow the integration scope before retrying.")
        return {
            "recent_alerts_24h": totals[0], "auth_failures_24h": totals[1], "high_severity_alerts_24h": totals[2],
            "alert_status": "ok", "alert_detail": None, "windows": windows,
            "range_start": start.isoformat(), "range_end": end.isoformat(),
            "window_description": "Indexed alerts in the last 24 completed UTC hours; high severity is rule.level >= 12; failed authentication is rule.groups=authentication_failed.",
        }
