# Connect Wazuh alert telemetry

CRISP has two independent Wazuh connections under **Connectors**:

| Connection | Purpose | Credentials |
| --- | --- | --- |
| SIEM & EDR (Wazuh) | Registered-agent status and endpoint control coverage | Manager API username/password (usually port 55000) |
| Alert Telemetry (Wazuh Indexer) | Alert counts and hourly anomaly observations | Indexer account with read/search access to `wazuh-alerts-*` (usually port 9200) |

The Manager's `wazuh-wui` credentials are not Indexer credentials. Use a dedicated read-only Indexer account. A successful connection test checks a read-only search; saving or **Refresh Status** loads the alert history. No credentials or endpoint are hardcoded. Stored passwords are encrypted and omitted from API responses. Hosted guest workspaces remain isolated and expire after 24 hours; their refresh is manual.

The hosted backend must be able to reach the supplied HTTPS URL, with a trusted certificate. `localhost` would address the backend itself, not your Ubuntu VM. Private-network deployments need network connectivity configured by their operator; the public guest deployment rejects private addresses.

For the existing Tailscale Funnel setup, keep the Manager on its existing port. On the Ubuntu VM, a separate Funnel listener can forward HTTPS port 8443 to the loopback Indexer:

```bash
sudo tailscale funnel --bg --https=8443 https+insecure://127.0.0.1:9200
sudo tailscale funnel status
```

Use the **8443 URL printed by Tailscale** in the Indexer card. Do not replace the Manager URL. Funnel makes that authenticated endpoint internet reachable. Its local `https+insecure` target handles Wazuh's local self-signed certificate; CRISP still verifies the public Funnel certificate. Do not enter Indexer credentials in chat or commit them to Git.

## What is measured

The connector issues fixed, read-only OpenSearch searches against `wazuh-alerts-*`, using paginated composite aggregations grouped by `agent.id` and `timestamp`. It reads the last 24 **completed UTC hours**, excluding the current partial hour.

- Event volume means **indexed alert count**, not all raw logs.
- Failed authentication means alerts whose `rule.groups` contains `authentication_failed`.
- High severity means `rule.level >= 12`.
- Only hours with indexed alerts become observations. Missing hours are not fabricated as zero activity.
- The baseline requires at least five distinct hourly timestamps, not five button clicks or five agents observed in one hour.
- Each refresh replaces the rolling history with unique agent/hour observations, updating late arrivals without duplication.
- History is part of the workspace snapshot and uses the existing transactional PostgreSQL/SQLite persistence.
- Search errors or partial results disable scoring until a successful refresh. Missing telemetry is not converted into zero alerts.

The detector fits an unsupervised model across the collected agent/hour observations. Five windows are a startup threshold, not evidence of a calibrated or reliable threat detector. Anomalies are investigation signals, not confirmed incidents, and do not automatically change the FAIR financial model.

If no alert indices exist, check Filebeat/Indexer ingestion. If search is forbidden, check credentials and index read permissions. If fewer than five completed hours contain alerts, the UI correctly shows insufficient history.

References: [Wazuh Indexer API](https://documentation.wazuh.com/current/user-manual/indexer-api/getting-started.html), [Tailscale Funnel](https://tailscale.com/kb/1311/tailscale-funnel).
