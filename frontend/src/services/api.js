const API_BASE = '/api';

export const api = {
  async refreshConnections() {
    const res = await fetch(`${API_BASE}/connections/refresh`, { method: 'POST' });
    if (!res.ok) throw new Error('Unable to refresh connections. Please try again.');
    return res.json();
  },
  async getSummary(refresh = false) {
    const res = await fetch(`${API_BASE}/risk/summary?refresh=${refresh}`);
    if (!res.ok) throw new Error('Failed to fetch risk summary');
    return res.json();
  },

  async getEntities(level = 'asset') {
    const res = await fetch(`${API_BASE}/risk/entities?level=${level}`);
    if (!res.ok) throw new Error('Failed to fetch risk entities');
    return res.json();
  },

  async getDrivers() {
    const res = await fetch(`${API_BASE}/risk/drivers`);
    if (!res.ok) throw new Error('Failed to fetch risk drivers');
    return res.json();
  },

  async getCurve() {
    const res = await fetch(`${API_BASE}/risk/curve`);
    if (!res.ok) throw new Error('Failed to fetch loss exceedance curve');
    return res.json();
  },

  async simulate(actions, seed = 42) {
    const res = await fetch(`${API_BASE}/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ actions, seed })
    });
    if (!res.ok) throw new Error('Failed to simulate what-if scenario');
    return res.json();
  },

  async optimize(budget = 10000000.0) {
    const res = await fetch(`${API_BASE}/optimize`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ budget })
    });
    if (!res.ok) throw new Error('Failed to run investment optimization');
    return res.json();
  },

  async getPareto() {
    const res = await fetch(`${API_BASE}/pareto`);
    if (!res.ok) throw new Error('Failed to fetch pareto curve');
    return res.json();
  },

  async getCompliance(framework = 'sebi') {
    const res = await fetch(`${API_BASE}/compliance/${framework}`);
    if (!res.ok) throw new Error('Failed to fetch compliance evaluation');
    return res.json();
  },

  async getComplianceSummary() {
    const res = await fetch(`${API_BASE}/compliance/summary`);
    if (!res.ok) throw new Error('Failed to fetch compliance summary');
    return res.json();
  },

  async getEvidenceReport(framework = 'sebi', format = 'json') {
    const res = await fetch(`${API_BASE}/compliance/${framework}/evidence-report?format=${format}`);
    if (!res.ok) throw new Error('Failed to fetch compliance evidence report');
    return format === 'json' ? res.json() : res.text();
  },

  async getTelemetryAnomalies() {
    const res = await fetch(`${API_BASE}/threats/anomalies`);
    if (!res.ok) throw new Error('Failed to fetch telemetry anomalies');
    return res.json();
  },

  async injectTelemetryAnomaly(payload) {
    const res = await fetch(`${API_BASE}/threats/anomalies/inject`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload || {})
    });
    if (!res.ok) throw new Error('Failed to inject telemetry anomaly');
    return res.json();
  },

  async askAI(question) {
    const res = await fetch(`${API_BASE}/ask`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question })
    });
    if (!res.ok) throw new Error('Failed to process AI question');
    return res.json();
  },

  async injectEvent(cve_id, asset_id, severity = 'Critical', epss = 0.98) {
    const res = await fetch(`${API_BASE}/demo/inject-event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cve_id, asset_id, severity, epss })
    });
    if (!res.ok) throw new Error('Failed to inject demo threat event');
    return res.json();
  },

  async getDataQuality() {
    const res = await fetch(`${API_BASE}/health/data-quality`);
    if (!res.ok) throw new Error('Failed to fetch data quality metrics');
    return res.json();
  },

  async getTornado() {
    const res = await fetch(`${API_BASE}/sensitivity/tornado`);
    if (!res.ok) throw new Error('Failed to fetch tornado sensitivity');
    return res.json();
  },

  async getConvergence() {
    const res = await fetch(`${API_BASE}/sensitivity/convergence`);
    if (!res.ok) throw new Error('Failed to fetch convergence verification');
    return res.json();
  },

  async getSnapshot() {
    const res = await fetch(`${API_BASE}/data/snapshot`);
    if (!res.ok) throw new Error('Failed to fetch data snapshot');
    return res.json();
  },

  async updateControlCoverage(control_id, coverage_pct) {
    const res = await fetch(`${API_BASE}/controls/update`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ control_id, coverage_pct: Number(coverage_pct) })
    });
    if (!res.ok) throw new Error('Failed to update control coverage');
    return res.json();
  },

  async updateControlsCoverage(controls) {
    const res = await fetch(`${API_BASE}/controls/bulk-update`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ controls })
    });
    if (!res.ok) throw new Error('Failed to apply control changes; your edits have been kept.');
    return res.json();
  },

  async syncAll() {
    const res = await fetch(`${API_BASE}/sync/all`, {
      method: 'POST'
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to sync telemetry and intelligence');
    }
    return res.json();
  },

  async getSyncState() {
    const res = await fetch(`${API_BASE}/sync/state`);
    if (!res.ok) throw new Error('Failed to fetch sync state');
    return res.json();
  },

  async syncWazuh(simulate = false) {
    const res = await fetch(`${API_BASE}/ingest/wazuh-sync?simulate=${simulate}`, {
      method: 'POST'
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to sync Wazuh telemetry');
    }
    return res.json();
  },

  async syncIAM(simulate = false) {
    const res = await fetch(`${API_BASE}/ingest/iam-sync?simulate=${simulate}`, {
      method: 'POST'
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to sync IAM telemetry');
    }
    return res.json();
  },

  async syncLiveIntel() {
    const res = await fetch(`${API_BASE}/ingest/sync-live-intel`, {
      method: 'POST'
    });
    if (!res.ok) throw new Error('Failed to sync live EPSS and CISA KEV threat intel');
    return res.json();
  },

  async ingestOpenVAS(formData) {
    const res = await fetch(`${API_BASE}/ingest/openvas`, {
      method: 'POST',
      body: formData
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to ingest OpenVAS scan file');
    }
    return res.json();
  },

  async ingestDefender(formData) {
    const res = await fetch(`${API_BASE}/ingest/defender`, {
      method: 'POST',
      body: formData
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to ingest Microsoft Defender EDR export');
    }
    return res.json();
  },

  async ingestAssets(formData) {
    const res = await fetch(`${API_BASE}/ingest/assets`, {
      method: 'POST',
      body: formData
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to ingest assets file');
    }
    return res.json();
  },

  async addAsset(assetData) {
    const res = await fetch(`${API_BASE}/assets/add`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(assetData)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to add asset');
    }
    return res.json();
  },

  async updateAsset(assetId, assetData) {
    const res = await fetch(`${API_BASE}/assets/${encodeURIComponent(assetId)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(assetData)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to update asset');
    }
    return res.json();
  },


  async deleteAsset(assetId) {
    const res = await fetch(`${API_BASE}/assets/${encodeURIComponent(assetId)}`, {
      method: 'DELETE'
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to delete asset');
    }
    return res.json();
  },

  async clearAssetInventory() {
    const res = await fetch(`${API_BASE}/assets`, {
      method: 'DELETE'
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to clear asset inventory');
    }
    return res.json();
  },


  async inspectVendorFile(formData) {
    const res = await fetch(`${API_BASE}/vendors/inspect`, {
      method: 'POST',
      body: formData
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to inspect vendor file');
    }
    return res.json();
  },

  async previewVendorMapping(formData) {
    const res = await fetch(`${API_BASE}/vendors/preview`, {
      method: 'POST',
      body: formData
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to preview vendor mapping');
    }
    return res.json();
  },

  async saveVendorConfig(configData) {
    const res = await fetch(`${API_BASE}/vendors/save`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(configData)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to save vendor configuration');
    }
    return res.json();
  },

  async getVendorList() {
    const res = await fetch(`${API_BASE}/vendors/list`);
    if (!res.ok) throw new Error('Failed to fetch vendor configurations');
    return res.json();
  },

  async ingestVendorScan(vendorSlug, formData) {
    const res = await fetch(`${API_BASE}/ingest/vendor/${vendorSlug}`, {
      method: 'POST',
      body: formData
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to ingest scan for vendor ${vendorSlug}`);
    }
    return res.json();
  },

  async ingestUnifiedScan(formData) {
    const res = await fetch(`${API_BASE}/ingest/scan`, {
      method: 'POST',
      body: formData
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to ingest scan file');
    }
    return res.json();
  },

  async getConnections() {
    const res = await fetch(`${API_BASE}/connections`);
    if (!res.ok) throw new Error('Failed to fetch connections');
    return res.json();
  },

  async testConnection(category, connectionData) {
    const res = await fetch(`${API_BASE}/connections/${category}/test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(connectionData)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Test connection request failed');
    }
    return res.json();
  },

  async saveConnection(category, connectionData) {
    const res = await fetch(`${API_BASE}/connections/${category}/save`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(connectionData)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Save connection failed');
    }
    return res.json();
  },

  async removeConnection(category) {
    const res = await fetch(`${API_BASE}/connections/${category}`, {
      method: 'DELETE'
    });
    if (!res.ok) throw new Error('Failed to remove connection');
    return res.json();
  },

  async getAIConfig() {
    const res = await fetch(`${API_BASE}/ai/config`);
    if (!res.ok) throw new Error('Failed to fetch AI configuration');
    return res.json();
  },

  async saveAIConfig(configData) {
    const res = await fetch(`${API_BASE}/ai/config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(configData)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to save AI configuration');
    }
    return res.json();
  },

  async testAIConnection(configData) {
    const res = await fetch(`${API_BASE}/ai/test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(configData)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Test AI connection failed');
    }
    return res.json();
  }
};
