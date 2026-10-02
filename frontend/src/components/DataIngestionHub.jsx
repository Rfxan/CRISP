import React, { useState, useEffect } from 'react';
import { 
  Database, UploadCloud, RefreshCw, Shield, AlertTriangle, 
  CheckCircle2, FileText, Sliders, Globe, Server, Activity,
  Sparkles, Plus, PlusCircle, Cpu, Crosshair, Trash2, Pencil
} from 'lucide-react';
import { formatINR } from '../utils/formatters';
import { api } from '../services/api';
import VendorWizard from './VendorWizard';
import AddAssetForm from './AddAssetForm';

function isBetterControlState(candidate, current) {
  // 1. Most recent last_checked timestamp
  if (candidate.last_checked && !current.last_checked) return true;
  if (!candidate.last_checked && current.last_checked) return false;
  if (candidate.last_checked && current.last_checked) {
    const candTime = new Date(candidate.last_checked).getTime();
    const currTime = new Date(current.last_checked).getTime();
    if (!isNaN(candTime) && !isNaN(currTime)) {
      if (candTime > currTime) return true;
      if (candTime < currTime) return false;
    }
  }

  // 2. Prefer non-null / non-undefined coverage_pct
  const candHasCov = candidate.coverage_pct !== null && candidate.coverage_pct !== undefined;
  const currHasCov = current.coverage_pct !== null && current.coverage_pct !== undefined;
  if (candHasCov && !currHasCov) return true;
  if (!candHasCov && currHasCov) return false;

  // 3. Prefer connected evidence over "Not Connected"
  const candConn = candidate.evidence_ref && candidate.evidence_ref.toLowerCase() !== 'not connected';
  const currConn = current.evidence_ref && current.evidence_ref.toLowerCase() !== 'not connected';
  if (candConn && !currConn) return true;
  if (!candConn && currConn) return false;

  // 4. Prefer user-set assumption
  if (candidate.is_user_assumed && !current.is_user_assumed) return true;

  // 5. Default keep-last rule
  return true;
}

export default function DataIngestionHub({ onDataUpdated }) {
  const notifyUpdated = () => {
    if (onDataUpdated) onDataUpdated();
  };
  const [snapshot, setSnapshot] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeSection, setActiveSection] = useState('assets');
  const [syncingIntel, setSyncingIntel] = useState(false);
  const [uploadingScan, setUploadingScan] = useState(false);
  const [uploadingDefender, setUploadingDefender] = useState(false);
  const [uploadingAssets, setUploadingAssets] = useState(false);
  const [statusMsg, setStatusMsg] = useState(null);
  const [controlEdits, setControlEdits] = useState({});
  const [savingControls, setSavingControls] = useState(false);
  const [customVendors, setCustomVendors] = useState([]);
  const [uploadingVendorSlug, setUploadingVendorSlug] = useState(null);
  const [showAddAssetModal, setShowAddAssetModal] = useState(false);
  const [editingAsset, setEditingAsset] = useState(null);
  const [anomalyData, setAnomalyData] = useState(null);
  const [anomalyLoading, setAnomalyLoading] = useState(false);
  const [injectingAnomaly, setInjectingAnomaly] = useState(false);

  const fetchAnomalies = async () => {
    try {
      setAnomalyLoading(true);
      const res = await api.getTelemetryAnomalies();
      setAnomalyData(res);
    } catch (err) {
      console.error('Failed to fetch telemetry anomalies:', err);
    } finally {
      setAnomalyLoading(false);
    }
  };

  const handleInjectAnomaly = async () => {
    try {
      setInjectingAnomaly(true);
      const res = await api.injectTelemetryAnomaly();
      setStatusMsg({
        type: 'success',
        text: `Synthetic Telemetry Spike Injected! Agent '${res.injected_window?.agent_name || res.injected_window?.agent_id}' scored ${(res.score_evaluation?.anomaly_score != null ? (res.score_evaluation.anomaly_score * 100).toFixed(0) : 'High')}% (${res.label}).`
      });
      await fetchAnomalies();
      notifyUpdated();
    } catch (err) {
      setStatusMsg({ type: 'error', text: 'Failed to inject anomaly: ' + err.message });
    } finally {
      setInjectingAnomaly(false);
    }
  };

  const handleAssetAdded = async (res) => {
    setStatusMsg({
      type: 'success',
      text: `Asset '${res.asset?.name || res.asset?.id}' added successfully! Total assets: ${res.total_active_assets}. New Organization EAL: ${res.new_eal ? formatINR(res.new_eal) : 'Recalculated'}`
    });
    await fetchSnapshot();
    notifyUpdated();
  };

  const handleAssetUpdated = async (res) => {
    setStatusMsg({
      type: 'success',
      text: `Asset '${res.asset?.name || res.asset?.id}' updated successfully! New Organization EAL: ${res.new_eal ? formatINR(res.new_eal) : 'Recalculated'}`
    });
    setEditingAsset(null);
    await fetchSnapshot();
    notifyUpdated();
  };

  const handleDeleteAsset = async (assetId, assetName) => {
    const label = assetName && assetName !== assetId ? `${assetName} (${assetId})` : assetId;
    if (!window.confirm(`Are you sure you want to delete asset "${label}"? This will remove the asset and recalculate FAIR risk exposure.`)) {
      return;
    }
    setStatusMsg(null);
    try {
      const res = await api.deleteAsset(assetId);
      setStatusMsg({
        type: 'success',
        text: `Asset '${assetId}' deleted successfully. Active assets: ${res.total_active_assets}.${res.new_eal ? ` New Organization EAL: ${formatINR(res.new_eal)}` : ''}`
      });
      await fetchSnapshot();
      notifyUpdated();
    } catch (err) {
      setStatusMsg({ type: 'error', text: 'Failed to delete asset: ' + err.message });
    }
  };

  const handleClearInventory = async () => {
    if (!window.confirm(`Are you sure you want to delete the entire asset inventory (${assets.length} assets)? This will clear all network nodes and recalculate risk exposure.`)) {
      return;
    }
    setStatusMsg(null);
    try {
      const res = await api.clearAssetInventory();
      setStatusMsg({
        type: 'success',
        text: `Asset inventory cleared successfully (${res.assets_removed || assets.length} assets removed).`
      });
      await fetchSnapshot();
      notifyUpdated();
    } catch (err) {
      setStatusMsg({ type: 'error', text: 'Failed to clear asset inventory: ' + err.message });
    }
  };


  const fetchVendors = async () => {
    try {
      const res = await api.getVendorList();
      setCustomVendors(res.vendors || []);
    } catch (err) {
      console.error('Failed to fetch custom vendors:', err);
    }
  };

  const fetchSnapshot = async (resetEdits = true) => {
    try {
      const data = await api.getSnapshot();
      setSnapshot(data);
      // Reset pending edits on fresh snapshot
      if (resetEdits) setControlEdits({});
    } catch (err) {
      console.error('Failed to fetch snapshot:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSnapshot();
    fetchVendors();
    fetchAnomalies();
  }, []);

  const handleSyncIntel = async () => {
    setSyncingIntel(true);
    setStatusMsg(null);
    try {
      const res = await api.syncLiveIntel();
      setStatusMsg({
        type: 'success',
        text: `Threat Intel Synchronized: ${res.synced_cves} CVEs enriched via FIRST EPSS API & CISA KEV catalog. Source: ${res.source}`
      });
      await fetchSnapshot();
      notifyUpdated();
    } catch (err) {
      setStatusMsg({ type: 'error', text: 'Failed to sync live intel: ' + err.message });
    } finally {
      setSyncingIntel(false);
    }
  };

  const handleControlSliderChange = (ctrlId, value) => {
    setControlEdits(prev => ({ ...prev, [ctrlId]: Number(value) }));
  };

  const handleSaveControl = async (ctrlId) => {
    if (savingControls) return;
    const val = controlEdits[ctrlId];
    if (val === undefined || val === null) return;
    setSavingControls(true);
    try {
      await api.updateControlCoverage(ctrlId, val);
      setStatusMsg({
        type: 'success',
        text: `Control ${ctrlId} coverage updated to ${val}%. FAIR Monte Carlo re-executed dynamically!`
      });
      setControlEdits(prev => {
        const next = { ...prev };
        delete next[ctrlId];
        return next;
      });
      await fetchSnapshot(false);
      if (Object.keys(controlEdits).length === 1) notifyUpdated();
    } catch (err) {
      setStatusMsg({ type: 'error', text: 'Failed to update control: ' + err.message });
    } finally {
      setSavingControls(false);
    }
  };

  const handleSaveAllControls = async () => {
    if (savingControls || !Object.keys(controlEdits).length) return;
    setSavingControls(true);
    try {
      const controls = Object.entries(controlEdits).map(([control_id, coverage_pct]) => ({ control_id, coverage_pct }));
      const result = await api.updateControlsCoverage(controls);
      setStatusMsg({ type: 'success', text: `${result.updated_count} control assumptions applied together. Risk recalculated once.` });
      await fetchSnapshot();
      notifyUpdated();
    } catch (err) {
      setStatusMsg({ type: 'error', text: err.message });
    } finally {
      setSavingControls(false);
    }
  };

  const handleFileUpload = async (e, type) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    setStatusMsg(null);
    if (type === 'openvas') {
      setUploadingScan(true);
      try {
        const res = await api.ingestOpenVAS(formData);
        setStatusMsg({
          type: 'success',
          text: `Scan Ingested Successfully: ${res.findings_added || res.parsed} findings added. New Organization EAL: ${formatINR(res.new_eal)}`
        });
        await fetchSnapshot();
        notifyUpdated();
      } catch (err) {
        setStatusMsg({ type: 'error', text: err.message });
      } finally {
        setUploadingScan(false);
      }
    } else if (type === 'defender') {
      setUploadingDefender(true);
      try {
        const res = await api.ingestDefender(formData);
        setStatusMsg({
          type: 'success',
          text: `Microsoft Defender EDR Ingested: ${res.detections_added || res.findings_added || 0} detections added. New Organization EAL: ${formatINR(res.new_eal)}`
        });
        await fetchSnapshot();
        notifyUpdated();
      } catch (err) {
        setStatusMsg({ type: 'error', text: err.message });
      } finally {
        setUploadingDefender(false);
      }
    } else if (type === 'assets') {
      setUploadingAssets(true);
      try {
        const res = await api.ingestAssets(formData);
        setStatusMsg({
          type: 'success',
          text: `Assets Ingested Successfully: ${res.assets_loaded} inventory items loaded. New Organization EAL: ${formatINR(res.new_eal)}`
        });
        await fetchSnapshot();
        notifyUpdated();
      } catch (err) {
        setStatusMsg({ type: 'error', text: err.message });
      } finally {
        setUploadingAssets(false);
      }
    }
  };

  const handleCustomVendorUpload = async (e, vendorSlug, vendorName) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const assetCount = snapshot?.assets?.length || 0;
    if (assetCount === 0) {
      setStatusMsg({
        type: 'error',
        text: 'Please upload your asset inventory first — findings need to be linked to assets to calculate financial risk.'
      });
      e.target.value = '';
      return;
    }

    const formData = new FormData();
    formData.append('file', file);

    setUploadingVendorSlug(vendorSlug);
    setStatusMsg(null);
    try {
      const res = await api.ingestVendorScan(vendorSlug, formData);
      setStatusMsg({
        type: 'success',
        text: `Scan for ${vendorName || res.vendor} Ingested Successfully: ${res.parsed} findings added (${res.skipped} skipped). New Organization EAL: ${formatINR(res.new_eal)}`
      });
      await fetchSnapshot();
      notifyUpdated();
    } catch (err) {
      setStatusMsg({ type: 'error', text: err.message });
    } finally {
      setUploadingVendorSlug(null);
    }
  };

  const assets = snapshot?.assets || [];
  const findings = snapshot?.findings || [];
  const catalogList = snapshot?.controls_catalog || [];
  const catalog = React.useMemo(() => {
    if (Array.isArray(catalogList)) {
      return Object.fromEntries(catalogList.map(c => [c.id, c]));
    }
    return catalogList || {};
  }, [catalogList]);

  // Standing principle: controls are part of the defensive risk model; telemetry is only evidence.
  // Losing evidence source must never delete the control — it only changes evidence to Not Connected.
  const controlStates = React.useMemo(() => {
    const existing = snapshot?.control_state || [];
    const existingMap = new Map(existing.map(cs => [cs.control_id, cs]));

    const merged = [...existing];
    
    // Default scopes for key defensive controls
    const defaultScopes = {
      'CTRL-MFA-01': 'Privileged Accounts',
      'CTRL-EDR-01': 'All Endpoints',
      'CTRL-PATCH-01': 'Internet-Facing & Tier-1 Core Servers',
      'CTRL-ENC-01': 'Primary Database Repositories',
      'CTRL-WAF-01': 'DMZ Edge & Customer Ingress Ports',
      'CTRL-SEG-01': 'Payment Switch & Core Banking VLANs',
      'CTRL-BKP-01': 'Critical CBS & Payment Databases',
      'CTRL-SIEM-01': 'Enterprise-wide telemetry sources',
      'CTRL-PAM-01': 'Domain Controllers & Database Root logins',
      'CTRL-DLP-01': 'Core Banking and Customer Support endpoints',
      'CTRL-API-01': 'External Partner UPI & Banking APIs',
      'CTRL-IR-01': 'Organization Wide'
    };

    if (Array.isArray(catalogList)) {
      for (const catCtrl of catalogList) {
        if (!existingMap.has(catCtrl.id)) {
          merged.push({
            control_id: catCtrl.id,
            asset_scope: defaultScopes[catCtrl.id] || 'Enterprise Scope',
            coverage_pct: null,
            evidence_ref: 'Not Connected',
            last_checked: null,
            is_simulated: false
          });
        }
      }
    }

    // Guarantee CTRL-MFA-01 and CTRL-EDR-01 are always present even if catalog is loading
    if (!existingMap.has('CTRL-MFA-01') && !merged.some(c => c.control_id === 'CTRL-MFA-01')) {
      merged.unshift({
        control_id: 'CTRL-MFA-01',
        asset_scope: 'Privileged Accounts',
        coverage_pct: null,
        evidence_ref: 'Not Connected',
        last_checked: null,
        is_simulated: false
      });
    }
    if (!existingMap.has('CTRL-EDR-01') && !merged.some(c => c.control_id === 'CTRL-EDR-01')) {
      merged.unshift({
        control_id: 'CTRL-EDR-01',
        asset_scope: 'All Endpoints',
        coverage_pct: null,
        evidence_ref: 'Not Connected',
        last_checked: null,
        is_simulated: false
      });
    }

    // Defensive dedupe: collapse controlStates by control_id before rendering (same keep-last / best-state rule)
    const dedupedMap = new Map();
    for (const cs of merged) {
      if (!cs || !cs.control_id) continue;
      if (!dedupedMap.has(cs.control_id)) {
        dedupedMap.set(cs.control_id, cs);
      } else {
        const existingCs = dedupedMap.get(cs.control_id);
        if (isBetterControlState(cs, existingCs)) {
          dedupedMap.set(cs.control_id, cs);
        }
      }
    }

    return Array.from(dedupedMap.values());
  }, [snapshot?.control_state, catalogList]);

  const cveIntel = snapshot?.cve_intel || {};
  const wazuh = snapshot?.wazuh_telemetry || {};
  const hasWazuhTelemetry = Boolean(
    wazuh &&
    Object.keys(wazuh).length > 0 &&
    wazuh.status !== 'not_configured' &&
    wazuh.source &&
    wazuh.source !== 'none' &&
    wazuh.source !== 'not_configured' &&
    wazuh.source !== 'None (Not Configured)' &&
    (wazuh.active_agents !== undefined || wazuh.total_endpoints !== undefined || wazuh.total_agents !== undefined)
  );
  const isMockWazuh = Boolean(wazuh?.source && wazuh.source.toLowerCase().includes('mock'));

  if (loading) {
    return (
      <div className="glass-panel" style={{ padding: 48, textAlign: 'center' }}>
        <RefreshCw className="animate-spin" size={28} color="var(--primary)" style={{ margin: '0 auto 12px auto' }} />
        <p style={{ color: 'var(--text-muted)' }}>Loading live data telemetry and controls catalog...</p>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header Banner */}
      <div className="glass-panel" style={{ padding: 22, borderTop: '3px solid var(--primary)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{
              width: 44, height: 44, borderRadius: 10,
              background: 'rgba(183, 140, 102, 0.1)', border: '1px solid rgba(183, 140, 102, 0.3)',
              display: 'flex', alignItems: 'center', justifyContent: 'center'
            }}>
              <Database size={24} color="var(--primary)" />
            </div>
            <div>
              <h2 style={{ margin: 0, fontSize: 18, color: 'var(--text-main)' }}>Live Telemetry & Data Ingestion Hub</h2>
              <p style={{ margin: '4px 0 0 0', fontSize: 12, color: 'var(--text-dim)' }}>
                Real-time ingestion for OpenVAS Scans, Wazuh SIEM Agent logs, FIRST EPSS API, and Asset Criticality Schemas.
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', gap: 10 }}>
            <button
              onClick={handleSyncIntel}
              disabled={syncingIntel}
              className="btn btn-secondary"
              style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, padding: '8px 14px' }}
            >
              <RefreshCw size={14} className={syncingIntel ? 'animate-spin' : ''} />
              {syncingIntel ? 'Syncing FIRST EPSS...' : 'Sync Live EPSS & KEV API'}
            </button>
          </div>
        </div>

        {/* Live Provenance Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', gap: 12, marginTop: 18 }}>
          <div className="glass-panel" style={{ padding: 12, background: 'rgba(255,255,255,0.02)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, color: 'var(--text-dim)' }}>
              <Server size={14} color="var(--primary)" /> Active Assets
            </div>
            <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-main)', marginTop: 4 }}>{assets.length}</div>
            <div style={{ fontSize: 11, color: 'var(--accent-green)' }}>100% Validated Nodes</div>
          </div>

          <div className="glass-panel" style={{ padding: 12, background: 'rgba(255,255,255,0.02)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, color: 'var(--text-dim)' }}>
              <AlertTriangle size={14} color="var(--accent-red)" /> Active Vulnerabilities
            </div>
            <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-main)', marginTop: 4 }}>{findings.length}</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>From Scans & Feeds</div>
          </div>

          <div className="glass-panel" style={{ padding: 12, background: 'rgba(255,255,255,0.02)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, color: 'var(--text-dim)' }}>
              <Shield size={14} color="var(--accent-green)" /> Active Controls
            </div>
            <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-main)', marginTop: 4 }}>{controlStates.length}</div>
            <div style={{ fontSize: 11, color: 'var(--primary)' }}>Live Coverage Tuner</div>
          </div>

          <div className="glass-panel" style={{ padding: 12, background: 'rgba(255,255,255,0.02)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 6, fontSize: 11, color: 'var(--text-dim)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <Activity size={14} color="var(--accent-amber)" /> Wazuh SIEM Telemetry
              </div>
              {hasWazuhTelemetry ? (
                <span style={{
                  fontSize: 9,
                  fontWeight: 700,
                  padding: '2px 6px',
                  borderRadius: 4,
                  whiteSpace: 'nowrap',
                  letterSpacing: '0.02em',
                  backgroundColor: isMockWazuh ? 'rgba(217, 119, 6, 0.15)' : 'rgba(34, 197, 94, 0.15)',
                  color: isMockWazuh ? 'var(--accent-amber)' : 'var(--accent-green)',
                  border: `1px solid ${isMockWazuh ? 'rgba(217, 119, 6, 0.3)' : 'rgba(34, 197, 94, 0.3)'}`
                }}>
                  {isMockWazuh ? 'SIMULATED' : 'Wazuh Live'}
                </span>
              ) : (
                <span style={{
                  fontSize: 9,
                  fontWeight: 600,
                  padding: '2px 6px',
                  borderRadius: 4,
                  backgroundColor: 'rgba(255,255,255,0.05)',
                  color: 'var(--text-dim)'
                }}>
                  Not Connected
                </span>
              )}
            </div>
            <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-main)', marginTop: 4 }}>
              {hasWazuhTelemetry ? (
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                  {isMockWazuh && (
                    <span className="badge badge-amber" style={{ fontSize: 9, fontWeight: 700, padding: '1px 5px' }}>SIMULATED</span>
                  )}
                  <span>{`${wazuh.active_agents ?? 0} / ${wazuh.total_endpoints ?? wazuh.total_agents ?? 0}`}</span>
                </span>
              ) : (
                <span style={{ fontSize: 16, color: 'var(--text-dim)', fontWeight: 600 }}>Not Connected</span>
              )}
            </div>
            <div style={{
              fontSize: 11,
              color: hasWazuhTelemetry
                ? (isMockWazuh ? 'var(--accent-amber)' : 'var(--accent-green)')
                : 'var(--text-dim)',
              fontWeight: hasWazuhTelemetry ? 600 : 500
            }}>
              {hasWazuhTelemetry ? (isMockWazuh ? 'Simulated Telemetry Feed' : 'Agent Daemon Active') : 'Not Connected'}
            </div>
          </div>

          <div className="glass-panel" style={{ padding: 12, background: 'rgba(255,255,255,0.02)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, color: 'var(--text-dim)' }}>
              <Globe size={14} color="var(--accent-purple)" /> FIRST EPSS / CISA
            </div>
            <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-main)', marginTop: 4 }}>
              {Object.keys(cveIntel).length} CVEs
            </div>
            <div style={{ fontSize: 11, color: 'var(--accent-purple)' }}>Live Intel Enriched</div>
          </div>

          <div className="glass-panel" style={{ padding: 12, background: 'rgba(255,255,255,0.02)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, color: 'var(--text-dim)' }}>
              <Crosshair size={14} color="#60a5fa" /> Defender EDR
            </div>
            <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-main)', marginTop: 4 }}>
              {findings.filter(f => (f.source && f.source.toLowerCase().includes('defender')) || (f.id && f.id.startsWith('MISCONF-EDR-'))).length}
            </div>
            <div style={{ fontSize: 11, color: '#60a5fa' }}>Advanced Hunting</div>
          </div>

          <div className="glass-panel" style={{ padding: 12, background: 'rgba(255,255,255,0.02)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, color: 'var(--text-dim)' }}>
              <Cpu size={14} color="var(--accent-amber)" /> ML IsolationForest
            </div>
            <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-main)', marginTop: 4 }}>
              {anomalyData?.is_insufficient ? (
                <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>Insufficient Baseline</span>
              ) : (
                <span>{anomalyData?.anomalies_detected || 0} Anomal{anomalyData?.anomalies_detected === 1 ? 'y' : 'ies'}</span>
              )}
            </div>
            <div style={{ fontSize: 10, color: (anomalyData?.anomalies_detected || 0) > 0 ? 'var(--accent-red)' : 'var(--accent-green)' }}>
              {anomalyData?.is_insufficient ? '< 5 windows' : 'Emerging Threats Signal'}
            </div>
          </div>
        </div>

        {/* Status Message */}
        {statusMsg && (
          <div style={{
            marginTop: 16,
            padding: '10px 14px',
            borderRadius: 8,
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            fontSize: 12,
            background: statusMsg.type === 'success' ? 'rgba(126, 143, 129, 0.15)' : 'rgba(201, 114, 114, 0.15)',
            border: `1px solid ${statusMsg.type === 'success' ? 'var(--accent-green)' : 'var(--accent-red)'}`,
            color: 'var(--text-main)'
          }}>
            {statusMsg.type === 'success' ? <CheckCircle2 size={16} color="var(--accent-green)" /> : <AlertTriangle size={16} color="var(--accent-red)" />}
            <span>{statusMsg.text}</span>
          </div>
        )}
      </div>

      {/* Guided Onboarding Order Banner */}
      <div style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-color)',
        borderRadius: 12,
        padding: '14px 20px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 16
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--primary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Guided Ingestion Order:
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
            <span style={{
              width: 22, height: 22, borderRadius: '50%',
              background: assets.length > 0 ? 'var(--accent-green)' : 'var(--primary)',
              color: '#051026', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 800, fontSize: 11
            }}>
              1
            </span>
            <span style={{ color: assets.length > 0 ? 'var(--accent-green)' : 'var(--text-main)', fontWeight: 600 }}>
              Upload Asset Inventory (CSV) {assets.length > 0 ? '✓' : '(Required First)'}
            </span>
          </div>
          <span style={{ color: 'var(--text-dim)' }}>→</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
            <span style={{
              width: 22, height: 22, borderRadius: '50%',
              background: findings.length > 0 ? 'var(--accent-green)' : (assets.length > 0 ? 'var(--primary)' : 'rgba(255,255,255,0.2)'),
              color: '#051026', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 800, fontSize: 11
            }}>
              2
            </span>
            <span style={{ color: findings.length > 0 ? 'var(--accent-green)' : (assets.length > 0 ? 'var(--text-main)' : 'var(--text-dim)'), fontWeight: 600 }}>
              Upload Vulnerability Scan or Connect SIEM/IAM {findings.length > 0 ? '✓' : ''}
            </span>
          </div>
          <span style={{ color: 'var(--text-dim)' }}>→</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
            <span style={{
              width: 22, height: 22, borderRadius: '50%',
              background: 'rgba(255,255,255,0.2)',
              color: 'var(--text-main)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 800, fontSize: 11
            }}>
              3
            </span>
            <span style={{ color: 'var(--text-muted)' }}>
              Tune Control Coverage & View Risk
            </span>
          </div>
        </div>
      </div>

      {/* Navigation Subtabs (Ordered 1 to 4) */}
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <button
          onClick={() => setActiveSection('assets')}
          className="btn"
          style={{
            background: activeSection === 'assets' ? 'rgba(183, 140, 102, 0.15)' : 'rgba(255,255,255,0.03)',
            border: activeSection === 'assets' ? '1px solid var(--primary)' : '1px solid var(--border-color)',
            color: activeSection === 'assets' ? 'var(--primary)' : 'var(--text-muted)',
            display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, padding: '8px 16px'
          }}
        >
          <Server size={15} /> Step 1: Asset Inventory ({assets.length})
        </button>

        <button
          onClick={() => setActiveSection('scans')}
          className="btn"
          style={{
            background: activeSection === 'scans' ? 'rgba(183, 140, 102, 0.15)' : 'rgba(255,255,255,0.03)',
            border: activeSection === 'scans' ? '1px solid var(--primary)' : '1px solid var(--border-color)',
            color: activeSection === 'scans' ? 'var(--primary)' : 'var(--text-muted)',
            display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, padding: '8px 16px'
          }}
        >
          <UploadCloud size={15} /> Step 2: Vulnerability Scans ({findings.length})
        </button>

        <button
          onClick={() => setActiveSection('controls')}
          className="btn"
          style={{
            background: activeSection === 'controls' ? 'rgba(183, 140, 102, 0.15)' : 'rgba(255,255,255,0.03)',
            border: activeSection === 'controls' ? '1px solid var(--primary)' : '1px solid var(--border-color)',
            color: activeSection === 'controls' ? 'var(--primary)' : 'var(--text-muted)',
            display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, padding: '8px 16px'
          }}
        >
          <Sliders size={15} /> Step 3: Control Coverage ({controlStates.length})
        </button>

        <button
          onClick={() => setActiveSection('wizard')}
          className="btn"
          style={{
            background: activeSection === 'wizard' ? 'rgba(183, 140, 102, 0.15)' : 'rgba(255,255,255,0.03)',
            border: activeSection === 'wizard' ? '1px solid var(--primary)' : '1px solid var(--border-color)',
            color: activeSection === 'wizard' ? 'var(--primary)' : 'var(--text-muted)',
            display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, padding: '8px 16px'
          }}
        >
          <Sparkles size={15} color="var(--primary)" /> Vendor Onboarding Wizard {customVendors.length > 0 && `(${customVendors.length})`}
        </button>

        <button
          onClick={() => setActiveSection('anomalies')}
          className="btn"
          style={{
            background: activeSection === 'anomalies' ? 'rgba(183, 140, 102, 0.15)' : 'rgba(255,255,255,0.03)',
            border: activeSection === 'anomalies' ? '1px solid var(--primary)' : '1px solid var(--border-color)',
            color: activeSection === 'anomalies' ? 'var(--primary)' : 'var(--text-muted)',
            display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, padding: '8px 16px'
          }}
        >
          <Cpu size={15} color="var(--accent-amber)" /> Emerging Threats (ML IsolationForest)
          {(anomalyData?.anomalies_detected || 0) > 0 && (
            <span className="badge badge-critical" style={{ fontSize: 10, padding: '1px 6px', marginLeft: 4 }}>
              {anomalyData.anomalies_detected}
            </span>
          )}
        </button>
      </div>

      {/* SECTION 1: Control Coverage Tuner */}
      {activeSection === 'controls' && (
        <div className="glass-panel" style={{ padding: 22 }} onKeyDown={e => {
          if (e.key === 'Enter') { e.preventDefault(); handleSaveAllControls(); }
        }}>
          <div style={{ marginBottom: 16 }}>
            <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-main)' }}>Dynamic Control Coverage & Mitigation Tuner</h3>
            <p style={{ margin: '4px 0 0 0', fontSize: 12, color: 'var(--text-dim)' }}>
              Adjust multiple sliders, then click Apply all changes or press Enter to save them together and recalculate risk once.
            </p>
            <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 12, marginTop: 14 }}>
              <button type="button" className="btn btn-primary" disabled={savingControls || !Object.keys(controlEdits).length} onClick={handleSaveAllControls}>
                {savingControls ? 'Applying changes…' : `Apply all changes (${Object.keys(controlEdits).length})`}
              </button>
              <button type="button" className="btn" disabled={savingControls || !Object.keys(controlEdits).length} onClick={() => setControlEdits({})}>Discard changes</button>
              <span
                role="status"
                className={`badge ${Object.keys(controlEdits).length ? 'badge-simulated' : 'badge-real'}`}
                style={{ fontSize: 11, padding: '6px 10px', letterSpacing: '0.02em' }}
              >
                {savingControls ? 'Saving changes…' : Object.keys(controlEdits).length
                  ? `${Object.keys(controlEdits).length} unsaved change${Object.keys(controlEdits).length === 1 ? '' : 's'}`
                  : 'No pending changes'}
              </span>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 16 }}>
            {controlStates.map(cs => {
              const meta = catalog[cs.control_id] || {};
              const capex = meta.implementation_cost || meta.capex || (cs.control_id === 'CTRL-MFA-01' ? 1500000 : (cs.control_id === 'CTRL-EDR-01' ? 2500000 : 0));
              const opex = meta.annual_cost || (cs.control_id === 'CTRL-MFA-01' ? 450000 : (cs.control_id === 'CTRL-EDR-01' ? 1200000 : 0));

              const isEdr = cs.control_id === 'CTRL-EDR-01';
              const isMfa = cs.control_id === 'CTRL-MFA-01';

              // Live telemetry checks
              const isEdrLive = isEdr && Boolean(hasWazuhTelemetry && !isMockWazuh && (cs.evidence_ref?.includes('Wazuh Live') || cs.evidence_ref?.includes('Wazuh Live API')));
              const isMfaLive = isMfa && Boolean(cs.evidence_ref?.includes('Keycloak Live'));
              const isEdrSimulated = isEdr && Boolean(isMockWazuh || cs.is_simulated || cs.evidence_ref?.toLowerCase().includes('mock'));
              const isMfaSimulated = isMfa && Boolean(cs.is_simulated || cs.evidence_ref?.toLowerCase().includes('mock'));

              // -------------------------------------------------------------
              // THREE DISTINCT STATES PER CONTROL (MEASURED, USER-SET, NO DATA)
              // -------------------------------------------------------------

              // State 2: USER-SET — shown ONLY after the user explicitly clicks "Set Assumption" and picks a value.
              const isUserSet = Boolean(cs.is_user_assumed || cs.evidence_ref?.includes('User Assumption'));

              // State 1: MEASURED — value comes from live / connected telemetry
              const isMeasured = !isUserSet && Boolean(
                cs.evidence_ref &&
                cs.evidence_ref !== 'Not Connected' &&
                !cs.evidence_ref.includes('User Assumption') &&
                cs.coverage_pct != null &&
                (
                  (!isEdr && !isMfa) ||
                  (isEdr && (hasWazuhTelemetry || cs.evidence_ref?.toLowerCase().includes('wazuh'))) ||
                  (isMfa && (cs.evidence_ref?.toLowerCase().includes('keycloak') || cs.evidence_ref?.toLowerCase().includes('iam')))
                )
              );

              // State 3: NO DATA — no telemetry and no user input.
              const isNoData = !isUserSet && !isMeasured;

              const isSimulated = isMeasured && Boolean(isEdrSimulated || isMfaSimulated || cs.is_simulated || cs.evidence_ref?.toLowerCase().includes('mock'));

              const userHasEdited = controlEdits[cs.control_id] !== undefined && controlEdits[cs.control_id] !== null;
              const baseCov = isNoData ? 0 : (cs.coverage_pct ?? 0);
              const sliderVal = Number(userHasEdited ? controlEdits[cs.control_id] : baseCov);
              const hasChanged = userHasEdited && (isNoData ? controlEdits[cs.control_id] > 0 : controlEdits[cs.control_id] !== baseCov);

              return (
                <div
                  key={cs.control_id}
                  className="glass-panel"
                  style={{
                    padding: 18,
                    background: 'rgba(255,255,255,0.02)',
                    border: hasChanged ? '1px solid var(--primary)' : '1px solid var(--border-color)'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                    <div>
                      <span className="badge badge-cyan" style={{ fontSize: 10, marginRight: 6 }}>{cs.control_id}</span>
                      <strong style={{ fontSize: 14, color: 'var(--text-main)' }}>{meta.name || cs.control_id}</strong>
                      <div style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 2 }}>{cs.asset_scope}</div>
                    </div>
                    <div style={{ textAlign: 'right' }}>
                      {isNoData ? (
                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 3 }}>
                          <span
                            className="badge"
                            style={{
                              fontSize: 9,
                              fontWeight: 600,
                              padding: '2px 7px',
                              color: 'var(--text-dim)',
                              background: 'rgba(0,0,0,0.03)',
                              border: '1px solid var(--border-color)',
                              letterSpacing: '0.02em',
                              textTransform: 'none'
                            }}
                          >
                            NO DATA — conservative 0% default
                          </span>
                          <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-dim)' }}>
                            {userHasEdited ? `${sliderVal}% (unapplied)` : '0%'}
                          </div>
                          <div style={{ fontSize: 10, color: 'var(--text-dim)' }}>
                            {userHasEdited ? 'pending assumption' : 'conservative default'}
                          </div>
                        </div>
                      ) : isUserSet ? (
                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 3 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <span
                              className="badge badge-simulated"
                              style={{
                                fontSize: 9,
                                fontWeight: 700,
                                padding: '2px 7px',
                                color: 'var(--accent-amber)',
                                letterSpacing: '0.04em'
                              }}
                            >
                              USER-SET
                            </span>
                            <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--accent-amber)' }}>
                              {sliderVal}%
                            </div>
                          </div>
                          <div style={{ fontSize: 10, color: 'var(--accent-amber)' }}>user-set, not measured</div>
                        </div>
                      ) : (
                        /* MEASURED */
                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 3 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <span
                              className="badge badge-real"
                              style={{
                                fontSize: 9,
                                fontWeight: 700,
                                padding: '2px 7px',
                                color: isSimulated ? 'var(--accent-amber)' : 'var(--accent-green)',
                                letterSpacing: '0.04em'
                              }}
                            >
                              {isSimulated ? 'MEASURED (MOCK)' : 'MEASURED'}
                            </span>
                            <div
                              style={{
                                fontSize: 18,
                                fontWeight: 700,
                                color: sliderVal >= 90 ? 'var(--accent-green)' : (sliderVal >= 60 ? 'var(--accent-amber)' : 'var(--accent-red)')
                              }}
                            >
                              {sliderVal}%
                            </div>
                          </div>
                          <div style={{ fontSize: 10, color: isSimulated ? 'var(--accent-amber)' : 'var(--accent-green)' }}>
                            {isSimulated ? 'Simulated Telemetry' : 'Live Telemetry'}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>

                  <p style={{ fontSize: 11, color: 'var(--text-muted)', margin: '8px 0', lineHeight: 1.4 }}>
                    {meta.description || 'Enterprise defensive control'}
                  </p>

                  <div style={{ display: 'flex', gap: 16, fontSize: 11, color: 'var(--text-dim)', marginBottom: 12, flexWrap: 'wrap' }}>
                    <span>CapEx: <strong>{formatINR(capex)}</strong></span>
                    <span>OpEx: <strong>{formatINR(opex)}/yr</strong></span>
                    <span>
                      Evidence:{' '}
                      {isNoData ? (
                        <>
                          <strong style={{ color: 'var(--text-dim)' }}>Not Connected</strong>
                          <span
                            className="badge"
                            style={{
                              fontSize: 9,
                              marginLeft: 6,
                              color: 'var(--text-dim)',
                              background: 'rgba(0,0,0,0.03)',
                              border: '1px solid var(--border-color)',
                              padding: '1px 5px'
                            }}
                          >
                            NO DATA
                          </span>
                        </>
                      ) : isUserSet ? (
                        <>
                          <strong style={{ color: 'var(--accent-amber)' }}>User Assumption (unmeasured)</strong>
                          <span
                            className="badge badge-simulated"
                            style={{
                              fontSize: 9,
                              marginLeft: 6,
                              color: 'var(--accent-amber)',
                              padding: '1px 5px'
                            }}
                          >
                            USER-SET
                          </span>
                        </>
                      ) : (
                        <>
                          <strong style={{ color: isSimulated ? 'var(--accent-amber)' : 'var(--accent-green)' }}>
                            {cs.evidence_ref}
                          </strong>
                          <span
                            className="badge badge-real"
                            style={{
                              fontSize: 9,
                              marginLeft: 6,
                              color: isSimulated ? 'var(--accent-amber)' : 'var(--accent-green)',
                              padding: '1px 5px'
                            }}
                          >
                            MEASURED
                          </span>
                          {cs.last_checked && (
                            <span style={{ fontSize: 10, color: 'var(--text-dim)', marginLeft: 8 }}>
                              · Sync: {new Date(cs.last_checked).toLocaleTimeString()}
                            </span>
                          )}
                        </>
                      )}
                    </span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <input
                      type="range"
                      aria-label={`${cs.control_id} coverage`}
                      disabled={savingControls}
                      min="0"
                      max="100"
                      step="5"
                      value={sliderVal}
                      onChange={(e) => handleControlSliderChange(cs.control_id, e.target.value)}
                      style={{ flex: 1, accentColor: 'var(--primary)', cursor: 'pointer' }}
                    />
                    <button
                      onClick={() => handleSaveControl(cs.control_id)}
                      disabled={savingControls || !hasChanged}
                      className="btn btn-primary"
                      style={{
                        padding: '6px 12px',
                        fontSize: 11,
                        opacity: hasChanged ? 1 : 0.5,
                        cursor: hasChanged ? 'pointer' : 'default'
                      }}
                    >
                      {isNoData ? 'Set Assumption' : 'Update'}
                    </button>
                  </div>
                  {isNoData && !userHasEdited && (
                    <div style={{ fontSize: 10, color: 'var(--text-dim)', marginTop: 6, fontStyle: 'italic' }}>
                      * No telemetry connected. Risk engine conservatively models 0% coverage. Move slider and click "Set Assumption" to set a custom assumption.
                    </div>
                  )}
                  {isNoData && userHasEdited && (
                    <div style={{ fontSize: 10, color: 'var(--accent-amber)', marginTop: 6, fontStyle: 'italic' }}>
                      * Selected assumption: {sliderVal}%. Click "Set Assumption" to apply to risk model.
                    </div>
                  )}
                  {isUserSet && !userHasEdited && (
                    <div style={{ fontSize: 10, color: 'var(--accent-amber)', marginTop: 6, fontStyle: 'italic' }}>
                      * User-set assumption ({sliderVal}%). Risk engine uses this value because telemetry is not connected.
                    </div>
                  )}
                  {isUserSet && userHasEdited && (
                    <div style={{ fontSize: 10, color: 'var(--accent-amber)', marginTop: 6, fontStyle: 'italic' }}>
                      * Adjusting assumption: {sliderVal}%. Click "Update" to recalibrate risk.
                    </div>
                  )}
                  {isMeasured && userHasEdited && (
                    <div style={{ fontSize: 10, color: 'var(--primary)', marginTop: 6, fontStyle: 'italic' }}>
                      * Tuning what-if override: {sliderVal}%. Click "Update" to simulate override.
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* SECTION 2: Vulnerability Ingestion */}
      {activeSection === 'scans' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          {/* File Upload Zone */}
          <div className="glass-panel" style={{ padding: 22, border: '2px dashed var(--border-color)' }}>
            <div style={{ textAlign: 'center', marginBottom: 18 }}>
              <UploadCloud size={36} color="var(--primary)" style={{ margin: '0 auto 10px auto' }} />
              <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-main)' }}>Vulnerability Scan & Posture Ingestion</h3>
              <p style={{ margin: '6px auto 0 auto', fontSize: 12, color: 'var(--text-dim)', maxWidth: 540 }}>
                Upload scan exports from built-in scanners (OpenVAS, Nessus) or any custom onboarded tool. The system maps assets and enriches findings with live EPSS & KEV threat intel.
              </p>
            </div>

            {/* Ingestion Options Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 14 }}>
              {/* Option 1: Built-in Scanners */}
              <div className="glass-panel" style={{ padding: 16, background: 'rgba(183, 140, 102, 0.03)', border: '1px solid rgba(183, 140, 102, 0.3)', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                    <strong style={{ fontSize: 13, color: 'var(--text-main)' }}>Built-in Scanners</strong>
                    <span className="badge badge-cyan" style={{ fontSize: 10 }}>Auto-Detect</span>
                  </div>
                  <p style={{ margin: '0 0 12px 0', fontSize: 11, color: 'var(--text-dim)' }}>
                    OpenVAS (XML, CSV, JSON) and Tenable Nessus (.nessus XML).
                  </p>
                </div>
                <label className="btn btn-primary" style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, padding: '8px 14px', fontSize: 12 }}>
                  <FileText size={14} />
                  <span>{uploadingScan ? 'Parsing Scan...' : 'Upload OpenVAS / Nessus'}</span>
                  <input
                    type="file"
                    accept=".xml,.nessus,.csv,.json"
                    onChange={(e) => handleFileUpload(e, 'openvas')}
                    disabled={uploadingScan}
                    style={{ display: 'none' }}
                  />
                </label>
              </div>

              {/* Option 2: Microsoft Defender for Endpoint (EDR) */}
              <div className="glass-panel" style={{ padding: 16, background: 'rgba(96, 165, 250, 0.03)', border: '1px solid rgba(96, 165, 250, 0.3)', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                    <strong style={{ fontSize: 13, color: 'var(--text-main)' }}>Microsoft Defender EDR</strong>
                    <span className="badge" style={{ fontSize: 10, background: 'rgba(96, 165, 250, 0.2)', color: '#60a5fa' }}>Hunting Export</span>
                  </div>
                  <p style={{ margin: '0 0 12px 0', fontSize: 11, color: 'var(--text-dim)' }}>
                    Advanced Hunting CSV or JSON export with automatic MITRE ATT&CK technique parsing.
                  </p>
                </div>
                <label className="btn btn-secondary" style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, padding: '8px 14px', fontSize: 12, borderColor: '#60a5fa', color: '#93c5fd' }}>
                  <Crosshair size={14} />
                  <span>{uploadingDefender ? 'Parsing EDR Telemetry...' : 'Upload Defender Hunting Export'}</span>
                  <input
                    type="file"
                    accept=".csv,.json"
                    onChange={(e) => handleFileUpload(e, 'defender')}
                    disabled={uploadingDefender}
                    style={{ display: 'none' }}
                  />
                </label>
              </div>

              {/* Option 2+: Configured Custom Vendors */}
              {customVendors.map((v) => {
                const isUploadingThis = uploadingVendorSlug === v.vendor_slug;
                return (
                  <div key={v.vendor_slug} className="glass-panel" style={{ padding: 16, background: 'rgba(126, 143, 129, 0.03)', border: '1px solid rgba(126, 143, 129, 0.3)', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                        <strong style={{ fontSize: 13, color: 'var(--text-main)' }}>{v.vendor_name}</strong>
                        <span className="badge badge-emerald" style={{ fontSize: 10, textTransform: 'uppercase' }}>{v.format}</span>
                      </div>
                      <p style={{ margin: '0 0 12px 0', fontSize: 11, color: 'var(--text-dim)' }}>
                        Config-driven ingestion via saved mapping schema.
                      </p>
                    </div>
                    <label className="btn btn-secondary" style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, padding: '8px 14px', fontSize: 12, borderColor: 'var(--accent-green)', color: 'var(--accent-green)' }}>
                      <Cpu size={14} />
                      <span>{isUploadingThis ? `Parsing ${v.vendor_name}...` : `Upload ${v.vendor_name}`}</span>
                      <input
                        type="file"
                        accept=".xml,.nessus,.csv,.json"
                        onChange={(e) => handleCustomVendorUpload(e, v.vendor_slug, v.vendor_name)}
                        disabled={isUploadingThis}
                        style={{ display: 'none' }}
                      />
                    </label>
                  </div>
                );
              })}

              {/* Option: Onboard New Vendor Button */}
              <div
                onClick={() => setActiveSection('wizard')}
                className="glass-panel"
                style={{
                  padding: 16,
                  border: '1px dashed var(--primary)',
                  background: 'rgba(183, 140, 102, 0.02)',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  cursor: 'pointer',
                  textAlign: 'center',
                  minHeight: 110
                }}
              >
                <Sparkles size={22} color="var(--primary)" style={{ marginBottom: 6 }} />
                <strong style={{ fontSize: 13, color: 'var(--primary)' }}>+ Onboard New Vendor</strong>
                <p style={{ margin: '4px 0 0 0', fontSize: 11, color: 'var(--text-dim)' }}>
                  Upload a sample file and map fields in the wizard.
                </p>
              </div>
            </div>
          </div>

          {/* Active Findings Table */}
          <div className="glass-panel" style={{ padding: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div>
                <h4 style={{ margin: 0, fontSize: 14, color: 'var(--text-main)' }}>Active Vulnerability Findings ({findings.length})</h4>
                <p style={{ margin: '2px 0 0 0', fontSize: 11, color: 'var(--text-dim)' }}>
                  Combined telemetry from real OpenVAS lab scans, live API intel, and event injections.
                </p>
              </div>
              <span className="badge badge-amber">Enriched via FIRST EPSS</span>
            </div>

            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, textAlign: 'left' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-dim)' }}>
                    <th style={{ padding: '8px 12px' }}>Finding ID</th>
                    <th style={{ padding: '8px 12px' }}>Target Asset</th>
                    <th style={{ padding: '8px 12px' }}>CVE Identifier</th>
                    <th style={{ padding: '8px 12px' }}>CVSS v3</th>
                    <th style={{ padding: '8px 12px' }}>EPSS %</th>
                    <th style={{ padding: '8px 12px' }}>CISA KEV</th>
                    <th style={{ padding: '8px 12px' }}>Provenance</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((f, i) => {
                    const intel = cveIntel[f.cve_id] || {};
                    const epssPct = intel.epss ? (intel.epss * 100).toFixed(1) + '%' : 'N/A';
                    return (
                      <tr key={f.id || i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                        <td style={{ padding: '10px 12px', color: 'var(--primary)', fontFamily: 'monospace' }}>{f.id}</td>
                        <td style={{ padding: '10px 12px', fontWeight: 600 }}>{f.asset_id}</td>
                        <td style={{ padding: '10px 12px', color: 'var(--accent-amber)', fontFamily: 'monospace' }}>
                          {f.cve_id ? (
                            f.cve_id
                          ) : f.mitre_techniques && f.mitre_techniques.length > 0 ? (
                            <div>
                              <span style={{ color: 'var(--text-dim)', fontStyle: 'italic', fontSize: 11, display: 'block', marginBottom: 4 }}>No CVE (EDR Detection)</span>
                              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                                {f.mitre_techniques.map(t => (
                                  <span key={t} style={{
                                    fontSize: 10,
                                    padding: '1px 5px',
                                    borderRadius: 3,
                                    background: 'rgba(96, 165, 250, 0.15)',
                                    border: '1px solid rgba(96, 165, 250, 0.3)',
                                    color: '#93c5fd',
                                    fontFamily: 'monospace'
                                  }}>
                                    {t}
                                  </span>
                                ))}
                              </div>
                            </div>
                          ) : (
                            <span style={{ color: 'var(--text-dim)', fontStyle: 'italic', fontSize: 11 }}>No CVE (Plugin Finding)</span>
                          )}
                        </td>
                        <td style={{ padding: '10px 12px' }}>
                          <span style={{
                            padding: '2px 8px', borderRadius: 4,
                            background: f.cvss >= 9 ? 'rgba(201, 114, 114, 0.2)' : 'rgba(209, 184, 121, 0.2)',
                            color: f.cvss >= 9 ? 'var(--accent-red)' : 'var(--accent-amber)',
                            fontWeight: 700
                          }}>
                            {f.cvss} ({f.severity})
                          </span>
                        </td>
                        <td style={{ padding: '10px 12px', color: 'var(--primary)' }}>{epssPct}</td>
                        <td style={{ padding: '10px 12px' }}>
                          {intel.in_kev ? (
                            <span className="badge" style={{ background: 'rgba(201, 114, 114, 0.2)', color: 'var(--accent-red)' }}>YES (KEV)</span>
                          ) : (
                            <span style={{ color: 'var(--text-dim)' }}>No</span>
                          )}
                        </td>
                        <td style={{ padding: '10px 12px', color: 'var(--text-dim)', fontSize: 11 }}>
                          {f.source || 'OpenVAS Scanner'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* SECTION 3: Asset Inventory & Criticality */}
      {activeSection === 'assets' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          {/* Asset Upload Zone */}
          <div className="glass-panel" style={{ padding: 22, border: '2px dashed var(--border-color)', textAlign: 'center' }}>
            <Server size={36} color="var(--accent-green)" style={{ margin: '0 auto 10px auto' }} />
            <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-main)' }}>Ingest Asset Inventory & Business Criticality CSV</h3>
            <p style={{ margin: '6px auto 16px auto', fontSize: 12, color: 'var(--text-dim)', maxWidth: 500 }}>
              Upload your CMDB CSV export with columns: Asset ID, Name, Service, Criticality (1-5), Records, RevenuePerHour.
            </p>

            <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
              <label className="btn btn-secondary" style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8, padding: '10px 20px' }}>
                <FileText size={16} />
                <span>{uploadingAssets ? 'Loading Inventory...' : 'Upload Asset CSV'}</span>
                <input
                  type="file"
                  accept=".csv"
                  onChange={(e) => handleFileUpload(e, 'assets')}
                  disabled={uploadingAssets}
                  style={{ display: 'none' }}
                />
              </label>

              <button
                type="button"
                className="btn btn-primary"
                onClick={() => {
                  setEditingAsset(null);
                  setShowAddAssetModal(true);
                }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  padding: '10px 20px',
                  background: 'linear-gradient(135deg, var(--accent-green) 0%, var(--accent-green) 100%)',
                  color: 'var(--text-main)',
                  boxShadow: '0 0 15px rgba(126, 143, 129, 0.35)',
                  cursor: 'pointer'
                }}
              >
                <PlusCircle size={16} />
                <span>Add Asset Manually</span>
              </button>
            </div>
          </div>

          {/* Active Assets Table */}
          <div className="glass-panel" style={{ padding: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div>
                <h4 style={{ margin: 0, fontSize: 14, color: 'var(--text-main)' }}>Active Network Assets & Financial Parameters ({assets.length})</h4>
                <p style={{ margin: '2px 0 0 0', fontSize: 11, color: 'var(--text-dim)' }}>
                  Underlying nodes used in FAIR loss magnitude sampling and business downtime calculations.
                </p>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                {assets.length > 0 && (
                  <button
                    onClick={handleClearInventory}
                    className="btn btn-secondary"
                    style={{
                      padding: '4px 10px',
                      fontSize: 12,
                      color: 'var(--accent-red)',
                      border: '1px solid rgba(201, 114, 114, 0.35)',
                      background: 'rgba(201, 114, 114, 0.08)',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 6,
                      cursor: 'pointer'
                    }}
                    title="Delete entire asset inventory"
                  >
                    <Trash2 size={13} />
                    <span>Delete Inventory</span>
                  </button>
                )}
                <span className="badge badge-emerald">CMDB Mapped</span>
              </div>
            </div>

            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, textAlign: 'left' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-dim)' }}>
                    <th style={{ padding: '8px 12px' }}>Asset ID</th>
                    <th style={{ padding: '8px 12px' }}>Name / Role</th>
                    <th style={{ padding: '8px 12px' }}>Business Service</th>
                    <th style={{ padding: '8px 12px' }}>Criticality</th>
                    <th style={{ padding: '8px 12px' }}>PII Records</th>
                    <th style={{ padding: '8px 12px' }}>Revenue Exposure / Hr</th>
                    <th style={{ padding: '8px 12px' }}>Internet Facing</th>
                    <th style={{ padding: '8px 12px', textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {assets.length === 0 && (
                    <tr>
                      <td colSpan={8} style={{ padding: '28px 12px', textAlign: 'center', color: 'var(--text-dim)' }}>
                        No network assets in inventory. Ingest an Asset Inventory CSV or click "Add Asset Manually".
                      </td>
                    </tr>
                  )}
                  {assets.map((a) => (
                    <tr key={a.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                      <td style={{ padding: '10px 12px', color: 'var(--primary)', fontFamily: 'monospace' }}>{a.id}</td>
                      <td style={{ padding: '10px 12px', fontWeight: 600 }}>
                        <div>{a.name || a.id}</div>
                        {!a.has_business_context && !a.business_service_id && (
                          <div style={{ marginTop: 3 }}>
                            <span className="badge badge-amber" style={{ fontSize: 9, padding: '1px 6px' }}>
                              No business context defined for this asset
                            </span>
                          </div>
                        )}
                      </td>
                      <td style={{ padding: '10px 12px' }}>
                        {a.business_service_id ? (
                          <span style={{ color: 'var(--text-muted)' }}>{a.business_service_id}</span>
                        ) : (
                          <span style={{ color: 'var(--text-dim)', fontStyle: 'italic', fontSize: 11 }}>Unassigned</span>
                        )}
                      </td>
                      <td style={{ padding: '10px 12px' }}>
                        {a.criticality_1_5 != null ? (
                          <span style={{
                            padding: '2px 8px', borderRadius: 4,
                            background: a.criticality_1_5 >= 4 ? 'rgba(201, 114, 114, 0.2)' : 'rgba(126, 143, 129, 0.2)',
                            color: a.criticality_1_5 >= 4 ? 'var(--accent-red)' : 'var(--accent-green)',
                            fontWeight: 700
                          }}>
                            Level {a.criticality_1_5} / 5
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-dim)', fontStyle: 'italic', fontSize: 11 }}>Unassigned</span>
                        )}
                      </td>
                      <td style={{ padding: '10px 12px' }}>
                        {a.records_count != null ? a.records_count.toLocaleString() : <span style={{ color: 'var(--text-dim)' }}>—</span>}
                      </td>
                      <td style={{ padding: '10px 12px', color: 'var(--accent-green)', fontWeight: 600 }}>
                        {a.revenue_per_hour != null ? formatINR(a.revenue_per_hour) : <span style={{ color: 'var(--text-dim)' }}>—</span>}
                      </td>
                      <td style={{ padding: '10px 12px' }}>
                        {a.internet_facing === true ? (
                          <span className="badge" style={{ background: 'rgba(201, 114, 114, 0.2)', color: 'var(--accent-red)' }}>Public</span>
                        ) : a.internet_facing === false ? (
                          <span className="badge" style={{ background: 'rgba(126, 143, 129, 0.2)', color: 'var(--accent-green)' }}>Internal</span>
                        ) : (
                          <span style={{ color: 'var(--text-dim)', fontStyle: 'italic', fontSize: 11 }}>Unknown</span>
                        )}
                      </td>
                      <td style={{ padding: '10px 12px', textAlign: 'right', whiteSpace: 'nowrap' }}>
                        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, justifyContent: 'flex-end' }}>
                          <button
                            onClick={() => {
                              setEditingAsset(a);
                              setShowAddAssetModal(true);
                            }}
                            className="btn btn-secondary"
                            style={{
                              padding: '4px 8px',
                              fontSize: 11,
                              color: 'var(--accent-amber)',
                              border: '1px solid rgba(224, 169, 109, 0.35)',
                              background: 'rgba(224, 169, 109, 0.08)',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: 4,
                              cursor: 'pointer'
                            }}
                            title={`Edit asset ${a.id}`}
                          >
                            <Pencil size={12} />
                            <span>Edit</span>
                          </button>
                          <button
                            onClick={() => handleDeleteAsset(a.id, a.name)}
                            className="btn btn-secondary"
                            style={{
                              padding: '4px 8px',
                              fontSize: 11,
                              color: 'var(--accent-red)',
                              border: '1px solid rgba(201, 114, 114, 0.25)',
                              background: 'rgba(201, 114, 114, 0.06)',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: 4,
                              cursor: 'pointer'
                            }}
                            title={`Delete asset ${a.id}`}
                          >
                            <Trash2 size={12} />
                            <span>Delete</span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* SECTION 5: Unsupervised ML IsolationForest Telemetry Anomalies */}
      {activeSection === 'anomalies' && (
        <div className="glass-panel" style={{ padding: 22 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 14, marginBottom: 20 }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                <Cpu size={20} color="var(--accent-amber)" />
                <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-main)' }}>
                  Unsupervised Telemetry Anomaly Detection (IsolationForest)
                </h3>
                {anomalyData?.is_demo && (
                  <span
                    className="badge"
                    style={{
                      fontSize: 10,
                      fontWeight: 700,
                      background: 'rgba(245, 158, 11, 0.18)',
                      color: 'var(--accent-amber)',
                      border: '1px solid rgba(245, 158, 11, 0.4)',
                      padding: '2px 8px',
                      letterSpacing: '0.04em'
                    }}
                  >
                    DEMO DATA — not from live ingestion
                  </span>
                )}
                {anomalyData?.source && (
                  <span
                    className={`badge ${anomalyData.source === 'Wazuh Live API' ? 'badge-real' : anomalyData.source === 'Wazuh Telemetry Mock' ? 'badge-simulated' : ''}`}
                    style={{
                      fontSize: 10,
                      background: anomalyData.source === 'Wazuh Live API' ? undefined : 'rgba(255, 255, 255, 0.05)',
                      border: '1px solid var(--border-color)',
                      color: anomalyData.source === 'Wazuh Live API' ? 'var(--accent-green)' : 'var(--text-dim)',
                      padding: '2px 8px'
                    }}
                  >
                    Source: {anomalyData.source}
                  </span>
                )}
              </div>
              <p style={{ margin: '4px 0 0 0', fontSize: 12, color: 'var(--text-dim)', maxWidth: 700 }}>
                Scikit-learn IsolationForest trained over per-agent SIEM telemetry features: <strong>Event Volume</strong>, <strong>Auth Failure Rate</strong>, and <strong>Alert Severity Mix</strong>.
                Signals emerging threats before signatures or CVEs exist.
              </p>
              <div style={{ marginTop: 8 }}>
                <span className="badge badge-amber" style={{ fontSize: 11 }}>
                  unsupervised anomaly (IsolationForest), not a confirmed incident
                </span>
                <span className="badge" style={{ marginLeft: 8, background: 'rgba(255,255,255,0.04)', color: 'var(--text-dim)', fontSize: 11 }}>
                  Signal Layer Only · Decoupled from Deterministic FAIR Loss Core
                </span>
              </div>
            </div>

            <div style={{ display: 'flex', gap: 10 }}>
              <button
                className="btn btn-outline"
                onClick={fetchAnomalies}
                disabled={anomalyLoading}
                style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6 }}
              >
                <RefreshCw size={13} className={anomalyLoading ? 'spin' : ''} />
                Refresh
              </button>
              <button
                className="btn btn-primary"
                onClick={handleInjectAnomaly}
                disabled={injectingAnomaly}
                style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6, background: 'var(--accent-amber)', color: '#000' }}
              >
                <AlertTriangle size={13} />
                {injectingAnomaly ? 'Injecting Spike...' : 'Simulate Telemetry Spike (Demo)'}
              </button>
            </div>
          </div>

          {/* Cold Start State */}
          {anomalyData?.is_insufficient ? (
            <div className="glass-panel" style={{ padding: 24, textAlign: 'center', background: 'rgba(255,255,255,0.02)', border: '1px dashed var(--border-color)' }}>
              <Activity size={36} color="var(--text-dim)" style={{ marginBottom: 10 }} />
              <h4 style={{ margin: 0, fontSize: 15, color: 'var(--text-main)' }}>
                {anomalyData?.message?.startsWith('Building baseline:') ? anomalyData.message : 'insufficient baseline data'}
              </h4>
              <p style={{ margin: '8px auto', fontSize: 12, color: 'var(--text-muted)', maxWidth: 500 }}>
                Currently {anomalyData.history_windows_count || anomalyData.total_windows || 0} observation windows recorded (minimum {anomalyData.min_required_windows || anomalyData.required_windows || 5} required).
                CRISP refuses to fabricate synthetic curves or guess anomaly scores during cold-start.
              </p>
              <button
                className="btn btn-primary"
                onClick={handleInjectAnomaly}
                disabled={injectingAnomaly}
                style={{ marginTop: 12, fontSize: 12, background: 'var(--accent-amber)', color: '#000' }}
              >
                Inject Synthetic Telemetry Spike to Trigger Scoring
              </button>
            </div>
          ) : (
            <div>
              {/* Telemetry Windows Overview */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12, marginBottom: 20 }}>
                <div className="glass-panel" style={{ padding: 14, background: 'rgba(255,255,255,0.02)' }}>
                  <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>Baseline Observation Windows</div>
                  <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-main)', marginTop: 4 }}>
                    {anomalyData?.history_windows_count || 0}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--accent-green)' }}>Rolling Telemetry Baseline</div>
                </div>

                <div className="glass-panel" style={{ padding: 14, background: 'rgba(255,255,255,0.02)' }}>
                  <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>Flagged Outlier Windows</div>
                  <div style={{ fontSize: 22, fontWeight: 700, color: (anomalyData?.anomalies_detected || 0) > 0 ? 'var(--accent-red)' : 'var(--accent-green)', marginTop: 4 }}>
                    {anomalyData?.anomalies_detected || 0}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Contamination parameter: 10%</div>
                </div>

                <div className="glass-panel" style={{ padding: 14, background: 'rgba(255,255,255,0.02)' }}>
                  <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>Model Architecture</div>
                  <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-main)', marginTop: 6 }}>
                    Scikit-Learn IsolationForest
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--accent-purple)' }}>3D Feature Space (Volume, Auth, Severity)</div>
                </div>
              </div>

              {/* Agents Telemetry Windows Table */}
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, textAlign: 'left' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-dim)' }}>
                      <th style={{ padding: '8px 12px' }}>Agent Name & ID</th>
                      <th style={{ padding: '8px 12px' }}>Classification</th>
                      <th style={{ padding: '8px 12px' }}>Anomaly Score</th>
                      <th style={{ padding: '8px 12px' }}>Event Vol</th>
                      <th style={{ padding: '8px 12px' }}>Auth Failure Rate</th>
                      <th style={{ padding: '8px 12px' }}>High Severity Alerts</th>
                      <th style={{ padding: '8px 12px' }}>Window Timestamp</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(anomalyData?.results || []).map((item, idx) => (
                      <tr key={idx} style={{
                        borderBottom: '1px solid rgba(255,255,255,0.03)',
                        background: item.is_anomaly ? 'rgba(201, 114, 114, 0.08)' : 'transparent'
                      }}>
                        <td style={{ padding: '10px 12px' }}>
                          <strong style={{ color: 'var(--text-main)' }}>{item.agent_name || item.agent_id}</strong>
                          <div className="mono" style={{ fontSize: 10, color: 'var(--text-dim)' }}>ID: {item.agent_id}</div>
                        </td>
                        <td style={{ padding: '10px 12px' }}>
                          {item.is_anomaly ? (
                            <span className="badge badge-critical" style={{ fontSize: 10 }}>
                              EMERGING THREAT (ANOMALY)
                            </span>
                          ) : (
                            <span className="badge badge-emerald" style={{ fontSize: 10 }}>
                              NORMAL BASELINE
                            </span>
                          )}
                        </td>
                        <td style={{ padding: '10px 12px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <strong className="mono" style={{
                              color: item.is_anomaly ? 'var(--accent-red)' : 'var(--text-main)',
                              fontSize: 13
                            }}>
                              {(item.anomaly_score * 100).toFixed(0)}%
                            </strong>
                            <div style={{
                              width: 60, height: 6, background: 'rgba(255,255,255,0.1)', borderRadius: 3, overflow: 'hidden'
                            }}>
                              <div style={{
                                width: `${Math.min(100, Math.max(0, item.anomaly_score * 100))}%`,
                                height: '100%',
                                background: item.is_anomaly ? 'var(--accent-red)' : 'var(--accent-green)'
                              }} />
                            </div>
                          </div>
                          <div style={{ fontSize: 9, color: 'var(--text-dim)', marginTop: 2 }}>
                            decision: {item.raw_decision_score?.toFixed(3)}
                          </div>
                        </td>
                        <td style={{ padding: '10px 12px', fontFamily: 'monospace' }}>
                          {item.features?.event_volume != null ? item.features.event_volume.toLocaleString() : '—'}
                        </td>
                        <td style={{ padding: '10px 12px', fontFamily: 'monospace', color: item.features?.auth_failure_rate > 0.2 ? 'var(--accent-amber)' : 'inherit' }}>
                          {item.features?.auth_failure_rate != null ? `${(item.features.auth_failure_rate * 100).toFixed(1)}%` : '—'}
                          <span style={{ fontSize: 10, color: 'var(--text-dim)', marginLeft: 4 }}>
                            ({item.features?.auth_failures || 0} fails)
                          </span>
                        </td>
                        <td style={{ padding: '10px 12px', fontFamily: 'monospace', color: item.features?.alert_severity_mix > 0.2 ? 'var(--accent-red)' : 'inherit' }}>
                          {item.features?.alert_severity_mix != null ? `${(item.features.alert_severity_mix * 100).toFixed(1)}%` : '—'}
                          <span style={{ fontSize: 10, color: 'var(--text-dim)', marginLeft: 4 }}>
                            ({item.features?.high_severity_alerts || 0} high)
                          </span>
                        </td>
                        <td style={{ padding: '10px 12px', color: 'var(--text-dim)', fontSize: 11 }}>
                          {item.window_timestamp ? new Date(item.window_timestamp).toLocaleTimeString() : 'Recent'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* SECTION 4: Vendor Onboarding Wizard */}
      {activeSection === 'wizard' && (
        <VendorWizard
          onVendorSaved={(newVendor) => {
            fetchVendors();
            fetchSnapshot();
            if (onDataUpdated) onDataUpdated();
            setActiveSection('scans');
          }}
          onCancel={() => setActiveSection('scans')}
        />
      )}

      {/* Manual Asset Creation / Edit Modal */}
      <AddAssetForm
        isOpen={showAddAssetModal}
        onClose={() => {
          setShowAddAssetModal(false);
          setEditingAsset(null);
        }}
        existingServices={snapshot?.services || []}
        onAssetAdded={handleAssetAdded}
        assetToEdit={editingAsset}
        onAssetUpdated={handleAssetUpdated}
      />
    </div>
  );
}
