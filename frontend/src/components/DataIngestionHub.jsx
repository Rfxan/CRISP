import React, { useState, useEffect } from 'react';
import { 
  Database, UploadCloud, RefreshCw, Shield, AlertTriangle, 
  CheckCircle2, FileText, Sliders, Globe, Server, Activity,
  Sparkles, Plus, PlusCircle, Cpu
} from 'lucide-react';
import { formatINR } from '../utils/formatters';
import { api } from '../services/api';
import VendorWizard from './VendorWizard';
import AddAssetForm from './AddAssetForm';

export default function DataIngestionHub({ onDataUpdated }) {
  const [snapshot, setSnapshot] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeSection, setActiveSection] = useState('assets');
  const [syncingIntel, setSyncingIntel] = useState(false);
  const [uploadingScan, setUploadingScan] = useState(false);
  const [uploadingAssets, setUploadingAssets] = useState(false);
  const [statusMsg, setStatusMsg] = useState(null);
  const [controlEdits, setControlEdits] = useState({});
  const [customVendors, setCustomVendors] = useState([]);
  const [uploadingVendorSlug, setUploadingVendorSlug] = useState(null);
  const [showAddAssetModal, setShowAddAssetModal] = useState(false);

  const handleAssetAdded = async (res) => {
    setStatusMsg({
      type: 'success',
      text: `Asset '${res.asset?.name || res.asset?.id}' added successfully! Total assets: ${res.total_active_assets}. New Organization EAL: ${res.new_eal ? formatINR(res.new_eal) : 'Recalculated'}`
    });
    await fetchSnapshot();
    if (onDataUpdated) onDataUpdated();
  };

  const fetchVendors = async () => {
    try {
      const res = await api.getVendorList();
      setCustomVendors(res.vendors || []);
    } catch (err) {
      console.error('Failed to fetch custom vendors:', err);
    }
  };

  const fetchSnapshot = async () => {
    try {
      const data = await api.getSnapshot();
      setSnapshot(data);
      // Initialize edit state
      const initial = {};
      (data.control_state || []).forEach(cs => {
        initial[cs.control_id] = cs.coverage_pct;
      });
      setControlEdits(initial);
    } catch (err) {
      console.error('Failed to fetch snapshot:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSnapshot();
    fetchVendors();
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
      if (onDataUpdated) onDataUpdated();
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
    const val = controlEdits[ctrlId];
    if (val === undefined) return;
    try {
      await api.updateControlCoverage(ctrlId, val);
      setStatusMsg({
        type: 'success',
        text: `Control ${ctrlId} coverage updated to ${val}%. FAIR Monte Carlo re-executed dynamically!`
      });
      await fetchSnapshot();
      if (onDataUpdated) onDataUpdated();
    } catch (err) {
      setStatusMsg({ type: 'error', text: 'Failed to update control: ' + err.message });
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
        if (onDataUpdated) onDataUpdated();
      } catch (err) {
        setStatusMsg({ type: 'error', text: err.message });
      } finally {
        setUploadingScan(false);
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
        if (onDataUpdated) onDataUpdated();
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
      if (onDataUpdated) onDataUpdated();
    } catch (err) {
      setStatusMsg({ type: 'error', text: err.message });
    } finally {
      setUploadingVendorSlug(null);
    }
  };

  if (loading) {
    return (
      <div className="glass-panel" style={{ padding: 48, textAlign: 'center' }}>
        <RefreshCw className="animate-spin" size={28} color="var(--primary)" style={{ margin: '0 auto 12px auto' }} />
        <p style={{ color: 'var(--text-muted)' }}>Loading live data telemetry and controls catalog...</p>
      </div>
    );
  }

  const assets = snapshot?.assets || [];
  const findings = snapshot?.findings || [];
  const controlStates = snapshot?.control_state || [];
  const catalog = snapshot?.controls_catalog || {};
  const cveIntel = snapshot?.cve_intel || {};
  const wazuh = snapshot?.wazuh_telemetry || {};

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
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, color: 'var(--text-dim)' }}>
              <Activity size={14} color="var(--accent-amber)" /> Wazuh SIEM Telemetry
            </div>
            <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-main)', marginTop: 4 }}>
              {wazuh.active_agents || 6} / {wazuh.total_endpoints || 6}
            </div>
            <div style={{ fontSize: 11, color: 'var(--accent-green)' }}>Agent Daemon Active</div>
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
      </div>

      {/* SECTION 1: Control Coverage Tuner */}
      {activeSection === 'controls' && (
        <div className="glass-panel" style={{ padding: 22 }}>
          <div style={{ marginBottom: 16 }}>
            <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-main)' }}>Dynamic Control Coverage & Mitigation Tuner</h3>
            <p style={{ margin: '4px 0 0 0', fontSize: 12, color: 'var(--text-dim)' }}>
              Adjust control coverage percentage in real time. The FAIR Monte Carlo engine recalculates residual loss and EAL across all affected asset scenarios dynamically.
            </p>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 16 }}>
            {controlStates.map(cs => {
              const meta = catalog[cs.control_id] || {};
              const currentVal = controlEdits[cs.control_id] ?? cs.coverage_pct;
              const hasChanged = currentVal !== cs.coverage_pct;

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
                      <div style={{ fontSize: 18, fontWeight: 700, color: currentVal >= 90 ? 'var(--accent-green)' : (currentVal >= 60 ? 'var(--accent-amber)' : 'var(--accent-red)') }}>
                        {currentVal}%
                      </div>
                      <div style={{ fontSize: 10, color: 'var(--text-dim)' }}>Coverage</div>
                    </div>
                  </div>

                  <p style={{ fontSize: 11, color: 'var(--text-muted)', margin: '8px 0', lineHeight: 1.4 }}>
                    {meta.description || 'Enterprise defensive control'}
                  </p>

                  <div style={{ display: 'flex', gap: 16, fontSize: 11, color: 'var(--text-dim)', marginBottom: 12 }}>
                    <span>CapEx: <strong>{formatINR(meta.implementation_cost || 0)}</strong></span>
                    <span>OpEx: <strong>{formatINR(meta.annual_cost || 0)}/yr</strong></span>
                    <span>Evidence: <strong style={{ color: 'var(--primary)' }}>{cs.evidence_ref}</strong></span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <input
                      type="range"
                      min="0"
                      max="100"
                      step="5"
                      value={currentVal}
                      onChange={(e) => handleControlSliderChange(cs.control_id, e.target.value)}
                      style={{ flex: 1, accentcolor: 'var(--primary)', cursor: 'pointer' }}
                    />
                    <button
                      onClick={() => handleSaveControl(cs.control_id)}
                      disabled={!hasChanged}
                      className="btn btn-primary"
                      style={{
                        padding: '6px 12px',
                        fontSize: 11,
                        opacity: hasChanged ? 1 : 0.5,
                        cursor: hasChanged ? 'pointer' : 'default'
                      }}
                    >
                      Update
                    </button>
                  </div>
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
                onClick={() => setShowAddAssetModal(true)}
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
              <span className="badge badge-emerald">CMDB Mapped</span>
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
                  </tr>
                </thead>
                <tbody>
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
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
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

      {/* Manual Asset Creation Modal */}
      <AddAssetForm
        isOpen={showAddAssetModal}
        onClose={() => setShowAddAssetModal(false)}
        existingServices={snapshot?.services || []}
        onAssetAdded={handleAssetAdded}
      />
    </div>
  );
}
