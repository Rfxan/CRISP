import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { 
  Radio, ShieldCheck, Key, RefreshCw, CheckCircle2, 
  AlertCircle, XCircle, Lock, Eye, EyeOff, Save, Trash2, 
  ArrowRight, ShieldAlert, Cpu, Check
} from 'lucide-react';

export default function ConnectionsSettings({ onConnectionChanged }) {
  const [connections, setConnections] = useState({
    siem: { connected: false, base_url: '', username: '', last_tested: null, last_test_result: null, last_test_detail: 'Not configured' },
    iam: { connected: false, base_url: '', username: '', last_tested: null, last_test_result: null, last_test_detail: 'Not configured' }
  });
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Form states
  const [forms, setForms] = useState({
    siem: { base_url: '', username: '', password: '', showPassword: false, editing: false },
    iam: { base_url: '', username: '', password: '', showPassword: false, editing: false }
  });

  // Test states
  const [testing, setTesting] = useState({ siem: false, iam: false });
  const [testResults, setTestResults] = useState({ siem: null, iam: null });
  const [saving, setSaving] = useState({ siem: false, iam: false });
  const [statusMessage, setStatusMessage] = useState(null);

  const fetchConnections = async () => {
    try {
      const data = await api.getConnections();
      setConnections(data);

      // Pre-fill form base_url and username from saved connections if not currently typing
      setForms(prev => ({
        siem: {
          ...prev.siem,
          base_url: prev.siem.editing ? prev.siem.base_url : (data.siem?.base_url || ''),
          username: prev.siem.editing ? prev.siem.username : (data.siem?.username || '')
        },
        iam: {
          ...prev.iam,
          base_url: prev.iam.editing ? prev.iam.base_url : (data.iam?.base_url || ''),
          username: prev.iam.editing ? prev.iam.username : (data.iam?.username || '')
        }
      }));
    } catch (err) {
      console.error('Failed to load connections:', err);
      setStatusMessage({ type: 'error', text: 'Failed to retrieve connection statuses from CRISP backend.' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchConnections();
  }, []);

  const handleRefresh = async () => {
    setRefreshing(true);
    setStatusMessage(null);
    try {
      const data = await api.refreshConnections();
      setConnections(data.connections);
      const entries = Object.entries(data.results);
      const failed = entries.filter(([, result]) => !result.success);
      setStatusMessage({
        type: failed.length ? 'error' : 'success',
        text: !entries.length ? 'No connections configured yet.' : failed.length
          ? failed.map(([category, result]) => `${category.toUpperCase()}: ${result.detail}`).join(' • ')
          : 'Live connection checks and telemetry refresh completed.'
      });
      if (onConnectionChanged) onConnectionChanged();
    } catch (err) {
      setStatusMessage({ type: 'error', text: err.message });
    } finally {
      setRefreshing(false);
    }
  };

  const handleInputChange = (category, field, value) => {
    setForms(prev => ({
      ...prev,
      [category]: {
        ...prev[category],
        [field]: value
      }
    }));
    // Clear previous inline test result on edit
    setTestResults(prev => ({ ...prev, [category]: null }));
  };

  const togglePasswordVisibility = (category) => {
    setForms(prev => ({
      ...prev,
      [category]: {
        ...prev[category],
        showPassword: !prev[category].showPassword
      }
    }));
  };

  const startEditing = (category) => {
    const conn = connections[category] || {};
    setForms(prev => ({
      ...prev,
      [category]: {
        ...prev[category],
        base_url: conn.base_url || (category === 'siem' ? 'https://localhost:55000' : 'http://localhost:8080'),
        username: conn.username || (category === 'siem' ? 'wazuh-wui' : 'admin'),
        password: '',
        editing: true
      }
    }));
    setTestResults(prev => ({ ...prev, [category]: null }));
  };

  const cancelEditing = (category) => {
    setForms(prev => ({
      ...prev,
      [category]: {
        ...prev[category],
        editing: false,
        password: ''
      }
    }));
    setTestResults(prev => ({ ...prev, [category]: null }));
  };

  const handleTest = async (category) => {
    const f = forms[category];
    if (!f.base_url) {
      setTestResults(prev => ({
        ...prev,
        [category]: { success: false, detail: 'Please enter a Base URL before testing.' }
      }));
      return;
    }

    setTesting(prev => ({ ...prev, [category]: true }));
    setTestResults(prev => ({ ...prev, [category]: null }));

    try {
      const res = await api.testConnection(category, {
        base_url: f.base_url,
        username: f.username,
        password: f.password
      });
      setTestResults(prev => ({ ...prev, [category]: res }));
    } catch (err) {
      setTestResults(prev => ({
        ...prev,
        [category]: {
          success: false,
          detail: err.message || 'Connection test failed with an unknown error'
        }
      }));
    } finally {
      setTesting(prev => ({ ...prev, [category]: false }));
    }
  };

  const handleSave = async (category) => {
    const f = forms[category];
    if (!f.base_url) return;

    setSaving(prev => ({ ...prev, [category]: true }));
    setStatusMessage(null);

    try {
      const res = await api.saveConnection(category, {
        base_url: f.base_url,
        username: f.username,
        password: f.password
      });

      setStatusMessage({
        type: 'success',
        text: `Saved ${category.toUpperCase()} connection. Use Refresh Status to check it now; scheduled updates require the synchronization worker.`
      });

      setForms(prev => ({
        ...prev,
        [category]: {
          ...prev[category],
          editing: false,
          password: ''
        }
      }));

      await fetchConnections();
      if (onConnectionChanged) onConnectionChanged();
    } catch (err) {
      setStatusMessage({
        type: 'error',
        text: `Failed to save connection: ${err.message}`
      });
    } finally {
      setSaving(prev => ({ ...prev, [category]: false }));
      setTimeout(() => setStatusMessage(null), 7000);
    }
  };

  const handleRemove = async (category) => {
    if (!window.confirm(`Are you sure you want to disconnect ${category.toUpperCase()}? Automated telemetry sync will stop.`)) {
      return;
    }

    try {
      await api.removeConnection(category);
      setStatusMessage({
        type: 'info',
        text: `Disconnected ${category.toUpperCase()} connection.`
      });
      await fetchConnections();
      if (onConnectionChanged) onConnectionChanged();
    } catch (err) {
      setStatusMessage({
        type: 'error',
        text: `Failed to remove connection: ${err.message}`
      });
    }
  };

  const formatTimeAgo = (isoString) => {
    if (!isoString) return 'never';
    const diffMs = Date.now() - new Date(isoString).getTime();
    const sec = Math.floor(diffMs / 1000);
    if (sec < 60) return `${sec}s ago`;
    const min = Math.floor(sec / 60);
    if (min < 60) return `${min}m ago`;
    const hrs = Math.floor(min / 60);
    return `${hrs}h ago`;
  };

  const renderCard = (category, title, subtitle, icon) => {
    const conn = connections[category] || {};
    const form = forms[category];
    const testResult = testResults[category];
    const isTesting = testing[category];
    const isSaving = saving[category];

    // Status derivation
    let statusBadge = null;
    const lastCheck = Date.parse(conn.last_tested);
    const stale = !Number.isFinite(lastCheck) || Date.now() - lastCheck > 120000;
    if (conn.connected && stale) {
      statusBadge = <span className="badge badge-simulated"><AlertCircle size={14} /> Status stale · checked {formatTimeAgo(conn.last_tested)}</span>;
    } else if (conn.connected) {
      statusBadge = (
        <span style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 6,
          padding: '4px 12px',
          borderRadius: 20,
          fontSize: 12,
          fontWeight: 600,
          background: 'rgba(126, 143, 129, 0.15)',
          color: 'var(--accent-green)',
          border: '1px solid rgba(126, 143, 129, 0.4)'
        }}>
          <CheckCircle2 size={14} /> Connected (checked {formatTimeAgo(conn.last_tested)})
        </span>
      );
    } else if (conn.last_test_result === 'FAILED') {
      statusBadge = (
        <span style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 6,
          padding: '4px 12px',
          borderRadius: 20,
          fontSize: 12,
          fontWeight: 600,
          background: 'rgba(201, 114, 114, 0.15)',
          color: 'var(--accent-red)',
          border: '1px solid rgba(201, 114, 114, 0.4)'
        }} title={conn.last_test_detail || 'Connection failed'}>
          <XCircle size={14} /> Connection Failed ❌
        </span>
      );
    } else {
      statusBadge = (
        <span style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 6,
          padding: '4px 12px',
          borderRadius: 20,
          fontSize: 12,
          fontWeight: 600,
          background: 'rgba(148, 163, 184, 0.12)',
          color: 'var(--text-dim)',
          border: '1px solid rgba(148, 163, 184, 0.2)'
        }}>
          <Radio size={14} /> Not Connected
        </span>
      );
    }

    return (
      <div className="glass-panel" style={{
        padding: 24,
        borderRadius: 14,
        background: 'var(--bg-card)',
        border: conn.connected ? '1px solid var(--primary)' : '1px solid var(--border-color)',
        display: 'flex',
        flexDirection: 'column',
        gap: 20,
        boxShadow: conn.connected ? '0 8px 32px rgba(183, 140, 102, 0.05)' : 'none'
      }}>
        {/* Card Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{
              width: 44,
              height: 44,
              borderRadius: 10,
              background: 'linear-gradient(135deg, rgba(183, 140, 102, 0.15) 0%, rgba(79, 70, 229, 0.15) 100%)',
              border: '1px solid rgba(183, 140, 102, 0.25)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--primary)'
            }}>
              {icon}
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: 18, color: 'var(--text-main)', fontWeight: 600 }}>{title}</h3>
              <p style={{ margin: '2px 0 0 0', fontSize: 13, color: 'var(--text-dim)' }}>{subtitle}</p>
            </div>
          </div>
          <div>
            {statusBadge}
          </div>
        </div>

        {/* Current Connection Info (when not editing) */}
        {!form.editing ? (
          <div style={{
            background: 'var(--bg-main)',
            borderRadius: 10,
            padding: '16px 18px',
            border: '1px solid var(--border-color)',
            display: 'flex',
            flexDirection: 'column',
            gap: 10
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13 }}>
              <span style={{ color: 'var(--text-dim)' }}>Server Endpoint:</span>
              <span style={{ color: 'var(--text-main)', fontFamily: 'monospace' }}>
                {conn.base_url || '—'}
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13 }}>
              <span style={{ color: 'var(--text-dim)' }}>API Username:</span>
              <span style={{ color: 'var(--text-main)', fontFamily: 'monospace' }}>
                {conn.username || '—'}
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13 }}>
              <span style={{ color: 'var(--text-dim)' }}>Credential Storage:</span>
              <span style={{ color: 'var(--accent-green)', display: 'flex', alignItems: 'center', gap: 4, fontSize: 12 }}>
                <Lock size={12} /> Fernet AES Encrypted
              </span>
            </div>
            {conn.last_test_detail && (
              <div style={{
                marginTop: 4,
                padding: '8px 12px',
                borderRadius: 6,
                fontSize: 12,
                background: conn.connected ? 'rgba(126, 143, 129, 0.08)' : 'rgba(201, 114, 114, 0.08)',
                color: conn.connected ? 'var(--accent-green)' : '#f87171',
                border: `1px solid ${conn.connected ? 'rgba(126, 143, 129, 0.2)' : 'rgba(201, 114, 114, 0.2)'}`
              }}>
                <strong>Last Result:</strong> {conn.last_test_detail}
              </div>
            )}

            <div style={{ display: 'flex', gap: 10, marginTop: 10 }}>
              <button
                className="btn btn-primary"
                onClick={() => startEditing(category)}
                style={{ padding: '8px 16px', fontSize: 13 }}
              >
                {conn.base_url ? 'Edit Connection' : 'Configure Connection'}
              </button>
              {conn.base_url && (
                <button
                  className="btn btn-outline"
                  onClick={() => handleRemove(category)}
                  style={{
                    padding: '8px 14px',
                    fontSize: 13,
                    color: 'var(--accent-red)',
                    border: '1px solid rgba(201, 114, 114, 0.3)',
                    background: 'rgba(201, 114, 114, 0.08)'
                  }}
                  title="Remove saved credentials"
                >
                  <Trash2 size={14} style={{ marginRight: 6 }} /> Disconnect
                </button>
              )}
            </div>
          </div>
        ) : (
          /* Edit Form */
          <div style={{
            background: 'var(--bg-main)',
            borderRadius: 10,
            padding: 20,
            border: '1px solid var(--primary)',
            display: 'flex',
            flexDirection: 'column',
            gap: 16
          }}>
            <div>
              <label style={{ display: 'block', fontSize: 12, color: 'var(--text-dim)', marginBottom: 6 }}>
                Base URL (REST API Host)
              </label>
              <input
                type="text"
                style={{ width: '100%', fontFamily: 'monospace', fontSize: 13, padding: '8px 12px', border: '1px solid var(--border-color)', borderRadius: 8, background: 'var(--bg-card)' }}
                placeholder={category === 'siem' ? 'https://192.168.1.100:55000' : 'http://localhost:8080'}
                value={form.base_url}
                onChange={(e) => handleInputChange(category, 'base_url', e.target.value)}
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
              <div>
                <label style={{ display: 'block', fontSize: 12, color: 'var(--text-dim)', marginBottom: 6 }}>
                  API Username / Client ID
                </label>
                <input
                  type="text"
                  style={{ width: '100%', fontSize: 13, padding: '8px 12px', border: '1px solid var(--border-color)', borderRadius: 8, background: 'var(--bg-card)' }}
                  placeholder={category === 'siem' ? 'wazuh-wui' : 'admin'}
                  value={form.username}
                  onChange={(e) => handleInputChange(category, 'username', e.target.value)}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: 12, color: 'var(--text-dim)', marginBottom: 6 }}>
                  Password / Bearer Token
                </label>
                <div style={{ position: 'relative' }}>
                  <input
                    type={form.showPassword ? 'text' : 'password'}
                    style={{ width: '100%', paddingRight: 36, fontSize: 13, padding: '8px 12px', border: '1px solid var(--border-color)', borderRadius: 8, background: 'var(--bg-card)' }}
                    placeholder={conn.base_url ? '•••••••• (unchanged)' : 'Enter password'}
                    value={form.password}
                    onChange={(e) => handleInputChange(category, 'password', e.target.value)}
                  />
                  <button
                    type="button"
                    onClick={() => togglePasswordVisibility(category)}
                    style={{
                      position: 'absolute',
                      right: 8,
                      top: '50%',
                      transform: 'translateY(-50%)',
                      background: 'none',
                      border: 'none',
                      color: 'var(--text-dim)',
                      cursor: 'pointer',
                      padding: 4
                    }}
                  >
                    {form.showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>
            </div>

            {/* Inline Test Result Message */}
            {testResult && (
              <div style={{
                padding: '12px 14px',
                borderRadius: 8,
                fontSize: 13,
                display: 'flex',
                alignItems: 'flex-start',
                gap: 10,
                background: testResult.success ? 'rgba(126, 143, 129, 0.1)' : 'rgba(201, 114, 114, 0.1)',
                border: `1px solid ${testResult.success ? 'rgba(126, 143, 129, 0.3)' : 'rgba(201, 114, 114, 0.3)'}`,
                color: testResult.success ? 'var(--accent-green)' : '#f87171'
              }}>
                {testResult.success ? (
                  <CheckCircle2 size={18} style={{ flexShrink: 0, marginTop: 1 }} />
                ) : (
                  <AlertCircle size={18} style={{ flexShrink: 0, marginTop: 1 }} />
                )}
                <div>
                  <strong>{testResult.success ? 'Connection Test Succeeded:' : 'Connection Test Failed:'}</strong>
                  <div style={{ marginTop: 2, fontSize: 12, opacity: 0.9 }}>{testResult.detail}</div>
                </div>
              </div>
            )}

            {/* Action Buttons */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: 4 }}>
              <div style={{ display: 'flex', gap: 10 }}>
                {/* Test Connection Button */}
                <button
                  type="button"
                  className="btn btn-outline"
                  onClick={() => handleTest(category)}
                  disabled={isTesting || !form.base_url}
                  style={{
                    padding: '8px 16px',
                    fontSize: 13,
                    color: 'var(--primary)',
                    border: '1px solid rgba(183, 140, 102, 0.35)',
                    background: 'rgba(183, 140, 102, 0.08)'
                  }}
                >
                  {isTesting ? (
                    <>
                      <RefreshCw size={14} className="spin" style={{ marginRight: 6 }} /> Testing live endpoint...
                    </>
                  ) : (
                    <>
                      <Radio size={14} style={{ marginRight: 6 }} /> Test Connection
                    </>
                  )}
                </button>

                {/* Save & Connect Button */}
                {/* Explicit Behavior: Enabled after successful test; or allows saving with warning if unverified */}
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => handleSave(category)}
                  disabled={isSaving || !form.base_url}
                  style={{
                    padding: '8px 18px',
                    fontSize: 13,
                    background: testResult?.success 
                      ? 'linear-gradient(135deg, var(--accent-green) 0%, var(--accent-green) 100%)' 
                      : (testResult && !testResult.success 
                          ? 'linear-gradient(135deg, #d97706 0%, #b45309 100%)' 
                          : 'linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%)')
                  }}
                >
                  {isSaving ? (
                    <>
                      <RefreshCw size={14} className="spin" style={{ marginRight: 6 }} /> Saving...
                    </>
                  ) : (
                    <>
                      <Save size={14} style={{ marginRight: 6 }} /> 
                      {testResult?.success 
                        ? 'Save & Connect ✅' 
                        : (testResult && !testResult.success ? 'Save Anyway ⚠️' : 'Save & Connect')}
                    </>
                  )}
                </button>
              </div>

              <button
                type="button"
                className="btn btn-outline"
                onClick={() => cancelEditing(category)}
                style={{ padding: '8px 14px', fontSize: 13 }}
              >
                Cancel
              </button>
            </div>

            {/* Note on security & behavior */}
            <div style={{ fontSize: 11, color: 'var(--text-dim)', borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: 8 }}>
              🔒 <strong>Security Policy:</strong> Passwords are encrypted with symmetric Fernet keys before persisting. Passwords are never sent back in API responses.
              {testResult && !testResult.success && (
                <span style={{ color: 'var(--accent-amber)', marginLeft: 6 }}>
                  ⚠️ Warning: Saving with an unverified connection may cause scheduled telemetry sync to skip until credentials are valid.
                </span>
              )}
            </div>
          </div>
        )}
      </div>
    );
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Top Banner */}
      <div className="glass-panel" style={{
        padding: '24px 28px',
        borderRadius: 14,
        background: 'var(--bg-card)',
        border: '1px solid var(--border-color)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: 16
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h2 style={{ margin: 0, fontSize: 22, color: 'var(--text-main)', fontWeight: 700 }}>
              Live Telemetry Connections
            </h2>
            <span style={{
              fontSize: 11,
              padding: '2px 8px',
              borderRadius: 10,
              background: 'rgba(183, 140, 102, 0.15)',
              color: 'var(--primary)',
              fontWeight: 600
            }}>
              SECURE CREDENTIAL VAULT
            </span>
          </div>
          <p style={{ margin: '6px 0 0 0', fontSize: 13, color: 'var(--text-dim)', maxWidth: 800 }}>
            Configure your SIEM/EDR and IAM connections. Refresh Status checks saved endpoints and updates telemetry now.
            Automatic telemetry updates run approximately every 30 seconds while the synchronization worker is running.
          </p>
        </div>

        <button
          className="btn btn-outline"
          onClick={handleRefresh}
          disabled={refreshing}
          style={{ padding: '8px 16px', fontSize: 13 }}
        >
          <RefreshCw size={14} className={refreshing ? 'spin' : ''} style={{ marginRight: 6 }} />
          {refreshing ? 'Checking live connections…' : 'Refresh Status'}
        </button>
      </div>

      {/* Status Alert Toast */}
      {statusMessage && (
        <div style={{
          padding: '12px 18px',
          borderRadius: 8,
          fontSize: 13,
          background: statusMessage.type === 'success' 
            ? 'rgba(126, 143, 129, 0.15)' 
            : (statusMessage.type === 'error' ? 'rgba(201, 114, 114, 0.15)' : 'rgba(183, 140, 102, 0.15)'),
          border: `1px solid ${statusMessage.type === 'success' ? 'var(--accent-green)' : (statusMessage.type === 'error' ? 'var(--accent-red)' : 'var(--primary)')}`,
          color: 'var(--text-main)',
          display: 'flex',
          alignItems: 'center',
          gap: 10
        }}>
          {statusMessage.type === 'success' ? <CheckCircle2 size={16} color="var(--accent-green)" /> : <AlertCircle size={16} />}
          <span>{statusMessage.text}</span>
        </div>
      )}

      {/* Grid of Connection Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(480px, 1fr))', gap: 24 }}>
        {renderCard(
          'siem',
          'SIEM & EDR (Wazuh)',
          'Syncs active endpoint agents, threat alert volumes, and coverage for CTRL-EDR-01',
          <Cpu size={24} />
        )}

        {renderCard(
          'iam',
          'Identity & Access (Keycloak)',
          'Syncs privileged admin accounts and multi-factor authentication coverage for CTRL-MFA-01',
          <Key size={24} />
        )}
      </div>

      {/* Background Scheduler & Security Architecture Explainer */}
      <div className="glass-panel" style={{
        padding: 20,
        borderRadius: 12,
        background: 'var(--bg-card)',
        border: '1px solid var(--border-color)',
        fontSize: 12,
        color: 'var(--text-dim)',
        lineHeight: 1.6
      }}>
        <strong style={{ color: 'var(--text-main)' }}>Continuous Telemetry Synchronization Architecture:</strong>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16, marginTop: 10 }}>
          <div>
            <span style={{ color: 'var(--primary)' }}>1. Zero Hardcoding:</span> All server endpoints and credentials are saved via <code style={{ color: 'var(--text-main)' }}>connections.json</code> and encrypted with Fernet symmetric keys.
          </div>
          <div>
            <span style={{ color: 'var(--primary)' }}>2. Isolated Scheduler:</span> APScheduler checks each connection every 30s. If any category is unconfigured, it skips silently without halting other integrations.
          </div>
          <div>
            <span style={{ color: 'var(--primary)' }}>3. Dynamic FAIR Recalibration:</span> Live agent coverage updates <code style={{ color: 'var(--text-main)' }}>CTRL-EDR-01</code> and privileged account MFA updates <code style={{ color: 'var(--text-main)' }}>CTRL-MFA-01</code>, recalculating Expected Annual Loss (EAL).
          </div>
        </div>
      </div>
    </div>
  );
}
