import React, { useState, useEffect } from 'react';
import { 
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend 
} from 'recharts';
import { Sparkles, Clock, CheckCircle2, RefreshCw, ArrowRight, ShieldAlert, Sliders, Play } from 'lucide-react';
import { formatINR, formatINRFull } from '../utils/formatters';
import { api } from '../services/api';
import EmptyState from './EmptyState';

export default function WhatIfSimulator({ baselineEal, baselineVar95, status, onNavigateToIngestion }) {
  const [mode, setMode] = useState('presets'); // 'presets' | 'custom'
  const [selectedPreset, setSelectedPreset] = useState('mfa');
  const [simResult, setSimResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const isEmpty = status === 'NO_DATA' || status === 'NO_FINDINGS' || baselineEal == null;

  // Custom scenario builder state
  const [customControl, setCustomControl] = useState('CTRL-MFA-01');
  const [customCoverage, setCustomCoverage] = useState(90);
  const [patchKev, setPatchKev] = useState(false);
  const [segmentNetwork, setSegmentNetwork] = useState(false);
  const [simulationSeed, setSimulationSeed] = useState(42);

  const presets = [
    {
      id: 'mfa',
      title: 'Enforce MFA on All Privileged & DB Accounts',
      desc: 'Upgrade CTRL-MFA-01 to 100% coverage across all administrators and databases.',
      actions: [{ type: 'increase_control_coverage', target_id: 'CTRL-MFA-01', coverage_pct: 100.0 }]
    },
    {
      id: 'kev',
      title: 'Remediate All CISA KEV Listed Vulnerabilities',
      desc: 'Immediately patch all CVEs flagged in the CISA Known Exploited Catalog.',
      actions: [{ type: 'patch_all_kev' }]
    },
    {
      id: 'segmentation',
      title: 'Zero-Trust Microsegmentation on Payment Switch',
      desc: 'Isolate Payment Core DB and UPI Switch with strict firewall segmentation.',
      actions: [{ type: 'segment_payment_network' }]
    },
    {
      id: 'edr_patch',
      title: 'Combo: 100% EDR Coverage + Strict Patch SLA',
      desc: 'Bring Wazuh/EDR to 100% of endpoints and enforce 7-day automated patch SLA.',
      actions: [
        { type: 'increase_control_coverage', target_id: 'CTRL-EDR-01', coverage_pct: 100.0 },
        { type: 'increase_control_coverage', target_id: 'CTRL-PATCH-01', coverage_pct: 100.0 }
      ]
    }
  ];

  const handleSimulate = async (presetId) => {
    setSelectedPreset(presetId);
    const preset = presets.find(p => p.id === presetId);
    if (!preset) return;

    setLoading(true);
    try {
      const res = await api.simulate(preset.actions, simulationSeed);
      setSimResult(res);
    } catch (e) {
      console.error('What-if error:', e);
    } finally {
      setLoading(false);
    }
  };

  const handleRunCustom = async () => {
    setLoading(true);
    const actions = [
      { type: 'increase_control_coverage', target_id: customControl, coverage_pct: Number(customCoverage) }
    ];
    if (patchKev) actions.push({ type: 'patch_all_kev' });
    if (segmentNetwork) actions.push({ type: 'segment_payment_network' });

    try {
      const res = await api.simulate(actions, Number(simulationSeed));
      setSimResult(res);
    } catch (e) {
      console.error('Custom simulation error:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!isEmpty) {
      handleSimulate('mfa');
    }
  }, [baselineEal, status]);

  if (isEmpty) {
    return (
      <EmptyState
        status={status || 'NO_DATA'}
        title="What-If Simulator Unavailable"
        message="Cannot simulate control interventions without baseline risk data. Ingest an asset inventory and scan results first."
        onNavigateToIngestion={onNavigateToIngestion}
      />
    );
  }

  const delta = simResult?.delta;
  const costOfDelay = simResult?.cost_of_delay;

  // Comparison curve data
  const comparisonCurve = [];
  if (simResult?.baseline_curve && simResult?.new_curve) {
    const basePts = simResult.baseline_curve;
    const newPts = simResult.new_curve;
    for (let i = 0; i < Math.min(basePts.length, newPts.length); i += 2) {
      comparisonCurve.push({
        loss: basePts[i][0],
        lossFormatted: formatINR(basePts[i][0]),
        Baseline: Number((basePts[i][1] * 100).toFixed(1)),
        PostIntervention: Number((newPts[i][1] * 100).toFixed(1))
      });
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      
      {/* Header & Controls */}
      <div className="glass-panel" style={{ padding: 22, borderTop: '3px solid #8b5cf6' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, flexWrap: 'wrap', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Sparkles size={22} color="#8b5cf6" />
            <div>
              <h3 style={{ margin: 0, fontSize: 16, color: '#fff' }}>What-If Scenario Sandbox & Counterfactual Simulator</h3>
              <p style={{ margin: 0, fontSize: 12, color: 'var(--text-dim)' }}>
                Re-executes 10,000 trials on the <strong>same deterministic seed (Seed: {simulationSeed})</strong> to isolate exact mathematical deltas.
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', gap: 8 }}>
            <button
              onClick={() => setMode('presets')}
              className="btn"
              style={{
                fontSize: 12, padding: '6px 14px',
                background: mode === 'presets' ? 'rgba(139, 92, 246, 0.2)' : 'transparent',
                border: mode === 'presets' ? '1px solid #8b5cf6' : '1px solid var(--border-color)',
                color: mode === 'presets' ? '#c4b5fd' : 'var(--text-muted)'
              }}
            >
              Curated Presets
            </button>
            <button
              onClick={() => setMode('custom')}
              className="btn"
              style={{
                fontSize: 12, padding: '6px 14px',
                background: mode === 'custom' ? 'rgba(139, 92, 246, 0.2)' : 'transparent',
                border: mode === 'custom' ? '1px solid #8b5cf6' : '1px solid var(--border-color)',
                color: mode === 'custom' ? '#c4b5fd' : 'var(--text-muted)',
                display: 'flex', alignItems: 'center', gap: 6
              }}
            >
              <Sliders size={14} /> Custom Counterfactual Builder
            </button>
          </div>
        </div>

        {/* MODE 1: Preset Cards */}
        {mode === 'presets' && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 12 }}>
            {presets.map((p) => {
              const isSelected = selectedPreset === p.id;
              return (
                <div 
                  key={p.id}
                  onClick={() => handleSimulate(p.id)}
                  className="glass-panel"
                  style={{
                    padding: 14,
                    cursor: 'pointer',
                    border: isSelected ? '2px solid #8b5cf6' : '1px solid var(--border-color)',
                    background: isSelected ? 'rgba(139, 92, 246, 0.1)' : 'rgba(255,255,255,0.02)',
                    transition: 'all 0.2s ease'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <strong style={{ fontSize: 13, color: isSelected ? '#c4b5fd' : '#fff' }}>{p.title}</strong>
                    {isSelected && <CheckCircle2 size={16} color="#8b5cf6" />}
                  </div>
                  <p style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 6, lineHeight: 1.4 }}>
                    {p.desc}
                  </p>
                </div>
              );
            })}
          </div>
        )}

        {/* MODE 2: Custom Counterfactual Builder */}
        {mode === 'custom' && (
          <div style={{
            background: 'rgba(255, 255, 255, 0.02)',
            padding: 16,
            borderRadius: 8,
            border: '1px solid var(--border-color)',
            display: 'flex',
            flexDirection: 'column',
            gap: 16
          }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16 }}>
              {/* Control Picker */}
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-dim)', display: 'block', marginBottom: 6 }}>Target Security Control</label>
                <select
                  value={customControl}
                  onChange={(e) => setCustomControl(e.target.value)}
                  style={{
                    width: '100%',
                    background: '#090d16',
                    border: '1px solid var(--border-color)',
                    color: '#fff',
                    padding: '8px 12px',
                    borderRadius: 6,
                    fontSize: 13
                  }}
                >
                  <option value="CTRL-MFA-01">CTRL-MFA-01: Multi-Factor Authentication</option>
                  <option value="CTRL-EDR-01">CTRL-EDR-01: Wazuh Endpoint Detection (EDR)</option>
                  <option value="CTRL-PATCH-01">CTRL-PATCH-01: Automated Patch Management</option>
                  <option value="CTRL-WAF-01">CTRL-WAF-01: Web Application Firewall</option>
                  <option value="CTRL-BACKUP-01">CTRL-BACKUP-01: Immutable Backups</option>
                  <option value="CTRL-DLP-01">CTRL-DLP-01: Data Loss Prevention</option>
                </select>
              </div>

              {/* Target Coverage Slider */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-dim)', marginBottom: 6 }}>
                  <span>Target Coverage %</span>
                  <span style={{ color: '#00f2fe', fontWeight: 700 }}>{customCoverage}%</span>
                </div>
                <input
                  type="range"
                  min="0"
                  max="100"
                  step="5"
                  value={customCoverage}
                  onChange={(e) => setCustomCoverage(e.target.value)}
                  style={{ width: '100%', accentColor: '#8b5cf6', cursor: 'pointer' }}
                />
              </div>

              {/* Deterministic Seed */}
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-dim)', display: 'block', marginBottom: 6 }}>Deterministic PRNG Seed</label>
                <input
                  type="number"
                  value={simulationSeed}
                  onChange={(e) => setSimulationSeed(Number(e.target.value))}
                  style={{
                    width: '100%',
                    background: '#090d16',
                    border: '1px solid var(--border-color)',
                    color: '#fff',
                    padding: '8px 12px',
                    borderRadius: 6,
                    fontSize: 13
                  }}
                />
              </div>
            </div>

            {/* Checkboxes & Run Button */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
              <div style={{ display: 'flex', gap: 20 }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text-muted)', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={patchKev}
                    onChange={(e) => setPatchKev(e.target.checked)}
                    style={{ accentColor: '#8b5cf6' }}
                  />
                  <span>Remediate All CISA KEV Exploits</span>
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text-muted)', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={segmentNetwork}
                    onChange={(e) => setSegmentNetwork(e.target.checked)}
                    style={{ accentColor: '#8b5cf6' }}
                  />
                  <span>Enforce Payment Network Microsegmentation</span>
                </label>
              </div>

              <button
                onClick={handleRunCustom}
                disabled={loading}
                className="btn btn-primary"
                style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, padding: '8px 18px' }}
              >
                <Play size={14} />
                <span>{loading ? 'Executing 10,000 Trials...' : 'Run Custom Simulation'}</span>
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Delta Results & Cost of Delay Banner */}
      {simResult && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 20 }}>
          
          {/* EAL Delta Card */}
          <div className="glass-panel" style={{ padding: 20 }}>
            <span style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>EAL Delta Reduction</span>
            <div className="display-title" style={{ fontSize: 28, color: '#34d399', margin: '8px 0 4px 0' }}>
              -{formatINR(delta?.eal_reduction)}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              Drops baseline loss by <strong style={{ color: '#34d399' }}>{delta?.pct_eal_reduction}%</strong> (from {formatINR(simResult.baseline.eal)} to {formatINR(simResult.post_intervention.eal)})
            </div>
          </div>

          {/* VaR95 Delta Card */}
          <div className="glass-panel" style={{ padding: 20 }}>
            <span style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>VaR95 Tail Delta Reduction</span>
            <div className="display-title" style={{ fontSize: 28, color: '#00f2fe', margin: '8px 0 4px 0' }}>
              -{formatINR(delta?.var95_reduction)}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              Reduces 95th percentile loss by <strong style={{ color: '#00f2fe' }}>{delta?.pct_var95_reduction}%</strong>
            </div>
          </div>

          {/* Cost of Delay Hero Card (PRD Sec 10.8) */}
          <div className="glass-panel" style={{ padding: 20, borderTop: '3px solid #f59e0b', background: 'rgba(245, 158, 11, 0.04)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Clock size={16} color="#f59e0b" />
              <span style={{ fontSize: 11, color: '#fbbf24', textTransform: 'uppercase', fontWeight: 700 }}>Cost of Delay Metric</span>
            </div>
            <div className="display-title" style={{ fontSize: 28, color: '#fbbf24', margin: '8px 0 4px 0' }}>
              {formatINR(costOfDelay?.per_week_inr)} / week
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              Financial loss accumulation rate for each week implementation is postponed.
            </div>
          </div>

        </div>
      )}

      {/* Comparison Loss Exceedance Curve */}
      <div className="glass-panel" style={{ padding: 22 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, color: '#fff' }}>Before vs. After Loss Exceedance Shift</h3>
            <p style={{ margin: 0, fontSize: 12, color: 'var(--text-dim)' }}>
              Downward shift in loss exceedance probability after counterfactual intervention
            </p>
          </div>
          <span className="badge badge-cyan">Identical Seed Comparison</span>
        </div>

        <div style={{ height: 280, width: '100%' }}>
          <ResponsiveContainer>
            <AreaChart data={comparisonCurve} margin={{ top: 10, right: 15, left: -10, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
              <XAxis dataKey="lossFormatted" stroke="#64748b" fontSize={11} interval={3} />
              <YAxis stroke="#64748b" fontSize={11} tickFormatter={(v) => `${v}%`} />
              <Tooltip 
                contentStyle={{ background: '#0d1527', border: '1px solid var(--border-color)', borderRadius: 8, fontSize: 12 }}
                formatter={(val, name) => [`${val}% probability`, name === 'Baseline' ? 'Baseline Risk' : 'With Intervention']}
              />
              <Legend verticalAlign="top" height={36} wrapperStyle={{ fontSize: 12 }} />
              <Area type="monotone" dataKey="Baseline" stroke="#ef4444" fill="rgba(239, 68, 68, 0.15)" strokeWidth={2} />
              <Area type="monotone" dataKey="PostIntervention" stroke="#10b981" fill="rgba(16, 185, 129, 0.2)" strokeWidth={2.5} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

    </div>
  );
}
