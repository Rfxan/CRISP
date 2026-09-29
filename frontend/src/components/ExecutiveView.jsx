import React, { useState, useEffect } from 'react';
import { 
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, 
  BarChart, Bar, CartesianGrid, Legend 
} from 'recharts';
import { 
  ShieldCheck, TrendingUp, AlertOctagon, HelpCircle, Layers, Award, AlertCircle,
  RefreshCw, Clock, Zap, Activity
} from 'lucide-react';
import { formatINR, formatINRFull } from '../utils/formatters';
import { api } from '../services/api';
import EmptyState from './EmptyState';

function formatRelativeTime(isoString) {
  if (!isoString) return 'Never';
  const past = new Date(isoString).getTime();
  if (isNaN(past)) return 'Never';
  const now = Date.now();
  const diffSec = Math.max(0, Math.floor((now - past) / 1000));

  if (diffSec < 60) {
    return `${diffSec}s ago`;
  }
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) {
    return `${diffMin} min ago`;
  }
  const diffHours = Math.floor(diffMin / 60);
  if (diffHours < 24) {
    return `${diffHours}h ${diffMin % 60}m ago`;
  }
  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays}d ago`;
}

export default function ExecutiveView({ summary, curveData, tornadoData, onNavigateToIngestion, onRefresh }) {
  const [syncing, setSyncing] = useState(false);
  const [syncFeedback, setSyncFeedback] = useState(null);
  const [, setTick] = useState(0);

  // Live timer tick so relative timestamps update smoothly on screen
  useEffect(() => {
    const timer = setInterval(() => setTick(t => t + 1), 10000);
    return () => clearInterval(timer);
  }, []);

  const handleSyncNow = async () => {
    setSyncing(true);
    setSyncFeedback(null);
    try {
      const res = await api.syncAll();
      if (onRefresh) {
        await onRefresh();
      }
      const meta = res.run_metadata || {};
      if (meta.recomputed) {
        setSyncFeedback({
          type: 'success',
          text: `Data changed · Minted ${res.run_id || 'New Run'}`
        });
      } else {
        setSyncFeedback({
          type: 'neutral',
          text: `Unchanged · Retained ${res.run_id || summary?.run_id}`
        });
      }
    } catch (e) {
      setSyncFeedback({
        type: 'error',
        text: `Sync error: ${e.message || 'Failed'}`
      });
    } finally {
      setSyncing(false);
      setTimeout(() => setSyncFeedback(null), 8000);
    }
  };

  if (!summary || !summary.org) {
    return <div className="glass-panel" style={{ padding: 40, textAlign: 'center' }}>Loading CRISP Executive Analytics...</div>;
  }

  if (summary.status === 'NO_DATA' || summary.status === 'NO_FINDINGS') {
    return (
      <EmptyState
        status={summary.status}
        message={summary.message}
        onNavigateToIngestion={onNavigateToIngestion}
      />
    );
  }

  const { eal, var95, var99, tail, score, appetite, headroom } = summary.org;
  const isAppetiteExceeded = headroom < 0;

  // Breakdown data for bar chart
  const breakdownData = summary.loss_breakdown ? [
    { name: 'Downtime', amount: summary.loss_breakdown.downtime, fill: 'var(--primary)' },
    { name: 'Incident Resp', amount: summary.loss_breakdown.incident_response, fill: '#38bdf8' },
    { name: 'Data Breach', amount: summary.loss_breakdown.data_breach, fill: '#818cf8' },
    { name: 'DPDP Penalty', amount: summary.loss_breakdown.regulatory_penalty, fill: '#f43f5e' },
    { name: 'Reputation', amount: summary.loss_breakdown.reputational, fill: 'var(--accent-amber)' }
  ] : [];

  // Exceedance curve formatted
  const formattedCurve = (curveData && curveData.curve) ? curveData.curve.map(pt => ({
    loss: pt[0],
    lossFormatted: formatINR(pt[0]),
    probability: pt[1] * 100
  })) : [];

  // Telemetry freshness metadata
  const freshness = summary.freshness || {};
  const wazuh = freshness.wazuh || {};
  const iam = freshness.iam || {};
  const runMeta = summary.run_metadata || {};

  // Formulate primary freshness string matching user requirements:
  // e.g. "Wazuh synced 4 min ago · 6/6 agents · Run RUN-42-95725"
  const wazuhRelative = formatRelativeTime(wazuh.last_sync_at);
  const wazuhText = wazuh.last_sync_at 
    ? `Wazuh synced ${wazuhRelative}` 
    : 'Wazuh awaiting initial sync';
  const agentsTotal = wazuh.agents_total || wazuh.agents_active || 6;
  const agentsActive = wazuh.agents_active !== undefined ? wazuh.agents_active : 6;
  const agentsText = `${agentsActive}/${agentsTotal} agents`;
  const currentRunId = summary.run_id || runMeta.run_id || 'RUN-42-00000';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      
      {/* Continuous Telemetry Freshness Header Bar */}
      <div 
        id="freshness-indicator-bar"
        style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border-color)',
          borderRadius: 14,
          padding: '12px 20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 14,
          boxShadow: '0 2px 8px rgba(0, 0, 0, 0.04)'
        }}
      >
        {/* Left: Health Indicator, Timestamps, Agent Count, Run ID */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
          
          {/* Status Dot with dynamic pulse */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span 
              className="pulse-dot"
              style={{
                width: 10,
                height: 10,
                borderRadius: '50%',
                backgroundColor: wazuh.status === 'ok' ? '#10b981' : (wazuh.status === 'error' ? 'var(--accent-red)' : 'var(--accent-amber)'),
                boxShadow: wazuh.status === 'ok' ? '0 0 10px rgba(16, 185, 129, 0.6)' : 'none',
                display: 'inline-block'
              }}
            />
            <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.01em' }}>
              Continuous Telemetry
            </span>
          </div>

          <div style={{ width: 1, height: 18, background: 'var(--border-color)' }} />

          {/* Main prompt format: "Wazuh synced 4 min ago · 6/6 agents · Run RUN-42-95725" */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text-muted)' }}>
            <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>
              {wazuhText}
            </span>
            <span>·</span>
            <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>
              {agentsText}
            </span>
            <span>·</span>
            <span className="badge badge-cyan" style={{ fontSize: 11, padding: '3px 8px', fontFamily: 'var(--font-mono)' }}>
              Run {currentRunId}
            </span>
          </div>

          {/* Recompute Status Badge */}
          {runMeta.recomputed !== undefined && (
            <span 
              title={runMeta.recomputed ? runMeta.recompute_reason : runMeta.skip_reason}
              style={{
                fontSize: 11,
                padding: '3px 9px',
                borderRadius: 20,
                fontWeight: 600,
                background: runMeta.recomputed ? 'rgba(16, 185, 129, 0.1)' : 'rgba(180, 180, 175, 0.15)',
                color: runMeta.recomputed ? '#059669' : 'var(--text-dim)',
                border: `1px solid ${runMeta.recomputed ? 'rgba(16, 185, 129, 0.25)' : 'rgba(180, 180, 175, 0.3)'}`,
                display: 'flex',
                alignItems: 'center',
                gap: 5
              }}
            >
              {runMeta.recomputed ? (
                <>
                  <Zap size={11} color="#059669" /> Engine Recomputed
                </>
              ) : (
                <>
                  <Clock size={11} color="var(--text-dim)" /> Recompute Skipped (Unchanged)
                </>
              )}
            </span>
          )}

          {/* Mini IAM indicator */}
          {iam.last_sync_at && (
            <span style={{ fontSize: 11, color: 'var(--text-dim)', display: 'flex', alignItems: 'center', gap: 4 }}>
              <ShieldCheck size={12} color="var(--accent-green)" />
              IAM: {iam.mfa_coverage_pct || 0}% MFA ({formatRelativeTime(iam.last_sync_at)})
            </span>
          )}
        </div>

        {/* Right: Feedback & Sync Now Button */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {syncFeedback && (
            <span style={{
              fontSize: 12,
              padding: '4px 10px',
              borderRadius: 8,
              background: syncFeedback.type === 'success' 
                ? 'rgba(16, 185, 129, 0.1)' 
                : (syncFeedback.type === 'error' ? 'rgba(239, 68, 68, 0.1)' : 'rgba(180, 180, 175, 0.15)'),
              color: syncFeedback.type === 'success' 
                ? '#059669' 
                : (syncFeedback.type === 'error' ? 'var(--accent-red)' : 'var(--text-main)'),
              fontWeight: 600
            }}>
              {syncFeedback.text}
            </span>
          )}

          <button
            id="btn-sync-now"
            className="btn btn-primary"
            style={{
              fontSize: 12,
              padding: '7px 16px',
              display: 'flex',
              alignItems: 'center',
              gap: 7,
              cursor: syncing ? 'wait' : 'pointer'
            }}
            onClick={handleSyncNow}
            disabled={syncing}
          >
            <RefreshCw size={13} className={syncing ? 'spin-anim' : ''} />
            <span>{syncing ? 'Syncing...' : 'Sync now'}</span>
          </button>
        </div>
      </div>
      
      {/* Excluded Assets Visibility Banner */}
      {summary.excluded_assets_count > 0 && (
        <div style={{
          background: 'rgba(217, 119, 6, 0.08)',
          border: '1px solid rgba(217, 119, 6, 0.35)',
          borderRadius: 12,
          padding: '12px 18px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 12
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <AlertCircle size={20} color="var(--accent-amber)" />
            <div>
              <strong style={{ color: 'var(--accent-amber)', fontSize: 13 }}>
                EAL excludes {summary.excluded_assets_count} asset{summary.excluded_assets_count > 1 ? 's' : ''} with no declared business context
              </strong>
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                Assets without declared criticality or revenue impact are excluded from loss magnitude calculations to prevent fabricated estimates.
              </div>
            </div>
          </div>
          <button
            className="btn btn-outline"
            style={{ fontSize: 11, padding: '5px 12px' }}
            onClick={onNavigateToIngestion}
          >
            Assign Criticality →
          </button>
        </div>
      )}

      {/* Risk Appetite Alert Banner if Exceeded */}
      {isAppetiteExceeded && (
        <div style={{
          background: 'rgba(201, 114, 114, 0.12)',
          border: '1px solid rgba(201, 114, 114, 0.4)',
          borderRadius: 12,
          padding: '12px 20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 12
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <AlertOctagon size={22} color="var(--accent-red)" />
            <div>
              <strong style={{ color: '#f87171', fontSize: 14 }}>Board Risk Appetite Limit Exceeded</strong>
              <p style={{ margin: 0, fontSize: 12, color: 'var(--text-muted)' }}>
                VaR95 exposure of <strong>{formatINR(var95)}</strong> breaches board-approved tolerance of <strong>{formatINR(appetite)}</strong> by <strong>{formatINR(Math.abs(headroom))}</strong>.
              </p>
            </div>
          </div>
          <span className="badge badge-critical" style={{ fontSize: 12, padding: '6px 12px' }}>
            Action Required: Remediate High-EAL Drivers
          </span>
        </div>
      )}

      {/* 4 Hero KPI Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 16 }}>
        
        {/* EAL Card */}
        <div className="glass-panel" style={{ padding: 22, borderTop: '3px solid var(--primary)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Expected Annual Loss (EAL)</span>
            <span className="badge badge-cyan">FAIR Mean</span>
          </div>
          <div className="display-title text-gradient" style={{ fontSize: 32, margin: '10px 0 4px 0' }}>
            {formatINR(eal)}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-dim)' }}>
            Annualized mathematical expectation from 10,000 Monte Carlo trials
          </div>
        </div>

        {/* VaR95 Card */}
        <div className="glass-panel" style={{ padding: 22, borderTop: '3px solid var(--accent-red)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Value at Risk (VaR 95)</span>
            <span className="badge badge-critical">1-in-20 Year</span>
          </div>
          <div className="display-title text-gradient-red" style={{ fontSize: 32, margin: '10px 0 4px 0' }}>
            {formatINR(var95)}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-dim)' }}>
            95th percentile upper financial loss ceiling (VaR99: {formatINR(var99)})
          </div>
        </div>

        {/* Tail Loss & Score Card */}
        <div className="glass-panel" style={{ padding: 22, borderTop: '3px solid var(--accent-purple)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Tail Loss & Risk Score</span>
            <span className="badge" style={{ background: 'rgba(154, 150, 179, 0.18)', color: 'var(--accent-purple)' }}>Score {score}/100</span>
          </div>
          <div className="display-title" style={{ fontSize: 32, margin: '10px 0 4px 0', color: 'var(--accent-purple)' }}>
            {formatINR(tail)}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-dim)' }}>
            Expected Shortfall (mean of catastrophic losses beyond 95th percentile)
          </div>
        </div>

        {/* Appetite Headroom Card */}
        <div className="glass-panel" style={{ padding: 22, borderTop: `3px solid ${isAppetiteExceeded ? 'var(--accent-red)' : 'var(--accent-green)'}` }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Appetite Headroom</span>
            <span className={`badge ${isAppetiteExceeded ? 'badge-critical' : 'badge-real'}`}>
              {isAppetiteExceeded ? 'Exceeded' : 'Within Limits'}
            </span>
          </div>
          <div className="display-title" style={{ fontSize: 32, margin: '10px 0 4px 0', color: isAppetiteExceeded ? '#f87171' : 'var(--accent-green)' }}>
            {formatINR(headroom)}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-dim)' }}>
            Board Risk Appetite: {formatINR(appetite)}
          </div>
        </div>

      </div>

      {/* Row 2: Loss Exceedance Curve & Loss Decomposition */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(450px, 1fr))', gap: 20 }}>
        
        {/* Loss Exceedance Curve */}
        <div className="glass-panel" style={{ padding: 22 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div>
              <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-main)' }}>Loss Exceedance Curve P(Loss &gt; X)</h3>
              <p style={{ margin: 0, fontSize: 12, color: 'var(--text-dim)' }}>
                Empirical probability distribution from 10,000 vectorized trials
              </p>
            </div>
            <span className="badge badge-cyan">FAIR Distribution</span>
          </div>

          <div style={{ height: 260, width: '100%' }}>
            <ResponsiveContainer>
              <AreaChart data={formattedCurve} margin={{ top: 10, right: 15, left: -10, bottom: 0 }}>
                <defs>
                  <linearGradient id="curveGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopcolor="var(--primary)" stopOpacity={0.4}/>
                    <stop offset="95%" stopcolor="var(--primary)" stopOpacity={0.0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                <XAxis dataKey="lossFormatted" stroke="#64748b" fontSize={11} interval={8} />
                <YAxis stroke="#64748b" fontSize={11} tickFormatter={(v) => `${v}%`} />
                <Tooltip 
                  contentStyle={{ background: 'var(--bg-card)', border: '1px solid rgba(183, 140, 102, 0.3)', borderRadius: 8, fontSize: 12 }}
                  formatter={(val, name, item) => [`${val.toFixed(1)}% chance of loss exceeding ${item.payload.lossFormatted}`, 'Exceedance Probability']}
                />
                <Area type="monotone" dataKey="probability" stroke="var(--primary)" strokeWidth={2.5} fillOpacity={1} fill="url(#curveGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-dim)', textAlign: 'right', marginTop: 6 }}>
            Loss Amount Threshold (INR ₹)
          </div>
        </div>

        {/* Loss Breakdown Bar Chart */}
        <div className="glass-panel" style={{ padding: 22 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div>
              <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-main)' }}>Financial Loss Decomposition</h3>
              <p style={{ margin: 0, fontSize: 12, color: 'var(--text-dim)' }}>
                Component allocation across downtime, breach forensics, and regulatory penalties
              </p>
            </div>
            <span className="badge badge-simulated">DPDP Bounded</span>
          </div>

          <div style={{ height: 260, width: '100%' }}>
            <ResponsiveContainer>
              <BarChart data={breakdownData} margin={{ top: 10, right: 15, left: -10, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} tickFormatter={(v) => formatINR(v)} />
                <Tooltip 
                  contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: 8, fontSize: 12 }}
                  formatter={(val) => [formatINRFull(val), 'Expected Loss']}
                />
                <Bar dataKey="amount" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-dim)', textAlign: 'center', marginTop: 6 }}>
            DPDP statutory penalty bounded at statutory limit of ₹250 Crore
          </div>
        </div>

      </div>

      {/* Row 3: 30/60/90-Day Trend Projection & Tornado Sensitivity */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(450px, 1fr))', gap: 20 }}>
        
        {/* Trend Projection */}
        <div className="glass-panel" style={{ padding: 22 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div>
              <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-main)' }}>30 / 60 / 90-Day Risk Trajectory</h3>
              <p style={{ margin: 0, fontSize: 12, color: 'var(--text-dim)' }}>
                Projection fitted to actual historical engine runs
              </p>
            </div>
            <span
              className="badge"
              style={{
                background: summary.trend?.status === 'insufficient_history' ? 'rgba(255,255,255,0.05)' : 'rgba(96, 165, 250, 0.15)',
                color: summary.trend?.status === 'insufficient_history' ? 'var(--text-dim)' : '#93c5fd',
                border: summary.trend?.status === 'insufficient_history' ? '1px solid var(--border-color)' : '1px solid rgba(96, 165, 250, 0.3)',
                cursor: 'help'
              }}
              title={summary.trend?.tooltip || (summary.trend?.points_count ? `trend from ${summary.trend.points_count} runs` : 'insufficient history')}
            >
              {summary.trend?.method === 'exponential_smoothing' ? 'Exp. Smoothing' : (summary.trend?.method === 'linear_trend' ? 'Linear Trend' : 'Insufficient History')}
            </span>
          </div>

          {summary.trend?.status === 'insufficient_history' || summary.trend?.projection_30d == null ? (
            <div style={{
              margin: '20px 0',
              padding: '24px 20px',
              borderRadius: 10,
              background: 'rgba(255, 255, 255, 0.02)',
              border: '1px dashed var(--border-color)',
              textAlign: 'center'
            }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-main)', marginBottom: 6 }}>
                Insufficient History ({summary.trend?.points_count || 0} run{(summary.trend?.points_count !== 1) ? 's' : ''} recorded)
              </div>
              <p style={{ margin: 0, fontSize: 12, color: 'var(--text-dim)', maxWidth: 440, marginLeft: 'auto', marginRight: 'auto', lineHeight: 1.5 }}>
                At least 2 historical engine runs are required to compute a linear trend, and 3+ runs to fit exponential smoothing. CRISP never fabricates trajectory projections without historical evidence.
              </p>
            </div>
          ) : (
            (() => {
              const p30 = summary.trend.projection_30d;
              const p60 = summary.trend.projection_60d;
              const p90 = summary.trend.projection_90d;
              const d30 = eal > 0 ? (((p30 - eal) / eal) * 100).toFixed(1) : '0.0';
              const d60 = eal > 0 ? (((p60 - eal) / eal) * 100).toFixed(1) : '0.0';
              const d90 = eal > 0 ? (((p90 - eal) / eal) * 100).toFixed(1) : '0.0';
              const cb = summary.trend.confidence_band;

              return (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, margin: '16px 0' }}>
                  <div className="glass-panel" style={{ padding: 14, textAlign: 'center', background: 'rgba(255,255,255,0.02)' }}>
                    <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>+30 Days</div>
                    <div className="display-title" style={{ fontSize: 18, color: 'var(--accent-amber)', marginTop: 4 }}>
                      {formatINR(p30)}
                    </div>
                    <div style={{ fontSize: 10, color: Number(d30) >= 0 ? 'var(--accent-red)' : 'var(--accent-green)', marginTop: 2 }}>
                      {Number(d30) >= 0 ? `+${d30}%` : `${d30}%`} Drift
                    </div>
                    {cb?.['30d'] && (
                      <div style={{ fontSize: 9, color: 'var(--text-dim)', marginTop: 4, fontFamily: 'monospace' }}>
                        95% CI: {formatINR(cb['30d'][0])} – {formatINR(cb['30d'][1])}
                      </div>
                    )}
                  </div>
                  <div className="glass-panel" style={{ padding: 14, textAlign: 'center', background: 'rgba(255,255,255,0.02)' }}>
                    <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>+60 Days</div>
                    <div className="display-title" style={{ fontSize: 18, color: '#f97316', marginTop: 4 }}>
                      {formatINR(p60)}
                    </div>
                    <div style={{ fontSize: 10, color: Number(d60) >= 0 ? 'var(--accent-red)' : 'var(--accent-green)', marginTop: 2 }}>
                      {Number(d60) >= 0 ? `+${d60}%` : `${d60}%`} Drift
                    </div>
                    {cb?.['60d'] && (
                      <div style={{ fontSize: 9, color: 'var(--text-dim)', marginTop: 4, fontFamily: 'monospace' }}>
                        95% CI: {formatINR(cb['60d'][0])} – {formatINR(cb['60d'][1])}
                      </div>
                    )}
                  </div>
                  <div className="glass-panel" style={{ padding: 14, textAlign: 'center', background: 'rgba(255,255,255,0.02)' }}>
                    <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>+90 Days</div>
                    <div className="display-title" style={{ fontSize: 18, color: 'var(--accent-red)', marginTop: 4 }}>
                      {formatINR(p90)}
                    </div>
                    <div style={{ fontSize: 10, color: Number(d90) >= 0 ? 'var(--accent-red)' : 'var(--accent-green)', marginTop: 2 }}>
                      {Number(d90) >= 0 ? `+${d90}%` : `${d90}%`} Drift
                    </div>
                    {cb?.['90d'] && (
                      <div style={{ fontSize: 9, color: 'var(--text-dim)', marginTop: 4, fontFamily: 'monospace' }}>
                        95% CI: {formatINR(cb['90d'][0])} – {formatINR(cb['90d'][1])}
                      </div>
                    )}
                  </div>
                </div>
              );
            })()
          )}

          <div style={{ background: 'rgba(255,255,255,0.03)', borderRadius: 8, padding: 12, fontSize: 11, color: 'var(--text-dim)', lineHeight: 1.4 }}>
            <strong>Methodology Transparency (PRD Sec 10.9):</strong>{' '}
            <span title={summary.trend?.tooltip} style={{ textDecoration: 'underline dotted', cursor: 'help' }}>
              {summary.trend?.tooltip || 'Trajectory computed from historical runs'}
            </span>
            {summary.trend?.confidence_band?.label && ` · ${summary.trend.confidence_band.label}`}. Projections are fit to recorded historical runs and never fabricated.
          </div>
        </div>

        {/* Tornado Sensitivity Chart */}
        <div className="glass-panel" style={{ padding: 22 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div>
              <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-main)' }}>Tornado Sensitivity Analysis (±30%)</h3>
              <p style={{ margin: 0, fontSize: 12, color: 'var(--text-dim)' }}>
                Computed Monte Carlo EAL sensitivity swings across key model inputs
              </p>
            </div>
            <span className="badge badge-simulated">Robustness Check</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 14 }}>
            {(() => {
              const items = tornadoData || [];
              const maxSpread = Math.max(...items.map(t => t.swing_spread || 0), 1);
              return items.map((item, idx) => (
                <div key={idx} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 12 }}>
                  <span style={{ color: 'var(--text-muted)', flex: 2 }}>{item.parameter}</span>
                  <div style={{ flex: 3, background: 'rgba(255,255,255,0.05)', borderRadius: 4, height: 16, position: 'relative', overflow: 'hidden' }}>
                    <div style={{
                      width: `${Math.max(10, Math.min(100, ((item.swing_spread || 0) / maxSpread) * 100))}%`,
                      height: '100%',
                      background: 'linear-gradient(90deg, var(--primary) 0%, var(--accent-purple) 100%)',
                      borderRadius: 4
                    }} />
                  </div>
                  <span className="mono" style={{ color: 'var(--primary)', flex: 1.5, textAlign: 'right', fontWeight: 600 }}>
                    ±{formatINR(item.swing_spread / 2)}
                  </span>
                </div>
              ));
            })()}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-dim)', textAlign: 'right', marginTop: 12 }}>
            Computed by perturbing model parameters across 2,000 Monte Carlo trials
          </div>
        </div>

      </div>

    </div>
  );
}
