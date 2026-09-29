import React from 'react';
import { 
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, 
  BarChart, Bar, CartesianGrid, Legend 
} from 'recharts';
import { ShieldCheck, TrendingUp, AlertOctagon, HelpCircle, Layers, Award } from 'lucide-react';
import { formatINR, formatINRFull } from '../utils/formatters';
import EmptyState from './EmptyState';

export default function ExecutiveView({ summary, curveData, tornadoData, onNavigateToIngestion }) {
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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      
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
                Projection if identified vulnerabilities remain unpatched
              </p>
            </div>
            <span className="badge badge-cyan">Moving Average</span>
          </div>

          {/* Dynamically computed drift percentages */}
          {(() => {
            const p30 = summary.trend?.projection_30d || eal;
            const p60 = summary.trend?.projection_60d || eal;
            const p90 = summary.trend?.projection_90d || eal;
            const d30 = eal > 0 ? (((p30 - eal) / eal) * 100).toFixed(1) : '0.0';
            const d60 = eal > 0 ? (((p60 - eal) / eal) * 100).toFixed(1) : '0.0';
            const d90 = eal > 0 ? (((p90 - eal) / eal) * 100).toFixed(1) : '0.0';

            return (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, margin: '16px 0' }}>
                <div className="glass-panel" style={{ padding: 14, textAlign: 'center', background: 'rgba(255,255,255,0.02)' }}>
                  <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>+30 Days</div>
                  <div className="display-title" style={{ fontSize: 20, color: 'var(--accent-amber)', marginTop: 4 }}>
                    {formatINR(p30)}
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--accent-red)' }}>+{d30}% Expected Drift</div>
                </div>
                <div className="glass-panel" style={{ padding: 14, textAlign: 'center', background: 'rgba(255,255,255,0.02)' }}>
                  <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>+60 Days</div>
                  <div className="display-title" style={{ fontSize: 20, color: '#f97316', marginTop: 4 }}>
                    {formatINR(p60)}
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--accent-red)' }}>+{d60}% Expected Drift</div>
                </div>
                <div className="glass-panel" style={{ padding: 14, textAlign: 'center', background: 'rgba(255,255,255,0.02)' }}>
                  <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>+90 Days</div>
                  <div className="display-title" style={{ fontSize: 20, color: 'var(--accent-red)', marginTop: 4 }}>
                    {formatINR(p90)}
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--accent-red)' }}>+{d90}% Expected Drift</div>
                </div>
              </div>
            );
          })()}

          <div style={{ background: 'rgba(255,255,255,0.03)', borderRadius: 8, padding: 12, fontSize: 11, color: 'var(--text-dim)', lineHeight: 1.4 }}>
            <strong>Methodology Transparency (PRD Sec 10.9):</strong> Linear regression trajectory computed from recorded historical snapshots. Explicitly labeled as a simple projection, not deep learning.
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
