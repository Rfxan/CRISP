import React, { useState, useEffect } from 'react';
import { 
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, ReferenceDot 
} from 'recharts';
import { Target, TrendingUp, Award, CheckCircle2, Shield, DollarSign, Sliders, ArrowUpRight } from 'lucide-react';
import { formatINR, formatINRFull } from '../utils/formatters';
import { api } from '../services/api';
import EmptyState from './EmptyState';

export default function OptimizerView({ baseEal, status, onNavigateToIngestion }) {
  const [budget, setBudget] = useState(10_000_000); // ₹1 Crore default
  const [optimizerData, setOptimizerData] = useState(null);
  const [paretoData, setParetoData] = useState(null);
  const [loading, setLoading] = useState(false);

  const isEmpty = status === 'NO_DATA' || status === 'NO_FINDINGS' || baseEal == null;

  const runOptimization = async (b) => {
    if (isEmpty) return;
    setLoading(true);
    try {
      const res = await api.optimize(b);
      setOptimizerData(res);
    } catch (e) {
      console.error('Optimization error:', e);
    } finally {
      setLoading(false);
    }
  };

  const loadPareto = async () => {
    if (isEmpty) return;
    try {
      const res = await api.getPareto();
      setParetoData(res);
    } catch (e) {
      console.error('Pareto error:', e);
    }
  };

  useEffect(() => {
    if (!isEmpty) {
      runOptimization(budget);
      loadPareto();
    }
  }, [baseEal, status]);

  if (isEmpty) {
    return (
      <EmptyState
        status={status || 'NO_DATA'}
        title="Investment Optimizer Unavailable"
        message="Cannot compute optimal control investments without baseline risk data. Ingest an asset inventory and scan results first."
        onNavigateToIngestion={onNavigateToIngestion}
      />
    );
  }

  const handleSliderChange = (e) => {
    const val = Number(e.target.value);
    setBudget(val);
  };

  const handleSliderRelease = () => {
    runOptimization(budget);
  };

  const benchmark = optimizerData?.benchmark;
  const plan = optimizerData?.plan;
  const strategies = benchmark?.strategies || [];
  const headline = benchmark?.headline;

  const paretoPoints = paretoData?.curve ? paretoData.curve.map(pt => ({
    budget: pt.budget,
    budgetFormatted: formatINR(pt.budget),
    ealReduction: pt.eal_reduction,
    ealReductionFormatted: formatINR(pt.eal_reduction),
    spent: pt.spent
  })) : [];

  const kneePoint = paretoData?.knee_point;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      
      {/* Interactive Budget Control Bar */}
      <div className="glass-panel" style={{ padding: 22, borderTop: '3px solid var(--primary)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Sliders size={22} color="var(--primary)" />
            <div>
              <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-main)' }}>Security Investment Budget Allocator</h3>
              <p style={{ margin: 0, fontSize: 12, color: 'var(--text-dim)' }}>
                Set available capital for cybersecurity patches and controls. Integer Linear Programming (PuLP) selects the optimal mix.
              </p>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>Target Budget:</span>
            <span className="display-title" style={{ fontSize: 24, color: 'var(--primary)' }}>{formatINR(budget)}</span>
            <span className="mono" style={{ fontSize: 12, color: 'var(--text-dim)' }}>({formatINRFull(budget)})</span>
          </div>
        </div>

        <div style={{ marginTop: 18 }}>
          <input 
            type="range"
            min="1000000"
            max="50000000"
            step="1000000"
            value={budget}
            onChange={handleSliderChange}
            onMouseUp={handleSliderRelease}
            onTouchEnd={handleSliderRelease}
            style={{
              width: '100%',
              accentcolor: 'var(--primary)',
              cursor: 'pointer'
            }}
          />
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-dim)', marginTop: 4 }}>
            <span>₹10 Lakh (Min Seed)</span>
            <span>₹1 Crore (Default Board Allocation)</span>
            <span>₹2.5 Crore</span>
            <span>₹5 Crore (Enterprise Ceiling)</span>
          </div>
        </div>
      </div>

      {/* THE HEADLINE BENCHMARK PROOF PANEL (PRD Section 10.7 & 14) */}
      <div className="glass-panel glow-border" style={{ padding: 24, background: 'rgba(10, 20, 40, 0.85)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 14 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Award size={22} color="var(--primary)" />
              <h2 className="display-title" style={{ margin: 0, fontSize: 18, color: 'var(--text-main)' }}>
                Live Benchmark Proof: CRISP ILP vs. Industry Baselines
              </h2>
            </div>
            <p style={{ margin: '4px 0 0 0', fontSize: 13, color: 'var(--text-muted)' }}>
              Evaluated under the <strong>identical FAIR Monte Carlo model and identical {formatINR(budget)} budget</strong>.
            </p>
          </div>
          {headline && (
            <span className="badge badge-real" style={{ fontSize: 13, padding: '6px 12px' }}>
              +{headline.outperformance_vs_cvss_pct}% More Loss Removed
            </span>
          )}
        </div>

        {/* Headline Victory Banner */}
        {headline && (
          <div style={{
            background: 'linear-gradient(90deg, rgba(183, 140, 102, 0.12) 0%, rgba(126, 143, 129, 0.12) 100%)',
            border: '1px solid rgba(183, 140, 102, 0.3)',
            borderRadius: 10,
            padding: '12px 18px',
            margin: '16px 0',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: 12
          }}>
            <div style={{ fontSize: 13, color: '#e2e8f0' }}>
              <strong>The Headline Finding:</strong> {headline.proof_summary}
            </div>
            <div className="mono" style={{ color: 'var(--accent-green)', fontSize: 13, fontWeight: 700 }}>
              Extra Loss Prevented: {formatINR(headline.extra_rupees_saved)}
            </div>
          </div>
        )}

        {/* 3 Strategy Comparison Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
          {strategies.map((strat, idx) => {
            const isWinner = strat.type === 'recommended';
            return (
              <div key={idx} className="glass-panel" style={{
                padding: 18,
                border: isWinner ? '2px solid var(--primary)' : '1px solid var(--border-color)',
                background: isWinner ? 'rgba(183, 140, 102, 0.05)' : 'rgba(255,255,255,0.02)',
                position: 'relative'
              }}>
                {isWinner && (
                  <div style={{
                    position: 'absolute',
                    top: -10,
                    right: 14,
                    background: 'var(--primary)',
                    color: 'var(--bg-main)',
                    fontSize: 10,
                    fontWeight: 800,
                    padding: '2px 8px',
                    borderRadius: 4,
                    textTransform: 'uppercase'
                  }}>
                    Recommended Optimal
                  </div>
                )}
                <div style={{ fontSize: 13, fontWeight: 700, color: isWinner ? 'var(--primary)' : 'var(--text-main)' }}>
                  {strat.strategy_name}
                </div>
                <p style={{ fontSize: 11, color: 'var(--text-dim)', margin: '4px 0 14px 0' }}>
                  {strat.description}
                </p>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 12 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Budget Spent:</span>
                    <strong className="mono" style={{ color: 'var(--text-main)' }}>{formatINR(strat.spend)}</strong>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Expected Loss Reduction:</span>
                    <strong className="mono display-title" style={{ color: isWinner ? 'var(--accent-green)' : 'var(--text-main)', fontSize: 16 }}>
                      {formatINR(strat.eal_reduction)}
                    </strong>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Remaining Unhedged EAL:</span>
                    <strong className="mono" style={{ color: '#f87171' }}>{formatINR(strat.remaining_eal)}</strong>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', borderTop: '1px solid var(--border-color)', paddingTop: 6 }}>
                    <span style={{ color: 'var(--text-muted)' }}>Reduction per Rupee:</span>
                    <strong className="mono" style={{ color: isWinner ? 'var(--primary)' : 'var(--text-dim)' }}>
                      {strat.reduction_per_rupee}x
                    </strong>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Row: Recommended Actions & Pareto Frontier Curve */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(460px, 1fr))', gap: 20 }}>
        
        {/* Recommended Actions Portfolio */}
        <div className="glass-panel" style={{ padding: 22 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div>
              <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-main)' }}>Recommended Action Portfolio ({plan?.all_actions?.length || 0} Actions)</h3>
              <p style={{ margin: 0, fontSize: 12, color: 'var(--text-dim)' }}>
                Total Allocated: <strong>{formatINR(plan?.total_spent || 0)}</strong> | Overall Portfolio ROSI: <strong>{plan?.overall_rosi || 0}x</strong>
              </p>
            </div>
            <span className="badge badge-cyan">CBC MILP Solver</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, maxHeight: 420, overflowY: 'auto' }}>
            {plan?.all_actions?.map((act, idx) => (
              <div key={idx} className="glass-panel" style={{
                padding: 14,
                borderLeft: act.type === 'control' ? '3px solid var(--primary)' : '3px solid var(--accent-purple)',
                background: 'rgba(255,255,255,0.02)'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div>
                    <span className="badge" style={{
                      background: act.type === 'control' ? 'rgba(183, 140, 102, 0.1)' : 'rgba(154, 150, 179, 0.1)',
                      color: act.type === 'control' ? 'var(--primary)' : 'var(--accent-purple)',
                      fontSize: 10,
                      marginBottom: 4
                    }}>
                      {act.type === 'control' ? 'Security Control' : 'Vulnerability Patch'}
                    </span>
                    <h4 style={{ margin: 0, fontSize: 13, color: 'var(--text-main)' }}>{act.name || act.cve_id}</h4>
                    {act.asset_id && (
                      <div className="mono" style={{ fontSize: 10, color: 'var(--text-dim)' }}>Target: {act.asset_id}</div>
                    )}
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <div className="mono" style={{ color: 'var(--text-main)', fontSize: 13, fontWeight: 700 }}>{formatINR(act.cost)}</div>
                    <span className="badge badge-real" style={{ fontSize: 10 }}>ROSI: {act.rosi}x</span>
                  </div>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-dim)', marginTop: 8, borderTop: '1px solid var(--border-color)', paddingTop: 6 }}>
                  <span>EAL Risk Reduction:</span>
                  <span className="mono" style={{ color: 'var(--accent-green)', fontWeight: 600 }}>{formatINR(act.estimated_reduction)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Pareto Diminishing Returns Curve */}
        <div className="glass-panel" style={{ padding: 22 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div>
              <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-main)' }}>Pareto Frontier & Diminishing Returns</h3>
              <p style={{ margin: 0, fontSize: 12, color: 'var(--text-dim)' }}>
                EAL Reduction vs Budget Sweep (₹10L to ₹5Cr) marking the optimal knee point
              </p>
            </div>
            <span className="badge badge-real">Pareto Curve</span>
          </div>

          <div style={{ height: 300, width: '100%' }}>
            <ResponsiveContainer>
              <LineChart data={paretoPoints} margin={{ top: 10, right: 15, left: -5, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                <XAxis dataKey="budgetFormatted" stroke="#64748b" fontSize={11} interval={2} />
                <YAxis stroke="#64748b" fontSize={11} tickFormatter={(v) => formatINR(v)} />
                <Tooltip 
                  contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--primary)', borderRadius: 8, fontSize: 12 }}
                  formatter={(val, name, item) => [formatINRFull(val), 'EAL Reduction']}
                  labelFormatter={(lbl, item) => `Budget: ${lbl}`}
                />
                <Line 
                  type="monotone" 
                  dataKey="ealReduction" 
                  stroke="var(--primary)" 
                  strokeWidth={3} 
                  dot={{ r: 3, fill: 'var(--primary)' }} 
                  activeDot={{ r: 6 }} 
                />
                {kneePoint && (
                  <ReferenceDot 
                    x={formatINR(kneePoint.budget)} 
                    y={kneePoint.eal_reduction} 
                    r={7} 
                    fill="var(--accent-green)" 
                    stroke="var(--text-main)" 
                  />
                )}
              </LineChart>
            </ResponsiveContainer>
          </div>

          {kneePoint && (
            <div style={{
              background: 'rgba(126, 143, 129, 0.08)',
              border: '1px solid rgba(126, 143, 129, 0.3)',
              borderRadius: 8,
              padding: '10px 14px',
              marginTop: 12,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              fontSize: 12
            }}>
              <div>
                <strong style={{ color: 'var(--accent-green)' }}>Optimal "Knee" Point: {formatINR(kneePoint.budget)}</strong>
                <span style={{ color: 'var(--text-muted)', marginLeft: 8 }}>
                  Achieves {formatINR(kneePoint.eal_reduction)} reduction before marginal return per rupee drops.
                </span>
              </div>
            </div>
          )}
        </div>

      </div>

    </div>
  );
}
