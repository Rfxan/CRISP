import React, { useState, useEffect, useRef } from 'react';
import { 
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, ReferenceDot 
} from 'recharts';
import { Target, TrendingUp, Award, CheckCircle2, Shield, DollarSign, Sliders, ArrowUpRight } from 'lucide-react';
import { formatINR, formatINRFull } from '../utils/formatters';
import { api } from '../services/api';
import EmptyState from './EmptyState';
import PortfolioBenefit from './PortfolioBenefit';

export default function OptimizerView({ baseEal, status, onNavigateToIngestion }) {
  const [budget, setBudget] = useState(10_000_000); // ₹1 Crore default
  const [optimizerData, setOptimizerData] = useState(null);
  const [paretoData, setParetoData] = useState(null);
  const [replay, setReplay] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [paretoError, setParetoError] = useState('');
  const [resultBudget, setResultBudget] = useState(null);
  const generation = useRef(0);

  const isEmpty = status === 'NO_DATA' || status === 'NO_FINDINGS' || baseEal == null;

  const runOptimization = async (b) => {
    if (isEmpty) return;
    const requestId = ++generation.current;
    setLoading(true);
    try {
      const res = await api.optimize(b);
      if (requestId !== generation.current) return;
      setResultBudget(b);
      setOptimizerData(res); setReplay(null); setError('');
    } catch (e) {
      if (requestId === generation.current) setError(e.message);
    } finally {
      if (requestId === generation.current) setLoading(false);
    }
  };

  const loadPareto = async () => {
    if (isEmpty) return;
    try {
      const res = await api.getPareto();
      setParetoData(res); setParetoError('');
    } catch (e) {
      setParetoError(e.message);
    }
  };

  useEffect(() => {
    if (!isEmpty) {
      runOptimization(budget);
      loadPareto();
    }
    return () => { generation.current++; };
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

  if (!optimizerData) return (
    <section className="glass-panel" aria-busy={loading} style={{ padding: 24 }}>
      <h3>Investment optimizer</h3>
      <p role={error ? 'alert' : 'status'}>{error || 'Calculating portfolio and comparison strategies. Results will appear when the calculation finishes.'}</p>
      {error && <button type="button" className="btn btn-primary" onClick={() => runOptimization(budget)}>Retry optimization</button>}
    </section>
  );

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
    <div aria-busy={loading} style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {loading && <p role="status">Calculating for {formatINR(budget)}. The displayed result is from the last completed budget of {formatINR(resultBudget)}.</p>}
      {paretoError && <div role="alert">Investment curve unavailable: {paretoError} <button className="btn btn-outline" onClick={loadPareto}>Retry investment curve</button></div>}
      
      {error && <p role="alert">{error}</p>}
      {plan && <PortfolioBenefit plan={plan} reproducibility={benchmark?.reproducibility} replay={replay} onReplay={async () => {
          try { setReplay(await api.simulate(plan.actions, plan.evaluation.seed)); setError(''); }
          catch (e) { setError(e.message); }
        }} />}
      {/* Interactive Budget Control Bar */}
      <div className="glass-panel" style={{ padding: 22, borderTop: '3px solid var(--primary)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Sliders size={22} color="var(--primary)" />
            <div>
              <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-main)' }}>Security Investment Budget Allocator</h3>
              <p style={{ margin: 0, fontSize: 12, color: 'var(--text-dim)' }}>
                Set available capital for cybersecurity patches and controls. Integer Linear Programming (PuLP) selects an approximate portfolio.
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
            aria-label="Security investment budget"
            type="range"
            min="1000000"
            max="50000000"
            step="1000000"
            value={budget}
            onChange={handleSliderChange}
            onMouseUp={handleSliderRelease}
            onTouchEnd={handleSliderRelease}
            onKeyUp={e => { if (['ArrowLeft', 'ArrowRight', 'Home', 'End', 'PageUp', 'PageDown'].includes(e.key)) handleSliderRelease(); }}
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
      <div className="glass-panel glow-border crisp-benchmark-panel" style={{ padding: 24, background: '#0B132B' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 14 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Award size={22} color="var(--primary)" />
              <h2 className="display-title" style={{ margin: 0, fontSize: 18, color: '#F8FAFC' }}>
                Live Benchmark Proof: CRISP ILP vs. Industry Baselines
              </h2>
            </div>
            <p className="benchmark-subtitle" style={{ margin: '4px 0 0 0', fontSize: 13, color: '#CBD5E1' }}>
              Evaluated under the <strong>identical FAIR Monte Carlo model and identical {formatINR(resultBudget)} budget</strong>.
            </p>
          </div>
          {headline && (
            <span className="badge badge-real" style={{ fontSize: 13, padding: '6px 12px' }}>
              {headline.outperformance_vs_cvss_pct == null ? 'Comparison unavailable' : `${headline.outperformance_vs_cvss_pct}% change vs CVSS`}
            </span>
          )}
        </div>

        {/* Headline Victory Banner */}
        {headline && (
          <div style={{
            background: 'linear-gradient(90deg, rgba(183, 140, 102, 0.15) 0%, rgba(126, 143, 129, 0.15) 100%)',
            border: '1px solid rgba(183, 140, 102, 0.35)',
            borderRadius: 10,
            padding: '12px 18px',
            margin: '16px 0',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: 12
          }}>
            <div style={{ fontSize: 13, color: '#F1F5F9' }}>
              <strong>Dataset comparison:</strong> {headline.proof_summary}
            </div>
            <div className="mono" style={{ color: 'var(--accent-green)', fontSize: 13, fontWeight: 700 }}>
              Extra Loss Prevented: {formatINR(headline.extra_rupees_saved)}
            </div>
          </div>
        )}

        {/* 3 Strategy Comparison Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 280px), 1fr))', gap: 16, paddingTop: 16 }}>
          {strategies.map((strat, idx) => {
            const isWinner = strat.type === 'recommended';
            return (
              <div key={idx} className="glass-panel" style={{
                padding: 18,
                border: isWinner ? '2px solid var(--primary)' : '1px solid rgba(255, 255, 255, 0.12)',
                background: isWinner ? 'rgba(183, 140, 102, 0.12)' : 'rgba(255, 255, 255, 0.04)',
                position: 'relative',
                overflow: 'visible'
              }}>
                {isWinner && (
                  <div style={{
                    position: 'absolute',
                    top: -11,
                    right: 14,
                    background: 'linear-gradient(135deg, var(--primary) 0%, #d4a779 100%)',
                    color: '#0B132B',
                    fontSize: 10,
                    fontWeight: 800,
                    padding: '3px 10px',
                    borderRadius: 6,
                    textTransform: 'uppercase',
                    letterSpacing: '0.05em',
                    boxShadow: '0 4px 10px rgba(0, 0, 0, 0.4)',
                    zIndex: 10
                  }}>
                    ILP selection
                  </div>
                )}
                <div style={{ fontSize: 13, fontWeight: 700, color: isWinner ? 'var(--primary)' : '#F8FAFC' }}>
                  {strat.strategy_name}
                </div>
                <p style={{ fontSize: 11, color: '#94A3B8', margin: '4px 0 14px 0' }}>
                  {strat.description}
                </p>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 12 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#94A3B8' }}>Budget Spent:</span>
                    <strong className="mono" style={{ color: '#F8FAFC' }}>{formatINR(strat.spend)}</strong>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#94A3B8' }}>Simulated annual loss reduction:</span>
                    <strong className="mono display-title" style={{ color: isWinner ? 'var(--accent-green)' : '#F8FAFC', fontSize: 16 }}>
                      {formatINR(strat.eal_reduction)}
                    </strong>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#94A3B8' }}>Remaining Unhedged EAL:</span>
                    <strong className="mono" style={{ color: '#F87171' }}>{formatINR(strat.remaining_eal)}</strong>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', borderTop: '1px solid rgba(255, 255, 255, 0.1)', paddingTop: 6 }}>
                    <span style={{ color: '#94A3B8' }}>Reduction per Rupee:</span>
                    <strong className="mono" style={{ color: isWinner ? 'var(--primary)' : '#CBD5E1' }}>
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
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 460px), 1fr))', gap: 20 }}>
        
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

          <div style={{ display: 'flex', flexDirection: 'column', gap: 12, maxHeight: 460, overflowY: 'auto', paddingRight: 6 }}>
            {plan?.all_actions?.map((act, idx) => (
              <div key={idx} className="glass-panel" style={{
                padding: '14px 16px',
                borderLeft: act.type === 'control' ? '4px solid var(--primary)' : '4px solid var(--accent-purple)',
                background: 'var(--bg-card)',
                display: 'flex',
                flexDirection: 'column',
                gap: 8,
                flexShrink: 0,
                borderRadius: 12,
                overflow: 'visible',
                minHeight: 'fit-content'
              }}>
                {/* Meta header: Badges on left, Cost & ROSI on right */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                    <span className="badge" style={{
                      background: act.type === 'control' ? 'rgba(183, 140, 102, 0.15)' : 'rgba(154, 150, 179, 0.15)',
                      color: act.type === 'control' ? 'var(--primary)' : 'var(--accent-purple)',
                      borderColor: act.type === 'control' ? 'rgba(183, 140, 102, 0.3)' : 'rgba(154, 150, 179, 0.3)',
                      fontSize: 10,
                      padding: '2px 8px',
                      whiteSpace: 'nowrap'
                    }}>
                      {act.type === 'control' ? 'Security Control' : 'Vulnerability Patch'}
                    </span>
                    {act.asset_id && (
                      <span className="mono" style={{ fontSize: 11, color: 'var(--text-dim)', background: 'rgba(0,0,0,0.03)', padding: '2px 6px', borderRadius: 4 }}>
                        Target: {act.asset_id}
                      </span>
                    )}
                    {act.severity && (
                      <span className="badge" style={{ fontSize: 9, padding: '2px 6px', color: act.severity === 'Critical' ? 'var(--accent-red)' : 'var(--accent-amber)' }}>
                        {act.severity}
                      </span>
                    )}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span className="mono" style={{ color: 'var(--text-main)', fontSize: 13, fontWeight: 700 }}>
                      {formatINR(act.cost)}
                    </span>
                    <span className="badge badge-real" style={{ fontSize: 10, padding: '2px 7px' }}>
                      {act.cost_source}
                    </span>
                  </div>
                </div>

                {/* Action Title: dedicated block, clean wrapping, title tooltip */}
                <div style={{ width: '100%', minWidth: 0 }}>
                  <h4 
                    title={act.name || act.cve_id}
                    style={{ 
                      margin: 0, 
                      fontSize: 13, 
                      fontWeight: 600, 
                      color: 'var(--text-main)', 
                      lineHeight: 1.45,
                      wordBreak: 'break-word',
                      overflowWrap: 'break-word'
                    }}
                  >
                    {act.name || act.cve_id}
                  </h4>
                </div>

                {/* Loss Reduction */}
                <div style={{ 
                  display: 'flex', 
                  justifyContent: 'space-between', 
                  alignItems: 'center', 
                  fontSize: 11, 
                  color: 'var(--text-dim)', 
                  borderTop: '1px solid var(--border-color)', 
                  paddingTop: 6 
                }}>
                  <span>Selection estimate:</span>
                  <span className="mono" style={{ color: 'var(--accent-green)', fontWeight: 700, fontSize: 12 }}>
                    {formatINR(act.objective_coefficient)}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Pareto Diminishing Returns Curve */}
        <div className="glass-panel" style={{ padding: 22 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div>
              <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-main)' }}>Evaluated Investment Curve</h3>
              <p style={{ margin: 0, fontSize: 12, color: 'var(--text-dim)' }}>
                Simulated EAL reduction across selected budgets (₹10L to ₹5Cr); selection is approximate
              </p>
            </div>
            <span className="badge badge-real">Pareto Curve</span>
          </div>

          <div style={{ height: 300, width: '100%' }}>
            <ResponsiveContainer>
              <LineChart data={paretoPoints} margin={{ top: 10, right: 15, left: -5, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                <XAxis dataKey="budget" type="number" domain={[0, 'dataMax']} tickFormatter={formatINR} stroke="#64748b" fontSize={11} interval={2} />
                <YAxis stroke="#64748b" fontSize={11} tickFormatter={(v) => formatINR(v)} />
                <Tooltip 
                  contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--primary)', borderRadius: 8, fontSize: 12 }}
                  formatter={(val, name, item) => [formatINRFull(val), 'EAL Reduction']}
                  labelFormatter={(lbl, item) => `Budget: ${formatINR(lbl)}`}
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
                    x={kneePoint.budget}
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
