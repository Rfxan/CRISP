import React from 'react';
import { FileSearch, ChevronDown, Database, Info } from 'lucide-react';
import { formatINR } from '../utils/formatters';
import './RiskExplanation.css';

function Fields({ value }) {
  if (value == null) return <span className="risk-explanation-muted">Not provided</span>;
  if (typeof value !== 'object') return <span>{String(value)}</span>;
  if (!Object.keys(value).length) return <span className="risk-explanation-muted">No entries</span>;
  return <dl className="risk-explanation-fields">{Object.entries(value).map(([key, item]) => <div key={key}>
    <dt>{Array.isArray(value) ? `Item ${Number(key) + 1}` : key.replaceAll('_', ' ')}</dt>
    <dd><Fields value={item} /></dd>
  </div>)}</dl>;
}

export default function RiskExplanation({ summary }) {
  if (!summary) return null;
  const available = summary.org?.eal != null;
  const excluded = summary.excluded_assets || [];
  const sections = Object.entries({ 'Loss components (INR/year)': summary.loss_breakdown, 'Excluded assets': excluded, ...summary.explanation });
  return <details className="glass-panel risk-explanation">
    <summary className="risk-explanation-heading">
      <span className="risk-explanation-icon"><FileSearch size={20} /></span>
      <span className="risk-explanation-title">
        <strong>Financial estimates & assumptions</strong>
        <span>{available ? 'Inspect the inputs, evidence and methodology behind your estimate.' : 'Estimates will appear once assessment data is available.'}</span>
      </span>
      <span className={`badge ${available ? 'badge-real' : 'badge-simulated'}`}>{available ? 'Model estimate' : 'Awaiting data'}</span>
      <ChevronDown size={17} className="risk-explanation-chevron" />
    </summary>
    <div className="risk-explanation-body">
      {!available ? <>
        <div className="risk-explanation-empty">
          <Database size={24} />
          <div><strong>No financial estimate available yet</strong>
            <p>{excluded.length ? 'Some assets are missing business context. Review the excluded assets below to complete the assessment.' : 'Add assets, business context and scan evidence to calculate financial exposure. Model and run details will appear after an assessment is computed.'}</p>
          </div>
        </div>
        {excluded.length > 0 && <details className="risk-explanation-section"><summary>Excluded assets <span>{excluded.length}</span></summary><Fields value={excluded} /></details>}
      </> : <>
        <div className="risk-explanation-metrics">
          <div><span>Expected annual loss</span><strong className="risk-explanation-eal">{formatINR(summary.org.eal)}</strong></div>
          {[['Model', summary.model_version], ['Seed', summary.seed], ['Simulation trials', summary.trials?.toLocaleString()]].map(([label, value]) =>
            <div key={label}><span>{label}</span><strong>{value ?? 'Not recorded'}</strong></div>)}
        </div>
        <div className="risk-explanation-note"><Info size={17} /><p>Annual-loss percentiles describe modeled year-to-year variability, not confidence bounds on assumptions. Estimates use configurable planning priors and are not empirically calibrated forecasts.</p></div>
        <div className="risk-explanation-identifiers">
          <span>Run <code>{summary.run_id || 'Not recorded'}</code></span>
          <span>Snapshot <code>{summary.snapshot_hash || 'Not recorded'}</code></span>
        </div>
        <div className="risk-explanation-sections">{sections.map(([key, value]) =>
          <details key={key} className="risk-explanation-section"><summary>{key.replaceAll('_', ' ')}</summary><Fields value={value} /></details>)}</div>
      </>}
    </div>
  </details>;
}
