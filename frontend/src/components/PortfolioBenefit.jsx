import React, { useState } from 'react';
import { TrendingDown, ShieldCheck, FileSearch, ChevronDown, Play, Download, Info, CheckCircle2, AlertCircle } from 'lucide-react';
import { formatINR } from '../utils/formatters';
import './PortfolioBenefit.css';

const labels = {
  epss_reference: 'EPSS methodology reference', missing_epss_prior: 'Missing EPSS planning prior',
  public_exposure: 'Public asset exposure', internal_exposure: 'Internal asset exposure',
  unknown_scenario_relevance: 'Unknown scenario relevance', background_probability: 'Background susceptibility',
  kev_multiplier: 'KEV multiplier', systemic_sigma: 'Shared threat variation',
  cost_per_record: 'Cost per affected record', incident_response: 'Incident response cost',
  breached_fraction: 'Affected record fraction', penalty: 'Penalty planning range',
  penalty_probability: 'Penalty probability assumption', penalty_ceiling: 'Penalty ceiling assumption',
  churn_per_record: 'Reputational cost per record', downtime_fraction: 'Downtime fraction',
  likelihood_multiplier: 'Likelihood multiplier', loss_multiplier: 'Loss multiplier',
  control_effectiveness_multiplier: 'Control effectiveness multiplier', driver_limit: 'Finding evaluation limit',
  low: 'Low', likely: 'Most likely', high: 'High', source: 'Source', version: 'Version',
};
function Fields({ value }) {
  if (value == null) return <span className="portfolio-muted">Not recorded</span>;
  if (typeof value !== 'object') return <span>{typeof value === 'number' ? value.toLocaleString('en-IN', { maximumFractionDigits: 6 }) : String(value)}</span>;
  return <dl className="portfolio-fields">{Object.entries(value).map(([key, item]) =>
    <div key={key}><dt>{labels[key] || key.replaceAll('_', ' ')}</dt><dd><Fields value={item} /></dd></div>
  )}</dl>;
}

export default function PortfolioBenefit({ plan, reproducibility, replay, onReplay }) {
  const [replaying, setReplaying] = useState(false);
  const evaluation = plan.evaluation || {};
  const details = reproducibility || {};
  const changed = replay && replay.snapshot_hash !== evaluation.snapshot_hash;
  const matches = replay && !changed && replay.post_intervention?.eal === plan.remaining_eal;
  const replayPortfolio = async () => {
    setReplaying(true);
    try { await onReplay(); } finally { setReplaying(false); }
  };
  const downloadDetails = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(details, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a');
    link.href = url; link.download = 'crisp-benchmark-details.json'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  return <section className="glass-panel portfolio-benefit" aria-labelledby="portfolio-benefit-title">
    <div className="portfolio-header">
      <span className="portfolio-icon"><TrendingDown size={23} /></span>
      <div className="portfolio-title"><h3 id="portfolio-benefit-title">Simulated portfolio benefit</h3>
        <p>The selected investments, evaluated through the same risk engine as the what-if simulator.</p></div>
      <span className="badge badge-real">Model estimate</span>
    </div>
    <div className="portfolio-metrics">
      <div><span>Remaining annual loss</span><strong>{formatINR(plan.remaining_eal)}</strong><small>Expected loss after the selected actions</small></div>
      <div className="portfolio-savings"><span>Annual loss reduction</span><strong>{formatINR(plan.total_reduction)}</strong><small>Simulated benefit of the whole portfolio</small></div>
      <div><span>Portfolio investment</span><strong>{formatINR(plan.total_spent)}</strong><small>{plan.actions?.length ?? plan.all_actions?.length ?? 0} selected actions</small></div>
    </div>
    <div className="portfolio-method"><Info size={18} /><div>
      <strong>Approximate selection objective <span>{formatINR(plan.objective_estimate)}</span></strong>
      <p>The optimizer uses an additive estimate to choose actions. Their benefits can overlap; the annual loss reduction above comes from simulating the complete portfolio.</p>
    </div></div>
    <div className="portfolio-footer">
      <div className="portfolio-run-tags">
        <span>Seed <strong>{evaluation.seed ?? details.seed ?? 'Not recorded'}</strong></span>
        <span><strong>{(evaluation.trials ?? details.trials)?.toLocaleString() ?? 'Not recorded'}</strong> trials</span>
        <span>Model <strong>{evaluation.model_version ?? details.model_version ?? 'Not recorded'}</strong></span>
      </div>
      <button type="button" className="btn btn-primary portfolio-replay" onClick={replayPortfolio} disabled={replaying}>
        <Play size={16} />{replaying ? 'Replaying portfolio…' : 'Replay portfolio in simulator'}
      </button>
    </div>
    {replay && <div className={`portfolio-replay-result ${matches ? 'portfolio-match' : 'portfolio-warning'}`} role="status">
      {matches ? <CheckCircle2 size={19} /> : <AlertCircle size={19} />}
      <div><strong>{matches ? 'Optimizer and simulator match' : changed ? 'Snapshot changed' : 'Results need review'}</strong>
        <p>Simulator residual EAL: {formatINR(replay.post_intervention?.eal)}. {matches ? 'The same actions produced the same residual annual loss.' : changed ? 'Run optimization again using the current snapshot.' : 'Verify the model configuration before using these results.'}</p>
      </div>
    </div>}
    <details className="portfolio-details">
      <summary><FileSearch size={19} /><span>Benchmark reproduction details<small>Dataset, evaluation method and model assumptions</small></span><ChevronDown size={18} className="portfolio-chevron" /></summary>
      <div className="portfolio-details-body">
        <div className="portfolio-evidence-grid">
          {[['Assets in snapshot', details.asset_count], ['Active findings', details.finding_count],
            ['Assumptions version', details.assumptions_version], ['Evaluation method', details.evaluation_method]].map(([label, value]) =>
            <div key={label}><span>{label}</span><strong>{value ?? 'Not recorded'}</strong></div>)}
        </div>
        <dl className="portfolio-identifiers">
          <div><dt>Baseline run</dt><dd>{details.baseline_run_id ?? 'Not recorded'}</dd></div>
          <div><dt>Snapshot</dt><dd>{details.snapshot_hash ?? 'Not recorded'}</dd></div>
          <div><dt>Selection method</dt><dd>{plan.selection_method ?? 'Not recorded'}</dd></div>
        </dl>
        <details className="portfolio-assumptions"><summary>Inspect model assumptions <ChevronDown size={15} /></summary><Fields value={details.assumptions} /></details>
        <div className="portfolio-export"><span><ShieldCheck size={16} />Use the same snapshot, actions, assumptions and seed to reproduce the comparison.</span>
          <button type="button" className="btn btn-outline" onClick={downloadDetails}><Download size={16} />Download details (JSON)</button></div>
      </div>
    </details>
  </section>;
}
