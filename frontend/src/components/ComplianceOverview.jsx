import React from 'react';
import { ShieldCheck, Info } from 'lucide-react';
import './GovernanceEvidence.css';

export default function ComplianceOverview({ data }) {
  const percent = value => value == null ? 'Unknown' : `${value}%`;
  return <section className="glass-panel compliance-overview" aria-labelledby="compliance-overview-title">
    <div className="governance-heading"><span className="governance-icon"><ShieldCheck size={22} /></span>
      <div><h3 id="compliance-overview-title">Compliance assessment overview</h3><p>Keep mapping, observed controls and reviewed evidence in context.</p></div>
      <span className="badge badge-cyan">Curated subset</span>
    </div>
    <div className="compliance-evidence-metrics">
      {[['Observed control coverage', data?.observed_control_coverage_pct, 'Coverage reported by the available control inputs'],
        ['Evidence completeness', data?.evidence_completeness_pct, 'Controls backed by current, qualifying evidence'],
        ['Assessed compliant controls', data?.assessed_compliance_pct, 'Controls meeting evidence and reviewer requirements']].map(([label, value, help]) =>
        <div key={label}><span>{label}</span><strong>{percent(value)}</strong><small>{help}</small></div>)}
    </div>
    <div className="governance-note"><Info size={17} /><p>{data?.scope || 'Mapping coverage describes a curated subset of requirements. It does not establish compliance with an entire framework.'}</p></div>
  </section>;
}
