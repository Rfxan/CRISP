import React, { useState, useEffect } from 'react';
import { 
  FileText, ShieldCheck, AlertCircle, Clock, ExternalLink, Download, CheckCircle, ShieldAlert 
} from 'lucide-react';
import { formatINR } from '../utils/formatters';
import { api } from '../services/api';
import EmptyState from './EmptyState';

export default function ComplianceHub({ status, onNavigateToIngestion }) {
  const [selectedFramework, setSelectedFramework] = useState('sebi');
  const [evalData, setEvalData] = useState(null);
  const [loading, setLoading] = useState(false);

  const isEmpty = status === 'NO_DATA' || status === 'NO_FINDINGS';

  const frameworks = [
    { id: 'sebi', name: 'SEBI CSCRF (Aug 2024)', desc: 'Cyber Resilience Framework & 6-Hour Reporting' },
    { id: 'dpdp', name: 'DPDP Act & Rules 2025', desc: 'Digital Personal Data Safeguards & ₹250 Cr Cap' },
    { id: 'rbi', name: 'RBI Cyber Security Framework', desc: 'Banking & NBFC IT Governance Directions' },
    { id: 'iso', name: 'ISO/IEC 27001:2022', desc: 'Annex A Information Security Controls' },
    { id: 'nist', name: 'NIST CSF 2.0', desc: 'Govern, Identify, Protect, Detect, Respond, Recover' },
    { id: 'cis', name: 'CIS Controls v8', desc: 'Prioritized Safeguards & Asset Hygiene' }
  ];

  const loadCompliance = async (fw) => {
    if (isEmpty) return;
    setLoading(true);
    setSelectedFramework(fw);
    try {
      const res = await api.getCompliance(fw);
      setEvalData(res);
    } catch (e) {
      console.error('Compliance error:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!isEmpty) {
      loadCompliance('sebi');
    }
  }, [status]);

  if (isEmpty) {
    return (
      <EmptyState
        status={status || 'NO_DATA'}
        title="Compliance & Regulatory Auditing Unavailable"
        message="Cannot assess regulatory framework compliance without ingested assets and controls telemetry. Ingest data to evaluate SEBI, RBI, and DPDP adherence."
        onNavigateToIngestion={onNavigateToIngestion}
      />
    );
  }

  const sebi6h = evalData?.sebi_6hour_readiness;
  const dpdp = evalData?.dpdp_readiness;

  const handleExportReport = () => {
    window.open(`/api/report/${selectedFramework}`, '_blank');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      
      {/* Framework Selector Tabs */}
      <div className="glass-panel" style={{ padding: 18, borderTop: '3px solid var(--accent-green)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14, flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-main)' }}>Continuous Compliance & Evidence Center</h3>
            <p style={{ margin: 0, fontSize: 12, color: 'var(--text-dim)' }}>
              Indicative mapping across national (India) and international standards with telemetry-backed evidence.
            </p>
          </div>
          <button className="btn btn-primary" onClick={handleExportReport}>
            <Download size={15} />
            <span>Export Audit Evidence Report (HTML/Print)</span>
          </button>
        </div>

        <div style={{ display: 'flex', gap: 8, overflowX: 'auto', paddingBottom: 4 }}>
          {frameworks.map((fw) => {
            const isSelected = selectedFramework === fw.id;
            return (
              <button
                key={fw.id}
                onClick={() => loadCompliance(fw.id)}
                className={`btn ${isSelected ? 'btn-primary' : 'btn-outline'}`}
                style={{ fontSize: 12, whiteSpace: 'nowrap' }}
              >
                {fw.name}
              </button>
            );
          })}
        </div>
      </div>

      {/* Special Indian Regulatory Modules: SEBI 6-Hour & DPDP */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: 20 }}>
        
        {/* SEBI 6-Hour Incident Notification Readiness */}
        {sebi6h && (
          <div className="glass-panel" style={{ padding: 22, borderLeft: '4px solid var(--primary)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Clock size={18} color="var(--primary)" />
                <h4 style={{ margin: 0, fontSize: 14, color: 'var(--text-main)' }}>SEBI CSCRF 6-Hour Reporting Readiness</h4>
              </div>
              <span className={`badge ${sebi6h.status === 'READY' ? 'badge-real' : 'badge-critical'}`}>
                {sebi6h.status} ({sebi6h.readiness_score_pct}%)
              </span>
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 14 }}>
              Mandated under SEBI Circular 20 Aug 2024: Regulated entities must declare and report cyber incidents within 6 hours of discovery.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {sebi6h.checklist?.map((item, idx) => (
                <div key={idx} style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '8px 12px',
                  background: 'rgba(255,255,255,0.02)',
                  borderRadius: 6,
                  fontSize: 12
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    {item.pass ? <CheckCircle size={15} color="var(--accent-green)" /> : <AlertCircle size={15} color="var(--accent-red)" />}
                    <span style={{ color: item.pass ? '#f8fafc' : '#f87171' }}>{item.item}</span>
                  </div>
                  <span className="mono" style={{ color: 'var(--primary)' }}>{item.coverage_pct}%</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* DPDP Act 2025 Safeguards & Penalty Ceiling */}
        {dpdp && (
          <div className="glass-panel" style={{ padding: 22, borderLeft: '4px solid var(--accent-red)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <ShieldAlert size={18} color="var(--accent-red)" />
                <h4 style={{ margin: 0, fontSize: 14, color: 'var(--text-main)' }}>DPDP Act 2025 Safeguards & Penalty Exposure</h4>
              </div>
              <span className="badge badge-simulated">
                {dpdp.status} ({dpdp.safeguards_score_pct}%)
              </span>
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 14 }}>
              Statutory cap: <strong>₹250 Crore</strong> for failing reasonable safeguards (Section 8(5)). Modeled as heavy-tailed PERT.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {dpdp.checklist?.map((item, idx) => (
                <div key={idx} style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '8px 12px',
                  background: 'rgba(255,255,255,0.02)',
                  borderRadius: 6,
                  fontSize: 12
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    {item.pass ? <CheckCircle size={15} color="var(--accent-green)" /> : <AlertCircle size={15} color="var(--accent-red)" />}
                    <span style={{ color: item.pass ? '#f8fafc' : '#f87171' }}>{item.item}</span>
                  </div>
                  <span className="mono" style={{ color: 'var(--primary)' }}>{item.coverage_pct}%</span>
                </div>
              ))}
            </div>
          </div>
        )}

      </div>

      {/* Control Assessment & Evidence Table */}
      <div className="glass-panel" style={{ padding: 22 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-main)' }}>
              {evalData?.framework_name} — Control Registry & Audit Evidence
            </h3>
            <p style={{ margin: 0, fontSize: 12, color: 'var(--text-dim)' }}>
              Overall Framework Coverage: <strong>{evalData?.overall_coverage_pct}%</strong> ({evalData?.compliant_controls}/{evalData?.total_controls_mapped} Controls Compliant)
            </p>
          </div>
          <span className="badge badge-simulated">{evalData?.gaps_count} Gaps Flagged</span>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Control ID</th>
                <th>Control Name</th>
                <th>Framework Clause</th>
                <th>Evidence Coverage</th>
                <th>Audit Telemetry Source</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {evalData?.controls?.map((c, idx) => (
                <tr key={idx}>
                  <td>
                    <strong className="mono" style={{ color: 'var(--text-main)' }}>{c.control_id}</strong>
                  </td>
                  <td>
                    <div style={{ fontWeight: 600, color: 'var(--text-main)' }}>{c.name}</div>
                  </td>
                  <td>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{c.framework_clause}</div>
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <div style={{ width: 60, height: 6, background: 'rgba(255,255,255,0.08)', borderRadius: 3, overflow: 'hidden' }}>
                        <div style={{
                          width: `${c.coverage_pct}%`,
                          height: '100%',
                          background: c.coverage_pct >= 75 ? 'var(--accent-green)' : (c.coverage_pct >= 50 ? 'var(--accent-amber)' : 'var(--accent-red)')
                        }} />
                      </div>
                      <span className="mono" style={{ fontSize: 11 }}>{c.coverage_pct}%</span>
                    </div>
                  </td>
                  <td>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                      {c.evidence_ref}
                    </div>
                    {c.is_simulated ? (
                      <span className="badge badge-simulated" style={{ fontSize: 9 }}>SIMULATED</span>
                    ) : (
                      <span className="badge badge-real" style={{ fontSize: 9 }}>LIVE LAB</span>
                    )}
                  </td>
                  <td>
                    <span className={`badge ${c.status === 'Compliant' ? 'badge-real' : (c.status === 'Partially Compliant' ? 'badge-simulated' : 'badge-critical')}`}>
                      {c.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div style={{ marginTop: 14, fontSize: 11, color: 'var(--text-dim)', borderTop: '1px solid var(--border-color)', paddingTop: 10 }}>
          <strong>Citation & Legal Disclaimer:</strong> {evalData?.citation}. {evalData?.disclaimer}
        </div>
      </div>

    </div>
  );
}
