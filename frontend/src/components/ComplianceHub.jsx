import React, { useState, useEffect } from 'react';
import { 
  FileText, ShieldCheck, AlertCircle, Clock, ExternalLink, Download, CheckCircle, ShieldAlert, ChevronDown, ChevronUp, Info, HelpCircle 
} from 'lucide-react';
import { formatINR } from '../utils/formatters';
import { api } from '../services/api';
import GovernanceEvidence from './GovernanceEvidence';
import EmptyState from './EmptyState';

export default function ComplianceHub({ status, onNavigateToIngestion }) {
  const [selectedFramework, setSelectedFramework] = useState('sebi');
  const [evalData, setEvalData] = useState(null);
  const [frameworkSummaries, setFrameworkSummaries] = useState({});
  const [loading, setLoading] = useState(false);
  const [exportError, setExportError] = useState('');
  const [showUnmapped, setShowUnmapped] = useState(true);

  const isEmpty = !status || status === 'NO_DATA' || status === 'NO_FINDINGS';

  const frameworks = [
    { id: 'sebi', name: 'SEBI CSCRF 2024', desc: 'Cyber Resilience Framework & 6-Hour Incident Notification' },
    { id: 'rbi', name: 'RBI Cyber Security Framework', desc: 'Banking & NBFC IT Governance & Telemetry Directions' },
    { id: 'iso', name: 'ISO/IEC 27001:2022', desc: 'Annex A Information Security Controls' },
    { id: 'nist', name: 'NIST CSF 2.0', desc: 'Govern, Identify, Protect, Detect, Respond, Recover' },
    { id: 'cis', name: 'CIS Controls v8', desc: 'Prioritized Technical Safeguards & Host Hygiene' },
    { id: 'dpdp', name: 'DPDP Act & Rules 2025', desc: 'Digital Personal Data Safeguards & Statutory Cap' }
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

  const loadSummaries = async () => {
    try {
      const summaries = await api.getComplianceSummary();
      setFrameworkSummaries(summaries);
    } catch (e) {
      console.error('Compliance summary error:', e);
    }
  };

  useEffect(() => {
    setEvalData(null);
    setFrameworkSummaries({});
    if (!isEmpty) {
      loadCompliance('sebi');
      loadSummaries();
    }
  }, [status]);

  if (isEmpty) {
    return (
      <EmptyState
        status={status || 'NO_DATA'}
        title="No compliance evidence ingested yet"
        message="Add your organization's assets and security telemetry to begin an assessment. Built-in framework mappings are reference material; they are not your organization's compliance results."
        onNavigateToIngestion={onNavigateToIngestion}
      />
    );
  }

  const sebi6h = evalData?.sebi_6hour_readiness;
  const dpdp = evalData?.dpdp_readiness;

  const downloadReport = async (format) => {
    try {
      const content = await api.getEvidenceReport(selectedFramework, format);
      const url = URL.createObjectURL(new Blob([content], { type: format === 'html' ? 'text/html' : 'text/csv' }));
      const link = document.createElement('a'); link.href = url; link.download = `${selectedFramework}-evidence.${format}`;
      link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) { setExportError(e.message); }
  };
  const handleExportHTML = () => downloadReport('html');
  const handleDownloadCSV = () => downloadReport('csv');

  // Get live summary stats for current framework
  const activeSummary = frameworkSummaries[selectedFramework] || {
    mapping_coverage_pct: evalData?.mapping_coverage_pct ?? 0,
    total_framework_requirements: evalData?.total_framework_requirements ?? 0,
    mapped_requirements_count: evalData?.mapped_requirements_count ?? 0,
    unmapped_requirements_count: evalData?.unmapped_requirements_count ?? 0
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      
      {exportError && <p role="alert">{exportError}</p>}
      <div className="glass-panel" style={{ padding: 20 }}>
        <p>{evalData?.scope}</p>
        <p>Observed control coverage: {evalData?.observed_control_coverage_pct == null ? 'Unknown' : `${evalData.observed_control_coverage_pct}%`} · Evidence completeness: {evalData?.evidence_completeness_pct ?? 'Unknown'}% · Assessed compliant controls: {evalData?.assessed_compliance_pct ?? 'Unknown'}%</p>
        <p>Mapping coverage describes this curated subset. It does not establish compliance with an entire framework.</p>
      </div>
      <GovernanceEvidence controls={evalData?.controls} onSaved={() => { loadCompliance(selectedFramework); loadSummaries(); }} />
      {/* Framework Selector Tabs with Honest Mapping Badges */}
      <div className="glass-panel" style={{ padding: 20, borderTop: '3px solid var(--accent-green)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-main)' }}>Continuous Compliance & Evidence Center</h3>
            <p style={{ margin: 0, fontSize: 12, color: 'var(--text-dim)' }}>
              Evidence and reviewer assessments for a curated subset of framework requirements.
            </p>
          </div>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            <button 
              className="btn btn-outline" 
              onClick={handleDownloadCSV} 
              style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, background: 'rgba(255,255,255,0.03)' }}
              title="Download RFC 4180 CSV evidence report for spreadsheet analysis"
            >
              <Download size={15} />
              <span>Download Evidence (CSV)</span>
            </button>
            <button 
              className="btn btn-primary" 
              onClick={handleExportHTML} 
              style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}
              title="Open printable HTML audit report with executive KPIs and evidence matrix"
            >
              <ExternalLink size={15} />
              <span>Print Audit Report (HTML)</span>
            </button>
          </div>
        </div>

        {/* Framework Selector Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: 10 }}>
          {frameworks.map((fw) => {
            const isSelected = selectedFramework === fw.id;
            const summary = frameworkSummaries[fw.id];
            const mappingPct = summary ? summary.mapping_coverage_pct : (selectedFramework === fw.id ? evalData?.mapping_coverage_pct : null);
            const unmappedCount = summary ? summary.unmapped_requirements_count : (selectedFramework === fw.id ? evalData?.unmapped_requirements_count : null);

            return (
              <button
                key={fw.id}
                onClick={() => loadCompliance(fw.id)}
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'flex-start',
                  padding: '12px 14px',
                  borderRadius: 8,
                  gap: 6,
                  textAlign: 'left',
                  cursor: 'pointer',
                  transition: 'all 0.2s ease',
                  background: isSelected ? 'rgba(34, 197, 94, 0.12)' : 'rgba(255, 255, 255, 0.02)',
                  border: isSelected ? '1px solid var(--accent-green)' : '1px solid rgba(255, 255, 255, 0.08)',
                  color: 'inherit'
                }}
              >
                <div style={{ fontWeight: 600, fontSize: 13, color: isSelected ? 'var(--text-main)' : 'var(--text-muted)' }}>
                  {fw.name}
                </div>
                <div style={{ fontSize: 11, display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                  {mappingPct !== null && mappingPct !== undefined ? (
                    <>
                      <span style={{ 
                        fontWeight: 600, 
                        color: mappingPct >= 80 ? 'var(--accent-green)' : (mappingPct >= 60 ? 'var(--accent-amber)' : 'var(--accent-red)') 
                      }}>
                        {mappingPct}% mapped
                      </span>
                      <span style={{ color: 'var(--text-dim)' }}>·</span>
                      <span style={{ color: 'var(--text-dim)' }}>
                        {unmappedCount} unmapped
                      </span>
                    </>
                  ) : (
                    <span style={{ color: 'var(--text-dim)' }}>Loading...</span>
                  )}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Honest Coverage & Audit Metrics Strip for Selected Framework */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 14 }}>
        
        {/* Metric 1: Telemetry Mapping Coverage */}
        <div className="glass-panel" style={{ padding: 18, borderLeft: '4px solid var(--accent-green)' }}>
          <div style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 4 }}>
            Telemetry Mapping Coverage
          </div>
          <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--accent-green)', fontFamily: 'JetBrains Mono, monospace' }}>
            {evalData?.mapping_coverage_pct ?? '--'}%
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
            {evalData?.mapped_requirements_count} of {evalData?.total_framework_requirements} requirements mapped in the curated subset
          </div>
        </div>

        {/* Metric 2: Active Controls Implementation Status */}
        <div className="glass-panel" style={{ padding: 18, borderLeft: '4px solid var(--primary)' }}>
          <div style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 4 }}>
            Assessed compliant controls
          </div>
          <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--primary)', fontFamily: 'JetBrains Mono, monospace' }}>
            {evalData?.assessed_compliance_pct ?? '--'}%
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
            {evalData?.compliant_controls} of {evalData?.total_controls_mapped} controls meet compliant thresholds
          </div>
        </div>

        {/* Metric 3: Technical Gaps Flagged */}
        <div className="glass-panel" style={{ padding: 18, borderLeft: '4px solid var(--accent-amber)' }}>
          <div style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 4 }}>
            Audit Gaps Flagged
          </div>
          <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--accent-amber)', fontFamily: 'JetBrains Mono, monospace' }}>
            {evalData?.gaps_count ?? 0}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
            Controls requiring remediation or coverage expansion
          </div>
        </div>

        {/* Metric 4: Unmapped Governance Scope */}
        <div className="glass-panel" style={{ padding: 18, borderLeft: '4px solid var(--text-dim)' }}>
          <div style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 4 }}>
            Out-of-Scope (Governance/HR)
          </div>
          <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--text-main)', fontFamily: 'JetBrains Mono, monospace' }}>
            {evalData?.unmapped_requirements_count ?? 0}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
            Clauses outside machine telemetry (charters, physical, HR)
          </div>
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
                {sebi6h.status} {sebi6h.readiness_score_pct == null ? '' : `(${sebi6h.readiness_score_pct}%)`}
              </span>
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 14 }}>
              {sebi6h.requirement}. Readiness requires recorded exercise evidence.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {sebi6h.checklist?.map((item, idx) => (
                <div key={idx} style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '8px 12px',
                  background: item.pass ? 'rgba(126, 143, 129, 0.08)' : 'rgba(201, 114, 114, 0.06)',
                  border: item.pass ? '1px solid rgba(126, 143, 129, 0.2)' : '1px solid rgba(201, 114, 114, 0.15)',
                  borderRadius: 6,
                  fontSize: 12
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    {item.pass ? <CheckCircle size={15} color="var(--accent-green)" /> : <AlertCircle size={15} color="var(--accent-red)" />}
                    <span style={{ color: item.pass ? 'var(--text-main)' : 'var(--accent-red)', fontWeight: 500 }}>{item.item}</span>
                  </div>
                  <span className="mono" style={{ color: item.pass ? 'var(--accent-green)' : 'var(--text-dim)', fontWeight: 600 }}>{item.coverage_pct == null ? 'Unknown' : `${item.coverage_pct}%`}</span>
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
                <h4 style={{ margin: 0, fontSize: 14, color: 'var(--text-main)' }}>Personal-data safeguards evidence</h4>
              </div>
              <span className="badge badge-simulated">
                {dpdp.status} {dpdp.safeguards_score_pct == null ? '' : `(${dpdp.safeguards_score_pct}%)`}
              </span>
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 14 }}>
              {dpdp.requirement}
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {dpdp.checklist?.map((item, idx) => (
                <div key={idx} style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '8px 12px',
                  background: item.pass ? 'rgba(126, 143, 129, 0.08)' : 'rgba(201, 114, 114, 0.06)',
                  border: item.pass ? '1px solid rgba(126, 143, 129, 0.2)' : '1px solid rgba(201, 114, 114, 0.15)',
                  borderRadius: 6,
                  fontSize: 12
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    {item.pass ? <CheckCircle size={15} color="var(--accent-green)" /> : <AlertCircle size={15} color="var(--accent-red)" />}
                    <span style={{ color: item.pass ? 'var(--text-main)' : 'var(--accent-red)', fontWeight: 500 }}>{item.item}</span>
                  </div>
                  <span className="mono" style={{ color: item.pass ? 'var(--accent-green)' : 'var(--text-dim)', fontWeight: 600 }}>{item.coverage_pct == null ? 'Unknown' : `${item.coverage_pct}%`}</span>
                </div>
              ))}
            </div>
          </div>
        )}

      </div>

      {/* Control Assessment & Evidence Table */}
      <div className="glass-panel" style={{ padding: 22 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-main)' }}>
              {evalData?.framework_name} — Mapped Technical Controls & Audit Evidence
            </h3>
            <p style={{ margin: '4px 0 0 0', fontSize: 12, color: 'var(--text-dim)' }}>
              Showing {evalData?.controls?.length || 0} catalog controls mapped to {evalData?.framework_name}; evidence and review status are shown individually.
            </p>
          </div>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            <span className="badge badge-real" style={{ fontSize: 11 }}>
              {evalData?.mapping_coverage_pct}% Framework Clause Coverage
            </span>
            <span className="badge badge-simulated" style={{ fontSize: 11 }}>
              {evalData?.gaps_count} Gaps Flagged
            </span>
          </div>
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
                      {c.coverage_pct != null && c.evidence_ref !== 'Not Connected' ? (
                        <>
                          <div style={{ width: 60, height: 6, background: 'rgba(255,255,255,0.08)', borderRadius: 3, overflow: 'hidden' }}>
                            <div style={{
                              width: `${c.coverage_pct}%`,
                              height: '100%',
                              background: c.coverage_pct >= 75 ? 'var(--accent-green)' : (c.coverage_pct >= 50 ? 'var(--accent-amber)' : 'var(--accent-red)')
                            }} />
                          </div>
                          <span className="mono" style={{ fontSize: 11 }}>{c.coverage_pct}%</span>
                        </>
                      ) : (
                        <span style={{ fontSize: 11, color: 'var(--text-dim)', fontWeight: 600 }}>Not Connected</span>
                      )}
                    </div>
                  </td>
                  <td>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                      {c.evidence_ref}
                    </div>
                    {c.evidence_ref === 'Not Connected' || c.coverage_pct == null ? (
                      <span className="badge" style={{ fontSize: 9, background: 'rgba(255,255,255,0.06)', color: 'var(--text-dim)' }}>NOT CONNECTED</span>
                    ) : c.is_simulated || c.evidence_ref?.toLowerCase().includes('mock') ? (
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
          <strong>Citation & Legal Authority:</strong> {evalData?.citation}. {evalData?.disclaimer}
        </div>
      </div>

      {/* Unmapped Regulatory Clauses / Governance Scope Transparency */}
      {evalData?.unmapped_requirements?.length > 0 && (
        <div className="glass-panel" style={{ padding: 22, borderLeft: '4px solid var(--accent-amber)' }}>
          <div 
            style={{ 
              display: 'flex', 
              justifyContent: 'space-between', 
              alignItems: 'center', 
              cursor: 'pointer',
              userSelect: 'none'
            }}
            onClick={() => setShowUnmapped(!showUnmapped)}
          >
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <ShieldAlert size={18} color="var(--accent-amber)" />
                <h3 style={{ margin: 0, fontSize: 15, color: 'var(--text-main)' }}>
                  Unmapped Regulatory Clauses & Out-of-Scope Governance ({evalData.unmapped_requirements.length} Requirements)
                </h3>
              </div>
              <p style={{ margin: '4px 0 0 0', fontSize: 12, color: 'var(--text-dim)' }}>
                CRISP exclusively reports automated compliance for controls measurable by technical telemetry. Clauses below require human policy review.
              </p>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span className="badge" style={{ background: 'rgba(245, 158, 11, 0.15)', color: 'var(--accent-amber)', border: '1px solid rgba(245, 158, 11, 0.3)' }}>
                Honest Audit Scope
              </span>
              {showUnmapped ? <ChevronUp size={18} color="var(--text-dim)" /> : <ChevronDown size={18} color="var(--text-dim)" />}
            </div>
          </div>

          {showUnmapped && (
            <div style={{ marginTop: 18 }}>
              <div style={{ 
                padding: '12px 16px', 
                background: 'rgba(255, 255, 255, 0.02)', 
                borderRadius: 8, 
                border: '1px solid rgba(255, 255, 255, 0.06)',
                marginBottom: 14,
                fontSize: 12,
                color: 'var(--text-muted)',
                lineHeight: 1.5
              }}>
                <strong style={{ color: 'var(--text-main)' }}>Methodology Note for SIH & Regulatory Audits:</strong> In accordance with regulatory standards (SEBI CSCRF, RBI Master Directions, ISO 27001), continuous automated systems cannot audit corporate board committee minutes, biometric data center turnstiles, or HR pre-employment background vetting. CRISP isolates these unmapped clauses to ensure zero false claims of 100% automated compliance.
              </div>

              <div style={{ overflowX: 'auto' }}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th style={{ width: '15%' }}>Clause Ref</th>
                      <th style={{ width: '15%' }}>Domain</th>
                      <th style={{ width: '30%' }}>Regulatory Requirement Title</th>
                      <th style={{ width: '40%' }}>Exemption Rationale (Out of Telemetry Scope)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {evalData.unmapped_requirements.map((req, idx) => (
                      <tr key={idx}>
                        <td>
                          <span className="mono" style={{ color: 'var(--accent-amber)', fontSize: 11, fontWeight: 600 }}>
                            {req.clause || req.id}
                          </span>
                        </td>
                        <td>
                          <span className="badge" style={{ fontSize: 10, background: 'rgba(255, 255, 255, 0.05)' }}>
                            {req.domain}
                          </span>
                        </td>
                        <td>
                          <strong style={{ fontSize: 12, color: 'var(--text-main)' }}>{req.title}</strong>
                        </td>
                        <td>
                          <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>
                            {req.unmapped_reason}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

    </div>
  );
}
