import React, { useState } from 'react';
import { ClipboardCheck, ChevronDown, Save, Clock, Info, CheckCircle2, AlertCircle } from 'lucide-react';
import './GovernanceEvidence.css';

export default function GovernanceEvidence({ controls = [], onSaved }) {
  const [message, setMessage] = useState('');
  const [messageKind, setMessageKind] = useState('success');
  const [saving, setSaving] = useState(null);
  const submit = async (event, kind) => {
    event.preventDefault();
    const values = Object.fromEntries(new FormData(event.currentTarget));
    const target = values.target; delete values.target;
    setSaving(kind); setMessage('');
    try {
      if (kind === 'exercises') {
        for (const field of ['incident_at', 'detected_at', 'escalated_at', 'reported_at']) values[field] = new Date(values[field]).toISOString();
      }
      const response = await fetch(`/api/governance/${kind}${target ? `/${encodeURIComponent(target)}` : ''}`, {
        method: kind === 'exercises' ? 'POST' : 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(values)
      });
      const result = await response.json();
      if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : 'Check the submitted evidence.');
      setMessage(kind === 'reviews' ? 'Compliance review saved.' : 'Reporting exercise saved.'); setMessageKind('success'); onSaved?.();
    } catch (e) { setMessage(e.message); setMessageKind('error'); }
    finally { setSaving(null); }
  };
  return <details className="glass-panel governance-evidence">
    <summary className="governance-heading"><span className="governance-icon"><ClipboardCheck size={22} /></span>
      <span className="governance-title"><strong>Record compliance review and reporting exercises</strong><span>Save reviewer decisions and measured incident-reporting evidence.</span></span><ChevronDown size={18} className="governance-chevron" /></summary>
    <div className="governance-body">
      <div className="governance-note"><Info size={17} /><p>A review is valid only while its underlying evidence remains current and unchanged.</p></div>
      <section className="governance-section" aria-labelledby="control-review-heading">
        <h4 id="control-review-heading"><ClipboardCheck size={18} />Control compliance review</h4>
        <p>Choose a control, record its applicability and add the reviewer’s decision.</p>
        <form onSubmit={e => submit(e, 'reviews')} className="governance-form governance-review-form">
          <label className="governance-wide">Control to review<select name="target" required disabled={!controls.length}>{controls.length ? controls.map(c => <option key={c.control_id} value={c.control_id}>{c.control_id} — {c.name}</option>) : <option value="">No controls available</option>}</select></label>
          <label>Reviewer decision<select name="decision"><option value="not_assessed">Not assessed</option><option value="compliant">Compliant</option><option value="partial">Partial</option><option value="non_compliant">Non-compliant</option></select></label>
          <label>Applicability<select name="applicability"><option value="applicable">Applicable</option><option value="not_applicable">Not applicable</option><option value="not_reviewed">Not reviewed</option></select></label>
          <label className="governance-wide">Review notes<textarea name="notes" placeholder="Explain the decision and any evidence gaps…" rows={3} /></label>
          <div className="governance-form-footer"><span>Decisions are linked to the current control evidence.</span><button type="submit" className="btn btn-primary" disabled={saving === 'reviews' || !controls.length}><Save size={16} />{saving === 'reviews' ? 'Saving review…' : 'Save review'}</button></div>
        </form>
      </section>
      <section className="governance-section" aria-labelledby="reporting-exercise-heading">
        <h4 id="reporting-exercise-heading"><Clock size={18} />Measured reporting exercise</h4>
        <p>Record actual exercise timestamps to assess detection, escalation and reporting readiness. Times use your browser’s local timezone.</p>
        <form onSubmit={e => submit(e, 'exercises')} className="governance-form governance-exercise-form">
          <label>Exercise ID<input name="id" placeholder="Enter an exercise identifier" required /></label>
          <label>Evidence reference<input name="evidence_ref" placeholder="Document, ticket or exercise report" required /></label>
          {[['incident_at', 'Incident occurred'], ['detected_at', 'Incident detected'], ['escalated_at', 'Incident escalated'], ['reported_at', 'Incident reported']].map(([name, label]) => <label key={name}>{label}<input name={name} type="datetime-local" required /></label>)}
          <div className="governance-form-footer"><span>Use measured times from a completed reporting exercise.</span><button type="submit" className="btn btn-primary" disabled={saving === 'exercises'}><Save size={16} />{saving === 'exercises' ? 'Saving exercise…' : 'Save exercise'}</button></div>
        </form>
      </section>
      {message && <div className={`governance-message governance-message-${messageKind}`} role={messageKind === 'error' ? 'alert' : 'status'}>{messageKind === 'error' ? <AlertCircle size={18} /> : <CheckCircle2 size={18} />}<span>{message}</span></div>}
    </div>
  </details>;
}
