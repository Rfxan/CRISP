import React, { useState } from 'react';

export default function GovernanceEvidence({ controls = [], onSaved }) {
  const [message, setMessage] = useState('');
  const submit = async (event, kind) => {
    event.preventDefault();
    const values = Object.fromEntries(new FormData(event.currentTarget));
    const target = values.target; delete values.target;
    if (kind === 'exercises') {
      for (const field of ['incident_at', 'detected_at', 'escalated_at', 'reported_at']) values[field] = new Date(values[field]).toISOString();
    }
    try {
      const response = await fetch(`/api/governance/${kind}${target ? `/${encodeURIComponent(target)}` : ''}`, {
        method: kind === 'exercises' ? 'POST' : 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(values)
      });
      const result = await response.json();
      if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : 'Check the submitted evidence.');
      setMessage('Evidence saved.'); onSaved();
    } catch (e) { setMessage(e.message); }
  };
  return <details className="glass-panel" style={{ padding: 20 }}>
    <summary>Record compliance review and reporting exercises</summary>
    <p>A review is valid only while its underlying evidence remains current and unchanged.</p>
    <form onSubmit={e => submit(e, 'reviews')} style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
      <select name="target" aria-label="Control to review" required>{controls.map(c => <option key={c.control_id} value={c.control_id}>{c.control_id} — {c.name}</option>)}</select>
      <select name="decision" aria-label="Reviewer decision"><option value="not_assessed">Not assessed</option><option value="compliant">Compliant</option><option value="partial">Partial</option><option value="non_compliant">Non-compliant</option></select>
      <select name="applicability" aria-label="Applicability"><option value="applicable">Applicable</option><option value="not_applicable">Not applicable</option><option value="not_reviewed">Not reviewed</option></select>
      <input name="notes" aria-label="Review notes" placeholder="Review notes" />
      <button className="btn-primary">Save review</button>
    </form>
    <h4>Measured reporting exercise</h4>
    <form onSubmit={e => submit(e, 'exercises')} style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
      <input name="id" aria-label="Exercise ID" placeholder="Exercise ID" required />
      {['incident_at', 'detected_at', 'escalated_at', 'reported_at'].map(name => <label key={name}>{name.replace('_at', '')}<input name={name} type="datetime-local" required /></label>)}
      <input name="evidence_ref" aria-label="Exercise evidence reference" placeholder="Evidence reference" required />
      <button className="btn-primary">Save exercise</button>
    </form>
    {message && <p role="status">{message}</p>}
  </details>;
}
