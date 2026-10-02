import React from 'react';
import { useAccess } from '../AccessContext';
import { Database, ArrowRight, ShieldAlert, Sparkles, Layers } from 'lucide-react';

export default function EmptyState({ 
  status = 'NO_DATA', 
  title = 'No Risk Data Available Yet',
  message, 
  onNavigateToIngestion 
}) {
  const { canEdit } = useAccess();
  const isNoFindings = status === 'NO_FINDINGS';

  const defaultMsg = isNoFindings
    ? "Assets are loaded, but no vulnerability findings have been ingested yet. Upload a scan report (OpenVAS, Nessus, or custom vendor) to compute quantitative risk."
    : "No risk data yet. Upload your asset inventory and a vulnerability scan to see your organization's risk profile.";

  return (
    <div className="glass-panel" style={{
      padding: '48px 32px',
      textAlign: 'center',
      border: '1px dashed rgba(183, 140, 102, 0.3)',
      background: 'var(--bg-card)',
      backdropFilter: 'blur(12px)',
      borderRadius: 16,
      maxWidth: 720,
      margin: '40px auto',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      gap: 18
    }}>
      <div style={{
        width: 64,
        height: 64,
        borderRadius: '50%',
        background: isNoFindings ? 'rgba(209, 184, 121, 0.1)' : 'rgba(183, 140, 102, 0.1)',
        border: `1px solid ${isNoFindings ? 'rgba(209, 184, 121, 0.4)' : 'rgba(183, 140, 102, 0.4)'}`,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        color: isNoFindings ? 'var(--accent-amber)' : 'var(--primary)'
      }}>
        {isNoFindings ? <ShieldAlert size={30} /> : <Database size={30} />}
      </div>

      <div>
        <div className="badge badge-cyan" style={{ marginBottom: 10, fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          {isNoFindings ? 'Step 2 Required: Vulnerability Scan' : 'System Initialized — Empty State'}
        </div>
        <h2 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-main)', margin: '0 0 8px 0' }}>
          {title}
        </h2>
        <p style={{ fontSize: 14, color: 'var(--text-muted)', lineHeight: 1.6, maxWidth: 540, margin: 0 }}>
          {!canEdit ? 'No published demo data is available yet. Only the site owner can prepare the demo dataset.' : message || defaultMsg}
        </p>
      </div>

      {canEdit && onNavigateToIngestion && (
        <button
          onClick={onNavigateToIngestion}
          className="btn btn-primary"
          style={{
            marginTop: 8,
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            padding: '12px 24px',
            fontSize: 14,
            fontWeight: 600,
            borderRadius: 8,
            cursor: 'pointer'
          }}
        >
          <span>Go to Data Ingestion</span>
          <ArrowRight size={16} />
        </button>
      )}
    </div>
  );
}
