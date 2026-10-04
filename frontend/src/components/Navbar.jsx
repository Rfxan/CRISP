import React from 'react';
import { ShieldAlert, Activity, Database } from 'lucide-react';

export default function Navbar({ runId, assumptionsVer, organization, dataQuality }) {
  return (
    <header style={{
      background: 'rgba(243, 240, 233, 0.85)',
      backdropFilter: 'blur(20px)',
      borderBottom: '1px solid var(--border-color)',
      position: 'sticky',
      top: 0,
      zIndex: 100,
      padding: '12px 24px',
      boxShadow: '0 4px 12px rgba(190, 185, 175, 0.2)'
    }}>
      <div style={{ maxWidth: 1400, margin: '0 auto', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16 }}>
        
        {/* Brand */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 40,
            height: 40,
            borderRadius: 12,
            background: 'linear-gradient(135deg, var(--primary) 0%, var(--accent-green) 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '4px 4px 8px rgba(190, 185, 175, 0.4), -4px -4px 8px rgba(255, 255, 255, 0.8)'
          }}>
            <ShieldAlert size={22} color="var(--text-main)" strokeWidth={2.5} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span className="display-title" style={{ fontSize: 20, letterSpacing: '0.04em', color: 'var(--text-main)' }}>CRISP</span>
              <span className="badge badge-cyan">SIH 26105</span>
              <span className="badge badge-simulated">{organization || 'Organization not configured'}</span>
            </div>
            <p style={{ fontSize: 11, color: 'var(--text-dim)', margin: 0, fontWeight: 500 }}>
              "Not a risk score. A budget decision, with the proof."
            </p>
          </div>
        </div>

        {/* Live Indicators */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          
          {/* Run ID Citation */}
          <div className="glass-panel" style={{ padding: '6px 12px', display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, borderRadius: 8 }}>
            <Activity size={14} color="var(--primary)" />
            <span style={{ color: 'var(--text-muted)' }}>Active Run:</span>
            <span className="mono" style={{ color: 'var(--primary)', fontWeight: 700 }}>{runId || 'RUN-INIT'}</span>
            <span style={{ color: 'var(--text-dim)', fontSize: 10 }}>v{assumptionsVer || 4}</span>
          </div>

          {/* Data Quality */}
          <div className="glass-panel" style={{ padding: '6px 12px', display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, borderRadius: 8 }}>
            <Database size={14} color="var(--accent-green)" />
            <span style={{ color: 'var(--text-muted)' }}>Data Quality:</span>
            <span className="mono" style={{ color: 'var(--accent-green)', fontWeight: 700 }}>
              {dataQuality ? `${Math.round(dataQuality.data_quality_score * 100)}%` : '—'}
            </span>
            <span className="badge badge-real" style={{ fontSize: 9 }}>
              {dataQuality?.asset_origins?.synthetic ? 'Includes synthetic data' : 'Uploaded / declared data'}
            </span>
          </div>

        </div>
      </div>
    </header>
  );
}
