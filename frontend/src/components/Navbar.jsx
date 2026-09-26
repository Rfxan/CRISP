import React, { useState } from 'react';
import { ShieldAlert, Zap, Activity, Database, CheckCircle2, AlertTriangle } from 'lucide-react';

export default function Navbar({ runId, assumptionsVer, dataQuality, onInjectEvent, injecting }) {
  const [injectOpen, setInjectOpen] = useState(false);
  const [cveId, setCveId] = useState('CVE-2026-9999');
  const [assetId, setAssetId] = useState('AST-PAY-GW-01');

  const handleInject = () => {
    onInjectEvent(cveId, assetId);
    setInjectOpen(false);
  };

  return (
    <header style={{
      background: 'rgba(10, 15, 30, 0.92)',
      backdropFilter: 'blur(16px)',
      borderBottom: '1px solid var(--border-color)',
      position: 'sticky',
      top: 0,
      zIndex: 100,
      padding: '12px 24px'
    }}>
      <div style={{ maxWidth: 1400, margin: '0 auto', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16 }}>
        
        {/* Brand */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 40,
            height: 40,
            borderRadius: 10,
            background: 'linear-gradient(135deg, #00f2fe 0%, #4facfe 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 16px rgba(0, 242, 254, 0.4)'
          }}>
            <ShieldAlert size={22} color="#051026" strokeWidth={2.5} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span className="display-title" style={{ fontSize: 20, letterSpacing: '0.04em', color: '#fff' }}>CRISP</span>
              <span className="badge badge-cyan">SIH 26105</span>
              <span className="badge badge-simulated">Apex FinCorp (Simulated NBFC)</span>
            </div>
            <p style={{ fontSize: 11, color: 'var(--text-dim)', margin: 0, fontWeight: 500 }}>
              "Not a risk score. A budget decision, with the proof."
            </p>
          </div>
        </div>

        {/* Live Indicators & Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          
          {/* Run ID Citation */}
          <div className="glass-panel" style={{ padding: '6px 12px', display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
            <Activity size={14} color="#00f2fe" />
            <span style={{ color: 'var(--text-muted)' }}>Active Run:</span>
            <span className="mono" style={{ color: '#00f2fe', fontWeight: 600 }}>{runId || 'RUN-INIT'}</span>
            <span style={{ color: 'var(--text-dim)', fontSize: 10 }}>v{assumptionsVer || 4}</span>
          </div>

          {/* Data Quality */}
          <div className="glass-panel" style={{ padding: '6px 12px', display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
            <Database size={14} color="#10b981" />
            <span style={{ color: 'var(--text-muted)' }}>Data Quality:</span>
            <span className="mono" style={{ color: '#10b981', fontWeight: 600 }}>
              {dataQuality ? `${Math.round(dataQuality.data_quality_score * 100)}%` : '82%'}
            </span>
            <span className="badge badge-real" style={{ fontSize: 9 }}>
              {dataQuality?.real_vs_simulated_ratio?.real_percentage !== undefined
                ? `${dataQuality.real_vs_simulated_ratio.real_percentage}% Real Lab`
                : 'Real Lab'}
            </span>
          </div>

          {/* Live Demo Threat Injection Button */}
          <button 
            className="btn btn-danger"
            onClick={() => setInjectOpen(!injectOpen)}
            disabled={injecting}
            style={{ position: 'relative' }}
          >
            <Zap size={15} />
            <span>{injecting ? 'Injecting Threat...' : '⚡ Demo 0-Day Injection'}</span>
          </button>

        </div>
      </div>

      {/* Demo Event Injection Modal */}
      {injectOpen && (
        <div style={{
          position: 'fixed',
          top: 75,
          right: 24,
          width: 360,
          background: '#0d1527',
          border: '1px solid rgba(239, 68, 68, 0.4)',
          borderRadius: 12,
          padding: 18,
          boxShadow: '0 10px 30px rgba(0,0,0,0.8), 0 0 20px rgba(239, 68, 68, 0.25)',
          zIndex: 200
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <AlertTriangle size={18} color="#ef4444" />
            <h4 style={{ margin: 0, fontSize: 14, color: '#f8fafc' }}>Simulate CISA KEV Zero-Day Addition</h4>
          </div>
          <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 14, lineHeight: 1.4 }}>
            Demonstrates <strong>continuous risk recalibration</strong> (PRD Sec 19.1). Injects a new high-exploitability vulnerability onto a critical asset and watches financial exposure spike in real time.
          </p>

          <div style={{ marginBottom: 10 }}>
            <label style={{ fontSize: 11, color: 'var(--text-dim)', display: 'block', marginBottom: 4 }}>Vulnerability CVE</label>
            <input 
              type="text" 
              value={cveId} 
              onChange={(e) => setCveId(e.target.value)}
              style={{
                width: '100%',
                background: '#070a12',
                border: '1px solid var(--border-color)',
                borderRadius: 6,
                padding: '6px 10px',
                color: '#fff',
                fontSize: 12,
                fontFamily: 'var(--font-mono)'
              }}
            />
          </div>

          <div style={{ marginBottom: 14 }}>
            <label style={{ fontSize: 11, color: 'var(--text-dim)', display: 'block', marginBottom: 4 }}>Target Asset</label>
            <select 
              value={assetId} 
              onChange={(e) => setAssetId(e.target.value)}
              style={{
                width: '100%',
                background: '#070a12',
                border: '1px solid var(--border-color)',
                borderRadius: 6,
                padding: '6px 10px',
                color: '#fff',
                fontSize: 12
              }}
            >
              <option value="AST-PAY-GW-01">pay-gateway-ingress (Payment Switch Edge)</option>
              <option value="AST-PAY-DB-01">pay-db-primary (PostgreSQL Crown Jewel)</option>
              <option value="AST-CORE-DB-01">cbs-db-oracle-01 (Core Banking Engine)</option>
              <option value="AST-NETBANK-APP-01">netbank-k8s-ingress (Retail Banking Ingress)</option>
            </select>
          </div>

          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-danger" style={{ flex: 1 }} onClick={handleInject}>
              Trigger KEV Ingestion
            </button>
            <button className="btn btn-outline" onClick={() => setInjectOpen(false)}>
              Cancel
            </button>
          </div>
        </div>
      )}
    </header>
  );
}
