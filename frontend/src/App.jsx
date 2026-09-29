import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import ExecutiveView from './components/ExecutiveView';
import TechnicalDrilldown from './components/TechnicalDrilldown';
import OptimizerView from './components/OptimizerView';
import WhatIfSimulator from './components/WhatIfSimulator';
import ComplianceHub from './components/ComplianceHub';
import AIQueryCenter from './components/AIQueryCenter';
import DataIngestionHub from './components/DataIngestionHub';
import ConnectionsSettings from './components/ConnectionsSettings';
import LandingPage from './components/LandingPage';
import { api } from './services/api';
import { 
  BarChart3, Search, Target, Sparkles, FileCheck, Bot, AlertTriangle, ShieldCheck, Database, Radio
} from 'lucide-react';
import { formatINR } from './utils/formatters';

export default function App() {
  const [activeTab, setActiveTab] = useState('executive');
  const [summary, setSummary] = useState(null);
  const [curveData, setCurveData] = useState(null);
  const [tornadoData, setTornadoData] = useState(null);
  const [driversData, setDriversData] = useState(null);
  const [dataQuality, setDataQuality] = useState(null);
  const [loading, setLoading] = useState(true);
  const [injecting, setInjecting] = useState(false);
  const [toast, setToast] = useState(null);

  const loadData = async (forceRefresh = false) => {
    try {
      const [sum, crv, tor, drv, dq] = await Promise.all([
        api.getSummary(forceRefresh),
        api.getCurve(),
        api.getTornado(),
        api.getDrivers(),
        api.getDataQuality()
      ]);
      setSummary(sum);
      setCurveData(crv);
      setTornadoData(tor);
      setDriversData(drv);
      setDataQuality(dq);
    } catch (err) {
      console.error('Data loading error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleInjectEvent = async (cveId, assetId) => {
    setInjecting(true);
    try {
      const res = await api.injectEvent(cveId, assetId);
      setToast({
        type: 'alert',
        title: 'CISA KEV Zero-Day Ingested!',
        message: `Injected ${cveId} on ${assetId}. Exposure increased by ${formatINR(res.jump_amount)}! Recalculated under Run ID: ${res.run_id}`
      });
      await loadData(true);
    } catch (e) {
      console.error('Injection error:', e);
    } finally {
      setInjecting(false);
      setTimeout(() => setToast(null), 8000);
    }
  };

  const tabs = [
    { id: 'executive', label: 'Executive Overview', shortLabel: 'Dashboard', icon: BarChart3 },
    { id: 'drilldown', label: 'Technical Drill-Down', shortLabel: 'Drilldown', icon: Search },
    { id: 'optimizer', label: 'Investment Optimizer & Benchmark', shortLabel: 'Optimizer', icon: Target },
    { id: 'whatif', label: 'What-If Simulator', shortLabel: 'What-If', icon: Sparkles },
    { id: 'compliance', label: 'Compliance & India Regs', shortLabel: 'Compliance', icon: FileCheck },
    { id: 'ai', label: 'AI Decision Support', shortLabel: 'AI Copilot', icon: Bot },
    { id: 'ingestion', label: 'Data Ingestion & Telemetry', shortLabel: 'Ingestion', icon: Database },
    { id: 'connections', label: 'Connections (SIEM/IAM)', shortLabel: 'Connectors', icon: Radio }
  ];

  if (activeTab === 'home') {
    return <LandingPage onSignIn={() => setActiveTab('executive')} />;
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'row', backgroundColor: 'var(--bg-main)' }}>
      
      {/* Left Sidebar */}
      <Sidebar tabs={tabs} activeTab={activeTab} setActiveTab={setActiveTab} />
      
      {/* Right Content Area */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        
        {/* Top Navbar */}
      <Navbar 
        runId={summary?.run_id}
        assumptionsVer={summary?.assumptions_version}
        dataQuality={dataQuality}
        onInjectEvent={handleInjectEvent}
        injecting={injecting}
      />

      {/* Main Container */}
      <main style={{ maxWidth: 1400, width: '100%', margin: '0 auto', padding: '24px 24px 60px 24px', flex: 1 }}>
        
        {/* Toast Alert */}
        {toast && (
          <div style={{
            background: 'linear-gradient(90deg, rgba(239, 68, 68, 0.95) 0%, rgba(185, 28, 28, 0.95) 100%)',
            color: '#fff',
            padding: '14px 20px',
            borderRadius: 10,
            marginBottom: 20,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            boxShadow: '0 0 20px rgba(239, 68, 68, 0.5)',
            animation: 'fadeIn 0.3s ease-in-out'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <AlertTriangle size={22} color="#fff" />
              <div>
                <strong>{toast.title}</strong>
                <p style={{ margin: 0, fontSize: 13 }}>{toast.message}</p>
              </div>
            </div>
            <button 
              onClick={() => setToast(null)}
              style={{ background: 'transparent', border: 'none', color: '#fff', fontSize: 18, cursor: 'pointer' }}
            >
              ✕
            </button>
          </div>
        )}



        {/* Active Tab Screen */}
        {loading ? (
          <div className="glass-panel" style={{ padding: 60, textAlign: 'center' }}>
            <div style={{ fontSize: 18, color: '#00f2fe', marginBottom: 8 }}>Initializing CRISP Quantitative Risk Engine...</div>
            <p style={{ fontSize: 13, color: 'var(--text-dim)' }}>Vectorizing 10,000 trials & evaluating asset dependency graphs</p>
          </div>
        ) : (
          <>
            {activeTab === 'executive' && (
              <ExecutiveView summary={summary} curveData={curveData} tornadoData={tornadoData} onNavigateToIngestion={() => setActiveTab('ingestion')} />
            )}
            {activeTab === 'drilldown' && (
              <TechnicalDrilldown summary={summary} driversData={driversData} onNavigateToIngestion={() => setActiveTab('ingestion')} />
            )}
            {activeTab === 'optimizer' && (
              <OptimizerView baseEal={summary?.org?.eal} status={summary?.status} onNavigateToIngestion={() => setActiveTab('ingestion')} />
            )}
            {activeTab === 'whatif' && (
              <WhatIfSimulator baselineEal={summary?.org?.eal} baselineVar95={summary?.org?.var95} status={summary?.status} onNavigateToIngestion={() => setActiveTab('ingestion')} />
            )}
            {activeTab === 'compliance' && (
              <ComplianceHub status={summary?.status} onNavigateToIngestion={() => setActiveTab('ingestion')} />
            )}
            {activeTab === 'ai' && (
              <AIQueryCenter currentRunId={summary?.run_id} />
            )}
            {activeTab === 'ingestion' && (
              <DataIngestionHub onDataUpdated={() => loadData(true)} />
            )}
            {activeTab === 'connections' && (
              <ConnectionsSettings onConnectionChanged={() => loadData(true)} />
            )}
          </>
        )}

      </main>

      {/* Footer with Compliance Transparency Note */}
      <footer style={{
        borderTop: '1px solid var(--border-color)',
        padding: '16px 24px',
        background: '#040710',
        fontSize: 12,
        color: 'var(--text-dim)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 12
      }}>
        <div>
          <strong>CRISP v1.0.0</strong> — Continuous Cyber Risk Quantification & Investment Optimization Platform
        </div>
        <div style={{ display: 'flex', gap: 16 }}>
          <span>Organization: <strong>Apex FinCorp (Simulated NBFC)</strong></span>
          <span>Lab Telemetry: <strong>Real OpenVAS & Wazuh</strong></span>
          <span>Assumptions: <strong>v{summary?.assumptions_version || 4} (Traceable)</strong></span>
        </div>
      </footer>

      </div>
    </div>
  );
}
