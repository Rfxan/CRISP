import React, { useState, useEffect } from 'react';
import { Routes, Route, Navigate, useNavigate } from 'react-router-dom';
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
  BarChart3, Search, Target, Sparkles, FileCheck, Bot, AlertTriangle, AlertCircle, ShieldCheck, Database, Radio
} from 'lucide-react';
import { formatINR } from './utils/formatters';

export default function App() {
  const [activeTab, setActiveTab] = useState('executive');
  const navigate = useNavigate();
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
      if (forceRefresh) setLoading(true);
      const [sum, curve, tornado, drivers, dq] = await Promise.all([
        api.getRiskSummary(),
        api.getLossExceedance(),
        api.getSensitivityTornado(),
        api.getRiskDrivers(),
        api.getDataQuality()
      ]);
      setSummary(sum);
      setCurveData(curve);
      setTornadoData(tornado);
      setDriversData(drivers);
      setDataQuality(dq);
    } catch (e) {
      console.error("Failed to load initial data", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

  const handleInjectTelemetry = async () => {
    setInjecting(true);
    try {
      const res = await api.injectTelemetryAnomaly();
      showToast(
        `🚨 ${res.message || 'Telemetry spike injected!'} High volume + auth failure anomaly created for agent ${res.telemetry?.agent_id || 'wazuh-agent-01'}.`,
        'success'
      );
      await loadData();
    } catch (e) {
      console.error("Failed to inject telemetry", e);
      showToast('Failed to simulate telemetry anomaly. Check console.', 'error');
    } finally {
      setInjecting(false);
    }
  };

  const tabs = [
    { id: 'executive', label: 'Executive Dashboard', shortLabel: 'Overview', icon: BarChart3 },
    { id: 'drilldown', label: 'Technical Drilldown & Choke Points', shortLabel: 'Drilldown', icon: Search },
    { id: 'optimizer', label: 'Investment Optimizer & Benchmark', shortLabel: 'Optimizer', icon: Target },
    { id: 'whatif', label: 'What-If Simulator', shortLabel: 'What-If', icon: Sparkles },
    { id: 'compliance', label: 'Compliance & India Regs', shortLabel: 'Compliance', icon: FileCheck },
    { id: 'ai', label: 'AI Decision Support', shortLabel: 'AI Copilot', icon: Bot },
    { id: 'ingestion', label: 'Data Ingestion & Telemetry', shortLabel: 'Ingestion', icon: Database },
    { id: 'connections', label: 'Connections (SIEM/IAM)', shortLabel: 'Connectors', icon: Radio }
  ];

  const DashboardLayout = () => (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'row', backgroundColor: 'var(--bg-main)' }}>
      
      {/* Left Sidebar */}
      <Sidebar tabs={tabs} activeTab={activeTab} setActiveTab={setActiveTab} />
      
      {/* Right Content Area */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        
        {/* Top Navbar */}
      <Navbar 
        runId={summary?.run_id}
        assumptionsVer={summary?.assumptions_version}
        isSimulated={summary?.is_simulated}
        summary={summary}
        onRefreshData={() => loadData(true)}
        onInjectTelemetry={handleInjectTelemetry}
        injectingTelemetry={injecting}
      />

      {/* Main View Area */}
      <main style={{ flex: 1, padding: '32px', overflowY: 'auto' }}>
        
        {/* Toast Alert */}
        {toast && (
          <div style={{
            position: 'fixed',
            bottom: '24px',
            right: '24px',
            zIndex: 9999,
            backgroundColor: toast.type === 'error' ? 'var(--accent-red)' : 'var(--accent-emerald)',
            color: '#fff',
            padding: '12px 20px',
            borderRadius: '10px',
            boxShadow: '0 8px 24px rgba(0,0,0,0.25)',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            fontSize: '13px',
            fontWeight: 600,
            maxWidth: '480px',
            animation: 'fadeIn 0.2s ease-out'
          }}>
            {toast.type === 'error' ? <AlertCircle size={18} /> : <ShieldCheck size={18} />}
            <span>{toast.message}</span>
          </div>
        )}

        {/* Global Loading Spinner */}
        {loading ? (
          <div style={{ 
            height: '60vh', 
            display: 'flex', 
            flexDirection: 'column', 
            alignItems: 'center', 
            justifyContent: 'center',
            gap: '16px',
            color: 'var(--text-muted)'
          }}>
            <div className="spinner" style={{ 
              width: '40px', 
              height: '40px', 
              border: '3px solid var(--border-color)', 
              borderTopColor: 'var(--primary-color)',
              borderRadius: '50%',
              animation: 'spin 1s linear infinite'
            }} />
            <p style={{ fontSize: '14px', letterSpacing: '0.05em' }}>QUANTIFYING ENTERPRISE RISK EXPOSURE...</p>
          </div>
        ) : (
          <>
            {activeTab === 'executive' && (
              <ExecutiveView 
                summary={summary} 
                curveData={curveData} 
                tornadoData={tornadoData} 
                onNavigateToIngestion={() => setActiveTab('ingestion')} 
                onRefresh={() => loadData(true)} 
              />
            )}
            {activeTab === 'drilldown' && (
              <TechnicalDrilldown summary={summary} driversData={driversData} onNavigateToIngestion={() => setActiveTab('ingestion')} />
            )}
            {activeTab === 'optimizer' && (
              <OptimizerView />
            )}
            {activeTab === 'whatif' && (
              <WhatIfSimulator onSimulate={loadData} />
            )}
            {activeTab === 'compliance' && (
              <ComplianceHub />
            )}
            {activeTab === 'ai' && (
              <AIQueryCenter />
            )}
            {activeTab === 'ingestion' && (
              <DataIngestionHub onRefreshData={() => loadData(true)} />
            )}
            {activeTab === 'connections' && (
              <ConnectionsSettings />
            )}
          </>
        )}
      </main>

      {/* Global CSS for spinner animation */}
      <style>{`
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      `}</style>
      </div>
    </div>
  );

  return (
    <Routes>
      <Route path="/home" element={<LandingPage onSignIn={() => navigate('/dashboard')} />} />
      <Route path="/dashboard" element={<DashboardLayout />} />
      <Route path="*" element={<Navigate to="/home" replace />} />
    </Routes>
  );
}
