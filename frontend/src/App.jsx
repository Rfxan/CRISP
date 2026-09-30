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
  BarChart3, Search, Target, Sparkles, FileCheck, Bot, AlertTriangle, AlertCircle, ShieldCheck, Database, Radio, RefreshCw
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
  const [loadError, setLoadError] = useState(null);
  const [failingEndpoints, setFailingEndpoints] = useState([]);
  const [toast, setToast] = useState(null);

  const loadData = async (forceRefresh = false) => {
    if (forceRefresh) setLoading(true);
    try {
      const results = await Promise.allSettled([
        api.getSummary(forceRefresh),
        api.getCurve(),
        api.getTornado(),
        api.getDrivers(),
        api.getDataQuality()
      ]);

      const [summaryRes, curveRes, tornadoRes, driversRes, dqRes] = results;
      const failed = [];

      if (summaryRes.status === 'fulfilled') {
        setSummary(summaryRes.value);
        setLoadError(null);
      } else {
        const errMsg = summaryRes.reason?.message || 'Failed to fetch risk summary';
        console.error("Failed to load risk summary:", summaryRes.reason);
        failed.push(`Risk Summary (/api/risk/summary: ${errMsg})`);
        setLoadError(errMsg);
      }

      if (curveRes.status === 'fulfilled') {
        setCurveData(curveRes.value);
      } else {
        const errMsg = curveRes.reason?.message || 'Failed to fetch loss exceedance curve';
        console.error("Failed to load loss exceedance curve:", curveRes.reason);
        failed.push(`Loss Exceedance (/api/risk/curve: ${errMsg})`);
      }

      if (tornadoRes.status === 'fulfilled') {
        setTornadoData(tornadoRes.value);
      } else {
        const errMsg = tornadoRes.reason?.message || 'Failed to fetch tornado sensitivity';
        console.error("Failed to load tornado sensitivity:", tornadoRes.reason);
        failed.push(`Sensitivity Tornado (/api/sensitivity/tornado: ${errMsg})`);
      }

      if (driversRes.status === 'fulfilled') {
        setDriversData(driversRes.value);
      } else {
        const errMsg = driversRes.reason?.message || 'Failed to fetch risk drivers';
        console.error("Failed to load risk drivers:", driversRes.reason);
        failed.push(`Risk Drivers (/api/risk/drivers: ${errMsg})`);
      }

      if (dqRes.status === 'fulfilled') {
        setDataQuality(dqRes.value);
      } else {
        const errMsg = dqRes.reason?.message || 'Failed to fetch data quality metrics';
        console.error("Failed to load data quality:", dqRes.reason);
        failed.push(`Data Quality (/api/health/data-quality: ${errMsg})`);
      }

      setFailingEndpoints(failed);
    } catch (e) {
      console.error("Unexpected error in loadData", e);
      setLoadError(e.message || 'Unexpected failure loading dashboard');
      setFailingEndpoints([`General: ${e.message || 'Failed'}`]);
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

  const tabs = [
    { id: 'executive', label: 'Executive Dashboard', shortLabel: 'Overview', icon: BarChart3 },
    { id: 'ingestion', label: 'Data Ingestion & Telemetry', shortLabel: 'Ingestion', icon: Database },
    { id: 'connections', label: 'Connections (SIEM/IAM)', shortLabel: 'Connectors', icon: Radio },
    { id: 'drilldown', label: 'Technical Drilldown & Choke Points', shortLabel: 'Drilldown', icon: Search },
    { id: 'optimizer', label: 'Investment Optimizer & Benchmark', shortLabel: 'Optimizer', icon: Target },
    { id: 'whatif', label: 'What-If Simulator', shortLabel: 'What-If', icon: Sparkles },
    { id: 'compliance', label: 'Compliance & India Regs', shortLabel: 'Compliance', icon: FileCheck },
    { id: 'ai', label: 'AI Decision Support', shortLabel: 'AI Copilot', icon: Bot }
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
        dataQuality={dataQuality}
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

        {/* API Endpoint Degradation / Failure Warning Banner */}
        {failingEndpoints.length > 0 && (
          <div 
            id="endpoint-error-banner"
            style={{
              marginBottom: 20,
              padding: '14px 18px',
              borderRadius: 10,
              backgroundColor: 'rgba(239, 68, 68, 0.12)',
              border: '1px solid rgba(239, 68, 68, 0.35)',
              display: 'flex',
              alignItems: 'flex-start',
              justifyContent: 'space-between',
              gap: 14
            }}
          >
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
              <AlertCircle size={18} color="var(--accent-red)" style={{ marginTop: 2, flexShrink: 0 }} />
              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--accent-red)' }}>
                  API Sync Degraded — {failingEndpoints.length} endpoint{failingEndpoints.length > 1 ? 's' : ''} failed to load:
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4, lineHeight: 1.4 }}>
                  {failingEndpoints.map((ep, idx) => (
                    <div key={idx}>• {ep}</div>
                  ))}
                </div>
              </div>
            </div>
            <button
              onClick={() => loadData(true)}
              className="btn btn-secondary"
              style={{ padding: '6px 12px', fontSize: 11, display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}
            >
              <RefreshCw size={12} /> Retry All
            </button>
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
                driversData={driversData}
                loadError={loadError}
                onRetry={() => loadData(true)}
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
