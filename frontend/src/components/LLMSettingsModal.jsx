import React, { useState, useEffect } from 'react';
import { 
  X, Cpu, Key, Globe, CheckCircle2, AlertCircle, Eye, EyeOff, 
  Sparkles, RefreshCw, Zap, Sliders, Shield
} from 'lucide-react';
import { api } from '../services/api';

const PROVIDER_OPTIONS = [
  { 
    id: 'gemini', 
    name: 'Google Gemini', 
    desc: 'Fast, high-quality, generous free tier',
    defaultModel: 'gemini-1.5-flash',
    models: ['gemini-1.5-flash', 'gemini-2.0-flash', 'gemini-1.5-pro']
  },
  { 
    id: 'openai', 
    name: 'OpenAI', 
    desc: 'Industry standard reasoning & tool execution',
    defaultModel: 'gpt-4o-mini',
    models: ['gpt-4o-mini', 'gpt-4o', 'gpt-3.5-turbo']
  },
  { 
    id: 'groq', 
    name: 'Groq (Ultra-Fast Llama 3)', 
    desc: 'Sub-second LPUs for Llama-3.3-70B, free tier',
    defaultModel: 'llama-3.3-70b-versatile',
    models: ['llama-3.3-70b-versatile', 'llama-3.1-8b-instant', 'mixtral-8x7b-32768']
  },
  { 
    id: 'anthropic', 
    name: 'Anthropic Claude', 
    desc: 'Nuanced financial reasoning & safety',
    defaultModel: 'claude-3-5-sonnet-20241022',
    models: ['claude-3-5-sonnet-20241022', 'claude-3-haiku-20240307']
  },
  { 
    id: 'ollama', 
    name: 'Local Ollama (100% Free / Offline)', 
    desc: 'Runs on localhost:11434 with zero API keys',
    defaultModel: 'llama3.2',
    models: ['llama3.2', 'mistral', 'deepseek-r1', 'phi3']
  },
  { 
    id: 'custom', 
    name: 'Custom OpenAI-Compatible Endpoint', 
    desc: 'Self-hosted vLLM, LM Studio, or OpenRouter',
    defaultModel: 'custom-model',
    models: []
  }
];

export default function LLMSettingsModal({ isOpen, onClose, onConfigSaved }) {
  const [config, setConfig] = useState(null);
  const [provider, setProvider] = useState('gemini');
  const [model, setModel] = useState('gemini-1.5-flash');
  const [apiKey, setApiKey] = useState('');
  const [baseUrl, setBaseUrl] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [statusMsg, setStatusMsg] = useState(null);

  useEffect(() => {
    if (isOpen) {
      loadConfig();
    }
  }, [isOpen]);

  const loadConfig = async () => {
    try {
      const data = await api.getAIConfig();
      setConfig(data);
      setProvider(data.provider || 'gemini');
      setModel(data.model || 'gemini-1.5-flash');
      setBaseUrl(data.base_url || '');
      setApiKey(data.masked_api_key || '');
      setTestResult(null);
      setStatusMsg(null);
    } catch (err) {
      console.error('Failed to load LLM config:', err);
    }
  };

  if (!isOpen) return null;

  const currentProviderOpt = PROVIDER_OPTIONS.find(p => p.id === provider) || PROVIDER_OPTIONS[0];

  const handleProviderSelect = (pId) => {
    setProvider(pId);
    const pOpt = PROVIDER_OPTIONS.find(p => p.id === pId);
    if (pOpt) {
      setModel(pOpt.defaultModel);
    }
    setTestResult(null);
  };

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await api.testAIConnection({
        provider,
        model,
        api_key: apiKey,
        base_url: baseUrl
      });
      setTestResult(res);
    } catch (err) {
      setTestResult({
        connected: false,
        error: err.message || 'Connection test failed'
      });
    } finally {
      setTesting(false);
    }
  };

  const handleSave = async (e) => {
    e.preventDefault();
    setSaving(true);
    setStatusMsg(null);
    try {
      const updated = await api.saveAIConfig({
        provider,
        model,
        api_key: apiKey,
        base_url: baseUrl,
        enabled: true
      });
      setStatusMsg({ type: 'success', text: `AI configuration saved! Model set to ${provider.toUpperCase()} (${model}).` });
      if (onConfigSaved) onConfigSaved(updated);
      setTimeout(() => {
        onClose();
      }, 900);
    } catch (err) {
      setStatusMsg({ type: 'error', text: err.message || 'Failed to save configuration' });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(5, 10, 20, 0.85)',
      backdropFilter: 'blur(8px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1100,
      padding: 16
    }}>
      <div 
        className="glass-panel"
        style={{
          width: '100%',
          maxWidth: 680,
          maxHeight: '92vh',
          overflowY: 'auto',
          backgroundColor: '#0c1322',
          border: '1px solid rgba(0, 242, 254, 0.3)',
          borderRadius: 16,
          boxShadow: '0 20px 50px rgba(0, 0, 0, 0.8), 0 0 30px rgba(0, 242, 254, 0.15)',
          padding: 24,
          position: 'relative'
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{
              width: 44,
              height: 44,
              borderRadius: 12,
              background: 'linear-gradient(135deg, rgba(0, 242, 254, 0.2) 0%, rgba(139, 92, 246, 0.2) 100%)',
              border: '1px solid rgba(0, 242, 254, 0.4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              <Sparkles size={24} color="#00f2fe" />
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: 18, color: '#fff', fontWeight: 700 }}>
                CRISP Multi-Provider LLM Configuration
              </h3>
              <p style={{ margin: '3px 0 0 0', fontSize: 12, color: 'var(--text-dim)' }}>
                Connect an actual LLM model to power executive conversational reasoning over audited FAIR metrics.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-dim)',
              cursor: 'pointer',
              padding: 6,
              borderRadius: 6
            }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Status Alerts */}
        {statusMsg && (
          <div style={{
            marginBottom: 16,
            padding: '10px 14px',
            borderRadius: 8,
            fontSize: 12,
            background: statusMsg.type === 'success' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
            border: `1px solid ${statusMsg.type === 'success' ? '#10b981' : '#ef4444'}`,
            color: '#fff',
            display: 'flex',
            alignItems: 'center',
            gap: 10
          }}>
            {statusMsg.type === 'success' ? <CheckCircle2 size={16} color="#10b981" /> : <AlertCircle size={16} color="#ef4444" />}
            <span>{statusMsg.text}</span>
          </div>
        )}

        <form onSubmit={handleSave} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          {/* 1. Select Provider */}
          <div>
            <label style={{ display: 'block', fontSize: 12, fontWeight: 700, color: '#fff', marginBottom: 8 }}>
              1. Choose LLM Provider
            </label>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 10 }}>
              {PROVIDER_OPTIONS.map(p => {
                const isSelected = provider === p.id;
                return (
                  <div
                    key={p.id}
                    onClick={() => handleProviderSelect(p.id)}
                    style={{
                      padding: '12px 14px',
                      borderRadius: 10,
                      background: isSelected ? 'rgba(0, 242, 254, 0.12)' : 'rgba(255, 255, 255, 0.02)',
                      border: isSelected ? '1.5px solid #00f2fe' : '1px solid var(--border-color)',
                      cursor: 'pointer',
                      transition: 'all 0.2s ease'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                      <strong style={{ fontSize: 13, color: isSelected ? '#00f2fe' : '#fff' }}>
                        {p.name}
                      </strong>
                      {isSelected && <CheckCircle2 size={14} color="#00f2fe" />}
                    </div>
                    <p style={{ margin: 0, fontSize: 11, color: 'var(--text-dim)', lineHeight: 1.3 }}>
                      {p.desc}
                    </p>
                  </div>
                );
              })}
            </div>
          </div>

          {/* 2. Model Selection & Base URL */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <div>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#fff', marginBottom: 6 }}>
                Model Identifier
              </label>
              {currentProviderOpt.models.length > 0 ? (
                <div style={{ display: 'flex', gap: 8 }}>
                  <select
                    value={model}
                    onChange={(e) => setModel(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '9px 12px',
                      borderRadius: 8,
                      background: '#090e1a',
                      border: '1px solid var(--border-color)',
                      color: '#fff',
                      fontSize: 13,
                      fontFamily: 'monospace'
                    }}
                  >
                    {currentProviderOpt.models.map(m => (
                      <option key={m} value={m}>{m}</option>
                    ))}
                  </select>
                </div>
              ) : (
                <input
                  type="text"
                  placeholder="e.g. meta-llama/Llama-3-70b-chat"
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '9px 12px',
                    borderRadius: 8,
                    background: '#090e1a',
                    border: '1px solid var(--border-color)',
                    color: '#fff',
                    fontSize: 13,
                    fontFamily: 'monospace'
                  }}
                  required
                />
              )}
            </div>

            <div>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#fff', marginBottom: 6 }}>
                Custom Base URL {provider === 'ollama' ? '(Default: http://localhost:11434/v1)' : '(Optional)'}
              </label>
              <input
                type="text"
                placeholder={provider === 'ollama' ? 'http://localhost:11434/v1' : 'https://api.example.com/v1'}
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                style={{
                  width: '100%',
                  padding: '9px 12px',
                  borderRadius: 8,
                  background: '#090e1a',
                  border: '1px solid var(--border-color)',
                  color: '#fff',
                  fontSize: 13,
                  fontFamily: 'monospace'
                }}
              />
            </div>
          </div>

          {/* 3. API Key */}
          {provider !== 'ollama' && (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <label style={{ fontSize: 12, fontWeight: 600, color: '#fff' }}>
                  {currentProviderOpt.name} API Key
                </label>
                <span className="badge badge-cyan" style={{ fontSize: 9 }}>
                  <Shield size={10} style={{ marginRight: 4 }} /> Fernet AES-256 Encrypted
                </span>
              </div>
              <div style={{ position: 'relative' }}>
                <input
                  type={showKey ? 'text' : 'password'}
                  placeholder={config?.has_api_key ? '•••••••• (Encrypted key saved - leave blank or paste to replace)' : 'Paste API Key (e.g. AIzaSy... or sk-...)'}
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '10px 42px 10px 14px',
                    borderRadius: 8,
                    background: '#090e1a',
                    border: '1px solid var(--border-color)',
                    color: '#fff',
                    fontFamily: 'monospace',
                    fontSize: 13
                  }}
                />
                <button
                  type="button"
                  onClick={() => setShowKey(!showKey)}
                  style={{
                    position: 'absolute',
                    right: 10,
                    top: '50%',
                    transform: 'translateY(-50%)',
                    background: 'transparent',
                    border: 'none',
                    color: 'var(--text-dim)',
                    cursor: 'pointer',
                    padding: 4
                  }}
                >
                  {showKey ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
              <span style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 4, display: 'block' }}>
                Saved locally to <code>backend/data/llm_config.json</code> with symmetric encryption.
              </span>
            </div>
          )}

          {/* Test Probe Result Box */}
          {testResult && (
            <div style={{
              padding: '10px 14px',
              borderRadius: 8,
              fontSize: 12,
              background: testResult.connected ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
              border: `1px solid ${testResult.connected ? '#10b981' : '#ef4444'}`,
              color: testResult.connected ? '#34d399' : '#f87171'
            }}>
              <strong>{testResult.connected ? '✓ Connection Verified:' : '✗ Connection Failed:'}</strong>{' '}
              {testResult.detail || testResult.error}
            </div>
          )}

          {/* Footer Actions */}
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            paddingTop: 16,
            borderTop: '1px solid var(--border-color)'
          }}>
            <button
              type="button"
              onClick={handleTest}
              disabled={testing || saving}
              className="btn btn-outline"
              style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}
            >
              {testing ? <RefreshCw size={13} className="animate-spin" /> : <Zap size={13} color="#00f2fe" />}
              <span>{testing ? 'Probing...' : 'Test Connection'}</span>
            </button>

            <div style={{ display: 'flex', gap: 10 }}>
              <button
                type="button"
                onClick={onClose}
                className="btn btn-outline"
                style={{ fontSize: 12 }}
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={saving}
                className="btn btn-primary"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  fontSize: 13,
                  background: 'linear-gradient(135deg, #00f2fe 0%, #0284c7 100%)',
                  color: '#031326',
                  fontWeight: 700
                }}
              >
                {saving ? 'Saving...' : 'Save & Enable AI Model'}
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
}
