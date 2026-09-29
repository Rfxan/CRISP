import React, { useState, useEffect } from 'react';
import { 
  X, Cpu, Key, Globe, CheckCircle2, AlertCircle, Eye, EyeOff, 
  Sparkles, RefreshCw, Zap, Sliders, Shield, Edit3
} from 'lucide-react';
import { api } from '../services/api';

const PROVIDER_OPTIONS = [
  { 
    id: 'gemini', 
    name: 'Google Gemini', 
    desc: 'Ultra-fast multimodal 2.0 & 2.5 models with 1M+ context window',
    defaultModel: 'gemini-2.0-flash',
    models: ['gemini-2.0-flash', 'gemini-2.5-flash', 'gemini-2.0-flash-lite', 'gemini-1.5-pro', 'gemini-1.5-flash']
  },
  { 
    id: 'anthropic', 
    name: 'Anthropic Claude', 
    desc: 'Premier hybrid reasoning, nuanced analysis & executive synthesis',
    defaultModel: 'claude-sonnet-5',
    models: [
      'claude-sonnet-5',
      'claude-opus-5',
      'claude-sonnet-4-5-20250929',
      'claude-haiku-4-5-20251001',
      'claude-opus-4-5-20251101',
      'claude-3-7-sonnet-20250219'
    ]
  },
  { 
    id: 'openai', 
    name: 'OpenAI', 
    desc: 'Frontier reasoning & multimodal intelligence (GPT-4o, o3-mini, o1)',
    defaultModel: 'gpt-4o',
    models: ['gpt-4o', 'gpt-4o-mini', 'o3-mini', 'o1', 'chatgpt-4o-latest']
  },
  { 
    id: 'deepseek', 
    name: 'DeepSeek', 
    desc: 'Cutting-edge DeepSeek-V3 & R1 reasoning models',
    defaultModel: 'deepseek-chat',
    models: ['deepseek-chat', 'deepseek-reasoner']
  },
  { 
    id: 'groq', 
    name: 'Groq (Ultra-Fast LPUs)', 
    desc: 'Sub-second LPUs delivering 500+ tokens/sec on Llama 3.3 & DeepSeek',
    defaultModel: 'llama-3.3-70b-versatile',
    models: ['llama-3.3-70b-versatile', 'deepseek-r1-distill-llama-70b', 'llama-3.1-8b-instant', 'qwen-2.5-32b']
  },
  { 
    id: 'ollama', 
    name: 'Local Ollama (100% Free / Offline)', 
    desc: 'Local GPU/CPU inference at localhost:11434 with zero API keys',
    defaultModel: 'deepseek-r1',
    models: ['deepseek-r1', 'llama3.3', 'llama3.2', 'qwen2.5', 'phi4', 'mistral']
  },
  { 
    id: 'custom', 
    name: 'Custom OpenAI-Compatible Endpoint', 
    desc: 'Self-hosted vLLM, LM Studio, OpenRouter, or internal LLM proxies',
    defaultModel: 'custom-model',
    models: []
  }
];

export default function LLMSettingsModal({ isOpen, onClose, onConfigSaved }) {
  const [config, setConfig] = useState(null);
  const [provider, setProvider] = useState('gemini');
  const [model, setModel] = useState('gemini-2.0-flash');
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
      setModel(data.model || 'gemini-2.0-flash');
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
      setBaseUrl(pId === 'deepseek' ? 'https://api.deepseek.com' : '');
    }
    setTestResult(null);
  };

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await api.testAIConnection({
        provider,
        model: model.trim(),
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
    if (!model.trim()) {
      setStatusMsg({ type: 'error', text: 'Model name cannot be empty. Please enter or select a model.' });
      return;
    }
    setSaving(true);
    setStatusMsg(null);
    try {
      const updated = await api.saveAIConfig({
        provider,
        model: model.trim(),
        api_key: apiKey,
        base_url: baseUrl,
        enabled: true
      });
      setStatusMsg({ type: 'success', text: `AI configuration saved! Model set to ${provider.toUpperCase()} (${model.trim()}).` });
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
          maxWidth: 720,
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
                CRISP LLM Configuration & Model Selection
              </h3>
              <p style={{ margin: '3px 0 0 0', fontSize: 12, color: 'var(--text-dim)' }}>
                Select latest frontier models or type any custom model ID to power grounded C-suite risk advisory.
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
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: 10 }}>
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

          {/* 2. Model Identifier (Editable + Presets) */}
          <div style={{
            background: 'rgba(255, 255, 255, 0.02)',
            border: '1px solid rgba(0, 242, 254, 0.2)',
            borderRadius: 12,
            padding: 16
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8, flexWrap: 'wrap', gap: 6 }}>
              <label style={{ fontSize: 12, fontWeight: 700, color: '#fff', display: 'flex', alignItems: 'center', gap: 8 }}>
                <Edit3 size={14} color="#00f2fe" />
                <span>2. Model Identifier (Custom / Editable)</span>
              </label>
              <span style={{ fontSize: 11, color: '#00f2fe' }}>
                ✏️ Type any custom model or click a preset below
              </span>
            </div>

            <div style={{ position: 'relative', marginBottom: 10 }}>
              <input
                type="text"
                placeholder="Type or paste any model ID (e.g. claude-3-7-sonnet-20250219, gemini-2.0-flash, gpt-4o, deepseek-reasoner)"
                value={model}
                onChange={(e) => setModel(e.target.value)}
                style={{
                  width: '100%',
                  padding: '11px 14px',
                  borderRadius: 8,
                  background: '#090e1a',
                  border: '1px solid rgba(0, 242, 254, 0.4)',
                  color: '#00f2fe',
                  fontSize: 13,
                  fontWeight: 600,
                  fontFamily: 'monospace',
                  letterSpacing: '0.02em',
                  boxShadow: '0 0 10px rgba(0, 242, 254, 0.1)'
                }}
                required
              />
            </div>

            {/* Quick Clickable Preset Badges */}
            {currentProviderOpt.models.length > 0 && (
              <div>
                <span style={{ fontSize: 11, color: 'var(--text-dim)', display: 'block', marginBottom: 6 }}>
                  Popular Latest {currentProviderOpt.name} Presets:
                </span>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {currentProviderOpt.models.map(m => {
                    const isMatch = model === m;
                    return (
                      <button
                        key={m}
                        type="button"
                        onClick={() => setModel(m)}
                        style={{
                          padding: '5px 10px',
                          borderRadius: 6,
                          fontSize: 11,
                          fontFamily: 'monospace',
                          cursor: 'pointer',
                          transition: 'all 0.15s ease',
                          background: isMatch ? 'rgba(0, 242, 254, 0.25)' : 'rgba(255, 255, 255, 0.04)',
                          border: isMatch ? '1px solid #00f2fe' : '1px solid rgba(255, 255, 255, 0.12)',
                          color: isMatch ? '#00f2fe' : 'var(--text-muted)',
                          fontWeight: isMatch ? 700 : 500
                        }}
                      >
                        {isMatch && '✓ '}{m}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}
          </div>

          {/* 3. Base URL & API Key */}
          <div style={{ display: 'grid', gridTemplateColumns: provider === 'ollama' ? '1fr' : '1fr 1fr', gap: 14 }}>
            <div>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#fff', marginBottom: 6 }}>
                Base URL {provider === 'ollama' ? '(Default: http://localhost:11434/v1)' : provider === 'deepseek' ? '(Default: https://api.deepseek.com)' : '(Optional Override)'}
              </label>
              <input
                type="text"
                placeholder={
                  provider === 'ollama' 
                    ? 'http://localhost:11434/v1' 
                    : provider === 'deepseek' 
                      ? 'https://api.deepseek.com' 
                      : 'https://api.example.com/v1'
                }
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

            {/* API Key */}
            {provider !== 'ollama' && (
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                  <label style={{ fontSize: 12, fontWeight: 600, color: '#fff' }}>
                    {currentProviderOpt.name} API Key
                  </label>
                  <span className="badge badge-cyan" style={{ fontSize: 9 }}>
                    <Shield size={10} style={{ marginRight: 4 }} /> Fernet AES-256
                  </span>
                </div>
                <div style={{ position: 'relative' }}>
                  <input
                    type={showKey ? 'text' : 'password'}
                    placeholder={config?.has_api_key && config?.provider === provider ? '•••••••• (Encrypted key saved - leave blank or paste to replace)' : 'Paste API Key'}
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '9px 38px 9px 12px',
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
                    {showKey ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                </div>
              </div>
            )}
          </div>

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
