import React, { useState, useEffect } from 'react';
import { 
  Bot, Send, Sparkles, Terminal, CheckCircle2, ShieldCheck, 
  Database, Wrench, Settings, Cpu, Zap, Sliders, AlertCircle
} from 'lucide-react';
import { api } from '../services/api';
import LLMSettingsModal from './LLMSettingsModal';

export default function AIQueryCenter({ currentRunId }) {
  const [query, setQuery] = useState('');
  const [messages, setMessages] = useState([
    {
      sender: 'ai',
      text: `Hello! I am the CRISP Executive Decision Support Assistant. I answer strategic risk, budget allocation, and compliance questions grounded in deterministic figures from the FAIR Monte Carlo engine and Integer Linear Programming solver.\n\nYou can connect an actual LLM (Gemini, OpenAI, Groq, Claude, or Local Ollama) using "AI Model Settings" above, or use the built-in verified mathematical reasoning engine. No hallucinated numbers.`,
      toolUsed: 'system_init',
      runId: currentRunId || 'RUN-INIT',
      assumptionsVer: 4,
      sources: ['FAIR Engine', 'PuLP ILP Optimizer', 'SEBI CSCRF Engine'],
      isLLM: false
    }
  ]);
  const [loading, setLoading] = useState(false);
  const [aiConfig, setAiConfig] = useState(null);
  const [showSettingsModal, setShowSettingsModal] = useState(false);

  useEffect(() => {
    fetchAIConfig();
  }, []);

  const fetchAIConfig = async () => {
    try {
      const cfg = await api.getAIConfig();
      setAiConfig(cfg);
    } catch (err) {
      console.error('Failed to load AI config:', err);
    }
  };

  const suggestedQuestions = [
    'What is our highest financial cyber risk today?',
    'How should we spend our ₹1 Crore security budget?',
    'Are we compliant with SEBI 6-hour reporting?',
    'What if we deploy MFA on all privileged accounts?',
    'Explain our Value at Risk (VaR 95) for the Board of Directors'
  ];

  const handleSend = async (questionText) => {
    const q = questionText || query;
    if (!q.trim()) return;

    const userMsg = { sender: 'user', text: q };
    setMessages(prev => [...prev, userMsg]);
    setQuery('');
    setLoading(true);

    try {
      const res = await api.askAI(q);
      const aiMsg = {
        sender: 'ai',
        text: res.answer,
        toolUsed: res.tool_used,
        toolArgs: res.tool_args,
        runId: res.run_id,
        assumptionsVer: res.assumptions_version,
        sources: res.sources,
        isLLM: Boolean(res.is_llm),
        llmProvider: res.llm_provider,
        llmModel: res.llm_model,
        latencyMs: res.latency_ms,
        fallbackReason: res.fallback_reason
      };
      setMessages(prev => [...prev, aiMsg]);
    } catch (e) {
      setMessages(prev => [...prev, {
        sender: 'ai',
        text: 'Error querying decision support engine. Please verify the backend is running.',
        error: true
      }]);
    } finally {
      setLoading(false);
    }
  };

  const isLLMActive = aiConfig && aiConfig.enabled && (aiConfig.has_api_key || aiConfig.provider === 'ollama');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      
      {/* AI Header */}
      <div className="glass-panel" style={{ padding: 20, borderTop: '3px solid var(--primary)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{
              width: 40,
              height: 40,
              borderRadius: 10,
              background: isLLMActive 
                ? 'linear-gradient(135deg, var(--accent-purple) 0%, var(--primary) 100%)' 
                : 'linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: isLLMActive ? '0 0 15px rgba(154, 150, 179, 0.4)' : 'none'
            }}>
              {isLLMActive ? <Sparkles size={22} color="var(--text-main)" /> : <Bot size={22} color="var(--text-main)" />}
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-main)', fontFamily: 'var(--font-rounded)', fontWeight: 800 }}>
                  Grounded Decision Support Layer
                </h3>
                {isLLMActive ? (
                  <span className="badge badge-cyan" style={{ fontSize: 10 }}>
                    <Cpu size={11} style={{ marginRight: 3 }} /> LLM: {aiConfig.provider?.toUpperCase()} ({aiConfig.model})
                  </span>
                ) : (
                  <span className="badge badge-simulated" style={{ fontSize: 10 }}>
                    <ShieldCheck size={11} style={{ marginRight: 3 }} /> Deterministic Grounded Engine
                  </span>
                )}
              </div>
              <p style={{ margin: '3px 0 0 0', fontSize: 12, color: 'var(--text-dim)' }}>
                Multi-provider LLM synthesis grounded in live FAIR Monte Carlo & PuLP ILP solver outputs.
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <button
              onClick={() => setShowSettingsModal(true)}
              className="btn btn-secondary"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                fontSize: 12,
                padding: '8px 14px',
                background: 'var(--bg-main)',
                border: '1px solid var(--primary)',
                color: 'var(--primary)'
              }}
            >
              <Settings size={14} />
              <span>AI Model Settings</span>
            </button>
          </div>
        </div>

        {/* Suggested Prompts */}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 14 }}>
          {suggestedQuestions.map((sq, idx) => (
            <button
              key={idx}
              onClick={() => handleSend(sq)}
              className="btn btn-outline"
              style={{ fontSize: 11, padding: '5px 12px', background: 'var(--bg-main)', color: 'var(--text-main)' }}
            >
              <Sparkles size={12} color="var(--primary)" />
              <span>{sq}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Chat Messages Log */}
      <div className="glass-panel" style={{ padding: 20, minHeight: 400, maxHeight: 540, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 16 }}>
        {messages.map((m, idx) => {
          const isUser = m.sender === 'user';
          return (
            <div 
              key={idx} 
              style={{
                alignSelf: isUser ? 'flex-end' : 'flex-start',
                maxWidth: isUser ? '75%' : '90%',
                background: isUser ? 'var(--bg-main)' : 'var(--bg-card)',
                border: isUser ? '1px solid var(--primary)' : '1px solid var(--border-color)',
                borderRadius: 12,
                padding: '16px 20px',
                boxShadow: isUser ? 'var(--clay-inner)' : 'var(--clay-shadow)'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 8, flexWrap: 'wrap' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  {isUser ? (
                    <strong style={{ fontSize: 12, color: 'var(--primary)' }}>Executive User</strong>
                  ) : (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                      <strong style={{ fontSize: 12, color: 'var(--text-main)' }}>CRISP Engine</strong>
                      {m.runId && (
                        <span className="mono badge badge-cyan" style={{ fontSize: 9 }}>
                          {m.runId}
                        </span>
                      )}
                      {m.isLLM ? (
                        <span className="badge badge-kev" style={{ fontSize: 9 }}>
                          <Cpu size={10} style={{ marginRight: 3 }} /> {m.llmProvider?.toUpperCase()} ({m.llmModel}) {m.latencyMs ? `· ${m.latencyMs}ms` : ''}
                        </span>
                      ) : (
                        m.toolUsed && (
                          <span className="mono badge badge-simulated" style={{ fontSize: 9 }}>
                            <Wrench size={10} style={{ marginRight: 3 }} /> {m.toolUsed}
                          </span>
                        )
                      )}
                    </div>
                  )}
                </div>
              </div>

              {/* Message Content */}
              <div style={{ fontSize: 13, color: 'var(--text-main)', whiteSpace: 'pre-line', lineHeight: 1.6 }}>
                {m.text}
              </div>

              {/* Fallback Notice if LLM failed */}
              {m.fallbackReason && (
                <div style={{
                  marginTop: 8,
                  padding: '6px 10px',
                  borderRadius: 6,
                  background: 'rgba(209, 184, 121, 0.1)',
                  border: '1px solid rgba(209, 184, 121, 0.3)',
                  fontSize: 11,
                  color: 'var(--accent-amber)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6
                }}>
                  <AlertCircle size={12} />
                  <span>Note: {m.fallbackReason}</span>
                </div>
              )}

              {/* Verified Sources Badge */}
              {!isUser && m.sources && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', marginTop: 12, borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 8 }}>
                  <span style={{ fontSize: 10, color: 'var(--text-dim)' }}>Audited Sources:</span>
                  {m.sources.map((src, sIdx) => (
                    <span key={sIdx} className="badge" style={{ background: 'var(--bg-main)', color: 'var(--text-main)', fontSize: 9 }}>
                      {src}
                    </span>
                  ))}
                </div>
              )}
            </div>
          );
        })}
        {loading && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            color: 'var(--primary)',
            fontSize: 12,
            padding: '10px 14px',
            background: 'var(--bg-main)',
            borderRadius: 8,
            border: '1px solid var(--border-color)',
            alignSelf: 'flex-start'
          }}>
            <Sparkles size={14} className="animate-spin" />
            <span>Consulting FAIR simulation engine & synthesizing executive guidance...</span>
          </div>
        )}
      </div>

      {/* Input Box */}
      <div className="glass-panel" style={{ padding: 12, display: 'flex', gap: 10 }}>
        <input 
          type="text"
          placeholder="Ask a question (e.g. 'What is our highest risk?', 'How to spend 1 Crore?', 'What if we deploy MFA?')..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSend()}
          style={{
            flex: 1,
            background: 'transparent',
            border: 'none',
            outline: 'none',
            color: 'var(--text-main)',
            fontSize: 13,
            fontFamily: 'var(--font-sans)',
            padding: '6px 12px'
          }}
        />
        <button 
          className="btn btn-primary" 
          onClick={() => handleSend()} 
          disabled={loading}
          style={{ padding: '8px 20px', gap: 8 }}
        >
          <Send size={14} />
          <span>Ask AI</span>
        </button>
      </div>

      {/* LLM Settings Modal */}
      <LLMSettingsModal
        isOpen={showSettingsModal}
        onClose={() => setShowSettingsModal(false)}
        onConfigSaved={(updated) => {
          setAiConfig(updated);
        }}
      />
    </div>
  );
}
