import React, { useState } from 'react';
import { Bot, Send, Sparkles, Terminal, CheckCircle2, ShieldCheck, Database, Wrench } from 'lucide-react';
import { api } from '../services/api';

export default function AIQueryCenter({ currentRunId }) {
  const [query, setQuery] = useState('');
  const [messages, setMessages] = useState([
    {
      sender: 'ai',
      text: `Hello! I am the CRISP Decision Support Assistant. I answer executive risk and budget questions using strictly verified figures from the deterministic FAIR Monte Carlo engine and Integer Linear Programming solver. No hallucinated numbers.\n\nEvery answer is grounded and cites an active Run ID. You can choose a sample question below or type your own.`,
      toolUsed: 'system_init',
      runId: currentRunId || 'RUN-INIT',
      assumptionsVer: 4,
      sources: ['FAIR Engine', 'PuLP ILP Optimizer', 'SEBI CSCRF Engine']
    }
  ]);
  const [loading, setLoading] = useState(false);

  const suggestedQuestions = [
    'What is our highest financial cyber risk today?',
    'How should we spend our ₹1 Crore security budget?',
    'Are we compliant with SEBI 6-hour reporting?',
    'What if we deploy MFA on all privileged accounts?'
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
        sources: res.sources
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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      
      {/* AI Header */}
      <div className="glass-panel" style={{ padding: 20, borderTop: '3px solid #00f2fe' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 36,
              height: 36,
              borderRadius: 8,
              background: 'linear-gradient(135deg, #00f2fe 0%, #0284c7 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              <Bot size={20} color="#051026" />
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: 16, color: '#fff' }}>Grounded Decision Support Layer</h3>
              <p style={{ margin: 0, fontSize: 12, color: 'var(--text-dim)' }}>
                Tool-calling architecture: maps questions directly to pure engine APIs (PRD Sec 7.2)
              </p>
            </div>
          </div>
          <span className="badge badge-real">Deterministic Citations (No Hallucinations)</span>
        </div>

        {/* Suggested Prompts */}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 14 }}>
          {suggestedQuestions.map((sq, idx) => (
            <button
              key={idx}
              onClick={() => handleSend(sq)}
              className="btn btn-outline"
              style={{ fontSize: 11, padding: '5px 12px', background: 'rgba(255,255,255,0.03)' }}
            >
              <Sparkles size={12} color="#00f2fe" />
              <span>{sq}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Chat Messages Log */}
      <div className="glass-panel" style={{ padding: 20, minHeight: 380, maxHeight: 520, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 16 }}>
        {messages.map((m, idx) => {
          const isUser = m.sender === 'user';
          return (
            <div 
              key={idx} 
              style={{
                alignSelf: isUser ? 'flex-end' : 'flex-start',
                maxWidth: isUser ? '75%' : '88%',
                background: isUser ? 'rgba(0, 242, 254, 0.12)' : 'rgba(15, 23, 42, 0.9)',
                border: isUser ? '1px solid rgba(0, 242, 254, 0.3)' : '1px solid var(--border-color)',
                borderRadius: 12,
                padding: '14px 18px'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                {isUser ? (
                  <strong style={{ fontSize: 12, color: '#00f2fe' }}>Executive User</strong>
                ) : (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <strong style={{ fontSize: 12, color: '#fff' }}>CRISP Engine</strong>
                    {m.runId && (
                      <span className="mono badge badge-cyan" style={{ fontSize: 9 }}>
                        {m.runId}
                      </span>
                    )}
                    {m.toolUsed && (
                      <span className="mono badge badge-simulated" style={{ fontSize: 9 }}>
                        <Wrench size={10} /> tool: {m.toolUsed}
                      </span>
                    )}
                  </div>
                )}
              </div>

              {/* Message Content */}
              <div style={{ fontSize: 13, color: '#f1f5f9', whiteSpace: 'pre-line', lineHeight: 1.5 }}>
                {m.text}
              </div>

              {/* Verified Sources Badge */}
              {!isUser && m.sources && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', marginTop: 10, borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 8 }}>
                  <span style={{ fontSize: 10, color: 'var(--text-dim)' }}>Audited Sources:</span>
                  {m.sources.map((src, sIdx) => (
                    <span key={sIdx} className="badge" style={{ background: 'rgba(255,255,255,0.05)', color: '#94a3b8', fontSize: 9 }}>
                      {src}
                    </span>
                  ))}
                </div>
              )}
            </div>
          );
        })}
        {loading && (
          <div style={{ color: 'var(--text-dim)', fontSize: 12, fontStyle: 'italic', padding: 10 }}>
            Querying FAIR Monte Carlo engine & ILP solver...
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
            color: '#fff',
            fontSize: 13,
            fontFamily: 'var(--font-sans)',
            padding: '4px 10px'
          }}
        />
        <button className="btn btn-primary" onClick={() => handleSend()} disabled={loading}>
          <Send size={14} />
          <span>Ask</span>
        </button>
      </div>

    </div>
  );
}
