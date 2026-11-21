import React, { useState } from 'react';
import { apiClient } from '../services/apiClient';

interface Message {
  sender: 'user' | 'assistant';
  text: string;
  timestamp: string;
  engine?: string;
  grounded?: boolean;
}

const PRESET_SCENARIOS = [
  {
    label: 'Why was this SMS marked as suspicious?',
    query: 'Why was this SMS marked as suspicious?',
    context: {
      source: 'sms',
      threat_type: 'scam',
      attack_class: 'SCAM',
      severity: 'HIGH',
      confidence: 0.8949,
      indicators: ['http://sbi-online-banking-kyc.com/update-pan.html', 'keyword: urgent verify block kyc'],
    },
  },
  {
    label: 'Explain this phishing URL',
    query: 'Explain this phishing URL.',
    context: {
      source: 'url',
      threat_type: 'phishing',
      attack_class: 'PHISHING',
      severity: 'HIGH',
      confidence: 0.85,
      indicators: ['host:sbi-online-banking-kyc.com', 'Missing HTTPS encryption', 'Multiple hyphens in domain'],
    },
  },
  {
    label: 'What does this network alert mean?',
    query: 'What does this network alert mean?',
    context: {
      source: 'network',
      threat_type: 'intrusion',
      attack_class: 'SYN_FLOOD',
      severity: 'CRITICAL',
      confidence: 0.95,
      indicators: ['Destination Port: 443', 'High SYN ratio', 'IP: 198.51.100.24'],
    },
  },
  {
    label: 'Explain this correlated attack',
    query: 'Explain this correlated attack.',
    context: {
      incident_id: 'INC-CORR-SBI-ONLINE-BANKING-K',
      severity: 'CRITICAL',
      indicators: ['sbi-online-banking-kyc.com', '198.51.100.24'],
    },
  },
  {
    label: 'What should I do next?',
    query: 'What should I do next?',
    context: {
      incident_id: 'INC-CORR-SBI-ONLINE-BANKING-K',
      severity: 'CRITICAL',
    },
  },
  {
    label: 'Summarize latest security events',
    query: 'Summarize the latest security incidents.',
    context: {},
  },
];

export const SecurityAssistantPage: React.FC = () => {
  const [messages, setMessages] = useState<Message[]>([
    {
      sender: 'assistant',
      text: 'Hello. I am the CyberShield Grounded Security Assistant.\n\nI provide deterministic, evidence-based security explanations and recommended mitigation playbooks completely offline. Select a quick prompt below or type your question.',
      timestamp: new Date().toLocaleTimeString(),
      engine: 'Deterministic Grounded Rule & Evidence Engine',
      grounded: true,
    },
  ]);
  const [inputQuery, setInputQuery] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleSend = async (queryText?: string, customContext?: Record<string, unknown>) => {
    const textToSend = (queryText || inputQuery).trim();
    if (!textToSend || isLoading) return;

    setErrorMsg(null);
    const userMsg: Message = {
      sender: 'user',
      text: textToSend,
      timestamp: new Date().toLocaleTimeString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    if (!queryText) setInputQuery('');
    setIsLoading(true);

    try {
      const response = await apiClient.queryAssistant(textToSend, customContext || { session_mode: 'soc_triage' });

      const assistantMsg: Message = {
        sender: 'assistant',
        text: response.answer || 'No response returned from the assistant engine.',
        timestamp: new Date().toLocaleTimeString(),
        engine: response.engine,
        grounded: response.grounded_in_telemetry,
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Error communicating with assistant backend');
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleSend();
    }
  };

  const resetConversation = () => {
    setMessages([
      {
        sender: 'assistant',
        text: 'Conversation reset. I am ready to analyze security events, explain detector classifications, or generate mitigation playbooks.',
        timestamp: new Date().toLocaleTimeString(),
        engine: 'Deterministic Grounded Rule & Evidence Engine',
        grounded: true,
      },
    ]);
    setErrorMsg(null);
  };

  return (
    <div className="page-container">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 className="page-title">AI Security Assistant</h2>
          <p className="page-subtitle">
            Local, grounded cybersecurity analyst assistant for incident investigation, threat explanation, and rapid mitigation.
          </p>
        </div>
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          onClick={resetConversation}
        >
          Reset Conversation
        </button>
      </div>

      <div className="card-box" style={{ display: 'flex', flexDirection: 'column', height: '620px' }}>
        {/* Preset Context-Grounded Prompts Bar */}
        <div style={{ marginBottom: '1rem', borderBottom: '1px solid #e2e8f0', paddingBottom: '0.75rem' }}>
          <span style={{ fontSize: '0.85rem', color: '#64748b', marginRight: '0.5rem', fontWeight: 600 }}>
            Context-Grounded Inquiries:
          </span>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', marginTop: '0.5rem' }}>
            {PRESET_SCENARIOS.map((item, idx) => (
              <button
                key={idx}
                type="button"
                className="btn btn-secondary"
                style={{ fontSize: '0.8rem', padding: '0.25rem 0.6rem' }}
                onClick={() => handleSend(item.query, item.context)}
                disabled={isLoading}
              >
                {item.label}
              </button>
            ))}
          </div>
        </div>

        {/* Message Stream */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '0.75rem', display: 'flex', flexDirection: 'column', gap: '1rem', background: '#0b1329', borderRadius: '6px' }}>
          {messages.map((m, idx) => (
            <div
              key={idx}
              style={{
                alignSelf: m.sender === 'user' ? 'flex-end' : 'flex-start',
                maxWidth: '85%',
                backgroundColor: m.sender === 'user' ? 'rgba(30, 58, 138, 0.45)' : '#1e293b',
                border: m.sender === 'user' ? '1px solid #3b82f6' : '1px solid #334155',
                borderRadius: '8px',
                padding: '0.85rem 1.1rem',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem', gap: '1rem' }}>
                <strong style={{ fontSize: '0.88rem', color: '#ffffff', fontWeight: 600 }}>
                  {m.sender === 'user' ? 'User' : 'AI Security Assistant'}
                </strong>
                <span style={{ fontSize: '0.78rem', color: '#cbd5e1' }}>{m.timestamp}</span>
              </div>
              <div style={{ fontSize: '0.95rem', whiteSpace: 'pre-line', lineHeight: 1.6, color: '#f8fafc' }}>
                {m.text}
              </div>
              {m.engine && (
                <div style={{ marginTop: '0.5rem', fontSize: '0.78rem', color: '#94a3b8', borderTop: '1px solid #334155', paddingTop: '0.35rem' }}>
                  Engine: <code style={{ color: '#38bdf8' }}>{m.engine}</code> {m.grounded && '• Grounded in verified detector telemetry'}
                </div>
              )}
            </div>
          ))}
          {isLoading && (
            <div style={{ alignSelf: 'flex-start', color: '#94a3b8', fontSize: '0.85rem', fontStyle: 'italic' }}>
              Analyzing threat context and retrieving evidence-backed guidance...
            </div>
          )}
        </div>

        {errorMsg && (
          <div style={{ color: '#f87171', fontSize: '0.85rem', marginTop: '0.5rem' }}>
            {errorMsg}
          </div>
        )}

        {/* Input Bar */}
        <div style={{ display: 'flex', gap: '0.75rem', marginTop: '1rem', borderTop: '1px solid #334155', paddingTop: '0.75rem' }}>
          <input
            type="text"
            className="form-control"
            placeholder="Ask a question about current threats, indicators, or recommended playbooks..."
            value={inputQuery}
            onChange={(e) => setInputQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={isLoading}
            style={{ flex: 1, backgroundColor: '#1e293b', color: '#f8fafc', borderColor: '#475569' }}
          />
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => handleSend()}
            disabled={isLoading || !inputQuery.trim()}
          >
            {isLoading ? 'Thinking...' : 'Send'}
          </button>
        </div>
      </div>
    </div>
  );
};
