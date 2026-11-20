import React, { useState } from 'react';
import { apiClient } from '../../services/apiClient';

interface ChatMessage {
  sender: 'user' | 'assistant';
  text: string;
  time: string;
}

const COMMON_QUESTIONS = [
  'What is a phishing attack and how do I spot it?',
  'Why did my bank send an urgent KYC message?',
  'What should I do if I accidentally clicked a suspicious link?',
  'How do I protect my UPI PIN and one-time passwords (OTP)?',
  'What does unusual network activity mean?',
];

export const UserSecurityAssistant: React.FC = () => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      sender: 'assistant',
      text: 'Hello! I am your personal Security Assistant. Ask me any question about strange text messages, suspicious websites, or how to keep your accounts safe.',
      time: new Date().toLocaleTimeString(),
    },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSend = async (queryText?: string) => {
    const textToSend = queryText || input;
    if (!textToSend.trim() || loading) return;

    const userMsg: ChatMessage = {
      sender: 'user',
      text: textToSend.trim(),
      time: new Date().toLocaleTimeString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    try {
      const res = await apiClient.queryAssistant(textToSend.trim(), { mode: 'simple_user' });
      const assistantText = res?.answer || res?.response || 'I have analyzed your question. For your safety, never share passwords or OTP codes with anyone, and always verify unfamiliar links before clicking.';

      setMessages((prev) => [
        ...prev,
        {
          sender: 'assistant',
          text: assistantText,
          time: new Date().toLocaleTimeString(),
        },
      ]);
    } catch {
      setMessages((prev) => [
        ...prev,
        {
          sender: 'assistant',
          text: 'I am currently unable to reach the offline security analysis engine. General safety rule: never share OTPs or click links from unknown senders.',
          time: new Date().toLocaleTimeString(),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: '850px', margin: '0 auto', padding: '1rem 0' }}>
      <div style={{ marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '1.8rem', fontWeight: 700, color: '#f8fafc', margin: '0 0 0.5rem' }}>
          Ask a Security Question
        </h2>
        <p style={{ color: '#94a3b8', fontSize: '1.05rem', margin: 0 }}>
          Friendly, jargon-free cybersecurity guidance grounded in real safety practices.
        </p>
      </div>

      {/* Suggested Quick Inquiries */}
      <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '1.25rem', marginBottom: '1.5rem' }}>
        <span style={{ fontSize: '0.85rem', color: '#94a3b8', fontWeight: 600, display: 'block', marginBottom: '0.6rem' }}>
          Common Security Questions:
        </span>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          {COMMON_QUESTIONS.map((q, idx) => (
            <button
              key={idx}
              type="button"
              className="btn btn-sm btn-outline-secondary"
              onClick={() => handleSend(q)}
              disabled={loading}
              style={{ fontSize: '0.82rem', padding: '5px 12px', borderRadius: '16px' }}
            >
              {q}
            </button>
          ))}
        </div>
      </div>

      {/* Chat Window */}
      <div
        style={{
          background: '#0f172a',
          border: '1px solid #1e293b',
          borderRadius: '16px',
          display: 'flex',
          flexDirection: 'column',
          height: '560px',
          padding: '1.25rem',
        }}
      >
        <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '1rem', paddingRight: '0.5rem' }}>
          {messages.map((m, idx) => (
            <div
              key={idx}
              style={{
                alignSelf: m.sender === 'user' ? 'flex-end' : 'flex-start',
                maxWidth: '82%',
                background: m.sender === 'user' ? '#1e3a6d' : '#141f36',
                border: `1px solid ${m.sender === 'user' ? '#38bdf8' : '#1e293b'}`,
                borderRadius: '12px',
                padding: '0.9rem 1.25rem',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem', gap: '1rem' }}>
                <strong style={{ fontSize: '0.88rem', color: m.sender === 'user' ? '#38bdf8' : '#10b981' }}>
                  {m.sender === 'user' ? 'You' : 'Digital Safety Assistant'}
                </strong>
                <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>{m.time}</span>
              </div>
              <div style={{ color: '#f8fafc', fontSize: '0.95rem', lineHeight: 1.6, whiteSpace: 'pre-line' }}>
                {m.text}
              </div>
            </div>
          ))}

          {loading && (
            <div style={{ alignSelf: 'flex-start', color: '#94a3b8', fontStyle: 'italic', fontSize: '0.88rem' }}>
              Preparing friendly security advice...
            </div>
          )}
        </div>

        {/* Input Bar */}
        <div style={{ display: 'flex', gap: '0.75rem', marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid #1e293b' }}>
          <input
            type="text"
            className="form-control"
            placeholder="Type your question here (e.g. Is it safe to click a prize link?)..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') handleSend();
            }}
            disabled={loading}
            style={{ flex: 1, background: '#141f36', color: '#ffffff', borderColor: '#334155', padding: '0.75rem 1rem' }}
          />
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => handleSend()}
            disabled={loading || !input.trim()}
            style={{ padding: '0.75rem 1.5rem', fontWeight: 600 }}
          >
            Ask
          </button>
        </div>
      </div>
    </div>
  );
};

