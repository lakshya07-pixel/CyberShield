import React, { useState, useEffect } from 'react';
import { apiClient } from '../../services/apiClient';

export const UserSecurityHistory: React.FC = () => {
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [filterChannel, setFilterChannel] = useState<string>('all');

  const fetchHistory = async () => {
    try {
      const res = await apiClient.getMonitoringEvents(100);
      if (res && res.success && res.events) {
        setEvents(res.events);
      }
    } catch {
      // Safe fallback
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
    const interval = setInterval(fetchHistory, 3000);
    return () => clearInterval(interval);
  }, []);

  const filtered = events.filter((e) => {
    if (filterChannel === 'all') return true;
    return e.source === filterChannel;
  });

  return (
    <div style={{ maxWidth: '950px', margin: '0 auto', padding: '1rem 0' }}>
      <div style={{ marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '1.8rem', fontWeight: 700, color: '#f8fafc', margin: '0 0 0.5rem' }}>
          My Security History
        </h2>
        <p style={{ color: '#94a3b8', fontSize: '1.05rem', margin: 0 }}>
          Complete, shared audit record of all your website scans, text message checks, and home network safety logs.
        </p>
      </div>

      {/* Filter Tabs */}
      <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
        <button
          type="button"
          onClick={() => setFilterChannel('all')}
          style={{
            padding: '6px 16px',
            borderRadius: '20px',
            border: '1px solid #334155',
            background: filterChannel === 'all' ? '#38bdf8' : '#0f172a',
            color: filterChannel === 'all' ? '#0f172a' : '#cbd5e1',
            fontWeight: 600,
            fontSize: '0.88rem',
            cursor: 'pointer',
          }}
        >
          All Activity ({events.length})
        </button>
        <button
          type="button"
          onClick={() => setFilterChannel('url')}
          style={{
            padding: '6px 16px',
            borderRadius: '20px',
            border: '1px solid #334155',
            background: filterChannel === 'url' ? '#38bdf8' : '#0f172a',
            color: filterChannel === 'url' ? '#0f172a' : '#cbd5e1',
            fontWeight: 600,
            fontSize: '0.88rem',
            cursor: 'pointer',
          }}
        >
          Websites ({events.filter((e) => e.source === 'url').length})
        </button>
        <button
          type="button"
          onClick={() => setFilterChannel('sms')}
          style={{
            padding: '6px 16px',
            borderRadius: '20px',
            border: '1px solid #334155',
            background: filterChannel === 'sms' ? '#38bdf8' : '#0f172a',
            color: filterChannel === 'sms' ? '#0f172a' : '#cbd5e1',
            fontWeight: 600,
            fontSize: '0.88rem',
            cursor: 'pointer',
          }}
        >
          Messages ({events.filter((e) => e.source === 'sms').length})
        </button>
        <button
          type="button"
          onClick={() => setFilterChannel('network')}
          style={{
            padding: '6px 16px',
            borderRadius: '20px',
            border: '1px solid #334155',
            background: filterChannel === 'network' ? '#38bdf8' : '#0f172a',
            color: filterChannel === 'network' ? '#0f172a' : '#cbd5e1',
            fontWeight: 600,
            fontSize: '0.88rem',
            cursor: 'pointer',
          }}
        >
          Network Traffic ({events.filter((e) => e.source === 'network').length})
        </button>
      </div>

      {/* History Items Container */}
      <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '16px', padding: '1.5rem' }}>
        {loading ? (
          <p style={{ color: '#94a3b8' }}>Loading your security history...</p>
        ) : filtered.length === 0 ? (
          <div style={{ padding: '3rem 1rem', textAlign: 'center', color: '#94a3b8' }}>
            <div style={{ fontSize: '1.2rem', color: '#f8fafc', marginBottom: '0.5rem' }}>No records found</div>
            <p style={{ margin: 0 }}>Scan a website or message to start building your personal security history.</p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {filtered.map((item) => {
              const isThreat = item.severity === 'CRITICAL' || item.severity === 'HIGH';
              const channelLabel = item.source === 'url' ? 'Website Check' : item.source === 'sms' ? 'Message Check' : 'Network Flow';

              return (
                <div
                  key={item.id}
                  style={{
                    background: '#141f36',
                    border: '1px solid #1e293b',
                    borderRadius: '10px',
                    padding: '1.1rem 1.4rem',
                    borderLeft: `5px solid ${isThreat ? '#ef4444' : '#10b981'}`,
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                      <span style={{ fontSize: '0.78rem', textTransform: 'uppercase', padding: '2px 8px', borderRadius: '4px', background: '#1e293b', color: '#38bdf8', fontWeight: 600 }}>
                        {channelLabel}
                      </span>
                      <span
                        style={{
                          fontSize: '0.78rem',
                          fontWeight: 700,
                          padding: '2px 8px',
                          borderRadius: '4px',
                          background: isThreat ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                          color: isThreat ? '#ef4444' : '#10b981',
                        }}
                      >
                        {isThreat ? 'Suspicious Item Flagged' : 'Safe / Clean'}
                      </span>
                    </div>
                    <span style={{ color: '#94a3b8', fontSize: '0.82rem' }}>
                      {item.time || item.timestamp}
                    </span>
                  </div>

                  <div style={{ color: '#f8fafc', fontSize: '0.98rem', fontWeight: 500, margin: '0.5rem 0' }}>
                    {item.event}
                  </div>

                  {item.indicators && item.indicators.length > 0 && (
                    <div style={{ color: '#94a3b8', fontSize: '0.84rem', marginTop: '0.4rem' }}>
                      <strong>Observed Details: </strong>
                      <code>{item.indicators.join(' • ')}</code>
                    </div>
                  )}

                  <div style={{ marginTop: '0.6rem', paddingTop: '0.5rem', borderTop: '1px solid #1e293b', fontSize: '0.85rem', color: isThreat ? '#fca5a5' : '#86efac' }}>
                    <strong>Recommended Action: </strong>
                    {isThreat
                      ? 'Avoid interacting with this item. Do not provide passwords or payment details.'
                      : 'No further action required. This item conforms to safe usage patterns.'}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};

