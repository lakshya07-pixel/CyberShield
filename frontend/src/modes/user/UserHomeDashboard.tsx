import React, { useState, useEffect } from 'react';
import { apiClient } from '../../services/apiClient';

interface UserHomeProps {
  onNavigate: (tab: 'url' | 'sms' | 'network' | 'history' | 'assistant') => void;
}

export const UserHomeDashboard: React.FC<UserHomeProps> = ({ onNavigate }) => {
  const [stats, setStats] = useState({
    totalChecks: 0,
    threatsFound: 0,
    networkStatus: 'Checking...',
    networkStatusDetail: 'Connecting to monitoring engine...',
    packetsCaptured: 0,
    packetsSent: 0,
    packetsRecv: 0,
    activeInterface: 'Wi-Fi',
    lastEventTime: null as string | null,
  });
  const [recentEvents, setRecentEvents] = useState<any[]>([]);
  const [backendOnline, setBackendOnline] = useState<boolean>(true);

  useEffect(() => {
    const loadStatus = async () => {
      try {
        const statusRes = await apiClient.getMonitoringStatus();
        if (statusRes && statusRes.stats) {
          const threats = (statusRes.stats.critical_count || 0) + (statusRes.stats.high_count || 0);
          const traffic = statusRes.traffic || {};
          const captureInfo = statusRes.capture_subsystem || {};

          let statusLabel = 'Standby';
          let statusDetail = 'Monitoring engine in standby mode.';

          if (!statusRes.is_running) {
            statusLabel = 'Standby';
            statusDetail = 'Monitoring engine available but not currently running.';
          } else if (traffic.available && (traffic.packets_captured > 0 || traffic.packets_sent > 0)) {
            statusLabel = 'Active Monitoring';
            statusDetail = `Tracking real traffic on ${traffic.active_interface || 'active interface'}: ${traffic.packets_captured.toLocaleString()} packets observed.`;
          } else if (captureInfo.provider && captureInfo.provider.includes('Blocked')) {
            statusLabel = 'Permission Required';
            statusDetail = 'Windows Npcap driver requires Administrator privileges for raw frame capture.';
          } else {
            statusLabel = 'Active Monitoring';
            statusDetail = 'Passive background ingress observation active.';
          }

          setStats({
            totalChecks: statusRes.total_events || 0,
            threatsFound: threats,
            networkStatus: statusLabel,
            networkStatusDetail: statusDetail,
            packetsCaptured: traffic.packets_captured || 0,
            packetsSent: traffic.packets_sent || 0,
            packetsRecv: traffic.packets_recv || 0,
            activeInterface: traffic.active_interface || 'Wi-Fi',
            lastEventTime: statusRes.stats.last_event_time,
          });
          setBackendOnline(true);
        }

        const eventsRes = await apiClient.getMonitoringEvents(5);
        if (eventsRes && eventsRes.events) {
          setRecentEvents(eventsRes.events);
        }
      } catch {
        setBackendOnline(false);
        setStats((prev) => ({
          ...prev,
          networkStatus: 'Backend Disconnected',
          networkStatusDetail: 'Unable to communicate with backend monitoring service.',
        }));
      }
    };

    loadStatus();
    const timer = setInterval(loadStatus, 3000);
    return () => clearInterval(timer);
  }, []);

  const getStatusBadge = () => {
    if (!backendOnline) {
      return {
        text: 'Backend Disconnected',
        color: '#64748b',
        bg: 'rgba(100, 116, 139, 0.15)',
        desc: 'Security server is currently offline or unreachable.',
      };
    }
    if (stats.threatsFound > 0) {
      return {
        text: 'Attention Needed',
        color: '#f97316',
        bg: 'rgba(249, 115, 22, 0.15)',
        desc: `${stats.threatsFound} potential digital risk(s) flagged during recent checks.`,
      };
    }
    if (stats.totalChecks > 0 || stats.packetsCaptured > 0) {
      return {
        text: 'All Clear',
        color: '#10b981',
        bg: 'rgba(16, 185, 129, 0.15)',
        desc: 'Network stream active. No active threats detected in your message, website, or network activity.',
      };
    }
    return {
      text: 'Checking Security',
      color: '#38bdf8',
      bg: 'rgba(56, 189, 248, 0.15)',
      desc: 'System is ready to check suspicious websites, messages, and network traffic.',
    };
  };

  const statusInfo = getStatusBadge();

  return (
    <div style={{ maxWidth: '1000px', margin: '0 auto', padding: '1rem 0' }}>
      {/* Welcome Banner */}
      <div style={{ marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '1.8rem', fontWeight: 700, color: '#f8fafc', margin: '0 0 0.5rem' }}>
          Your Digital Safety Dashboard
        </h2>
        <p style={{ color: '#94a3b8', fontSize: '1.05rem', margin: 0 }}>
          Simple, everyday cybersecurity protection for your websites, messages, and home network.
        </p>
      </div>

      {/* Main Status Hero Card */}
      <div
        style={{
          background: 'linear-gradient(135deg, #0f1d38 0%, #15274d 100%)',
          border: '1px solid #1e3a6d',
          borderRadius: '16px',
          padding: '1.75rem',
          marginBottom: '2rem',
          boxShadow: '0 8px 24px rgba(0,0,0,0.3)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'inline-block', padding: '4px 12px', borderRadius: '20px', background: statusInfo.bg, color: statusInfo.color, fontWeight: 700, fontSize: '0.9rem', marginBottom: '0.75rem' }}>
              ● {statusInfo.text}
            </div>
            <h3 style={{ fontSize: '1.4rem', color: '#f8fafc', margin: '0 0 0.5rem' }}>
              {statusInfo.desc}
            </h3>
            <p style={{ color: '#cbd5e1', fontSize: '0.92rem', margin: 0 }}>
              Live Network Activity: <strong style={{ color: '#38bdf8' }}>{stats.packetsCaptured > 0 ? `${stats.packetsCaptured.toLocaleString()} packets observed` : 'Active'}</strong> on <code>{stats.activeInterface}</code>
            </p>
          </div>
          <div style={{ display: 'flex', gap: '0.75rem' }}>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => onNavigate('url')}
              style={{ padding: '0.75rem 1.25rem', borderRadius: '10px', fontWeight: 600 }}
            >
              Check a Website
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => onNavigate('sms')}
              style={{ padding: '0.75rem 1.25rem', borderRadius: '10px', fontWeight: 600 }}
            >
              Check a Message
            </button>
          </div>
        </div>
      </div>

      {/* Key Metrics Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.5rem', marginBottom: '2rem' }}>
        <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '1.5rem' }}>
          <div style={{ color: '#94a3b8', fontSize: '0.85rem', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>
            Live Packets Observed
          </div>
          <div style={{ fontSize: '2.2rem', fontWeight: 700, color: '#f8fafc', margin: '0.5rem 0' }}>
            {stats.packetsCaptured > 0 ? stats.packetsCaptured.toLocaleString() : stats.totalChecks}
          </div>
          <p style={{ color: '#cbd5e1', fontSize: '0.88rem', margin: 0 }}>
            {stats.packetsCaptured > 0
              ? `In: ${stats.packetsRecv.toLocaleString()} • Out: ${stats.packetsSent.toLocaleString()}`
              : 'Websites, SMS text lures, and network flow inspections.'}
          </p>
        </div>

        <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '1.5rem' }}>
          <div style={{ color: '#94a3b8', fontSize: '0.85rem', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>
            Threats Detected
          </div>
          <div style={{ fontSize: '2.2rem', fontWeight: 700, color: stats.threatsFound > 0 ? '#ef4444' : '#10b981', margin: '0.5rem 0' }}>
            {stats.threatsFound}
          </div>
          <p style={{ color: '#cbd5e1', fontSize: '0.88rem', margin: 0 }}>
            {stats.threatsFound > 0 ? 'Suspicious items flagged for your review.' : 'Zero dangerous items active in your system.'}
          </p>
        </div>

        <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '1.5rem' }}>
          <div style={{ color: '#94a3b8', fontSize: '0.85rem', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>
            Network Status
          </div>
          <div
            style={{
              fontSize: '1.4rem',
              fontWeight: 700,
              color:
                stats.networkStatus === 'Active Monitoring'
                  ? '#10b981'
                  : stats.networkStatus === 'Permission Required'
                  ? '#f59e0b'
                  : stats.networkStatus === 'Backend Disconnected'
                  ? '#ef4444'
                  : '#38bdf8',
              margin: '0.8rem 0',
            }}
          >
            {stats.networkStatus}
          </div>
          <p style={{ color: '#cbd5e1', fontSize: '0.88rem', margin: 0 }}>
            {stats.networkStatusDetail}
          </p>
        </div>
      </div>

      {/* Recommended Safety Actions Card */}
      <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '1.5rem', marginBottom: '2rem' }}>
        <h4 style={{ fontSize: '1.15rem', color: '#f8fafc', margin: '0 0 1rem' }}>
          Recommended Safety Actions
        </h4>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
          <div style={{ background: '#141f36', padding: '1rem', borderRadius: '8px', borderLeft: '4px solid #38bdf8' }}>
            <strong style={{ color: '#f8fafc' }}>Verify Unfamiliar SMS Links</strong>
            <p style={{ color: '#cbd5e1', fontSize: '0.85rem', margin: '0.35rem 0 0' }}>
              Bank or government OTP texts asking for urgent action are frequently phishing lures. Paste them in &quot;Check a Message&quot;.
            </p>
          </div>
          <div style={{ background: '#141f36', padding: '1rem', borderRadius: '8px', borderLeft: '4px solid #10b981' }}>
            <strong style={{ color: '#f8fafc' }}>Look for HTTPS and Spelling</strong>
            <p style={{ color: '#cbd5e1', fontSize: '0.85rem', margin: '0.35rem 0 0' }}>
              Check the exact address of websites asking for passwords or card numbers before typing.
            </p>
          </div>
          <div style={{ background: '#141f36', padding: '1rem', borderRadius: '8px', borderLeft: '4px solid #eab308' }}>
            <strong style={{ color: '#f8fafc' }}>Have a Question?</strong>
            <p style={{ color: '#cbd5e1', fontSize: '0.85rem', margin: '0.35rem 0 0' }}>
              Ask our local AI Security Assistant to explain any suspicious alert in simple language.
            </p>
          </div>
        </div>
      </div>

      {/* Recent Security Activity Stream */}
      <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h4 style={{ fontSize: '1.15rem', color: '#f8fafc', margin: 0 }}>
            Recent Activity
          </h4>
          <span style={{ fontSize: '0.85rem', color: '#94a3b8' }}>Live Background Stream</span>
        </div>

        {recentEvents.length === 0 ? (
          <div style={{ padding: '2rem', textAlign: 'center', color: '#94a3b8', background: '#141f36', borderRadius: '8px' }}>
            No recent activity recorded. Click &quot;Check a Website&quot; or &quot;Check a Message&quot; above to scan suspicious items.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {recentEvents.map((item) => {
              const isThreat = item.severity === 'CRITICAL' || item.severity === 'HIGH';
              const isWarning = item.severity === 'MEDIUM';
              return (
                <div
                  key={item.id}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    background: '#141f36',
                    padding: '0.85rem 1.25rem',
                    borderRadius: '8px',
                    borderLeft: `4px solid ${isThreat ? '#ef4444' : isWarning ? '#f59e0b' : '#10b981'}`,
                  }}
                >
                  <div>
                    <div style={{ color: '#f8fafc', fontWeight: 600, fontSize: '0.92rem' }}>
                      {item.event}
                    </div>
                    <div style={{ color: '#94a3b8', fontSize: '0.8rem', marginTop: '0.2rem' }}>
                      Channel: <span style={{ textTransform: 'capitalize' }}>{item.source}</span> • Status: {item.status || 'Verified'}
                    </div>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <span
                      style={{
                        padding: '2px 8px',
                        borderRadius: '4px',
                        fontSize: '0.75rem',
                        fontWeight: 700,
                        background: isThreat ? '#ef4444' : isWarning ? '#f59e0b' : '#10b981',
                        color: isWarning ? '#0f172a' : '#ffffff',
                      }}
                    >
                      {item.severity}
                    </span>
                    <div style={{ color: '#94a3b8', fontSize: '0.78rem', marginTop: '0.2rem' }}>
                      {item.time}
                    </div>
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
