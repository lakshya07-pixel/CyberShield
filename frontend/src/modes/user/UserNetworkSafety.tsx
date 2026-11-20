import React, { useState, useEffect } from 'react';
import { apiClient } from '../../services/apiClient';

interface NetworkEventItem {
  id: string | number;
  time: string;
  source: string;
  event: string;
  severity: string;
  verdict?: string;
  indicators?: string[];
  dest_ip?: string;
  src_ip?: string;
}

export const UserNetworkSafety: React.FC = () => {
  const [networkStats, setNetworkStats] = useState({
    eventsCount: 0,
    threatsCount: 0,
    isRunning: false,
    uptimeSeconds: 0,
    packetsCaptured: 0,
    packetsSent: 0,
    packetsRecv: 0,
    activeInterface: 'Wi-Fi',
    liveCaptureCapable: false,
    statusState: 'Active Monitoring',
    statusDetail: 'Monitoring engine active.',
    lastEventTime: null as string | null,
  });
  const [networkAlerts, setNetworkAlerts] = useState<NetworkEventItem[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<NetworkEventItem | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const fetchStatus = async () => {
    try {
      const res = await apiClient.getMonitoringStatus();
      if (res && res.stats) {
        const traffic = res.traffic || {};
        const captureInfo = res.capture_subsystem || {};
        const isRunning = res.is_running || false;

        let statusState = 'Active Monitoring';
        let statusDetail = 'Continuous network telemetry active.';

        if (!isRunning) {
          statusState = 'Standby';
          statusDetail = 'Worker available but not currently capturing traffic.';
        } else if (traffic.available && (traffic.packets_captured > 0 || traffic.packets_sent > 0)) {
          statusState = 'Active Monitoring';
          statusDetail = `Observing live packet flows on ${traffic.active_interface || 'network interface'}.`;
        } else if (captureInfo.provider && captureInfo.provider.includes('Blocked')) {
          statusState = 'Permission Required';
          statusDetail = 'Npcap driver in Admin-only mode. Live raw sniffing requires Administrator privileges.';
        } else if (captureInfo.interface_count === 0) {
          statusState = 'Interface Unavailable';
          statusDetail = 'No suitable network interface can be accessed.';
        }

        setNetworkStats({
          eventsCount: res.stats.network_events || 0,
          threatsCount: (res.stats.critical_count || 0) + (res.stats.high_count || 0),
          isRunning: isRunning,
          uptimeSeconds: res.uptime_seconds || 0,
          packetsCaptured: traffic.packets_captured || 0,
          packetsSent: traffic.packets_sent || 0,
          packetsRecv: traffic.packets_recv || 0,
          activeInterface: traffic.active_interface || 'Wi-Fi',
          liveCaptureCapable: res.live_capture_capable || false,
          statusState: statusState,
          statusDetail: statusDetail,
          lastEventTime: res.stats.last_event_time,
        });
      }

      const eventsRes = await apiClient.getMonitoringEvents(50);
      if (eventsRes && eventsRes.events) {
        const netOnly = eventsRes.events.filter((e) => e.source === 'network');
        setNetworkAlerts(netOnly);
      }
    } catch {
      setNetworkStats((prev) => ({
        ...prev,
        statusState: 'Backend Disconnected',
        statusDetail: 'Unable to reach backend monitoring API.',
      }));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 3000);
    return () => clearInterval(interval);
  }, []);

  const getRiskExplanation = (ev: NetworkEventItem) => {
    const isCriticalOrHigh = ev.severity === 'CRITICAL' || ev.severity === 'HIGH';
    const isMedium = ev.severity === 'MEDIUM';
    const textLower = (ev.event || '').toLowerCase();

    if (textLower.includes('syn flood') || textLower.includes('flood') || textLower.includes('dos')) {
      return {
        type: 'SYN Flood / Denial of Service',
        whatHappened:
          'A rapid, coordinated flood of TCP connection initiation packets (SYN) was directed at your system without completing the connection handshake. This saturates the network connection table.',
        whyRisky:
          'Attackers use this technique to exhaust your router or computer network capacity, causing home Wi-Fi slowdowns, website disconnects, and service disruptions.',
        whatToDo:
          'Ensure your router firewall and SYN cookie protection are enabled. If the traffic persists from a specific public IP, add an ingress block rule on your network gateway.',
        prevention:
          'Keep router firmware updated, disable WAN remote administration ports, and use rate-limiting on incoming connections.',
      };
    } else if (textLower.includes('port scan') || textLower.includes('scan') || textLower.includes('reconnaissance')) {
      return {
        type: 'Automated Port Scan (Network Reconnaissance)',
        whatHappened:
          'A device sent automated probe requests across multiple network ports (such as 21, 22, 80, 443, 8080) to discover active listening services on your computer.',
        whyRisky:
          'Port scanning is the preliminary phase of a targeted network attack. Scammers and botnets scout for vulnerable, unpatched services or default passwords to exploit.',
        whatToDo:
          'Verify if the scanning source is an internal device (e.g. smart TV or printer doing discovery) or an external intruder. Close or fire-wall unused open ports.',
        prevention:
          'Disable universal plug and play (UPnP) on your router if not required, and keep all networked devices patched with latest security updates.',
      };
    } else if (!isCriticalOrHigh && !isMedium) {
      return {
        type: 'Legitimate Network Communication',
        whatHappened:
          'Standard network flow traffic observed across active interfaces. Packets are evaluated against known malicious signature thresholds.',
        whyRisky:
          'Normal traffic carries minimal risk under active encryption and standard firewall state tracking.',
        whatToDo:
          'No action required. Network stream operates within normal baseline boundaries.',
        prevention:
          'Maintain regular operating system updates and ensure trusted Wi-Fi encryption (WPA2/WPA3).',
      };
    }

    return {
      type: 'Suspicious Network Event',
      whatHappened: `Unusual traffic patterns or abnormal protocol flags were detected: ${ev.event}`,
      whyRisky:
        'Anomalous network flows can indicate unauthorized data transmission, malware communicating with command servers, or an external probe.',
      whatToDo:
        'Review the source IP and verify that background apps running on your device are recognized.',
      prevention:
        'Use host-based firewall rules and reputable antivirus to inspect background connections.',
    };
  };

  const formatUptime = (secs: number) => {
    if (!secs || secs <= 0) return 'Just started';
    const mins = Math.floor(secs / 60);
    const remSecs = secs % 60;
    if (mins === 0) return `${remSecs}s`;
    return `${mins}m ${remSecs}s`;
  };

  return (
    <div style={{ maxWidth: '950px', margin: '0 auto', padding: '1rem 0' }}>
      <div style={{ marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '1.8rem', fontWeight: 700, color: '#f8fafc', margin: '0 0 0.5rem' }}>
          Network Safety &amp; Intrusion Defense
        </h2>
        <p style={{ color: '#94a3b8', fontSize: '1.05rem', margin: 0 }}>
          Continuous background defense monitoring your local network against intrusions, unauthorized port scanning, and suspicious connection attempts.
        </p>
      </div>

      {/* Main Status Overview */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1.5rem', marginBottom: '2rem' }}>
        <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '1.5rem' }}>
          <span style={{ fontSize: '0.85rem', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase' }}>Monitoring Engine</span>
          <div
            style={{
              fontSize: '1.5rem',
              fontWeight: 700,
              color:
                networkStats.statusState === 'Active Monitoring'
                  ? '#10b981'
                  : networkStats.statusState === 'Permission Required'
                  ? '#f59e0b'
                  : networkStats.statusState === 'Backend Disconnected'
                  ? '#ef4444'
                  : '#38bdf8',
              margin: '0.5rem 0',
            }}
          >
            {networkStats.statusState}
          </div>
          <p style={{ color: '#cbd5e1', fontSize: '0.88rem', margin: 0 }}>
            {networkStats.statusDetail}
          </p>
          <div style={{ marginTop: '0.6rem', fontSize: '0.8rem', color: '#94a3b8' }}>
            Interface: <strong style={{ color: '#f8fafc' }}>{networkStats.activeInterface}</strong> • Uptime: {formatUptime(networkStats.uptimeSeconds)}
          </div>
        </div>

        <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '1.5rem' }}>
          <span style={{ fontSize: '0.85rem', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase' }}>Network Threats Detected</span>
          <div style={{ fontSize: '1.5rem', fontWeight: 700, color: networkStats.threatsCount > 0 ? '#ef4444' : '#10b981', margin: '0.5rem 0' }}>
            {networkStats.threatsCount} Threat(s) Detected
          </div>
          <p style={{ color: '#cbd5e1', fontSize: '0.88rem', margin: 0 }}>
            {networkStats.threatsCount > 0 ? 'Suspicious connection attempts flagged by IDS.' : 'Zero active network threats detected.'}
          </p>
          <div style={{ marginTop: '0.6rem', fontSize: '0.8rem', color: '#94a3b8' }}>
            Normal Traffic: <strong style={{ color: '#10b981' }}>{networkStats.eventsCount} events</strong>
          </div>
        </div>

        <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '1.5rem' }}>
          <span style={{ fontSize: '0.85rem', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase' }}>Packets Observed</span>
          <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f8fafc', margin: '0.5rem 0' }}>
            {networkStats.packetsCaptured > 0 ? networkStats.packetsCaptured.toLocaleString() : (networkStats.eventsCount > 0 ? `${networkStats.eventsCount} Flows` : 'N/A')}
          </div>
          <p style={{ color: '#cbd5e1', fontSize: '0.88rem', margin: 0 }}>
            {networkStats.packetsCaptured > 0
              ? `Incoming: ${networkStats.packetsRecv.toLocaleString()} • Outgoing: ${networkStats.packetsSent.toLocaleString()}`
              : 'Live packet stream tracking.'}
          </p>
          <div style={{ marginTop: '0.6rem', fontSize: '0.8rem', color: '#94a3b8' }}>
            Capture Driver: {networkStats.liveCaptureCapable ? 'Npcap Active' : 'Npcap (Admin Needed for Raw)'}
          </div>
        </div>
      </div>

      {/* Explanatory Safety Reference Cards */}
      <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '1.5rem', marginBottom: '2rem' }}>
        <h4 style={{ color: '#f8fafc', fontSize: '1.15rem', margin: '0 0 1rem' }}>
          Understanding Network Threat Classes
        </h4>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1rem' }}>
          <div style={{ background: '#141f36', padding: '1.1rem', borderRadius: '8px', borderLeft: '3px solid #ef4444' }}>
            <strong style={{ color: '#f8fafc' }}>SYN Flood / Packet Bursts</strong>
            <p style={{ color: '#cbd5e1', fontSize: '0.85rem', margin: '0.35rem 0 0' }}>
              Hostile automated packet storms aimed at crashing your router or exhausting memory buffers.
            </p>
          </div>
          <div style={{ background: '#141f36', padding: '1.1rem', borderRadius: '8px', borderLeft: '3px solid #f59e0b' }}>
            <strong style={{ color: '#f8fafc' }}>Port Scanning Probes</strong>
            <p style={{ color: '#cbd5e1', fontSize: '0.85rem', margin: '0.35rem 0 0' }}>
              Automated reconnaissance looking for open communication ports and unpatched devices on your Wi-Fi.
            </p>
          </div>
          <div style={{ background: '#141f36', padding: '1.1rem', borderRadius: '8px', borderLeft: '3px solid #10b981' }}>
            <strong style={{ color: '#f8fafc' }}>Normal Encrypted Traffic</strong>
            <p style={{ color: '#cbd5e1', fontSize: '0.85rem', margin: '0.35rem 0 0' }}>
              Standard HTTPS, DNS, and TLS handshake exchanges between your browser and verified internet servers.
            </p>
          </div>
        </div>
      </div>

      {/* Selected Event Risk Explanation Modal/Accordion */}
      {selectedEvent && (
        <div
          style={{
            background: '#162032',
            border: '2px solid #38bdf8',
            borderRadius: '12px',
            padding: '1.5rem',
            marginBottom: '2rem',
            position: 'relative',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <span style={{ fontSize: '0.85rem', fontWeight: 700, textTransform: 'uppercase', color: '#38bdf8', letterSpacing: '0.05em' }}>
              Detailed Risk Explanation for Event #{selectedEvent.id}
            </span>
            <button
              onClick={() => setSelectedEvent(null)}
              className="btn btn-sm btn-outline-secondary"
              style={{ padding: '2px 8px', fontSize: '0.8rem' }}
            >
              Close Details ✕
            </button>
          </div>

          {(() => {
            const exp = getRiskExplanation(selectedEvent);
            const isAlert = selectedEvent.severity === 'CRITICAL' || selectedEvent.severity === 'HIGH';
            return (
              <div>
                <h3 style={{ fontSize: '1.3rem', color: '#f8fafc', margin: '0 0 1rem' }}>
                  {exp.type}: <span style={{ color: isAlert ? '#ef4444' : '#10b981' }}>{selectedEvent.event}</span>
                </h3>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.9rem' }}>
                  <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.9rem', borderRadius: '6px' }}>
                    <strong style={{ color: '#f8fafc', display: 'block', marginBottom: '0.25rem' }}>1. What happened?</strong>
                    <p style={{ color: '#cbd5e1', fontSize: '0.9rem', margin: 0 }}>{exp.whatHappened}</p>
                  </div>

                  <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.9rem', borderRadius: '6px' }}>
                    <strong style={{ color: '#f8fafc', display: 'block', marginBottom: '0.25rem' }}>2. Why is it risky?</strong>
                    <p style={{ color: '#cbd5e1', fontSize: '0.9rem', margin: 0 }}>{exp.whyRisky}</p>
                  </div>

                  <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.9rem', borderRadius: '6px' }}>
                    <strong style={{ color: '#f8fafc', display: 'block', marginBottom: '0.25rem' }}>3. What should I do now?</strong>
                    <p style={{ color: '#cbd5e1', fontSize: '0.9rem', margin: 0 }}>{exp.whatToDo}</p>
                  </div>

                  <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.9rem', borderRadius: '6px' }}>
                    <strong style={{ color: '#f8fafc', display: 'block', marginBottom: '0.25rem' }}>4. Prevention suggestions</strong>
                    <p style={{ color: '#cbd5e1', fontSize: '0.9rem', margin: 0 }}>{exp.prevention}</p>
                  </div>
                </div>
              </div>
            );
          })()}
        </div>
      )}

      {/* Recent Network Alerts Stream */}
      <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h4 style={{ color: '#f8fafc', fontSize: '1.15rem', margin: 0 }}>
            Recent Network Security Flow Activity
          </h4>
          <span style={{ fontSize: '0.82rem', color: '#94a3b8' }}>Click any event below to read its safety explanation</span>
        </div>

        {loading ? (
          <p style={{ color: '#94a3b8' }}>Loading network security history...</p>
        ) : networkAlerts.length === 0 ? (
          <div style={{ padding: '2rem', textAlign: 'center', background: '#141f36', borderRadius: '8px', color: '#94a3b8' }}>
            No recent network events recorded yet. Active network monitoring is tracking packets in the background.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {networkAlerts.map((ev) => {
              const isAlert = ev.severity === 'CRITICAL' || ev.severity === 'HIGH';
              const isWarning = ev.severity === 'MEDIUM';
              const isSelected = selectedEvent && selectedEvent.id === ev.id;
              return (
                <div
                  key={ev.id}
                  onClick={() => setSelectedEvent(ev)}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    background: isSelected ? '#1e293b' : '#141f36',
                    padding: '0.9rem 1.25rem',
                    borderRadius: '8px',
                    borderLeft: `4px solid ${isAlert ? '#ef4444' : isWarning ? '#f59e0b' : '#10b981'}`,
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                  }}
                  title="Click to view detailed risk analysis"
                >
                  <div>
                    <div style={{ color: '#f8fafc', fontWeight: 600, fontSize: '0.92rem' }}>
                      {ev.event}
                    </div>
                    <div style={{ color: '#94a3b8', fontSize: '0.8rem', marginTop: '0.25rem', display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                      {ev.src_ip && <span>Source: <code>{ev.src_ip}</code></span>}
                      {ev.dest_ip && <span>Destination: <code>{ev.dest_ip}</code></span>}
                      {ev.indicators && ev.indicators.length > 0 && (
                        <span>Indicator: {ev.indicators.join(' • ')}</span>
                      )}
                    </div>
                  </div>
                  <div style={{ textAlign: 'right', minWidth: '130px' }}>
                    <span
                      style={{
                        fontSize: '0.75rem',
                        fontWeight: 700,
                        padding: '3px 8px',
                        borderRadius: '4px',
                        background: isAlert ? '#ef4444' : isWarning ? '#f59e0b' : '#10b981',
                        color: isWarning ? '#0f172a' : '#ffffff',
                        display: 'inline-block',
                        marginBottom: '0.2rem',
                      }}
                    >
                      {isAlert ? 'Threat Detected' : isWarning ? 'Suspicious' : 'Normal Traffic'}
                    </span>
                    <div style={{ color: '#94a3b8', fontSize: '0.78rem' }}>{ev.time}</div>
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
