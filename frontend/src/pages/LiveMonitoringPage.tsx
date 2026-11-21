import React, { useState, useEffect, useRef } from 'react';
import { apiClient } from '../services/apiClient';

type TelemetryEvent = {
  id: number;
  time: string;
  timestamp?: string;
  source: string;
  event: string;
  event_type?: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  status: string;
  provenance: string;
  indicators?: string[];
};

type CaptureSubsystemInfo = {
  available: boolean;
  provider: string | null;
  interface_count: number;
  reason?: string;
  remedy?: string;
};

const DEMO_EVENTS: TelemetryEvent[] = [
  {
    id: 1,
    time: '20:56:02',
    timestamp: '2026-11-01T00:56:02Z',
    source: 'network',
    event: 'Unusual network connection attempts',
    severity: 'CRITICAL',
    status: 'Needs investigation',
    provenance: 'demo_sample',
    indicators: ['SYN flood ratio: 8.5', 'Port 443'],
  },
  {
    id: 2,
    time: '20:55:41',
    timestamp: '2026-11-01T00:55:41Z',
    source: 'url',
    event: 'Suspicious phishing URL with brand spoofing',
    severity: 'HIGH',
    status: 'Demo event',
    provenance: 'demo_sample',
    indicators: ['host:sbi-online-banking-kyc.com'],
  },
  {
    id: 3,
    time: '20:55:13',
    timestamp: '2026-11-01T00:55:13Z',
    source: 'sms',
    event: 'Urgent payment / prize claim scam message',
    severity: 'HIGH',
    status: 'Demo event',
    provenance: 'demo_sample',
    indicators: ['keyword: urgent verify KYC'],
  },
];

export const LiveMonitoringPage: React.FC = () => {
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [filter, setFilter] = useState('ALL');
  const [channelFilter, setChannelFilter] = useState('ALL');
  const [isLiveActive, setIsLiveActive] = useState<boolean>(false);
  const [backendConnected, setBackendConnected] = useState<boolean>(true);
  const [captureInfo, setCaptureInfo] = useState<CaptureSubsystemInfo | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<TelemetryEvent | null>(null);
  const [stats, setStats] = useState({
    network_events: 0,
    url_threats: 0,
    sms_threats: 0,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0,
    last_event_time: null as string | null,
  });
  const pollingTimerRef = useRef<number | null>(null);

  // Poll for monitoring events and subsystem status
  const fetchStatusAndEvents = async () => {
    try {
      // 1. Always fetch events from backend buffer
      const eventsRes = await apiClient.getMonitoringEvents(100);
      if (eventsRes?.success && Array.isArray(eventsRes.events)) {
        setEvents(eventsRes.events as TelemetryEvent[]);
      }

      // 2. Get subsystem status & sync stats
      const statusRes = await apiClient.getMonitoringStatus();
      if (statusRes) {
        setBackendConnected(true);
        if (statusRes.capture_subsystem) {
          setCaptureInfo(statusRes.capture_subsystem);
        }
        if (statusRes.stats) {
          setStats({
            network_events: statusRes.stats.network_events || 0,
            url_threats: statusRes.stats.url_threats || 0,
            sms_threats: statusRes.stats.sms_threats || 0,
            critical_count: statusRes.stats.critical_count || 0,
            high_count: statusRes.stats.high_count || 0,
            medium_count: statusRes.stats.medium_count || 0,
            low_count: statusRes.stats.low_count || 0,
            last_event_time: statusRes.stats.last_event_time,
          });
        }
      }
    } catch {
      setBackendConnected(false);
    }
  };

  useEffect(() => {
    // Initial fetch on mount regardless of streaming status
    fetchStatusAndEvents();

    // Always poll at a steady 3s interval so events from other tabs/detectors show up
    pollingTimerRef.current = window.setInterval(fetchStatusAndEvents, isLiveActive ? 2000 : 4000);

    return () => {
      if (pollingTimerRef.current !== null) {
        window.clearInterval(pollingTimerRef.current);
      }
    };
  }, [isLiveActive]);

  const toggleLiveMonitoring = async () => {
    if (isLiveActive) {
      try {
        await apiClient.stopMonitoring();
      } catch {
        // Safe fallback
      }
      setIsLiveActive(false);
    } else {
      try {
        await apiClient.startMonitoring();
        setIsLiveActive(true);
        fetchStatusAndEvents();
      } catch {
        setBackendConnected(false);
      }
    }
  };

  const resetDemo = () => {
    setIsLiveActive(false);
    setEvents([...DEMO_EVENTS]);
    setStats({
      network_events: 1,
      url_threats: 1,
      sms_threats: 1,
      critical_count: 1,
      high_count: 2,
      medium_count: 0,
      low_count: 0,
      last_event_time: '2026-11-01T00:56:02Z',
    });
    setSelectedEvent(null);
  };

  // Filter events
  const visibleEvents = events.filter((ev) => {
    const matchSeverity = filter === 'ALL' || ev.severity === filter;
    const matchChannel = channelFilter === 'ALL' || ev.source.toLowerCase() === channelFilter.toLowerCase();
    return matchSeverity && matchChannel;
  });

  return (
    <div className="page-container">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 className="page-title">Live Security Monitoring</h2>
          <p className="page-subtitle">
            Unified real-time telemetry engine tracking Network IDS, URL Phishing, and SMS Scam activity.
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <span className={`status-badge-${backendConnected ? 'verified' : 'unverified'}`} style={{ fontSize: '0.85rem' }}>
            {backendConnected ? '● BACKEND ONLINE' : '○ BACKEND OFFLINE (RECONNECTING)'}
          </span>
          <button
            type="button"
            className={`btn ${isLiveActive ? 'btn-danger' : 'btn-primary'}`}
            onClick={toggleLiveMonitoring}
            style={{ minWidth: '160px' }}
          >
            {isLiveActive ? '⏹ Stop Monitoring' : '▶ Start Monitoring'}
          </button>
        </div>
      </div>

      {/* Operating Mode & Capture Subsystem Notification */}
      <div className={`integration-callout ${isLiveActive ? 'callout-success' : ''} mb-4`}>
        <div className="callout-header">
          <strong>
            {isLiveActive ? 'REAL-TIME TELEMETRY STREAM ACTIVE' : 'MONITORING STREAM IDLE'}
          </strong>
        </div>
        <p className="callout-text" style={{ margin: '0.25rem 0 0' }}>
          {isLiveActive
            ? 'Background multi-channel telemetry engine is actively streaming events with authentic provenance tags.'
            : 'Click "Start Monitoring" to launch the background event stream worker. Live detector submissions are automatically ingested into the feed below.'}
        </p>

        {/* Npcap Host Status Warning */}
        {captureInfo && !captureInfo.available && (
          <div style={{ marginTop: '0.6rem', padding: '0.5rem 0.75rem', background: '#fffbeb', border: '1px solid #fef3c7', borderRadius: '4px', fontSize: '0.85rem', color: '#92400e' }}>
            <strong>Native Live Packet Capture Notice: </strong>
            {captureInfo.reason} <em>(PCAP Replay and Synthetic Telemetry remain 100% operational)</em>.
          </div>
        )}
      </div>

      {/* Overview Metric Cards */}
      <div className="overview-cards-grid mb-4">
        <div className="overview-card">
          <h3 className="card-title">Network Events</h3>
          <p className="card-subtext">PCAP Replay &amp; Flows</p>
          <div className="card-footer">
            <span className="confidence-pill">{stats.network_events} event(s)</span>
          </div>
        </div>

        <div className="overview-card">
          <h3 className="card-title">URL Threats</h3>
          <p className="card-subtext">Phishing &amp; Brand Spoofing</p>
          <div className="card-footer">
            <span className="confidence-pill">{stats.url_threats} threat(s)</span>
          </div>
        </div>

        <div className="overview-card">
          <h3 className="card-title">SMS Threats</h3>
          <p className="card-subtext">Smishing &amp; Financial Fraud</p>
          <div className="card-footer">
            <span className="confidence-pill">{stats.sms_threats} threat(s)</span>
          </div>
        </div>

        <div className="overview-card">
          <h3 className="card-title">Threat Verdicts</h3>
          <p className="card-subtext">Critical &amp; High Priority</p>
          <div className="card-footer">
            <span className="confidence-pill" style={{ color: '#ef4444', fontWeight: 600 }}>
              {stats.critical_count + stats.high_count} alert(s)
            </span>
          </div>
        </div>
      </div>

      {/* Filter and Control Bar */}
      <div className="card-box mb-4" style={{ padding: '1rem' }}>
        <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <div>
            <label htmlFor="mon-channel-filter" style={{ marginRight: '0.5rem', fontWeight: 600, fontSize: '0.9rem' }}>Channel:</label>
            <select
              id="mon-channel-filter"
              className="form-control"
              value={channelFilter}
              onChange={(e) => setChannelFilter(e.target.value)}
              style={{ display: 'inline-block', width: 'auto', padding: '0.3rem 0.6rem' }}
            >
              <option value="ALL">All Channels</option>
              <option value="network">Network IDS</option>
              <option value="url">URL Phishing</option>
              <option value="sms">SMS Scam</option>
            </select>
          </div>

          <div>
            <label htmlFor="mon-severity-filter" style={{ marginRight: '0.5rem', fontWeight: 600, fontSize: '0.9rem' }}>Severity:</label>
            <select
              id="mon-severity-filter"
              className="form-control"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              style={{ display: 'inline-block', width: 'auto', padding: '0.3rem 0.6rem' }}
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={resetDemo}
            style={{ marginLeft: 'auto' }}
          >
            Reset to Sample Data
          </button>
        </div>
      </div>

      {/* Selected Event Detail Modal / Drawer */}
      {selectedEvent && (
        <section className="card-box mb-4" style={{ borderLeft: '4px solid #ef4444', background: '#f8fafc' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <h4 style={{ margin: 0, color: '#1e293b' }}>
                Event Inspection #{selectedEvent.id}: {selectedEvent.source.toUpperCase()} Threat
              </h4>
              <p className="text-muted" style={{ margin: '0.25rem 0 0.5rem', fontSize: '0.88rem' }}>
                Timestamp: <strong>{selectedEvent.timestamp || selectedEvent.time}</strong> | Provenance:{' '}
                <span className="badge-demo" style={{ textTransform: 'uppercase' }}>{selectedEvent.provenance}</span>
              </p>
            </div>
            <button
              type="button"
              className="btn btn-sm btn-outline-secondary"
              onClick={() => setSelectedEvent(null)}
            >
              &times; Close
            </button>
          </div>

          <div style={{ marginTop: '0.5rem' }}>
            <strong>Event Description:</strong>
            <p style={{ margin: '0.25rem 0' }}>{selectedEvent.event}</p>
            {selectedEvent.indicators && selectedEvent.indicators.length > 0 && (
              <div style={{ marginTop: '0.5rem' }}>
                <strong>Observed Indicators:</strong>
                <ul style={{ margin: '0.2rem 0 0', paddingLeft: '1.2rem', fontFamily: 'monospace', fontSize: '0.85rem' }}>
                  {selectedEvent.indicators.map((ind, i) => (
                    <li key={i}>{ind}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </section>
      )}

      {/* Security Event Feed Table */}
      <section className="card-box">
        <div className="panel-container-header">
          <h3 className="container-heading">Live Telemetry Feed ({visibleEvents.length} events)</h3>
          <span className="text-muted" style={{ fontSize: '0.85rem' }}>
            Last Update: {stats.last_event_time ? new Date(stats.last_event_time).toLocaleTimeString() : 'N/A'}
          </span>
        </div>

        <div className="table-responsive">
          <table className="telemetry-table">
            <thead>
              <tr>
                <th style={{ width: '15%' }}>Time</th>
                <th style={{ width: '15%' }}>Channel</th>
                <th style={{ width: '38%' }}>Event Description</th>
                <th style={{ width: '12%' }}>Severity</th>
                <th style={{ width: '12%' }}>Provenance</th>
                <th style={{ width: '8%', textAlign: 'center' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {visibleEvents.map((event) => (
                <tr key={event.id} onClick={() => setSelectedEvent(event)} style={{ cursor: 'pointer' }}>
                  <td className="telemetry-cell-time">{event.time}</td>
                  <td className="telemetry-cell-channel">
                    <span className="badge-channel">{event.source.toUpperCase()}</span>
                  </td>
                  <td className="telemetry-cell-desc">{event.event}</td>
                  <td>
                    <span className={`severity-${event.severity.toLowerCase()}`}>
                      {event.severity}
                    </span>
                  </td>
                  <td>
                    <span className="confidence-pill" style={{ textTransform: 'uppercase', fontSize: '0.78rem' }}>
                      {event.provenance || 'telemetry'}
                    </span>
                  </td>
                  <td className="telemetry-cell-action">
                    <button
                      type="button"
                      className="btn btn-sm btn-outline-secondary"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedEvent(event);
                      }}
                      style={{ fontSize: '0.78rem', padding: '0.2rem 0.5rem' }}
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))}

              {visibleEvents.length === 0 && (
                <tr>
                  <td colSpan={6} className="text-center text-muted py-4">
                    No security events match the current filter criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
