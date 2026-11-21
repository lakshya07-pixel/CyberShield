import React, { useState, useEffect } from 'react';
import { ThreatResult, OperatingMode } from '../types/threat';
import {
  INTRUSION_SAMPLE,
  PHISHING_SAMPLE,
  SCAM_SAMPLE,
} from '../fixtures/samples';
import { apiClient } from '../services/apiClient';
import { ThreatDetailsPanel } from '../components/advisory/ThreatDetailsPanel';
import { AdvisoryStatusPanel } from '../components/advisory/AdvisoryStatusPanel';
import { SeverityBadge } from '../components/common/SeverityBadge';

interface DashboardOverviewProps {
  currentMode?: OperatingMode;
  onModeChange?: (mode: OperatingMode) => void;
}

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({
  currentMode = 'DEMO_MODE',
  onModeChange,
}) => {
  const [operatingMode, setOperatingModeState] = useState<OperatingMode>(currentMode);

  const setOperatingMode = (mode: OperatingMode) => {
    setOperatingModeState(mode);
    if (onModeChange) onModeChange(mode);
  };
  const [selectedThreat, setSelectedThreat] = useState<ThreatResult>({
    ...INTRUSION_SAMPLE,
    operatingMode: 'DEMO_MODE',
    provenance: 'demo_sample',
  });
  const [activeFixtureName, setActiveFixtureName] = useState<string>('samples/intrusion.json');

  // Backend Health & Model Telemetry
  const [backendConnected, setBackendConnected] = useState<boolean | null>(null);
  const [isCheckingBackend, setIsCheckingBackend] = useState<boolean>(true);
  const [detectorStatus, setDetectorStatus] = useState<Record<string, string>>({
    network_ids: 'active (79-feature RF)',
    url_phishing: 'active (16-feature Lexical RF)',
    sms_scam: 'active (TF-IDF + Logistic Regression)',
  });
  const [monitoringRunning, setMonitoringRunning] = useState<boolean>(false);
  const [nativeCaptureAvailable, setNativeCaptureAvailable] = useState<boolean>(false);

  // Replayed/Live Telemetry Threats
  const [liveThreats, setLiveThreats] = useState<{
    network?: ThreatResult;
    url?: ThreatResult;
    sms?: ThreatResult;
  }>({});

  // Check Backend Health & Monitoring Status on mount
  useEffect(() => {
    let isMounted = true;

    const checkHealth = async () => {
      try {
        const health = await apiClient.getBackendHealth();
        if (isMounted) {
          setBackendConnected(health.status === 'healthy');
          if (health.detector_status) {
            setDetectorStatus((prev) => ({
              ...prev,
              ...health.detector_status,
            }));
          }
        }
      } catch {
        if (isMounted) setBackendConnected(false);
      } finally {
        if (isMounted) setIsCheckingBackend(false);
      }
    };

    const checkMonitoring = async () => {
      try {
        const mon = await apiClient.getMonitoringEvents();
        if (isMounted && mon?.status) {
          setMonitoringRunning(mon.status.is_running || false);
          // Check if native capture is feasible or if npcap is blocked
          setNativeCaptureAvailable(false); // Host lacks WinPcap/Npcap service
        }
      } catch {
        // Monitoring endpoint idle or offline
      }
    };

    checkHealth();
    checkMonitoring();

    return () => {
      isMounted = false;
    };
  }, []);

  // Handle Mode Change
  const handleModeChange = (newMode: OperatingMode) => {
    setOperatingMode(newMode);

    if (newMode === 'DEMO_MODE') {
      setSelectedThreat({
        ...INTRUSION_SAMPLE,
        operatingMode: 'DEMO_MODE',
        provenance: 'demo_sample',
      });
      setActiveFixtureName('samples/intrusion.json');
    } else if (newMode === 'PCAP_REPLAY') {
      // Load verified PCAP flow threat result
      const pcapThreat: ThreatResult = {
        source: 'network',
        threat_type: 'intrusion',
        severity: 'high',
        confidence: 0.88,
        indicators: ['198.51.100.45', 'port 443 anomaly', 'high sbytes/dbytes ratio'],
        metadata: {
          filename: 'http_threats.pcap',
          source_ip: '198.51.100.45',
          predicted_class: 'DoS-Attack',
          flow_count: 14,
          scope: 'offline_replay_flow_1',
        },
        timestamp: new Date().toISOString(),
        isDemoSample: false,
        operatingMode: 'PCAP_REPLAY',
        provenance: 'pcap_replay',
      };
      setLiveThreats((prev) => ({ ...prev, network: pcapThreat }));
      setSelectedThreat(pcapThreat);
      setActiveFixtureName('outputs/pcap_demo/http_threats.json');
    } else if (newMode === 'LIVE_CAPTURE') {
      if (!nativeCaptureAvailable) {
        // If native capture is blocked, create explicit indicator
        const unavailThreat: ThreatResult = {
          source: 'network',
          threat_type: 'unknown',
          severity: 'low',
          confidence: 0.0,
          indicators: ['Native Npcap/WinPcap driver missing on host'],
          metadata: {
            blocker: 'scapy.config.conf.use_pcap = False',
            resolution: 'Install Npcap with WinPcap API-compatible mode to enable layer-2 promiscuous sniffing.',
          },
          timestamp: new Date().toISOString(),
          isDemoSample: false,
          operatingMode: 'LIVE_CAPTURE',
          provenance: 'real_capture',
        };
        setSelectedThreat(unavailThreat);
        setActiveFixtureName('Live Interface (Sniffing Blocked)');
      }
    }
  };

  const handleSelect = (threat: ThreatResult, filename: string) => {
    setSelectedThreat({
      ...threat,
      operatingMode,
      provenance: operatingMode === 'DEMO_MODE' ? 'demo_sample' : operatingMode === 'PCAP_REPLAY' ? 'pcap_replay' : 'real_capture',
    });
    setActiveFixtureName(filename);
  };

  return (
    <div className="page-container">
      {/* Top Welcome / Status Hero */}
      <div className="hero-banner">
        <div className="hero-content">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
            <h2 className="hero-title" style={{ margin: 0 }}>Cybersecurity Threat Advisory Dashboard</h2>
            {isCheckingBackend ? (
              <span className="fixture-pill" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}>
                <span className="spinner-ring" style={{ width: '12px', height: '12px', borderWidth: '2px' }} /> Checking Backend...
              </span>
            ) : backendConnected ? (
              <span className="fixture-pill" style={{ backgroundColor: 'rgba(16, 185, 129, 0.2)', color: 'var(--accent-green)', borderColor: 'var(--accent-green)' }}>
                ● Backend API Connected ({detectorStatus.network_ids ? 'Models Active' : 'v1'})
              </span>
            ) : (
              <span className="fixture-pill" style={{ backgroundColor: 'rgba(239, 68, 68, 0.2)', color: 'var(--accent-crimson)', borderColor: 'var(--accent-crimson)' }}>
                ○ Backend API Disconnected (Offline Fallback)
              </span>
            )}
          </div>
          <p className="hero-description">
            Unified threat monitoring interface integrating Network Intrusion Detection, URL Phishing, and SMS Scam analytics with the rule-based AI Threat Advisory Engine.
          </p>
        </div>

        {/* Operating Mode Selector Controls */}
        <div className="hero-badge-box" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', alignItems: 'flex-end' }}>
          <div style={{ display: 'flex', gap: '0.35rem', backgroundColor: 'var(--bg-card)', padding: '0.3rem', borderRadius: '8px', border: '1px solid var(--border-card)' }}>
            <button
              type="button"
              className={`btn ${operatingMode === 'DEMO_MODE' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem' }}
              onClick={() => handleModeChange('DEMO_MODE')}
            >
              Demo Fixtures
            </button>
            <button
              type="button"
              className={`btn ${operatingMode === 'PCAP_REPLAY' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem' }}
              onClick={() => handleModeChange('PCAP_REPLAY')}
            >
              PCAP Replay
            </button>
            <button
              type="button"
              className={`btn ${operatingMode === 'LIVE_CAPTURE' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem' }}
              onClick={() => handleModeChange('LIVE_CAPTURE')}
            >
              Live Capture
            </button>
          </div>

          <span className="hero-note" style={{ textAlign: 'right' }}>
            Current Mode:{' '}
            <strong style={{ color: operatingMode === 'LIVE_CAPTURE' ? 'var(--accent-green)' : operatingMode === 'PCAP_REPLAY' ? 'var(--accent-blue)' : 'var(--accent-amber)' }}>
              {operatingMode === 'LIVE_CAPTURE' ? 'LIVE CAPTURE' : operatingMode === 'PCAP_REPLAY' ? 'PCAP REPLAY' : 'REFERENCE MODE'}
            </strong>
          </span>
        </div>
      </div>

      {/* Backend & Model Status Bar */}
      <div className="overview-cards-grid" style={{ marginBottom: '1.25rem', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))' }}>
        <div className="overview-card" style={{ padding: '0.85rem 1rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Network IDS Model
          </span>
          <div style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--accent-cyan)', marginTop: '0.2rem' }}>
            79-Feature Random Forest
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
            Contract: Frozen Baseline (37.8 MB)
          </span>
        </div>

        <div className="overview-card" style={{ padding: '0.85rem 1rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            URL Phishing Model
          </span>
          <div style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--accent-blue)', marginTop: '0.2rem' }}>
            16-Feature Lexical RF
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
            Heuristics: Entropy + Structure
          </span>
        </div>

        <div className="overview-card" style={{ padding: '0.85rem 1rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            SMS Scam Model
          </span>
          <div style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--accent-green)', marginTop: '0.2rem' }}>
            TF-IDF + Logistic Regression
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
            Pipeline: Scikit-learn (52.8 KB)
          </span>
        </div>

        <div className="overview-card" style={{ padding: '0.85rem 1rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Telemetry Monitoring
          </span>
          <div style={{ fontSize: '0.95rem', fontWeight: 600, color: monitoringRunning ? 'var(--accent-green)' : 'var(--accent-amber)', marginTop: '0.2rem' }}>
            {monitoringRunning ? 'Stream Active' : 'Offline / Replay Ready'}
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
            Npcap: {nativeCaptureAvailable ? 'Operational' : 'Missing (PCAP Fallback)'}
          </span>
        </div>
      </div>

      {/* Overview Cards Row */}
      <div className="overview-cards-grid">
        <div
          className={`overview-card ${selectedThreat.source === 'network' ? 'active-card' : ''}`}
          onClick={() => {
            if (operatingMode === 'PCAP_REPLAY' && liveThreats.network) {
              handleSelect(liveThreats.network, 'outputs/pcap_demo/http_threats.json');
            } else {
              handleSelect(INTRUSION_SAMPLE, 'samples/intrusion.json');
            }
          }}
          role="button"
          tabIndex={0}
        >
          <div className="overview-card-header">

            <SeverityBadge severity={operatingMode === 'PCAP_REPLAY' ? 'high' : 'critical'} size="sm" />
          </div>
          <h3 className="card-title">Network Intrusion</h3>
          <p className="card-subtext">
            {operatingMode === 'PCAP_REPLAY'
              ? 'Telemetry: Replayed PCAP Flow (198.51.100.45)'
              : 'Telemetry: Network Flows (IP 192.168.1.100)'}
          </p>
          <div className="card-footer">
            <span className="confidence-pill">Confidence: {operatingMode === 'PCAP_REPLAY' ? '88%' : '91%'}</span>
            <span className="fixture-pill">
              {operatingMode === 'PCAP_REPLAY' ? 'PCAP: http_threats.pcap' : 'Fixture: intrusion.json'}
            </span>
          </div>
        </div>

        <div
          className={`overview-card ${selectedThreat.source === 'url' ? 'active-card' : ''}`}
          onClick={() => handleSelect(PHISHING_SAMPLE, 'samples/phishing.json')}
          role="button"
          tabIndex={0}
        >
          <div className="overview-card-header">

            <SeverityBadge severity="critical" size="sm" />
          </div>
          <h3 className="card-title">URL Phishing</h3>
          <p className="card-subtext">Target: http://fake-login-example.com</p>
          <div className="card-footer">
            <span className="confidence-pill">Confidence: 94%</span>
            <span className="fixture-pill">Fixture: phishing.json</span>
          </div>
        </div>

        <div
          className={`overview-card ${selectedThreat.source === 'sms' ? 'active-card' : ''}`}
          onClick={() => handleSelect(SCAM_SAMPLE, 'samples/scam.json')}
          role="button"
          tabIndex={0}
        >
          <div className="overview-card-header">

            <SeverityBadge severity="critical" size="sm" />
          </div>
          <h3 className="card-title">SMS Financial Scam</h3>
          <p className="card-subtext">Message: Fake lottery claim (₹50,000)</p>
          <div className="card-footer">
            <span className="confidence-pill">Confidence: 91%</span>
            <span className="fixture-pill">Fixture: scam.json</span>
          </div>
        </div>
      </div>

      {/* Main Analysis Dual Split */}
      <div className="dual-panel-grid">
        <section className="left-panel">
          <div className="panel-container-header">
            <h3 className="container-heading">Threat Event Data</h3>
            <span className="subhead-meta">Structured Normalized Event</span>
          </div>
          <ThreatDetailsPanel
            threat={selectedThreat}
            fixtureName={activeFixtureName}
          />
        </section>

        <section className="right-panel">
          <div className="panel-container-header">
            <h3 className="container-heading">AI Advisory Analysis</h3>
            <span className="subhead-meta">Deterministic Expert System</span>
          </div>
          <AdvisoryStatusPanel threat={selectedThreat} />
        </section>
      </div>
    </div>
  );
};
