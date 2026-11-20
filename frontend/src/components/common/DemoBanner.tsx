import React from 'react';

interface DemoBannerProps {
  sourceFile?: string;
  details?: string;
  operatingMode?: 'DEMO_MODE' | 'PCAP_REPLAY' | 'LIVE_CAPTURE';
  provenance?: 'real_capture' | 'pcap_replay' | 'synthetic_telemetry' | 'demo_sample' | 'user_submitted';
}

export const DemoBanner: React.FC<DemoBannerProps> = ({
  sourceFile,
  details,
  operatingMode = 'DEMO_MODE',
  provenance,
}) => {
  if (provenance === 'user_submitted') {
    return (
      <div className="demo-sample-banner" style={{ borderColor: 'var(--accent-cyan)', backgroundColor: 'rgba(0, 229, 255, 0.08)' }}>
        <div className="demo-tag">
          <span className="demo-indicator-pill" style={{ backgroundColor: 'var(--accent-cyan)', color: '#000' }}>
            USER SUBMITTED — ACTIVE ML SCAN
          </span>
        </div>
        <div className="demo-message">
          <p>
            <strong>Live Model Execution:</strong> Real payload evaluated on-premise by trained ML detection engine.
          </p>
          {details && <p className="demo-subtext">{details}</p>}
        </div>
      </div>
    );
  }

  if (operatingMode === 'LIVE_CAPTURE') {
    return (
      <div className="demo-sample-banner" style={{ borderColor: 'var(--accent-green)', backgroundColor: 'rgba(16, 185, 129, 0.1)' }}>
        <div className="demo-tag">
          <span className="demo-indicator-pill" style={{ backgroundColor: 'var(--accent-green)', color: '#000' }}>
            LIVE CAPTURE — REAL NETWORK TRAFFIC
          </span>
        </div>
        <div className="demo-message">
          <p>
            <strong>Active Native Capture:</strong> Live telemetry captured from network interface and processed by the ML detection pipeline.
          </p>
          {details && <p className="demo-subtext">{details}</p>}
        </div>
      </div>
    );
  }

  if (operatingMode === 'PCAP_REPLAY') {
    return (
      <div className="demo-sample-banner" style={{ borderColor: 'var(--accent-blue)', backgroundColor: 'rgba(56, 189, 248, 0.1)' }}>
        <div className="demo-tag">
          <span className="demo-indicator-pill" style={{ backgroundColor: 'var(--accent-blue)', color: '#000' }}>
            PCAP REPLAY — REPLAYED CAPTURE
          </span>
        </div>
        <div className="demo-message">
          <p>
            <strong>Deterministic Replay:</strong> Processed from ingested PCAP flow capture via offline ML inference pipeline.
          </p>
          {details && <p className="demo-subtext">{details}</p>}
        </div>
      </div>
    );
  }

  return (
    <div className="demo-sample-banner">
      <div className="demo-tag">
        <span className="demo-indicator-pill">REFERENCE TELEMETRY</span>
      </div>
      <div className="demo-message">
        <p>
          <strong>Notice:</strong> This display is populated using baseline reference telemetry.
          Switch to PCAP Replay or trigger real detectors for live telemetry.
        </p>
        {details && <p className="demo-subtext">{details}</p>}
      </div>
    </div>
  );
};


