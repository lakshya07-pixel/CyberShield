import React from 'react';
import { ThreatResult } from '../../types/threat';
import { SeverityBadge } from '../common/SeverityBadge';
import { ConfidenceMeter } from '../common/ConfidenceMeter';
import { DemoBanner } from '../common/DemoBanner';
import { ThreatIndicatorsList } from './ThreatIndicatorsList';

interface ThreatDetailsPanelProps {
  threat: ThreatResult;
  fixtureName?: string;
}

export const ThreatDetailsPanel: React.FC<ThreatDetailsPanelProps> = ({
  threat,
  fixtureName,
}) => {
  return (
    <div className="threat-details-panel">
      <DemoBanner
        sourceFile={fixtureName}
        operatingMode={threat.operatingMode || (threat.isDemoSample ? 'DEMO_MODE' : 'PCAP_REPLAY')}
        provenance={threat.provenance}
        details={
          threat.provenance === 'user_submitted'
            ? 'Processed via trained on-premise classifier with real-time heuristic validation.'
            : threat.operatingMode === 'LIVE_CAPTURE'
            ? 'Processed via Scapy native interface sniffer and 79-feature Network IDS model.'
            : threat.operatingMode === 'PCAP_REPLAY'
            ? 'Processed via offline PCAP packet ingestion and Person 1 ML inference engine.'
            : 'Pre-recorded reference baseline telemetry for SOC validation.'
        }
      />

      <div className="panel-header">
        <div>
          <div className="threat-header-meta">
            <span className="source-pill">Source: {threat.source.toUpperCase()}</span>
            {threat.timestamp && (
              <span className="timestamp-pill">{threat.timestamp}</span>
            )}
          </div>
          <h3 className="threat-title">
            Threat Classification:{' '}
<span className="highlight-text">
  {typeof threat.metadata.predicted_class === 'string'
    ? threat.metadata.predicted_class.toUpperCase()
    : threat.threat_type.toUpperCase()}
</span>
          </h3>
        </div>
        <div>
          <SeverityBadge severity={threat.severity} size="lg" />
        </div>
      </div>

      <div className="metrics-grid">
        <div className="metric-card">
          <span className="metric-label">Detection Confidence</span>
          <ConfidenceMeter confidence={threat.confidence} />
        </div>

        <div className="metric-card">
          <span className="metric-label">Assigned Severity</span>
          <div className="severity-display-row">
            <SeverityBadge severity={threat.severity} size="md" />
            <span>Derived from confidence {`(${(threat.confidence * 100).toFixed(0)}%)`}</span>
          </div>
        </div>
      </div>

      {/* Metadata Section */}
      <div className="metadata-section">
        <h4 className="section-subtitle">Event Metadata</h4>
        {Object.keys(threat.metadata).length > 0 ? (
          <div className="metadata-table-wrapper">
            <table className="metadata-table">
              <thead>
                <tr>
                  <th>Field Key</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(threat.metadata).map(([key, val]) => (
                  <tr key={key}>
                    <td className="meta-key">{key}</td>
                    <td className="meta-val">{String(val)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-muted">No additional metadata recorded.</p>
        )}
      </div>

      {/* Indicators Section */}
      <ThreatIndicatorsList indicators={threat.indicators} />
    </div>
  );
};
