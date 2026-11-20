
import React from 'react';
import type { ThreatResult } from '../../types/threat';
import type { AdvisoryResult } from '../../types/advisory';
import { apiClient } from '../../services/apiClient';
import { SeverityBadge } from '../common/SeverityBadge';
import { RecommendationCard } from './RecommendationCard';

interface AdvisoryStatusPanelProps {
  threat: ThreatResult;
}

export const AdvisoryStatusPanel: React.FC<AdvisoryStatusPanelProps> = ({
  threat,
}) => {
  const [advisory, setAdvisory] = React.useState<AdvisoryResult | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    let cancelled = false;

    const loadAdvisory = async () => {
      setLoading(true);
      setError(null);
      setAdvisory(null);

      try {
        const response = await apiClient.generateAdvisory(threat);

        if (cancelled) return;

        if (response.success && response.data) {
          setAdvisory(response.data);
        } else {
          setError(response.error ?? 'Unable to generate backend advisory.');
        }
      } catch (err: unknown) {
        if (cancelled) return;

        setError(
          err instanceof Error
            ? err.message
            : 'Unexpected error while requesting the advisory.'
        );
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    void loadAdvisory();

    return () => {
      cancelled = true;
    };
  }, [threat]);

  return (
    <div className="advisory-status-panel">
      <div className="advisory-terminal-header">
        <div className="terminal-dots">
          <span className="dot red" />
          <span className="dot yellow" />
          <span className="dot green" />
        </div>
        <div className="terminal-title">CYBER AI ADVISORY ENGINE</div>
      </div>

      <div className="advisory-body">
        {loading && (
          <div className="advisory-card" role="status">
            <h4 className="card-subtitle">Generating advisory</h4>
            <p className="detection-rationale">
              Requesting a rule-based advisory from the backend...
            </p>
          </div>
        )}

        {!loading && error && (
          <div className="advisory-card" role="alert">
            <h4 className="card-subtitle">Backend advisory unavailable</h4>
            <p className="detection-rationale">{error}</p>
            <p className="text-secondary">
              This panel does not substitute a demo advisory when the backend
              request fails.
            </p>
          </div>
        )}

        {!loading && advisory && (
          <>
            <div className="advisory-summary-row">
              <div>
                <span className="advisory-label">Threat Classification:</span>
                <span className="advisory-value uppercase-bold">
                  {advisory.threat.threat_type}
                </span>
              </div>

              <div>
                <span className="advisory-label">
                  Engine Calculated Severity:
                </span>
                <SeverityBadge
                  severity={advisory.threat.severity}
                  size="md"
                />
              </div>

              <div>
                <span className="advisory-label">Confidence:</span>
                <span className="advisory-value accent-cyan">
                  {Math.round(advisory.threat.confidence * 100)}% (
                  {advisory.threat.confidence.toFixed(2)})
                </span>
              </div>
            </div>

            <div className="advisory-card">
              <h4 className="card-subtitle">Why was this detected?</h4>
              <p className="detection-rationale">
                {advisory.threatExplanation}
              </p>
              <span className="source-tag">
                Source: backend rule-based advisory API
              </span>
            </div>

            <div className="advisory-card">
              <h4 className="card-subtitle">Analyzed Indicator Context</h4>
              {advisory.indicatorExplanations.length > 0 ? (
                <ul className="advisory-indicator-list">
                  {advisory.indicatorExplanations.map((item, idx) => (
                    <li key={`${idx}-${item}`}>
                      <span className="bullet">↳</span> {item}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-secondary">
                  The backend returned no indicator explanations.
                </p>
              )}
            </div>

            <RecommendationCard
              threatType={advisory.threat.threat_type}
              customRecommendation={advisory.recommendation}
            />
          </>
        )}
      </div>
    </div>
  );
};
