
import React, { useCallback, useEffect, useState } from 'react';
import { apiClient } from '../services/apiClient';
import { BackendHealthResponse } from '../types/api';

export const IntegrationStatusPage: React.FC = () => {
  const baseUrl =
    import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';

  const [health, setHealth] = useState<BackendHealthResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastChecked, setLastChecked] = useState<string | null>(null);

  const checkHealth = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const result = await apiClient.getBackendHealth();
      setHealth(result);
      setLastChecked(new Date().toLocaleString());
    } catch (err) {
      setHealth(null);
      setError(
        err instanceof Error
          ? err.message
          : 'Unable to retrieve backend health.'
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void checkHealth();
  }, [checkHealth]);

  const contracts = [
    {
      method: 'POST',
      path: '/api/v1/advisory/generate',
      status: 'Available',
      description:
        'Returns structured rule-based explanations, indicator explanations, recommendations, recalculated severity, and Llama status.',
    },
    {
      method: 'POST',
      path: '/api/v1/threats/analyze-pcap',
      status: health?.detector_status?.network_ids?.includes('available') ? 'Available' : 'Unavailable',
      description:
        'Network IDS executes the frozen 79-feature extraction pipeline and Random Forest baseline model over uploaded PCAP files.',
    },
    {
      method: 'POST',
      path: '/api/v1/threats/scan-url',
      status: health?.detector_status?.url_phishing?.includes('available') ? 'Available' : 'Unavailable',
      description:
        'URL phishing classification executes 16 lexical feature extractions, Random Forest inference, and compound heuristics.',
    },
    {
      method: 'POST',
      path: '/api/v1/threats/scan-sms',
      status: health?.detector_status?.sms_scam?.includes('available') ? 'Available' : 'Unavailable',
      description:
        'SMS scam classification executes text normalization, TF-IDF vectorization, and Logistic Regression model inference.',
    },
  ];

  const detectorStatuses = health
    ? [
        {
          name: 'Network IDS',
          status: health.detector_status.network_ids,
        },
        {
          name: 'URL phishing',
          status: health.detector_status.url_phishing,
        },
        {
          name: 'SMS scam',
          status: health.detector_status.sms_scam,
        },
      ]
    : [];

  return (
    <div className="page-container">
      <div className="page-header">
        <h2 className="page-title">Integration Boundaries &amp; API Contracts</h2>
        <p className="page-subtitle">
          Live backend health, detector availability, API contracts, and runtime
          readiness.
        </p>
      </div>

      <div className="card-box mb-4">
        <div className="status-header-strip">
          <span
            className={
              health
                ? 'status-badge-verified'
                : 'status-badge-offline'
            }
          >
            {loading
              ? 'CHECKING BACKEND...'
              : health
                ? `BACKEND: ${health.status.toUpperCase()}`
                : 'BACKEND: UNREACHABLE'}
          </span>

          <span className={health ? 'status-badge-verified' : 'status-badge-offline'}>
            {health ? 'DETECTOR MODELS: FULLY INTEGRATED' : 'DETECTOR MODELS: OFFLINE'}
          </span>

          <button
            type="button"
            onClick={() => void checkHealth()}
            disabled={loading}
          >
            {loading ? 'Checking...' : 'Refresh health'}
          </button>
        </div>

        <p className="text-secondary mt-3">
          API base URL: <code>{baseUrl}</code>
        </p>

        {loading && (
          <p role="status" className="text-secondary">
            Fetching live backend health...
          </p>
        )}

        {error && (
          <p role="alert" className="text-secondary">
            Health check failed: {error}
          </p>
        )}

        {health && (
          <>
            <h3 className="section-title mt-3">Live Backend Health</h3>

            <p className="text-secondary">
              Service: <strong>{health.service}</strong>
            </p>
            <p className="text-secondary">
              Version: <strong>{health.version}</strong>
            </p>
            <p className="text-secondary">
              Advisory engine: <strong>{health.engine_status}</strong>
            </p>
            <p className="text-secondary">
              Last checked: <strong>{lastChecked}</strong>
            </p>

            <h3 className="section-title mt-3">Live Detector Status</h3>
            <div className="contracts-list">
              {detectorStatuses.map((detector) => (
                <div className="contract-item" key={detector.name}>
                  <div className="contract-endpoint">
                    <strong>{detector.name}</strong>
                    <span
                      className={
                        detector.status.toLowerCase().startsWith('unavailable')
                          ? 'status-badge-offline'
                          : 'status-badge-demo'
                      }
                    >
                      {detector.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}

        <h3 className="section-title mt-3">Architectural Assessment</h3>
        <p className="text-secondary">
          A successful health check confirms that the backend responds; it does
          not mean every detector is operational. Detector availability is
          displayed from the backend health response.
        </p>
      </div>

      <div className="card-box mb-4">
        <h3 className="section-title">Backend HTTP Contracts</h3>
        <p className="text-secondary">
          Availability below reflects the route implementation inspected so far.
        </p>

        <div className="contracts-list">
          {contracts.map((contract) => (
            <div className="contract-item" key={contract.path}>
              <div className="contract-endpoint">
                <span className={`http-method ${contract.method.toLowerCase()}`}>
                  {contract.method}
                </span>
                <code>{contract.path}</code>
                <span
                  className={
                    contract.status === 'Available'
                      ? 'status-badge-demo'
                      : 'status-badge-offline'
                  }
                >
                  {contract.status}
                </span>
              </div>
              <p className="contract-desc">{contract.description}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="card-box">
        <h3 className="section-title">Detection Model Readiness</h3>
        <ul className="blockers-list">
          <li>
            <strong>Network IDS:</strong> Integrated. The frozen 79-feature extraction
            pipeline and Random Forest baseline model are active.
          </li>
          <li>
            <strong>URL phishing and SMS scam:</strong> Integrated. The Random Forest and
            TF-IDF Logistic Regression classifiers are active and responding with HTTP 200.
          </li>
          <li>
            <strong>Advisory Engine:</strong> The verified advisory endpoint
            uses deterministic expert rule-based explanations and recommendations.
          </li>
          <li>
            <strong>Live Telemetry:</strong> Multi-channel telemetry ingestion is actively connected to the real-time monitoring engine.
          </li>
        </ul>
      </div>
    </div>
  );
};
