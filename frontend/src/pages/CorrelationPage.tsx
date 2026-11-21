
import React, { useState } from 'react';
import { apiClient } from '../services/apiClient';
import type {
  CorrelationEventInput,
  CorrelationResult,
} from '../types/api';

type CorrelationEvent = {
  id: number;
  channel: string;
  indicator: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
};

const DEMO_CORRELATION_EVENTS: CorrelationEvent[] = [
  {
    id: 1,
    channel: 'Network IDS',
    indicator: '192.168.1.100',
    description: 'Unusual connection attempts',
    severity: 'CRITICAL',
  },
  {
    id: 2,
    channel: 'URL Phishing',
    indicator: 'fake-login-example.com',
    description: 'Suspicious login page',
    severity: 'HIGH',
  },
  {
    id: 3,
    channel: 'SMS Scam',
    indicator: 'Prize claim message',
    description: 'Urgent payment request',
    severity: 'HIGH',
  },
];

const SAMPLE_API_EVENTS: CorrelationEventInput[] = [
  {
    source: 'network',
    indicators: ['192.168.1.100', 'suspicious-host.example'],
    threat_type: 'Unusual connection attempts',
    severity: 'CRITICAL',
  },
  {
    source: 'url',
    indicators: ['192.168.1.100', 'fake-login-example.com'],
    threat_type: 'Suspicious login page',
    severity: 'HIGH',
  },
  {
    source: 'sms',
    indicators: ['fake-login-example.com'],
    threat_type: 'Suspicious payment message',
    severity: 'HIGH',
  },
];

const INITIAL_JSON = JSON.stringify(SAMPLE_API_EVENTS, null, 2);

const PRIORITY_CLASS: Record<string, string> = {
  CRITICAL: 'severity-critical',
  HIGH: 'severity-high',
  MEDIUM: 'severity-medium',
  LOW: 'severity-low',
  UNKNOWN: 'severity-unknown',
};

export const CorrelationPage: React.FC = () => {
  const [showDemoResults, setShowDemoResults] = useState(false);
  const [eventJson, setEventJson] = useState(INITIAL_JSON);
  const [apiResult, setApiResult] = useState<CorrelationResult | null>(null);
  const [apiError, setApiError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const runCorrelation = () => {
    setShowDemoResults(true);
  };

  const runApiCorrelation = async () => {
    setApiError('');
    setApiResult(null);

    let events: CorrelationEventInput[];

    try {
      const parsed: unknown = JSON.parse(eventJson);

      if (!Array.isArray(parsed)) {
        throw new Error(
          'The JSON input must be an array of event objects.'
        );
      }

      if (parsed.length === 0) {
        throw new Error('Add at least one event before submitting.');
      }

      if (parsed.length > 500) {
        throw new Error('A maximum of 500 events can be submitted.');
      }

      for (let index = 0; index < parsed.length; index += 1) {
        const event = parsed[index] as Record<string, unknown>;

        if (
          !event ||
          typeof event !== 'object' ||
          Array.isArray(event)
        ) {
          throw new Error(`Event ${index + 1} must be an object.`);
        }

        if (
          !['network', 'url', 'sms'].includes(
            String(event.source ?? '').trim().toLowerCase()
          )
        ) {
          throw new Error(
            `Event ${index + 1}: source must be network, url, or sms.`
          );
        }

        if (
          !Array.isArray(event.indicators) ||
          !event.indicators.every(
            (indicator) => typeof indicator === 'string'
          )
        ) {
          throw new Error(
            `Event ${index + 1}: indicators must be an array of strings.`
          );
        }

        if (event.indicators.length > 100) {
          throw new Error(
            `Event ${index + 1}: maximum 100 indicators allowed.`
          );
        }
      }

      events = parsed.map((item) => {
        const event = item as CorrelationEventInput;

        return {
          ...event,
          source: event.source.trim().toLowerCase() as
            | 'network'
            | 'url'
            | 'sms',
        };
      });
    } catch (error) {
      setApiError(
        error instanceof Error
          ? error.message
          : 'The event JSON is invalid.'
      );
      return;
    }

    setIsSubmitting(true);

    try {
      const result = await apiClient.analyzeCorrelation(events);
      setApiResult(result);
    } catch (error) {
      setApiError(
        error instanceof Error
          ? error.message
          : 'Unable to contact the correlation API.'
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  const clearApiResults = () => {
    setApiResult(null);
    setApiError('');
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <h2 className="page-title">Cross-Channel Attack Correlation</h2>
        <p className="page-subtitle">
          Investigate relationships between network, URL, and SMS threat events.
        </p>
      </div>

      <div className="integration-callout">
        <div className="callout-header">
          <strong>IMPORTANT — CORRELATION SCOPE</strong>
        </div>
        <p className="callout-text">
          The correlation API checks submitted event records for indicators
          shared across channels. It does not run the network, URL, or SMS
          detectors, ingest live telemetry, or prove that events belong to
          the same attacker or campaign.
        </p>
      </div>

      <section className="card-box">
        <h3 className="section-title">Backend Correlation Engine</h3>
        <p className="text-muted">
          Submit event records as JSON. The backend identifies exact,
          case-insensitive indicator matches appearing in at least two
          different channels and derives priority from supplied severity values.
        </p>

        <div className="form-group mt-4">
          <label htmlFor="correlation-event-json">
            Event records (JSON array)
          </label>
          <textarea
            id="correlation-event-json"
            className="form-control"
            rows={18}
            value={eventJson}
            onChange={(event) => setEventJson(event.target.value)}
            spellCheck={false}
            disabled={isSubmitting}
            aria-describedby="correlation-json-help"
            style={{
              width: '100%',
              fontFamily: 'monospace',
              fontSize: '0.9rem',
              resize: 'vertical',
            }}
          />
          <p id="correlation-json-help" className="text-muted mt-2">
            Each event requires a source of network, url, or sms and an
            indicators array containing strings. The initial values are
            synthetic test events. Replace them with records you want to
            analyze.
          </p>
        </div>

        <div className="action-button-row mt-4">
          <button
            type="button"
            className="btn btn-primary"
            onClick={runApiCorrelation}
            disabled={isSubmitting}
          >
            {isSubmitting ? 'Analyzing Events...' : 'Analyze Submitted Events'}
          </button>

          <button
            type="button"
            className="btn btn-secondary"
            onClick={clearApiResults}
            disabled={isSubmitting}
          >
            Clear API Results
          </button>

          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => setEventJson(INITIAL_JSON)}
            disabled={isSubmitting}
          >
            Restore Sample JSON
          </button>
        </div>

        {apiError && (
          <div className="integration-callout mt-4" role="alert">
            <div className="callout-header">
              <strong>Correlation Request Failed</strong>
            </div>
            <p className="callout-text">{apiError}</p>
          </div>
        )}
      </section>

      {apiResult && (
        <section className="card-box">
          <div className="panel-container-header">
            <h3 className="container-heading">
              Backend Correlation Results
            </h3>
            <span className="status-badge-demo">SUBMITTED EVENTS</span>
          </div>

          <p className="text-muted">
            Analysis time: {new Date(apiResult.generated_at).toLocaleString()}
          </p>

          <div className="dashboard-grid mt-4">
            <div className="card-box">
              <h4 className="section-title">Events Submitted</h4>
              <p className="metric-value">{apiResult.input_event_count}</p>
            </div>
            <div className="card-box">
              <h4 className="section-title">Shared Indicators</h4>
              <p className="metric-value">
                {apiResult.correlated_group_count}
              </p>
            </div>
          </div>

          {apiResult.correlated_groups.length === 0 ? (
            <div className="integration-callout mt-4">
              <div className="callout-header">
                <strong>No Cross-Channel Matches Found</strong>
              </div>
              <p className="callout-text">
                No submitted indicator was found in two or more distinct
                channels. This does not prove that the events are unrelated.
              </p>
            </div>
          ) : (
            <div className="mt-4">
              {apiResult.correlated_groups.map((group, index) => (
                <div
                  className="card-box"
                  key={`${group.shared_indicator}-${index}`}
                >
                  <div className="panel-container-header">
                    <h4 className="section-title">
                      Shared Indicator: {group.shared_indicator}
                    </h4>
                    <span className="status-badge-demo">
                      {group.channels.length} CHANNELS
                    </span>
                  </div>

                  <div className="integration-callout mt-3">
                    <div className="callout-header">
                      <strong>Incident Priority</strong>
                    </div>

                    <p>
                      <span
                        className={
                          PRIORITY_CLASS[group.priority] ??
                          PRIORITY_CLASS.UNKNOWN
                        }
                      >
                        {group.priority}
                      </span>
                    </p>

                    <p className="callout-text">
                      {group.priority_explanation}
                    </p>

                    <p className="callout-text">
                      <strong>Supplied severities:</strong>{' '}
                      {(group.severity_values_used ?? []).length > 0
                        ? (group.severity_values_used ?? []).join(', ')
                        : 'None supplied'}
                    </p>
                  </div>

                  <p className="mt-3">
                    <strong>Channels:</strong>{' '}
                    {group.channels.join(', ')}
                  </p>

                  <p>
                    <strong>Events involved:</strong> {group.event_count}
                  </p>

                  <div className="integration-callout mt-3">
                    <div className="callout-header">
                      <strong>What this means</strong>
                    </div>
                    <p className="callout-text">
                      The indicator <strong>{group.shared_indicator}</strong>{' '}
                      appeared in {group.channels.join(' and ')} event
                      records. This is why the correlation engine grouped
                      these events together.
                    </p>
                    <p className="callout-text">
                      <strong>For a non-technical user:</strong> The same
                      piece of information appeared in more than one type
                      of security event, so the events may be related and
                      are worth reviewing together.
                    </p>
                  </div>

                  <h5 className="mt-4">Evidence</h5>
                  <div className="table-responsive">
                    <table>
                      <thead>
                        <tr>
                          <th>Event Index</th>
                          <th>Channel</th>
                        </tr>
                      </thead>
                      <tbody>
                        {group.evidence.map((evidence, evidenceIndex) => (
                          <tr
                            key={`${evidence.event_index}-${evidence.source}-${evidenceIndex}`}
                          >
                            <td>{evidence.event_index + 1}</td>
                            <td>{evidence.source}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  <p className="callout-text mt-3">
                    {group.interpretation}
                  </p>
                </div>
              ))}
            </div>
          )}

          <div className="integration-callout mt-4">
            <p className="callout-text">{apiResult.notice}</p>
          </div>
        </section>
      )}

      <section className="card-box">
        <h3 className="section-title">Synthetic Demo</h3>
        <p className="text-muted">
          Review predefined example events separately. These sample events
          are not sent to the backend by the demo button.
        </p>

        <div className="action-button-row mt-4">
          <button
            type="button"
            className="btn btn-primary"
            onClick={runCorrelation}
          >
            Run Demo Correlation
          </button>

          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => setShowDemoResults(false)}
          >
            Clear Demo Results
          </button>
        </div>
      </section>

      {showDemoResults && (
        <section className="card-box">
          <div className="panel-container-header">
            <h3 className="container-heading">Sample Event Review</h3>
            <span className="status-badge-demo">DEMO RESULTS</span>
          </div>

          <p className="callout-text mb-4">
            These three synthetic events are displayed for demonstration.
            No shared indicator has been verified between them, so this
            demo does not declare a correlated incident.
          </p>

          <div className="table-responsive">
            <table>
              <thead>
                <tr>
                  <th>Channel</th>
                  <th>Indicator</th>
                  <th>Event Description</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {DEMO_CORRELATION_EVENTS.map((event) => (
                  <tr key={event.id}>
                    <td>{event.channel}</td>
                    <td>{event.indicator}</td>
                    <td>{event.description}</td>
                    <td>
                      <span
                        className={`severity-${event.severity.toLowerCase()}`}
                      >
                        {event.severity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
};
