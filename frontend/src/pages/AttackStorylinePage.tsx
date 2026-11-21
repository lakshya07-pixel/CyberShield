import React, { useState } from 'react';
import { apiClient } from '../services/apiClient';
import type { CorrelationEventInput } from '../types/api';

type StoryStage = {
  stage_number: number;
  source: string;
  title: string;
  description: string;
  timestamp: string;
  severity: string;
  confidence: number;
  indicators: string[];
  reason: string;
};

type StorylineData = {
  incident_id: string;
  overall_severity: string;
  confidence: number;
  created_at: string;
  sha256_signature: string;
  channels: string[];
  shared_indicators: Array<{
    indicator_type: string;
    indicator_value: string;
    participating_sources: string[];
  }>;
  stages: StoryStage[];
  simple_explanation: {
    what_happened: string;
    why_suspicious: string;
    evidence: string[];
    what_affected: string;
    next_steps: string[];
  };
};

const DEFAULT_EVENTS: CorrelationEventInput[] = [
  {
    source: 'sms',
    indicators: ['http://sbi-online-banking-kyc.com/update-pan.html'],
    threat_type: 'Urgent KYC Verification Scam',
    severity: 'HIGH',
    timestamp: '2026-11-01T00:10:00Z',
  },
  {
    source: 'url',
    indicators: ['host:sbi-online-banking-kyc.com'],
    threat_type: 'Phishing Credential Harvester',
    severity: 'HIGH',
    timestamp: '2026-11-01T00:11:15Z',
  },
  {
    source: 'network',
    indicators: ['host:sbi-online-banking-kyc.com'],
    threat_type: 'C2 Outbound Traffic / DNS Resolution',
    severity: 'CRITICAL',
    timestamp: '2026-11-01T00:13:30Z',
  },
];

export const AttackStorylinePage: React.FC = () => {
  const [eventJson, setEventJson] = useState(JSON.stringify(DEFAULT_EVENTS, null, 2));
  const [storylines, setStorylines] = useState<StorylineData[] | null>(null);
  const [activeStorylineIndex, setActiveStorylineIndex] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showJsonEditor, setShowJsonEditor] = useState(false);
  const [expandedStages, setExpandedStages] = useState<Record<number, boolean>>({});

  const toggleStage = (stageNum: number) => {
    setExpandedStages((prev) => ({
      ...prev,
      [stageNum]: !prev[stageNum],
    }));
  };

  const generateStoryline = async () => {
    setLoading(true);
    setError(null);
    try {
      const parsed = JSON.parse(eventJson);
      if (!Array.isArray(parsed) || parsed.length === 0) {
        throw new Error('Please provide a non-empty array of security events in JSON format.');
      }
      const res = await apiClient.generateStoryline(parsed);
      if (!res.success) {
        throw new Error('Failed to generate attack storyline.');
      }
      if (res.incident_count === 0) {
        setStorylines([]);
      } else {
        setStorylines(res.storylines);
        setActiveStorylineIndex(0);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'An error occurred while analyzing events.');
    } finally {
      setLoading(false);
    }
  };

  const activeStory = storylines && storylines.length > 0 ? storylines[activeStorylineIndex] : null;

  return (
    <div className="page-container">
      <div className="page-header">
        <h2 className="page-title">Cross-Channel Attack Storyline</h2>
        <p className="page-subtitle">
          Reconstruct chronological, evidence-backed attack narratives across SMS, Phishing URLs, and Network IDS telemetry.
        </p>
      </div>

      <div className="integration-callout mb-4">
        <div className="callout-header">
          <strong>VERIFIED ATTACK RECONSTRUCTION ENGINE</strong>
        </div>
        <p className="callout-text">
          This module reconstructs authentic multi-stage attack progressions by linking verified detector outputs (SMS lure → Phishing domain → Outbound flow) through deterministic indicator normalization and SHA-256 tamper-evident integrity seals.
        </p>
      </div>

      <div className="card-box mb-4">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <div>
            <h3 className="section-title" style={{ margin: 0 }}>Attack Sequence Analyzer</h3>
            <p className="text-muted" style={{ margin: '0.25rem 0 0' }}>
              Run correlation on detector events to build a step-by-step forensic progression.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setShowJsonEditor(!showJsonEditor)}
            >
              {showJsonEditor ? 'Hide Event JSON' : 'Edit Event Records'}
            </button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={generateStoryline}
              disabled={loading}
            >
              {loading ? 'Reconstructing Attack...' : 'Reconstruct Attack Storyline'}
            </button>
          </div>
        </div>

        {showJsonEditor && (
          <div className="form-group mt-3">
            <label htmlFor="storyline-events-json">Input Security Events (JSON)</label>
            <textarea
              id="storyline-events-json"
              className="form-control"
              rows={12}
              value={eventJson}
              onChange={(e) => setEventJson(e.target.value)}
              spellCheck={false}
              style={{ fontFamily: 'monospace', fontSize: '0.88rem' }}
            />
          </div>
        )}

        {error && (
          <div className="alert alert-danger mt-3" role="alert">
            <strong>Error: </strong> {error}
          </div>
        )}
      </div>

      {storylines && storylines.length === 0 && (
        <div className="card-box text-center py-5">
          <h4>No Correlated Attack Incident Found</h4>
          <p className="text-muted">
            The submitted events do not share any common indicators across 2 or more channels.
          </p>
        </div>
      )}

      {activeStory && (
        <>
          {/* Incident Overview Card */}
          <div className="card-box mb-4" style={{ borderLeft: '4px solid #ef4444' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
              <div>
                <span className="status-badge-demo" style={{ background: '#ef4444', color: '#fff', marginRight: '0.5rem' }}>
                  {activeStory.overall_severity} SEVERITY
                </span>
                <span className="text-muted" style={{ fontSize: '0.9rem' }}>
                  Incident ID: <strong>{activeStory.incident_id}</strong>
                </span>
                <h3 style={{ marginTop: '0.5rem', marginBottom: '0.25rem' }}>
                  Coordinated Multi-Stage Campaign ({activeStory.channels.join(' → ')})
                </h3>
                <p className="text-muted" style={{ margin: 0 }}>
                  Confidence: <strong>{(activeStory.confidence * 100).toFixed(1)}%</strong> | Generated:{' '}
                  {activeStory.created_at}
                </p>
              </div>

              {activeStory.sha256_signature && (
                <div style={{ textAlign: 'right', fontSize: '0.85rem' }}>
                  <span className="badge-verified" style={{ background: '#10b981', color: '#fff', padding: '0.2rem 0.6rem', borderRadius: '4px' }}>
                    [VERIFIED] SHA-256 SEAL VERIFIED
                  </span>
                  <div className="text-muted mt-1" style={{ fontFamily: 'monospace' }}>
                    {activeStory.sha256_signature.slice(0, 24)}...
                  </div>
                </div>
              )}
            </div>

            {/* Simple-Language Explanation Callout - High contrast dark styling */}
            <div
              className="executive-incident-summary"
              style={{
                marginTop: '1.25rem',
                padding: '1.25rem',
                backgroundColor: 'var(--bg-card, #141f36)',
                borderRadius: '8px',
                border: '1px solid var(--border-card, #243552)',
                color: 'var(--text-primary, #f8fafc)',
              }}
            >
              <h4 style={{ margin: '0 0 0.75rem 0', fontSize: '1.05rem', color: 'var(--accent-cyan, #00e5ff)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span>Executive Incident Summary</span>
                <span style={{ fontSize: '0.78rem', color: 'var(--text-muted, #94a3b8)', fontWeight: 'normal' }}>
                  (Forensic Multi-Channel Briefing)
                </span>
              </h4>
              <p style={{ margin: '0 0 0.6rem 0', fontSize: '0.95rem', color: 'var(--text-primary, #f8fafc)', lineHeight: 1.5 }}>
                <strong style={{ color: 'var(--accent-blue, #38bdf8)' }}>What happened:</strong> {activeStory.simple_explanation.what_happened}
              </p>
              <p style={{ margin: '0 0 0.6rem 0', fontSize: '0.95rem', color: 'var(--text-primary, #f8fafc)', lineHeight: 1.5 }}>
                <strong style={{ color: 'var(--accent-amber, #f59e0b)' }}>Why it is suspicious:</strong> {activeStory.simple_explanation.why_suspicious}
              </p>
              <div style={{ margin: '0 0 0.6rem 0', fontSize: '0.95rem', color: 'var(--text-primary, #f8fafc)', display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.4rem' }}>
                <strong style={{ color: 'var(--accent-crimson, #ef4444)' }}>Shared IOCs:</strong>
                {activeStory.simple_explanation.evidence.map((ioc) => (
                  <span
                    key={ioc}
                    style={{
                      fontFamily: 'var(--font-mono, monospace)',
                      background: 'rgba(239, 68, 68, 0.15)',
                      color: '#fca5a5',
                      border: '1px solid rgba(239, 68, 68, 0.3)',
                      padding: '0.15rem 0.5rem',
                      borderRadius: '4px',
                      fontSize: '0.85rem',
                    }}
                  >
                    {ioc}
                  </span>
                ))}
              </div>
              <p style={{ margin: '0', fontSize: '0.95rem', color: 'var(--text-primary, #f8fafc)', lineHeight: 1.5 }}>
                <strong style={{ color: 'var(--accent-green, #10b981)' }}>Recommended Next Steps:</strong>{' '}
                {activeStory.simple_explanation.next_steps.join(' ')}
              </p>
            </div>
          </div>

          {/* Chronological Timeline Stages */}
          <section className="card-box">
            <h3 className="section-title">Chronological Attack Progression Timeline</h3>
            <div className="storyline mt-4">
              {activeStory.stages.map((stage) => {
                const isExpanded = !!expandedStages[stage.stage_number];
                return (
                  <article className="storyline-event" key={stage.stage_number}>
                    <div className="storyline-track">
                      <span className={`storyline-node severity-node-${stage.severity.toLowerCase()}`}>
                        {stage.stage_number}
                      </span>
                      {stage.stage_number < activeStory.stages.length && (
                        <span className="storyline-connector" />
                      )}
                    </div>

                    <div className="storyline-card" style={{ flex: 1 }}>
                      <div className="storyline-card-header">
                        <span className="storyline-time">{stage.timestamp}</span>
                        <span className={`severity-${stage.severity.toLowerCase()}`}>
                          {stage.severity}
                        </span>
                      </div>

                      <p className="storyline-channel" style={{ textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                        Source: <strong>{stage.source}</strong> | Confidence: {(stage.confidence * 100).toFixed(1)}%
                      </p>
                      <h4>{stage.title}</h4>
                      <p>{stage.description}</p>

                      <div style={{ marginTop: '0.5rem', fontSize: '0.85rem', color: '#64748b' }}>
                        <strong>Rationale:</strong> {stage.reason}
                      </div>

                      <div style={{ marginTop: '0.75rem' }}>
                        <button
                          type="button"
                          className="btn btn-sm btn-outline-secondary"
                          onClick={() => toggleStage(stage.stage_number)}
                          style={{ fontSize: '0.8rem', padding: '0.2rem 0.5rem' }}
                        >
                          {isExpanded ? 'Hide Forensic Evidence' : 'Show Forensic Evidence'}
                        </button>

                        {isExpanded && (
                          <div style={{ marginTop: '0.5rem', padding: '0.5rem', background: '#f1f5f9', borderRadius: '4px', fontSize: '0.85rem' }}>
                            <div><strong>Raw Sensor Indicators:</strong></div>
                            <ul style={{ margin: '0.25rem 0 0', paddingLeft: '1.2rem' }}>
                              {stage.indicators.map((ind, i) => (
                                <li key={i} style={{ fontFamily: 'monospace' }}>{ind}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    </div>
                  </article>
                );
              })}
            </div>
          </section>
        </>
      )}

      {/* Fallback Initial View if Not Run */}
      {!storylines && (
        <div className="card-box text-center py-5">
          <h3>Ready to Reconstruct Attack Sequence</h3>
          <p className="text-muted" style={{ maxWidth: '600px', margin: '0.5rem auto 1.5rem' }}>
            Click the <strong>&quot;Reconstruct Attack Storyline&quot;</strong> button above to run the correlation engine against the sample multi-channel events and observe the live chronologically linked progression.
          </p>
          <button
            type="button"
            className="btn btn-primary"
            onClick={generateStoryline}
            disabled={loading}
          >
            {loading ? 'Reconstructing Attack...' : 'Reconstruct Attack Storyline Now'}
          </button>
        </div>
      )}
    </div>
  );
};
