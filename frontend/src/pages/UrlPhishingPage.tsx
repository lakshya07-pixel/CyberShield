import React, { useState } from 'react';
import { ThreatResult } from '../types/threat';
import { PHISHING_SAMPLE } from '../fixtures/samples';
import { apiClient } from '../services/apiClient';
import { ThreatDetailsPanel } from '../components/advisory/ThreatDetailsPanel';
import { AdvisoryStatusPanel } from '../components/advisory/AdvisoryStatusPanel';
import { ErrorAlert } from '../components/common/ErrorAlert';
import { EmptyState } from '../components/common/EmptyState';

export const UrlPhishingPage: React.FC = () => {
  const [inputUrl, setInputUrl] = useState<string>('');
  const [validationError, setValidationError] = useState<string | null>(null);
  const [submissionNotice, setSubmissionNotice] = useState<string | null>(null);
  const [showDemoResult, setShowDemoResult] = useState<boolean>(false);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [threatData, setThreatData] = useState<ThreatResult | null>(null);

  const isValidUrl = (urlStr: string): boolean => {
    try {
      const parsed = new URL(urlStr);
      return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch {
      return false;
    }
  };

  const handleScanSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError(null);
    setSubmissionNotice(null);

    const trimmed = inputUrl.trim();
    if (!trimmed) {
      setValidationError('Please enter a URL to scan.');
      return;
    }

    if (!isValidUrl(trimmed)) {
      setValidationError('Please enter a valid HTTP or HTTPS URL (e.g., https://example.com/login).');
      return;
    }

    setIsScanning(true);
    setShowDemoResult(false);

    try {
      const response = await apiClient.scanUrl({ url: trimmed });
      if (!response.success || !response.data) {
        setSubmissionNotice(response.error ?? 'Phishing scan failed.');
        return;
      }
      setThreatData(response.data);
    } catch (err) {
      setSubmissionNotice(err instanceof Error ? err.message : 'Unknown scanning error');
    } finally {
      setIsScanning(false);
    }
  };

  const handleLoadDemo = () => {
    setValidationError(null);
    setSubmissionNotice(null);
    setInputUrl(PHISHING_SAMPLE.metadata.url || 'http://fake-login-example.com');
    setThreatData(PHISHING_SAMPLE);
    setShowDemoResult(true);
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <h2 className="page-title">URL Phishing Scanner</h2>
        <p className="page-subtitle">
          Domain reputation, lexical analysis, and credential harvesting threat detection.
        </p>
      </div>

      <div className="card-box mb-4">
        <h3 className="section-title">Analyze Suspicious URL</h3>
        <p className="text-muted">
          Input a suspicious web link to inspect phishing indicators and credential interception risk.
        </p>

        <form onSubmit={handleScanSubmit} className="url-form">
          <div className="form-group">
            <label htmlFor="url-input" className="form-label">
              Target URL to Scan
            </label>
            <div className="input-group">
              <input
                id="url-input"
                type="text"
                className="text-input"
                placeholder="https://example-security-alert.com/login"
                value={inputUrl}
                onChange={(e) => setInputUrl(e.target.value)}
              />
              <button type="submit" className="btn btn-primary" disabled={isScanning}>
                {isScanning ? 'Scanning...' : 'Scan URL'}
              </button>
            </div>
          </div>
        </form>

        {validationError && (
          <div className="mt-3">
            <ErrorAlert
              title="Input Validation Failed"
              message={validationError}
              onDismiss={() => setValidationError(null)}
            />
          </div>
        )}

        {submissionNotice && (
          <div className="mt-3">
            <ErrorAlert
              title="Backend Detection Unavailable"
              message={submissionNotice}
              contractNotice="POST /threats/scan-url with JSON body {'url': string} returning ThreatResult schema."
              onDismiss={() => setSubmissionNotice(null)}
            />
          </div>
        )}

        <div className="action-button-row mt-4">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={handleLoadDemo}
          >
            Inspect Sample Phishing Fixture
          </button>
        </div>
      </div>

      {/* Results Section */}
      {threatData ? (
        <div className="dual-panel-grid mt-4">
          <div className="left-panel">
            <ThreatDetailsPanel
              threat={threatData}
              fixtureName={showDemoResult ? "threat_engine/samples/phishing.json" : undefined}
            />
          </div>
          <div className="right-panel">
            <AdvisoryStatusPanel threat={threatData} />
          </div>
        </div>
      ) : (
        <EmptyState
          title="No Phishing Scans Run"
          description="Enter a URL above to validate format or load the verified sample fixture to view the threat format and advisory workflow."
          actionButton={{
            label: 'Load Phishing Sample Fixture',
            onClick: handleLoadDemo,
          }}
        />
      )}
    </div>
  );
};

