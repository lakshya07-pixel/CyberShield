import React, { useState } from 'react';
import { ThreatResult } from '../types/threat';
import { SCAM_SAMPLE } from '../fixtures/samples';
import { apiClient } from '../services/apiClient';
import { ThreatDetailsPanel } from '../components/advisory/ThreatDetailsPanel';
import { AdvisoryStatusPanel } from '../components/advisory/AdvisoryStatusPanel';
import { ErrorAlert } from '../components/common/ErrorAlert';
import { EmptyState } from '../components/common/EmptyState';

export const SmsScamPage: React.FC = () => {
  const [smsText, setSmsText] = useState<string>('');
  const [validationError, setValidationError] = useState<string | null>(null);
  const [submissionNotice, setSubmissionNotice] = useState<string | null>(null);
  const [showDemoResult, setShowDemoResult] = useState<boolean>(false);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [threatData, setThreatData] = useState<ThreatResult | null>(null);

  const MAX_SMS_CHARS = 1000;

  const handleScanSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError(null);
    setSubmissionNotice(null);

    const trimmed = smsText.trim();
    if (!trimmed) {
      setValidationError('Please enter SMS text to scan.');
      return;
    }

    if (trimmed.length > MAX_SMS_CHARS) {
      setValidationError(`SMS text exceeds maximum length of ${MAX_SMS_CHARS} characters.`);
      return;
    }

    setIsScanning(true);
    setShowDemoResult(false);

    try {
      const response = await apiClient.scanSms({ message: trimmed });
      if (!response.success || !response.data) {
        setSubmissionNotice(response.error ?? 'SMS scan failed.');
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
    setSmsText(SCAM_SAMPLE.metadata.message || 'Congratulations! You won ₹50,000. Pay ₹500 to claim.');
    setThreatData(SCAM_SAMPLE);
    setShowDemoResult(true);
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <h2 className="page-title">SMS Financial Scam Scanner</h2>
        <p className="page-subtitle">
          Text message fraud, fake prize claims, OTP theft, and social engineering threat detection.
        </p>
      </div>

      <div className="card-box mb-4">
        <h3 className="section-title">Analyze Suspicious SMS Message</h3>
        <p className="text-muted">
          Input an incoming SMS or instant message to analyze fraudulent claims, urgent payment triggers, or credential solicitation.
        </p>

        <form onSubmit={handleScanSubmit} className="sms-form">
          <div className="form-group">
            <div className="label-row">
              <label htmlFor="sms-input" className="form-label">
                SMS Content
              </label>
              <span className="char-counter">
                {smsText.length} / {MAX_SMS_CHARS} characters
              </span>
            </div>
            <textarea
              id="sms-input"
              rows={4}
              className="textarea-input"
              placeholder="e.g. Congratulations! You won ₹50,000 in the national lottery. Call immediately or transfer ₹500 fee to claim."
              value={smsText}
              onChange={(e) => setSmsText(e.target.value)}
            />
          </div>

          <div className="form-action-row">
            <button type="submit" className="btn btn-primary" disabled={isScanning}>
              {isScanning ? 'Scanning...' : 'Scan Message'}
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={handleLoadDemo}
            >
              Inspect Sample Scam Fixture
            </button>
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
              contractNotice="POST /threats/scan-sms with JSON body {'message': string} returning ThreatResult schema."
              onDismiss={() => setSubmissionNotice(null)}
            />
          </div>
        )}
      </div>

      {/* Results Section */}
      {threatData ? (
        <div className="dual-panel-grid mt-4">
          <div className="left-panel">
            <ThreatDetailsPanel
              threat={threatData}
              fixtureName={showDemoResult ? "threat_engine/samples/scam.json" : undefined}
            />
          </div>
          <div className="right-panel">
            <AdvisoryStatusPanel threat={threatData} />
          </div>
        </div>
      ) : (
        <EmptyState
          title="No SMS Messages Scanned"
          description="Enter a message above to validate content or load the verified sample fixture to view the threat format and advisory workflow."
          actionButton={{
            label: 'Load Scam Sample Fixture',
            onClick: handleLoadDemo,
          }}
        />
      )}
    </div>
  );
};

