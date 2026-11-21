
import React, { useState } from 'react';
import { ThreatResult } from '../types/threat';
import { NetworkPredictionExplanation } from '../types/api';
import { INTRUSION_SAMPLE } from '../fixtures/samples';
import { apiClient } from '../services/apiClient';
import { ThreatDetailsPanel } from '../components/advisory/ThreatDetailsPanel';
import { AdvisoryStatusPanel } from '../components/advisory/AdvisoryStatusPanel';
import { ErrorAlert } from '../components/common/ErrorAlert';
import { EmptyState } from '../components/common/EmptyState';

export const NetworkIdsPage: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [requestError, setRequestError] = useState<string | null>(null);
  const [showDemoResult, setShowDemoResult] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [threatData, setThreatData] = useState<ThreatResult | null>(null);

  const [analysisSummary, setAnalysisSummary] = useState<{
    filename: string;
    flowCount: number;
    predictedClass: string;
    scope: string;
  } | null>(null);

  // Real feature contributions returned by the perturbation-based explainability module
  const [explanation, setExplanation] = useState<NetworkPredictionExplanation>({
    available: false,
    top_features: [],
    unavailable_reason:
      'The model returned a prediction, but a verified feature-contribution explanation is not available.',
  });

  const ALLOWED_EXTENSIONS = ['.pcap', '.pcapng'];
  const MAX_FILE_SIZE_MB = 25;

  const handleFileChange = (
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    setFileError(null);
    setRequestError(null);
    setAnalysisSummary(null);
    setThreatData(null);
    setShowDemoResult(false);

    const file = event.target.files?.[0];

    if (!file) {
      setSelectedFile(null);
      return;
    }

    const extension = file.name
      .slice(file.name.lastIndexOf('.'))
      .toLowerCase();

    if (!ALLOWED_EXTENSIONS.includes(extension)) {
      setFileError(
        'Unsupported file format. Upload a .pcap or .pcapng capture. CSV and .cap files are not accepted by the current worker.'
      );
      setSelectedFile(null);
      event.target.value = '';
      return;
    }

    if (file.size === 0) {
      setFileError('The selected file is empty.');
      setSelectedFile(null);
      event.target.value = '';
      return;
    }

    if (file.size > MAX_FILE_SIZE_MB * 1024 * 1024) {
      setFileError(
        `The file exceeds the worker's 25 MiB upload limit.`
      );
      setSelectedFile(null);
      event.target.value = '';
      return;
    }

    setSelectedFile(file);
  };

  const handleAnalyze = async () => {
    if (!selectedFile || isAnalyzing) {
      return;
    }

    setIsAnalyzing(true);
    setRequestError(null);
    setFileError(null);
    setThreatData(null);
    setAnalysisSummary(null);
    setShowDemoResult(false);

    try {
      const response = await apiClient.analyzePcap({
        pcapFile: selectedFile,
        featureMode: 'pcap_auto',
      });

      if (!response.success || !response.data) {
        setRequestError(
          response.error ?? 'Network IDS analysis failed.'
        );
        return;
      }

      const threat = response.data;
      const metadata = threat.metadata;

      const predictedClass =
        typeof metadata.predicted_class === 'string'
          ? metadata.predicted_class
          : threat.threat_type.toUpperCase();

      const flowCount =
        typeof metadata.flow_count === 'number'
          ? metadata.flow_count
          : 1;

      setThreatData(threat);
      setAnalysisSummary({
        filename: selectedFile.name,
        flowCount,
        predictedClass,
        scope: 'First flow prediction',
      });

      // Map explainability from advisory/metadata if present
      const explainData = metadata?.explainability as {
        method?: string;
        predicted_class?: string;
        predicted_class_probability?: number;
        summary?: string;
        features?: Array<{
          feature: string;
          value: number;
          probability_change: number;
          effect: string;
          description: string;
        }>;
      } | undefined;

      if (explainData && Array.isArray(explainData.features) && explainData.features.length > 0) {
        setExplanation({
          available: true,
          method: explainData.method,
          target_class: explainData.predicted_class,
          prediction: {
            label: explainData.predicted_class || predictedClass,
            confidence: explainData.predicted_class_probability ?? threat.confidence,
            model_name: 'RandomForestBaseline (79-feature contract)',
          },
          top_features: explainData.features.map((f) => ({
            feature_name: f.feature,
            feature_value: f.value,
            contribution: f.probability_change,
            direction: f.effect === 'supports_prediction' ? 'supports_prediction' : 'opposes_prediction',
            explanation: f.description,
          })),
          plain_language_summary: explainData.summary,
        });
      } else {
        setExplanation({
          available: false,
          top_features: [],
          unavailable_reason: 'Feature attribution was not produced for this flow.',
        });
      }
    } catch (error) {
      setRequestError(
        error instanceof Error
          ? error.message
          : 'Unexpected error during Network IDS analysis.'
      );
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleLoadDemo = () => {
    setSelectedFile(null);
    setFileError(null);
    setRequestError(null);
    setAnalysisSummary(null);
    setThreatData(INTRUSION_SAMPLE);
    setShowDemoResult(true);
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <h2 className="page-title">
          Network Intrusion Detection System (IDS)
        </h2>
        <p className="page-subtitle">
          Offline packet-capture analysis using the integrated 79-feature
          network classification model.
        </p>
      </div>

      <div className="card-box mb-4">
        <h3 className="section-title">
          Upload 📁
        </h3>

        <p className="text-muted">
          Upload a PCAP or PCAPNG file for offline flow extraction and
          model inference. This feature analyzes an uploaded capture;
          it does not continuously sniff live network traffic.
        </p>

        <div className="upload-dropzone">
          <input
            type="file"
            id="pcap-upload-input"
            accept=".pcap,.pcapng"
            onChange={handleFileChange}
            className="file-input-hidden"
            disabled={isAnalyzing}
          />

          <label
            htmlFor="pcap-upload-input"
            className="dropzone-label"
          >
            <span className="dropzone-icon">📁</span>

            <span className="dropzone-main-text">
              {selectedFile
                ? selectedFile.name
                : 'Choose a PCAP or PCAPNG file'}
            </span>

            <span className="dropzone-sub-text">
              Accepted: .pcap, .pcapng Â· Maximum 25 MiB
            </span>
          </label>
        </div>

        {selectedFile && (
          <div className="file-info-badge">
            <span>
              Selected: <strong>{selectedFile.name}</strong> (
              {(selectedFile.size / 1024).toFixed(1)} KB)
            </span>
          </div>
        )}

        {fileError && (
          <div className="mt-3">
            <ErrorAlert
              title="File Validation Error"
              message={fileError}
              onDismiss={() => setFileError(null)}
            />
          </div>
        )}

        {requestError && (
          <div className="mt-3">
            <ErrorAlert
              title="Network IDS Analysis Failed"
              message={requestError}
              onDismiss={() => setRequestError(null)}
            />
          </div>
        )}

        <div className="integration-callout mt-4">
          <div className="callout-header">

            <strong>Analysis Mode</strong>
          </div>

          <p className="callout-text">
            Analysis runs locally through the isolated Network IDS
            worker. Results depend on the uploaded capture, flow
            extraction, and model predictions. Model accuracy has not
            been established by the successful upload test alone.
          </p>
        </div>

        <div className="action-button-row mt-4">
          <button
            type="button"
            className={`btn ${!selectedFile || isAnalyzing ? 'btn-disabled' : 'btn-primary'}`}
            onClick={handleAnalyze}
            disabled={!selectedFile || isAnalyzing}
          >
            {isAnalyzing
              ? 'Analyzing Capture...'
              : 'Analyze PCAP'}
          </button>

          <button
            type="button"
            className="btn btn-secondary"
            onClick={handleLoadDemo}
            disabled={isAnalyzing}
          >
            Inspect Sample Intrusion Fixture (DEMO DATA)
          </button>
        </div>

        {isAnalyzing && (
          <p className="text-muted mt-3" role="status">
            Extracting network flows and running model inference.
            Large captures may take some time.
          </p>
        )}
      </div>

      {analysisSummary && threatData && !showDemoResult && (
        <div className="card-box mt-4">
          <h3 className="section-title">
            Actual Model Prediction
          </h3>

          <p>
            <strong>Capture:</strong> {analysisSummary.filename}
          </p>

          <p>
            <strong>Flows extracted:</strong>{' '}
            {analysisSummary.flowCount}
          </p>

          <p>
            <strong>Predicted class:</strong>{' '}
            {analysisSummary.predictedClass}
          </p>

          <p>
            <strong>Model confidence:</strong>{' '}
            {(threatData.confidence * 100).toFixed(2)}%
          </p>

          <p className="text-muted">
            The detailed threat panel below represents the first flow's
            prediction only. Other flows in the capture may have different
            classifications.
          </p>

          {analysisSummary.predictedClass.toUpperCase() === 'BENIGN' && (
            <p>
              The model classified the first flow as BENIGN. This is a
              model prediction, not a guarantee that the traffic is safe.
            </p>
          )}
        </div>
      )}

      {threatData && (
        <div className="dual-panel-grid mt-4">
          <div className="left-panel">
            <ThreatDetailsPanel
              threat={threatData}
              fixtureName={
                showDemoResult
                  ? 'threat_engine/samples/intrusion.json'
                  : undefined
              }
            />
          </div>

          <div className="right-panel">
            <AdvisoryStatusPanel threat={threatData} />
          </div>
        </div>
      )}

      {!threatData && !isAnalyzing && (
        <EmptyState
          title="No Detection Results to Display"
          description="Upload a PCAP capture and select Analyze PCAP, or load the clearly labeled sample fixture for a demonstration."
          actionButton={{
            label: 'Load Intrusion Sample Fixture',
            onClick: handleLoadDemo,
          }}
        />
      )}
    </div>
  );
};
