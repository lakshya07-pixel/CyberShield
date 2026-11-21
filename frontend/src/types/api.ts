
import { ThreatResult } from './threat';
import { AdvisoryResult } from './advisory';

/**
 * API Contracts requested from Backend / Detection Team
 */

export interface NetworkAnalyzeRequest {
  pcapFile: File;
  /** Frozen 79-feature extraction contract (pending Person 1 merge) */
  featureMode?: '79_features_raw' | 'pcap_auto';
}

export interface UrlScanRequest {
  url: string;
}

export interface SmsScanRequest {
  message: string;
}

export interface GenerateAdvisoryRequest {
  threat: ThreatResult;
}

/**
 * Standard unified API response wrapper
 */
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  code?: string;
  timestamp: string;
}

export type NetworkAnalyzeResponse = ApiResponse<ThreatResult>;
export type UrlScanResponse = ApiResponse<ThreatResult>;
export type SmsScanResponse = ApiResponse<ThreatResult>;
export type AdvisoryResponse = ApiResponse<AdvisoryResult>;

/**
 * Live response from GET /api/v1/health
 */
export interface BackendHealthResponse {
  status: string;
  version: string;
  service: string;
  engine_status: string;
  detector_status: {
    network_ids: string;
    url_phishing: string;
    sms_scam: string;
  };
  llama_status: {
    enabled: boolean;
    reason: string;
    runtime_verified: boolean;
  };
}

/**
 * Stage RT2: Explainable AI data contracts.
 *
 * These types describe evidence returned by a real detector and
 * explanation method. They do not calculate predictions or feature
 * contributions themselves.
 */

/** Classification returned by the integrated Network IDS model. */
export interface NetworkModelPrediction {
  label: string;
  confidence: number;
  model_name: string;
  model_version?: string;
}

/** One feature's contribution to a particular model prediction. */
export interface FeatureContribution {
  feature_name: string;
  feature_value: number | string;
  contribution: number;
  direction: 'supports_prediction' | 'opposes_prediction';
  explanation: string;
}

/**
 * Explanation for an individual network-flow prediction.
 * Contributions must come from the actual model explanation method.
 */
export interface NetworkPredictionExplanation {
  available: boolean;
  method?: string;
  target_class?: string;
  prediction?: NetworkModelPrediction;
  top_features: FeatureContribution[];
  plain_language_summary?: string;
  unavailable_reason?: string;
}

/**
 * Supported channels for cross-channel correlation.
 */
export type CorrelationChannel = 'network' | 'url' | 'sms';

/**
 * Event submitted to the correlation API.
 */
export interface CorrelationEventInput {
  source: CorrelationChannel;
  indicators: string[];
  threat_type?: string;
  severity?: string;
  confidence?: number;
  metadata?: Record<string, unknown>;
  timestamp?: string | null;
}

/**
 * Evidence identifying which submitted event contained an indicator.
 * event_index is zero-based.
 */
export interface CorrelationEvidence {
  event_index: number;
  source: CorrelationChannel;
}

/**
 * Correlated events sharing an indicator across multiple channels.
 *
 * Priority is derived from supplied severity values only.
 * UNKNOWN means no valid severity was supplied for the group.
 */
export interface CorrelatedGroup {
  shared_indicator: string;
  channels: CorrelationChannel[];
  event_indexes: number[];
  event_count: number;
  evidence: CorrelationEvidence[];
  priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  severity_values_used: string[];
  priority_explanation: string;
  interpretation: string;
}

/**
 * Response from POST /api/v1/correlation/analyze.
 */
export interface CorrelationResult {
  success: boolean;
  mode: 'submitted_events';
  generated_at: string;
  input_event_count: number;
  correlated_group_count: number;
  correlated_groups: CorrelatedGroup[];
  notice: string;
}
