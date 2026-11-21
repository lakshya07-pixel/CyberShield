/**
 * Threat schema types matching backend schemas.py and threat_engine definitions.
 */

export type ThreatType = 'intrusion' | 'phishing' | 'scam' | 'normal' | 'unknown';

export type SeverityLevel = 'low' | 'medium' | 'high' | 'critical';

export interface ThreatMetadata {
  source_ip?: string;
  url?: string;
  message?: string;
  [key: string]: unknown;
}

export type OperatingMode = 'DEMO_MODE' | 'PCAP_REPLAY' | 'LIVE_CAPTURE';

/**
 * Exact representation of create_threat_result() in schemas.py
 */
export interface ThreatResult {
  source: string;
  threat_type: ThreatType;
  severity: SeverityLevel;
  confidence: number; // Must be between 0.0 and 1.0
  indicators: string[];
  metadata: ThreatMetadata;
  timestamp?: string | null;
  /** Explicit UI label flag indicating demonstration fixture data */
  isDemoSample?: boolean;
  /** Explicit operating mode and provenance */
  operatingMode?: OperatingMode;
  provenance?: 'real_capture' | 'pcap_replay' | 'synthetic_telemetry' | 'demo_sample' | 'user_submitted';
}

/**
 * Helper to compute severity from confidence value using existing severity.py rules
 */
export function calculateSeverity(confidence: number): SeverityLevel {
  if (typeof confidence !== 'number' || isNaN(confidence)) {
    throw new Error('Confidence must be a valid number between 0 and 1.');
  }
  if (confidence < 0 || confidence > 1) {
    throw new Error('Confidence must be between 0 and 1.');
  }

  if (confidence >= 0.90) return 'critical';
  if (confidence >= 0.75) return 'high';
  if (confidence >= 0.50) return 'medium';
  return 'low';
}
