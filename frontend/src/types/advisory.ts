import { ThreatResult } from './threat';

/**
 * AI Advisory output structure matching rules.py, recommendations.py, and advisory.py
 */
export interface AdvisoryResult {
  threat: ThreatResult;
  threatExplanation: string;
  indicatorExplanations: string[];
  recommendation: string;
  llamaStatus: {
    enabled: boolean;
    reason: string;
    notice: string;
  };
}

