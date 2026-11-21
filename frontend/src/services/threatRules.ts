import { ThreatResult, ThreatType, calculateSeverity } from '../types/threat';
import { AdvisoryResult } from '../types/advisory';

/**
 * Matches rules.py: get_threat_explanation(threat_type, indicators)
 */
export function getThreatExplanation(threatType: ThreatType): string {
  if (threatType === 'phishing') {
    return 'This may be a phishing attempt designed to steal sensitive information.';
  } else if (threatType === 'scam') {
    return 'This message may be a scam attempting to trick the user into sending money or personal information.';
  } else if (threatType === 'intrusion') {
    return 'Suspicious network activity was detected and may indicate an unauthorized intrusion.';
  } else if (threatType === 'normal') {
    return 'Routine benign network activity was observed. Traffic characteristics are within normal operational baseline.';
  } else {
    return 'A potentially suspicious activity was detected.';
  }
}

/**
 * Matches rules.py: get_indicator_explanation(indicators)
 */
export function getIndicatorExplanation(indicators: string[]): string[] {
  return indicators.map((indicator) => {
    if (indicator.toLowerCase().includes('normal') || indicator.toLowerCase().includes('benign')) {
      return `Observed baseline: ${indicator}`;
    }
    return `Suspicious indicator: ${indicator}`;
  });
}

/**
 * Matches recommendations.py: get_recommendation(threat_type)
 */
export function getRecommendation(threatType: ThreatType): string {
  if (threatType === 'phishing') {
    return 'Do not open the link or enter your username, password, or other credentials.';
  } else if (threatType === 'scam') {
    return 'Do not send money or share OTPs, passwords, or personal information.';
  } else if (threatType === 'intrusion') {
    return 'Check the affected device and block or investigate suspicious network activity.';
  } else if (threatType === 'normal') {
    return 'No threat-specific mitigation is required. Traffic is within normal operational parameters.';
  } else {
    return 'Avoid interacting with the suspicious activity and investigate it further.';
  }
}

/**
 * Generates verified advisory structure matching advisory.py logic
 */
export function buildAdvisoryFromThreat(threat: ThreatResult): AdvisoryResult {
  const recalculatedSeverity =
    threat.threat_type === 'normal' ? 'low' : calculateSeverity(threat.confidence);
  const syncedThreat = { ...threat, severity: recalculatedSeverity };

  return {
    threat: syncedThreat,
    threatExplanation: getThreatExplanation(threat.threat_type),
    indicatorExplanations: getIndicatorExplanation(threat.indicators),
    recommendation: getRecommendation(threat.threat_type),
    llamaStatus: {
      enabled: false,
      reason: 'Llama output is disabled because it may contain unsupported claims.',
      notice: 'Experimental Llama/ExecuTorch generation is disabled. Native runner execution is not established in this environment.',
    },
  };
}
