import { ThreatResult } from '../types/threat';

/**
 * Exact mirror of threat_engine/samples/intrusion.json
 * Flagged explicitly as DEMO - SAMPLE DATA
 */
export const INTRUSION_SAMPLE: ThreatResult = {
  source: 'network',
  threat_type: 'intrusion',
  severity: 'critical',
  confidence: 0.91,
  indicators: [
    'abnormal traffic volume',
    'multiple connection attempts',
  ],
  metadata: {
    source_ip: '192.168.1.100',
  },
  timestamp: '2026-09-25T20:00:00',
  isDemoSample: true,
};

/**
 * Exact mirror of threat_engine/samples/phishing.json
 * Flagged explicitly as DEMO - SAMPLE DATA
 */
export const PHISHING_SAMPLE: ThreatResult = {
  source: 'url',
  threat_type: 'phishing',
  severity: 'critical',
  confidence: 0.94,
  indicators: [
    'suspicious domain',
    'login keyword',
    'unusual URL structure',
  ],
  metadata: {
    url: 'http://fake-login-example.com',
  },
  timestamp: '2026-09-25T20:00:00',
  isDemoSample: true,
};

/**
 * Exact mirror of threat_engine/samples/scam.json
 * Flagged explicitly as DEMO - SAMPLE DATA
 */
export const SCAM_SAMPLE: ThreatResult = {
  source: 'sms',
  threat_type: 'scam',
  severity: 'critical',
  confidence: 0.91,
  indicators: [
    'prize claim',
    'urgent payment request',
  ],
  metadata: {
    message: 'Congratulations! You won ₹50,000. Pay ₹500 to claim.',
  },
  timestamp: '2026-09-25T20:00:00',
  isDemoSample: true,
};

export const ALL_DEMO_FIXTURES: ThreatResult[] = [
  INTRUSION_SAMPLE,
  PHISHING_SAMPLE,
  SCAM_SAMPLE,
];

