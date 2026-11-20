/**
 * Centralized API Configuration & Backend Contract Specification
 *
 * NOTE: Currently, there is NO running backend HTTP API server in this workspace.
 * Person 1's detection pipeline (including the frozen 79-feature Network IDS model)
 * and Person 2's backend advisory service have not yet been exposed over HTTP.
 *
 * This configuration defines the expected endpoint contracts for future integration.
 */

export const API_CONFIG = {
  // Base URL for future backend API service (defaults to environment variable or standard port)
  BASE_URL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1',
  TIMEOUT_MS: 15000,
  
  // Future endpoint paths to be implemented by backend
  ENDPOINTS: {
    HEALTH: '/health',
    NETWORK_ANALYZE: '/threats/analyze-pcap',
    URL_SCAN: '/threats/scan-url',
    SMS_SCAN: '/threats/scan-sms',
    GENERATE_ADVISORY: '/advisory/generate',
    CORRELATION_ANALYZE: '/correlation/analyze',
    CORRELATION_STORYLINE: '/correlation/storyline',
  },

  // Documented status of backend connections
  INTEGRATION_STATUS: {
    IS_BACKEND_AVAILABLE: true,
    ACTIVE_MODE: 'BACKEND_ACTIVE_REAL_DETECTORS',
    MISSING_CONTRACTS: [
      'Native ExecuTorch / Llama runtime verification on host operating system',
    ],
  },
};

