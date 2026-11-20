
import { API_CONFIG } from '../config/apiConfig';
import { ThreatResult } from '../types/threat';
import { AdvisoryResult } from '../types/advisory';
import {
  NetworkAnalyzeRequest,
  UrlScanRequest,
  SmsScanRequest,
  ApiResponse,
  BackendHealthResponse,
  CorrelationEventInput,
  CorrelationResult,
} from '../types/api';
import {
  INTRUSION_SAMPLE,
  PHISHING_SAMPLE,
  SCAM_SAMPLE,
} from '../fixtures/samples';
import { buildAdvisoryFromThreat } from './threatRules';

/**
 * Error for unavailable or unimplemented backend endpoints.
 */
export class BackendNotConnectedError extends Error {
  public endpoint: string;
  public requiredContract: string;

  constructor(endpoint: string, requiredContract: string) {
    super(
      `Backend HTTP endpoint '${endpoint}' is not connected. ${requiredContract}`
    );
    this.name = 'BackendNotConnectedError';
    this.endpoint = endpoint;
    this.requiredContract = requiredContract;
  }
}

/**
 * API client for Bharat AI-SoC.
 *
 * Network PCAP analysis uses the isolated Person 1 Network IDS worker.
 * Advisory generation and event correlation use the existing backend.
 * URL and SMS detection remain unavailable until their detector pipelines
 * are integrated.
 *
 * Demo fixtures remain available for offline demonstrations.
 */
class ApiClient {
  /**
   * Reports the configured backend availability flag.
   * This is not a live connectivity check.
   */
  public isConnected(): boolean {
    return API_CONFIG.INTEGRATION_STATUS.IS_BACKEND_AVAILABLE;
  }

  /**
   * Fetches the current health and detector status from the main backend.
   */
  public async getBackendHealth(): Promise<BackendHealthResponse> {
    const controller = new AbortController();

    const timeoutId = setTimeout(
      () => controller.abort(),
      API_CONFIG.TIMEOUT_MS
    );

    try {
      const response = await fetch(
        `${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.HEALTH}`,
        {
          method: 'GET',
          headers: {
            Accept: 'application/json',
          },
          signal: controller.signal,
        }
      );

      if (!response.ok) {
        throw new Error(
          `Backend health check failed: HTTP ${response.status}`
        );
      }

      return (await response.json()) as BackendHealthResponse;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Uploads a PCAP to the isolated Network IDS worker.
   *
   * The worker extracts flows and executes the frozen 79-feature
   * model. The existing ThreatResult contract displays the first
   * flow's prediction; additional flow results are not discarded
   * by the worker, but require a separate multi-flow UI.
   */
  public async analyzePcap(
    request: NetworkAnalyzeRequest
  ): Promise<ApiResponse<ThreatResult>> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 120000);

    try {
      const formData = new FormData();

      formData.append(
        'file',
        request.pcapFile,
        request.pcapFile.name
      );

      const response = await fetch(
        `${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.NETWORK_ANALYZE}`,
        {
          method: 'POST',
          body: formData,
          signal: controller.signal,
        }
      );

      const result = await response.json();

      if (!response.ok) {
        return {
          success: false,
          error:
            typeof result?.detail === 'string'
              ? result.detail
              : `Network IDS request failed (HTTP ${response.status}).`,
          code: String(response.status),
          timestamp: new Date().toISOString(),
        };
      }

      if (
        result?.success !== true ||
        !Array.isArray(result.results) ||
        result.results.length === 0
      ) {
        return {
          success: false,
          error: 'The Network IDS worker returned no valid threat results.',
          code: 'INVALID_WORKER_RESPONSE',
          timestamp: new Date().toISOString(),
        };
      }

      const first = result.results[0]?.threat_result;

      if (
        !first ||
        typeof first.attack_class !== 'string' ||
        typeof first.confidence !== 'number' ||
        !Number.isFinite(first.confidence) ||
        first.confidence < 0 ||
        first.confidence > 1 ||
        !Array.isArray(first.indicators)
      ) {
        return {
          success: false,
          error: 'The Network IDS worker returned an invalid prediction.',
          code: 'INVALID_PREDICTION',
          timestamp: new Date().toISOString(),
        };
      }

      const attackClass: string = first.attack_class;
      const isBenign = attackClass.toUpperCase() === 'BENIGN';

      const allowedSeverities = [
        'low',
        'medium',
        'high',
        'critical',
      ] as const;

      const severityValue = String(first.severity).toLowerCase();

      const severity: ThreatResult['severity'] =
        allowedSeverities.includes(
          severityValue as (typeof allowedSeverities)[number]
        )
          ? (severityValue as ThreatResult['severity'])
          : 'high';

      const threat: ThreatResult = {
        source: 'network',

        // "normal" is not a member of the existing ThreatType union.
        // Preserve the actual model label in metadata rather than
        // falsely labeling benign traffic as an intrusion.
        threat_type: isBenign ? 'normal' : 'intrusion',

        severity,
        confidence: first.confidence,

        indicators: first.indicators.filter(
          (item: unknown): item is string =>
            typeof item === 'string'
        ),

        metadata: {
          filename:
            typeof result.filename === 'string'
              ? result.filename
              : request.pcapFile.name,

          flow_count:
            typeof result.flow_count === 'number'
              ? result.flow_count
              : result.results.length,

          predicted_class: attackClass,
          prediction_scope: 'first_flow',
          model_confidence: first.confidence,
          explainability:
            result.results[0]?.advisory?.metadata?.explainability ||
            first?.metadata?.explainability,
        },

        timestamp: new Date().toISOString(),
        isDemoSample: false,
        operatingMode: 'PCAP_REPLAY',
        provenance: 'pcap_replay',
      };

      return {
        success: true,
        data: threat,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      const timedOut =
        error instanceof Error &&
        error.name === 'AbortError';

      return {
        success: false,
        error: timedOut
          ? 'Network IDS analysis timed out after 120 seconds.'
          : error instanceof Error
            ? error.message
            : 'Unknown Network IDS connection error.',

        code: timedOut
          ? 'NETWORK_IDS_TIMEOUT'
          : 'NETWORK_IDS_CONNECTION_ERROR',

        timestamp: new Date().toISOString(),
      };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Scans a URL for phishing using the integrated ML model.
   * Accepts either an object { url: string } or directly a string URL.
   */
  public async scanUrl(
    request: UrlScanRequest | string
  ): Promise<ApiResponse<ThreatResult>> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), API_CONFIG.TIMEOUT_MS);
    const targetUrl = typeof request === 'string' ? request : request.url;

    try {
      const response = await fetch(
        `${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.URL_SCAN}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ url: targetUrl }),
          signal: controller.signal,
        }
      );

      const result = await response.json();

      if (!response.ok) {
        return {
          success: false,
          error:
            typeof result?.detail === 'string'
              ? result.detail
              : `URL scan failed (HTTP ${response.status}).`,
          code: String(response.status),
          timestamp: new Date().toISOString(),
        };
      }

      return {
        success: true,
        data: {
          ...(result.data as ThreatResult),
          operatingMode: 'DEMO_MODE', // Preserves global UI context without falsely claiming native layer-2 sniffing
          provenance: 'user_submitted',
          isDemoSample: false,
        },
        timestamp: result.timestamp ?? new Date().toISOString(),
      };
    } catch (error) {
      const timedOut = error instanceof Error && error.name === 'AbortError';
      return {
        success: false,
        error: timedOut ? 'URL scan timed out.' : (error instanceof Error ? error.message : 'Unknown URL scan error.'),
        code: timedOut ? 'URL_SCAN_TIMEOUT' : 'URL_SCAN_ERROR',
        timestamp: new Date().toISOString(),
      };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Scans an SMS text for scam patterns using the integrated ML model.
   * Accepts either an object { message: string } or directly a string text.
   */
  public async scanSms(
    request: SmsScanRequest | string
  ): Promise<ApiResponse<ThreatResult>> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), API_CONFIG.TIMEOUT_MS);
    const messageText = typeof request === 'string' ? request : request.message;

    try {
      const response = await fetch(
        `${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SMS_SCAN}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ message: messageText }),
          signal: controller.signal,
        }
      );

      const result = await response.json();

      if (!response.ok) {
        return {
          success: false,
          error:
            typeof result?.detail === 'string'
              ? result.detail
              : `SMS scan failed (HTTP ${response.status}).`,
          code: String(response.status),
          timestamp: new Date().toISOString(),
        };
      }

      return {
        success: true,
        data: {
          ...(result.data as ThreatResult),
          operatingMode: 'DEMO_MODE', // Preserves global UI context without falsely claiming native layer-2 sniffing
          provenance: 'user_submitted',
          isDemoSample: false,
        },
        timestamp: result.timestamp ?? new Date().toISOString(),
      };
    } catch (error) {
      const timedOut = error instanceof Error && error.name === 'AbortError';
      return {
        success: false,
        error: timedOut ? 'SMS scan timed out.' : (error instanceof Error ? error.message : 'Unknown SMS scan error.'),
        code: timedOut ? 'SMS_SCAN_TIMEOUT' : 'SMS_SCAN_ERROR',
        timestamp: new Date().toISOString(),
      };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Start, stop, or fetch live security monitoring events.
   */
  public async startMonitoring(): Promise<{ status: string; started_at?: string }> {
    const res = await fetch(`${API_CONFIG.BASE_URL}/monitoring/start`, { method: 'POST' });
    return res.json();
  }

  public async stopMonitoring(): Promise<{ status: string }> {
    const res = await fetch(`${API_CONFIG.BASE_URL}/monitoring/stop`, { method: 'POST' });
    return res.json();
  }

  public async getMonitoringStatus(): Promise<{
    is_running: boolean;
    total_events: number;
    stats: {
      network_events: number;
      url_threats: number;
      sms_threats: number;
      critical_count: number;
      high_count: number;
      medium_count: number;
      low_count: number;
      start_time: string | null;
      last_event_time: string | null;
    };
    live_capture_capable: boolean;
    capture_subsystem: {
      available: boolean;
      provider: string | null;
      interface_count: number;
      reason?: string;
      remedy?: string;
    };
  }> {
    const res = await fetch(`${API_CONFIG.BASE_URL}/monitoring/status`);
    return res.json();
  }

  public async getMonitoringEvents(limit: number = 100, sinceId?: number): Promise<{
    success: boolean;
    events: Array<{
      id: number;
      time: string;
      timestamp: string;
      source: string;
      event: string;
      event_type: string;
      severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
      status: string;
      provenance: string;
      indicators: string[];
      geo?: {
        ip: string;
        location_available: boolean;
        city?: string;
        country?: string;
        lat?: number | null;
        lon?: number | null;
        x?: number | null;
        y?: number | null;
        is_approximate?: boolean;
        attribution_disclaimer?: string;
        reason?: string;
      } | null;
    }>;
    status: {
      is_running: boolean;
      total_events: number;
      stats: Record<string, unknown>;
    };
  }> {
    const params = new URLSearchParams();
    if (limit) params.append('limit', limit.toString());
    if (sinceId !== undefined) params.append('since_id', sinceId.toString());
    const query = params.toString() ? `?${params.toString()}` : '';
    const res = await fetch(`${API_CONFIG.BASE_URL}/monitoring/events${query}`);
    return res.json();
  }

  /**
   * AI Security Assistant Query
   */
  public async queryAssistant(question: string, context?: Record<string, unknown>): Promise<{
    answer: string;
    engine: string;
    grounded_in_telemetry: boolean;
    llama_status: { enabled: boolean; reason: string };
  }> {
    const res = await fetch(`${API_CONFIG.BASE_URL}/assistant/query`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question, context }),
    });
    return res.json();
  }

  /**
   * Sends a threat to the existing backend and retrieves
   * its rule-based advisory.
   */
  public async generateAdvisory(
    threat: ThreatResult
  ): Promise<ApiResponse<AdvisoryResult>> {
    const controller = new AbortController();

    const timeoutId = setTimeout(
      () => controller.abort(),
      API_CONFIG.TIMEOUT_MS
    );

    try {
      const response = await fetch(
        `${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.GENERATE_ADVISORY}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(threat),
          signal: controller.signal,
        }
      );

      const result = await response.json();

      if (!response.ok) {
        return {
          success: false,
          error:
            typeof result?.detail === 'string'
              ? result.detail
              : JSON.stringify(result?.detail ?? result),
          code: String(response.status),
          timestamp: new Date().toISOString(),
        };
      }

      const advisory: AdvisoryResult = {
        threat: result.threat_details,
        threatExplanation: result.explanation,
        indicatorExplanations: result.indicator_explanations,
        recommendation: result.recommendation,
        llamaStatus: {
          enabled: result.llama_status.enabled,
          reason: result.llama_status.reason,
          notice: result.llama_status.reason,
        },
      };

      return {
        success: true,
        data: advisory,
        timestamp:
          result.timestamp ?? new Date().toISOString(),
      };
    } catch (error) {
      const isTimeout =
        error instanceof Error &&
        error.name === 'AbortError';

      return {
        success: false,
        error: isTimeout
          ? 'Backend request timed out.'
          : error instanceof Error
            ? error.message
            : 'Unknown backend connection error.',
        code: isTimeout
          ? 'BACKEND_TIMEOUT'
          : 'BACKEND_CONNECTION_ERROR',
        timestamp: new Date().toISOString(),
      };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Correlates submitted events using shared indicators.
   *
   * This processes submitted records only. It does not independently
   * run network, URL, or SMS detection or prove a common attacker.
   */
  public async analyzeCorrelation(
    events: CorrelationEventInput[]
  ): Promise<CorrelationResult> {
    const controller = new AbortController();

    const timeoutId = setTimeout(
      () => controller.abort(),
      API_CONFIG.TIMEOUT_MS
    );

    try {
      const response = await fetch(
        `${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.CORRELATION_ANALYZE}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json',
          },
          body: JSON.stringify({ events }),
          signal: controller.signal,
        }
      );

      const result = await response.json();

      if (!response.ok) {
        const message =
          typeof result?.detail === 'string'
            ? result.detail
            : JSON.stringify(result?.detail ?? result);

        throw new Error(
          `Correlation API failed (HTTP ${response.status}): ${message}`
        );
      }

      return result as CorrelationResult;
    } catch (error) {
      if (
        error instanceof Error &&
        error.name === 'AbortError'
      ) {
        throw new Error('Correlation API request timed out.');
      }

      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Generates a chronological multi-stage attack storyline from submitted events.
   */
  public async generateStoryline(
    events: CorrelationEventInput[]
  ): Promise<{
    success: boolean;
    incident_count: number;
    storylines: Array<{
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
      stages: Array<{
        stage_number: number;
        source: string;
        title: string;
        description: string;
        timestamp: string;
        severity: string;
        confidence: number;
        indicators: string[];
        reason: string;
      }>;
      simple_explanation: {
        what_happened: string;
        why_suspicious: string;
        evidence: string[];
        what_affected: string;
        next_steps: string[];
      };
    }>;
    notice: string;
  }> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), API_CONFIG.TIMEOUT_MS);

    try {
      const response = await fetch(
        `${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.CORRELATION_STORYLINE}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json',
          },
          body: JSON.stringify({ events }),
          signal: controller.signal,
        }
      );

      const result = await response.json();
      if (!response.ok) {
        const message =
          typeof result?.detail === 'string'
            ? result.detail
            : JSON.stringify(result?.detail ?? result);
        throw new Error(`Storyline API failed (HTTP ${response.status}): ${message}`);
      }
      return result;
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error('Storyline API request timed out.');
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Returns the existing demonstration fixtures.
   *
   * These are sample data, not real detector predictions.
   */
  public getDemoThreats(): {
    intrusion: ThreatResult;
    phishing: ThreatResult;
    scam: ThreatResult;
  } {
    return {
      intrusion: INTRUSION_SAMPLE,
      phishing: PHISHING_SAMPLE,
      scam: SCAM_SAMPLE,
    };
  }

  /**
   * Retains the existing frontend rule-based advisory helper.
   */
  public getLocalAdvisory(
    threat: ThreatResult
  ): AdvisoryResult {
    return buildAdvisoryFromThreat(threat);
  }
}

export const apiClient = new ApiClient();

