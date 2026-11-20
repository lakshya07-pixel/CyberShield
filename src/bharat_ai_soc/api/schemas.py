"""
Pydantic schemas for the Bharat AI-SoC REST Gateway.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = Field(..., description="Overall health status")
    version: str = Field("1.0.0", description="API version")
    service: str = Field("Bharat AI-SoC Threat Advisory API", description="Service name")
    engine_status: str = Field("rule_based_active", description="Rule engine status")
    detectors: Optional[Dict[str, str]] = Field(None, description="Status of individual detectors")
    detector_status: Optional[Dict[str, str]] = Field(None, description="Detailed detector availability")
    threat_engine: str = Field("ready", description="Status of Shared Threat Engine")
    llama_advisory: str = Field("fallback_only", description="Status of Llama ExecuTorch advisory")
    llama_status: Optional[Dict[str, Any]] = Field(None, description="Llama status details")
    timestamp: str = Field(..., description="UTC ISO timestamp")


class URLDetectRequest(BaseModel):
    url: str = Field(..., min_length=1, description="Target URL to inspect for phishing")
    use_lite: bool = Field(False, description="Use lightweight Logistic Regression model")
    include_advisory: bool = Field(True, description="Attach Shared Threat Engine advisory")
    use_llama: bool = Field(False, description="Attempt on-device Llama advisory reasoning")


class SMSDetectRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Raw SMS text to inspect for scam/fraud")
    include_advisory: bool = Field(True, description="Attach Shared Threat Engine advisory")
    use_llama: bool = Field(False, description="Attempt on-device Llama advisory reasoning")


class DetectionResponse(BaseModel):
    threat_result: Dict[str, Any] = Field(..., description="Raw authoritative detector result")
    advisory: Optional[Dict[str, Any]] = Field(None, description="Enriched security advisory")


class PCAPDetectResponse(BaseModel):
    summary: Dict[str, Any] = Field(..., description="Aggregated SOC telemetry summary")
    flows: List[Dict[str, Any]] = Field(..., description="List of processed flow records")
    total_flows: int = Field(..., description="Total flows extracted and evaluated")
    displayed_flows: int = Field(..., description="Number of flow records included in response")


class ErrorResponse(BaseModel):
    error: str = Field(..., description="Error classification code")
    message: str = Field(..., description="Human-readable explanation of error")
    timestamp: str = Field(..., description="UTC ISO timestamp")


class CorrelateRequest(BaseModel):
    events: List[Dict[str, Any]] = Field(..., min_length=1, description="List of raw detector event records to correlate")
    verify_integrity: bool = Field(True, description="Whether to verify SHA-256 seal integrity")


class CorrelateResponse(BaseModel):
    incidents: List[Dict[str, Any]] = Field(..., description="List of synthesized Unified Incident Records")
    total_events: int = Field(..., description="Total events ingested")
    total_incidents: int = Field(..., description="Total multi-channel incidents correlated")
    integrity_verified: bool = Field(True, description="Whether all synthesized incidents passed SHA-256 seal verification")
    timestamp: str = Field(..., description="UTC ISO timestamp")


class MetricsResponse(BaseModel):
    total_incidents: int = Field(..., description="Total correlated incidents")
    high_critical_incidents: int = Field(..., description="High or Critical severity incidents")
    channels_monitored: List[str] = Field(..., description="Monitored detection channels")
    by_severity: List[Dict[str, Any]] = Field(..., description="Incidents by severity")
    by_source: List[Dict[str, Any]] = Field(..., description="Events by source channel")
    timestamp: str = Field(..., description="UTC ISO timestamp")


class QuickDemoResponse(BaseModel):
    status: str = Field(..., description="Execution status of the demo: completed or failed")
    scenario_name: str = Field("Coordinated Phishing Campaign — Demo", description="Name of the demo attack scenario")
    sms_stage: Dict[str, Any] = Field(..., description="Result of SMS scam detector stage")
    url_stage: Dict[str, Any] = Field(..., description="Result of URL phishing detector stage")
    network_stage: Dict[str, Any] = Field(..., description="Result of Network PCAP flow detector stage")
    correlation_stage: Dict[str, Any] = Field(..., description="Result of cross-channel correlation stage")
    incident: Optional[Dict[str, Any]] = Field(None, description="Resulting Unified Incident Record")
    integrity_verified: bool = Field(False, description="SHA-256 seal verification status")
    timestamp: str = Field(..., description="UTC ISO timestamp")


class LiveCaptureStartRequest(BaseModel):
    interface: Optional[str] = Field(None, description="Network interface name or GUID")
    bpf_filter: Optional[str] = Field("ip and (tcp or udp)", description="BPF filter string")


class LiveCaptureStatusResponse(BaseModel):
    status: str = Field(..., description="Capture status: STOPPED, STARTING, RUNNING, STOPPING, ERROR, BLOCKED_PERMISSIONS")
    interface: Optional[str] = Field(None, description="Currently selected or active interface")
    started_at: Optional[str] = Field(None, description="UTC ISO start timestamp")
    packets_captured: int = Field(0, description="Total packets captured")
    packets_processed: int = Field(0, description="Total packets processed into flows")
    packets_dropped: int = Field(0, description="Total packets dropped due to queue saturation")
    flows_active: int = Field(0, description="Currently active bidirectional flows")
    flows_finalized: int = Field(0, description="Total finalized and classified flows")
    total_events: int = Field(0, description="Total live threat events recorded")
    last_error: Optional[str] = Field(None, description="Last recorded capture or permission error")
    timestamp: str = Field(..., description="UTC ISO timestamp")


class LiveEventsResponse(BaseModel):
    events: List[Dict[str, Any]] = Field(..., description="List of recent live network detection events")
    total_returned: int = Field(..., description="Number of events in this response")
    timestamp: str = Field(..., description="UTC ISO timestamp")


class SecurityQARequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=2000, description="User question or query")
    context: Optional[Dict[str, Any]] = Field(None, description="Optional active detection context (url, sms, network flow, or incident)")
    use_llama: bool = Field(False, description="Attempt on-device Llama ExecuTorch advisory")
    provider: Optional[str] = Field("local", description="Local AI provider identifier")
    allow_cloud: bool = Field(False, description="Deprecated. System operates strictly offline and on-device.")


class SecurityQAResponse(BaseModel):
    answer: str = Field(..., description="Educational, grounded answer to the user's security query")
    mode: str = Field(..., description="Execution mode: deterministic or local_llama")
    grounded: bool = Field(..., description="Whether answer is explicitly grounded in provided detection context")
    intent: Optional[str] = Field(None, description="Classified natural language intent")
    provider: Optional[str] = Field("local", description="Local AI provider that produced this response")
    model: Optional[str] = Field(None, description="Model identifier utilized")
    fallback_triggered: bool = Field(False, description="Whether fallback to local execution occurred")
    disclaimer: Optional[str] = Field(None, description="Safety and forensic distinction disclaimer")
    followups: Optional[List[str]] = Field(default_factory=list, description="Context-aware suggested follow-up questions")
    timestamp: str = Field(..., description="UTC ISO timestamp")


class IncidentSummaryRequest(BaseModel):
    incident: Dict[str, Any] = Field(..., description="Unified Incident Record to summarize")
    use_llama: bool = Field(False, description="Attempt on-device Llama ExecuTorch advisory")
    provider: Optional[str] = Field("local", description="Local AI provider identifier")
    allow_cloud: bool = Field(False, description="Deprecated. System operates strictly offline and on-device.")


class IncidentSummaryResponse(BaseModel):
    summary: Dict[str, Any] = Field(..., description="Structured multi-section attack storyline summary")
    mode: str = Field("deterministic", description="Execution mode: deterministic on-device")
    grounded: bool = Field(..., description="Whether summary strictly reflects observed evidence")
    provider: Optional[str] = Field("local", description="Local AI provider that produced this summary")
    model: Optional[str] = Field(None, description="Model identifier utilized")
    fallback_triggered: bool = Field(False, description="Whether fallback occurred")
    timestamp: str = Field(..., description="UTC ISO timestamp")


class AIProviderStatusResponse(BaseModel):
    active_provider: str = Field("local", description="Currently active provider (strictly local)")
    active_model: str = Field(..., description="Currently configured local model")
    cloud_enabled: bool = Field(False, description="Whether hosted cloud inference is permitted (strictly False)")
    is_cloud_active: bool = Field(False, description="Whether active provider is cloud (strictly False)")
    available_providers: List[str] = Field(default_factory=lambda: ["local"], description="List of available providers")
    timeout_seconds: int = Field(15, description="Timeout in seconds")
    redaction_active: bool = Field(False, description="Redaction status")
    keys_configured: Dict[str, bool] = Field(default_factory=dict, description="Safe boolean indicator for local engine")
    timestamp: str = Field(..., description="UTC ISO timestamp")



