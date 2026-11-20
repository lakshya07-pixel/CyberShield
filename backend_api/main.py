
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
PERSON1_ROOT = PROJECT_ROOT
for p in [str(PROJECT_ROOT)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from fastapi import FastAPI, File, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from schemas import create_threat_result
from backend_api.correlation import correlate_events
from backend_api.monitoring import monitoring_engine
from backend_api.assistant import assistant_service
from threat_engine.rules import get_indicator_explanation, get_threat_explanation
from threat_engine.recommendations import get_recommendation
from threat_engine.severity import calculate_severity

# Import real detectors and PCAP pipeline from person1_submission
try:
    from detectors.url.inference import detect_url_threat
    URL_DETECTOR_AVAILABLE = True
except Exception:
    URL_DETECTOR_AVAILABLE = False

try:
    from detectors.sms.inference import detect_sms_threat
    SMS_DETECTOR_AVAILABLE = True
except Exception:
    SMS_DETECTOR_AVAILABLE = False

try:
    from examples.pcap_to_threats import run_pcap_pipeline
    NETWORK_IDS_MODEL_DIR = PERSON1_ROOT / "models" / "network_ids" / "baseline_model"
    NETWORK_IDS_AVAILABLE = (
        (NETWORK_IDS_MODEL_DIR / "random_forest_baseline.joblib").is_file()
        and (NETWORK_IDS_MODEL_DIR / "label_encoder.joblib").is_file()
        and (NETWORK_IDS_MODEL_DIR / "features.json").is_file()
    )
except Exception:
    NETWORK_IDS_AVAILABLE = False


SUPPORTED_THREAT_TYPES = {"intrusion", "phishing", "scam", "normal", "benign"}

app = FastAPI(
    title="Bharat AI-SoC Threat Advisory API",
    description=(
        "HTTP API for the verified rule-based threat advisory engine "
        "and evidence-based correlation of submitted event records."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request and response schemas
# ---------------------------------------------------------------------------

class ThreatInput(BaseModel):
    source: str = Field(
        ...,
        description="Telemetry source, such as network, url, or sms.",
        min_length=1,
    )
    threat_type: str = Field(
        ...,
        description="Supported values: intrusion, phishing, scam, normal, benign.",
    )
    confidence: float = Field(
        ...,
        description="Confidence between 0.0 and 1.0.",
    )
    indicators: List[str] = Field(default_factory=list)
    severity: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: Optional[str] = None

    @field_validator("threat_type")
    @classmethod
    def validate_threat_type(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if cleaned not in SUPPORTED_THREAT_TYPES:
            raise ValueError(
                f"Unsupported threat_type '{value}'. "
                f"Supported types are: {', '.join(sorted(SUPPORTED_THREAT_TYPES))}."
            )
        return cleaned

    @field_validator("confidence", mode="before")
    @classmethod
    def validate_confidence(cls, value: Any) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("Confidence must be a number between 0 and 1.")
        if not 0.0 <= value <= 1.0:
            raise ValueError("Confidence must be between 0 and 1.")
        return float(value)


class LlamaStatus(BaseModel):
    enabled: bool = False
    reason: str = (
        "Llama output is disabled because it may contain unsupported claims."
    )
    runtime_verified: bool = False


class ThreatDetails(BaseModel):
    source: str
    threat_type: str
    severity: str
    confidence: float
    indicators: List[str]
    metadata: Dict[str, Any]
    timestamp: Optional[str] = None


class AdvisoryResponse(BaseModel):
    success: bool = True
    threat_details: ThreatDetails
    calculated_severity: str
    explanation: str
    indicator_explanations: List[str]
    recommendation: str
    llama_status: LlamaStatus
    timestamp: str


class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str = "1.0.0"
    service: str = "Bharat AI-SoC Threat Advisory API"
    engine_status: str = "rule_based_active"
    detector_status: Dict[str, str]
    llama_status: LlamaStatus


class CorrelationRequest(BaseModel):
    events: List[Dict[str, Any]] = Field(
        ...,
        description="Submitted event records to correlate using shared indicators.",
        max_length=500,
    )


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------

@app.get("/api/v1/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        service="Bharat AI-SoC Threat Advisory API",
        engine_status="rule_based_active",
        detector_status={
            "network_ids": "available (in-process 79-feature RF pipeline)" if NETWORK_IDS_AVAILABLE else "unavailable",
            "url_phishing": "available (Random Forest classifier)" if URL_DETECTOR_AVAILABLE else "unavailable",
            "sms_scam": "available (TF-IDF + Logistic Regression)" if SMS_DETECTOR_AVAILABLE else "unavailable",
        },
        llama_status=LlamaStatus(),
    )


# ---------------------------------------------------------------------------
# Rule-based advisory endpoint
# ---------------------------------------------------------------------------

@app.post(
    "/api/v1/advisory/generate",
    response_model=AdvisoryResponse,
    tags=["Advisory"],
    summary="Generate rule-based threat advisory",
)
async def generate_advisory_endpoint(threat: ThreatInput):
    try:
        # For benign/normal, the model prediction confidence represents high confidence that
        # the flow is BENIGN, which corresponds to LOW threat severity.
        if threat.threat_type in ("normal", "benign"):
            severity = "low"
        else:
            severity = calculate_severity(threat.confidence)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    explanation = get_threat_explanation(
        threat.threat_type,
        threat.indicators,
    )
    indicator_explanations = get_indicator_explanation(threat.indicators)
    recommendation = get_recommendation(threat.threat_type)

    current_time_iso = datetime.now(timezone.utc).isoformat()
    record_timestamp = threat.timestamp or current_time_iso

    threat_dict = create_threat_result(
        source=threat.source,
        threat_type=threat.threat_type,
        severity=severity,
        confidence=threat.confidence,
        indicators=threat.indicators,
        metadata=threat.metadata,
        timestamp=record_timestamp,
    )

    return AdvisoryResponse(
        success=True,
        threat_details=ThreatDetails(**threat_dict),
        calculated_severity=severity,
        explanation=explanation,
        indicator_explanations=indicator_explanations,
        recommendation=recommendation,
        llama_status=LlamaStatus(),
        timestamp=current_time_iso,
    )


# ---------------------------------------------------------------------------
# Cross-channel correlation endpoint
# ---------------------------------------------------------------------------

@app.post(
    "/api/v1/correlation/analyze",
    tags=["Correlation"],
    summary="Correlate submitted events across channels",
)
async def analyze_correlation(request: CorrelationRequest):
    """
    Match submitted events using shared indicators.

    This endpoint does not run threat detectors, ingest live telemetry,
    or prove that matching events share an attacker or campaign.
    """
    try:
        return correlate_events(request.events)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )


@app.post(
    "/api/v1/correlation/storyline",
    tags=["Correlation"],
    summary="Generate chronological attack storyline from events",
)
async def generate_storyline_endpoint(request: CorrelationRequest):
    """
    Generates a chronological multi-stage attack storyline from submitted events.
    """
    try:
        from backend_api.storyline import generate_storyline_from_events
        return generate_storyline_from_events(request.events)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )


# ---------------------------------------------------------------------------
# Network IDS PCAP Analysis endpoint
# ---------------------------------------------------------------------------

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
ALLOWED_PCAP_EXTENSIONS = {".pcap", ".pcapng"}

@app.post(
    "/api/v1/threats/analyze-pcap",
    tags=["Detectors"],
    summary="Network IDS PCAP Analysis",
)
async def analyze_pcap_endpoint(file: UploadFile = File(...)):
    if not NETWORK_IDS_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Network IDS detector is unavailable. Baseline model artifacts were not found.",
        )

    filename = Path(file.filename or "").name
    extension = Path(filename).suffix.lower()

    if extension not in ALLOWED_PCAP_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .pcap and .pcapng files are accepted.",
        )

    import tempfile
    try:
        with tempfile.TemporaryDirectory(prefix="bharat_ids_api_") as temp:
            work = Path(temp)
            pcap_path = work / ("capture" + extension)
            csv_path = work / "flows.csv"
            json_path = work / "results.json"

            size = 0
            with pcap_path.open("wb") as output:
                while True:
                    chunk = await file.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > MAX_UPLOAD_BYTES:
                        raise HTTPException(
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            detail="PCAP exceeds the 25 MiB upload limit.",
                        )
                    output.write(chunk)

            if size < 4:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="The uploaded capture is empty or too small.",
                )

            try:
                results = run_pcap_pipeline(
                    pcap_path=str(pcap_path),
                    output_json_path=str(json_path),
                    flow_csv_path=str(csv_path),
                    models_dir=str(NETWORK_IDS_MODEL_DIR),
                    include_advisory=True,
                )
                # Ingest detected network flows directly into monitoring telemetry buffer
                for r in results[:10]:
                    indicators = [f"Attack: {r.get('prediction', 'Intrusion')}"]
                    if r.get("source_ip"):
                        indicators.append(f"Src: {r.get('source_ip')}")
                    if r.get("destination_ip"):
                        indicators.append(f"Dst: {r.get('destination_ip')}")
                    monitoring_engine.add_event(
                        source="network",
                        event_type="pcap_flow",
                        severity=r.get("severity", "HIGH"),
                        details=f"Flow anomaly detected: {r.get('prediction', 'Suspicious activity')}",
                        provenance="pcap_replay",
                        indicators=indicators,
                    )
            except (ValueError, FileNotFoundError) as exc:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=str(exc),
                ) from exc
            except Exception as exc:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"PCAP processing or model inference failed: {type(exc).__name__}",
                ) from exc

            if not results:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="No threat results were produced.",
                )

            return {
                "success": True,
                "filename": filename,
                "flow_count": len(results),
                "results": results,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
    finally:
        await file.close()


class UrlScanPayload(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="URL to analyze for phishing.")

class SmsScanPayload(BaseModel):
    message: str = Field(..., min_length=1, max_length=4096, description="SMS text to analyze for scam patterns.")

class AssistantQueryPayload(BaseModel):
    question: str = Field(..., min_length=1, max_length=1000)
    context: Optional[Dict[str, Any]] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Active ML Detection endpoints
# ---------------------------------------------------------------------------

@app.post(
    "/api/v1/threats/scan-url",
    tags=["Detectors"],
    summary="URL Phishing Scanner",
)
async def scan_url_endpoint(payload: UrlScanPayload):
    if not URL_DETECTOR_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="URL detector model artifacts not available.",
        )
    try:
        raw_result = detect_url_threat(payload.url)
        # raw_result has: source, threat_type, attack_class, severity, confidence, indicators, metadata, timestamp
        
        # Ingest URL detection into monitoring telemetry buffer with accurate provenance
        monitoring_engine.add_event(
            source="url",
            event_type=raw_result.get("attack_class", "phishing_url"),
            severity=raw_result.get("severity", "HIGH"),
            details=f"URL threat scanned: {payload.url[:60]}",
            provenance="api_submission",
            indicators=raw_result.get("indicators", [payload.url]),
        )

        return {
            "success": True,
            "data": raw_result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"URL threat detection failed: {str(exc)}",
        )


@app.post(
    "/api/v1/threats/scan-sms",
    tags=["Detectors"],
    summary="SMS Scam Scanner",
)
async def scan_sms_endpoint(payload: SmsScanPayload):
    if not SMS_DETECTOR_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SMS detector model artifacts not available.",
        )
    try:
        raw_result = detect_sms_threat(payload.message)
        # raw_result has: source, threat_type, attack_class, severity, confidence, indicators, metadata, timestamp

        # Ingest SMS detection into monitoring telemetry buffer with accurate provenance
        monitoring_engine.add_event(
            source="sms",
            event_type=raw_result.get("attack_class", "scam_message"),
            severity=raw_result.get("severity", "HIGH"),
            details=f"SMS threat scanned: {payload.message[:60]}",
            provenance="api_submission",
            indicators=raw_result.get("indicators", [payload.message[:40]]),
        )

        return {
            "success": True,
            "data": raw_result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"SMS threat detection failed: {str(exc)}",
        )


# ---------------------------------------------------------------------------
# Real-Time Monitoring endpoints
# ---------------------------------------------------------------------------

@app.post("/api/v1/monitoring/start", tags=["Monitoring"])
async def start_monitoring():
    return monitoring_engine.start()

@app.post("/api/v1/monitoring/stop", tags=["Monitoring"])
async def stop_monitoring():
    return monitoring_engine.stop()

@app.get("/api/v1/monitoring/status", tags=["Monitoring"])
async def monitoring_status():
    return monitoring_engine.get_status()

@app.get("/api/v1/monitoring/events", tags=["Monitoring"])
async def monitoring_events(limit: int = 50, since_id: Optional[int] = None):
    raw_events = monitoring_engine.get_events(limit=limit, since_id=since_id)
    # Augment events with approximate IP geolocation metadata if IP indicators are present
    from backend_api.geo_service import get_ip_geolocation
    import re
    
    augmented_events = []
    for ev in raw_events:
        ev_copy = dict(ev)
        geo_info = None
        for ind in ev.get("indicators", []):
            # Check for IP pattern
            ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", ind)
            if ip_match:
                geo_info = get_ip_geolocation(ip_match.group(1))
                if geo_info:
                    break
        ev_copy["geo"] = geo_info
        augmented_events.append(ev_copy)

    return {
        "success": True,
        "events": augmented_events,
        "status": monitoring_engine.get_status(),
    }


# ---------------------------------------------------------------------------
# AI Security Assistant endpoint
# ---------------------------------------------------------------------------

@app.post("/api/v1/assistant/query", tags=["Assistant"])
async def assistant_query(payload: AssistantQueryPayload):
    return assistant_service.query(payload.question, payload.context)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend_api.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )
