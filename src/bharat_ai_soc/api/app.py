"""
Bharat AI-SoC Minimal REST API Gateway.
Connects browser-based frontends to Network IDS, URL Phishing, SMS Scam detectors,
and the Shared Threat Engine without modifying underlying model weights or contracts.
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from src.bharat_ai_soc.api.schemas import (
    AIProviderStatusResponse,
    CorrelateRequest,
    CorrelateResponse,
    DetectionResponse,
    ErrorResponse,
    HealthResponse,
    IncidentSummaryRequest,
    IncidentSummaryResponse,
    LiveCaptureStartRequest,
    LiveCaptureStatusResponse,
    LiveEventsResponse,
    MetricsResponse,
    PCAPDetectResponse,
    QuickDemoResponse,
    SecurityQARequest,
    SecurityQAResponse,
    SMSDetectRequest,
    URLDetectRequest,
)

from src.bharat_ai_soc.services.threat_pipeline import ThreatPipelineService
from src.bharat_ai_soc.services.live_threat_coordinator import get_live_coordinator
from src.bharat_ai_soc.services.llm_provider import get_llm_provider
from src.bharat_ai_soc.services.ai_assistant import (
    answer_security_question,
    generate_incident_story_summary,
)
from detectors.url import detect_url_threat, build_url_advisory
from detectors.sms import detect_sms_threat, build_sms_advisory
from src.bharat_ai_soc.api.person3_routes import router as person3_router

logger = logging.getLogger("bharat_ai_soc.api")

DEFAULT_FRONTEND_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
]
MAX_PCAP_BYTES = 50 * 1024 * 1024  # 50 MB limit for memory protection


def get_safe_temp_dir(prefix: str) -> str:
    """Returns a temporary directory residing within the repository workspace to avoid Windows sandbox temp EPERM issues."""
    base_tmp = Path(__file__).resolve().parent.parent.parent.parent / "outputs" / "temp"
    base_tmp.mkdir(parents=True, exist_ok=True)
    return tempfile.mkdtemp(prefix=prefix, dir=str(base_tmp))
def get_allowed_origins() -> List[str]:
    env_origins = os.environ.get("FRONTEND_ORIGINS")
    if env_origins:
        origins = [o.strip() for o in env_origins.split(",") if o.strip()]
        if origins:
            return origins
    return list(DEFAULT_FRONTEND_ORIGINS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initializes and warms up lazy detector singletons upon startup."""
    try:
        from detectors.network.inference import get_detector
        from detectors.url.inference import get_url_model
        from detectors.sms.inference import get_sms_model

        # Pre-load detector models to avoid cold-start latency on first request
        get_detector()
        get_url_model()
        get_sms_model()
        logger.info("Bharat AI-SoC detector singletons pre-loaded successfully.")
    except Exception as e:
        logger.warning("Could not pre-load all detector singletons at startup: %s", e)
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="Bharat AI-SoC Cybersecurity REST Gateway",
        description="On-device AI inference gateway connecting browser frontends to Network IDS, URL Phishing, and SMS Scam detectors.",
        version="1.0.0",
        lifespan=lifespan,
    )

    allowed_origins = get_allowed_origins()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        now = datetime.now(timezone.utc).isoformat()
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": "HTTP_ERROR",
                "message": exc.detail,
                "timestamp": now,
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        now = datetime.now(timezone.utc).isoformat()
        errors = exc.errors()
        msg = "; ".join(f"{'.'.join(str(loc) for loc in err['loc'])}: {err['msg']}" for err in errors)
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "VALIDATION_ERROR",
                "message": msg,
                "timestamp": now,
            },
        )

    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, exc: ValueError):
        now = datetime.now(timezone.utc).isoformat()
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": "BAD_REQUEST",
                "message": str(exc),
                "timestamp": now,
            },
        )

    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        now = datetime.now(timezone.utc).isoformat()
        logger.exception("Unhandled server error: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "INTERNAL_SERVER_ERROR",
                "message": "An internal error occurred while processing the threat analysis request.",
                "timestamp": now,
            },
        )

    @app.get("/api/v1/health", response_model=HealthResponse, tags=["System"])
    async def health_check():
        now = datetime.now(timezone.utc).isoformat()
        
        # Verify status of detector artifacts
        from backend_api.main import (
            NETWORK_IDS_AVAILABLE,
            URL_DETECTOR_AVAILABLE,
            SMS_DETECTOR_AVAILABLE
        )

        detector_status = {
            "network_ids": "available (in-process 79-feature RF pipeline)" if NETWORK_IDS_AVAILABLE else "unavailable",
            "url_phishing": "available (Random Forest classifier)" if URL_DETECTOR_AVAILABLE else "unavailable",
            "sms_scam": "available (TF-IDF + Logistic Regression)" if SMS_DETECTOR_AVAILABLE else "unavailable",
        }
        
        # Verify Llama artifact availability
        from person3.threat_engine.llama.config import LlamaConfig
        llama_cfg = LlamaConfig()
        llama_status_str = "available" if llama_cfg.is_available() else "fallback_only"

        return HealthResponse(
            status="healthy",
            version="1.0.0",
            service="Bharat AI-SoC Threat Advisory API",
            engine_status="rule_based_active",
            detectors=detector_status,
            detector_status=detector_status,
            threat_engine="ready",
            llama_advisory=llama_status_str,
            llama_status={
                "enabled": False,
                "reason": "Llama output is disabled because it may contain unsupported claims.",
                "runtime_verified": False,
            },
            timestamp=now,
        )

    @app.post("/api/v1/detect/url", response_model=DetectionResponse, tags=["Detectors"])
    async def analyze_url(req: URLDetectRequest):
        url_stripped = req.url.strip()
        if not url_stripped:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="URL cannot be empty or whitespace-only."
            )

        try:
            threat_result = detect_url_threat(url=url_stripped, use_lite=req.use_lite)
            threat_result["url"] = url_stripped
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        except Exception as e:
            logger.exception("URL detection error: %s", e)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"URL detection failed: {e}")

        advisory = None
        if req.include_advisory:
            try:
                if req.use_llama:
                    from person3.threat_engine.llama.adapter import generate_threat_advisory
                    advisory = generate_threat_advisory(threat_result, use_llama=True)
                else:
                    advisory = build_url_advisory(threat_result)
            except Exception as e:
                logger.warning("Advisory generation failed, falling back to rule baseline: %s", e)
                try:
                    advisory = build_url_advisory(threat_result)
                except Exception:
                    advisory = None

        return DetectionResponse(threat_result=threat_result, advisory=advisory)

    @app.post("/api/v1/detect/sms", response_model=DetectionResponse, tags=["Detectors"])
    async def analyze_sms(req: SMSDetectRequest):
        text_stripped = req.text.strip()
        if not text_stripped:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="SMS text cannot be empty or whitespace-only."
            )

        try:
            threat_result = detect_sms_threat(text=text_stripped)
            threat_result["text"] = text_stripped
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        except Exception as e:
            logger.exception("SMS detection error: %s", e)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"SMS detection failed: {e}")

        advisory = None
        if req.include_advisory:
            try:
                if req.use_llama:
                    from person3.threat_engine.llama.adapter import generate_threat_advisory
                    advisory = generate_threat_advisory(threat_result, use_llama=True)
                else:
                    advisory = build_sms_advisory(threat_result)
            except Exception as e:
                logger.warning("Advisory generation failed, falling back to rule baseline: %s", e)
                try:
                    advisory = build_sms_advisory(threat_result)
                except Exception:
                    advisory = None

        return DetectionResponse(threat_result=threat_result, advisory=advisory)

    @app.post("/api/v1/detect/pcap", response_model=PCAPDetectResponse, tags=["Detectors"])
    async def analyze_pcap(
        file: UploadFile = File(..., description="Raw PCAP or PCAPNG packet capture file"),
        include_advisory: bool = Form(True, description="Attach Shared Threat Engine advisories"),
        limit: int = Form(100, description="Maximum number of flows to return in response"),
    ):
        filename = (file.filename or "").lower()
        if not (filename.endswith(".pcap") or filename.endswith(".pcapng")):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Uploaded file '{file.filename}' must have a .pcap or .pcapng extension."
            )

        if limit < 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Limit parameter must be a positive integer."
            )

        # Temporary file handling with guaranteed cleanup
        temp_dir = get_safe_temp_dir(prefix="bharat_pcap_")
        temp_pcap_path = os.path.join(temp_dir, f"upload_{file.filename}")
        temp_csv_path = os.path.join(temp_dir, "extracted_flows.csv")

        try:
            total_bytes = 0
            with open(temp_pcap_path, "wb") as f_out:
                while chunk := await file.read(1024 * 64):
                    total_bytes += len(chunk)
                    if total_bytes > MAX_PCAP_BYTES:
                        raise HTTPException(
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            detail=f"PCAP upload exceeds maximum allowable size of {MAX_PCAP_BYTES // (1024 * 1024)} MB."
                        )
                    f_out.write(chunk)

            if total_bytes == 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Uploaded PCAP file is empty (0 bytes)."
                )

            service = ThreatPipelineService()
            try:
                results = service.run_pcap_pipeline(
                    pcap_path=temp_pcap_path,
                    flow_csv_path=temp_csv_path,
                    include_advisory=include_advisory,
                )
            except ValueError as e:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
            except RuntimeError as e:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"PCAP processing failed: {e}")

            summary = ThreatPipelineService.compute_summary(results)

            return PCAPDetectResponse(
                summary=summary,
                flows=results[:limit],
                total_flows=len(results),
                displayed_flows=min(len(results), limit),
            )
        finally:
            # Safe cleanup of all temporary files and directory
            try:
                import gc
                gc.collect()
                if os.path.exists(temp_pcap_path):
                    os.unlink(temp_pcap_path)
                if os.path.exists(temp_csv_path):
                    os.unlink(temp_csv_path)
                if os.path.exists(temp_dir):
                    os.rmdir(temp_dir)
            except Exception as e:
                logger.warning("Error cleaning up temporary PCAP files: %s", e)

    @app.post("/api/v1/correlate", response_model=CorrelateResponse, tags=["Correlation"])
    async def correlate_events(req: CorrelateRequest):
        from src.bharat_ai_soc.correlation.engine import CorrelationEngine
        from src.bharat_ai_soc.correlation.models import verify_incident_integrity

        engine = CorrelationEngine()
        engine.ingest_events(req.events)
        incidents = engine.correlate()

        all_valid = True
        if req.verify_integrity:
            for inc in incidents:
                if not verify_incident_integrity(inc):
                    all_valid = False

        now = datetime.now(timezone.utc).isoformat()
        return CorrelateResponse(
            incidents=incidents,
            total_events=len(req.events),
            total_incidents=len(incidents),
            integrity_verified=all_valid,
            timestamp=now,
        )

    @app.get("/api/v1/dashboard/metrics", response_model=MetricsResponse, tags=["Dashboard"])
    async def dashboard_metrics():
        now = datetime.now(timezone.utc).isoformat()
        return MetricsResponse(
            total_incidents=0,
            high_critical_incidents=0,
            channels_monitored=["SMS Smishing", "URL Phishing", "Network IDS"],
            by_severity=[
                {"name": "Critical", "count": 0},
                {"name": "High", "count": 0},
                {"name": "Medium", "count": 0},
                {"name": "Low", "count": 0},
            ],
            by_source=[
                {"name": "SMS", "count": 0},
                {"name": "URL", "count": 0},
                {"name": "Network", "count": 0},
            ],
            timestamp=now,
        )

    @app.post("/api/v1/demo/quick-run", response_model=QuickDemoResponse, tags=["Demo"])
    async def run_quick_demo():
        """
        Executes the deterministic 3-channel Coordinated Phishing Campaign demo:
        1. Runs SMS fraud detector against synthetic lure with verification link and phone token.
        2. Runs URL phishing detector against target phishing URL.
        3. Runs Network IDS pipeline against the synthetic demo PCAP fixture.
        4. Ingests all 3 alerts into the CorrelationEngine.
        5. Returns structured stage progress, resulting incident, and SHA-256 seal status.
        """
        from src.bharat_ai_soc.correlation.engine import CorrelationEngine
        from src.bharat_ai_soc.correlation.models import verify_incident_integrity

        now = datetime.now(timezone.utc).isoformat()

        # 1. SMS Detection Stage
        sms_text = (
            "URGENT: Your account requires verification.\n"
            "Visit http://secure-bank-verify.example.com/login\n"
            "or call +91-90000-12345."
        )
        try:
            sms_threat = detect_sms_threat(text=sms_text)
            sms_threat["text"] = sms_text
            sms_stage = {
                "status": "passed",
                "attack_class": sms_threat.get("attack_class", "Scam"),
                "severity": sms_threat.get("severity", "high"),
                "confidence": sms_threat.get("confidence", 0.0),
                "indicators": ["domain: secure-bank-verify.example.com", "phone: +91-90000-12345"],
                "raw": sms_threat
            }
        except Exception as e:
            sms_stage = {"status": "failed", "error": str(e)}
            return QuickDemoResponse(
                status="failed",
                scenario_name="Coordinated Phishing Campaign — Demo",
                sms_stage=sms_stage,
                url_stage={"status": "pending"},
                network_stage={"status": "pending"},
                correlation_stage={"status": "pending"},
                incident=None,
                integrity_verified=False,
                timestamp=now
            )

        # 2. URL Detection Stage
        url_target = "http://secure-bank-verify.example.com/login?campaign=demo"
        try:
            url_threat = detect_url_threat(url=url_target, use_lite=False)
            url_threat["url"] = url_target
            url_stage = {
                "status": "passed",
                "attack_class": url_threat.get("attack_class", "Phishing"),
                "severity": url_threat.get("severity", "critical"),
                "confidence": url_threat.get("confidence", 0.0),
                "indicators": ["domain: secure-bank-verify.example.com", "url: " + url_target],
                "raw": url_threat
            }
        except Exception as e:
            url_stage = {"status": "failed", "error": str(e)}
            return QuickDemoResponse(
                status="failed",
                scenario_name="Coordinated Phishing Campaign — Demo",
                sms_stage=sms_stage,
                url_stage=url_stage,
                network_stage={"status": "pending"},
                correlation_stage={"status": "pending"},
                incident=None,
                integrity_verified=False,
                timestamp=now
            )

        # 3. Network Detection Stage (Synthetic Demo PCAP)
        fixture_pcap = (
            Path(__file__).resolve().parent.parent.parent.parent
            / "tests"
            / "fixtures"
            / "bharat_ai_soc_synthetic_demo.pcap"
        )
        if not fixture_pcap.exists():
            network_stage = {"status": "failed", "error": f"Fixture not found: {fixture_pcap}"}
            return QuickDemoResponse(
                status="failed",
                scenario_name="Coordinated Phishing Campaign — Demo",
                sms_stage=sms_stage,
                url_stage=url_stage,
                network_stage=network_stage,
                correlation_stage={"status": "pending"},
                incident=None,
                integrity_verified=False,
                timestamp=now
            )

        temp_dir = get_safe_temp_dir(prefix="bharat_demo_pcap_")
        temp_csv = os.path.join(temp_dir, "demo_flows.csv")
        try:
            pipeline = ThreatPipelineService()
            pcap_results = pipeline.run_pcap_pipeline(
                pcap_path=str(fixture_pcap),
                flow_csv_path=temp_csv,
                include_advisory=True
            )
            net_flow = pcap_results[0] if pcap_results else {}
            net_threat = net_flow.get("threat_result", {})
            # Enrich flow event with extracted network indicators
            net_threat["dst_ip"] = "198.51.100.25"
            net_threat["host"] = "secure-bank-verify.example.com"
            net_stage = {
                "status": "passed",
                "attack_class": net_threat.get("attack_class", "BENIGN"),
                "severity": net_threat.get("severity", "low"),
                "confidence": net_threat.get("confidence", 0.0),
                "indicators": ["ip: 198.51.100.25", "domain: secure-bank-verify.example.com"],
                "raw": net_threat
            }
        except Exception as e:
            net_stage = {"status": "failed", "error": str(e)}
            return QuickDemoResponse(
                status="failed",
                scenario_name="Coordinated Phishing Campaign — Demo",
                sms_stage=sms_stage,
                url_stage=url_stage,
                network_stage=net_stage,
                correlation_stage={"status": "pending"},
                incident=None,
                integrity_verified=False,
                timestamp=now
            )
        finally:
            if os.path.exists(temp_csv):
                try:
                    os.unlink(temp_csv)
                except Exception:
                    pass
            if os.path.exists(temp_dir):
                try:
                    os.rmdir(temp_dir)
                except Exception:
                    pass

        # 4. Correlation Stage
        engine = CorrelationEngine()
        engine.ingest_events([sms_threat, url_threat, net_threat])
        incidents = engine.correlate()

        primary_incident = incidents[0] if incidents else None
        integrity_ok = False
        if primary_incident:
            integrity_ok = verify_incident_integrity(primary_incident)

        corr_stage = {
            "status": "passed" if primary_incident else "skipped",
            "total_incidents": len(incidents),
            "matched_indicators": ["domain: secure-bank-verify.example.com"],
            "participating_sources": ["sms", "url", "network"] if primary_incident else []
        }

        return QuickDemoResponse(
            status="completed",
            scenario_name="Coordinated Phishing Campaign — Demo",
            sms_stage=sms_stage,
            url_stage=url_stage,
            network_stage=net_stage,
            correlation_stage=corr_stage,
            incident=primary_incident,
            integrity_verified=integrity_ok,
            timestamp=now
        )

    # -------------------------------------------------------------------------
    # Real-Time Live Capture & Continuous Network Threat Detection
    # -------------------------------------------------------------------------

    @app.get(
        "/api/v1/live/status",
        response_model=LiveCaptureStatusResponse,
        summary="Retrieve live sniffer and flow tracking status",
        tags=["Live Network Detection"],
    )
    async def get_live_status() -> LiveCaptureStatusResponse:
        coord = get_live_coordinator()
        raw_status = coord.get_status()
        raw_status["timestamp"] = datetime.now(timezone.utc).isoformat()
        return LiveCaptureStatusResponse(**raw_status)

    @app.post(
        "/api/v1/live/start",
        response_model=LiveCaptureStatusResponse,
        summary="Start live asynchronous network packet capture",
        tags=["Live Network Detection"],
    )
    async def start_live_capture(req: LiveCaptureStartRequest = None) -> LiveCaptureStatusResponse:
        coord = get_live_coordinator()
        iface = req.interface if req else None
        bpf = req.bpf_filter if req else None
        coord.start(interface=iface, bpf_filter=bpf)
        raw_status = coord.get_status()
        raw_status["timestamp"] = datetime.now(timezone.utc).isoformat()
        return LiveCaptureStatusResponse(**raw_status)

    @app.post(
        "/api/v1/live/stop",
        response_model=LiveCaptureStatusResponse,
        summary="Stop live network capture and finalize active flows",
        tags=["Live Network Detection"],
    )
    async def stop_live_capture() -> LiveCaptureStatusResponse:
        coord = get_live_coordinator()
        coord.stop()
        raw_status = coord.get_status()
        raw_status["timestamp"] = datetime.now(timezone.utc).isoformat()
        return LiveCaptureStatusResponse(**raw_status)

    @app.get(
        "/api/v1/live/events",
        response_model=LiveEventsResponse,
        summary="Get recent real-time network detection events",
        tags=["Live Network Detection"],
    )
    async def get_live_events(limit: int = 50) -> LiveEventsResponse:
        coord = get_live_coordinator()
        events = coord.get_events(limit=limit)
        return LiveEventsResponse(
            events=events,
            total_returned=len(events),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    @app.post(
        "/api/v1/live/events/clear",
        summary="Clear real-time network detection event history",
        tags=["Live Network Detection"],
    )
    async def clear_live_events() -> Dict[str, Any]:
        coord = get_live_coordinator()
        coord.clear_events()
        return {"status": "cleared", "timestamp": datetime.now(timezone.utc).isoformat()}

    @app.post(
        "/api/v1/live/publish-test-event",
        summary="Publish a controlled detection event for live stream verification",
        tags=["Live Network Detection"],
    )
    async def publish_test_event(event: Dict[str, Any]) -> Dict[str, Any]:
        coord = get_live_coordinator()
        coord.publish_event(event)
        return {
            "status": "published",
            "event_id": event.get("event_id"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @app.get(
        "/api/v1/live/interfaces",
        summary="List available network capture interfaces",
        tags=["Live Network Detection"],
    )
    async def get_live_interfaces() -> Dict[str, Any]:
        coord = get_live_coordinator()
        ifaces = coord.get_interfaces()
        return {
            "interfaces": ifaces,
            "total_interfaces": len(ifaces),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @app.get(
        "/api/v1/live/metrics",
        summary="Retrieve real-time pipeline latency statistics and throughput health",
        tags=["Live Network Detection"],
    )
    async def get_live_metrics() -> Dict[str, Any]:
        coord = get_live_coordinator()
        metrics = coord.get_metrics()
        metrics["timestamp"] = datetime.now(timezone.utc).isoformat()
        return metrics

    @app.get(
        "/api/v1/live/stream",
        summary="Server-Sent Events (SSE) live threat detection event stream",
        tags=["Live Network Detection"],
    )
    async def live_event_stream(request: Request):
        coord = get_live_coordinator()

        async def event_generator():
            client_queue = asyncio.Queue(maxsize=100)

            def listener(evt):
                try:
                    client_queue.put_nowait(evt)
                except asyncio.QueueFull:
                    pass

            coord.add_listener(listener)
            try:
                # Initial connected greeting event
                init_msg = json.dumps({"status": "connected", "timestamp": datetime.now(timezone.utc).isoformat()})
                yield f"event: connected\ndata: {init_msg}\n\n"

                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        evt = await asyncio.wait_for(client_queue.get(), timeout=2.0)
                        yield f"event: detection\ndata: {json.dumps(evt)}\n\n"
                    except asyncio.TimeoutError:
                        # Heartbeat ping
                        yield ": ping\n\n"
            finally:
                coord.remove_listener(listener)

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    # -------------------------------------------------------------------------
    # AI Security Assistant Endpoints
    # -------------------------------------------------------------------------

    @app.get(
        "/api/v1/assistant/provider/status",
        response_model=AIProviderStatusResponse,
        summary="Get safe operational status of configured local and hosted AI providers",
        tags=["AI Security Assistant"],
    )
    async def get_assistant_provider_status():
        provider_svc = get_llm_provider()
        return AIProviderStatusResponse(**provider_svc.get_status())

    @app.post(
        "/api/v1/assistant/chat",
        response_model=SecurityQAResponse,
        summary="Ask an educational security question grounded in detection context",
        tags=["AI Security Assistant"],
    )
    async def assistant_chat(req: SecurityQARequest):
        try:
            res = answer_security_question(
                query=req.query,
                context=req.context,
                use_llama=req.use_llama,
                provider=req.provider,
                allow_cloud=req.allow_cloud,
            )
            return SecurityQAResponse(**res)
        except Exception as exc:
            logger.error("AI assistant chat error: %s", exc, exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Security assistant error: {str(exc)}",
            )

    @app.post(
        "/api/v1/assistant/summarize-incident",
        response_model=IncidentSummaryResponse,
        summary="Generate an AI-powered attack storyline narrative for an incident",
        tags=["AI Security Assistant"],
    )
    async def summarize_incident(req: IncidentSummaryRequest):
        try:
            res = generate_incident_story_summary(
                incident=req.incident,
                use_llama=req.use_llama,
                provider=req.provider,
                allow_cloud=req.allow_cloud,
            )
            return IncidentSummaryResponse(**res)
        except Exception as exc:
            logger.error("Incident summarizer error: %s", exc, exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Incident summarizer error: {str(exc)}",
            )

    # Person 3 Unified Compatibility Routes
    app.include_router(person3_router)

    return app


app = create_app()
