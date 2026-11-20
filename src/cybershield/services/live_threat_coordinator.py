"""
Real-time Network Threat Coordinator for CyberShield.
Integrates LiveSnifferService, FlowManager, FlowExtractor, ThreatPipelineService,
BehavioralPortScanDetector, and LiveEventHub into a unified non-blocking pipeline.
"""

from collections import deque
import dataclasses
import datetime
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional
import uuid

import pandas as pd

from detectors.network.inference import detect_network_threat, get_detector
from detectors.network.schemas import ThreatResult
from detectors.network.advisory_adapter import build_network_advisory
from src.cybershield.ingestion.flow_manager import FlowManager, FlowState
from src.cybershield.ingestion.flow_extractor import extract_features_from_flow
from src.cybershield.ingestion.live_sniffer import LiveSnifferService, SnifferConfig
from src.cybershield.explainability.flow_explainer import get_flow_explainer
from src.cybershield.detectors.behavioral_scanner import BehavioralPortScanDetector, ScanAlert

logger = logging.getLogger("cybershield.realtime_coordinator")


class LiveThreatCoordinator:
    """
    Coordinates continuous packet capture, flow tracking, model inference,
    cross-flow behavioral scanning detection, and event publishing.
    """

    def __init__(
        self,
        config: Optional[SnifferConfig] = None,
        max_events_history: int = 200,
        event_listener: Optional[Callable[[Dict[str, Any]], None]] = None,
        scan_window_seconds: float = 30.0,
        scan_port_threshold: int = 5,
    ):
        self.config = config or SnifferConfig()
        self.event_listener = event_listener

        # Thread-safe listener registry for SSE/WebSocket/subscribers
        self._listeners_lock = threading.Lock()
        self._listeners: List[Callable[[Dict[str, Any]], None]] = []
        if event_listener:
            self._listeners.append(event_listener)

        # Thread-safe ring buffer for real-time events
        self._events_lock = threading.Lock()
        self._events: deque = deque(maxlen=max_events_history)

        # Granular pipeline metrics tracking
        self._metrics_lock = threading.Lock()
        self.inferences_attempted: int = 0
        self.inferences_completed: int = 0
        self.benign_predictions: int = 0
        self.non_benign_predictions: int = 0
        self.behavioral_alerts_count: int = 0
        self.feature_extraction_errors: int = 0
        self.inference_errors: int = 0
        self.processing_errors: int = 0
        self.last_inference_time: Optional[str] = None
        self._latency_samples: deque = deque(maxlen=500)

        # Initialize Behavioral Port-Scan Detector
        self.behavioral_detector = BehavioralPortScanDetector(
            window_seconds=scan_window_seconds,
            port_threshold=scan_port_threshold,
        )

        # Initialize FlowManager
        self.flow_manager = FlowManager(
            inactivity_timeout_sec=self.config.inactivity_timeout_sec,
            max_flows=self.config.max_flows,
            on_flow_finalized=self._handle_finalized_flow,
        )

        # Initialize LiveSnifferService
        self.sniffer = LiveSnifferService(
            config=self.config,
            on_packet_callback=self.flow_manager.process_packet,
        )

        # Inactivity ticker thread
        self._ticker_thread: Optional[threading.Thread] = None
        self._stop_ticker = threading.Event()

    # Backward compatibility alias
    @property
    def inferences_count(self) -> int:
        with self._metrics_lock:
            return self.inferences_attempted

    @inferences_count.setter
    def inferences_count(self, val: int):
        with self._metrics_lock:
            self.inferences_attempted = val

    @property
    def detections_count(self) -> int:
        with self._metrics_lock:
            return self.non_benign_predictions + self.behavioral_alerts_count

    @property
    def benign_count(self) -> int:
        with self._metrics_lock:
            return self.benign_predictions

    def add_listener(self, callback: Callable[[Dict[str, Any]], None]):
        """Registers a subscriber for real-time detection events."""
        with self._listeners_lock:
            if callback not in self._listeners:
                self._listeners.append(callback)

    def remove_listener(self, callback: Callable[[Dict[str, Any]], None]):
        """Unregisters an event subscriber."""
        with self._listeners_lock:
            if callback in self._listeners:
                self._listeners.remove(callback)

    def get_interfaces(self) -> List[Dict[str, Any]]:
        """Returns the list of available network capture interfaces."""
        return LiveSnifferService.get_available_interfaces()

    def get_metrics(self) -> Dict[str, Any]:
        """Calculates monotonic latency statistics and pipeline health metrics."""
        sniffer_stats = self.sniffer.get_status()
        with self._metrics_lock:
            samples = list(self._latency_samples)
            inf_att = self.inferences_attempted
            inf_comp = self.inferences_completed
            ben_pred = self.benign_predictions
            non_ben = self.non_benign_predictions
            behav_alerts = self.behavioral_alerts_count
            ext_err = self.feature_extraction_errors
            inf_err = self.inference_errors
            proc_err = self.processing_errors
            last_ts = self.last_inference_time

        # Model readiness status check
        model_ready = False
        model_version = "RandomForestBaseline-v1"
        try:
            detector = get_detector()
            model_ready = detector._pipeline is not None
        except Exception:
            model_ready = False

        p50 = float(pd.Series(samples).quantile(0.50)) if samples else 0.0
        p95 = float(pd.Series(samples).quantile(0.95)) if samples else 0.0
        max_lat = max(samples) if samples else 0.0
        mean_lat = float(sum(samples) / len(samples)) if samples else 0.0

        return {
            "status": sniffer_stats["status"],
            "interface": sniffer_stats["interface"],
            "packets_captured": sniffer_stats["packets_captured"],
            "packets_processed": sniffer_stats["packets_processed"],
            "packets_dropped": sniffer_stats["packets_dropped"],
            "flows_active": self.flow_manager.active_flow_count,
            "flows_finalized": self.flow_manager.finalized_count,
            "inferences_attempted": inf_att,
            "inferences_completed": inf_comp,
            "benign_predictions": ben_pred,
            "non_benign_predictions": non_ben,
            "behavioral_alerts": behav_alerts,
            "feature_extraction_errors": ext_err,
            "model_inference_errors": inf_err,
            "processing_errors": proc_err,
            "last_inference_time": last_ts,
            "model_ready": model_ready,
            "model_identity": model_version,
            "sample_count": len(samples),
            "latency_p50_ms": round(p50, 2),
            "latency_p95_ms": round(p95, 2),
            "latency_mean_ms": round(mean_lat, 2),
            "latency_max_ms": round(max_lat, 2),
            # Preserved legacy fields for UI compatibility
            "detections_count": non_ben + behav_alerts,
            "benign_count": ben_pred,
        }

    def start(self, interface: Optional[str] = None, bpf_filter: Optional[str] = None) -> bool:
        """Starts live packet capture and flow expiration monitoring."""
        started = self.sniffer.start(interface=interface, bpf_filter=bpf_filter)
        if started:
            self._stop_ticker.clear()
            self._ticker_thread = threading.Thread(
                target=self._inactivity_ticker_worker,
                name="cybershield_inactivity_ticker",
                daemon=True,
            )
            self._ticker_thread.start()
        return started

    def stop(self) -> bool:
        """Stops live capture, terminates ticker, and finalizes remaining flows."""
        self._stop_ticker.set()
        stopped = self.sniffer.stop()

        # Finalize remaining active flows
        self.flow_manager.finalize_all(reason="shutdown")

        if self._ticker_thread and self._ticker_thread.is_alive():
            self._ticker_thread.join(timeout=2.0)

        return stopped

    def get_status(self) -> Dict[str, Any]:
        """Returns comprehensive capture and flow tracking status."""
        status = self.sniffer.get_status()
        status["flows_active"] = self.flow_manager.active_flow_count
        status["flows_finalized"] = self.flow_manager.finalized_count
        with self._events_lock:
            status["total_events"] = len(self._events)
        with self._metrics_lock:
            status["behavioral_alerts"] = self.behavioral_alerts_count
        return status

    def get_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns the most recent detection events in reverse chronological order."""
        with self._events_lock:
            ev_list = list(self._events)
        return ev_list[-limit:][::-1]

    def clear_events(self):
        """Clears the event ring buffer without corrupting cumulative metric counters."""
        with self._events_lock:
            self._events.clear()

    def publish_event(self, event_record: Dict[str, Any]):
        """Publishes an externally supplied event to all listeners and ring buffer history."""
        with self._metrics_lock:
            self.inferences_completed += 1
            if event_record.get("attack_class") == "BENIGN":
                self.benign_predictions += 1
            else:
                self.non_benign_predictions += 1
            self._latency_samples.append(float(event_record.get("latency_ms", 1.0)))

        with self._events_lock:
            self._events.append(event_record)

        with self._listeners_lock:
            subscribers = list(self._listeners)

        for sub in subscribers:
            try:
                sub(event_record)
            except Exception as sub_err:
                logger.warning("Subscriber listener exception: %s", sub_err)

    def inject_synthetic_packet(self, pkt: Any) -> bool:
        """Injects a packet into the sniffer pipeline."""
        return self.sniffer.inject_synthetic_packet(pkt)

    def _inactivity_ticker_worker(self):
        """Periodically polls flow manager for inactive flows (every 1 second)."""
        while not self._stop_ticker.is_set():
            time.sleep(1.0)
            now = time.time()
            self.flow_manager.check_inactivity(now)

    def _handle_finalized_flow(self, flow: FlowState):
        """Processes a finalized flow: feature extraction -> model inference -> behavioral scanner -> event emission."""
        try:
            t0 = time.perf_counter()
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

            # 1. Extract 78 canonical statistical features
            t_extract_start = time.perf_counter()
            features = None
            try:
                features = extract_features_from_flow(flow)
            except Exception as ext_err:
                with self._metrics_lock:
                    self.feature_extraction_errors += 1
                    self.processing_errors += 1
                logger.error("Feature extraction error: %s", ext_err)
                return

            t_extract_end = time.perf_counter()
            if not features:
                return

            extraction_ms = (t_extract_end - t_extract_start) * 1000.0

            # 2. Run real model inference
            t_infer_start = time.perf_counter()
            threat_res: Optional[ThreatResult] = None
            with self._metrics_lock:
                self.inferences_attempted += 1

            try:
                threat_res = detect_network_threat(features)
                with self._metrics_lock:
                    self.inferences_completed += 1
                    self.last_inference_time = now_iso
            except Exception as inf_err:
                with self._metrics_lock:
                    self.inference_errors += 1
                    self.processing_errors += 1
                logger.error("Network model inference error: %s", inf_err)
                return

            t_infer_end = time.perf_counter()
            inference_ms = (t_infer_end - t_infer_start) * 1000.0

            src_ip, dst_ip, sport, dport, proto = flow.key

            # 3. Cross-Flow Behavioral Port-Scan Detection
            scan_alert: Optional[ScanAlert] = None
            try:
                # Approximate flow timestamp from last packet
                flow_ts = flow.packets[-1].timestamp if flow.packets else time.time()
                scan_alert = self.behavioral_detector.record_flow(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    sport=sport,
                    dport=dport,
                    proto=proto,
                    timestamp=flow_ts,
                    packet_count=len(flow.packets),
                )
            except Exception as scan_err:
                logger.warning("Behavioral port scan analysis error: %s", scan_err)

            # 4. Determine Unified Threat Verdict & Provenance
            ml_attack_class = threat_res.attack_class
            ml_confidence = float(threat_res.confidence)
            behavioral_alerts = []

            # Initialize final verdict matching ML baseline
            final_threat_verdict = ml_attack_class
            final_severity = threat_res.severity
            detection_source = "ml_classifier"

            if scan_alert:
                behavioral_alerts.append(scan_alert.to_dict())
                with self._metrics_lock:
                    self.behavioral_alerts_count += 1

                # Behavioral detection elevates threat verdict transparently
                final_threat_verdict = "PortScan (Behavioral)"
                final_severity = scan_alert.severity
                detection_source = "behavioral_detector"

            # 5. Build Person 3 advisory & explainability
            t_expl_start = time.perf_counter()
            flow_meta = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": sport,
                "dst_port": dport,
                "protocol": proto,
                "duration_us": features.get("Flow Duration", 0.0),
                "finalization_reason": flow.finalization_reason,
            }
            if flow.host_header:
                flow_meta["host"] = flow.host_header

            advisory = build_network_advisory(threat_res, flow_metadata=flow_meta)
            if scan_alert and advisory:
                advisory["advisory_text"] = f"[BEHAVIORAL SCAN ALERT] {scan_alert.evidence}"
                advisory["recommendation"] = scan_alert.remediation_recommendation
                advisory["priority"] = scan_alert.severity

            # 6. Compute XAI Feature Attribution for Alert
            explanation_data = None
            try:
                explainer = get_flow_explainer()
                explanation_res = explainer.explain_flow(features, top_k=3)
                explanation_data = explanation_res.to_dict()
            except Exception as ex_err:
                logger.warning("Feature attribution skipped or failed: %s", ex_err)
                explanation_data = {
                    "status": "unavailable",
                    "method": "tree_decision_path_attribution",
                    "explained_class": threat_res.attack_class,
                    "contributions": [],
                    "error_category": "runtime_error",
                    "limitations": [f"Attribution failed: {ex_err}"],
                }

            t_expl_end = time.perf_counter()
            explanation_ms = (t_expl_end - t_expl_start) * 1000.0
            total_latency_ms = (time.perf_counter() - t0) * 1000.0

            # 7. Construct normalized detection event with transparent provenance
            event_id = f"net-{uuid.uuid4().hex[:12]}"
            indicators = [f"ip: {dst_ip}"]
            if flow.host_header:
                indicators.append(f"domain: {flow.host_header}")
            if scan_alert:
                indicators.append(f"scan: {scan_alert.distinct_ports_count} ports probed")

            is_loopback = (
                str(src_ip).startswith("127.")
                or str(dst_ip).startswith("127.")
                or src_ip in ("::1", "localhost")
                or dst_ip in ("::1", "localhost")
            )
            geo_info = {
                "is_loopback": is_loopback,
                "location_type": "loopback_local" if is_loopback else "non_geographic",
                "display_location": "Local Workstation (Loopback / Offline)" if is_loopback else "Unknown / Non-Geographic",
                "coordinates": None,
                "external_lookup": False,
                "provenance": "local_hardware_interface",
                "country": "LOCAL",
                "city": "LOCALHOST",
            }

            event_record = {
                "event_id": event_id,
                "timestamp": now_iso,
                "source": "network",
                # Transparent dual provenance fields
                "attack_class": final_threat_verdict,
                "ml_attack_class": ml_attack_class,
                "ml_confidence": ml_confidence,
                "behavioral_alerts": behavioral_alerts,
                "detection_source": detection_source,
                "final_threat_verdict": final_threat_verdict,
                "threat_type": "intrusion" if final_threat_verdict != "BENIGN" else "normal",
                "severity": final_severity,
                "confidence": ml_confidence if not scan_alert else max(ml_confidence, scan_alert.confidence),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": sport,
                "dst_port": dport,
                "protocol": proto,
                "indicators": indicators,
                "advisory": advisory,
                "explanation": explanation_data,
                "geo": geo_info,
                "latency_ms": round(total_latency_ms, 2),
                "stage_latencies": {
                    "extraction_ms": round(extraction_ms, 2),
                    "inference_ms": round(inference_ms, 2),
                    "explanation_ms": round(explanation_ms, 2),
                    "total_ms": round(total_latency_ms, 2),
                },
                "finalization_reason": flow.finalization_reason,
                "packet_count": len(flow.packets),
            }

            # Update metrics
            with self._metrics_lock:
                if threat_res.attack_class == "BENIGN":
                    self.benign_predictions += 1
                else:
                    self.non_benign_predictions += 1
                self._latency_samples.append(total_latency_ms)

            with self._events_lock:
                self._events.append(event_record)

            # Broadcast to all registered subscribers
            with self._listeners_lock:
                subscribers = list(self._listeners)

            for sub in subscribers:
                try:
                    sub(event_record)
                except Exception as sub_err:
                    logger.warning("Subscriber listener exception: %s", sub_err)

        except Exception as e:
            with self._metrics_lock:
                self.processing_errors += 1
            logger.error("Error evaluating finalized flow: %s", e)


# Global coordinator instance (lazy)
_coordinator_instance: Optional[LiveThreatCoordinator] = None


def get_live_coordinator() -> LiveThreatCoordinator:
    global _coordinator_instance
    if _coordinator_instance is None:
        _coordinator_instance = LiveThreatCoordinator()
    return _coordinator_instance


def reset_live_coordinator(
    config: Optional[SnifferConfig] = None,
    scan_window_seconds: float = 30.0,
    scan_port_threshold: int = 5,
) -> LiveThreatCoordinator:
    """Resets the singleton coordinator with a fresh instance (for isolated testing)."""
    global _coordinator_instance
    if _coordinator_instance:
        try:
            _coordinator_instance.stop()
        except Exception:
            pass
    _coordinator_instance = LiveThreatCoordinator(
        config=config,
        scan_window_seconds=scan_window_seconds,
        scan_port_threshold=scan_port_threshold,
    )
    return _coordinator_instance
