"""
Live Packet Sniffer Service for Bharat AI-SoC.
Provides controlled asynchronous packet capture, rate-bounded packet queues,
interface validation, and graceful stop/error handling.
"""

from dataclasses import dataclass, field
import datetime
import logging
import queue
import threading
import time
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("bharat_ai_soc.live_sniffer")


@dataclass
class SnifferConfig:
    enabled: bool = False
    interface: Optional[str] = None
    bpf_filter: str = "ip and (tcp or udp)"
    inactivity_timeout_sec: float = 5.0
    max_flows: int = 5000
    queue_capacity: int = 10000
    batch_size: int = 50
    shutdown_timeout_sec: float = 3.0


@dataclass
class SnifferStats:
    status: str = "STOPPED"  # STOPPED, STARTING, RUNNING, STOPPING, ERROR, BLOCKED_PERMISSIONS
    interface: Optional[str] = None
    started_at: Optional[str] = None
    packets_captured: int = 0
    packets_processed: int = 0
    packets_dropped: int = 0
    flows_active: int = 0
    flows_finalized: int = 0
    last_error: Optional[str] = None


class LiveSnifferService:
    """
    Asynchronous network sniffer service that decodes packet headers and updates a FlowManager.
    Does not persist or expose packet payload content.
    """

    def __init__(
        self,
        config: Optional[SnifferConfig] = None,
        on_packet_callback: Optional[Callable[..., None]] = None,
    ):
        self.config = config or SnifferConfig()
        self.on_packet_callback = on_packet_callback
        self.stats = SnifferStats(interface=self.config.interface)

        self._packet_queue: "queue.Queue[Any]" = queue.Queue(maxsize=self.config.queue_capacity)
        self._sniffer_thread: Optional[threading.Thread] = None
        self._processing_thread: Optional[threading.Thread] = None
        self._async_sniffer = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "status": self.stats.status,
                "interface": self.stats.interface,
                "started_at": self.stats.started_at,
                "packets_captured": self.stats.packets_captured,
                "packets_processed": self.stats.packets_processed,
                "packets_dropped": self.stats.packets_dropped,
                "flows_active": self.stats.flows_active,
                "flows_finalized": self.stats.flows_finalized,
                "last_error": self.stats.last_error,
            }

    @staticmethod
    def get_available_interfaces() -> List[Dict[str, Any]]:
        """
        Discovers supported network capture interfaces without exposing host sensitive data.
        """
        interfaces = []
        try:
            from scapy.all import get_if_list, conf
            raw_list = list(get_if_list())
            default_iface = str(conf.iface) if hasattr(conf, "iface") else None
            for dev in raw_list:
                is_loopback = "loopback" in dev.lower() or dev == r"\Device\NPF_Loopback"
                is_default = (dev == default_iface)
                name = "Npcap Loopback Adapter (Local Traffic)" if is_loopback else dev
                interfaces.append({
                    "id": dev,
                    "name": name,
                    "is_loopback": is_loopback,
                    "is_default": is_default,
                    "supported": True,
                })
        except Exception as e:
            logger.warning("Could not enumerate network interfaces: %s", e)
        return interfaces

    def start(self, interface: Optional[str] = None, bpf_filter: Optional[str] = None) -> bool:
        """
        Starts live packet capture on the specified or default interface.
        Returns True if successfully transitioned to RUNNING, False otherwise.
        """
        with self._lock:
            if self.stats.status in ("RUNNING", "STARTING"):
                logger.warning("Sniffer already running or starting.")
                return False

            self.stats.status = "STARTING"
            self.stats.last_error = None

            # Resolve loopback aliases
            resolved_iface = interface if interface is not None else self.config.interface
            if resolved_iface in ("loopback", "NPF_Loopback", "127.0.0.1", "localhost"):
                resolved_iface = r"\Device\NPF_Loopback"
            elif resolved_iface is None:
                # Default to Npcap Loopback if present on Windows for safe, non-promiscuous local testing
                try:
                    from scapy.all import get_if_list
                    if r"\Device\NPF_Loopback" in get_if_list():
                        resolved_iface = r"\Device\NPF_Loopback"
                except Exception:
                    pass

            # Validate interface existence if specified
            if resolved_iface:
                try:
                    from scapy.all import get_if_list
                    avail = list(get_if_list())
                    if resolved_iface not in avail:
                        self.stats.status = "ERROR"
                        self.stats.last_error = f"Interface '{resolved_iface}' not found on system."
                        logger.error("Capture start failed: interface '%s' not in available interfaces", resolved_iface)
                        return False
                except Exception as e:
                    logger.warning("Interface validation check warning: %s", e)

            self.config.interface = resolved_iface
            if bpf_filter:
                self.config.bpf_filter = bpf_filter

            self.stats.interface = self.config.interface

        # Check Scapy availability
        try:
            from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP
        except ImportError as e:
            with self._lock:
                self.stats.status = "ERROR"
                self.stats.last_error = f"Scapy dependency missing: {e}"
            return False

        self._stop_event.clear()

        # Start background worker queue thread
        self._processing_thread = threading.Thread(
            target=self._process_queue_worker,
            name="bharat_sniffer_worker",
            daemon=True,
        )
        self._processing_thread.start()

        # Packet reception callback from Scapy
        def _scapy_packet_handler(pkt):
            if self._stop_event.is_set():
                return
            with self._lock:
                self.stats.packets_captured += 1
            try:
                self._packet_queue.put_nowait(pkt)
            except queue.Full:
                with self._lock:
                    self.stats.packets_dropped += 1

        # Launch Scapy AsyncSniffer safely
        try:
            self._async_sniffer = AsyncSniffer(
                iface=self.config.interface,
                filter=self.config.bpf_filter,
                prn=_scapy_packet_handler,
                store=False,
            )
            self._async_sniffer.start()
            with self._lock:
                self.stats.status = "RUNNING"
                self.stats.started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            logger.info("Live packet capture started on interface %s", self.config.interface)
            return True
        except PermissionError as e:
            with self._lock:
                self.stats.status = "BLOCKED_PERMISSIONS"
                self.stats.last_error = f"Insufficient raw socket / capture permissions: {e}"
            self.stop()
            return False
        except Exception as e:
            with self._lock:
                self.stats.status = "ERROR"
                self.stats.last_error = f"Capture initialization error: {e}"
            self.stop()
            return False

    def stop(self) -> bool:
        """
        Stops live capture cleanly and drains bounded queues.
        """
        with self._lock:
            if self.stats.status in ("STOPPED", "STOPPING"):
                return True
            self.stats.status = "STOPPING"

        self._stop_event.set()

        if self._async_sniffer is not None:
            try:
                self._async_sniffer.stop()
            except Exception as e:
                logger.error("Error stopping AsyncSniffer: %s", e)
            finally:
                self._async_sniffer = None

        if self._processing_thread and self._processing_thread.is_alive():
            self._processing_thread.join(timeout=self.config.shutdown_timeout_sec)

        with self._lock:
            self.stats.status = "STOPPED"
        logger.info("Live packet capture stopped cleanly.")
        return True

    def inject_synthetic_packet(self, pkt: Any) -> bool:
        """
        Allows deterministic injection of test / synthetic packets into the queue.
        """
        try:
            self._packet_queue.put_nowait(pkt)
            with self._lock:
                self.stats.packets_captured += 1
            return True
        except queue.Full:
            with self._lock:
                self.stats.packets_dropped += 1
            return False

    def _process_queue_worker(self):
        """Processes enqueued packets, extracting headers and delegating to callback."""
        from scapy.all import IP, IPv6, TCP, UDP, Raw

        while not self._stop_event.is_set():
            try:
                pkt = self._packet_queue.get(timeout=0.2)
            except queue.Empty:
                continue

            try:
                has_ip = pkt.haslayer(IP)
                has_ipv6 = pkt.haslayer(IPv6)
                if not (has_ip or has_ipv6):
                    continue

                is_tcp = pkt.haslayer(TCP)
                is_udp = pkt.haslayer(UDP)
                if not (is_tcp or is_udp):
                    continue

                ip_layer = pkt[IP] if has_ip else pkt[IPv6]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                proto = ip_layer.proto if has_ip else ip_layer.nh
                sport = int(pkt[TCP].sport if is_tcp else pkt[UDP].sport)
                dport = int(pkt[TCP].dport if is_tcp else pkt[UDP].dport)

                pkt_len = len(pkt)
                payload_len = 0
                header_len = 0
                tcp_flags = ""
                tcp_window = -1
                host_hdr = None

                if is_tcp:
                    payload_len = len(pkt[TCP].payload)
                    header_len = int(pkt[TCP].dataofs * 4)
                    tcp_flags = str(pkt[TCP].flags)
                    tcp_window = int(pkt[TCP].window)

                    # Extract Host header safely from HTTP GET/POST if present in Raw payload
                    if pkt.haslayer(Raw):
                        raw_bytes = bytes(pkt[Raw].load)
                        if b"Host: " in raw_bytes:
                            try:
                                h_part = raw_bytes.split(b"Host: ")[1].split(b"\r\n")[0]
                                host_hdr = h_part.decode("utf-8", errors="ignore").strip()
                            except Exception:
                                pass
                elif is_udp:
                    payload_len = len(pkt[UDP].payload)
                    header_len = 8

                pkt_time = float(getattr(pkt, "time", time.time()))

                if self.on_packet_callback:
                    self.on_packet_callback(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        sport=sport,
                        dport=dport,
                        proto=proto,
                        timestamp=pkt_time,
                        packet_len=pkt_len,
                        payload_len=payload_len,
                        header_len=header_len,
                        tcp_flags=tcp_flags,
                        tcp_window=tcp_window,
                        host_header=host_hdr,
                    )

                with self._lock:
                    self.stats.packets_processed += 1
            except Exception as e:
                logger.error("Error decoding enqueued packet: %s", e)
            finally:
                self._packet_queue.task_done()

