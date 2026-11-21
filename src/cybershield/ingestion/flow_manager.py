"""
Real-time Network Flow Manager for CyberShield.
Maintains bidirectional connection states, tracks packet length statistics and TCP flags,
and finalizes flows upon inactivity timeout, shutdown, or capacity pressure.
"""

from collections import OrderedDict
from dataclasses import dataclass, field
import datetime
import logging
import math
from typing import Any, Callable, Dict, List, Optional, Tuple
import numpy as np

logger = logging.getLogger("cybershield.flow_manager")

FlowKey = Tuple[str, str, int, int, int]  # (src_ip, dst_ip, sport, dport, proto)


@dataclass
class PacketMetadata:
    timestamp: float
    length: int
    payload_len: int
    header_len: int
    direction: str  # "FORWARD" or "BACKWARD"
    tcp_flags: str = ""
    tcp_window: int = -1


@dataclass
class FlowState:
    key: FlowKey
    start_time: float
    last_seen: float
    packets: List[PacketMetadata] = field(default_factory=list)
    host_header: Optional[str] = None
    finalization_reason: str = "active"

    @property
    def fwd_packets(self) -> List[PacketMetadata]:
        return [p for p in self.packets if p.direction == "FORWARD"]

    @property
    def bwd_packets(self) -> List[PacketMetadata]:
        return [p for p in self.packets if p.direction == "BACKWARD"]


class FlowManager:
    """
    Manages active bidirectional network flows with bounded capacity and inactivity expiration.
    """

    def __init__(
        self,
        inactivity_timeout_sec: float = 5.0,
        max_flows: int = 5000,
        on_flow_finalized: Optional[Callable[[FlowState], None]] = None,
    ):
        self.inactivity_timeout_sec = inactivity_timeout_sec
        self.max_flows = max_flows
        self.on_flow_finalized = on_flow_finalized
        self._flows: "OrderedDict[Tuple[str, str, int, int, int], FlowState]" = OrderedDict()
        self._finalized_count = 0
        self._dropped_flows_count = 0

    @property
    def active_flow_count(self) -> int:
        return len(self._flows)

    @property
    def finalized_count(self) -> int:
        return self._finalized_count

    def process_packet(
        self,
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int,
        proto: int,
        timestamp: float,
        packet_len: int,
        payload_len: int,
        header_len: int,
        tcp_flags: str = "",
        tcp_window: int = -1,
        host_header: Optional[str] = None,
    ) -> Optional[FlowState]:
        """
        Updates an existing flow or creates a new one. Enforces directionality and max capacity.
        Returns a finalized flow if eviction occurred due to capacity pressure.
        """
        fwd_key: FlowKey = (src_ip, dst_ip, sport, dport, proto)
        bwd_key: FlowKey = (dst_ip, src_ip, dport, sport, proto)

        evicted_flow: Optional[FlowState] = None

        if fwd_key in self._flows:
            flow = self._flows[fwd_key]
            direction = "FORWARD"
            self._flows.move_to_end(fwd_key)
        elif bwd_key in self._flows:
            flow = self._flows[bwd_key]
            direction = "BACKWARD"
            self._flows.move_to_end(bwd_key)
        else:
            # Capacity check: evict oldest if at capacity
            if len(self._flows) >= self.max_flows:
                oldest_key, oldest_flow = self._flows.popitem(last=False)
                oldest_flow.finalization_reason = "capacity_pressure"
                self._finalized_count += 1
                self._dropped_flows_count += 1
                if self.on_flow_finalized:
                    self.on_flow_finalized(oldest_flow)
                evicted_flow = oldest_flow

            flow = FlowState(
                key=fwd_key,
                start_time=timestamp,
                last_seen=timestamp,
            )
            self._flows[fwd_key] = flow
            direction = "FORWARD"

        flow.last_seen = timestamp
        flow.packets.append(
            PacketMetadata(
                timestamp=timestamp,
                length=packet_len,
                payload_len=payload_len,
                header_len=header_len,
                direction=direction,
                tcp_flags=tcp_flags,
                tcp_window=tcp_window,
            )
        )
        if host_header and not flow.host_header:
            flow.host_header = host_header

        return evicted_flow

    def check_inactivity(self, current_time: float) -> List[FlowState]:
        """
        Finalizes all flows where (current_time - last_seen) > inactivity_timeout_sec.
        Returns the list of newly finalized flows.
        """
        expired_keys = []
        finalized_flows = []

        for key, flow in list(self._flows.items()):
            if (current_time - flow.last_seen) >= self.inactivity_timeout_sec:
                expired_keys.append(key)
                flow.finalization_reason = "inactivity_timeout"
                finalized_flows.append(flow)

        for key in expired_keys:
            self._flows.pop(key, None)
            self._finalized_count += 1

        if self.on_flow_finalized:
            for flow in finalized_flows:
                self.on_flow_finalized(flow)

        return finalized_flows

    def finalize_all(self, reason: str = "shutdown") -> List[FlowState]:
        """
        Finalizes all currently active flows (e.g. upon capture stop or shutdown).
        """
        finalized_flows = list(self._flows.values())
        for flow in finalized_flows:
            flow.finalization_reason = reason
            self._finalized_count += 1
            if self.on_flow_finalized:
                self.on_flow_finalized(flow)

        self._flows.clear()
        return finalized_flows
