import datetime
import uuid
from typing import Dict, Any, List, Set, Tuple
from collections import defaultdict

from .normalizer import extract_and_normalize_indicators
from .models import (
    SEVERITY_ORDER,
    UnifiedIncidentRecord,
    SharedIndicatorMatch,
    verify_incident_integrity
)

class CorrelationEngine:
    """
    Deterministic Cross-Channel Threat Correlation Engine.
    Correlates observations across SMS, URL, and Network IDS channels based on explicit
    shared indicators (domain, host, IP, phone, URL) without temporal or fuzzy heuristics.
    """

    def __init__(self):
        self._events: List[Dict[str, Any]] = []

    def ingest_event(self, event: Dict[str, Any]) -> None:
        """
        Ingests a detector event record (from SMS, URL, or Network IDS).
        """
        # Ensure deep-copy or safe dict handling
        self._events.append(dict(event))

    def ingest_events(self, events: List[Dict[str, Any]]) -> None:
        for ev in events:
            self.ingest_event(ev)

    def clear(self) -> None:
        self._events.clear()

    def correlate(self) -> List[Dict[str, Any]]:
        """
        Evaluates ingested events and synthesizes Unified Incident Records for events
        sharing one or more high-entropy indicators across at least two distinct channels/sources.
        Returns a list of sealed Incident Record dictionaries.
        """
        if not self._events:
            return []

        # 1. Map events to their normalized indicators
        event_indicators: List[Set[Tuple[str, str]]] = []
        indicator_to_event_indices = defaultdict(set)

        for idx, ev in enumerate(self._events):
            inds = extract_and_normalize_indicators(ev)
            event_indicators.append(inds)
            for ind in inds:
                indicator_to_event_indices[ind].add(idx)

        # 2. Build graph/clusters of connected events
        # An edge exists between event A and B if they share an indicator AND have distinct sources
        # (or provide multi-observation correlation)
        adj = defaultdict(set)
        shared_indicator_map = defaultdict(lambda: defaultdict(set))

        for ind, indices in indicator_to_event_indices.items():
            idx_list = sorted(list(indices))
            if len(idx_list) < 2:
                continue

            # Check if indices span at least two distinct sources (or distinct events)
            sources = {self._events[i].get("source", f"unknown_{i}") for i in idx_list}
            if len(sources) >= 2 or len(idx_list) >= 2:
                for i in range(len(idx_list)):
                    for j in range(i + 1, len(idx_list)):
                        u, v = idx_list[i], idx_list[j]
                        adj[u].add(v)
                        adj[v].add(u)
                        shared_indicator_map[(min(u, v), max(u, v))][ind].add(u)
                        shared_indicator_map[(min(u, v), max(u, v))][ind].add(v)

        # 3. Find connected components
        visited = set()
        clusters = []

        for i in range(len(self._events)):
            if i not in visited and i in adj:
                cluster = []
                queue = [i]
                visited.add(i)
                while queue:
                    curr = queue.pop(0)
                    cluster.append(curr)
                    for neighbor in adj[curr]:
                        if neighbor not in visited:
                            visited.add(neighbor)
                            queue.append(neighbor)
                clusters.append(sorted(cluster))

        # 4. Synthesize incident records for clusters
        incidents: List[Dict[str, Any]] = []

        for cluster_indices in clusters:
            cluster_events = [self._events[i] for i in cluster_indices]
            participating_sources = sorted(list({ev.get("source", "unknown") for ev in cluster_events}))

            # Identify all shared indicators in this cluster
            cluster_indicators_count = defaultdict(set)
            for i in cluster_indices:
                for ind in event_indicators[i]:
                    cluster_indicators_count[ind].add(self._events[i].get("source", "unknown"))

            shared_matches: List[SharedIndicatorMatch] = []
            for (itype, ival), sources in sorted(cluster_indicators_count.items()):
                if len(sources) >= 2:
                    shared_matches.append(
                        SharedIndicatorMatch(
                            indicator_type=itype,
                            indicator_value=ival,
                            participating_sources=sorted(list(sources))
                        )
                    )

            if not shared_matches:
                # No shared indicator across distinct sources
                continue

            # Deterministic Severity Aggregation: Highest severity wins
            highest_sev = "BENIGN"
            highest_rank = -1
            for ev in cluster_events:
                sev = ev.get("severity", "BENIGN").upper()
                rank = SEVERITY_ORDER.get(sev, 0)
                if rank > highest_rank:
                    highest_rank = rank
                    highest_sev = sev

            # Deterministic Confidence Aggregation:
            # Base = max confidence, boosted by 0.05 per additional channel, bounded by 1.0
            base_conf = max((float(ev.get("confidence", 0.5)) for ev in cluster_events), default=0.5)
            multi_source_boost = 0.05 * (len(participating_sources) - 1)
            combined_conf = round(min(1.0, base_conf + multi_source_boost), 4)

            # Generate Incident ID deterministically or timestamped
            primary_ind = shared_matches[0].indicator_value.replace(".", "-")[:20]
            incident_id = f"INC-CORR-{primary_ind.upper()}"

            summary = (
                f"Multi-channel threat correlation across {', '.join(participating_sources)} "
                f"sharing indicators: {', '.join(m.indicator_value for m in shared_matches)}"
            )

            # Generate Cross-Channel Advisory
            advisory = self._generate_cross_channel_advisory(
                highest_sev, participating_sources, shared_matches, cluster_events
            )

            # Build and Seal Unified Incident Record
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            incident = UnifiedIncidentRecord(
                incident_id=incident_id,
                created_at=now_iso,
                status="CORRELATED_THREAT",
                severity=highest_sev,
                confidence=combined_conf,
                summary=summary,
                shared_indicators=[m.to_dict() for m in shared_matches],
                correlated_events=cluster_events,
                advisory=advisory
            ).seal()

            incidents.append(incident.to_dict())

        return incidents

    def _generate_cross_channel_advisory(
        self,
        severity: str,
        sources: List[str],
        shared_indicators: List[SharedIndicatorMatch],
        events: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generates cross-channel containment and mitigation advisory.
        Uses deterministic rule-based synthesis strictly compliant with advisory contract.
        """
        actionable_steps = []
        domain_targets = [m.indicator_value for m in shared_indicators if m.indicator_type == "domain"]
        ip_targets = [m.indicator_value for m in shared_indicators if m.indicator_type == "ip"]
        phone_targets = [m.indicator_value for m in shared_indicators if m.indicator_type == "phone"]

        if domain_targets:
            actionable_steps.append(f"Block DNS queries and HTTP/TLS traffic to domain(s): {', '.join(domain_targets)}.")
        if ip_targets:
            actionable_steps.append(f"Add perimeter firewall drop rule for destination IP(s): {', '.join(ip_targets)}.")
        if phone_targets:
            actionable_steps.append(f"Block incoming SMS lures from sender(s): {', '.join(phone_targets)}.")

        actionable_steps.append("Isolate impacted host and check endpoint for secondary payloads or credential exposure.")

        return {
            "advisory_source": "deterministic_cross_channel_engine",
            "summary": f"Coordinated attack campaign detected spanning {len(sources)} channels ({', '.join(sources)}).",
            "threat_scope": {
                "participating_channels": sources,
                "correlated_event_count": len(events),
                "severity_verdict": severity
            },
            "actionable_steps": actionable_steps
        }
