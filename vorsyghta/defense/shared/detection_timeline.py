"""Detection timeline for tracking blue team detections.

Records detection events with timestamps for correlation with attacks.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class DetectionEvent:
    """Represents a single detection event in the timeline."""
    event_id: str
    timestamp: datetime
    detection_type: str  # siem, ids, edr, threat_hunt, manual
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    source: str
    mitre_technique: Optional[str] = None
    confidence: float = 0.0
    status: str = "new"  # new, investigating, confirmed, false_positive
    metadata: Dict[str, Any] = field(default_factory=dict)


class DetectionTimeline:
    """Timeline of detection events for purple team correlation."""

    def __init__(self):
        self._events: List[DetectionEvent] = []

    def add_event(self, event: DetectionEvent) -> None:
        self._events.append(event)
        self._events.sort(key=lambda e: e.timestamp)

    def add(
        self,
        detection_type: str,
        severity: str,
        title: str,
        description: str,
        source: str = "",
        mitre_technique: Optional[str] = None,
        confidence: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> DetectionEvent:
        event = DetectionEvent(
            event_id=f"det-{len(self._events) + 1:04d}",
            timestamp=datetime.utcnow(),
            detection_type=detection_type,
            severity=severity,
            title=title,
            description=description,
            source=source,
            mitre_technique=mitre_technique,
            confidence=confidence,
            metadata=metadata or {},
        )
        self.add_event(event)
        return event

    def get_events(
        self,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        severity: Optional[str] = None,
        detection_type: Optional[str] = None,
    ) -> List[DetectionEvent]:
        events = self._events
        if start:
            events = [e for e in events if e.timestamp >= start]
        if end:
            events = [e for e in events if e.timestamp <= end]
        if severity:
            events = [e for e in events if e.severity == severity]
        if detection_type:
            events = [e for e in events if e.detection_type == detection_type]
        return events

    def get_by_technique(self, technique_id: str) -> List[DetectionEvent]:
        return [e for e in self._events if e.mitre_technique == technique_id]

    @property
    def events(self) -> List[DetectionEvent]:
        return list(self._events)

    def to_dict(self) -> List[Dict[str, Any]]:
        return [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "detection_type": e.detection_type,
                "severity": e.severity,
                "title": e.title,
                "description": e.description,
                "source": e.source,
                "mitre_technique": e.mitre_technique,
                "confidence": e.confidence,
                "status": e.status,
                "metadata": e.metadata,
            }
            for e in self._events
        ]
