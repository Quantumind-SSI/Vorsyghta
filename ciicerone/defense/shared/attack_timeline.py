"""Attack timeline for tracking red team events.

Records attack events with timestamps for correlation with detections.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class AttackEvent:
    """Represents a single attack event in the timeline."""
    event_id: str
    timestamp: datetime
    technique_id: str
    technique_name: str
    description: str
    source: str
    target: str
    outcome: str  # success, failed, partial
    metadata: Dict[str, Any] = field(default_factory=dict)


class AttackTimeline:
    """Timeline of attack events for purple team correlation."""

    def __init__(self):
        self._events: List[AttackEvent] = []

    def add_event(self, event: AttackEvent) -> None:
        self._events.append(event)
        self._events.sort(key=lambda e: e.timestamp)

    def add(
        self,
        technique_id: str,
        technique_name: str,
        description: str,
        source: str = "",
        target: str = "",
        outcome: str = "success",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AttackEvent:
        event = AttackEvent(
            event_id=f"atk-{len(self._events) + 1:04d}",
            timestamp=datetime.utcnow(),
            technique_id=technique_id,
            technique_name=technique_name,
            description=description,
            source=source,
            target=target,
            outcome=outcome,
            metadata=metadata or {},
        )
        self.add_event(event)
        return event

    def get_events(
        self,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        technique_id: Optional[str] = None,
    ) -> List[AttackEvent]:
        events = self._events
        if start:
            events = [e for e in events if e.timestamp >= start]
        if end:
            events = [e for e in events if e.timestamp <= end]
        if technique_id:
            events = [e for e in events if e.technique_id == technique_id]
        return events

    def get_techniques(self) -> List[str]:
        return list({e.technique_id for e in self._events})

    @property
    def events(self) -> List[AttackEvent]:
        return list(self._events)

    def to_dict(self) -> List[Dict[str, Any]]:
        return [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "technique_id": e.technique_id,
                "technique_name": e.technique_name,
                "description": e.description,
                "source": e.source,
                "target": e.target,
                "outcome": e.outcome,
                "metadata": e.metadata,
            }
            for e in self._events
        ]
