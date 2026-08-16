"""Shared utilities for defense modules.

Provides cross-team utilities:
    - attack_timeline: Attack event timeline
    - detection_timeline: Detection event timeline
    - correlation_engine: Attack-to-detection correlation
"""

from .correlation_engine import CorrelationEngine, CorrelationResult
from .attack_timeline import AttackTimeline, AttackEvent
from .detection_timeline import DetectionTimeline, DetectionEvent

__all__ = [
    "CorrelationEngine",
    "CorrelationResult",
    "AttackTimeline",
    "AttackEvent",
    "DetectionTimeline",
    "DetectionEvent",
]
