"""Defense modules for Vorsyghta.

Provides Blue Team, Yellow Team, and Purple Team capabilities:
    - blue_team: SIEM, IDS, EDR, IR, threat hunting, log analysis, alert triage, forensics
    - yellow_team: Compliance, risk assessment, architecture review (planned)
    - purple_team: Red-Blue coordination, AAR, detection validation (planned)
    - shared: Cross-team utilities for correlation and timelines
"""

from .blue_team import (
    SIEMSimulator,
    IDSDetector,
    EDRAgent,
    IncidentResponse,
    ThreatHunter,
    LogAnalyzer,
    AlertTriage,
    ForensicsCollector,
)

__all__ = [
    "SIEMSimulator",
    "IDSDetector",
    "EDRAgent",
    "IncidentResponse",
    "ThreatHunter",
    "LogAnalyzer",
    "AlertTriage",
    "ForensicsCollector",
]
