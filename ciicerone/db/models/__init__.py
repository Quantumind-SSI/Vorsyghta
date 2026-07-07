"""ORM model registry for Ciicerone.

Import this package to ensure all ORM models are registered with
Base.metadata (required for Alembic autogenerate and app startup).

Usage::

    import ciicerone.db.models  # noqa: F401

    from ciicerone.db.models import SimulationResultRecord, AlertRecord
"""
from __future__ import annotations

from ciicerone.db.models.simulation import SimulationResultRecord, SimulationStageRecord
from ciicerone.db.models.red_team import AttackPlanRecord, AttackResultRecord, AttackStepRecord
from ciicerone.db.models.blue_team import AlertRecord, IncidentRecord
from ciicerone.db.models.audit import AuditEventRecord
from ciicerone.db.models.auth import TenantRecord, UserRecord

# Orange Team (compliance & governance)
from ciicerone.db.models.orange_team import (
    ComplianceGapRecord,
    FrameworkMappingRecord,
    ComplianceReportRecord,
)
from ciicerone.db.models.yellow_team import (
    EnvironmentComponentRecord,
    EnvironmentRecord,
)
from ciicerone.db.models.white_team import (
    ROECheckRecord,
    ROEViolationRecord,
    RiskAssessmentRecord,
)
from ciicerone.db.models.green_team import (
    AwarenessAssessmentRecord,
    TrainingAssignmentRecord,
    TrainingModuleRecord,
)

# Proprietary Threat Intelligence Stack
from ciicerone.db.models.threat_intel import (
    ThreatActorRecord,
    CampaignRecord,
    MalwareFamilyRecord,
    IndicatorRecord,
    TTPRecord,
    ThreatReportRecord,
)

# Tool Usage & Attack Sequence Tracking
from ciicerone.db.models.tool_tracking import (
    ToolUsageRecord,
    AttackSequenceRecord,
    AttackSequenceStepRecord,
    AttackExecutionRecord,
)

__all__ = [
    # Simulation
    "SimulationResultRecord",
    "SimulationStageRecord",
    # Red Team
    "AttackPlanRecord",
    "AttackResultRecord",
    "AttackStepRecord",
    # Blue Team
    "AlertRecord",
    "IncidentRecord",
    # Audit
    "AuditEventRecord",
    # Auth
    "TenantRecord",
    "UserRecord",
    # Orange Team
    "ComplianceGapRecord",
    "FrameworkMappingRecord",
    "ComplianceReportRecord",
    # Yellow Team
    "EnvironmentRecord",
    "EnvironmentComponentRecord",
    # White Team
    "ROECheckRecord",
    "ROEViolationRecord",
    "RiskAssessmentRecord",
    # Threat Intelligence
    "ThreatActorRecord",
    "CampaignRecord",
    "MalwareFamilyRecord",
    "IndicatorRecord",
    "TTPRecord",
    "ThreatReportRecord",
    # Tool Tracking
    "ToolUsageRecord",
    "AttackSequenceRecord",
    "AttackSequenceStepRecord",
    "AttackExecutionRecord",
    # Green Team
    "TrainingAssignmentRecord",
    "TrainingModuleRecord",
    "AwarenessAssessmentRecord",
    # White Team
    "ROECheckRecord",
    "ROEViolationRecord",
    "RiskAssessmentRecord",
    # Yellow Team
    "EnvironmentRecord",
    "EnvironmentComponentRecord",
]
