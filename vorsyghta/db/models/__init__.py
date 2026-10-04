"""ORM model registry for Vorsyghta.

Import this package to ensure all ORM models are registered with
Base.metadata (required for Alembic autogenerate and app startup).

Usage::

    import vorsyghta.db.models  # noqa: F401

    from vorsyghta.db.models import SimulationResultRecord, AlertRecord
"""

from __future__ import annotations

from vorsyghta.db.models.simulation import SimulationResultRecord, SimulationStageRecord
from vorsyghta.db.models.red_team import AttackPlanRecord, AttackResultRecord, AttackStepRecord
from vorsyghta.db.models.blue_team import AlertRecord, IncidentRecord
from vorsyghta.db.models.audit import AuditEventRecord
from vorsyghta.db.models.auth import TenantRecord, UserRecord
from vorsyghta.db.models.billing import (
    BillingStatus,
    StripeWebhookEventRecord,
    TenantSubscriptionRecord,
)

# Orange Team (compliance & governance)
from vorsyghta.db.models.orange_team import (
    ComplianceGapRecord,
    FrameworkMappingRecord,
    ComplianceReportRecord,
)
from vorsyghta.db.models.yellow_team import (
    EnvironmentComponentRecord,
    EnvironmentRecord,
)
from vorsyghta.db.models.white_team import (
    ROECheckRecord,
    ROEViolationRecord,
    RiskAssessmentRecord,
)
from vorsyghta.db.models.green_team import (
    AwarenessAssessmentRecord,
    TrainingAssignmentRecord,
    TrainingModuleRecord,
)

# Proprietary Threat Intelligence Stack
from vorsyghta.db.models.threat_intel import (
    ThreatActorRecord,
    CampaignRecord,
    MalwareFamilyRecord,
    IndicatorRecord,
    TTPRecord,
    ThreatReportRecord,
)

# Tool Usage & Attack Sequence Tracking
from vorsyghta.db.models.tool_tracking import (
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
    # Billing
    "BillingStatus",
    "StripeWebhookEventRecord",
    "TenantSubscriptionRecord",
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
