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

__all__ = [
    "SimulationResultRecord",
    "SimulationStageRecord",
    "AttackPlanRecord",
    "AttackResultRecord",
    "AttackStepRecord",
    "AlertRecord",
    "IncidentRecord",
    "AuditEventRecord",
    "TenantRecord",
    "UserRecord",
]
