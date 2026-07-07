"""SQLAlchemy ORM models for green-team training and awareness.

Tables:
    training_assignments
    training_modules
    awareness_assessments
"""
from __future__ import annotations

from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, JSON, String, Text, func

from ciicerone.db.base import Base


class TrainingAssignmentRecord(Base):
    """Persisted record of a training assignment issued by the Green Team.

    Tracks an individual training module assignment to one or more roles,
    including the AAR/evaluation findings that triggered it and its
    completion status.
    """

    __tablename__ = "training_assignments"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    assignment_id = Column(String, unique=True, nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)
    exercise_id = Column(String, nullable=True, index=True)
    plan_id = Column(String, nullable=True, index=True)
    module_id = Column(String, nullable=False, index=True)
    module_name = Column(String, nullable=False)
    target_roles = Column(JSON, nullable=False)
    priority = Column(String, nullable=False, default="medium")
    delivery_method = Column(String, nullable=True)
    duration_hours = Column(Integer, nullable=True)
    based_on_findings = Column(JSON, nullable=True)
    technique_id = Column(String, nullable=True, index=True)
    status = Column(String, nullable=False, default="assigned")
    completion_pct = Column(Integer, nullable=True)
    assigned_at = Column(DateTime, nullable=False, server_default=func.now())
    due_date = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    def __repr__(self) -> str:
        return (
            f"<TrainingAssignmentRecord assignment_id={self.assignment_id!r} "
            f"module={self.module_name!r} status={self.status!r}>"
        )


class TrainingModuleRecord(Base):
    """Persisted catalog entry for an available training module.

    Mirrors the in-memory :data:`ciicerone.core.green_team.TRAINING_MODULE_CATALOG`
    so that modules can be managed, extended, and queried from the database.
    """

    __tablename__ = "training_modules"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    module_id = Column(String, unique=True, nullable=False, index=True)
    tenant_id = Column(String, nullable=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    technique_id = Column(String, nullable=True, index=True)
    target_roles = Column(JSON, nullable=True)
    duration_hours = Column(Integer, nullable=True)
    delivery_method = Column(String, nullable=True)
    priority = Column(String, nullable=False, default="medium")
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    def __repr__(self) -> str:
        return (
            f"<TrainingModuleRecord module_id={self.module_id!r} "
            f"name={self.name!r} active={self.is_active!r}>"
        )


class AwarenessAssessmentRecord(Base):
    """Persisted record of a security awareness assessment over time.

    Stores the computed awareness score, maturity level, and component
    breakdown so that trends can be analyzed across exercises.
    """

    __tablename__ = "awareness_assessments"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    assessment_id = Column(String, unique=True, nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)
    exercise_id = Column(String, nullable=True, index=True)
    score = Column(Float, nullable=False)
    level = Column(String, nullable=False)
    level_description = Column(Text, nullable=True)
    components = Column(JSON, nullable=True)
    weights = Column(JSON, nullable=True)
    recommendations = Column(JSON, nullable=True)
    assessed_at = Column(DateTime, nullable=False, server_default=func.now())
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    def __repr__(self) -> str:
        return (
            f"<AwarenessAssessmentRecord assessment_id={self.assessment_id!r} "
            f"score={self.score!r} level={self.level!r}>"
        )
