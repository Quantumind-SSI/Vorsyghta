"""SQLAlchemy ORM models for red-team operations.

Tables:
    attack_plans
    attack_results
    attack_steps
"""
from __future__ import annotations

from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import relationship

from ciicerone.db.base import Base


class AttackPlanRecord(Base):
    """Persisted record of a red-team attack plan."""

    __tablename__ = "attack_plans"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    plan_id = Column(String, unique=True, nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)
    exercise_id = Column(String, nullable=True)
    scenario_name = Column(String, nullable=False)
    threat_type = Column(String, nullable=False)
    objective = Column(Text, nullable=True)
    status = Column(String, nullable=False, default="pending")
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    results = relationship(
        "AttackResultRecord",
        back_populates="plan",
        cascade="all, delete-orphan",
        lazy="select",
    )

    def __repr__(self) -> str:
        return f"<AttackPlanRecord plan_id={self.plan_id!r} status={self.status!r}>"


class AttackResultRecord(Base):
    """Persisted record of a single attack plan execution."""

    __tablename__ = "attack_results"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    result_id = Column(String, unique=True, nullable=False, index=True)
    plan_id = Column(
        String,
        ForeignKey("attack_plans.plan_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tenant_id = Column(String, nullable=False)
    success = Column(Boolean, nullable=False)
    total_steps = Column(Integer, nullable=False, default=0)
    successful_steps = Column(Integer, nullable=False, default=0)
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    plan = relationship("AttackPlanRecord", back_populates="results", lazy="select")
    steps = relationship(
        "AttackStepRecord",
        back_populates="result",
        cascade="all, delete-orphan",
        lazy="select",
    )

    def __repr__(self) -> str:
        return f"<AttackResultRecord result_id={self.result_id!r} success={self.success!r}>"


class AttackStepRecord(Base):
    """Persisted record of one step within an attack execution."""

    __tablename__ = "attack_steps"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    step_id = Column(String, unique=True, nullable=False, index=True)
    result_id = Column(
        String,
        ForeignKey("attack_results.result_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tenant_id = Column(String, nullable=False)
    step_name = Column(String, nullable=False)
    technique_id = Column(String, nullable=True)
    command = Column(Text, nullable=True)
    output = Column(Text, nullable=True)
    success = Column(Boolean, nullable=False, default=False)
    duration_seconds = Column(Float, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    result = relationship("AttackResultRecord", back_populates="steps", lazy="select")

    def __repr__(self) -> str:
        return f"<AttackStepRecord step_id={self.step_id!r} success={self.success!r}>"
