"""SQLAlchemy ORM models for simulation results.

Tables:
    simulation_results
    simulation_stages
"""
from __future__ import annotations

from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, String, Text, func
from sqlalchemy.orm import relationship

from ciicerone.db.base import Base


class SimulationResultRecord(Base):
    """Persisted record of a single simulation run."""

    __tablename__ = "simulation_results"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    result_id = Column(String, unique=True, nullable=False, index=True)
    scenario_id = Column(String, nullable=False)
    tenant_id = Column(String, nullable=False, index=True)
    status = Column(String, nullable=False)
    success = Column(Boolean, nullable=False)
    error_message = Column(Text, nullable=True)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=True)
    total_duration_seconds = Column(Float, nullable=True)
    success_rate = Column(Float, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    stages = relationship(
        "SimulationStageRecord",
        back_populates="result",
        cascade="all, delete-orphan",
        lazy="select",
    )

    def __repr__(self) -> str:
        return f"<SimulationResultRecord result_id={self.result_id!r} status={self.status!r}>"


class SimulationStageRecord(Base):
    """Persisted record of one stage within a simulation run."""

    __tablename__ = "simulation_stages"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    stage_id = Column(String, unique=True, nullable=False, index=True)
    result_id = Column(
        String,
        ForeignKey("simulation_results.result_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tenant_id = Column(String, nullable=False)
    stage_name = Column(String, nullable=False)
    technique_id = Column(String, nullable=True)
    tactic = Column(String, nullable=True)
    content = Column(Text, nullable=True)
    status = Column(String, nullable=False)
    duration_seconds = Column(Float, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    result = relationship("SimulationResultRecord", back_populates="stages", lazy="select")

    def __repr__(self) -> str:
        return f"<SimulationStageRecord stage_id={self.stage_id!r} status={self.status!r}>"
