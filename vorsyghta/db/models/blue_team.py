"""SQLAlchemy ORM models for blue-team operations.

Tables:
    alerts
    incidents
"""
from __future__ import annotations

from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, Integer, JSON, String, Text, func

from vorsyghta.db.base import Base


class AlertRecord(Base):
    """Persisted record of a detection alert."""

    __tablename__ = "alerts"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    alert_id = Column(String, unique=True, nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)
    exercise_id = Column(String, nullable=True)
    source_module = Column(String, nullable=False)
    technique_id = Column(String, nullable=True)
    severity = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    detected = Column(Boolean, nullable=False, default=True)
    response_time_ms = Column(Integer, nullable=True)
    # Soft reference — no FK constraint to allow alerts to outlive their stage
    stage_id = Column(String, nullable=True)
    iocs = Column(JSON, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    def __repr__(self) -> str:
        return f"<AlertRecord alert_id={self.alert_id!r} severity={self.severity!r} detected={self.detected!r}>"


class IncidentRecord(Base):
    """Persisted record of a security incident."""

    __tablename__ = "incidents"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    incident_id = Column(String, unique=True, nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)
    exercise_id = Column(String, nullable=True)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    category = Column(String, nullable=False)
    status = Column(String, nullable=False, default="open")
    mitre_techniques = Column(JSON, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    def __repr__(self) -> str:
        return f"<IncidentRecord incident_id={self.incident_id!r} status={self.status!r}>"
