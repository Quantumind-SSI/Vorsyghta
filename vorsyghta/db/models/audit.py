"""SQLAlchemy ORM models for the audit trail.

Table:
    audit_events
"""
from __future__ import annotations

from uuid import uuid4

from sqlalchemy import Column, DateTime, JSON, String, Text, func

from vorsyghta.db.base import Base


class AuditEventRecord(Base):
    """Persisted record of a single auditable event with hash-chain integrity."""

    __tablename__ = "audit_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    event_id = Column(String, unique=True, nullable=False, index=True)
    event_type = Column(String, nullable=False, index=True)
    category = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    actor = Column(JSON, nullable=False)
    target = Column(JSON, nullable=False)
    context = Column(JSON, nullable=False)
    timestamp = Column(DateTime, nullable=False, index=True)
    correlation_id = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    prev_hash = Column(String(64), nullable=True)
    event_hash = Column(String(64), nullable=True)
    tenant_id = Column(String, nullable=True, index=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    def __repr__(self) -> str:
        return f"<AuditEventRecord event_id={self.event_id!r} event_type={self.event_type!r}>"
