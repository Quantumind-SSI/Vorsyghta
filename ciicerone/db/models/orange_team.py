"""SQLAlchemy ORM models for the Orange Team (compliance & governance).

Tables:
    compliance_gap_records
    framework_mapping_records
    compliance_report_records

Each record is tenant-scoped and tied to a specific exercise so that
compliance posture can be tracked over time across multiple exercises.

Owner: Orange Team Lead — Compliance & Governance
Phase 4 — Orange Team persistence
"""
from __future__ import annotations

from uuid import uuid4

from sqlalchemy import Column, DateTime, JSON, String, Text, func

from ciicerone.db.base import Base


class ComplianceGapRecord(Base):
    """Persisted record of a single compliance gap identified during an exercise.

    Attributes:
        id: Primary key (UUID).
        gap_id: Business-facing gap identifier (e.g. ``CG-PCI-DSS-Req_8``).
        exercise_id: Exercise that exposed the gap.
        tenant_id: Tenant scope.
        framework: Regulatory framework (PCI-DSS, SOX, GDPR, NIST CSF, ISO 27001).
        control_id: Specific control within the framework.
        title: Human-readable control title.
        family: Control family.
        status: ``partially_compliant`` or ``non_compliant``.
        severity: Gap severity (critical, high, medium, low).
        gap_description: Narrative description of the gap.
        remediation: Recommended remediation action.
        related_techniques: JSON list of related MITRE technique IDs.
        missed_techniques: JSON list of MITRE technique IDs not detected.
        deadline_days: Regulatory remediation deadline in days.
        risk_register_entry: Optional risk register reference ID.
        evidence: JSON list of evidence strings.
        remediation_status: Lifecycle status (open, in_progress, remediated, accepted).
        created_at: Row creation timestamp.
        updated_at: Row last-update timestamp.
    """

    __tablename__ = "compliance_gap_records"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    gap_id = Column(String, nullable=False, index=True)
    exercise_id = Column(String, nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)
    framework = Column(String, nullable=False, index=True)
    control_id = Column(String, nullable=False)
    title = Column(String, nullable=True)
    family = Column(String, nullable=True)
    status = Column(String, nullable=False)
    severity = Column(String, nullable=False, index=True)
    gap_description = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    related_techniques = Column(JSON, nullable=False, default=list)
    missed_techniques = Column(JSON, nullable=False, default=list)
    deadline_days = Column(String, nullable=True)
    risk_register_entry = Column(String, nullable=True)
    evidence = Column(JSON, nullable=False, default=list)
    remediation_status = Column(String, nullable=False, default="open", index=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())

    def __repr__(self) -> str:
        return (
            f"<ComplianceGapRecord gap_id={self.gap_id!r} "
            f"framework={self.framework!r} control={self.control_id!r} "
            f"severity={self.severity!r}>"
        )


class FrameworkMappingRecord(Base):
    """Persisted framework->control mapping snapshot for an exercise.

    Stores the full control-status matrix produced by
    :meth:`ComplianceGovernanceEngine.map_to_frameworks` as JSON so that the
    compliance posture at the time of the exercise can be replayed.

    Attributes:
        id: Primary key (UUID).
        exercise_id: Exercise the mapping belongs to.
        tenant_id: Tenant scope.
        mapping: JSON blob of ``framework -> control_id -> status dict``.
        assessed_controls: Count of controls that were assessed.
        overall_posture: Rolled-up posture label.
        created_at: Row creation timestamp.
    """

    __tablename__ = "framework_mapping_records"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    exercise_id = Column(String, nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)
    mapping = Column(JSON, nullable=False)
    assessed_controls = Column(String, nullable=True)
    overall_posture = Column(String, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    def __repr__(self) -> str:
        return (
            f"<FrameworkMappingRecord exercise_id={self.exercise_id!r} "
            f"posture={self.overall_posture!r}>"
        )


class ComplianceReportRecord(Base):
    """Persisted compliance report generated for an exercise.

    Attributes:
        id: Primary key (UUID).
        report_id: Business-facing report identifier (UUID).
        exercise_id: Exercise the report covers.
        tenant_id: Tenant scope.
        executive_summary: Auditor-facing executive summary text.
        framework_summary: JSON per-framework status summary.
        compliance_gaps: JSON list of compliance gap dicts.
        remediation_priorities: JSON list of prioritized remediation items.
        regulatory_impact: JSON regulatory/financial impact assessment.
        overall_posture: Rolled-up posture label.
        generated_at: ISO timestamp when the report was generated.
        created_at: Row creation timestamp.
    """

    __tablename__ = "compliance_report_records"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    report_id = Column(String, unique=True, nullable=False, index=True)
    exercise_id = Column(String, nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)
    executive_summary = Column(Text, nullable=True)
    framework_summary = Column(JSON, nullable=False, default=dict)
    compliance_gaps = Column(JSON, nullable=False, default=list)
    remediation_priorities = Column(JSON, nullable=False, default=list)
    regulatory_impact = Column(JSON, nullable=False, default=dict)
    overall_posture = Column(String, nullable=True)
    generated_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    def __repr__(self) -> str:
        return (
            f"<ComplianceReportRecord report_id={self.report_id!r} "
            f"exercise_id={self.exercise_id!r} posture={self.overall_posture!r}>"
        )
