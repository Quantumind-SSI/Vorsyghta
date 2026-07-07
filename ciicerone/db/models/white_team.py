"""SQLAlchemy ORM models for white-team governance operations.

Tables:
    roe_check_records
    roe_violation_records
    risk_assessment_records
"""
from __future__ import annotations

from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, JSON, String, Text, func

from ciicerone.db.base import Base


class ROECheckRecord(Base):
    """Persisted record of a single ROE check performed during an exercise.

    One row is written for every rule evaluated against every red team stage,
    regardless of whether the check passed or failed.

    Attributes:
        check_id: Unique identifier for the check (mirrors the event).
        rule_id: The ROE rule that was evaluated.
        rule_description: Human-readable rule description.
        passed: Whether the stage complied with the rule.
        violation_severity: Severity when the check failed, else None.
        details: Additional context about the check outcome.
        stage_id: The red team stage that was checked.
    """

    __tablename__ = "roe_check_records"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    check_id = Column(String, unique=True, nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)
    exercise_id = Column(String, nullable=True, index=True)
    rule_id = Column(String, nullable=False, index=True)
    rule_description = Column(Text, nullable=False)
    passed = Column(Boolean, nullable=False)
    violation_severity = Column(String, nullable=True)
    details = Column(Text, nullable=True)
    stage_id = Column(String, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    def __repr__(self) -> str:
        return (
            f"<ROECheckRecord check_id={self.check_id!r} "
            f"rule_id={self.rule_id!r} passed={self.passed!r}>"
        )


class ROEViolationRecord(Base):
    """Persisted record of an ROE violation during an exercise.

    Attributes:
        violation_id: Unique identifier for the violation (mirrors the event).
        rule_id: The ROE rule that was violated.
        severity: Violation severity (critical, high, medium, low).
        description: Human-readable description of the violation.
        red_team_stage_id: The red team stage that triggered the violation.
        action_taken: Action taken or recommended (warn, pause, abort).
        details: Additional context about the violation.
    """

    __tablename__ = "roe_violation_records"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    violation_id = Column(String, unique=True, nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)
    exercise_id = Column(String, nullable=True, index=True)
    rule_id = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    red_team_stage_id = Column(String, nullable=True)
    action_taken = Column(String, nullable=False, default="warn")
    details = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    def __repr__(self) -> str:
        return (
            f"<ROEViolationRecord violation_id={self.violation_id!r} "
            f"rule_id={self.rule_id!r} severity={self.severity!r}>"
        )


class RiskAssessmentRecord(Base):
    """Persisted snapshot of a risk assessment over the course of an exercise.

    Multiple rows may be written per exercise as risk is re-evaluated over
    time, enabling trend analysis.

    Attributes:
        assessment_id: Unique identifier for the assessment.
        risk_score: 0-100 numeric risk score.
        risk_level: low / medium / high / critical.
        recommendation: continue / monitor / pause / abort.
        components: Breakdown of contributing risk factors.
        roe_violations: Counts of ROE violations by severity.
        total_stages: Number of red team stages considered.
        total_alerts: Number of blue team alerts considered.
        missed_detections: Number of stages that were not detected.
        lateral_movement_indicators: Count of lateral movement techniques.
    """

    __tablename__ = "risk_assessment_records"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    assessment_id = Column(String, unique=True, nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)
    exercise_id = Column(String, nullable=True, index=True)
    risk_score = Column(Float, nullable=False)
    risk_level = Column(String, nullable=False)
    recommendation = Column(String, nullable=False)
    components = Column(JSON, nullable=True)
    roe_violations = Column(JSON, nullable=True)
    total_stages = Column(Integer, nullable=False, default=0)
    total_alerts = Column(Integer, nullable=False, default=0)
    missed_detections = Column(Integer, nullable=False, default=0)
    lateral_movement_indicators = Column(Integer, nullable=False, default=0)
    total_roe_violations = Column(Integer, nullable=False, default=0)
    assessed_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    def __repr__(self) -> str:
        return (
            f"<RiskAssessmentRecord assessment_id={self.assessment_id!r} "
            f"risk_score={self.risk_score!r} risk_level={self.risk_level!r}>"
        )
