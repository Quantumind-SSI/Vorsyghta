"""Tool usage, attack sequence, and attack result tracking ORM models.

These tables track the execution of security tools during attack
simulations, the ordered sequence of attack steps, and their results.
This provides full observability into how the Ciicerone platform
uses its tool server during exercises.

Tables:
    tool_usage           — every tool invocation (who, what, when, result)
    attack_sequences     — ordered sequence of attack steps for an exercise
    attack_sequence_steps — individual steps within a sequence
    attack_executions    — detailed execution results per step

Owner: Ciicerone Core Team
"""
from __future__ import annotations

from uuid import uuid4

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import relationship

from ciicerone.db.base import Base


# ---------------------------------------------------------------------------
# Tool Usage — every tool invocation tracked
# ---------------------------------------------------------------------------

class ToolUsageRecord(Base):
    """Tracks every invocation of a security tool via the tool server.

    Records who invoked the tool, what command was run, the result,
    duration, and whether it was successful. This provides metrics
    for tool effectiveness and usage patterns.
    """

    __tablename__ = "tool_usage"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    usage_id = Column(String, unique=True, nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)

    # Context
    exercise_id = Column(String, nullable=True, index=True)
    simulation_id = Column(String, nullable=True, index=True)
    sequence_step_id = Column(
        String,
        ForeignKey("attack_sequence_steps.step_id", ondelete="SET NULL"),
        nullable=True, index=True,
    )

    # Tool details
    tool_name = Column(String, nullable=False, index=True)
    # nmap, nikto, sqlmap, hydra, gobuster, etc.
    command = Column(Text, nullable=False)
    # Full command string
    args = Column(Text, nullable=True)  # JSON: parsed arguments
    target = Column(String, nullable=True)  # Target host/IP/URL

    # Result
    return_code = Column(Integer, nullable=True)
    stdout = Column(Text, nullable=True)
    stderr = Column(Text, nullable=True)
    success = Column(Boolean, nullable=False, default=False)
    error_message = Column(Text, nullable=True)

    # Timing
    duration_seconds = Column(Float, nullable=True)
    timeout_seconds = Column(Integer, nullable=True)
    timed_out = Column(Boolean, nullable=False, default=False)

    # MITRE ATT&CK mapping
    mitre_technique_id = Column(String, nullable=True)
    attack_phase = Column(String, nullable=True)
    # reconnaissance, scanning, exploitation, post_exploitation, etc.

    # Actor
    invoked_by = Column(String, nullable=True)  # user_id or "system"
    invocation_source = Column(String, nullable=False, default="api")
    # api, simulation, agent, manual, orchestrator

    # Metadata
    tool_server_url = Column(String, nullable=True)
    output_size_bytes = Column(Integer, nullable=True)
    extra_metadata = Column("metadata", Text, nullable=True)  # JSON

    # Timestamps
    started_at = Column(DateTime, nullable=False, server_default=func.now())
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    sequence_step = relationship("AttackSequenceStepRecord", back_populates="tool_usages", lazy="select")

    def __repr__(self) -> str:
        return f"<ToolUsageRecord usage_id={self.usage_id!r} tool={self.tool_name!r} success={self.success}>"


# ---------------------------------------------------------------------------
# Attack Sequence — ordered sequence of attack steps
# ---------------------------------------------------------------------------

class AttackSequenceRecord(Base):
    """An ordered sequence of attack steps for an exercise or simulation.

    This tracks the full attack chain from reconnaissance through
    exfiltration, including step dependencies and outcomes.
    """

    __tablename__ = "attack_sequences"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    sequence_id = Column(String, unique=True, nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)

    # Context
    exercise_id = Column(String, nullable=True, index=True)
    simulation_id = Column(String, nullable=True, index=True)
    scenario_name = Column(String, nullable=True)

    # Identity
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)

    # Attack chain
    target_system = Column(String, nullable=True)
    target_ip = Column(String, nullable=True)
    target_url = Column(String, nullable=True)
    attacker_vm = Column(String, nullable=True)

    # MITRE ATT&CK
    mitre_tactics = Column(Text, nullable=True)  # JSON list
    mitre_techniques = Column(Text, nullable=True)  # JSON list

    # Status
    sequence_status = Column(String, nullable=False, default="pending")
    # pending, running, completed, failed, aborted
    total_steps = Column(Integer, nullable=False, default=0)
    completed_steps = Column(Integer, nullable=False, default=0)
    successful_steps = Column(Integer, nullable=False, default=0)
    failed_steps = Column(Integer, nullable=False, default=0)

    # Timing
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    total_duration_seconds = Column(Float, nullable=True)

    # Result summary
    overall_success = Column(Boolean, nullable=False, default=False)
    result_summary = Column(Text, nullable=True)
    key_findings = Column(Text, nullable=True)  # JSON list

    # Actor
    initiated_by = Column(String, nullable=True)  # user_id
    initiated_by_source = Column(String, nullable=False, default="api")
    # api, simulation, orchestrator, agent, manual

    # Timestamps
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    # Relationships
    steps = relationship(
        "AttackSequenceStepRecord", back_populates="sequence",
        cascade="all, delete-orphan", lazy="select",
        order_by="AttackSequenceStepRecord.step_order",
    )

    def __repr__(self) -> str:
        return f"<AttackSequenceRecord sequence_id={self.sequence_id!r} name={self.name!r} status={self.sequence_status!r}>"


# ---------------------------------------------------------------------------
# Attack Sequence Step — individual steps within a sequence
# ---------------------------------------------------------------------------

class AttackSequenceStepRecord(Base):
    """A single step within an attack sequence.

    Each step has an ordered position, a tool to execute, a MITRE
    technique mapping, and tracks the result of execution.
    """

    __tablename__ = "attack_sequence_steps"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    step_id = Column(String, unique=True, nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)

    # Sequence
    sequence_id = Column(
        String,
        ForeignKey("attack_sequences.sequence_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    # Ordering
    step_order = Column(Integer, nullable=False, default=0)
    # 0-based order within the sequence

    # Identity
    step_name = Column(String, nullable=False)
    step_type = Column(String, nullable=False, default="tool_execution")
    # tool_execution, manual_action, llm_generation, observation, decision
    description = Column(Text, nullable=True)

    # MITRE ATT&CK
    mitre_technique_id = Column(String, nullable=True, index=True)
    mitre_tactic = Column(String, nullable=True)
    attack_phase = Column(String, nullable=True)
    # reconnaissance, initial_access, execution, persistence, privilege_escalation,
    # defense_evasion, credential_access, discovery, lateral_movement,
    # collection, exfiltration, impact

    # Tool
    tool_name = Column(String, nullable=True)
    command = Column(Text, nullable=True)
    target = Column(String, nullable=True)

    # Dependencies
    depends_on_steps = Column(Text, nullable=True)  # JSON list of step_ids
    condition = Column(Text, nullable=True)
    # Optional condition expression: "step_3.success == true"

    # Status
    step_status = Column(String, nullable=False, default="pending")
    # pending, running, completed, failed, skipped
    success = Column(Boolean, nullable=False, default=False)
    error_message = Column(Text, nullable=True)

    # Result
    output = Column(Text, nullable=True)
    output_summary = Column(Text, nullable=True)
    findings = Column(Text, nullable=True)  # JSON list of findings
    iocs_discovered = Column(Text, nullable=True)  # JSON list

    # Timing
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)

    # Timestamps
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    # Relationships
    sequence = relationship("AttackSequenceRecord", back_populates="steps", lazy="select")
    tool_usages = relationship(
        "ToolUsageRecord", back_populates="sequence_step",
        cascade="all, delete-orphan", lazy="select",
    )
    execution = relationship(
        "AttackExecutionRecord", back_populates="step",
        cascade="all, delete-orphan", lazy="select", uselist=False,
    )

    def __repr__(self) -> str:
        return f"<AttackSequenceStepRecord step_id={self.step_id!r} order={self.step_order} tool={self.tool_name!r}>"


# ---------------------------------------------------------------------------
# Attack Execution — detailed execution result per step
# ---------------------------------------------------------------------------

class AttackExecutionRecord(Base):
    """Detailed execution result for a single attack sequence step.

    This captures the full output, parsed results, and evidence
    from executing a tool or action during an attack sequence.
    """

    __tablename__ = "attack_executions"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    execution_id = Column(String, unique=True, nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)

    # Step
    step_id = Column(
        String,
        ForeignKey("attack_sequence_steps.step_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    # Execution details
    executor = Column(String, nullable=False, default="tool_server")
    # tool_server, vm_operator, llm, manual, external_api
    executor_endpoint = Column(String, nullable=True)
    # URL or VM ID used for execution

    # Input
    input_command = Column(Text, nullable=True)
    input_parameters = Column(Text, nullable=True)  # JSON

    # Output
    raw_output = Column(Text, nullable=True)
    parsed_output = Column(Text, nullable=True)  # JSON: structured result
    output_format = Column(String, nullable=True)
    # text, json, xml, csv, html

    # Result analysis
    return_code = Column(Integer, nullable=True)
    exit_status = Column(String, nullable=True)
    # success, failure, timeout, partial_success, error
    error_details = Column(Text, nullable=True)

    # Evidence
    screenshots = Column(Text, nullable=True)  # JSON list of file paths
    artifacts = Column(Text, nullable=True)    # JSON list of artifact paths
    evidence_hash = Column(String, nullable=True)  # SHA-256 of evidence

    # Impact assessment
    impact_level = Column(String, nullable=True)
    # none, low, medium, high, critical
    impact_description = Column(Text, nullable=True)
    vulnerabilities_found = Column(Text, nullable=True)  # JSON list

    # Timing
    execution_duration_seconds = Column(Float, nullable=True)
    queued_at = Column(DateTime, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # Timestamps
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    # Relationships
    step = relationship("AttackSequenceStepRecord", back_populates="execution", lazy="select")

    def __repr__(self) -> str:
        return f"<AttackExecutionRecord execution_id={self.execution_id!r} status={self.exit_status!r}>"
