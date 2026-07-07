"""SQLAlchemy ORM models for the Yellow Team (infrastructure).

Tables:
    yellow_team_environments
    yellow_team_environment_components

These records persist the lifecycle of sandbox environments provisioned by
:class:`ciicerone.core.yellow_team.InfrastructureManager`.  Each environment
owns a collection of components (VMs, networks, tool servers, LLM
connectivity).
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
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.orm import relationship

from ciicerone.db.base import Base


class EnvironmentRecord(Base):
    """Persisted record of a provisioned Yellow Team environment.

    Attributes:
        id: Primary key (UUID).
        env_id: Business identifier returned by ``provision_environment``.
        tenant_id: Tenant scope.
        scenario_id: Scenario that the environment was provisioned for.
        scenario_name: Human-readable scenario name.
        exercise_id: Optional linked exercise identifier.
        status: Environment lifecycle status (provisioning, ready,
            running, tearing_down, torn_down, error).
        ready: Whether all components reached a ready state.
        network_config: JSON blob with the isolated network configuration.
        vm_ids: JSON list of provisioned VM identifiers.
        snapshot_id: Pre-exercise baseline snapshot identifier.
        config: Full structured environment configuration (JSON).
        issues: JSON list of provisioning/validation issues.
        created_at: When the environment record was created.
        provisioned_at: When provisioning completed.
        torn_down_at: When the environment was torn down.
    """

    __tablename__ = "yellow_team_environments"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    env_id = Column(String, unique=True, nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)
    scenario_id = Column(String, nullable=False)
    scenario_name = Column(String, nullable=False)
    exercise_id = Column(String, nullable=True, index=True)
    status = Column(String, nullable=False, index=True)
    ready = Column(Boolean, nullable=False, default=False)
    network_config = Column(JSON, nullable=False)
    vm_ids = Column(JSON, nullable=False)
    snapshot_id = Column(String, nullable=True)
    config = Column(JSON, nullable=False)
    issues = Column(JSON, nullable=False)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    provisioned_at = Column(DateTime, nullable=True)
    torn_down_at = Column(DateTime, nullable=True)

    components = relationship(
        "EnvironmentComponentRecord",
        back_populates="environment",
        cascade="all, delete-orphan",
        lazy="select",
    )

    def __repr__(self) -> str:
        return (
            f"<EnvironmentRecord env_id={self.env_id!r} "
            f"tenant_id={self.tenant_id!r} status={self.status!r}>"
        )


class EnvironmentComponentRecord(Base):
    """Persisted record of a single component within an environment.

    Attributes:
        id: Primary key (UUID).
        component_id: Business identifier for the component.
        env_id: Foreign key to ``yellow_team_environments.env_id``.
        tenant_id: Tenant scope (denormalised for query convenience).
        component_type: One of ``attacker_vm``, ``target_vm``,
            ``siem_vm``, ``network``, ``tool_server``, ``llm_provider``.
        state: Component lifecycle state.
        vm_id: VM identifier (only for VM components).
        ip_address: Allocated IP address (only for VM components).
        specs: JSON blob with VM specifications (CPU, memory, disk).
        config: JSON blob with component-specific configuration.
        health: Health status (healthy, unhealthy, unknown).
        error: Error message if the component failed to provision.
        cpu_cores: VM CPU cores (denormalised for reporting).
        memory_mb: VM memory in MB (denormalised for reporting).
        disk_gb: VM disk in GB (denormalised for reporting).
        provisioned_at: When the component reached a running state.
        torn_down_at: When the component was torn down.
        created_at: When the record was created.
    """

    __tablename__ = "yellow_team_environment_components"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    component_id = Column(String, unique=True, nullable=False, index=True)
    env_id = Column(
        String,
        ForeignKey("yellow_team_environments.env_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tenant_id = Column(String, nullable=False, index=True)
    component_type = Column(String, nullable=False, index=True)
    state = Column(String, nullable=False)
    vm_id = Column(String, nullable=True, index=True)
    ip_address = Column(String, nullable=True)
    specs = Column(JSON, nullable=False)
    config = Column(JSON, nullable=False)
    health = Column(String, nullable=False, default="unknown")
    error = Column(Text, nullable=True)
    cpu_cores = Column(Integer, nullable=True)
    memory_mb = Column(Integer, nullable=True)
    disk_gb = Column(Float, nullable=True)
    provisioned_at = Column(DateTime, nullable=True)
    torn_down_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    environment = relationship(
        "EnvironmentRecord", back_populates="components", lazy="select"
    )

    def __repr__(self) -> str:
        return (
            f"<EnvironmentComponentRecord component_id={self.component_id!r} "
            f"component_type={self.component_type!r} state={self.state!r}>"
        )
