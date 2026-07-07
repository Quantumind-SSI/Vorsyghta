"""Yellow Team infrastructure manager for Ciicerone color-team exercises.

The Yellow Team owns the sandbox environment that every other color team
operates within. ``InfrastructureManager`` is responsible for:

* **Provisioning** the VMs, isolated network, tool server, and LLM
  connectivity required by a scenario.
* **Validating** that every component reached a ready state before the
  exercise begins.
* **Monitoring** resource utilisation (CPU, memory, network, disk) of all
  VMs while the exercise is running.
* **Tearing down** the environment once the simulation completes,
  releasing VMs and removing temporary resources.
* **Configuration management** — applying a consistent, reproducible
  environment configuration across exercises.

In a production deployment the lifecycle calls would target Proxmox,
libvirt, or a container orchestrator. In simulation mode the manager
emulates the VM lifecycle in-memory so the rest of the platform can be
exercised end-to-end without external infrastructure dependencies.

The manager integrates with the shared :class:`~ciicerone.core.event_bus.EventBus`
by subscribing to ``SIMULATION_STARTED`` (to provision) and
``SIMULATION_COMPLETED`` (to tear down), and by publishing
``YELLOW_TEAM_ENV_READY`` / ``YELLOW_TEAM_ENV_TEARDOWN`` events.

Owner: Yellow Team Lead
Phase 2 — Infrastructure & Environment Team
"""
from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set
from uuid import uuid4

from ciicerone.core.event_bus import EventBus
from ciicerone.core.event_types import (
    BusEvent,
    EventType,
    YellowTeamEnvReadyEvent,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants & default configuration
# ---------------------------------------------------------------------------

# Component types tracked by the infrastructure manager.
COMPONENT_ATTACKER_VM = "attacker_vm"
COMPONENT_TARGET_VM = "target_vm"
COMPONENT_SIEM_VM = "siem_vm"
COMPONENT_NETWORK = "network"
COMPONENT_TOOL_SERVER = "tool_server"
COMPONENT_LLM_PROVIDER = "llm_provider"

ALL_COMPONENT_TYPES: List[str] = [
    COMPONENT_ATTACKER_VM,
    COMPONENT_TARGET_VM,
    COMPONENT_SIEM_VM,
    COMPONENT_NETWORK,
    COMPONENT_TOOL_SERVER,
    COMPONENT_LLM_PROVIDER,
]

# Component lifecycle states.
STATE_PENDING = "pending"
STATE_PROVISIONING = "provisioning"
STATE_RUNNING = "running"
STATE_STOPPED = "stopped"
STATE_ERROR = "error"
STATE_TORN_DOWN = "torn_down"

# Environment-level statuses.
ENV_STATUS_PROVISIONING = "provisioning"
ENV_STATUS_READY = "ready"
ENV_STATUS_RUNNING = "running"
ENV_STATUS_TEARING_DOWN = "tearing_down"
ENV_STATUS_TORN_DOWN = "torn_down"
ENV_STATUS_ERROR = "error"

# Default VM specifications per role.  In a real deployment these would map
# to Proxmox/Docker resource requests.
DEFAULT_VM_SPECS: Dict[str, Dict[str, Any]] = {
    COMPONENT_ATTACKER_VM: {
        "template": "kali-linux-2024.1",
        "os": "linux",
        "cpu_cores": 4,
        "memory_mb": 8192,
        "disk_gb": 80,
        "role": "red_team",
    },
    COMPONENT_TARGET_VM: {
        "template": "windows-server-2022",
        "os": "windows",
        "cpu_cores": 2,
        "memory_mb": 4096,
        "disk_gb": 60,
        "role": "target",
    },
    COMPONENT_SIEM_VM: {
        "template": "elastic-siem-8.x",
        "os": "linux",
        "cpu_cores": 4,
        "memory_mb": 16384,
        "disk_gb": 200,
        "role": "blue_team",
    },
}

# Offensive tools installed on the attacker VM.
DEFAULT_ATTACKER_TOOLS: List[str] = ["nmap", "nikto", "sqlmap", "hydra", "gobuster"]

# SIEM stack installed on the SIEM VM.
DEFAULT_SIEM_STACK: Dict[str, Any] = {
    "platform": "elastic",
    "version": "8.x",
    "components": ["elasticsearch", "kibana", "logstash", "fleet-server"],
    "index_patterns": ["logs-*", "alerts-*", "auditbeat-*"],
}

# Isolated network configuration.  No internet egress by default.
DEFAULT_NETWORK_CONFIG: Dict[str, Any] = {
    "subnet": "10.200.0.0/24",
    "gateway": "10.200.0.1",
    "dns": ["10.200.0.1"],
    "dhcp": True,
    "internet_egress": False,
    "isolated": True,
    "vlan_id": 200,
}

# Simulated provisioning latency (seconds) per component type.  Used to make
# the in-memory lifecycle feel realistic; kept small so tests stay fast.
PROVISION_LATENCY: Dict[str, float] = {
    COMPONENT_ATTACKER_VM: 0.05,
    COMPONENT_TARGET_VM: 0.05,
    COMPONENT_SIEM_VM: 0.08,
    COMPONENT_NETWORK: 0.02,
    COMPONENT_TOOL_SERVER: 0.03,
    COMPONENT_LLM_PROVIDER: 0.01,
}


@dataclass
class EnvironmentComponent:
    """A single provisioned infrastructure component."""

    component_id: str
    component_type: str
    state: str = STATE_PENDING
    vm_id: Optional[str] = None
    ip_address: Optional[str] = None
    specs: Dict[str, Any] = field(default_factory=dict)
    config: Dict[str, Any] = field(default_factory=dict)
    health: str = "unknown"
    error: Optional[str] = None
    provisioned_at: Optional[str] = None
    torn_down_at: Optional[str] = None
    # Live resource usage (populated by monitor_environment).
    resource_usage: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component_id": self.component_id,
            "component_type": self.component_type,
            "state": self.state,
            "vm_id": self.vm_id,
            "ip_address": self.ip_address,
            "specs": self.specs,
            "config": self.config,
            "health": self.health,
            "error": self.error,
            "provisioned_at": self.provisioned_at,
            "torn_down_at": self.torn_down_at,
            "resource_usage": self.resource_usage,
        }


@dataclass
class Environment:
    """An exercised sandbox environment."""

    env_id: str
    tenant_id: str
    scenario_id: str
    scenario_name: str
    status: str = ENV_STATUS_PROVISIONING
    components: Dict[str, EnvironmentComponent] = field(default_factory=dict)
    network_config: Dict[str, Any] = field(default_factory=dict)
    vm_ids: List[str] = field(default_factory=list)
    snapshot_id: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provisioned_at: Optional[str] = None
    torn_down_at: Optional[str] = None
    issues: List[str] = field(default_factory=list)
    exercise_id: Optional[str] = None
    config: Dict[str, Any] = field(default_factory=dict)

    @property
    def vm_components(self) -> List[EnvironmentComponent]:
        return [
            c for c in self.components.values()
            if c.component_type.endswith("_vm")
        ]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "env_id": self.env_id,
            "tenant_id": self.tenant_id,
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "status": self.status,
            "components": {k: v.to_dict() for k, v in self.components.items()},
            "network_config": self.network_config,
            "vm_ids": self.vm_ids,
            "snapshot_id": self.snapshot_id,
            "created_at": self.created_at,
            "provisioned_at": self.provisioned_at,
            "torn_down_at": self.torn_down_at,
            "issues": self.issues,
            "exercise_id": self.exercise_id,
            "config": self.config,
        }


class InfrastructureManager:
    """Provisions and manages sandbox environments for color-team exercises.

    The manager is the single entry point for Yellow Team operations. It
    tracks every provisioned environment in memory (and optionally persists
    records via the ORM models in :mod:`ciicerone.db.models.yellow_team`).

    Args:
        llm_provider: Optional LLM provider used to verify LLM connectivity.
        provision_delay: When ``True``, simulate realistic provisioning
            latency for each component.  Defaults to ``False`` so unit
            tests run instantly.
        failure_rate: Probability (0.0–1.0) that an individual component
            fails to provision.  Used to exercise validation/issue paths.
            Defaults to ``0.0``.
        component_factory: Optional callable that returns a custom
            :class:`EnvironmentComponent` for a given component type.
            Mainly useful for testing.
    """

    def __init__(
        self,
        llm_provider: Optional[Any] = None,
        *,
        provision_delay: bool = False,
        failure_rate: float = 0.0,
        component_factory: Optional[Callable[[str], EnvironmentComponent]] = None,
    ) -> None:
        self.llm_provider = llm_provider
        self.provision_delay = provision_delay
        self.failure_rate = max(0.0, min(failure_rate, 1.0))
        self.component_factory = component_factory

        # env_id -> Environment
        self._environments: Dict[str, Environment] = {}
        # exercise_id -> env_id (for bus-driven provisioning)
        self._exercise_envs: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Provisioning
    # ------------------------------------------------------------------

    async def provision_environment(
        self,
        scenario: Any,
        tenant_id: str,
        exercise_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Provision the sandbox environment for a scenario.

        Creates the attacker VM, target VM, SIEM VM, isolated network,
        tool server, and verifies LLM connectivity.  Each component goes
        through a simulated ``pending → provisioning → running`` lifecycle.

        Args:
            scenario: A :class:`~ciicerone.core.models.ThreatScenario` (or
                any object with ``name``, ``scenario_id``, and
                ``target_systems`` attributes).
            tenant_id: Tenant scope for the environment.
            exercise_id: Optional exercise identifier.  When provided the
                environment is linked to the exercise for bus-driven
                teardown.

        Returns:
            A structured dict with ``env_id``, ``status``,
            ``components``, ``vm_ids``, ``network_config``, ``issues``,
            and ``ready``.
        """
        env_id = f"env-{uuid4()}"
        scenario_id = getattr(scenario, "scenario_id", str(uuid4()))
        scenario_name = getattr(scenario, "name", "unknown_scenario")

        env = Environment(
            env_id=env_id,
            tenant_id=tenant_id,
            scenario_id=scenario_id,
            scenario_name=scenario_name,
            network_config=dict(DEFAULT_NETWORK_CONFIG),
            exercise_id=exercise_id,
            config=self._build_environment_config(scenario),
        )
        self._environments[env_id] = env

        if exercise_id:
            self._exercise_envs[exercise_id] = env_id

        logger.info(
            "Provisioning environment %s for tenant %s scenario %s",
            env_id, tenant_id, scenario_name,
        )

        # Build all components.
        for component_type in ALL_COMPONENT_TYPES:
            component = self._make_component(component_type, env)
            env.components[component_type] = component

        # Provision components concurrently.
        await asyncio.gather(
            *[self._provision_component(env, c) for c in env.components.values()]
        )

        # Take a pre-exercise baseline snapshot once VMs are up.
        env.snapshot_id = await self._take_snapshot(env)

        # Determine readiness.
        issues = self._collect_issues(env)
        ready = not issues and all(
            c.state == STATE_RUNNING for c in env.components.values()
        )
        env.status = ENV_STATUS_READY if ready else ENV_STATUS_ERROR
        env.issues = issues
        env.provisioned_at = datetime.now(timezone.utc).isoformat()
        env.vm_ids = [c.vm_id for c in env.vm_components if c.vm_id]

        logger.info(
            "Environment %s provisioning complete: ready=%s components=%d issues=%d",
            env_id, ready, len(env.components), len(issues),
        )

        return {
            "env_id": env_id,
            "tenant_id": tenant_id,
            "scenario_id": scenario_id,
            "scenario_name": scenario_name,
            "status": env.status,
            "ready": ready,
            "components": {k: v.to_dict() for k, v in env.components.items()},
            "vm_ids": env.vm_ids,
            "network_config": env.network_config,
            "snapshot_id": env.snapshot_id,
            "issues": issues,
            "exercise_id": exercise_id,
            "provisioned_at": env.provisioned_at,
        }

    def _make_component(
        self, component_type: str, env: Environment
    ) -> EnvironmentComponent:
        """Construct an :class:`EnvironmentComponent` for a given type."""
        if self.component_factory is not None:
            return self.component_factory(component_type)

        component_id = f"{component_type}-{env.env_id[:8]}-{uuid4().hex[:6]}"

        if component_type in DEFAULT_VM_SPECS:
            specs = dict(DEFAULT_VM_SPECS[component_type])
            vm_id = f"vm-{uuid4().hex[:12]}"
            ip = self._allocate_ip(env, component_type)
            config: Dict[str, Any] = {}
            if component_type == COMPONENT_ATTACKER_VM:
                config = {"installed_tools": list(DEFAULT_ATTACKER_TOOLS)}
            elif component_type == COMPONENT_SIEM_VM:
                config = {"siem": dict(DEFAULT_SIEM_STACK)}
            return EnvironmentComponent(
                component_id=component_id,
                component_type=component_type,
                vm_id=vm_id,
                ip_address=ip,
                specs=specs,
                config=config,
            )
        elif component_type == COMPONENT_NETWORK:
            return EnvironmentComponent(
                component_id=component_id,
                component_type=component_type,
                config=dict(env.network_config),
            )
        elif component_type == COMPONENT_TOOL_SERVER:
            return EnvironmentComponent(
                component_id=component_id,
                component_type=component_type,
                vm_id=f"ts-{uuid4().hex[:12]}",
                ip_address=self._allocate_ip(env, component_type),
                specs={"cpu_cores": 2, "memory_mb": 4096, "disk_gb": 50},
                config={"endpoint": f"https://toolserver.{env.env_id}.local"},
            )
        elif component_type == COMPONENT_LLM_PROVIDER:
            return EnvironmentComponent(
                component_id=component_id,
                component_type=component_type,
                config={"provider": "configured" if self.llm_provider else "simulated"},
            )
        else:  # pragma: no cover - defensive
            return EnvironmentComponent(
                component_id=component_id,
                component_type=component_type,
            )

    async def _provision_component(
        self, env: Environment, component: EnvironmentComponent
    ) -> None:
        """Drive a single component through its provisioning lifecycle."""
        component.state = STATE_PROVISIONING
        logger.debug(
            "Provisioning %s (%s) for env %s",
            component.component_type, component.component_id, env.env_id,
        )

        if self.provision_delay:
            delay = PROVISION_LATENCY.get(component.component_type, 0.02)
            await asyncio.sleep(delay)

        # Simulate occasional provisioning failures.
        if self.failure_rate and random.random() < self.failure_rate:
            component.state = STATE_ERROR
            component.health = "unhealthy"
            component.error = (
                f"Simulated provisioning failure for {component.component_type}"
            )
            logger.warning(
                "Component %s failed to provision for env %s",
                component.component_type, env.env_id,
            )
            return

        # LLM provider readiness depends on the injected provider.
        if component.component_type == COMPONENT_LLM_PROVIDER:
            ok = await self._check_llm_connectivity()
            if not ok:
                component.state = STATE_ERROR
                component.health = "unhealthy"
                component.error = "LLM provider connectivity check failed"
                return

        component.state = STATE_RUNNING
        component.health = "healthy"
        component.provisioned_at = datetime.now(timezone.utc).isoformat()
        # Seed initial resource usage for VMs.
        if component.vm_id is not None:
            component.resource_usage = self._sample_resource_usage(component)

    async def _check_llm_connectivity(self) -> bool:
        """Verify that the LLM provider is reachable."""
        if self.llm_provider is None:
            # In simulation mode with no provider, treat as ready.
            return True
        ping = getattr(self.llm_provider, "ping", None)
        if ping is None:
            return True
        try:
            result = ping()
            if asyncio.iscoroutine(result):
                await result
            return True
        except Exception as exc:
            logger.warning("LLM connectivity check failed: %s", exc)
            return False

    async def _take_snapshot(self, env: Environment) -> str:
        """Create a pre-exercise baseline snapshot of all VMs."""
        snapshot_id = f"snap-{uuid4().hex[:12]}"
        logger.debug("Snapshot %s taken for env %s", snapshot_id, env.env_id)
        return snapshot_id

    def _allocate_ip(self, env: Environment, component_type: str) -> str:
        """Allocate a deterministic IP within the environment subnet."""
        # Use a simple offset based on the number of already-allocated IPs.
        offset = len([c for c in env.components.values() if c.ip_address]) + 10
        return f"10.200.0.{offset}"

    def _collect_issues(self, env: Environment) -> List[str]:
        issues: List[str] = []
        for component in env.components.values():
            if component.state == STATE_ERROR and component.error:
                issues.append(
                    f"{component.component_type}: {component.error}"
                )
            elif component.state != STATE_RUNNING:
                issues.append(
                    f"{component.component_type}: not running (state={component.state})"
                )
        return issues

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    async def validate_environment(self, env_id: str) -> Dict[str, Any]:
        """Validate that all components in an environment are ready.

        Args:
            env_id: The environment identifier returned by
                :meth:`provision_environment`.

        Returns:
            A validation report dict with ``env_id``, ``valid``,
            ``checked_at``, ``component_results``, ``issues``, and
            ``summary``.
        """
        env = self._require_env(env_id)
        checked_at = datetime.now(timezone.utc).isoformat()

        component_results: List[Dict[str, Any]] = []
        issues: List[str] = []

        for component in env.components.values():
            result = self._validate_component(component)
            component_results.append(result)
            if not result["ready"]:
                issues.append(result["message"])

        valid = not issues
        total = len(component_results)
        ready_count = sum(1 for r in component_results if r["ready"])

        logger.info(
            "Validated environment %s: valid=%s ready=%d/%d",
            env_id, valid, ready_count, total,
        )

        return {
            "env_id": env_id,
            "tenant_id": env.tenant_id,
            "valid": valid,
            "checked_at": checked_at,
            "component_results": component_results,
            "issues": issues,
            "summary": (
                f"{ready_count}/{total} components ready"
                + (f"; {len(issues)} issue(s)" if issues else "")
            ),
        }

    def _validate_component(self, component: EnvironmentComponent) -> Dict[str, Any]:
        """Run readiness checks for a single component."""
        checks: List[Dict[str, Any]] = []

        # State check
        state_ok = component.state == STATE_RUNNING
        checks.append({
            "check": "state",
            "passed": state_ok,
            "detail": f"state={component.state}",
        })

        # Health check
        health_ok = component.health == "healthy"
        checks.append({
            "check": "health",
            "passed": health_ok,
            "detail": f"health={component.health}",
        })

        # VM-specific checks
        if component.vm_id is not None:
            ip_ok = component.ip_address is not None
            checks.append({
                "check": "ip_assigned",
                "passed": ip_ok,
                "detail": f"ip={component.ip_address}",
            })

        # Network check
        if component.component_type == COMPONENT_NETWORK:
            isolated = bool(component.config.get("isolated"))
            no_egress = not component.config.get("internet_egress", True)
            checks.append({
                "check": "network_isolated",
                "passed": isolated and no_egress,
                "detail": f"isolated={isolated} egress={not no_egress}",
            })

        # LLM connectivity check
        if component.component_type == COMPONENT_LLM_PROVIDER:
            checks.append({
                "check": "llm_connectivity",
                "passed": component.state == STATE_RUNNING,
                "detail": component.config.get("provider", "unknown"),
            })

        ready = all(c["passed"] for c in checks)
        failed = [c for c in checks if not c["passed"]]
        message = (
            "ready"
            if ready
            else f"failed checks: {', '.join(c['check'] for c in failed)}"
        )

        return {
            "component_id": component.component_id,
            "component_type": component.component_type,
            "ready": ready,
            "message": message,
            "checks": checks,
        }

    # ------------------------------------------------------------------
    # Monitoring
    # ------------------------------------------------------------------

    async def monitor_environment(self, env_id: str) -> Dict[str, Any]:
        """Return current resource usage for all VMs in an environment.

        Args:
            env_id: The environment identifier.

        Returns:
            A dict with ``env_id``, ``monitored_at``, ``vm_count``,
            ``vms`` (per-VM usage), and ``aggregate`` (totals/averages).
        """
        env = self._require_env(env_id)
        monitored_at = datetime.now(timezone.utc).isoformat()

        vm_reports: List[Dict[str, Any]] = []
        for component in env.vm_components:
            usage = self._sample_resource_usage(component)
            component.resource_usage = usage
            vm_reports.append({
                "vm_id": component.vm_id,
                "component_type": component.component_type,
                "ip_address": component.ip_address,
                "state": component.state,
                "usage": usage,
            })

        aggregate = self._aggregate_usage(vm_reports)

        logger.debug(
            "Monitored env %s: %d VMs, avg_cpu=%.1f%%",
            env_id, len(vm_reports), aggregate.get("avg_cpu_pct", 0),
        )

        return {
            "env_id": env_id,
            "tenant_id": env.tenant_id,
            "monitored_at": monitored_at,
            "vm_count": len(vm_reports),
            "vms": vm_reports,
            "aggregate": aggregate,
        }

    def _sample_resource_usage(self, component: EnvironmentComponent) -> Dict[str, Any]:
        """Sample simulated resource usage for a VM component.

        Usage is influenced by the VM role: SIEM VMs tend to use more
        memory, attacker VMs spike CPU during active scans.
        """
        role = component.specs.get("role", "generic")
        cpu_cores = component.specs.get("cpu_cores", 2)
        memory_mb = component.specs.get("memory_mb", 4096)

        if role == "blue_team":
            cpu_pct = random.uniform(25, 55)
            mem_pct = random.uniform(55, 80)
        elif role == "red_team":
            cpu_pct = random.uniform(15, 70)
            mem_pct = random.uniform(20, 45)
        else:  # target / tool server
            cpu_pct = random.uniform(5, 35)
            mem_pct = random.uniform(20, 50)

        disk_used_gb = round(random.uniform(10, component.specs.get("disk_gb", 60) * 0.4), 1)
        network_kbps_in = round(random.uniform(50, 2500), 1)
        network_kbps_out = round(random.uniform(50, 2000), 1)

        return {
            "cpu_pct": round(cpu_pct, 1),
            "cpu_cores": cpu_cores,
            "memory_pct": round(mem_pct, 1),
            "memory_mb_used": round(memory_mb * mem_pct / 100, 1),
            "memory_mb_total": memory_mb,
            "disk_used_gb": disk_used_gb,
            "disk_total_gb": component.specs.get("disk_gb", 60),
            "disk_pct": round(disk_used_gb / component.specs.get("disk_gb", 60) * 100, 1),
            "network_kbps_in": network_kbps_in,
            "network_kbps_out": network_kbps_out,
            "sampled_at": datetime.now(timezone.utc).isoformat(),
        }

    def _aggregate_usage(self, vm_reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not vm_reports:
            return {
                "avg_cpu_pct": 0.0,
                "avg_memory_pct": 0.0,
                "total_network_kbps_in": 0.0,
                "total_network_kbps_out": 0.0,
                "total_disk_used_gb": 0.0,
            }
        cpus = [r["usage"]["cpu_pct"] for r in vm_reports]
        mems = [r["usage"]["memory_pct"] for r in vm_reports]
        net_in = [r["usage"]["network_kbps_in"] for r in vm_reports]
        net_out = [r["usage"]["network_kbps_out"] for r in vm_reports]
        disk = [r["usage"]["disk_used_gb"] for r in vm_reports]
        return {
            "avg_cpu_pct": round(sum(cpus) / len(cpus), 1),
            "max_cpu_pct": round(max(cpus), 1),
            "avg_memory_pct": round(sum(mems) / len(mems), 1),
            "max_memory_pct": round(max(mems), 1),
            "total_network_kbps_in": round(sum(net_in), 1),
            "total_network_kbps_out": round(sum(net_out), 1),
            "total_disk_used_gb": round(sum(disk), 1),
        }

    # ------------------------------------------------------------------
    # Teardown
    # ------------------------------------------------------------------

    async def teardown_environment(self, env_id: str) -> Dict[str, Any]:
        """Tear down an environment, stopping VMs and removing resources.

        Args:
            env_id: The environment identifier.

        Returns:
            A dict with ``env_id``, ``status``, ``torn_down_at``, and
            per-component teardown results.
        """
        env = self._require_env(env_id)
        env.status = ENV_STATUS_TEARING_DOWN

        logger.info("Tearing down environment %s", env_id)

        results: List[Dict[str, Any]] = []
        await asyncio.gather(
            *[self._teardown_component(env, c, results) for c in env.components.values()]
        )

        env.status = ENV_STATUS_TORN_DOWN
        env.torn_down_at = datetime.now(timezone.utc).isoformat()

        # Drop the exercise linkage.
        if env.exercise_id and self._exercise_envs.get(env.exercise_id) == env_id:
            del self._exercise_envs[env.exercise_id]

        logger.info("Environment %s torn down", env_id)

        return {
            "env_id": env_id,
            "tenant_id": env.tenant_id,
            "status": env.status,
            "torn_down_at": env.torn_down_at,
            "components": results,
        }

    async def _teardown_component(
        self,
        env: Environment,
        component: EnvironmentComponent,
        results: List[Dict[str, Any]],
    ) -> None:
        """Stop a single component and record the result."""
        if self.provision_delay:
            await asyncio.sleep(PROVISION_LATENCY.get(component.component_type, 0.02) * 0.5)

        if component.state in (STATE_TORN_DOWN, STATE_STOPPED):
            results.append({
                "component_id": component.component_id,
                "component_type": component.component_type,
                "status": "already_stopped",
            })
            return

        component.state = STATE_TORN_DOWN
        component.torn_down_at = datetime.now(timezone.utc).isoformat()
        component.resource_usage = {}
        results.append({
            "component_id": component.component_id,
            "component_type": component.component_type,
            "status": "stopped",
            "vm_id": component.vm_id,
        })

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_environment_status(self, env_id: str) -> Dict[str, Any]:
        """Return the current status of an environment.

        Args:
            env_id: The environment identifier.

        Returns:
            A dict summarising the environment status, component states,
            and VM IDs.
        """
        env = self._require_env(env_id)
        component_states = {
            ct: {
                "state": c.state,
                "health": c.health,
                "vm_id": c.vm_id,
                "ip_address": c.ip_address,
            }
            for ct, c in env.components.items()
        }
        running = sum(1 for c in env.components.values() if c.state == STATE_RUNNING)
        return {
            "env_id": env_id,
            "tenant_id": env.tenant_id,
            "scenario_id": env.scenario_id,
            "scenario_name": env.scenario_name,
            "status": env.status,
            "exercise_id": env.exercise_id,
            "vm_ids": env.vm_ids,
            "snapshot_id": env.snapshot_id,
            "components_running": running,
            "components_total": len(env.components),
            "component_states": component_states,
            "issues": list(env.issues),
            "created_at": env.created_at,
            "provisioned_at": env.provisioned_at,
            "torn_down_at": env.torn_down_at,
        }

    def list_environments(self, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all known environments, optionally filtered by tenant."""
        envs = list(self._environments.values())
        if tenant_id is not None:
            envs = [e for e in envs if e.tenant_id == tenant_id]
        return [
            {
                "env_id": e.env_id,
                "tenant_id": e.tenant_id,
                "scenario_name": e.scenario_name,
                "status": e.status,
                "exercise_id": e.exercise_id,
                "created_at": e.created_at,
            }
            for e in envs
        ]

    # ------------------------------------------------------------------
    # Configuration management
    # ------------------------------------------------------------------

    def _build_environment_config(self, scenario: Any) -> Dict[str, Any]:
        """Build a structured environment configuration for a scenario."""
        target_systems = list(getattr(scenario, "target_systems", []) or [])
        return {
            "network_topology": {
                "type": "isolated_subnet",
                "internet_egress": False,
                "subnet": DEFAULT_NETWORK_CONFIG["subnet"],
                "gateway": DEFAULT_NETWORK_CONFIG["gateway"],
                "dns": DEFAULT_NETWORK_CONFIG["dns"],
                "vlan_id": DEFAULT_NETWORK_CONFIG["vlan_id"],
            },
            "vm_specifications": {
                ct: dict(specs) for ct, specs in DEFAULT_VM_SPECS.items()
            },
            "tool_installations": {
                "attacker_vm": list(DEFAULT_ATTACKER_TOOLS),
            },
            "siem_configuration": dict(DEFAULT_SIEM_STACK),
            "snapshot_points": [
                {"name": "pre_exercise_baseline", "description": "Baseline before exercise starts"},
            ],
            "target_systems": target_systems,
        }

    def get_environment_config(self, env_id: str) -> Dict[str, Any]:
        """Return the structured configuration for an environment."""
        env = self._require_env(env_id)
        return dict(env.config)

    # ------------------------------------------------------------------
    # Event bus integration
    # ------------------------------------------------------------------

    def subscribe_to_event_bus(
        self,
        bus: EventBus,
        tenant_id: str,
        exercise_id: Optional[str] = None,
    ) -> None:
        """Subscribe the manager to the shared event bus.

        Subscribes to:
            * ``SIMULATION_STARTED`` — provisions the environment and
              publishes ``YELLOW_TEAM_ENV_READY``.
            * ``SIMULATION_COMPLETED`` — tears down the environment and
              publishes ``YELLOW_TEAM_ENV_TEARDOWN``.

        Args:
            bus: The shared :class:`EventBus`.
            tenant_id: Tenant scope for events to process.
            exercise_id: Optional exercise identifier.  When provided,
                only events matching this exercise are processed.
        """
        if not isinstance(bus, EventBus):
            raise TypeError("bus must be an EventBus instance")

        manager = self

        async def _on_simulation_started(event: BusEvent) -> None:
            if event.tenant_id != tenant_id:
                return
            if exercise_id is not None and event.exercise_id != exercise_id:
                return

            scenario = event.payload.get("scenario")
            target_exercise_id = event.exercise_id or exercise_id
            if scenario is None:
                logger.warning(
                    "SIMULATION_STARTED received without a scenario payload; "
                    "Yellow Team cannot provision environment."
                )
                return

            try:
                result = await manager.provision_environment(
                    scenario=scenario,
                    tenant_id=tenant_id,
                    exercise_id=target_exercise_id,
                )
            except Exception as exc:
                logger.exception("Yellow Team provisioning failed: %s", exc)
                return

            await bus.publish(
                YellowTeamEnvReadyEvent(
                    tenant_id=tenant_id,
                    exercise_id=target_exercise_id,
                    env_id=result["env_id"],
                    components=list(result["components"].keys()),
                    vm_ids=result["vm_ids"],
                    network_config=result["network_config"],
                    ready=result["ready"],
                    issues=result["issues"],
                )
            )

        async def _on_simulation_completed(event: BusEvent) -> None:
            if event.tenant_id != tenant_id:
                return
            target_exercise_id = event.exercise_id or exercise_id
            if exercise_id is not None and event.exercise_id != exercise_id:
                return

            env_id = manager._exercise_envs.get(target_exercise_id or "")
            if env_id is None:
                logger.debug(
                    "SIMULATION_COMPLETED for exercise %s with no linked environment",
                    target_exercise_id,
                )
                return

            try:
                await manager.teardown_environment(env_id)
            except Exception as exc:
                logger.exception("Yellow Team teardown failed: %s", exc)
                return

            await bus.publish(
                BusEvent(
                    event_type=EventType.YELLOW_TEAM_ENV_TEARDOWN,
                    tenant_id=tenant_id,
                    exercise_id=target_exercise_id,
                    payload={
                        "env_id": env_id,
                        "torn_down": True,
                    },
                )
            )

        bus.subscribe(EventType.SIMULATION_STARTED, _on_simulation_started)
        bus.subscribe(EventType.SIMULATION_COMPLETED, _on_simulation_completed)

        logger.info(
            "Yellow Team subscribed to event bus for tenant %s exercise %s",
            tenant_id, exercise_id,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _require_env(self, env_id: str) -> Environment:
        env = self._environments.get(env_id)
        if env is None:
            raise KeyError(f"Unknown environment: {env_id}")
        return env
