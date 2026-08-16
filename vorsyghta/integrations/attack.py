"""Vorsyghta Attack Integration Wrapper.

High-level integration that wraps AttackClient with Vorsyghta scenario
management, audit logging, and RAG storage.
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from .attack_client import (
    AttackClient,
    AttackFlow,
    AttackReport,
    AttackArtifact,
    AttackMemoryEntry,
)
from .attack_mapper import AttackMapper

logger = logging.getLogger(__name__)


class AttackIntegration:
    """High-level Vorsyghta Attack integration for Vorsyghta.

    Wraps the Vorsyghta Attack API client with:
        - Scenario-to-flow mapping
        - Audit logging
        - RAG storage for after-action reviews
        - Real-time monitoring with callbacks

    Example:
        integration = AttackIntegration()
        flow = await integration.launch_attack(scenario, target_info)
        status = await integration.monitor_flow(flow.flow_id)
        aar = await integration.generate_aar(flow.flow_id, scenario)
    """

    def __init__(
        self,
        client: Optional[AttackClient] = None,
        mapper: Optional[AttackMapper] = None,
        audit_logger: Optional[Any] = None,
    ):
        self.client = client or AttackClient()
        self.mapper = mapper or AttackMapper()
        self.audit_logger = audit_logger
        self._active_flows: Dict[str, AttackFlow] = {}

    async def launch_attack(
        self,
        scenario: Dict[str, Any],
        target_info: Dict[str, Any],
        payloads: Optional[Dict[str, Any]] = None,
    ) -> AttackFlow:
        """Launch a Vorsyghta Attack attack flow from a Vorsyghta scenario.

        Args:
            scenario: Vorsyghta scenario dict from YAML template
            target_info: Target environment information
            payloads: Optional LLM-generated threat content to arm agents with

        Returns:
            AttackFlow with the created flow
        """
        logger.info(f"Launching Vorsyghta Attack attack for scenario: {scenario.get('name', 'Unknown')}")

        flow_params = self.mapper.scenario_to_flow(scenario, target_info, payloads=payloads)

        self._log_audit("attack_flow_create", {
            "scenario": scenario.get("name"),
            "target": flow_params["target"],
            "mitre_techniques": scenario.get("mitre_techniques", []),
            "has_payloads": payloads is not None,
        })

        flow = await self.client.create_flow(
            input_text=flow_params["description"],
            provider=flow_params.get("provider", "openai"),
        )

        self._active_flows[flow.flow_id] = flow
        logger.info(f"Vorsyghta Attack flow created: {flow.flow_id} (status: {flow.status})")

        return flow

    async def monitor_flow(
        self,
        flow_id: str,
        callback: Optional[Any] = None,
        poll_interval: int = 10,
        timeout: int = 3600,
    ) -> AttackFlow:
        """Monitor a Vorsyghta Attack flow until completion.

        Args:
            flow_id: The flow ID to monitor
            callback: Optional async callback called on each status update
            poll_interval: Seconds between status checks
            timeout: Maximum wait time in seconds

        Returns:
            Final AttackFlow state
        """
        elapsed = 0
        last_status = None

        while elapsed < timeout:
            flow = await self.client.get_flow_status(flow_id)

            if flow.status != last_status:
                logger.info(f"Flow {flow_id} status: {flow.status}")
                last_status = flow.status

                self._log_audit("attack_flow_status", {
                    "flow_id": flow_id,
                    "status": flow.status,
                    "tasks": len(flow.tasks),
                })

                if callback:
                    try:
                        await callback(flow)
                    except Exception as e:
                        logger.warning(f"Monitor callback error: {e}")

            if flow.status in ("completed", "failed", "cancelled"):
                return flow

            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        logger.warning(f"Flow {flow_id} monitoring timed out after {timeout}s")
        return await self.client.get_flow_status(flow_id)

    async def steer_flow(self, flow_id: str, instruction: str) -> bool:
        """Send a steering instruction to an active flow.

        Args:
            flow_id: Active flow ID
            instruction: Natural language instruction

        Returns:
            True if instruction was accepted
        """
        self._log_audit("attack_flow_steer", {
            "flow_id": flow_id,
            "instruction": instruction,
        })

        return await self.client.steer_flow(flow_id, instruction)

    async def stop_flow(self, flow_id: str) -> bool:
        """Stop a running flow.

        Args:
            flow_id: The flow ID to stop

        Returns:
            True if flow was stopped
        """
        self._log_audit("attack_flow_stop", {"flow_id": flow_id})
        return await self.client.stop_flow(flow_id)

    async def generate_aar(
        self,
        flow_id: str,
        scenario: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate an After Action Review from a completed flow.

        Args:
            flow_id: Completed flow ID
            scenario: Original Vorsyghta scenario

        Returns:
            AAR dict with structured review data
        """
        flow = await self.client.get_flow_status(flow_id)
        report = await self.client.get_flow_report(flow_id)

        aar = self.mapper.flow_to_aar(
            flow_status={
                "flow_id": flow.flow_id,
                "status": flow.status,
                "target": flow.target,
            },
            report={
                "executive_summary": report.executive_summary,
                "vulnerabilities": report.vulnerabilities,
                "mitre_techniques": report.mitre_techniques,
                "recommendations": report.recommendations,
                "report_markdown": report.report_markdown,
            },
            scenario=scenario,
        )

        aar["generated_at"] = datetime.utcnow().isoformat()
        aar["flow_duration"] = None

        self._log_audit("attack_aar_generated", {
            "flow_id": flow_id,
            "scenario": scenario.get("name"),
            "vulnerabilities_found": len(aar.get("vulnerabilities", [])),
            "objectives_met": sum(
                1 for o in aar.get("objectives_met", [])
                if o.get("status") == "likely_met"
            ),
        })

        return aar

    async def get_artifacts(self, flow_id: str) -> List[AttackArtifact]:
        """Get all artifacts from a flow.

        Args:
            flow_id: The flow ID

        Returns:
            List of artifacts
        """
        return await self.client.get_flow_artifacts(flow_id)

    async def search_past_attacks(self, query: str, limit: int = 10) -> List[AttackMemoryEntry]:
        """Search Vorsyghta Attack's memory for past attack patterns.

        Args:
            query: Natural language search query
            limit: Maximum results

        Returns:
            List of memory entries
        """
        return await self.client.search_memory(query, limit)

    async def list_flows(self, limit: int = 50) -> List[AttackFlow]:
        """List all Vorsyghta Attack flows.

        Args:
            limit: Maximum number of flows

        Returns:
            List of flows
        """
        return await self.client.list_flows(limit)

    async def health_check(self) -> Dict[str, Any]:
        """Check if Vorsyghta Attack is reachable and healthy."""
        return await self.client.health_check()

    def _log_audit(self, event_type: str, data: Dict[str, Any]) -> None:
        """Log an audit event if audit logger is available."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event": event_type,
            "data": data,
        }
        logger.debug(f"Vorsyghta Attack audit: {json.dumps(log_entry)}")

        if self.audit_logger:
            try:
                if hasattr(self.audit_logger, "log"):
                    self.audit_logger.log(event_type, data)
                elif hasattr(self.audit_logger, "info"):
                    self.audit_logger.info(f"{event_type}: {json.dumps(data)}")
            except Exception as e:
                logger.warning(f"Audit log failed: {e}")
