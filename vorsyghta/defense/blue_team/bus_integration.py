"""Blue team event bus integration for color-team orchestration.

This module provides a convenience class that wires all blue team defensive
modules to the shared event bus in a single operation. Each module also exposes
its own ``subscribe_to_event_bus`` method for fine-grained use.

Owner: David Onoja (@ocheme1107) — Blue Team Lead (Advanced)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from vorsyghta.core.event_bus import EventBus
from vorsyghta.defense.blue_team.alert_triage import AlertTriage
from vorsyghta.defense.blue_team.edr_agent import EDRAgent, FileEvent, ProcessEvent
from vorsyghta.defense.blue_team.ids_detector import IDSDetector, NetworkPacket
from vorsyghta.defense.blue_team.incident_response import IncidentResponse
from vorsyghta.defense.blue_team.siem_simulator import SIEMAlert, SIEMSimulator
from vorsyghta.defense.blue_team.threat_hunter import ThreatHunter

logger = logging.getLogger(__name__)


class BlueTeamBusIntegration:
    """Wires all blue team modules to the shared event bus.

    This is a convenience orchestrator. It instantiates the standard blue team
    modules (SIEM, IDS, EDR, Threat Hunter, IR, Alert Triage) and calls each
    module's ``subscribe_to_event_bus`` method against the supplied bus.

    Attributes:
        bus: The shared :class:`EventBus`.
        tenant_id: Tenant scope for the exercise.
        exercise_id: Optional exercise identifier.
        siem: SIEM simulator.
        ids: IDS detector.
        edr: EDR agent.
        threat_hunter: Threat hunter.
        incident_response: Incident response engine.
        alert_triage: Alert triage engine.
    """

    def __init__(
        self,
        bus: EventBus,
        tenant_id: str,
        exercise_id: Optional[str] = None,
        siem: Optional[SIEMSimulator] = None,
        ids: Optional[IDSDetector] = None,
        edr: Optional[EDRAgent] = None,
        threat_hunter: Optional[ThreatHunter] = None,
        incident_response: Optional[IncidentResponse] = None,
        alert_triage: Optional[AlertTriage] = None,
    ):
        self.bus = bus
        self.tenant_id = tenant_id
        self.exercise_id = exercise_id

        self.siem = siem or SIEMSimulator()
        self.ids = ids or IDSDetector()
        self.edr = edr or EDRAgent()
        self.threat_hunter = threat_hunter or ThreatHunter()
        self.incident_response = incident_response or IncidentResponse()
        self.alert_triage = alert_triage or AlertTriage()

        self._blue_team_alert_handlers: List[Callable[[SIEMAlert], None]] = []

    def register(self) -> None:
        """Register all blue team modules with the event bus."""
        self.siem.subscribe_to_event_bus(self.bus, self.tenant_id, self.exercise_id)
        self.ids.subscribe_to_event_bus(self.bus, self.tenant_id, self.exercise_id)
        self.edr.subscribe_to_event_bus(self.bus, self.tenant_id, self.exercise_id)
        self.threat_hunter.subscribe_to_event_bus(self.bus, self.tenant_id, self.exercise_id)
        self.incident_response.subscribe_to_event_bus(self.bus, self.tenant_id, self.exercise_id)
        self.alert_triage.subscribe_to_event_bus(self.bus, self.tenant_id, self.exercise_id)

        logger.info(
            "Blue team bus integration registered for tenant %s exercise %s",
            self.tenant_id,
            self.exercise_id,
        )

    def on_blue_team_alert(self, handler: Callable[[SIEMAlert], None]) -> None:
        """Register a callback for every blue team alert generated.

        Note: The callback is invoked by the individual module handlers after
        they publish their alert events. This is best-effort and does not
        replace the event bus subscription model.
        """
        self._blue_team_alert_handlers.append(handler)

    def get_stats(self) -> dict:
        """Return a combined stats snapshot from all blue team modules."""
        return {
            "siem": self.siem.get_stats(),
            "ids": self.ids.get_stats(),
            "edr": self.edr.get_stats(),
            "threat_hunter": self.threat_hunter.get_stats(),
            "incident_response": self.incident_response.get_stats(),
            "alert_triage": self.alert_triage.get_stats(),
        }

    def evaluate_stage_payload(self, payload: Dict[str, Any]) -> List[SIEMAlert]:
        """Run every blue module against one red team stage payload.

        This is the single home for shaping stage payloads into module
        telemetry (SIEM log entry, IDS packet, EDR process/file events).
        Both the in-process bus handlers and the exercise orchestrator call
        this, so detection input never drifts between paths.

        Args:
            payload: Red team stage payload with ``content``,
                ``technique_id``, ``stage_id``.

        Returns:
            Raw module alerts (SIEMAlert) for the stage; empty when the
            stage evades all modules.
        """
        content = payload.get("content", "")
        technique_id = payload.get("technique_id", "")
        stage_id = payload.get("stage_id", "")
        timestamp = datetime.now(timezone.utc).isoformat()
        alerts: List[SIEMAlert] = []

        # SIEM: ingest the stage as a log entry and run correlation rules.
        self.siem.ingest_log({
            "source": "red_team_simulator",
            "message": content,
            "mitre_technique": technique_id,
            "stage_id": stage_id,
            "timestamp": timestamp,
        })
        alerts.extend(self.siem.check_correlations())

        # IDS: inspect a network packet derived from the stage.
        technique_ports = {
            "T1046": 80, "T1190": 80, "T1110": 22, "T1003": 445,
            "T1059": 443, "T1071": 443, "T1041": 443, "T1048": 53,
            "T1505": 80, "T1136": 445,
        }
        packet = NetworkPacket(
            timestamp=timestamp,
            protocol="tcp",
            source_ip="10.0.0.5",
            source_port=12345,
            dest_ip="10.0.0.10",
            dest_port=technique_ports.get(technique_id, 80),
            payload=content[:1000],
        )
        alerts.extend(self.ids.inspect_packet(packet))

        # EDR: process and file telemetry from the stage content.
        process_event = ProcessEvent(
            pid=1,
            process_name="attack.exe",
            command_line=content,
            user="attacker",
            timestamp=timestamp,
        )
        alerts.extend(self.edr.monitor_process(process_event))

        file_event = FileEvent(
            path=f"/tmp/{stage_id}.dat",
            operation="create",
            process="attack.exe",
            user="attacker",
            timestamp=timestamp,
        )
        alerts.extend(self.edr.monitor_file(file_event))

        return alerts
