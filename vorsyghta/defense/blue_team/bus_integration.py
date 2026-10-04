"""Blue team event bus integration for color-team orchestration.

This module provides a convenience class that wires all blue team defensive
modules to the shared event bus in a single operation. Each module also exposes
its own ``subscribe_to_event_bus`` method for fine-grained use.

Owner: David Onoja (@ocheme1107) — Blue Team Lead (Advanced)
"""

from __future__ import annotations

import logging
from typing import Any, Callable, List, Optional

from vorsyghta.core.event_bus import EventBus
from vorsyghta.defense.blue_team.alert_triage import AlertTriage
from vorsyghta.defense.blue_team.edr_agent import EDRAgent
from vorsyghta.defense.blue_team.ids_detector import IDSDetector
from vorsyghta.defense.blue_team.incident_response import IncidentResponse
from vorsyghta.defense.blue_team.siem_simulator import SIEMSimulator
from vorsyghta.defense.blue_team.threat_hunter import ThreatHunter
from vorsyghta.integrations.siem_client import SIEMAlert

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
