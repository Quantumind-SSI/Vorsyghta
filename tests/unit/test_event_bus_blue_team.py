"""Tests for the shared event bus and blue team bus integration.

Covers DAVID-001: wire blue team modules to event bus.
"""

import asyncio
import pytest

from vorsyghta.core.event_bus import EventBus
from vorsyghta.core.event_types import (
    BlueTeamAlertEvent,
    BlueTeamHuntEvent,
    BlueTeamIncidentCreatedEvent,
    BusEvent,
    EventType,
    RedTeamAttackStageEvent,
)
from vorsyghta.defense.blue_team import BlueTeamBusIntegration


@pytest.fixture
def event_bus():
    return EventBus()


@pytest.fixture
def blue_team(event_bus):
    integration = BlueTeamBusIntegration(
        bus=event_bus,
        tenant_id="tenant-1",
        exercise_id="ex-001",
    )
    integration.register()
    return integration


@pytest.mark.asyncio
async def test_event_bus_publish_and_subscribe(event_bus):
    received = []

    async def handler(event: BusEvent):
        received.append(event)

    event_bus.subscribe(EventType.RED_TEAM_ATTACK_STAGE, handler)

    attack = RedTeamAttackStageEvent(
        tenant_id="tenant-1",
        exercise_id="ex-001",
        simulation_id="sim-001",
        stage_id="stage-1",
        stage_name="Spearphishing",
        technique_id="T1566",
        tactic="initial_access",
        content="Malicious email attachment",
        iocs=["evil.exe"],
    )
    await event_bus.publish(attack)

    assert len(received) == 1
    assert received[0].payload["technique_id"] == "T1566"


@pytest.mark.asyncio
async def test_blue_team_detects_red_team_attack(blue_team, event_bus):
    blue_alerts = []

    async def alert_handler(event: BusEvent):
        if event.event_type == EventType.BLUE_TEAM_ALERT:
            blue_alerts.append(event)

    event_bus.subscribe(EventType.BLUE_TEAM_ALERT, alert_handler)

    attack = RedTeamAttackStageEvent(
        tenant_id="tenant-1",
        exercise_id="ex-001",
        simulation_id="sim-001",
        stage_id="stage-1",
        stage_name="Spearphishing",
        technique_id="T1566",
        tactic="initial_access",
        content="powershell.exe -enc SGVsbG8gV29ybGQ=",
        iocs=["evil.exe"],
    )
    await event_bus.publish(attack)
    await asyncio.sleep(0.1)

    assert len(blue_alerts) >= 1
    assert any(a.payload["technique_id"] == "T1059" for a in blue_alerts)


@pytest.mark.asyncio
async def test_tenant_isolation(blue_team, event_bus):
    blue_alerts = []

    async def alert_handler(event: BusEvent):
        if event.event_type == EventType.BLUE_TEAM_ALERT:
            blue_alerts.append(event)

    event_bus.subscribe(EventType.BLUE_TEAM_ALERT, alert_handler)

    attack = RedTeamAttackStageEvent(
        tenant_id="tenant-2",  # different tenant
        exercise_id="ex-001",
        simulation_id="sim-001",
        stage_id="stage-1",
        stage_name="Spearphishing",
        technique_id="T1566",
        tactic="initial_access",
        content="Office application spawned powershell.exe",
    )
    await event_bus.publish(attack)
    await asyncio.sleep(0.1)

    assert len(blue_alerts) == 0


@pytest.mark.asyncio
async def test_critical_alert_triggers_hunt_and_incident(blue_team, event_bus):
    hunts = []
    incidents = []

    async def downstream_handler(event: BusEvent):
        if event.event_type == EventType.BLUE_TEAM_HUNT_EVENT:
            hunts.append(event)
        elif event.event_type == EventType.BLUE_TEAM_INCIDENT_CREATED:
            incidents.append(event)

    event_bus.subscribe(EventType.BLUE_TEAM_HUNT_EVENT, downstream_handler)
    event_bus.subscribe(EventType.BLUE_TEAM_INCIDENT_CREATED, downstream_handler)

    attack = RedTeamAttackStageEvent(
        tenant_id="tenant-1",
        exercise_id="ex-001",
        simulation_id="sim-001",
        stage_id="stage-1",
        stage_name="Credential Dumping",
        technique_id="T1003",
        tactic="credential_access",
        content="mimikatz.exe executed lsadump::sam",
        iocs=["mimikatz.exe"],
    )
    await event_bus.publish(attack)
    await asyncio.sleep(0.5)

    assert len(hunts) >= 1
    assert any(h.payload["technique_id"] == "T1003" for h in hunts)
    assert len(incidents) >= 1


@pytest.mark.asyncio
async def test_alert_triage_receives_blue_alerts(blue_team, event_bus):
    attack = RedTeamAttackStageEvent(
        tenant_id="tenant-1",
        exercise_id="ex-001",
        simulation_id="sim-001",
        stage_id="stage-1",
        stage_name="Credential Dumping",
        technique_id="T1003",
        tactic="credential_access",
        content="mimikatz.exe executed lsadump::sam",
    )
    await event_bus.publish(attack)
    await asyncio.sleep(0.1)

    assert len(blue_team.alert_triage.get_triaged()) >= 1
