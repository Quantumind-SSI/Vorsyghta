from vorsyghta.core.worker.base import TeamWorker
from vorsyghta.core.broker.redis_broker import RedisStreamsBroker
from vorsyghta.core.event_types import EventType


def create_red_worker(broker: RedisStreamsBroker):
    """Consume red team attack stage events from the stream."""

    async def handler(event):
        # Red team attack stages are produced upstream (Simulator via the
        # orchestrator); workers downstream persist or forward as needed.
        return event

    return TeamWorker(
        "red",
        [
            EventType.RED_TEAM_ATTACK_STAGE.value,
            EventType.RED_TEAM_IOC_GENERATED.value,
        ],
        broker,
        handler,
    )


def create_blue_worker(broker: RedisStreamsBroker):
    """Consume blue team alert, hunt, and incident events."""

    async def handler(event):
        return event

    return TeamWorker(
        "blue",
        [
            EventType.BLUE_TEAM_ALERT.value,
            EventType.BLUE_TEAM_HUNT_EVENT.value,
            EventType.BLUE_TEAM_INCIDENT_CREATED.value,
        ],
        broker,
        handler,
    )


def create_purple_worker(broker: RedisStreamsBroker):
    """Consume purple team AAR events."""

    async def handler(event):
        return event

    return TeamWorker("purple", [EventType.PURPLE_TEAM_AAR.value], broker, handler)


def create_white_worker(broker: RedisStreamsBroker):
    """Consume white team ROE check, violation, and scope approval events."""

    async def handler(event):
        return event

    return TeamWorker(
        "white",
        [
            EventType.WHITE_TEAM_ROE_CHECK.value,
            EventType.WHITE_TEAM_ROE_VIOLATION.value,
            EventType.WHITE_TEAM_SCOPE_APPROVAL.value,
        ],
        broker,
        handler,
    )


def create_black_worker(broker: RedisStreamsBroker):
    """Consume black team scoring events."""

    async def handler(event):
        return event

    return TeamWorker("black", [EventType.BLACK_TEAM_SCORE.value], broker, handler)


def create_yellow_worker(broker: RedisStreamsBroker):
    """Consume yellow team environment lifecycle events."""

    async def handler(event):
        return event

    return TeamWorker(
        "yellow",
        [
            EventType.YELLOW_TEAM_ENV_READY.value,
            EventType.YELLOW_TEAM_ENV_TEARDOWN.value,
        ],
        broker,
        handler,
    )


def create_green_worker(broker: RedisStreamsBroker):
    """Consume green team training assignment and awareness events."""

    async def handler(event):
        return event

    return TeamWorker(
        "green",
        [
            EventType.GREEN_TEAM_TRAINING_ASSIGNED.value,
            EventType.GREEN_TEAM_AWARENESS_ASSESSMENT.value,
        ],
        broker,
        handler,
    )


def create_orange_worker(broker: RedisStreamsBroker):
    """Consume orange team compliance gap and regulatory mapping events."""

    async def handler(event):
        return event

    return TeamWorker(
        "orange",
        [
            EventType.ORANGE_TEAM_COMPLIANCE_GAP.value,
            EventType.ORANGE_TEAM_REGULATORY_MAPPING.value,
        ],
        broker,
        handler,
    )


def create_all_workers(broker: RedisStreamsBroker) -> list[TeamWorker]:
    """Build one worker per color team against the shared broker."""
    return [
        create_red_worker(broker),
        create_blue_worker(broker),
        create_purple_worker(broker),
        create_white_worker(broker),
        create_black_worker(broker),
        create_yellow_worker(broker),
        create_green_worker(broker),
        create_orange_worker(broker),
    ]
