"""Core simulation engine and models.

Contains the main simulation orchestration logic, data models,
and business logic for threat scenario execution.
"""

from vorsyghta.core.models import (
    SimulationResult,
    ThreatScenario,
    SimulationStatus,
    SimulationStage,
)
from vorsyghta.core.simulator import Simulator
from vorsyghta.core.exceptions import (
    VorsyghtaError,
    SimulationError,
    ConfigurationError,
    ValidationError,
    LLMProviderError,
)
from vorsyghta.core.mitigation_generator import (
    MitigationGenerator,
    MitigationPlaybook,
    generate_mitigation_playbook,
)
from vorsyghta.core.team_playbooks import (
    TeamPlaybookGenerator,
    TeamPlaybook,
    SecurityTeam,
    generate_team_playbook,
    generate_all_team_playbooks,
)
from vorsyghta.core.ai_enhanced_playbooks import (
    AIEnhancedPlaybookGenerator,
    PlaybookContext,
    PlaybookQuality,
    generate_ai_enhanced_manual,
    generate_all_ai_enhanced_manuals,
)
from vorsyghta.core.playbook_validator import (
    PlaybookValidator,
    ValidationReport,
    ValidationFinding,
    ValidationScore,
    ValidationSeverity,
    ValidationCategory,
    ComplianceFramework,
    validate_playbook,
    get_validation_summary,
)
from vorsyghta.core.batch_processor import (
    BatchProcessor,
    BatchConfig,
    BatchProgress,
    BatchResult,
    BatchStatus,
    BatchMetrics,
    JobResult,
    JobStatus,
    process_scenarios_batch,
    process_scenarios_batch_sync,
)
from vorsyghta.core.event_sourcing import (
    Event,
    EventStore,
    EventSourcedAggregate,
    EventSourcedRepository,
    AggregateType,
    EventStoreError,
    ConcurrencyError,
)
from vorsyghta.core.postgres_event_store import (
    PostgresEventStore,
)
from vorsyghta.core.audit_logger import (
    AuditLogger,
    AuditEvent,
    AuditCategory,
    AuditSeverity,
    AuditSink,
    MemoryAuditSink,
    FileAuditSink,
    get_audit_logger,
    reset_audit_logger,
    sanitize_for_log,
)

__all__ = [
    "SimulationResult",
    "ThreatScenario",
    "SimulationStatus",
    "SimulationStage",
    "Simulator",
    "VorsyghtaError",
    "SimulationError",
    "ConfigurationError",
    "ValidationError",
    "LLMProviderError",
    "MitigationGenerator",
    "MitigationPlaybook",
    "generate_mitigation_playbook",
    "TeamPlaybookGenerator",
    "TeamPlaybook",
    "SecurityTeam",
    "generate_team_playbook",
    "generate_all_team_playbooks",
    "AIEnhancedPlaybookGenerator",
    "PlaybookContext",
    "PlaybookQuality",
    "generate_ai_enhanced_manual",
    "generate_all_ai_enhanced_manuals",
    # Playbook Validation
    "PlaybookValidator",
    "ValidationReport",
    "ValidationFinding",
    "ValidationScore",
    "ValidationSeverity",
    "ValidationCategory",
    "ComplianceFramework",
    "validate_playbook",
    "get_validation_summary",
    # Batch Processing
    "BatchProcessor",
    "BatchConfig",
    "BatchProgress",
    "BatchResult",
    "BatchStatus",
    "BatchMetrics",
    "JobResult",
    "JobStatus",
    "process_scenarios_batch",
    "process_scenarios_batch_sync",
    # Event Sourcing
    "Event",
    "EventStore",
    "EventSourcedAggregate",
    "EventSourcedRepository",
    "AggregateType",
    "EventStoreError",
    "ConcurrencyError",
    # PostgreSQL Event Store
    "PostgresEventStore",
    # Audit Logger
    "AuditLogger",
    "AuditEvent",
    "AuditCategory",
    "AuditSeverity",
    "AuditSink",
    "MemoryAuditSink",
    "FileAuditSink",
    "get_audit_logger",
    "reset_audit_logger",
    "sanitize_for_log",
]
