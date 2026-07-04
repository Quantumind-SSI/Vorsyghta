"""Quantum threat simulation package for Ciicerone.

Provides quantum cryptographic threat assessment capabilities:
    - crypto_scanner: Detect cryptographic implementations in targets
    - vulnerability_analyzer: Assess quantum vulnerability (Shor's/Grover's)
    - pqc_migration_planner: Generate NIST-standard PQC migration plans
    - hybrid_validator: Validate hybrid PQ/TLS deployments
    - timeline_simulator: Model Y2Q readiness timelines
    - agent: QuantumThreatAgent orchestrating all components
"""

from .agent import QuantumThreatAgent
from .crypto_scanner import CryptoInventoryScanner
from .hybrid_validator import HybridCryptoValidator
from .models import (
    CryptoAlgorithmType,
    CryptoInventoryItem,
    HybridCryptoValidationResult,
    MigrationItem,
    PQCMigrationPlan,
    QuantumAttackSimulationResult,
    QuantumAttackVector,
    QuantumCryptoScanResult,
    QuantumVulnerabilityFinding,
    SeverityLevel,
    TimelineMilestone,
    Y2QTimelineResult,
)
from .pqc_migration_planner import PQCMigrationPlanner
from .timeline_simulator import QuantumTimelineSimulator
from .vulnerability_analyzer import QuantumVulnerabilityAnalyzer

__all__ = [
    "QuantumThreatAgent",
    "CryptoInventoryScanner",
    "QuantumVulnerabilityAnalyzer",
    "PQCMigrationPlanner",
    "HybridCryptoValidator",
    "QuantumTimelineSimulator",
    "CryptoAlgorithmType",
    "CryptoInventoryItem",
    "HybridCryptoValidationResult",
    "MigrationItem",
    "PQCMigrationPlan",
    "QuantumAttackSimulationResult",
    "QuantumAttackVector",
    "QuantumCryptoScanResult",
    "QuantumVulnerabilityFinding",
    "SeverityLevel",
    "TimelineMilestone",
    "Y2QTimelineResult",
]
