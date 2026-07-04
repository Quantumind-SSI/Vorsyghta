"""Quantum threat simulation models.

Pydantic models for quantum vulnerability scanning, attack simulation,
PQC migration planning, hybrid crypto validation, and Y2Q timeline modeling.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class QuantumAttackVector(str, Enum):
    """Quantum attack vector types."""
    SHORS = "shors_algorithm"
    GROVERS = "grovers_algorithm"
    NOT_VULNERABLE = "not_vulnerable"


class SeverityLevel(str, Enum):
    """Severity levels for quantum vulnerabilities."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CryptoAlgorithmType(str, Enum):
    """Cryptographic algorithm categories."""
    ENCRYPTION = "encryption"
    SIGNATURE = "signature"
    HASH = "hash"
    KEY_EXCHANGE = "key_exchange"
    SYMMETRIC = "symmetric"
    UNKNOWN = "unknown"


class CryptoInventoryItem(BaseModel):
    """A single cryptographic implementation found during scanning."""
    algorithm: str = Field(..., description="Algorithm name (RSA, ECC, AES, etc.)")
    algorithm_type: CryptoAlgorithmType = Field(..., description="Category of algorithm")
    key_size: int = Field(..., description="Key size in bits")
    location: str = Field(..., description="Where found (file path, service, endpoint)")
    protocol: Optional[str] = Field(None, description="Protocol context (TLS, SSH, IPsec)")
    certificate_fingerprint: Optional[str] = Field(None, description="Certificate fingerprint if applicable")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class QuantumVulnerabilityFinding(BaseModel):
    """Result of quantum vulnerability analysis on a single crypto item."""
    algorithm: str
    algorithm_type: CryptoAlgorithmType
    key_size: int
    location: str
    quantum_vulnerable: bool
    attack_vector: QuantumAttackVector
    severity: SeverityLevel
    y2q_risk: SeverityLevel
    recommended_replacement: Optional[str] = None
    migration_priority: int = Field(1, ge=1, le=10, description="Priority 1-10 (10 = highest)")
    confidence_score: float = Field(1.0, ge=0.0, le=1.0)
    qubits_required: Optional[int] = Field(None, description="Estimated qubits for quantum attack")
    estimated_time_years: Optional[float] = Field(None, description="Estimated time to break with quantum computer")
    classical_security_bits: Optional[int] = Field(None, description="Classical security level in bits")
    quantum_security_bits: Optional[int] = Field(None, description="Post-quantum security level in bits")


class QuantumCryptoScanResult(BaseModel):
    """Complete result of a quantum crypto scan."""
    scan_id: str
    target: str
    total_crypto_implementations: int
    quantum_vulnerable_count: int
    quantum_resistant_count: int
    findings: List[QuantumVulnerabilityFinding]
    scan_timestamp: datetime
    confidence_score: float
    summary: Dict[str, Any] = Field(default_factory=dict)


class QuantumAttackSimulationResult(BaseModel):
    """Result of simulating a quantum attack on a specific algorithm."""
    simulation_id: str
    target_algorithm: str
    attack_type: QuantumAttackVector
    qubits_required: int
    estimated_time_years: float
    success_probability: float
    current_security_level: str
    post_quantum_security_level: str
    y2q_risk_assessment: SeverityLevel
    recommendations: List[str]
    timestamp: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict)


class MigrationItem(BaseModel):
    """A single PQC migration item."""
    current_algorithm: str
    current_location: str
    recommended_replacement: str
    priority: int = Field(..., ge=1, le=10)
    complexity: str = Field(..., description="low, medium, high, critical")
    estimated_effort_months: float
    dependencies: List[str] = Field(default_factory=list)


class TimelineMilestone(BaseModel):
    """A milestone in the PQC migration timeline."""
    year: int
    milestone: str
    description: str
    completed: bool = False


class PQCMigrationPlan(BaseModel):
    """Complete PQC migration plan for an organization."""
    plan_id: str
    organization_id: str
    current_year: int
    y2q_estimate: int
    critical_vulnerabilities: int
    migration_items: List[MigrationItem]
    estimated_completion_year: int
    risk_level: SeverityLevel
    total_estimated_effort: str
    timeline: List[TimelineMilestone]
    recommendations: List[str]


class HybridCryptoValidationResult(BaseModel):
    """Result of validating a hybrid PQ/TLS deployment."""
    validation_id: str
    hybrid_valid: bool
    classical_component: str
    post_quantum_component: str
    fallback_mechanism: str
    performance_impact: float = Field(..., description="Performance overhead percentage")
    security_level: str
    test_details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime


class Y2QTimelineResult(BaseModel):
    """Y2Q readiness timeline for an organization."""
    organization_id: str
    current_year: int
    y2q_estimate: int
    critical_vulnerabilities: int
    migration_years: float
    completion_year: int
    risk_level: SeverityLevel
    recommendations: List[str]
    timeline: List[TimelineMilestone]
    timestamp: datetime
