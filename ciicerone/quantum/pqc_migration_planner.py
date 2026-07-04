"""PQC migration planner.

Generates post-quantum cryptography migration plans based on NIST standards.
Maps vulnerable algorithms to NIST-approved PQC replacements and estimates
migration effort, complexity, and timeline.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional

from .models import (
    CryptoAlgorithmType,
    MigrationItem,
    PQCMigrationPlan,
    QuantumVulnerabilityFinding,
    SeverityLevel,
    TimelineMilestone,
)

logger = logging.getLogger(__name__)


# NIST PQC standard replacements
NIST_PQC_STANDARDS: Dict[CryptoAlgorithmType, Dict[str, str]] = {
    CryptoAlgorithmType.ENCRYPTION: {
        "primary": "CRYSTALS-Kyber (FIPS 203)",
        "alternate": "Classic McEliece",
        "hybrid": "Kyber + X25519 (hybrid key exchange)",
    },
    CryptoAlgorithmType.KEY_EXCHANGE: {
        "primary": "CRYSTALS-Kyber (FIPS 203)",
        "alternate": "Classic McEliece",
        "hybrid": "Kyber + X25519 (hybrid key exchange)",
    },
    CryptoAlgorithmType.SIGNATURE: {
        "primary": "CRYSTALS-Dilithium (FIPS 204)",
        "alternate": "Falcon (FIPS 206)",
        "fallback": "SPHINCS+ (FIPS 205)",
        "hybrid": "Dilithium + Ed25519 (hybrid signature)",
    },
    CryptoAlgorithmType.HASH: {
        "primary": "SHA-384 or SHA-512 (doubled security)",
        "alternate": "SHAKE-256",
    },
    CryptoAlgorithmType.SYMMETRIC: {
        "primary": "AES-256 (doubled key size)",
        "alternate": "ChaCha20-Poly1305 with 256-bit keys",
    },
}

# Complexity estimation based on algorithm type and deployment context
COMPLEXITY_MAP: Dict[CryptoAlgorithmType, str] = {
    CryptoAlgorithmType.ENCRYPTION: "high",
    CryptoAlgorithmType.KEY_EXCHANGE: "high",
    CryptoAlgorithmType.SIGNATURE: "medium",
    CryptoAlgorithmType.HASH: "low",
    CryptoAlgorithmType.SYMMETRIC: "medium",
}

# Effort estimates in person-months (base values)
EFFORT_BASE: Dict[CryptoAlgorithmType, float] = {
    CryptoAlgorithmType.ENCRYPTION: 6.0,
    CryptoAlgorithmType.KEY_EXCHANGE: 8.0,
    CryptoAlgorithmType.SIGNATURE: 4.0,
    CryptoAlgorithmType.HASH: 2.0,
    CryptoAlgorithmType.SYMMETRIC: 3.0,
}


class PQCMigrationPlanner:
    """Generates PQC migration plans based on NIST standards.

    Takes a list of quantum vulnerability findings and produces a structured
    migration plan with:
    - NIST-approved PQC replacements for each vulnerable algorithm
    - Migration complexity and effort estimates
    - Prioritized timeline with milestones
    - Risk assessment and recommendations
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.current_year = self.config.get("current_year", 2026)
        self.y2q_estimate = self.config.get("y2q_estimate", 2030)
        self.migrations_per_year = self.config.get("migrations_per_year", 10)

    async def generate_plan(
        self,
        findings: List[QuantumVulnerabilityFinding],
        organization_id: str = "default",
    ) -> PQCMigrationPlan:
        """Generate a complete PQC migration plan.

        Args:
            findings: List of quantum vulnerability findings
            organization_id: Organization identifier

        Returns:
            PQCMigrationPlan with migration items, timeline, and recommendations
        """
        logger.info(f"Generating PQC migration plan for {len(findings)} findings")

        migration_items: List[MigrationItem] = []
        vulnerable_findings = [f for f in findings if f.quantum_vulnerable]

        for finding in vulnerable_findings:
            item = self._create_migration_item(finding)
            migration_items.append(item)

        migration_items.sort(key=lambda x: x.priority, reverse=True)

        critical_count = sum(1 for f in vulnerable_findings if f.severity == SeverityLevel.CRITICAL)
        total_effort = sum(item.estimated_effort_months for item in migration_items)
        migration_years = max(1.0, len(vulnerable_findings) / self.migrations_per_year)
        completion_year = self.current_year + int(migration_years)

        risk_level = SeverityLevel.CRITICAL if completion_year > self.y2q_estimate else SeverityLevel.HIGH

        timeline = self._build_timeline(migration_items, completion_year)
        recommendations = self._generate_recommendations(vulnerable_findings, completion_year)

        plan = PQCMigrationPlan(
            plan_id=str(uuid.uuid4()),
            organization_id=organization_id,
            current_year=self.current_year,
            y2q_estimate=self.y2q_estimate,
            critical_vulnerabilities=critical_count,
            migration_items=migration_items,
            estimated_completion_year=completion_year,
            risk_level=risk_level,
            total_estimated_effort=f"{total_effort:.1f} person-months",
            timeline=timeline,
            recommendations=recommendations,
        )

        logger.info(f"Migration plan generated: {len(migration_items)} items, completion by {completion_year}")
        return plan

    def _create_migration_item(self, finding: QuantumVulnerabilityFinding) -> MigrationItem:
        """Create a migration item from a vulnerability finding."""
        replacement = self._get_replacement(finding.algorithm_type, finding.recommended_replacement)
        complexity = self._estimate_complexity(finding)
        effort = self._estimate_effort(finding)
        dependencies = self._get_dependencies(finding)

        return MigrationItem(
            current_algorithm=finding.algorithm,
            current_location=finding.location,
            recommended_replacement=replacement,
            priority=finding.migration_priority,
            complexity=complexity,
            estimated_effort_months=effort,
            dependencies=dependencies,
        )

    def _get_replacement(self, algo_type: CryptoAlgorithmType, suggested: Optional[str]) -> str:
        """Get the NIST PQC replacement for an algorithm type."""
        standards = NIST_PQC_STANDARDS.get(algo_type)
        if standards:
            return standards.get("primary", suggested or "Unknown")
        return suggested or "Consult NIST PQC standards"

    def _estimate_complexity(self, finding: QuantumVulnerabilityFinding) -> str:
        """Estimate migration complexity."""
        base = COMPLEXITY_MAP.get(finding.algorithm_type, "medium")

        if finding.severity == SeverityLevel.CRITICAL:
            if base == "low":
                return "medium"
            elif base == "medium":
                return "high"
            else:
                return "critical"
        elif finding.severity == SeverityLevel.HIGH:
            return base

        return base

    def _estimate_effort(self, finding: QuantumVulnerabilityFinding) -> float:
        """Estimate migration effort in person-months."""
        base = EFFORT_BASE.get(finding.algorithm_type, 4.0)

        multiplier = 1.0
        if finding.severity == SeverityLevel.CRITICAL:
            multiplier = 1.5
        elif finding.severity == SeverityLevel.HIGH:
            multiplier = 1.2
        elif finding.severity == SeverityLevel.MEDIUM:
            multiplier = 0.8

        return round(base * multiplier, 1)

    def _get_dependencies(self, finding: QuantumVulnerabilityFinding) -> List[str]:
        """Get migration dependencies."""
        deps: List[str] = []

        if finding.algorithm_type in (CryptoAlgorithmType.ENCRYPTION, CryptoAlgorithmType.KEY_EXCHANGE):
            deps.append("TLS library PQC support (OQS-OpenSSL or oqs-provider)")
            deps.append("Certificate authority PQC support")
        elif finding.algorithm_type == CryptoAlgorithmType.SIGNATURE:
            deps.append("PQC signature library (liboqs)")
            deps.append("Certificate authority PQC support")

        if finding.protocol:
            deps.append(f"{finding.protocol} protocol PQC negotiation support")

        return deps

    def _build_timeline(self, items: List[MigrationItem], completion_year: int) -> List[TimelineMilestone]:
        """Build a migration timeline with milestones."""
        timeline: List[TimelineMilestone] = []

        timeline.append(TimelineMilestone(
            year=self.current_year,
            milestone="Crypto Inventory Complete",
            description="Full cryptographic inventory and quantum vulnerability assessment completed.",
            completed=True,
        ))

        timeline.append(TimelineMilestone(
            year=self.current_year,
            milestone="PQC Pilot Deployment",
            description="Deploy PQC pilot using hybrid Kyber+X25519 for key exchange in non-production.",
        ))

        critical_items = [i for i in items if i.priority >= 9]
        if critical_items:
            timeline.append(TimelineMilestone(
                year=self.current_year + 1,
                milestone="Critical Algorithms Migrated",
                description=f"Migrate {len(critical_items)} critical quantum-vulnerable algorithms to PQC.",
            ))

        timeline.append(TimelineMilestone(
            year=self.current_year + 2,
            milestone="Hybrid Deployment",
            description="Deploy hybrid PQ/TLS across all external-facing services.",
        ))

        high_items = [i for i in items if 7 <= i.priority < 9]
        if high_items:
            timeline.append(TimelineMilestone(
                year=completion_year - 1,
                milestone="High Priority Migration",
                description=f"Migrate {len(high_items)} high-priority algorithms to PQC.",
            ))

        timeline.append(TimelineMilestone(
            year=completion_year,
            milestone="Full PQC Migration",
            description="All quantum-vulnerable cryptographic implementations migrated to PQC.",
        ))

        return timeline

    def _generate_recommendations(
        self, findings: List[QuantumVulnerabilityFinding], completion_year: int
    ) -> List[str]:
        """Generate migration recommendations."""
        recs: List[str] = []

        critical = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
        high = [f for f in findings if f.severity == SeverityLevel.HIGH]

        if critical:
            recs.append(
                f"URGENT: {len(critical)} critical quantum-vulnerable algorithms detected. "
                f"Begin migration immediately to meet Y2Q deadline ({self.y2q_estimate})."
            )

        if completion_year > self.y2q_estimate:
            recs.append(
                f"WARNING: Estimated migration completion ({completion_year}) exceeds Y2Q estimate "
                f"({self.y2q_estimate}). Increase migration team size or prioritize critical items."
            )

        has_tls = any(f.protocol == "TLS" for f in findings)
        if has_tls:
            recs.append(
                "Deploy OQS-OpenSSL or oqs-provider for hybrid PQ/TLS key exchange "
                "to protect TLS traffic with forward secrecy against quantum attacks."
            )

        has_ssh = any(f.protocol == "SSH" for f in findings)
        if has_ssh:
            recs.append(
                "Upgrade SSH to support PQC key exchange algorithms. "
                "OpenSSH 9.0+ includes experimental PQC support."
            )

        has_rsa = any(f.algorithm == "RSA" for f in findings)
        if has_rsa:
            recs.append(
                "Replace RSA with CRYSTALS-Dilithium (FIPS 204) for signatures and "
                "CRYSTALS-Kyber (FIPS 203) for key encapsulation."
            )

        has_ecc = any(f.algorithm in ("ECC", "ECDSA", "ECDH") for f in findings)
        if has_ecc:
            recs.append(
                "Replace ECC/ECDSA/ECDH with CRYSTALS-Kyber for key exchange and "
                "CRYSTALS-Dilithium for signatures. Consider hybrid mode during transition."
            )

        recs.append(
            "Implement a cryptographic agility framework to enable rapid algorithm "
            "switching without code changes. Use a centralized crypto policy engine."
        )

        recs.append(
            "Establish a crypto inventory monitoring pipeline to detect new "
            "quantum-vulnerable implementations as they are deployed."
        )

        if high:
            recs.append(
                f"Schedule migration of {len(high)} high-priority algorithms within 2 years."
            )

        return recs
