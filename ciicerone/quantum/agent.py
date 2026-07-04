"""Quantum threat agent.

Orchestrates quantum cryptographic threat simulation: crypto inventory scanning,
quantum vulnerability analysis, PQC migration planning, hybrid crypto validation,
and Y2Q timeline modeling.
"""

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from .crypto_scanner import CryptoInventoryScanner
from .hybrid_validator import HybridCryptoValidator
from .models import (
    CryptoInventoryItem,
    HybridCryptoValidationResult,
    PQCMigrationPlan,
    QuantumAttackSimulationResult,
    QuantumAttackVector,
    QuantumCryptoScanResult,
    QuantumVulnerabilityFinding,
    SeverityLevel,
    Y2QTimelineResult,
)
from .pqc_migration_planner import PQCMigrationPlanner
from .timeline_simulator import QuantumTimelineSimulator
from .vulnerability_analyzer import QuantumVulnerabilityAnalyzer

logger = logging.getLogger(__name__)


class QuantumThreatAgent:
    """Specialized AI agent for quantum cryptographic threat simulation.

    Coordinates:
    - CryptoInventoryScanner: detect crypto implementations in targets
    - QuantumVulnerabilityAnalyzer: assess quantum vulnerability (Shor's/Grover's)
    - PQCMigrationPlanner: generate NIST-standard PQC migration plans
    - HybridCryptoValidator: validate hybrid PQ/TLS deployments
    - QuantumTimelineSimulator: model Y2Q readiness timeline
    """

    def __init__(
        self,
        llm_manager: Any = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.llm = llm_manager
        self.config = config or {}

        self.crypto_scanner = CryptoInventoryScanner(self.config.get("scanner", {}))
        self.quantum_analyzer = QuantumVulnerabilityAnalyzer(self.config.get("analyzer", {}))
        self.pqc_planner = PQCMigrationPlanner(self.config.get("planner", {}))
        self.hybrid_validator = HybridCryptoValidator(self.config.get("validator", {}))
        self.timeline_simulator = QuantumTimelineSimulator(self.config.get("timeline", {}))

    async def scan_crypto_inventory(
        self,
        target: str,
        vm_operator: Any = None,
    ) -> QuantumCryptoScanResult:
        """Scan a target for quantum-vulnerable cryptographic implementations.

        Args:
            target: Target URL, IP, hostname, or VM ID
            vm_operator: Optional VMOperator for VM scanning

        Returns:
            QuantumCryptoScanResult with all findings
        """
        logger.info(f"QuantumThreatAgent: scanning crypto inventory for {target}")

        inventory = await self.crypto_scanner.scan(target, vm_operator)

        findings: List[QuantumVulnerabilityFinding] = []
        for item in inventory:
            finding = await self.quantum_analyzer.analyze(item)
            findings.append(finding)

        vulnerable = [f for f in findings if f.quantum_vulnerable]
        resistant = [f for f in findings if not f.quantum_vulnerable]

        summary = self._build_scan_summary(findings)

        result = QuantumCryptoScanResult(
            scan_id=str(uuid.uuid4()),
            target=target,
            total_crypto_implementations=len(findings),
            quantum_vulnerable_count=len(vulnerable),
            quantum_resistant_count=len(resistant),
            findings=findings,
            scan_timestamp=datetime.utcnow(),
            confidence_score=self._calculate_confidence(findings),
            summary=summary,
        )

        logger.info(
            f"Scan complete: {len(findings)} total, {len(vulnerable)} vulnerable, "
            f"{len(resistant)} resistant"
        )
        return result

    async def simulate_quantum_attack(
        self,
        algorithm: str,
        key_size: int,
        algorithm_type: str = "unknown",
    ) -> QuantumAttackSimulationResult:
        """Simulate a quantum attack on a specific cryptographic algorithm.

        Args:
            algorithm: Algorithm name (RSA, ECC, AES, etc.)
            key_size: Key size in bits
            algorithm_type: Algorithm type (encryption, signature, etc.)

        Returns:
            QuantumAttackSimulationResult with attack simulation details
        """
        logger.info(f"QuantumThreatAgent: simulating quantum attack on {algorithm}-{key_size}")

        from .models import CryptoAlgorithmType
        try:
            algo_type = CryptoAlgorithmType(algorithm_type)
        except ValueError:
            algo_type = CryptoAlgorithmType.UNKNOWN

        item = CryptoInventoryItem(
            algorithm=algorithm,
            algorithm_type=algo_type,
            key_size=key_size,
            location="simulated",
        )

        finding = await self.quantum_analyzer.analyze(item)

        current_security = f"{key_size}-bit classical"
        if finding.quantum_security_bits is not None and finding.quantum_security_bits > 0:
            pq_security = f"{finding.quantum_security_bits}-bit post-quantum"
        else:
            pq_security = "0-bit (fully broken)"

        recommendations = self._attack_recommendations(finding)

        result = QuantumAttackSimulationResult(
            simulation_id=str(uuid.uuid4()),
            target_algorithm=algorithm,
            attack_type=finding.attack_vector,
            qubits_required=finding.qubits_required or 0,
            estimated_time_years=finding.estimated_time_years or 0.0,
            success_probability=0.99 if finding.attack_vector == QuantumAttackVector.SHORS else 0.95,
            current_security_level=current_security,
            post_quantum_security_level=pq_security,
            y2q_risk_assessment=finding.y2q_risk,
            recommendations=recommendations,
            timestamp=datetime.utcnow(),
            metadata={
                "key_size": key_size,
                "algorithm_type": algorithm_type,
                "severity": finding.severity.value,
            },
        )

        logger.info(
            f"Attack simulation: {algorithm}-{key_size} via {finding.attack_vector.value}, "
            f"qubits={finding.qubits_required}, time={finding.estimated_time_years}y"
        )
        return result

    async def plan_pqc_migration(
        self,
        findings: List[QuantumVulnerabilityFinding],
        organization_id: str = "default",
    ) -> PQCMigrationPlan:
        """Generate a PQC migration plan from vulnerability findings.

        Args:
            findings: List of quantum vulnerability findings
            organization_id: Organization identifier

        Returns:
            PQCMigrationPlan with migration items and timeline
        """
        return await self.pqc_planner.generate_plan(findings, organization_id)

    async def validate_hybrid_deployment(
        self,
        config: Dict[str, Any],
    ) -> HybridCryptoValidationResult:
        """Validate a hybrid PQ/TLS deployment.

        Args:
            config: Hybrid deployment configuration

        Returns:
            HybridCryptoValidationResult with validation details
        """
        return await self.hybrid_validator.validate(config)

    async def simulate_y2q_timeline(
        self,
        findings: List[QuantumVulnerabilityFinding],
        organization_id: str = "default",
        migration_plan: Optional[PQCMigrationPlan] = None,
    ) -> Y2QTimelineResult:
        """Simulate Y2Q readiness timeline for an organization.

        Args:
            findings: Quantum vulnerability findings
            organization_id: Organization identifier
            migration_plan: Optional pre-generated migration plan

        Returns:
            Y2QTimelineResult with timeline and recommendations
        """
        return await self.timeline_simulator.simulate(
            findings, organization_id, migration_plan
        )

    async def full_assessment(
        self,
        target: str,
        vm_operator: Any = None,
        organization_id: str = "default",
    ) -> Dict[str, Any]:
        """Run a full quantum threat assessment on a target.

        Combines crypto scan, vulnerability analysis, migration planning,
        and Y2Q timeline simulation into a single comprehensive report.

        Args:
            target: Target to assess
            vm_operator: Optional VMOperator for VM scanning
            organization_id: Organization identifier

        Returns:
            Dictionary containing all assessment results
        """
        logger.info(f"QuantumThreatAgent: full assessment for {target}")

        scan_result = await self.scan_crypto_inventory(target, vm_operator)
        migration_plan = await self.plan_pqc_migration(scan_result.findings, organization_id)
        y2q_timeline = await self.simulate_y2q_timeline(
            scan_result.findings, organization_id, migration_plan
        )

        return {
            "scan_result": scan_result,
            "migration_plan": migration_plan,
            "y2q_timeline": y2q_timeline,
            "executive_summary": self._executive_summary(
                scan_result, migration_plan, y2q_timeline
            ),
        }

    def _build_scan_summary(self, findings: List[QuantumVulnerabilityFinding]) -> Dict[str, Any]:
        """Build a summary of scan findings."""
        vulnerable = [f for f in findings if f.quantum_vulnerable]
        shors = [f for f in vulnerable if f.attack_vector == QuantumAttackVector.SHORS]
        grovers = [f for f in vulnerable if f.attack_vector == QuantumAttackVector.GROVERS]
        critical = [f for f in vulnerable if f.severity == SeverityLevel.CRITICAL]

        algorithms = {}
        for f in findings:
            if f.algorithm not in algorithms:
                algorithms[f.algorithm] = {"count": 0, "vulnerable": 0}
            algorithms[f.algorithm]["count"] += 1
            if f.quantum_vulnerable:
                algorithms[f.algorithm]["vulnerable"] += 1

        return {
            "total_implementations": len(findings),
            "vulnerable": len(vulnerable),
            "resistant": len(findings) - len(vulnerable),
            "shors_vulnerable": len(shors),
            "grovers_affected": len(grovers),
            "critical_count": len(critical),
            "algorithms_detected": algorithms,
        }

    def _calculate_confidence(self, findings: List[QuantumVulnerabilityFinding]) -> float:
        """Calculate overall confidence score for the scan."""
        if not findings:
            return 0.0
        return sum(f.confidence_score for f in findings) / len(findings)

    def _attack_recommendations(self, finding: QuantumVulnerabilityFinding) -> List[str]:
        """Generate recommendations for a quantum attack simulation."""
        recs: List[str] = []

        if finding.attack_vector == QuantumAttackVector.SHORS:
            recs.append(
                f"{finding.algorithm} with {finding.key_size}-bit keys is fully breakable "
                f"by Shor's algorithm on a sufficiently large quantum computer."
            )
            if finding.recommended_replacement:
                recs.append(f"Migrate to {finding.recommended_replacement} immediately.")
            recs.append(
                "This is a deterministic attack — once a CRQC exists, all RSA/ECC/DSA/DH "
                "keys of this size are breakable in polynomial time."
            )
        elif finding.attack_vector == QuantumAttackVector.GROVERS:
            quantum_bits = finding.quantum_security_bits or 0
            recs.append(
                f"{finding.algorithm} with {finding.key_size}-bit keys has reduced security "
                f"to {quantum_bits}-bit under Grover's algorithm."
            )
            recs.append(
                f"Doubling the key size to {finding.key_size * 2} bits restores "
                f"{finding.key_size}-bit post-quantum security."
            )
        else:
            recs.append("This algorithm appears to be post-quantum safe.")

        if finding.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH):
            recs.append("Prioritize migration of this implementation in the PQC migration plan.")

        return recs

    def _executive_summary(
        self,
        scan: QuantumCryptoScanResult,
        plan: PQCMigrationPlan,
        timeline: Y2QTimelineResult,
    ) -> str:
        """Generate an executive summary of the full assessment."""
        return (
            f"Quantum threat assessment identified {scan.quantum_vulnerable_count} "
            f"quantum-vulnerable cryptographic implementations out of "
            f"{scan.total_crypto_implementations} total. "
            f"{scan.summary.get('critical_count', 0)} are critical severity. "
            f"PQC migration is estimated to complete by {plan.estimated_completion_year} "
            f"with {plan.total_estimated_effort} of effort. "
            f"Y2Q risk level: {timeline.risk_level.value}. "
            f"Conservative Y2Q estimate: {timeline.y2q_estimate}."
        )
