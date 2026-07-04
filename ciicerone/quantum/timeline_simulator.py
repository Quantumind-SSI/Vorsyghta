"""Quantum timeline simulator (Y2Q readiness).

Models the Y2Q (Year to Quantum) readiness timeline for organizations.
Estimates when a quantum computer capable of breaking current cryptography
will be available, and whether the organization can complete PQC migration
before that deadline.
"""

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from .models import (
    PQCMigrationPlan,
    QuantumVulnerabilityFinding,
    SeverityLevel,
    TimelineMilestone,
    Y2QTimelineResult,
)

logger = logging.getLogger(__name__)


class QuantumTimelineSimulator:
    """Simulates Y2Q readiness timeline for organizations.

    Models:
    - Current quantum computing progress (qubit counts, error correction)
    - Projected timeline for cryptographically relevant quantum computer (CRQC)
    - Organization's PQC migration timeline
    - Gap analysis between migration completion and Y2Q deadline
    - Risk assessment and recommendations
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.current_year = self.config.get("current_year", 2026)
        self.y2q_estimate = self.config.get("y2q_estimate", 2030)
        self.conservative_y2q = self.config.get("conservative_y2q", 2035)
        self.optimistic_y2q = self.config.get("optimistic_y2q", 2028)
        self.migrations_per_year = self.config.get("migrations_per_year", 10)

    async def simulate(
        self,
        findings: List[QuantumVulnerabilityFinding],
        organization_id: str = "default",
        migration_plan: Optional[PQCMigrationPlan] = None,
    ) -> Y2QTimelineResult:
        """Simulate Y2Q readiness timeline.

        Args:
            findings: Quantum vulnerability findings for the organization
            organization_id: Organization identifier
            migration_plan: Optional pre-generated migration plan

        Returns:
            Y2QTimelineResult with timeline, risk level, and recommendations
        """
        logger.info(f"Simulating Y2Q timeline for organization: {organization_id}")

        vulnerable = [f for f in findings if f.quantum_vulnerable]
        critical = [f for f in vulnerable if f.severity == SeverityLevel.CRITICAL]
        high = [f for f in vulnerable if f.severity == SeverityLevel.HIGH]

        if migration_plan:
            completion_year = migration_plan.estimated_completion_year
            migration_years = completion_year - self.current_year
        else:
            migration_years = max(1.0, len(vulnerable) / self.migrations_per_year)
            completion_year = self.current_year + int(migration_years)

        risk_level = self._assess_risk(completion_year, len(critical))

        timeline = self._build_timeline(
            critical_count=len(critical),
            high_count=len(high),
            total_vulnerable=len(vulnerable),
            completion_year=completion_year,
        )

        recommendations = self._generate_recommendations(
            critical_count=len(critical),
            high_count=len(high),
            completion_year=completion_year,
            risk_level=risk_level,
        )

        result = Y2QTimelineResult(
            organization_id=organization_id,
            current_year=self.current_year,
            y2q_estimate=self.y2q_estimate,
            critical_vulnerabilities=len(critical),
            migration_years=migration_years,
            completion_year=completion_year,
            risk_level=risk_level,
            recommendations=recommendations,
            timeline=timeline,
            timestamp=datetime.utcnow(),
        )

        logger.info(
            f"Y2Q simulation complete: completion={completion_year}, "
            f"y2q={self.y2q_estimate}, risk={risk_level.value}"
        )
        return result

    def _assess_risk(self, completion_year: int, critical_count: int) -> SeverityLevel:
        """Assess overall Y2Q risk level."""
        if completion_year > self.y2q_estimate and critical_count > 0:
            return SeverityLevel.CRITICAL
        elif completion_year > self.y2q_estimate:
            return SeverityLevel.HIGH
        elif completion_year == self.y2q_estimate:
            return SeverityLevel.HIGH
        elif completion_year > self.optimistic_y2q:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW

    def _build_timeline(
        self,
        critical_count: int,
        high_count: int,
        total_vulnerable: int,
        completion_year: int,
    ) -> List[TimelineMilestone]:
        """Build the Y2Q readiness timeline."""
        timeline: List[TimelineMilestone] = []

        timeline.append(TimelineMilestone(
            year=self.current_year,
            milestone="Assessment Complete",
            description=(
                f"Quantum vulnerability assessment complete. "
                f"{total_vulnerable} vulnerable implementations found "
                f"({critical_count} critical, {high_count} high)."
            ),
            completed=True,
        ))

        timeline.append(TimelineMilestone(
            year=self.current_year,
            milestone="PQC Strategy Defined",
            description="Define PQC migration strategy and select NIST-approved algorithms.",
        ))

        timeline.append(TimelineMilestone(
            year=self.current_year + 1,
            milestone="Pilot Hybrid Deployment",
            description="Deploy hybrid PQ/TLS on pilot services using Kyber+X25519.",
        ))

        if critical_count > 0:
            timeline.append(TimelineMilestone(
                year=self.current_year + 2,
                milestone="Critical Vulnerabilities Addressed",
                description=f"Migrate {critical_count} critical quantum-vulnerable algorithms to PQC.",
            ))

        timeline.append(TimelineMilestone(
            year=self.optimistic_y2q,
            milestone="Optimistic Y2Q",
            description=(
                "Optimistic estimate for cryptographically relevant quantum computer. "
                "Organizations should have critical migrations complete by this date."
            ),
        ))

        timeline.append(TimelineMilestone(
            year=self.y2q_estimate,
            milestone="Conservative Y2Q Deadline",
            description=(
                "Conservative estimate for CRQC availability. "
                "All quantum-vulnerable cryptography should be migrated by this date."
            ),
        ))

        timeline.append(TimelineMilestone(
            year=completion_year,
            milestone="Migration Complete",
            description="Full PQC migration completed for all quantum-vulnerable implementations.",
        ))

        if completion_year > self.conservative_y2q:
            timeline.append(TimelineMilestone(
                year=self.conservative_y2q,
                milestone="Worst-Case Y2Q",
                description=(
                    "Worst-case CRQC estimate. Organization is at severe risk "
                    "if migration is not complete by this date."
                ),
            ))

        return timeline

    def _generate_recommendations(
        self,
        critical_count: int,
        high_count: int,
        completion_year: int,
        risk_level: SeverityLevel,
    ) -> List[str]:
        """Generate Y2Q readiness recommendations."""
        recs: List[str] = []

        recs.append(
            f"Current Y2Q estimate: {self.y2q_estimate} (conservative: {self.conservative_y2q}, "
            f"optimistic: {self.optimistic_y2q})."
        )

        recs.append(
            f"Estimated migration completion: {completion_year}. "
            f"Gap: {completion_year - self.y2q_estimate} years from conservative Y2Q."
        )

        if risk_level == SeverityLevel.CRITICAL:
            recs.append(
                "CRITICAL RISK: Migration will not complete before Y2Q. "
                "Immediately increase migration team size and prioritize critical algorithms. "
                "Consider interim measures: hybrid crypto for all external TLS endpoints."
            )
        elif risk_level == SeverityLevel.HIGH:
            recs.append(
                "HIGH RISK: Migration timeline is tight. "
                "Accelerate PQC adoption and implement hybrid crypto as an interim measure."
            )
        elif risk_level == SeverityLevel.MEDIUM:
            recs.append(
                "MEDIUM RISK: Migration timeline is feasible but monitor quantum computing progress closely. "
                "Begin hybrid crypto deployment now."
            )
        else:
            recs.append(
                "LOW RISK: Migration timeline is comfortable. "
                "Continue planned PQC adoption and maintain crypto inventory monitoring."
            )

        if critical_count > 0:
            recs.append(
                f"Address {critical_count} critical vulnerabilities first. "
                f"These are breakable by Shor's algorithm once a CRQC exists."
            )

        recs.append(
            "Implement 'harvest now, decrypt later' defense: ensure all long-lived "
            "data uses hybrid encryption to protect against retroactive quantum decryption."
        )

        recs.append(
            "Monitor NIST PQC standardization: CRYSTALS-Kyber (FIPS 203), "
            "CRYSTALS-Dilithium (FIPS 204), Falcon (FIPS 206), SPHINCS+ (FIPS 205)."
        )

        recs.append(
            "Establish a quantum readiness task force with quarterly reviews "
            "of quantum computing progress and migration status."
        )

        return recs
