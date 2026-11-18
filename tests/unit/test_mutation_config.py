"""Mutation testing configuration and helpers for Red Team tests.

This module defines mutation testing strategies and configurations
for validating test suite effectiveness.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict, Any, Callable
from enum import Enum


class MutationOperator(Enum):
    """Types of mutations to test against."""
    BOOLEAN_NEGATION = "boolean_negation"
    COMPARISON_OPERATOR_CHANGE = "comparison_operator_change"
    RETURN_VALUE_CHANGE = "return_value_change"
    CONDITION_REMOVAL = "condition_removal"
    SAFE_COMMAND_ALLOWANCE_CHANGE = "safe_command_allowance"
    DANGEROUS_COMMAND_BLOCK_CHANGE = "dangerous_command_block"
    MITRE_MAPPING_REMOVAL = "mitre_mapping_removal"
    ENGAGEMENT_CHECK_REMOVAL = "engagement_check_removal"
    SAFETY_VALIDATION_REMOVAL = "safety_validation_removal"
    AUDIT_LOGGING_REMOVAL = "audit_logging_removal"


@dataclass
class MutationTestCase:
    """Definition of a mutation test case."""
    name: str
    operator: MutationOperator
    target_module: str
    target_function: str
    mutation_description: str
    test_should_catch: bool
    severity: str  # critical, high, medium, low


# ===========================================================================
# Mutation test definitions for Red Team
# ===========================================================================

MUTATION_TEST_CASES: List[MutationTestCase] = [
    # Safety controller mutations
    MutationTestCase(
        name="safety_allows_rm_rf",
        operator=MutationOperator.SAFE_COMMAND_ALLOWANCE_CHANGE,
        target_module="vorsyghta.vm.safety",
        target_function="VMSafetyController.validate_command",
        mutation_description="Change safety to allow rm -rf / command",
        test_should_catch=True,
        severity="critical"
    ),
    
    MutationTestCase(
        name="safety_blocks_nmap",
        operator=MutationOperator.DANGEROUS_COMMAND_BLOCK_CHANGE,
        target_module="vorsyghta.vm.safety",
        target_function="VMSafetyController.validate_command",
        mutation_description="Change safety to incorrectly block nmap commands",
        test_should_catch=True,
        severity="high"
    ),
    
    MutationTestCase(
        name="safety_fork_bomb_allowed",
        operator=MutationOperator.CONDITION_REMOVAL,
        target_module="vorsyghta.vm.safety",
        target_function="VMSafetyController.validate_command",
        mutation_description="Remove fork bomb detection logic",
        test_should_catch=True,
        severity="critical"
    ),
    
    # Engagement authorization mutations
    MutationTestCase(
        name="engagement_check_bypassed",
        operator=MutationOperator.ENGAGEMENT_CHECK_REMOVAL,
        target_module="vorsyghta.core.attack_orchestrator",
        target_function="AttackOrchestrator.check_authorization",
        mutation_description="Remove engagement authorization check",
        test_should_catch=True,
        severity="critical"
    ),
    
    MutationTestCase(
        name="engagement_always_authorized",
        operator=MutationOperator.RETURN_VALUE_CHANGE,
        target_module="vorsyghta.core.attack_orchestrator",
        target_function="AttackOrchestrator.check_authorization",
        mutation_description="Change authorization to always return True",
        test_should_catch=True,
        severity="critical"
    ),
    
    # Safety validation mutations
    MutationTestCase(
        name="safety_validation_skipped",
        operator=MutationOperator.SAFETY_VALIDATION_REMOVAL,
        target_module="vorsyghta.core.attack_orchestrator",
        target_function="AttackOrchestrator.execute_step",
        mutation_description="Remove safety validation from execute_step",
        test_should_catch=True,
        severity="critical"
    ),
    
    # MITRE mapping mutations
    MutationTestCase(
        name="mitre_mapping_removed",
        operator=MutationOperator.MITRE_MAPPING_REMOVAL,
        target_module="vorsyghta.core.attack_orchestrator",
        target_function="MITRE_TO_TOOL_MAP",
        mutation_description="Remove T1046 (Network Service Scanning) mapping",
        test_should_catch=True,
        severity="high"
    ),
    
    MutationTestCase(
        name="mitre_tool_swapped",
        operator=MutationOperator.RETURN_VALUE_CHANGE,
        target_module="vorsyghta.core.attack_orchestrator",
        target_function="MITRE_TO_TOOL_MAP",
        mutation_description="Change T1046 tool from nmap to dangerous tool",
        test_should_catch=True,
        severity="high"
    ),
    
    # Audit logging mutations
    MutationTestCase(
        name="audit_logging_removed",
        operator=MutationOperator.AUDIT_LOGGING_REMOVAL,
        target_module="vorsyghta.vm.agent",
        target_function="AIAttackAgent.execute_command",
        mutation_description="Remove audit logging from command execution",
        test_should_catch=True,
        severity="medium"
    ),
    
    # Boolean logic mutations
    MutationTestCase(
        name="safety_boolean_inverted",
        operator=MutationOperator.BOOLEAN_NEGATION,
        target_module="vorsyghta.vm.safety",
        target_function="VMSafetyController.validate_command",
        mutation_description="Invert safety validation boolean return",
        test_should_catch=True,
        severity="critical"
    ),
    
    MutationTestCase(
        name="engagement_boolean_inverted",
        operator=MutationOperator.BOOLEAN_NEGATION,
        target_module="vorsyghta.core.attack_orchestrator",
        target_function="AttackOrchestrator.check_authorization",
        mutation_description="Invert authorization boolean return",
        test_should_catch=True,
        severity="critical"
    ),
    
    # Comparison operator mutations
    MutationTestCase(
        name="target_comparison_changed",
        operator=MutationOperator.COMPARISON_OPERATOR_CHANGE,
        target_module="vorsyghta.core.attack_orchestrator",
        target_function="EngagementManager.is_authorized",
        mutation_description="Change target comparison from == to !=",
        test_should_catch=True,
        severity="critical"
    ),
    
    # Command execution mutations
    MutationTestCase(
        name="command_execution_unchecked",
        operator=MutationOperator.CONDITION_REMOVAL,
        target_module="vorsyghta.vm.operator",
        target_function="VMOperator.execute_command",
        mutation_description="Remove safety check before command execution",
        test_should_catch=True,
        severity="critical"
    ),
    
    # Database mutations
    MutationTestCase(
        name="attack_plan_status_not_updated",
        operator=MutationOperator.CONDITION_REMOVAL,
        target_module="vorsyghta.db.models.red_team",
        target_function="AttackPlanRecord",
        mutation_description="Remove status field updates",
        test_should_catch=True,
        severity="medium"
    ),
]


# ===========================================================================
# Mutation test helpers
# ===========================================================================

def check_mutation_survival(
    test_name: str,
    original_behavior: Any,
    mutated_behavior: Any,
    expected_output: Any
) -> Dict[str, Any]:
    """Check if a mutation would survive (not caught by tests)."""
    
    survived = mutated_behavior == expected_output
    caught = original_behavior != mutated_behavior
    
    return {
        "test_name": test_name,
        "survived": survived,
        "caught": caught,
        "mutation_killed": caught and not survived,
        "original": original_behavior,
        "mutated": mutated_behavior,
        "expected": expected_output
    }


def calculate_mutation_score(test_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate mutation testing score."""
    
    total = len(test_results)
    killed = sum(1 for r in test_results if r["mutation_killed"])
    survived = sum(1 for r in test_results if r["survived"])
    
    score = (killed / total * 100) if total > 0 else 0
    
    return {
        "total_mutations": total,
        "killed": killed,
        "survived": survived,
        "mutation_score": round(score, 2),
        "killed_percent": round(killed / total * 100, 2) if total > 0 else 0
    }


# ===========================================================================
# Mutation test scenarios
# ===========================================================================

class MutationScenarios:
    """Pre-defined mutation scenarios for testing."""
    
    @staticmethod
    def safety_bypass_mutation():
        """Scenario: Safety validation bypassed."""
        return {
            "name": "Safety Bypass",
            "description": "Safety validation is removed from orchestrator",
            "original_implementation": """
                def execute_step(self, command):
                    ok, reason = self.safety.validate_command(command)
                    if not ok:
                        raise CommandBlockedError(reason)
                    return self.execute(command)
            """,
            "mutated_implementation": """
                def execute_step(self, command):
                    # Safety check removed!
                    return self.execute(command)
            """,
            "test_detection": "Tests should catch that dangerous commands execute without validation"
        }
    
    @staticmethod
    def engagement_bypass_mutation():
        """Scenario: Engagement check bypassed."""
        return {
            "name": "Engagement Bypass",
            "description": "Authorization check is removed",
            "original_implementation": """
                def check_authorization(self, engagement_id, target):
                    authorized, reason = self.engagement.is_authorized(engagement_id, target)
                    if not authorized:
                        raise EngagementNotAuthorizedError(reason)
                    return True
            """,
            "mutated_implementation": """
                def check_authorization(self, engagement_id, target):
                    # Authorization check removed!
                    return True
            """,
            "test_detection": "Tests should catch unauthorized targets being accessed"
        }
    
    @staticmethod
    def audit_logging_removal():
        """Scenario: Audit logging removed."""
        return {
            "name": "Audit Logging Removal",
            "description": "Audit trail is no longer created",
            "original_implementation": """
                def execute_command(self, command):
                    self.audit_log.append({"command": command, "time": now()})
                    return self.execute(command)
            """,
            "mutated_implementation": """
                def execute_command(self, command):
                    # Audit logging removed!
                    return self.execute(command)
            """,
            "test_detection": "Tests should catch missing audit entries"
        }


# ===========================================================================
# Test quality metrics
# ===========================================================================

@dataclass
class TestQualityMetrics:
    """Metrics for test suite quality."""
    
    coverage_percentage: float
    mutation_score: float
    critical_mutations_killed: int
    high_mutations_killed: int
    safety_tests_passing: int
    authorization_tests_passing: int
    audit_tests_passing: int
    
    def is_acceptable(self) -> bool:
        """Check if test quality meets minimum standards."""
        return (
            self.coverage_percentage >= 80
            and self.mutation_score >= 70
            and self.critical_mutations_killed > 0
            and self.safety_tests_passing > 0
            and self.authorization_tests_passing > 0
        )
    
    def report(self) -> Dict[str, Any]:
        """Generate quality report."""
        return {
            "coverage": self.coverage_percentage,
            "mutation_score": self.mutation_score,
            "critical_mutations_killed": self.critical_mutations_killed,
            "high_mutations_killed": self.high_mutations_killed,
            "safety_tests": self.safety_tests_passing,
            "authorization_tests": self.authorization_tests_passing,
            "audit_tests": self.audit_tests_passing,
            "acceptable": self.is_acceptable()
        }


# Export for use in tests
__all__ = [
    "MutationOperator",
    "MutationTestCase",
    "MUTATION_TEST_CASES",
    "MutationScenarios",
    "TestQualityMetrics",
    "check_mutation_survival",
    "calculate_mutation_score"
]
