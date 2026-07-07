"""
Zero-Day Research Module

This package contains the discovery and vulnerability research toolchain
that extends Ciicerone beyond known-vulnerability scanning into finding
*new* (zero-day) vulnerabilities.

Modules:
    - crash_pipeline: Crash collection, deduplication, triage, and reporting
    - llm_mutator: LLM-guided mutation for smart fuzz input generation
    - vuln_report: Vulnerability report generation with CVSS scoring
    - engagement: Client engagement scope manager (rules of engagement,
                  target inventories, legal framework, authorization)
    - disclosure: Vulnerability disclosure workflow (CVE coordination,
                  vendor notification, embargo tracking, public disclosure)
"""

from .crash_pipeline import CrashPipeline, CrashEntry, CrashCatalog
from .llm_mutator import LLMMutator, MutationStrategy
from .vuln_report import VulnerabilityReport, ReportGenerator
from .engagement import (
    EngagementManager, Engagement, RulesOfEngagement, LegalFramework,
    TargetEntry, TargetType, ResearchMethod, EngagementStatus, AuthorizationType,
)
from .disclosure import (
    DisclosureManager, DisclosureRecord, VendorContact, VendorResponse,
    DisclosureStatus, DisclosureTimeline,
)

__all__ = [
    # Crash pipeline
    "CrashPipeline",
    "CrashEntry",
    "CrashCatalog",
    # LLM mutator
    "LLMMutator",
    "MutationStrategy",
    # Vulnerability reporting
    "VulnerabilityReport",
    "ReportGenerator",
    # Engagement management
    "EngagementManager",
    "Engagement",
    "RulesOfEngagement",
    "LegalFramework",
    "TargetEntry",
    "TargetType",
    "ResearchMethod",
    "EngagementStatus",
    "AuthorizationType",
    # Disclosure workflow
    "DisclosureManager",
    "DisclosureRecord",
    "VendorContact",
    "VendorResponse",
    "DisclosureStatus",
    "DisclosureTimeline",
]
