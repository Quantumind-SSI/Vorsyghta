"""
Vulnerability Report Generator

Turns triaged crashes and SAST findings into structured vulnerability
reports suitable for client delivery, CVE coordination, and responsible
disclosure.

Usage:
    from ciicerone.research.vuln_report import ReportGenerator
    from ciicerone.research.crash_pipeline import CrashCatalog

    generator = ReportGenerator()
    report = generator.generate_from_catalog(catalog)
    print(report.to_markdown())
"""

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityFinding:
    """A single vulnerability finding for a report."""
    title: str = ""
    cwe_id: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    severity: str = "medium"           # critical, high, medium, low, info
    description: str = ""
    affected_component: str = ""
    attack_vector: str = ""            # network, local, adjacent
    attack_complexity: str = "low"     # low, high
    privileges_required: str = "none"  # none, low, high
    user_interaction: str = "none"     # none, required
    scope: str = "unchanged"           # unchanged, changed
    confidentiality_impact: str = "none"    # none, low, high
    integrity_impact: str = "none"          # none, low, high
    availability_impact: str = "none"       # none, low, high
    proof_of_concept: str = ""
    reproduction_steps: List[str] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    status: str = "new"                # new, confirmed, reported, fixed
    discovery_method: str = ""         # fuzzing, sast, manual, binary_analysis

    def to_dict(self) -> dict:
        return asdict(self)

    def to_markdown(self) -> str:
        """Render finding as markdown."""
        md = f"""## {self.title}

| Field | Value |
|-------|-------|
| CWE | {self.cwe_id} |
| CVSS | {self.cvss_score} ({self.severity}) |
| Attack Vector | {self.attack_vector} |
| Attack Complexity | {self.attack_complexity} |
| Privileges Required | {self.privileges_required} |
| User Interaction | {self.user_interaction} |
| Scope | {self.scope} |
| Confidentiality Impact | {self.confidentiality_impact} |
| Integrity Impact | {self.integrity_impact} |
| Availability Impact | {self.availability_impact} |
| Status | {self.status} |
| Discovered | {self.discovered_at} |
| Method | {self.discovery_method} |

### Description

{self.description}

### Affected Component

{self.affected_component}

### Proof of Concept

```
{self.proof_of_concept}
```

### Reproduction Steps

"""
        for i, step in enumerate(self.reproduction_steps, 1):
            md += f"{i}. {step}\n"

        md += f"""
### Remediation

{self.remediation}

### References

"""
        for ref in self.references:
            md += f"- {ref}\n"

        return md


@dataclass
class VulnerabilityReport:
    """A complete vulnerability report for client delivery."""
    title: str = ""
    client: str = ""
    engagement_id: str = ""
    scope: str = ""
    assessment_period: str = ""
    executive_summary: str = ""
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    methodology: str = ""
    tools_used: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    prepared_by: str = ""

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "client": self.client,
            "engagement_id": self.engagement_id,
            "scope": self.scope,
            "assessment_period": self.assessment_period,
            "executive_summary": self.executive_summary,
            "findings": [f.to_dict() for f in self.findings],
            "methodology": self.methodology,
            "tools_used": self.tools_used,
            "created_at": self.created_at,
            "prepared_by": self.prepared_by,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        """Render full report as markdown."""
        # Count findings by severity
        severity_counts = {}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        md = f"""# {self.title}

| Field | Value |
|-------|-------|
| Client | {self.client} |
| Engagement ID | {self.engagement_id} |
| Scope | {self.scope} |
| Assessment Period | {self.assessment_period} |
| Prepared By | {self.prepared_by} |
| Date | {self.created_at} |

## Executive Summary

{self.executive_summary}

### Findings Summary

| Severity | Count |
|----------|-------|
| Critical | {severity_counts.get('critical', 0)} |
| High | {severity_counts.get('high', 0)} |
| Medium | {severity_counts.get('medium', 0)} |
| Low | {severity_counts.get('low', 0)} |
| Info | {severity_counts.get('info', 0)} |
| **Total** | **{len(self.findings)}** |

## Methodology

{self.methodology}

### Tools Used

"""
        for tool in self.tools_used:
            md += f"- {tool}\n"

        md += "\n## Findings\n\n"
        for i, finding in enumerate(self.findings, 1):
            md += finding.to_markdown()
            md += "\n---\n\n"

        return md

    def save(self, path: str, format: str = "markdown"):
        """Save report to file."""
        if format == "json":
            with open(path, "w") as f:
                f.write(self.to_json())
        else:
            with open(path, "w") as f:
                f.write(self.to_markdown())
        logger.info(f"Report saved to {path}")


class ReportGenerator:
    """Generates vulnerability reports from crash catalogs and SAST findings."""

    def __init__(self, llm_manager=None):
        """
        Args:
            llm_manager: Optional LLM for generating descriptions and remediation
        """
        self.llm = llm_manager

    def generate_from_catalog(
        self,
        catalog,
        client: str = "",
        engagement_id: str = "",
        target_description: str = "",
    ) -> VulnerabilityReport:
        """Generate a vulnerability report from a CrashCatalog.

        Args:
            catalog: CrashCatalog from the crash pipeline
            client: Client name
            engagement_id: Engagement identifier
            target_description: Description of the target

        Returns:
            VulnerabilityReport
        """
        findings = []

        for crash in catalog.crashes:
            if crash.status.value in ["rejected", "duplicate"]:
                continue

            severity = self._cvss_to_severity(crash.cvss_score or 0)

            finding = VulnerabilityFinding(
                title=f"{crash.crash_type.value.title()} in {crash.target_binary}",
                cwe_id=crash.cwe_id or "CWE-119",
                cvss_score=crash.cvss_score or 5.0,
                severity=severity,
                description=self._generate_description(crash),
                affected_component=crash.target_binary,
                attack_vector="network" if crash.fuzzer == "network" else "local",
                proof_of_concept=self._generate_poc(crash),
                reproduction_steps=self._generate_repro_steps(crash),
                remediation=self._generate_remediation(crash),
                references=self._generate_references(crash),
                discovered_at=crash.discovered_at,
                status=crash.status.value,
                discovery_method=f"fuzzing ({crash.fuzzer})" if crash.fuzzer else "fuzzing",
            )
            findings.append(finding)

        # Sort by severity (critical first)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: severity_order.get(f.severity, 5))

        report = VulnerabilityReport(
            title=f"Vulnerability Assessment Report — {target_description or catalog.target_binary}",
            client=client,
            engagement_id=engagement_id,
            scope=target_description or catalog.target_binary,
            executive_summary=self._generate_exec_summary(findings, catalog),
            findings=findings,
            methodology=(
                "Vulnerabilities were discovered using automated fuzzing campaigns "
                "on isolated attacker VMs within the Ciicerone platform. Crashes were "
                "collected, deduplicated by stack trace signature, and triaged under "
                "GDB to determine root cause and exploitability. CVSS scores are "
                "preliminary estimates based on crash classification."
            ),
            tools_used=["AFL++", "libFuzzer", "GDB", "radare2"],
        )

        return report

    def generate_from_sast(
        self,
        sast_results: List[dict],
        client: str = "",
        engagement_id: str = "",
        source_path: str = "",
    ) -> VulnerabilityReport:
        """Generate a vulnerability report from SAST findings.

        Args:
            sast_results: List of SAST finding dicts (from semgrep/codeql/bandit)
            client: Client name
            engagement_id: Engagement identifier
            source_path: Path to the analyzed source code

        Returns:
            VulnerabilityReport
        """
        findings = []

        for result in sast_results:
            severity = self._map_sast_severity(result.get("severity", "medium"))
            finding = VulnerabilityFinding(
                title=result.get("title", result.get("check_id", "SAST Finding")),
                cwe_id=result.get("cwe", "CWE-Unknown"),
                cvss_score=self._severity_to_cvss(severity),
                severity=severity,
                description=result.get("message", result.get("description", "")),
                affected_component=result.get("path", source_path),
                proof_of_concept=result.get("code", result.get("snippet", "")),
                reproduction_steps=[
                    f"Review source file: {result.get('path', 'unknown')}",
                    f"Examine line {result.get('start', {}).get('line', '?')}",
                    f"Rule: {result.get('check_id', 'N/A')}",
                ],
                remediation=result.get("fix", "Review and remediate per secure coding guidelines."),
                references=result.get("references", []),
                discovery_method="static_analysis",
            )
            findings.append(finding)

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: severity_order.get(f.severity, 5))

        report = VulnerabilityReport(
            title=f"Static Analysis Report — {source_path}",
            client=client,
            engagement_id=engagement_id,
            scope=source_path,
            executive_summary=self._generate_exec_summary(findings, None),
            findings=findings,
            methodology=(
                "Static analysis was performed using automated SAST tools "
                "(Semgrep, CodeQL, Bandit) on the target source code. Findings "
                "were classified by severity and mapped to CWE IDs."
            ),
            tools_used=["Semgrep", "CodeQL", "Bandit"],
        )

        return report

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _cvss_to_severity(self, cvss: float) -> str:
        if cvss >= 9.0:
            return "critical"
        elif cvss >= 7.0:
            return "high"
        elif cvss >= 4.0:
            return "medium"
        elif cvss > 0:
            return "low"
        return "info"

    def _severity_to_cvss(self, severity: str) -> float:
        return {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}.get(severity, 5.0)

    def _map_sast_severity(self, severity: str) -> str:
        sev = severity.lower().strip()
        if sev in ["error", "critical", "high"]:
            return "high" if sev != "critical" else "critical"
        elif sev in ["warning", "medium", "moderate"]:
            return "medium"
        elif sev in ["info", "low"]:
            return "low"
        return "medium"

    def _generate_description(self, crash) -> str:
        """Generate a human-readable description of the vulnerability."""
        crash_type = crash.crash_type.value
        exploitability = crash.exploitability.value

        descriptions = {
            "segfault": f"A segmentation fault occurs when processing crafted input. "
                       f"This indicates a memory safety violation — potentially a buffer "
                       f"overflow, use-after-free, or null pointer dereference. "
                       f"Exploitability: {exploitability}.",
            "stack_overflow": f"A stack-based buffer overflow was detected. The target "
                             f"fails to properly bounds-check input, allowing overwrite "
                             f"of stack memory including potentially the return address. "
                             f"This is a classic exploitable vulnerability.",
            "abort": f"The target aborted when processing malformed input, indicating "
                    f"an unhandled error condition or assertion failure.",
            "floating_point_exception": f"A floating point exception (divide by zero or "
                                        f"invalid operation) occurs with crafted numeric input.",
            "bus_error": f"A bus error indicates misaligned memory access, which may "
                        f"indicate a type confusion or memory corruption issue.",
            "illegal_instruction": f"The target executed an illegal instruction, potentially "
                                  f"indicating control flow hijacking or memory corruption.",
            "timeout": f"The target entered an infinite loop or deadlock when processing "
                      f"crafted input, causing a denial of service.",
            "out_of_memory": f"The target consumed excessive memory when processing crafted "
                            f"input, causing a denial of service condition.",
            "assertion_failure": f"An assertion was triggered by malformed input, indicating "
                                f"an unhandled edge case that could lead to undefined behavior.",
            "unknown": f"A crash was detected when processing crafted input. The exact "
                      f"crash type requires further analysis.",
        }
        return descriptions.get(crash_type, descriptions["unknown"])

    def _generate_poc(self, crash) -> str:
        """Generate proof-of-concept text."""
        poc = f"# Crash input hash: {crash.input_hash}\n"
        poc += f"# Crash type: {crash.crash_type.value}\n"
        poc += f"# Exploitability: {crash.exploitability.value}\n"
        poc += f"# Target: {crash.target_binary}\n\n"

        if crash.input_b64:
            poc += f"# Crash input (base64):\n# {crash.input_b64[:500]}\n\n"

        if crash.stack_trace:
            poc += f"# Stack trace:\n{crash.stack_trace[:2000]}\n"

        if crash.faulting_instruction:
            poc += f"\n# Faulting instruction:\n{crash.faulting_instruction}\n"

        return poc

    def _generate_repro_steps(self, crash) -> List[str]:
        """Generate reproduction steps."""
        steps = [
            f"Deploy target binary: {crash.target_binary}",
            f"Obtain crash input file (hash: {crash.input_hash[:16]}...)",
            f"Run: {crash.target_binary} < crash_input",
            "Observe crash (segfault/abort/etc.)",
        ]

        if crash.stack_trace:
            steps.append("Attach GDB for detailed analysis: gdb --args " +
                        crash.target_binary)

        return steps

    def _generate_remediation(self, crash) -> str:
        """Generate remediation advice based on crash type."""
        remediations = {
            "segfault": "Add proper bounds checking on all input parsing. "
                       "Use memory-safe constructs or enable compiler hardening "
                       "(stack canaries, ASLR, NX). Consider migrating to a "
                       "memory-safe language for input parsing code.",
            "stack_overflow": "Replace unsafe string/memory functions (strcpy, memcpy, "
                             "sprintf) with bounded equivalents (strncpy, memmove, snprintf). "
                             "Add explicit length validation before all buffer operations. "
                             "Enable stack canaries (-fstack-protector-strong).",
            "abort": "Handle error conditions gracefully instead of aborting. "
                    "Validate all inputs before processing and return meaningful "
                    "error codes rather than triggering assertion failures.",
            "floating_point_exception": "Add explicit checks for division by zero "
                                        "and invalid numeric operations before performing "
                                        "arithmetic.",
            "timeout": "Add input validation to reject pathological inputs that cause "
                      "excessive processing. Implement timeouts on all operations.",
            "out_of_memory": "Add limits on input size and allocation size. "
                            "Implement proper resource cleanup on allocation failure.",
            "assertion_failure": "Replace assertions with proper error handling for "
                                "production code. Validate inputs before assertions.",
        }
        return remediations.get(crash.crash_type.value,
            "Review the crash root cause and implement appropriate input validation "
            "and error handling.")

    def _generate_references(self, crash) -> List[str]:
        """Generate reference URLs based on CWE."""
        if crash.cwe_id:
            cwe_num = crash.cwe_id.replace("CWE-", "")
            return [
                f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
                "https://owasp.org/www-community/vulnerabilities/",
            ]
        return []

    def _generate_exec_summary(self, findings: List[VulnerabilityFinding], catalog) -> str:
        """Generate executive summary."""
        total = len(findings)
        critical = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        summary = (
            f"This report details {total} vulnerabilities discovered during "
            f"automated security assessment. "
        )

        if catalog:
            summary += (
                f"The assessment involved fuzzing campaigns that produced "
                f"{catalog.total_raw_crashes} raw crashes, which were "
                f"deduplicated to {catalog.unique_crashes} unique vulnerabilities. "
            )

        summary += (
            f"\n\n**Severity breakdown:**\n"
            f"- Critical: {critical}\n"
            f"- High: {high}\n"
            f"- Medium: {medium}\n"
            f"- Low: {low}\n\n"
        )

        if critical > 0:
            summary += (
                f"**{critical} critical vulnerabilities** were identified that "
                f"could allow remote code execution or complete system compromise. "
                f"These should be remediated immediately.\n\n"
            )

        if high > 0:
            summary += (
                f"**{high} high-severity vulnerabilities** were found that "
                f"could lead to significant security impact. These should be "
                f"prioritized for remediation.\n\n"
            )

        summary += (
            "All findings include proof-of-concept inputs, reproduction steps, "
            "and remediation guidance. Refer to the detailed findings section "
            "for technical specifics."
        )

        return summary
