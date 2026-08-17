"""Deterministic classifier: tool output -> structured vulnerability findings.

The red-team engines emit *evidence* (raw tool stdout plus the tool name and the
MITRE technique that produced it). To deliver a real client report we must turn
that evidence into structured findings with CWE ids, CVSS scores/vectors, and
remediation — WITHOUT fabricating anything. A finding is emitted only when the
tool output actually contains the signature of the issue; nothing is invented.

This is the bridge between measured pentest output and
:class:`vorsyghta.research.vuln_report.VulnerabilityFinding`.

Design:
  - Each classifier rule is (matcher, builder). The matcher inspects a single
    output line (already lower-cased for matching) and the builder produces a
    :class:`ClassifiedFinding` from the ORIGINAL line. Rules are grouped by the
    tool that produced the output so an nmap line is never parsed as sqlmap.
  - CVSS scores/vectors are fixed, defensible baselines per issue class (the
    same values a human analyst would assign for the observed evidence class),
    not model guesses. They are explicitly documented per rule.
  - De-duplication: identical (cwe, evidence) findings collapse to one.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ClassifiedFinding:
    """A structured finding derived from measured tool evidence.

    Mirrors the fields :class:`VulnerabilityFinding` needs; the report layer
    converts this into that dataclass. Every field is derived from real output.
    """

    title: str
    cwe_id: str
    cvss_score: float
    cvss_vector: str
    severity: str
    description: str
    evidence: str
    remediation: str
    tool: str
    technique_id: str = ""
    references: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# CVSS helpers
# --------------------------------------------------------------------------- #
def _severity_for(score: float) -> str:
    """Map a CVSS base score to a qualitative severity band (CVSS v3.1)."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def _cwe_refs(cwe_id: str) -> List[str]:
    """Standard references for a CWE id."""
    num = cwe_id.replace("CWE-", "")
    return [
        f"https://cwe.mitre.org/data/definitions/{num}.html",
        "https://owasp.org/www-community/",
    ]


# --------------------------------------------------------------------------- #
# Rule definitions
#
# Each rule: (predicate on lowered line, builder from original line, tool).
# Builders assign a defensible CVSS baseline for the OBSERVED evidence class.
# --------------------------------------------------------------------------- #
def _finding(
    title: str,
    cwe_id: str,
    cvss_score: float,
    cvss_vector: str,
    description: str,
    evidence: str,
    remediation: str,
    tool: str,
    technique_id: str,
) -> ClassifiedFinding:
    return ClassifiedFinding(
        title=title,
        cwe_id=cwe_id,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        severity=_severity_for(cvss_score),
        description=description,
        evidence=evidence.strip()[:500],
        remediation=remediation,
        tool=tool,
        technique_id=technique_id,
        references=_cwe_refs(cwe_id),
    )


# sqlmap: confirmed SQL injection (CWE-89). Network AV, no priv/UI -> 9.8.
# Negations ("not vulnerable", "no injectable parameters") must NOT match — a
# finding is emitted only on POSITIVE evidence of injection.
_SQLMAP_NEGATIONS = ("not vulnerable", "no injectable", "does not seem", "were not")


def _sqlmap_injection(line: str, tech: str) -> Optional[ClassifiedFinding]:
    low = line.lower()
    if any(neg in low for neg in _SQLMAP_NEGATIONS):
        return None
    positive = (
        "is vulnerable" in low
        or "sqlmap identified the following injection" in low
        or ("parameter" in low and "vulnerable" in low)
    )
    if positive:
        return _finding(
            title="SQL Injection",
            cwe_id="CWE-89",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            description=(
                "The application is vulnerable to SQL injection: sqlmap confirmed "
                "an injectable parameter, allowing an attacker to read or modify "
                "database contents and potentially bypass authentication."
            ),
            evidence=line,
            remediation=(
                "Use parameterised queries / prepared statements for all database "
                "access. Validate and canonicalise input at trust boundaries. Apply "
                "least-privilege database accounts."
            ),
            tool="sqlmap",
            technique_id=tech,
        )
    if "available databases" in low:
        return _finding(
            title="SQL Injection — database enumeration",
            cwe_id="CWE-89",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            description=(
                "SQL injection was exploited to enumerate database schemas, "
                "confirming an attacker can extract arbitrary data."
            ),
            evidence=line,
            remediation=(
                "Use parameterised queries; restrict DB account privileges; monitor "
                "for injection attempts."
            ),
            tool="sqlmap",
            technique_id=tech,
        )
    return None


# hydra: credentials recovered by brute force (CWE-307 / weak credentials).
def _hydra_creds(line: str, tech: str) -> Optional[ClassifiedFinding]:
    low = line.lower()
    if ("login:" in low and "password:" in low) or ("successfully" in low and "password" in low):
        return _finding(
            title="Weak / brute-forceable credentials",
            cwe_id="CWE-307",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            description=(
                "Valid credentials were recovered by online brute force, indicating "
                "missing rate limiting / account lockout and weak passwords."
            ),
            evidence=line,
            remediation=(
                "Enforce account lockout / exponential backoff, strong password "
                "policy, and multi-factor authentication. Alert on repeated failures."
            ),
            tool="hydra",
            technique_id=tech,
        )
    return None


# nikto: server misconfig / exposed resources (CWE-16 / CWE-200). Medium-ish.
def _nikto_issue(line: str, tech: str) -> Optional[ClassifiedFinding]:
    low = line.lower()
    if not line.strip().startswith("+"):
        return None
    if "osvdb" in low or "/admin" in low or "index of" in low or "directory indexing" in low:
        return _finding(
            title="Exposed sensitive resource / server misconfiguration",
            cwe_id="CWE-200",
            cvss_score=5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            description=(
                "The web server exposes sensitive resources or is misconfigured "
                "(admin path, directory indexing, or a known issue), leaking "
                "information useful to an attacker."
            ),
            evidence=line,
            remediation=(
                "Remove or protect administrative and backup paths, disable "
                "directory indexing, and patch the identified server issue."
            ),
            tool="nikto",
            technique_id=tech,
        )
    if "server:" in low and ("apache" in low or "nginx" in low or "iis" in low):
        return _finding(
            title="Server version disclosure",
            cwe_id="CWE-200",
            cvss_score=3.7,
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            description="The server discloses its software and version in headers.",
            evidence=line,
            remediation="Suppress or genericise the Server header.",
            tool="nikto",
            technique_id=tech,
        )
    return None


# nmap: open port -> exposure/attack surface (CWE-1327 info; low severity).
_NMAP_SENSITIVE_PORTS = {
    "23": ("Telnet", "CWE-319"),
    "21": ("FTP", "CWE-319"),
    "3389": ("RDP", "CWE-1327"),
    "445": ("SMB", "CWE-1327"),
}


def _nmap_open_port(line: str, tech: str) -> Optional[ClassifiedFinding]:
    low = line.lower()
    if "/tcp" not in low or "open" not in low:
        return None
    port = line.split("/")[0].strip()
    if port in _NMAP_SENSITIVE_PORTS:
        svc, cwe = _NMAP_SENSITIVE_PORTS[port]
        return _finding(
            title=f"Exposed {svc} service (port {port})",
            cwe_id=cwe,
            cvss_score=5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            description=(
                f"A {svc} service is exposed on port {port}. This increases attack "
                f"surface and, for cleartext protocols, risks credential interception."
            ),
            evidence=line,
            remediation=(
                f"Restrict access to {svc} via firewall/VPN, disable it if unused, "
                f"and prefer an encrypted alternative."
            ),
            tool="nmap",
            technique_id=tech,
        )
    return _finding(
        title="Open network port",
        cwe_id="CWE-1327",
        cvss_score=0.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        description="An open TCP port was discovered (attack-surface inventory).",
        evidence=line,
        remediation="Confirm the service is required; firewall unused ports.",
        tool="nmap",
        technique_id=tech,
    )


# gobuster / dirb: discovered path (CWE-200, low unless sensitive).
def _dir_found(line: str, tech: str) -> Optional[ClassifiedFinding]:
    low = line.lower()
    is_hit = ("status:" in low and any(c in low for c in ("200", "301", "302"))) or (
        "+ " in line and "code:" in low
    )
    if not is_hit:
        return None
    sensitive = any(k in low for k in ("admin", "backup", ".git", "config", ".env", "phpinfo"))
    score = 5.3 if sensitive else 0.0
    title = "Sensitive path exposed" if sensitive else "Discovered path"
    return _finding(
        title=title,
        cwe_id="CWE-200",
        cvss_score=score,
        cvss_vector=(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" if sensitive
            else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        ),
        description=(
            "A path was discovered via directory brute force"
            + (" that appears sensitive (admin/backup/config)." if sensitive else ".")
        ),
        evidence=line,
        remediation=(
            "Remove or authenticate sensitive paths; ensure backups/VCS metadata "
            "are not web-accessible."
        ),
        tool="gobuster",
        technique_id=tech,
    )


# Rule registry keyed by tool. Each entry is a list of builder callables.
_RULES: Dict[str, List[Callable[[str, str], Optional[ClassifiedFinding]]]] = {
    "sqlmap": [_sqlmap_injection],
    "hydra": [_hydra_creds],
    "nikto": [_nikto_issue],
    "nmap": [_nmap_open_port],
    "gobuster": [_dir_found],
    "dirb": [_dir_found],
}


class _InvocationDedup:
    """De-duplication policy for findings within one tool invocation.

    Non-info findings collapse by CWE (multiple confirming lines = one vuln);
    info-level inventory findings (e.g. open ports) collapse by evidence (each
    distinct asset is listed once).
    """

    def __init__(self) -> None:
        self._seen_cwe: set = set()
        self._seen_evidence: set = set()

    def accept(self, finding: "ClassifiedFinding") -> bool:
        """Return True if this finding is new under the policy (and record it)."""
        if finding.severity == "info":
            if finding.evidence in self._seen_evidence:
                return False
            self._seen_evidence.add(finding.evidence)
            return True
        if finding.cwe_id in self._seen_cwe:
            return False
        self._seen_cwe.add(finding.cwe_id)
        return True


class FindingClassifier:
    """Turn measured tool output into structured, de-duplicated findings.

    Emits a :class:`ClassifiedFinding` only when the output actually matches a
    known vulnerability/exposure signature for the tool that produced it. This is
    evidence-based classification — it never invents a finding that the output
    does not support.
    """

    def classify(
        self,
        tool_name: str,
        output: str,
        technique_id: str = "",
    ) -> List[ClassifiedFinding]:
        """Classify one tool invocation's output into structured findings.

        Args:
            tool_name: The tool that produced ``output`` (e.g. ``sqlmap``).
            output: Raw stdout from the tool.
            technique_id: MITRE technique id of the step, recorded on findings.

        Returns:
            De-duplicated list of :class:`ClassifiedFinding`. Empty when the tool
            is unknown or nothing matched.
        """
        if not output or not tool_name:
            return []
        builders = _RULES.get(tool_name.lower())
        if not builders:
            return []

        # Within one tool invocation, collapse repeated findings of the same CWE
        # to a single finding: multiple confirming lines (e.g. sqlmap printing an
        # injection banner AND the vulnerable parameter) describe ONE vulnerability.
        # The exception is the "attack-surface inventory" info class (open ports),
        # where each distinct evidence line is a distinct asset worth listing.
        dedup = _InvocationDedup()
        findings: List[ClassifiedFinding] = []
        for raw in output.split("\n"):
            line = raw.strip()
            if not line:
                continue
            for builder in builders:
                result = builder(line, technique_id)
                if result is not None and dedup.accept(result):
                    findings.append(result)
        return findings

    def classify_many(
        self,
        observations: List[Tuple[str, str, str]],
    ) -> List[ClassifiedFinding]:
        """Classify a batch of ``(tool_name, output, technique_id)`` observations.

        Findings are globally de-duplicated across observations by (cwe, evidence)
        so the same open port reported by two steps is one finding.
        """
        seen: set = set()
        out: List[ClassifiedFinding] = []
        for tool_name, output, technique_id in observations:
            for finding in self.classify(tool_name, output, technique_id):
                key = (finding.cwe_id, finding.evidence)
                if key in seen:
                    continue
                seen.add(key)
                out.append(finding)
        return out
