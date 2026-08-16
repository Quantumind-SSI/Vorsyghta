"""Log Analyzer.

Multi-source log parsing, normalization, and correlation engine.
Supports Windows Event Logs, Linux syslog, Apache/Nginx, auth logs,
and application logs.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ParsedLogEntry:
    """A parsed and normalized log entry."""
    timestamp: Optional[str]
    source: str
    source_type: str
    host: str
    severity: str
    message: str
    fields: Dict[str, Any] = field(default_factory=dict)
    raw: str = ""
    mitre_technique: Optional[str] = None


@dataclass
class CorrelationFinding:
    """A correlation finding from multi-source log analysis."""
    finding_id: str
    title: str
    description: str
    severity: str
    sources: List[str]
    events: List[ParsedLogEntry]
    mitre_technique: Optional[str] = None
    confidence: float = 0.0


class LogAnalyzer:
    """Multi-source log analysis and correlation engine.

    Provides:
        - Log parsing for Windows Event, Linux syslog, Apache/Nginx, auth logs
        - Log normalization to common schema
        - Cross-source correlation
        - Pattern detection and anomaly highlighting

    Example:
        analyzer = LogAnalyzer()
        entries = analyzer.parse_file("/var/log/auth.log", "linux_auth")
        findings = analyzer.correlate(entries)
    """

    LOG_PATTERNS: Dict[str, List[Tuple[str, str, Optional[str]]]] = {
        "linux_auth": [
            (r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\w+)\[?(\d+)?\]?:\s+(.*)", "syslog", None),
            (r"(?i)Failed password for (\S+) from (\S+)", "auth_failed", "T1110"),
            (r"(?i)Accepted password for (\S+) from (\S+)", "auth_success", None),
            (r"(?i)Invalid user (\S+) from (\S+)", "invalid_user", "T1110"),
            (r"(?i)session opened for user (\S+)", "session_open", None),
            (r"(?i)session closed for user (\S+)", "session_close", None),
            (r"(?i)sudo:\s+(\S+).*COMMAND=(.*)", "sudo_command", "T1548"),
            (r"(?i)USER=.*\s+CMD=(.*)", "sudo_command", "T1548"),
        ],
        "linux_syslog": [
            (r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\w+)(\[\d+\])?:\s+(.*)", "syslog", None),
            (r"(?i)CRITICAL|ERROR|FATAL", "error", None),
            (r"(?i)segfault", "crash", None),
        ],
        "windows_security": [
            (r"EventID=(\d+).*?(?:User|Account):\s+(.*)", "windows_event", None),
            (r"EventID=4625.*?Account:\s+(\S+).*?Source:\s+(\S+)", "auth_failed", "T1110"),
            (r"EventID=4624.*?Account:\s+(\S+).*?Logon Type:\s+(\d+)", "auth_success", None),
            (r"EventID=4688.*?Process:\s+(\S+)", "process_created", "T1059"),
            (r"EventID=4720.*?Account:\s+(\S+)", "user_created", "T1136"),
            (r"EventID=4732.*?Account:\s+(\S+).*?Group:\s+(\S+)", "user_added_to_group", "T1078"),
            (r"EventID=4722.*?Account:\s+(\S+)", "user_enabled", None),
            (r"EventID=4724.*?Account:\s+(\S+)", "password_reset", "T1098"),
        ],
        "apache_access": [
            (r'(\S+)\s+\S+\s+\S+\s+\[(.*?)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+|-)\s+"(.*?)"\s+"(.*?)"', "apache_access", None),
            (r"(?i)union.*select|or.*1=1|xp_cmdshell", "sqli_attempt", "T1190"),
            (r"(?i)<script|javascript:|onerror=", "xss_attempt", "T1185"),
            (r"(?i)\.\./|%2e%2e%2f", "path_traversal", "T1083"),
        ],
        "nginx_access": [
            (r'(\S+)\s+-\s+\S+\s+\[(.*?)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+)\s+"(.*?)"\s+"(.*?)"', "nginx_access", None),
        ],
    }

    CORRELATION_RULES: List[Dict[str, Any]] = [
        {
            "name": "Failed then Successful Login",
            "description": "Multiple failed logins followed by success from same IP",
            "condition": lambda events: _check_brute_force_success(events),
            "severity": "high",
            "mitre": "T1110",
        },
        {
            "name": "Process Execution After Auth",
            "description": "Suspicious process execution shortly after login",
            "condition": lambda events: _check_process_after_auth(events),
            "severity": "medium",
            "mitre": "T1059",
        },
        {
            "name": "Privilege Escalation Chain",
            "description": "User added to privileged group after login",
            "condition": lambda events: _check_priv_escalation(events),
            "severity": "critical",
            "mitre": "T1078",
        },
    ]

    def __init__(self):
        self._entries: List[ParsedLogEntry] = []
        self._findings: List[CorrelationFinding] = []

    def parse_line(self, line: str, source_type: str, host: str = "") -> Optional[ParsedLogEntry]:
        """Parse a single log line."""
        patterns = self.LOG_PATTERNS.get(source_type, [])
        raw = line.strip()

        for pattern, log_type, mitre in patterns:
            match = re.search(pattern, raw)
            if match:
                fields: Dict[str, Any] = {}
                groups = match.groups()

                if log_type == "syslog":
                    timestamp_str = groups[0] if groups else ""
                    host = groups[1] if len(groups) > 1 else host
                    fields["process"] = groups[2] if len(groups) > 2 else ""
                    fields["pid"] = groups[3] if len(groups) > 3 else ""
                    message = groups[4] if len(groups) > 4 else raw
                elif log_type == "auth_failed":
                    fields["user"] = groups[0] if groups else ""
                    fields["source_ip"] = groups[1] if len(groups) > 1 else ""
                    message = raw
                elif log_type == "auth_success":
                    fields["user"] = groups[0] if groups else ""
                    fields["source_ip"] = groups[1] if len(groups) > 1 else ""
                    message = raw
                elif log_type == "apache_access" or log_type == "nginx_access":
                    fields["client_ip"] = groups[0] if groups else ""
                    fields["timestamp"] = groups[1] if len(groups) > 1 else ""
                    fields["method"] = groups[2] if len(groups) > 2 else ""
                    fields["path"] = groups[3] if len(groups) > 3 else ""
                    fields["status"] = groups[5] if len(groups) > 5 else ""
                    fields["size"] = groups[6] if len(groups) > 6 else ""
                    fields["user_agent"] = groups[8] if len(groups) > 8 else ""
                    message = f'{fields.get("method", "")} {fields.get("path", "")} {fields.get("status", "")}'
                else:
                    message = raw
                    for i, g in enumerate(groups):
                        fields[f"group_{i}"] = g

                severity = self._determine_severity(log_type, raw)

                return ParsedLogEntry(
                    timestamp=datetime.utcnow().isoformat(),
                    source=source_type,
                    source_type=log_type,
                    host=host,
                    severity=severity,
                    message=message,
                    fields=fields,
                    raw=raw,
                    mitre_technique=mitre,
                )

        return ParsedLogEntry(
            timestamp=datetime.utcnow().isoformat(),
            source=source_type,
            source_type="unknown",
            host=host,
            severity="info",
            message=raw,
            raw=raw,
        )

    def parse_lines(self, lines: List[str], source_type: str, host: str = "") -> List[ParsedLogEntry]:
        """Parse multiple log lines."""
        entries: List[ParsedLogEntry] = []
        for line in lines:
            entry = self.parse_line(line, source_type, host)
            if entry:
                entries.append(entry)
                self._entries.append(entry)
        return entries

    def parse_file(self, file_path: str, source_type: str, host: str = "") -> List[ParsedLogEntry]:
        """Parse a log file."""
        entries: List[ParsedLogEntry] = []
        try:
            with open(file_path, "r", errors="ignore") as f:
                for line in f:
                    entry = self.parse_line(line, source_type, host)
                    if entry:
                        entries.append(entry)
                        self._entries.append(entry)
        except FileNotFoundError:
            logger.error(f"Log file not found: {file_path}")
        return entries

    def _determine_severity(self, log_type: str, raw: str) -> str:
        if log_type in ("auth_failed", "sqli_attempt", "xss_attempt", "path_traversal"):
            return "high"
        if log_type in ("user_created", "user_added_to_group", "password_reset"):
            return "high"
        if log_type in ("sudo_command", "process_created"):
            return "medium"
        if "error" in log_type or "crash" in log_type:
            return "medium"
        return "info"

    def correlate(self, entries: Optional[List[ParsedLogEntry]] = None) -> List[CorrelationFinding]:
        """Correlate log entries to find patterns."""
        entries = entries or self._entries
        findings: List[CorrelationFinding] = []

        for rule in self.CORRELATION_RULES:
            try:
                result = rule["condition"](entries)
                if result:
                    finding = CorrelationFinding(
                        finding_id=f"corr-{len(findings) + 1:04d}",
                        title=rule["name"],
                        description=rule["description"],
                        severity=rule["severity"],
                        sources=list({e.source for e in result}),
                        events=result,
                        mitre_technique=rule.get("mitre"),
                        confidence=0.8,
                    )
                    findings.append(finding)
                    self._findings.append(finding)
            except Exception as e:
                logger.error(f"Correlation rule '{rule['name']}' failed: {e}")

        return findings

    def search(
        self,
        query: str,
        entries: Optional[List[ParsedLogEntry]] = None,
    ) -> List[ParsedLogEntry]:
        """Search log entries with a simple query."""
        entries = entries or self._entries
        query_lower = query.lower()

        results: List[ParsedLogEntry] = []
        for entry in entries:
            searchable = f"{entry.message} {entry.raw} {json.dumps(entry.fields)}".lower()
            if query_lower in searchable:
                results.append(entry)

        return results

    def get_findings(self) -> List[CorrelationFinding]:
        return list(self._findings)

    def get_stats(self) -> Dict[str, Any]:
        source_counts: Dict[str, int] = {}
        type_counts: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {}

        for entry in self._entries:
            source_counts[entry.source] = source_counts.get(entry.source, 0) + 1
            type_counts[entry.source_type] = type_counts.get(entry.source_type, 0) + 1
            severity_counts[entry.severity] = severity_counts.get(entry.severity, 0) + 1

        return {
            "total_entries": len(self._entries),
            "total_findings": len(self._findings),
            "by_source": source_counts,
            "by_type": type_counts,
            "by_severity": severity_counts,
        }

    def clear(self) -> None:
        self._entries.clear()
        self._findings.clear()


def _check_brute_force_success(events: List[ParsedLogEntry]) -> List[ParsedLogEntry]:
    """Check for brute force followed by success."""
    failed_ips: Dict[str, List[ParsedLogEntry]] = {}
    successes: List[ParsedLogEntry] = []

    for e in events:
        if e.source_type == "auth_failed":
            ip = e.fields.get("source_ip", "")
            if ip:
                failed_ips.setdefault(ip, []).append(e)
        elif e.source_type == "auth_success":
            successes.append(e)

    for success in successes:
        ip = success.fields.get("source_ip", "")
        if ip in failed_ips and len(failed_ips[ip]) >= 3:
            return failed_ips[ip] + [success]

    return []


def _check_process_after_auth(events: List[ParsedLogEntry]) -> List[ParsedLogEntry]:
    """Check for suspicious process execution after authentication."""
    auth_events = [e for e in events if e.source_type == "auth_success"]
    process_events = [e for e in events if e.source_type == "process_created"]

    suspicious_processes = {"powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe"}

    for proc in process_events:
        proc_name = proc.fields.get("process", "").lower()
        if proc_name in suspicious_processes:
            return [proc]

    return []


def _check_priv_escalation(events: List[ParsedLogEntry]) -> List[ParsedLogEntry]:
    """Check for privilege escalation patterns."""
    group_adds = [e for e in events if e.source_type == "user_added_to_group"]
    admin_keywords = {"admin", "root", "wheel", "sudo", "Domain Admins"}

    for add_event in group_adds:
        group = str(add_event.fields.get("group_1", add_event.fields.get("Group", ""))).lower()
        if any(kw in group for kw in admin_keywords):
            return [add_event]

    return []
