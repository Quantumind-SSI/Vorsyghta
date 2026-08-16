"""Endpoint Detection & Response (EDR) Agent.

Monitors endpoint activity for suspicious processes, file modifications,
registry changes, and behavioral anomalies.
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from vorsyghta.core.event_types import BlueTeamAlertEvent, BusEvent, EventType
from vorsyghta.integrations.siem_client import SIEMAlert

logger = logging.getLogger(__name__)


@dataclass
class ProcessEvent:
    """Represents a process execution event."""
    pid: int
    process_name: str
    command_line: str
    parent_pid: Optional[int] = None
    parent_process: Optional[str] = None
    user: str = ""
    timestamp: str = ""
    cwd: str = ""
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None


@dataclass
class FileEvent:
    """Represents a file system event."""
    path: str
    operation: str  # create, modify, delete, rename
    process: str = ""
    user: str = ""
    timestamp: str = ""
    old_path: Optional[str] = None
    size: Optional[int] = None
    hash_sha256: Optional[str] = None


@dataclass
class RegistryEvent:
    """Represents a Windows registry event."""
    key: str
    value: str
    data: str
    operation: str  # create, modify, delete
    process: str = ""
    timestamp: str = ""


@dataclass
class NetworkConnectionEvent:
    """Represents a network connection event."""
    process: str
    pid: int
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: str = "tcp"
    timestamp: str = ""
    bytes_sent: int = 0
    bytes_received: int = 0


SUSPICIOUS_PROCESSES = {
    "mimikatz", "procdump", "pwdump", "hashcat", "john",
    "hydra", "medusa", "ncat", "netcat", "nmap", "masscan",
    "responder", "impacket", "crackmapexec", "evil-winrm",
    "bloodhound", "sharpshound", "rubeus", "kekeo", "lsassy",
}

SUSPICIOUS_PATTERNS = [
    (r"(?i)powershell.*-enc", "PowerShell encoded command", "T1059", "high"),
    (r"(?i)powershell.*-exec.*bypass", "PowerShell execution policy bypass", "T1059", "high"),
    (r"(?i)cmd.*\/c.*powershell", "PowerShell via cmd.exe", "T1059", "medium"),
    (r"(?i)certutil.*-decode", "CertUtil for file decoding", "T1105", "medium"),
    (r"(?i)bitsadmin.*\/transfer", "BITSAdmin for file transfer", "T1105", "medium"),
    (r"(?i)reg.*save.*HKLM", "Registry hive dumping", "T1003", "critical"),
    (r"(?i)ntdsutil.*snapshot", "NTDS.dit extraction", "T1003", "critical"),
    (r"(?i)vssadmin.*delete.*shadows", "Volume shadow copy deletion", "T1490", "critical"),
    (r"(?i)wbadmin.*delete", "Backup deletion", "T1490", "critical"),
    (r"(?i)schtasks.*\/create", "Scheduled task creation", "T1053", "medium"),
    (r"(?i)sc.*create.*binpath", "Service creation", "T1543", "medium"),
    (r"(?i)netsh.*firewall.*add", "Firewall rule modification", "T1562", "high"),
    (r"(?i)whoami.*\/all", "Whoami privilege enumeration", "T1033", "low"),
    (r"(?i)net.*user.*\/add", "User account creation", "T1136", "high"),
    (r"(?i)net.*localgroup.*\/add", "Local group modification", "T1078", "high"),
    (r"(?i)wmic.*process.*call.*create", "WMI process creation", "T1047", "high"),
    (r"(?i)downloadstring\(", "PowerShell download cradle", "T1105", "high"),
    (r"(?i)invoke-mimikatz", "Mimikatz invocation", "T1003", "critical"),
    (r"(?i)seatbelt", "Seatbelt enumeration", "T1087", "medium"),
    (r"(?i)sharpup", "SharpUp privilege escalation", "T1068", "medium"),
]

SUSPICIOUS_FILE_PATHS = [
    (r"(?i)/tmp/\.\w+", "Hidden file in /tmp", "T1027", "medium"),
    (r"(?i)C:\\Temp\\.*\.(exe|dll|bat|ps1)", "Executable in Temp directory", "T1105", "medium"),
    (r"(?i)C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\", "Temp directory execution", "T1105", "medium"),
    (r"(?i)/var/tmp/\.\w+", "Hidden file in /var/tmp", "T1027", "medium"),
    (r"(?i)\\AppData\\Roaming\\.*\.(exe|dll)", "Executable in AppData Roaming", "T1547", "high"),
    (r"(?i)\\Startup\\.*\.", "Startup folder persistence", "T1547", "high"),
]

SUSPICIOUS_REGISTRY_KEYS = [
    (r"(?i)HKLM\\.*\\Run\\", "Run key persistence", "T1547", "high"),
    (r"(?i)HKCU\\.*\\Run\\", "User Run key persistence", "T1547", "high"),
    (r"(?i)HKLM\\.*\\Winlogon\\Shell", "Winlogon Shell modification", "T1547", "critical"),
    (r"(?i)HKLM\\.*\\Image File Execution Options\\", "IFEO injection", "T1546", "high"),
    (r"(?i)HKLM\\.*\\Services\\.*\\ImagePath", "Service image path modification", "T1543", "high"),
]


class EDRAgent:
    """Endpoint Detection & Response agent.

    Provides:
        - Process monitoring with suspicious pattern detection
        - File integrity monitoring
        - Registry change tracking (Windows)
        - Network connection monitoring
        - Behavioral anomaly detection

    Example:
        edr = EDRAgent()
        edr.monitor_process(ProcessEvent(
            pid=1234, process_name="powershell.exe",
            command_line="powershell -enc SGVsbG8=",
            user="admin", timestamp=...,
        ))
    """

    def __init__(self, host: str = "localhost"):
        self.host = host
        self._process_events: List[ProcessEvent] = []
        self._file_events: List[FileEvent] = []
        self._registry_events: List[RegistryEvent] = []
        self._network_events: List[NetworkConnectionEvent] = []
        self._alerts: List[SIEMAlert] = []

    def monitor_process(self, event: ProcessEvent) -> List[SIEMAlert]:
        """Monitor a process execution event."""
        self._process_events.append(event)
        alerts: List[SIEMAlert] = []

        proc_lower = event.process_name.lower()
        if proc_lower in SUSPICIOUS_PROCESSES:
            alerts.append(self._create_alert(
                title=f"[EDR] Suspicious process: {event.process_name}",
                severity="critical",
                description=f"Known attack tool executed: {event.process_name} (PID: {event.pid})",
                mitre="T1059",
                metadata={"pid": event.pid, "process": event.process_name, "command_line": event.command_line, "user": event.user},
            ))

        for pattern, desc, mitre, severity in SUSPICIOUS_PATTERNS:
            if re.search(pattern, event.command_line):
                alerts.append(self._create_alert(
                    title=f"[EDR] {desc}",
                    severity=severity,
                    description=f"{desc} detected in {event.process_name}: {event.command_line[:200]}",
                    mitre=mitre,
                    metadata={"pid": event.pid, "process": event.process_name, "command_line": event.command_line, "user": event.user},
                ))

        if event.parent_process:
            parent_lower = event.parent_process.lower()
            # winword.exe = MS Word, excel.exe = MS Excel, outlook.exe = MS Outlook,
            # powerpnt.exe = MS PowerPoint, winproj.exe = MS Project
            suspicious_parents = {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "winproj.exe"}
            if parent_lower in suspicious_parents and proc_lower in ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"):
                alerts.append(self._create_alert(
                    title=f"[EDR] Office app spawning shell: {event.parent_process} -> {event.process_name}",
                    severity="high",
                    description=f"Office application {event.parent_process} spawned {event.process_name}",
                    mitre="T1566",
                    metadata={"pid": event.pid, "parent_pid": event.parent_pid, "parent_process": event.parent_process, "command_line": event.command_line},
                ))

        self._alerts.extend(alerts)
        return alerts

    def monitor_file(self, event: FileEvent) -> List[SIEMAlert]:
        """Monitor a file system event."""
        self._file_events.append(event)
        alerts: List[SIEMAlert] = []

        for pattern, desc, mitre, severity in SUSPICIOUS_FILE_PATHS:
            if re.search(pattern, event.path):
                alerts.append(self._create_alert(
                    title=f"[EDR] {desc}",
                    severity=severity,
                    description=f"{event.operation} on suspicious path: {event.path}",
                    mitre=mitre,
                    metadata={"path": event.path, "operation": event.operation, "process": event.process},
                ))

        if event.operation == "modify":
            critical_paths = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "C:\\Windows\\System32\\config\\SAM"]
            for cp in critical_paths:
                if cp in event.path:
                    alerts.append(self._create_alert(
                        title=f"[EDR] Critical file modified: {event.path}",
                        severity="critical",
                        description=f"Modification of critical system file: {event.path} by {event.process}",
                        mitre="T1003",
                        metadata={"path": event.path, "operation": event.operation, "process": event.process},
                    ))

        self._alerts.extend(alerts)
        return alerts

    def monitor_registry(self, event: RegistryEvent) -> List[SIEMAlert]:
        """Monitor a Windows registry event."""
        self._registry_events.append(event)
        alerts: List[SIEMAlert] = []

        for pattern, desc, mitre, severity in SUSPICIOUS_REGISTRY_KEYS:
            if re.search(pattern, event.key):
                alerts.append(self._create_alert(
                    title=f"[EDR] {desc}",
                    severity=severity,
                    description=f"Registry {event.operation}: {event.key} = {event.value} by {event.process}",
                    mitre=mitre,
                    metadata={"key": event.key, "value": event.value, "operation": event.operation, "process": event.process},
                ))

        self._alerts.extend(alerts)
        return alerts

    def monitor_network(self, event: NetworkConnectionEvent) -> List[SIEMAlert]:
        """Monitor a network connection event."""
        self._network_events.append(event)
        alerts: List[SIEMAlert] = []

        suspicious_ports = {4444, 1337, 31337, 6666, 6667, 6668, 6669, 9001}
        if event.dest_port in suspicious_ports:
            alerts.append(self._create_alert(
                title=f"[EDR] Suspicious outbound connection to port {event.dest_port}",
                severity="high",
                description=f"Process {event.process} (PID: {event.pid}) connected to {event.dest_ip}:{event.dest_port}",
                mitre="T1071",
                metadata={"process": event.process, "pid": event.pid, "dest_ip": event.dest_ip, "dest_port": event.dest_port},
            ))

        if event.bytes_sent > 10_000_000:
            alerts.append(self._create_alert(
                title=f"[EDR] Large data transfer: {event.bytes_sent} bytes",
                severity="high",
                description=f"Process {event.process} sent {event.bytes_sent} bytes to {event.dest_ip}",
                mitre="T1041",
                metadata={"process": event.process, "bytes_sent": event.bytes_sent, "dest_ip": event.dest_ip},
            ))

        self._alerts.extend(alerts)
        return alerts

    def _create_alert(
        self,
        title: str,
        severity: str,
        description: str,
        mitre: str,
        metadata: Dict[str, Any],
    ) -> SIEMAlert:
        return SIEMAlert(
            alert_id=f"edr-{self.host}-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}",
            title=title,
            severity=severity,
            status="new",
            created_at=datetime.utcnow().isoformat(),
            description=description,
            source=f"edr:{self.host}",
            mitre_techniques=[mitre],
            metadata=metadata,
        )

    def get_alerts(
        self,
        severity: Optional[str] = None,
        limit: int = 50,
    ) -> List[SIEMAlert]:
        alerts = list(self._alerts)
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        alerts.sort(key=lambda a: a.created_at, reverse=True)
        return alerts[:limit]

    def get_stats(self) -> Dict[str, Any]:
        severity_counts: Dict[str, int] = {}
        for alert in self._alerts:
            severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1

        return {
            "host": self.host,
            "process_events": len(self._process_events),
            "file_events": len(self._file_events),
            "registry_events": len(self._registry_events),
            "network_events": len(self._network_events),
            "total_alerts": len(self._alerts),
            "alerts_by_severity": severity_counts,
        }

    def clear(self) -> None:
        self._process_events.clear()
        self._file_events.clear()
        self._registry_events.clear()
        self._network_events.clear()
        self._alerts.clear()

    def subscribe_to_event_bus(
        self,
        bus: Any,
        tenant_id: str,
        exercise_id: Optional[str] = None,
    ) -> None:
        """Subscribe this EDR agent to red team attack events on the shared event bus.

        Args:
            bus: The shared :class:`EventBus`.
            tenant_id: Tenant scope for events to process.
            exercise_id: Optional exercise identifier to include in published events.
        """
        from vorsyghta.core.event_bus import EventBus

        if not isinstance(bus, EventBus):
            raise TypeError("bus must be an EventBus instance")

        async def _handler(event: BusEvent) -> None:
            if event.tenant_id != tenant_id:
                return
            if event.event_type != EventType.RED_TEAM_ATTACK_STAGE:
                return

            payload = event.payload
            content = payload.get("content", "")
            technique_id = payload.get("technique_id", "")
            stage_id = payload.get("stage_id", "")
            timestamp = datetime.now(timezone.utc).isoformat()
            alerts: List[SIEMAlert] = []

            process_event = ProcessEvent(
                pid=1,
                process_name="attack.exe",
                command_line=content,
                user="attacker",
                timestamp=timestamp,
            )
            alerts.extend(self.monitor_process(process_event))

            file_event = FileEvent(
                path=f"/tmp/{stage_id}.dat",
                operation="create",
                process="attack.exe",
                user="attacker",
                timestamp=timestamp,
            )
            alerts.extend(self.monitor_file(file_event))

            if any(term in content.lower() for term in ["exfil", "c2", "beacon", "upload"]):
                network_event = NetworkConnectionEvent(
                    process="attack.exe",
                    pid=1,
                    source_ip="10.0.0.5",
                    source_port=54321,
                    dest_ip="192.0.2.100",
                    dest_port=4444,
                    protocol="tcp",
                    timestamp=timestamp,
                    bytes_sent=50_000_000,
                )
                alerts.extend(self.monitor_network(network_event))

            if technique_id in {"T1547", "T1053", "T1543"}:
                registry_event = RegistryEvent(
                    key="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    value="persistence",
                    data=content[:100],
                    operation="create",
                    process="attack.exe",
                    timestamp=timestamp,
                )
                alerts.extend(self.monitor_registry(registry_event))

            for alert in alerts:
                await bus.publish(
                    BlueTeamAlertEvent(
                        tenant_id=tenant_id,
                        exercise_id=exercise_id,
                        simulation_id=event.simulation_id,
                        alert_id=alert.alert_id,
                        source_module=alert.source,
                        technique_id=alert.mitre_techniques[0] if alert.mitre_techniques else "",
                        severity=alert.severity,
                        description=alert.description,
                        detected=True,
                        stage_id=stage_id,
                        iocs=payload.get("iocs", []),
                        raw_data={
                            "title": alert.title,
                            "metadata": alert.metadata,
                            "related_events": alert.related_events,
                        },
                    )
                )

        bus.subscribe(EventType.RED_TEAM_ATTACK_STAGE, _handler)
