"""Blue Team CLI commands for defensive operations.

Provides commands for SIEM querying, IDS detection, EDR monitoring,
incident response, threat hunting, log analysis, alert triage, and forensics.
"""

import asyncio
import json
import os
import sys
from datetime import datetime, timedelta
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown
from rich.json import JSON

console = Console()


def _get_siem_client():
    """Get SIEM client from environment."""
    from ciicerone.integrations.siem_client import SIEMClient

    return SIEMClient()


def _get_siem_simulator():
    """Get SIEM simulator with optional real SIEM client."""
    from ciicerone.integrations.siem_client import SIEMClient
    from ciicerone.defense.blue_team.siem_simulator import SIEMSimulator

    client = SIEMClient()
    if client.base_url:
        return SIEMSimulator(siem_client=client)
    return SIEMSimulator()


@click.group()
def blue_team():
    """Blue team defensive operations.

    SIEM, IDS, EDR, incident response, threat hunting, log analysis,
    alert triage, and digital forensics capabilities.

    Connects to real SIEM platforms (Splunk, Elastic, Sentinel, QRadar)
    when configured via environment variables.
    """
    pass


# === SIEM Commands ===

@blue_team.group()
def siem():
    """SIEM operations — query logs, manage alerts, test connectivity."""
    pass


@siem.command()
def connect():
    """Test SIEM connectivity."""
    from ciicerone.integrations.siem_client import SIEMClient

    client = SIEMClient()

    if not client.base_url:
        console.print("[yellow]No SIEM configured. Set SIEM_URL and SIEM_PLATFORM env vars.[/yellow]")
        console.print("\nSupported platforms: splunk, elastic, sentinel, qradar, generic")
        console.print("Example: SIEM_PLATFORM=splunk SIEM_URL=https://splunk.example.com:8089")
        return

    console.print(f"[cyan]Testing connection to {client.platform} at {client.base_url}...[/cyan]")

    result = asyncio.run(client.test_connection())

    if result["status"] == "ok":
        console.print("[green]✓ SIEM connection successful[/green]")
        console.print(f"  Platform: {result['platform']}")
        console.print(f"  URL: {result['url']}")
        if "info" in result:
            console.print(f"  Info: {JSON.from_data(result['info'])}")
    else:
        console.print(f"[red]✗ Connection failed: {result.get('message', 'Unknown error')}[/red]")
        if "code" in result:
            console.print(f"  HTTP Status: {result['code']}")


@siem.command()
@click.option("--query", "-q", required=True, help="Search query (platform-specific syntax)")
@click.option("--hours", "-h", default=1, help="Hours to search back")
@click.option("--limit", "-l", default=100, help="Maximum results")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def search(query, hours, limit, json_output):
    """Search logs in the SIEM."""
    from ciicerone.integrations.siem_client import SIEMClient

    client = SIEMClient()

    if not client.base_url:
        console.print("[red]No SIEM configured. Set SIEM_URL env var.[/red]")
        return

    start = datetime.utcnow() - timedelta(hours=hours)

    console.print(f"[cyan]Searching: {query}[/cyan]")
    console.print(f"  Time range: {start} to now ({hours}h)")

    events = asyncio.run(client.search_logs(query, start_time=start, limit=limit))

    if not events:
        console.print("[yellow]No events found.[/yellow]")
        return

    if json_output:
        console.print_json(json.dumps([{
            "id": e.event_id,
            "timestamp": e.timestamp,
            "source": e.source,
            "host": e.host,
            "severity": e.severity,
            "fields": e.fields,
        } for e in events]))
        return

    table = Table(title=f"SIEM Search Results ({len(events)} events)")
    table.add_column("Timestamp", style="cyan")
    table.add_column("Source", style="green")
    table.add_column("Host", style="yellow")
    table.add_column("Severity", style="red")
    table.add_column("Message", style="white")

    for e in events:
        table.add_row(
            str(e.timestamp)[:19],
            e.source[:20],
            e.host[:20],
            e.severity,
            (e.fields.get("message", e.raw))[:80],
        )

    console.print(table)


@siem.command()
@click.option("--severity", "-s", help="Filter by severity")
@click.option("--status", help="Filter by status")
@click.option("--limit", "-l", default=50, help="Maximum results")
def alerts(severity, status, limit):
    """Get alerts from the SIEM."""
    from ciicerone.integrations.siem_client import SIEMClient

    client = SIEMClient()

    if not client.base_url:
        console.print("[red]No SIEM configured.[/red]")
        return

    alerts = asyncio.run(client.get_alerts(severity=severity, status=status, limit=limit))

    if not alerts:
        console.print("[yellow]No alerts found.[/yellow]")
        return

    table = Table(title=f"SIEM Alerts ({len(alerts)})")
    table.add_column("ID", style="cyan")
    table.add_column("Title", style="white")
    table.add_column("Severity", style="red")
    table.add_column("Status", style="yellow")
    table.add_column("MITRE", style="green")
    table.add_column("Created", style="dim")

    for a in alerts:
        sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue"}.get(a.severity, "white")
        table.add_row(
            a.alert_id[:20],
            a.title[:40],
            f"[{sev_color}]{a.severity}[/{sev_color}]",
            a.status,
            ", ".join(a.mitre_techniques),
            str(a.created_at)[:19],
        )

    console.print(table)


@siem.command()
def stats():
    """Get SIEM simulator statistics."""
    siem = _get_siem_simulator()
    stats = siem.get_stats()

    console.print(Panel.fit(
        f"[cyan]SIEM Statistics[/cyan]\n\n"
        f"Total Logs: {stats['total_logs']}\n"
        f"Total Alerts: {stats['total_alerts']}\n"
        f"Active Rules: {stats['active_rules']}\n"
        f"Connected to SIEM: {'yes' if stats['connected_to_siem'] else 'no (simulator only)'}\n\n"
        f"Alerts by Severity: {json.dumps(stats.get('alerts_by_severity', {}))}\n"
        f"Logs by Source: {json.dumps(stats.get('logs_by_source', {}))}",
        title="SIEM Stats",
    ))


# === IDS Commands ===

@blue_team.group()
def ids():
    """IDS/IPS detection operations."""
    pass


@ids.command()
@click.option("--protocol", "-p", help="Protocol filter (tcp, udp, icmp)")
@click.option("--src-ip", help="Source IP")
@click.option("--src-port", type=int, help="Source port")
@click.option("--dest-ip", help="Destination IP")
@click.option("--dest-port", type=int, help="Destination port")
@click.option("--payload", help="Packet payload")
def inspect(protocol, src_ip, src_port, dest_ip, dest_port, payload):
    """Inspect a network packet against IDS rules."""
    from ciicerone.defense.blue_team.ids_detector import IDSDetector, NetworkPacket

    ids_detector = IDSDetector()
    packet = NetworkPacket(
        timestamp=datetime.utcnow().isoformat(),
        protocol=protocol or "tcp",
        source_ip=src_ip or "0.0.0.0",
        source_port=src_port or 0,
        dest_ip=dest_ip or "0.0.0.0",
        dest_port=dest_port or 0,
        payload=payload or "",
    )

    alerts = ids_detector.inspect_packet(packet)

    if not alerts:
        console.print("[green]No IDS alerts triggered.[/green]")
        return

    table = Table(title=f"IDS Alerts ({len(alerts)})")
    table.add_column("Rule", style="cyan")
    table.add_column("Severity", style="red")
    table.add_column("MITRE", style="green")
    table.add_column("Description", style="white")

    for a in alerts:
        table.add_row(
            a.metadata.get("rule_id", ""),
            a.severity,
            ", ".join(a.mitre_techniques),
            a.title,
        )

    console.print(table)


@ids.command()
def rules():
    """List IDS detection rules."""
    from ciicerone.defense.blue_team.ids_detector import IDSDetector

    ids_detector = IDSDetector()
    rule_list = ids_detector.list_rules()

    table = Table(title=f"IDS Rules ({len(rule_list)})")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Protocol", style="green")
    table.add_column("Port", style="yellow")
    table.add_column("Severity", style="red")
    table.add_column("MITRE", style="blue")

    for r in rule_list:
        table.add_row(
            r.rule_id,
            r.name,
            r.protocol,
            r.dest_port,
            r.severity,
            r.mitre_technique or "",
        )

    console.print(table)


@ids.command()
def stats():
    """Get IDS statistics."""
    from ciicerone.defense.blue_team.ids_detector import IDSDetector

    ids_detector = IDSDetector()
    stats = ids_detector.get_stats()

    console.print(Panel.fit(
        f"[cyan]IDS Statistics[/cyan]\n\n"
        f"Total Packets: {stats['total_packets']}\n"
        f"Total Alerts: {stats['total_alerts']}\n"
        f"Active Rules: {stats['active_rules']}\n"
        f"Tracked Sources: {stats['tracked_sources']}\n\n"
        f"Alerts by Severity: {json.dumps(stats.get('alerts_by_severity', {}))}",
        title="IDS Stats",
    ))


# === EDR Commands ===

@blue_team.group()
def edr():
    """EDR endpoint detection operations."""
    pass


@edr.command()
@click.option("--process", "-p", required=True, help="Process name")
@click.option("--cmd", "-c", required=True, help="Command line")
@click.option("--pid", type=int, default=0, help="Process ID")
@click.option("--user", "-u", default="", help="User context")
@click.option("--parent", default="", help="Parent process")
def monitor(process, cmd, pid, user, parent):
    """Monitor a process execution event."""
    from ciicerone.defense.blue_team.edr_agent import EDRAgent, ProcessEvent

    agent = EDRAgent()
    event = ProcessEvent(
        pid=pid,
        process_name=process,
        command_line=cmd,
        parent_process=parent or None,
        user=user,
        timestamp=datetime.utcnow().isoformat(),
    )

    alerts = agent.monitor_process(event)

    if not alerts:
        console.print("[green]No EDR alerts triggered.[/green]")
        return

    for a in alerts:
        sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue"}.get(a.severity, "white")
        console.print(f"[{sev_color}][{a.severity.upper()}][/{sev_color}] {a.title}")
        console.print(f"  {a.description}")


@edr.command()
def stats():
    """Get EDR statistics."""
    from ciicerone.defense.blue_team.edr_agent import EDRAgent

    agent = EDRAgent()
    stats = agent.get_stats()

    console.print(Panel.fit(
        f"[cyan]EDR Statistics[/cyan]\n\n"
        f"Host: {stats['host']}\n"
        f"Process Events: {stats['process_events']}\n"
        f"File Events: {stats['file_events']}\n"
        f"Registry Events: {stats['registry_events']}\n"
        f"Network Events: {stats['network_events']}\n"
        f"Total Alerts: {stats['total_alerts']}\n\n"
        f"Alerts by Severity: {json.dumps(stats.get('alerts_by_severity', {}))}",
        title="EDR Stats",
    ))


# === Incident Response Commands ===

@blue_team.group()
def incident():
    """Incident response operations."""
    pass


@incident.command()
@click.option("--title", "-t", required=True, help="Incident title")
@click.option("--severity", "-s", required=True, type=click.Choice(["critical", "high", "medium", "low"]))
@click.option("--category", "-c", required=True, type=click.Choice(["intrusion", "malware", "phishing", "data_breach", "ddos"]))
@click.option("--systems", help="Comma-separated affected systems")
@click.option("--mitre", help="Comma-separated MITRE techniques")
@click.option("--description", "-d", default="", help="Incident description")
@click.option("--auto", is_flag=True, help="Auto-execute automated steps")
def create(title, severity, category, systems, mitre, description, auto):
    """Create a new incident and execute playbook."""
    from ciicerone.defense.blue_team.incident_response import IncidentResponse

    ir = IncidentResponse()
    incident = ir.create_incident(
        title=title,
        severity=severity,
        category=category,
        affected_systems=systems.split(",") if systems else [],
        mitre_techniques=mitre.split(",") if mitre else [],
        description=description,
    )

    console.print(f"[green]Created incident: {incident.incident_id}[/green]")
    console.print(f"  Title: {incident.title}")
    console.print(f"  Severity: {incident.severity}")
    console.print(f"  Category: {incident.category}")
    console.print(f"  Playbook steps: {len(incident.steps)}")

    if auto:
        ir.execute_playbook(incident, auto_execute=True)
        completed = sum(1 for s in incident.steps if s.completed)
        console.print(f"\n[cyan]Auto-executed: {completed}/{len(incident.steps)} steps[/cyan]")
        console.print(f"  Status: {incident.status}")

    console.print(f"\n[yellow]Use 'ciicerone blue-team incident show {incident.incident_id}' for details[/yellow]")


@incident.command()
@click.argument("incident_id")
def show(incident_id):
    """Show incident details."""
    from ciicerone.defense.blue_team.incident_response import IncidentResponse

    ir = IncidentResponse()
    incident = ir.get_incident(incident_id)

    if not incident:
        console.print(f"[red]Incident not found: {incident_id}[/red]")
        return

    console.print(Panel.fit(
        f"[cyan]Incident {incident.incident_id}[/cyan]\n\n"
        f"Title: {incident.title}\n"
        f"Severity: {incident.severity}\n"
        f"Status: {incident.status}\n"
        f"Category: {incident.category}\n"
        f"Created: {incident.created_at}\n"
        f"Systems: {', '.join(incident.affected_systems)}\n"
        f"MITRE: {', '.join(incident.mitre_techniques)}\n"
        f"Description: {incident.description}",
        title="Incident Details",
    ))

    table = Table(title="Playbook Steps")
    table.add_column("Step", style="cyan")
    table.add_column("Phase", style="green")
    table.add_column("Action", style="white")
    table.add_column("Done", style="yellow")
    table.add_column("Result", style="dim")

    for step in incident.steps:
        done = "✓" if step.completed else "○"
        table.add_row(step.step_id, step.phase, step.action, done, (step.result or "")[:50])

    console.print(table)


@incident.command()
@click.argument("incident_id")
@click.argument("step_id")
@click.option("--result", "-r", default="", help="Result of the step")
def execute(incident_id, step_id, result):
    """Execute a specific incident response step."""
    from ciicerone.defense.blue_team.incident_response import IncidentResponse

    ir = IncidentResponse()
    success = ir.execute_step(incident_id, step_id, result)

    if success:
        console.print(f"[green]Step {step_id} executed for {incident_id}[/green]")
    else:
        console.print(f"[red]Failed to execute step. Check incident/step ID.[/red]")


@incident.command()
@click.option("--status", "-s", help="Filter by status")
@click.option("--severity", help="Filter by severity")
def list(status, severity):
    """List incidents."""
    from ciicerone.defense.blue_team.incident_response import IncidentResponse

    ir = IncidentResponse()
    incidents = ir.list_incidents(status=status, severity=severity)

    if not incidents:
        console.print("[yellow]No incidents found.[/yellow]")
        return

    table = Table(title=f"Incidents ({len(incidents)})")
    table.add_column("ID", style="cyan")
    table.add_column("Title", style="white")
    table.add_column("Severity", style="red")
    table.add_column("Status", style="yellow")
    table.add_column("Category", style="green")

    for inc in incidents:
        table.add_row(inc.incident_id, inc.title[:40], inc.severity, inc.status, inc.category)

    console.print(table)


@incident.command()
@click.argument("incident_id")
def report(incident_id):
    """Generate post-incident report."""
    from ciicerone.defense.blue_team.incident_response import IncidentResponse

    ir = IncidentResponse()
    report_data = ir.generate_report(incident_id)

    if not report_data:
        console.print(f"[red]Incident not found: {incident_id}[/red]")
        return

    console.print_json(json.dumps(report_data))


# === Threat Hunting Commands ===

@blue_team.group()
def hunt():
    """Threat hunting operations."""
    pass


@hunt.command()
@click.option("--technique", "-t", help="MITRE ATT&CK technique ID (e.g., T1003)")
@click.option("--hypothesis-id", help="Specific hypothesis ID to execute")
@click.option("--all", "hunt_all", is_flag=True, help="Execute all hypotheses")
def search(technique, hypothesis_id, hunt_all):
    """Execute threat hunting hypotheses."""
    from ciicerone.integrations.siem_client import SIEMClient
    from ciicerone.defense.blue_team.threat_hunter import ThreatHunter

    client = SIEMClient()
    hunter = ThreatHunter(siem_client=client if client.base_url else None)

    if hunt_all:
        console.print("[cyan]Executing all hunt hypotheses...[/cyan]")
        results = asyncio.run(hunter.hunt_all())
    elif technique:
        console.print(f"[cyan]Hunting for technique {technique}...[/cyan]")
        result = asyncio.run(hunter.hunt_technique(technique))
        results = [result] if result else []
    elif hypothesis_id:
        console.print(f"[cyan]Executing hypothesis {hypothesis_id}...[/cyan]")
        result = asyncio.run(hunter.hunt_hypothesis(hypothesis_id))
        results = [result] if result else []
    else:
        console.print("[red]Specify --technique, --hypothesis-id, or --all[/red]")
        return

    for result in results:
        status_color = "red" if result.confirmed else "green"
        console.print(f"\n[{status_color}]{result.hypothesis.technique_id}: {'CONFIRMED' if result.confirmed else 'DISPROVED'}[/{status_color}]")
        console.print(f"  {result.summary}")
        if result.findings:
            console.print(f"  Findings: {len(result.findings)}")
            if result.affected_systems:
                console.print(f"  Affected: {', '.join(result.affected_systems)}")


@hunt.command()
def hypotheses():
    """List available hunt hypotheses."""
    from ciicerone.defense.blue_team.threat_hunter import ThreatHunter

    hunter = ThreatHunter(enable_default_hypotheses=True)
    hyps = hunter.list_hypotheses()

    table = Table(title=f"Hunt Hypotheses ({len(hyps)})")
    table.add_column("ID", style="cyan")
    table.add_column("MITRE", style="green")
    table.add_column("Name", style="white")
    table.add_column("Confidence", style="yellow")
    table.add_column("Description", style="dim")

    for h in hyps:
        table.add_row(h.hypothesis_id, h.technique_id, h.technique_name, str(h.confidence), h.description[:60])

    console.print(table)


# === Log Analysis Commands ===

@blue_team.group()
def logs():
    """Log analysis operations."""
    pass


@logs.command()
@click.option("--file", "-f", required=True, type=click.Path(exists=True), help="Log file path")
@click.option("--type", "-t", required=True, type=click.Choice(["linux_auth", "linux_syslog", "windows_security", "apache_access", "nginx_access"]), help="Log type")
@click.option("--host", default="", help="Source host name")
def parse(file, type, host):
    """Parse a log file."""
    from ciicerone.defense.blue_team.log_analyzer import LogAnalyzer

    analyzer = LogAnalyzer()
    entries = analyzer.parse_file(file, type, host)

    console.print(f"[green]Parsed {len(entries)} entries from {file}[/green]")

    findings = analyzer.correlate(entries)
    if findings:
        console.print(f"\n[yellow]Correlation Findings: {len(findings)}[/yellow]")
        for f in findings:
            console.print(f"  [{f.severity}] {f.title}: {f.description}")

    stats = analyzer.get_stats()
    console.print(f"\n[cyan]Stats: {json.dumps(stats)}[/cyan]")


@logs.command()
@click.option("--query", "-q", required=True, help="Search query")
@click.option("--file", "-f", type=click.Path(exists=True), help="Log file to search")
@click.option("--type", "-t", default="linux_auth", help="Log type")
def search(query, file, type):
    """Search parsed log entries."""
    from ciicerone.defense.blue_team.log_analyzer import LogAnalyzer

    analyzer = LogAnalyzer()

    if file:
        analyzer.parse_file(file, type)

    results = analyzer.search(query)

    if not results:
        console.print("[yellow]No matching entries found.[/yellow]")
        return

    table = Table(title=f"Search Results ({len(results)})")
    table.add_column("Timestamp", style="cyan")
    table.add_column("Type", style="green")
    table.add_column("Severity", style="red")
    table.add_column("Message", style="white")

    for e in results[:50]:
        table.add_row(str(e.timestamp)[:19], e.source_type, e.severity, e.message[:80])

    console.print(table)


# === Alert Triage Commands ===

@blue_team.group()
def triage():
    """Alert triage operations."""
    pass


@triage.command()
@click.option("--severity", "-s", help="Filter by severity")
@click.option("--limit", "-l", default=20, help="Maximum results")
def alerts(severity, limit):
    """Get triaged alerts sorted by priority."""
    from ciicerone.integrations.siem_client import SIEMClient
    from ciicerone.defense.blue_team.alert_triage import AlertTriage

    client = SIEMClient()
    triage_engine = AlertTriage()

    if client.base_url:
        raw_alerts = asyncio.run(client.get_alerts(severity=severity, limit=limit))
    else:
        console.print("[yellow]No SIEM configured. Showing simulator alerts.[/yellow]")
        from ciicerone.defense.blue_team.siem_simulator import SIEMSimulator
        siem = SIEMSimulator()
        raw_alerts = siem.get_alerts(severity=severity, limit=limit)

    if not raw_alerts:
        console.print("[yellow]No alerts to triage.[/yellow]")
        return

    triaged = triage_engine.triage_batch(raw_alerts)

    table = Table(title=f"Triaged Alerts ({len(triaged)})")
    table.add_column("Priority", style="red")
    table.add_column("Score", style="cyan")
    table.add_column("Title", style="white")
    table.add_column("Severity", style="yellow")
    table.add_column("FP", style="dim")
    table.add_column("Action", style="green")

    for t in triaged[:limit]:
        fp = "yes" if t.is_false_positive else "no"
        table.add_row(
            t.priority_level,
            f"{t.priority_score:.0f}",
            t.alert.title[:40],
            t.alert.severity,
            fp,
            t.recommended_action[:50],
        )

    console.print(table)


@triage.command()
def stats():
    """Get triage statistics."""
    from ciicerone.defense.blue_team.alert_triage import AlertTriage

    triage_engine = AlertTriage()
    stats = triage_engine.get_stats()

    console.print(Panel.fit(
        f"[cyan]Alert Triage Statistics[/cyan]\n\n"
        f"Total Triaged: {stats['total_triaged']}\n"
        f"P1 (Critical): {stats['p1_alerts']}\n"
        f"P2 (High): {stats['p2_alerts']}\n"
        f"False Positives: {stats['false_positives']}\n"
        f"FP Rate: {stats['fp_rate']:.1f}%\n\n"
        f"By Priority: {json.dumps(stats.get('by_priority', {}))}",
        title="Triage Stats",
    ))


# === Forensics Commands ===

@blue_team.group()
def forensics():
    """Digital forensics operations."""
    pass


@forensics.command()
@click.option("--case-id", "-c", help="Case ID")
def init(case_id):
    """Initialize a forensic case."""
    from ciicerone.defense.blue_team.forensics import ForensicsCollector

    fc = ForensicsCollector(case_id=case_id)
    console.print(f"[green]Forensic case initialized: {fc.case_id}[/green]")


@forensics.command()
@click.option("--file", "-f", required=True, type=click.Path(exists=True), help="File to collect")
@click.option("--source", "-s", required=True, help="Source host/system")
def collect(file, source):
    """Collect a file as forensic evidence."""
    from ciicerone.defense.blue_team.forensics import ForensicsCollector

    fc = ForensicsCollector()
    artifact = fc.collect_file(file, source)

    console.print(f"[green]Collected: {artifact.artifact_id}[/green]")
    console.print(f"  Type: {artifact.artifact_type}")
    console.print(f"  Source: {artifact.source}")
    console.print(f"  Size: {artifact.size} bytes")
    if artifact.hash_sha256:
        console.print(f"  SHA256: {artifact.hash_sha256}")


@forensics.command()
@click.option("--case-id", "-c", help="Case ID to report on")
def report(case_id):
    """Generate forensic case report."""
    from ciicerone.defense.blue_team.forensics import ForensicsCollector

    fc = ForensicsCollector(case_id=case_id)
    report_data = fc.generate_report()

    console.print_json(json.dumps(report_data))


@forensics.command()
def stats():
    """Get forensics statistics."""
    from ciicerone.defense.blue_team.forensics import ForensicsCollector

    fc = ForensicsCollector()
    stats = fc.get_stats()

    console.print(Panel.fit(
        f"[cyan]Forensics Statistics[/cyan]\n\n"
        f"Case ID: {stats['case_id']}\n"
        f"Total Artifacts: {stats['total_artifacts']}\n"
        f"Timeline Entries: {stats['total_timeline_entries']}\n"
        f"Total Size: {stats['total_size_mb']} MB\n\n"
        f"By Type: {json.dumps(stats.get('by_type', {}))}",
        title="Forensics Stats",
    ))


# === Dashboard ===

@blue_team.command()
def dashboard():
    """Show blue team dashboard with all component stats."""
    from ciicerone.defense.blue_team.siem_simulator import SIEMSimulator
    from ciicerone.defense.blue_team.ids_detector import IDSDetector
    from ciicerone.defense.blue_team.edr_agent import EDRAgent
    from ciicerone.defense.blue_team.incident_response import IncidentResponse
    from ciicerone.defense.blue_team.threat_hunter import ThreatHunter
    from ciicerone.defense.blue_team.alert_triage import AlertTriage

    siem = _get_siem_simulator()
    ids = IDSDetector()
    edr = EDRAgent()
    ir = IncidentResponse()
    hunter = ThreatHunter()
    triage = AlertTriage()

    siem_stats = siem.get_stats()
    ids_stats = ids.get_stats()
    edr_stats = edr.get_stats()
    ir_stats = ir.get_stats()
    hunt_stats = hunter.get_stats()
    triage_stats = triage.get_stats()

    console.print(Panel.fit(
        f"[bold cyan]Blue Team Dashboard[/bold cyan]\n\n"
        f"[green]SIEM:[/green] {siem_stats['total_logs']} logs, {siem_stats['total_alerts']} alerts, "
        f"{'connected' if siem_stats['connected_to_siem'] else 'simulator'}\n"
        f"[green]IDS:[/green] {ids_stats['total_alerts']} alerts, {ids_stats['active_rules']} rules\n"
        f"[green]EDR:[/green] {edr_stats['total_alerts']} alerts on {edr_stats['host']}\n"
        f"[green]IR:[/green] {ir_stats['total_incidents']} incidents ({ir_stats.get('by_status', {})})\n"
        f"[green]Threat Hunt:[/green] {hunt_stats['hunts_executed']} hunts, {hunt_stats['confirmed_threats']} confirmed\n"
        f"[green]Triage:[/green] {triage_stats['total_triaged']} triaged, {triage_stats['p1_alerts']} P1, "
        f"{triage_stats['fp_rate']:.0f}% FP rate",
        title="Blue Team Status",
    ))
