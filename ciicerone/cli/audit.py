"""CLI commands for the Ciicerone audit trail.

Provides tools to view, filter, and export the structured audit log
produced by the platform's :mod:`ciicerone.core.audit_logger` module.
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from ciicerone.core.audit_logger import (
    AuditCategory,
    AuditEvent,
    AuditSeverity,
    get_audit_logger,
)

console = Console()
logger = logging.getLogger(__name__)

_SEVERITY_COLORS = {
    "EMERGENCY": "bold red",
    "ALERT": "red",
    "CRITICAL": "bright_red",
    "ERROR": "red",
    "WARNING": "yellow",
    "NOTICE": "cyan",
    "INFO": "green",
    "DEBUG": "dim",
}


@click.group(name="audit")
def audit_group():
    """View and export the Ciicerone audit trail."""


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _load_events_from_file(log_path: Path, limit: int = 500) -> list:
    """Read events from a JSONL audit log file (newest-last order)."""
    events = []
    if not log_path.exists():
        return events
    with log_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events[-limit:]


def _default_log_path() -> Optional[Path]:
    """Return the default audit log path from env or well-known location."""
    import os
    env = os.environ.get("CIICERONE_AUDIT_LOG_PATH")
    if env:
        return Path(env)
    candidate = Path.home() / ".ciicerone" / "audit.log"
    if candidate.exists():
        return candidate
    return None


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

@audit_group.command("list")
@click.option("--log", "-l", type=click.Path(path_type=Path), help="Audit log file path")
@click.option("--limit", default=50, show_default=True, help="Number of events to show")
@click.option(
    "--category",
    type=click.Choice([c.value for c in AuditCategory]),
    help="Filter by category",
)
@click.option(
    "--severity",
    type=click.Choice([s.value for s in AuditSeverity]),
    help="Minimum severity to show",
)
@click.option("--days", type=int, help="Show events from last N days")
@click.option("--actor", help="Filter by actor user_id or email (substring match)")
@click.option("--event-type", help="Filter by event_type (substring match)")
def list_events(
    log: Optional[Path],
    limit: int,
    category: Optional[str],
    severity: Optional[str],
    days: Optional[int],
    actor: Optional[str],
    event_type: Optional[str],
):
    """List audit events with optional filtering.

    Reads from the audit log file set by CIICERONE_AUDIT_LOG_PATH or
    the default ~/.ciicerone/audit.log.  Falls back to the in-process
    MemoryAuditSink if no file is available.
    """
    log_path = log or _default_log_path()

    if log_path:
        raw_events = _load_events_from_file(log_path, limit=limit * 4)
    else:
        # Fall back to the in-process memory sink
        audit = get_audit_logger()
        from ciicerone.core.audit_logger import MemoryAuditSink
        mem_sinks = [s for s in audit.sinks if isinstance(s, MemoryAuditSink)]
        raw_events = [e.to_dict() for s in mem_sinks for e in s.events]

    # ----- filtering -----
    severity_order = {
        "EMERGENCY": 0, "ALERT": 1, "CRITICAL": 2, "ERROR": 3,
        "WARNING": 4, "NOTICE": 5, "INFO": 6, "DEBUG": 7,
    }
    min_sev_rank = severity_order.get(severity, 99) if severity else 99
    cutoff = datetime.utcnow() - timedelta(days=days) if days else None

    filtered = []
    for ev in raw_events:
        if category and ev.get("category") != category:
            continue
        if severity:
            ev_rank = severity_order.get(ev.get("severity", "INFO"), 99)
            if ev_rank > min_sev_rank:
                continue
        if actor:
            ev_actor = json.dumps(ev.get("actor", {}))
            if actor.lower() not in ev_actor.lower():
                continue
        if event_type and event_type.lower() not in ev.get("event_type", "").lower():
            continue
        if cutoff:
            ts_str = ev.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if ts.replace(tzinfo=None) < cutoff:
                    continue
            except ValueError:
                pass
        filtered.append(ev)

    filtered = filtered[-limit:]

    if not filtered:
        console.print("[yellow]No audit events match the filter criteria.[/yellow]")
        return

    table = Table(title=f"Audit Events ({len(filtered)} shown)", show_lines=True)
    table.add_column("Timestamp", style="dim", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Category", style="cyan")
    table.add_column("Event Type", style="bold")
    table.add_column("Actor")
    table.add_column("Description")

    for ev in filtered:
        sev = ev.get("severity", "INFO")
        sev_color = _SEVERITY_COLORS.get(sev, "white")
        actor_info = ev.get("actor", {})
        actor_label = actor_info.get("user_id") or actor_info.get("email") or "—"
        table.add_row(
            str(ev.get("timestamp", "—"))[:19],
            f"[{sev_color}]{sev}[/{sev_color}]",
            ev.get("category", "—"),
            ev.get("event_type", "—"),
            actor_label,
            (ev.get("description") or "")[:80],
        )

    console.print(table)


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------

@audit_group.command("show")
@click.argument("event_type_filter")
@click.option("--log", "-l", type=click.Path(path_type=Path))
@click.option("--limit", default=10, show_default=True)
@click.option("--format", "-f", type=click.Choice(["json", "pretty"]), default="pretty")
def show_event(event_type_filter: str, log: Optional[Path], limit: int, format: str):
    """Show full details of events matching EVENT_TYPE_FILTER.

    EVENT_TYPE_FILTER is a case-insensitive substring match against the
    event_type field (e.g. 'login', 'simulation.started').
    """
    log_path = log or _default_log_path()
    raw_events = _load_events_from_file(log_path, limit=5000) if log_path else []

    matching = [
        ev for ev in raw_events
        if event_type_filter.lower() in ev.get("event_type", "").lower()
    ][-limit:]

    if not matching:
        console.print(f"[yellow]No events matching '{event_type_filter}'.[/yellow]")
        return

    for ev in matching:
        if format == "json":
            console.print(Syntax(json.dumps(ev, indent=2, default=str), "json", theme="monokai"))
        else:
            sev = ev.get("severity", "INFO")
            sev_color = _SEVERITY_COLORS.get(sev, "white")
            ctx_str = json.dumps(ev.get("context", {}), indent=2)
            console.print(
                Panel(
                    f"[bold]Timestamp:[/bold] {ev.get('timestamp', '—')}\n"
                    f"[bold]Category:[/bold]  {ev.get('category', '—')}\n"
                    f"[bold]Severity:[/bold]  [{sev_color}]{sev}[/{sev_color}]\n"
                    f"[bold]Actor:[/bold]     {json.dumps(ev.get('actor', {}))}\n"
                    f"[bold]Target:[/bold]    {json.dumps(ev.get('target', {}))}\n"
                    f"[bold]Description:[/bold] {ev.get('description') or '—'}\n\n"
                    f"[bold]Context:[/bold]\n{ctx_str}",
                    title=ev.get("event_type", "Audit Event"),
                    border_style=sev_color,
                )
            )


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------

@audit_group.command("export")
@click.option("--log", "-l", type=click.Path(path_type=Path), help="Source audit log file")
@click.option(
    "--output", "-o", required=True, type=click.Path(path_type=Path), help="Destination file"
)
@click.option(
    "--format", "-f", type=click.Choice(["json", "csv", "jsonl"]), default="json"
)
@click.option("--category", type=click.Choice([c.value for c in AuditCategory]))
@click.option("--days", type=int, help="Restrict to last N days")
def export_events(
    log: Optional[Path],
    output: Path,
    format: str,
    category: Optional[str],
    days: Optional[int],
):
    """Export audit events to a file in JSON, JSONL, or CSV format.

    \b
    Example:
        ciicerone audit export -o report.json --format json --days 7
        ciicerone audit export -o report.csv --format csv --category authentication
    """
    log_path = log or _default_log_path()
    if not log_path:
        console.print("[red]No audit log file found. Set CIICERONE_AUDIT_LOG_PATH.[/red]")
        raise SystemExit(1)

    raw_events = _load_events_from_file(log_path, limit=100_000)

    cutoff = datetime.utcnow() - timedelta(days=days) if days else None
    filtered = []
    for ev in raw_events:
        if category and ev.get("category") != category:
            continue
        if cutoff:
            ts_str = ev.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if ts.replace(tzinfo=None) < cutoff:
                    continue
            except ValueError:
                pass
        filtered.append(ev)

    if format == "json":
        output.write_text(json.dumps(filtered, indent=2, default=str), encoding="utf-8")
    elif format == "jsonl":
        with output.open("w", encoding="utf-8") as fh:
            for ev in filtered:
                fh.write(json.dumps(ev, default=str) + "\n")
    elif format == "csv":
        import csv
        fieldnames = ["timestamp", "severity", "category", "event_type", "actor", "description", "correlation_id"]
        with output.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for ev in filtered:
                row = {
                    "timestamp": ev.get("timestamp", ""),
                    "severity": ev.get("severity", ""),
                    "category": ev.get("category", ""),
                    "event_type": ev.get("event_type", ""),
                    "actor": json.dumps(ev.get("actor", {})),
                    "description": ev.get("description", ""),
                    "correlation_id": ev.get("correlation_id", ""),
                }
                writer.writerow(row)

    console.print(
        f"[green]Exported {len(filtered)} events to[/green] [bold]{output}[/bold] "
        f"[dim]({format})[/dim]"
    )


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------

@audit_group.command("stats")
@click.option("--log", "-l", type=click.Path(path_type=Path))
@click.option("--days", default=7, show_default=True, help="Window in days")
def audit_stats(log: Optional[Path], days: int):
    """Show audit event statistics for the last N days."""
    log_path = log or _default_log_path()
    raw_events = _load_events_from_file(log_path, limit=100_000) if log_path else []

    cutoff = datetime.utcnow() - timedelta(days=days)
    recent = []
    for ev in raw_events:
        ts_str = ev.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if ts.replace(tzinfo=None) >= cutoff:
                recent.append(ev)
        except ValueError:
            recent.append(ev)

    if not recent:
        console.print(f"[yellow]No audit events in the last {days} days.[/yellow]")
        return

    # category counts
    cat_counts: dict = {}
    sev_counts: dict = {}
    for ev in recent:
        cat = ev.get("category", "unknown")
        sev = ev.get("severity", "INFO")
        cat_counts[cat] = cat_counts.get(cat, 0) + 1
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    console.print(
        Panel(
            f"[bold]Total events:[/bold] {len(recent)}\n"
            f"[bold]Window:[/bold] last {days} days",
            title="Audit Statistics",
            border_style="blue",
        )
    )

    cat_table = Table(title="By Category", show_lines=True)
    cat_table.add_column("Category", style="cyan")
    cat_table.add_column("Count", justify="right")
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        cat_table.add_row(cat, str(count))
    console.print(cat_table)

    sev_table = Table(title="By Severity", show_lines=True)
    sev_table.add_column("Severity")
    sev_table.add_column("Count", justify="right")
    sev_order = ["EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG"]
    for sev in sev_order:
        if sev in sev_counts:
            color = _SEVERITY_COLORS.get(sev, "white")
            sev_table.add_row(f"[{color}]{sev}[/{color}]", str(sev_counts[sev]))
    console.print(sev_table)
