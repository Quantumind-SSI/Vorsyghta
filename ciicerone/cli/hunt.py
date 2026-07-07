"""CLI commands for threat hunting in Ciicerone.

Provides interactive tools to create, manage, and analyse threat hunting
sessions. Integrates with the intelligence module for CVE lookup, KEV
correlation, and MITRE ATT&CK-aligned hypothesis generation.
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional
from datetime import datetime

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.syntax import Syntax
from rich.tree import Tree

console = Console()
logger = logging.getLogger(__name__)


@click.group(name="hunt")
def hunt_group():
    """Threat hunting — CVE intelligence, hypotheses, and hunt sessions."""


# ---------------------------------------------------------------------------
# CVE lookup
# ---------------------------------------------------------------------------

@hunt_group.command("cve")
@click.argument("cve_id")
@click.option("--format", "-f", type=click.Choice(["table", "json"]), default="table")
def lookup_cve(cve_id: str, format: str):
    """Fetch details for a specific CVE identifier.

    \b
    Example:
        ciicerone hunt cve CVE-2024-3094
    """
    cve_id = cve_id.upper()
    console.print(f"[cyan]Looking up[/cyan] [bold]{cve_id}[/bold]…")

    async def _fetch():
        try:
            import httpx
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                console.print(f"[red]CVE {cve_id} not found in NVD.[/red]")
                return

            cve_data = vulns[0]["cve"]
            desc = next(
                (d["value"] for d in cve_data.get("descriptions", []) if d["lang"] == "en"),
                "No description available.",
            )
            metrics = cve_data.get("metrics", {})
            cvss_list = (
                metrics.get("cvssMetricV31", [])
                or metrics.get("cvssMetricV30", [])
                or metrics.get("cvssMetricV2", [])
            )
            base_score = (
                cvss_list[0]["cvssData"]["baseScore"] if cvss_list else "N/A"
            )
            severity = (
                cvss_list[0]["cvssData"].get("baseSeverity", "N/A") if cvss_list else "N/A"
            )

            if format == "json":
                rendered = json.dumps(cve_data, indent=2, default=str)
                console.print(Syntax(rendered, "json", theme="monokai"))
                return

            sev_color = {
                "CRITICAL": "red",
                "HIGH": "bright_red",
                "MEDIUM": "yellow",
                "LOW": "green",
            }.get(str(severity).upper(), "white")

            console.print(
                Panel(
                    f"[bold]CVE ID:[/bold] {cve_id}\n"
                    f"[bold]CVSS Score:[/bold] {base_score}\n"
                    f"[bold]Severity:[/bold] [{sev_color}]{severity}[/{sev_color}]\n"
                    f"[bold]Published:[/bold] {cve_data.get('published', 'N/A')[:10]}\n\n"
                    f"{desc}",
                    title=f"CVE Details — {cve_id}",
                    border_style=sev_color,
                )
            )

            refs = cve_data.get("references", [])
            if refs:
                console.print("[bold]References:[/bold]")
                for ref in refs[:5]:
                    console.print(f"  • {ref.get('url', '—')}")
                if len(refs) > 5:
                    console.print(f"  … and {len(refs) - 5} more")

        except Exception as exc:
            logger.exception("CVE lookup failed")
            console.print(f"[red]CVE lookup failed:[/red] {exc}")
            raise SystemExit(1)

    asyncio.run(_fetch())


# ---------------------------------------------------------------------------
# KEV check
# ---------------------------------------------------------------------------

@hunt_group.command("kev")
@click.option("--cve", help="Filter to a specific CVE ID")
@click.option("--days", default=30, show_default=True, help="Show KEV entries from last N days")
@click.option("--limit", default=25, show_default=True, help="Max entries to display")
def check_kev(cve: Optional[str], days: int, limit: int):
    """Check CISA's Known Exploited Vulnerabilities (KEV) catalogue.

    Fetches the live KEV feed from CISA and displays recently added entries,
    optionally filtered to a specific CVE.
    """
    console.print("[cyan]Fetching CISA KEV catalogue…[/cyan]")

    async def _fetch():
        try:
            import httpx
            from datetime import timedelta

            url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()

            entries = data.get("vulnerabilities", [])
            cutoff = datetime.utcnow() - timedelta(days=days)

            filtered = []
            for entry in entries:
                if cve and cve.upper() != entry.get("cveID", "").upper():
                    continue
                added = entry.get("dateAdded", "")
                try:
                    if datetime.strptime(added, "%Y-%m-%d") >= cutoff:
                        filtered.append(entry)
                except ValueError:
                    filtered.append(entry)

            filtered = filtered[:limit]

            if not filtered:
                msg = f"No KEV entries found"
                msg += f" for {cve}" if cve else f" in the last {days} days"
                console.print(f"[yellow]{msg}.[/yellow]")
                return

            table = Table(title=f"CISA KEV — last {days} days", show_lines=True)
            table.add_column("CVE ID", style="cyan", no_wrap=True)
            table.add_column("Vendor", style="yellow")
            table.add_column("Product")
            table.add_column("Date Added", style="dim")
            table.add_column("Due Date", style="red")

            for entry in filtered:
                table.add_row(
                    entry.get("cveID", "—"),
                    entry.get("vendorProject", "—"),
                    entry.get("product", "—"),
                    entry.get("dateAdded", "—"),
                    entry.get("dueDate", "—"),
                )

            console.print(table)
            console.print(f"[dim]Total entries in catalogue: {len(entries)}[/dim]")

        except Exception as exc:
            logger.exception("KEV fetch failed")
            console.print(f"[red]KEV fetch failed:[/red] {exc}")
            raise SystemExit(1)

    asyncio.run(_fetch())


# ---------------------------------------------------------------------------
# Hypothesis management
# ---------------------------------------------------------------------------

@hunt_group.command("hypothesis")
@click.option("--target", "-t", required=True, help="Target environment description")
@click.option("--tactic", help="MITRE ATT&CK tactic to focus on (e.g. persistence)")
@click.option("--cve", multiple=True, help="CVE IDs to base hypotheses on")
@click.option("--count", default=5, show_default=True, help="Number of hypotheses to generate")
@click.option("--output", "-o", type=click.Path(path_type=Path))
def generate_hypothesis(
    target: str,
    tactic: Optional[str],
    cve: tuple,
    count: int,
    output: Optional[Path],
):
    """Generate threat hunting hypotheses using AI.

    Uses the configured LLM to produce structured, testable hunting
    hypotheses aligned to MITRE ATT&CK for the given environment.

    \b
    Example:
        ciicerone hunt hypothesis --target "AWS environment with EKS" --tactic persistence
        ciicerone hunt hypothesis --target "Windows AD" --cve CVE-2024-3094 --count 3
    """
    console.print(
        Panel(
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Tactic:[/bold] {tactic or 'all'}\n"
            f"[bold]CVEs:[/bold] {', '.join(cve) if cve else 'none'}\n"
            f"[bold]Count:[/bold] {count}",
            title="Hypothesis Generation",
            border_style="cyan",
        )
    )

    async def _generate():
        try:
            from ciicerone.llm.manager import LLMManager
            from ciicerone.config.models import LLMConfig

            mgr = LLMManager()
            cve_context = f"CVEs of interest: {', '.join(cve)}. " if cve else ""
            tactic_context = f"Focus on the '{tactic}' tactic. " if tactic else ""

            prompt = (
                f"You are a threat hunting expert. Generate {count} structured threat hunting "
                f"hypotheses for: {target}. {tactic_context}{cve_context}"
                "For each hypothesis provide: id, title, tactic (MITRE ATT&CK), technique_id, "
                "description, data_sources (list), hunt_queries (list of pseudo-queries), "
                "priority (critical/high/medium/low). Return JSON array."
            )

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                progress.add_task("Generating hypotheses…", total=None)
                response = await mgr.generate(prompt, max_tokens=2000)

            try:
                import re
                match = re.search(r"\[.*\]", response, re.DOTALL)
                hypotheses = json.loads(match.group(0)) if match else []
            except Exception:
                hypotheses = []
                console.print(f"[yellow]Raw LLM response (JSON parsing failed):[/yellow]\n{response}")

            if hypotheses:
                _display_hypotheses(hypotheses)

                if output:
                    output.write_text(json.dumps(hypotheses, indent=2))
                    console.print(f"[green]Hypotheses saved to {output}[/green]")

        except ImportError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise SystemExit(1)
        except Exception as exc:
            logger.exception("Hypothesis generation failed")
            console.print(f"[red]Generation failed:[/red] {exc}")
            raise SystemExit(1)

    asyncio.run(_generate())


def _display_hypotheses(hypotheses: list) -> None:
    """Render a list of hypothesis dicts as Rich panels."""
    priority_colors = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "green"}
    for hyp in hypotheses:
        prio = str(hyp.get("priority", "medium")).lower()
        color = priority_colors.get(prio, "white")
        console.print(
            Panel(
                f"[bold]Tactic:[/bold] {hyp.get('tactic', '—')}\n"
                f"[bold]Technique:[/bold] {hyp.get('technique_id', '—')}\n"
                f"[bold]Priority:[/bold] [{color}]{prio.upper()}[/{color}]\n\n"
                f"{hyp.get('description', '')}\n\n"
                f"[bold]Data sources:[/bold] {', '.join(hyp.get('data_sources', []))}\n"
                f"[bold]Hunt queries:[/bold]\n"
                + "\n".join(f"  • {q}" for q in hyp.get("hunt_queries", [])),
                title=f"[{color}]{hyp.get('title', 'Hypothesis')}[/{color}]",
                border_style=color,
            )
        )


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

@hunt_group.command("session")
@click.argument("action", type=click.Choice(["start", "list", "show", "close"]))
@click.option("--id", "session_id", help="Session ID (for show/close)")
@click.option("--target", help="Target environment (for start)")
@click.option("--name", help="Session name (for start)")
def manage_session(action: str, session_id: Optional[str], target: Optional[str], name: Optional[str]):
    """Manage threat hunting sessions.

    \b
    Actions:
        start  — Begin a new hunting session
        list   — List all sessions
        show   — Show details of a session
        close  — Mark a session as complete
    """
    session_file = Path.home() / ".ciicerone" / "hunt_sessions.json"
    session_file.parent.mkdir(parents=True, exist_ok=True)

    sessions: list = []
    if session_file.exists():
        try:
            sessions = json.loads(session_file.read_text())
        except Exception:
            sessions = []

    if action == "start":
        if not target:
            console.print("[red]--target is required to start a session.[/red]")
            raise SystemExit(1)
        new_id = f"hunt-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        session = {
            "id": new_id,
            "name": name or f"Hunt {datetime.utcnow().strftime('%Y-%m-%d')}",
            "target": target,
            "status": "active",
            "created_at": datetime.utcnow().isoformat(),
            "hypotheses": [],
            "findings": [],
        }
        sessions.append(session)
        session_file.write_text(json.dumps(sessions, indent=2))
        console.print(
            Panel(
                f"[bold]Session ID:[/bold] {new_id}\n"
                f"[bold]Target:[/bold] {target}\n"
                f"[bold]Status:[/bold] [green]active[/green]",
                title="Hunt Session Started",
                border_style="green",
            )
        )

    elif action == "list":
        if not sessions:
            console.print("[yellow]No hunt sessions found.[/yellow]")
            return
        table = Table(title="Hunt Sessions", show_lines=True)
        table.add_column("ID", style="cyan")
        table.add_column("Name")
        table.add_column("Target", style="yellow")
        table.add_column("Status")
        table.add_column("Created")
        for s in sessions:
            status_color = "green" if s["status"] == "active" else "dim"
            table.add_row(
                s["id"],
                s["name"],
                s["target"],
                f"[{status_color}]{s['status']}[/{status_color}]",
                s.get("created_at", "—")[:16],
            )
        console.print(table)

    elif action == "show":
        if not session_id:
            console.print("[red]--id is required for 'show'.[/red]")
            raise SystemExit(1)
        matching = [s for s in sessions if s["id"] == session_id]
        if not matching:
            console.print(f"[red]Session {session_id} not found.[/red]")
            raise SystemExit(1)
        console.print(Syntax(json.dumps(matching[0], indent=2), "json", theme="monokai"))

    elif action == "close":
        if not session_id:
            console.print("[red]--id is required for 'close'.[/red]")
            raise SystemExit(1)
        for s in sessions:
            if s["id"] == session_id:
                s["status"] = "closed"
                s["closed_at"] = datetime.utcnow().isoformat()
                break
        else:
            console.print(f"[red]Session {session_id} not found.[/red]")
            raise SystemExit(1)
        session_file.write_text(json.dumps(sessions, indent=2))
        console.print(f"[green]Session {session_id} closed.[/green]")
