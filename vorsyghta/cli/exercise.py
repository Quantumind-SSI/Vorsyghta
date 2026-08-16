"""Exercise CLI commands for Vorsyghta.

Provides the `vorsyghta exercise run` command that chains Red Team →
Blue Team → Purple Team → Black Team in a single integrated exercise.

Usage:
    vorsyghta exercise run --scenario templates/finance_bec.yaml
    vorsyghta exercise run --scenario-name "BEC Wire Fraud" --teams red,blue,purple
    vorsyghta exercise run --tenant bank-abc --json-output
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from vorsyghta.core.exercise_orchestrator import ExerciseOrchestrator
from vorsyghta.core.models import ThreatScenario, ThreatType

console = Console()
logger = logging.getLogger(__name__)


@click.group(name="exercise")
def exercise_group():
    """Color-team exercise commands (red → blue → purple → black)."""
    pass


@exercise_group.command(name="run")
@click.option(
    "--scenario",
    "scenario_file",
    type=click.Path(exists=False),
    default=None,
    help="Path to a YAML scenario file.",
)
@click.option(
    "--scenario-name",
    default="BEC Wire Fraud — Bank Pilot",
    show_default=True,
    help="Scenario name (used when no YAML file is provided).",
)
@click.option(
    "--threat-type",
    default="phishing",
    show_default=True,
    type=click.Choice(
        ["phishing", "ransomware", "insider_threat", "supply_chain", "apt", "custom"],
        case_sensitive=False,
    ),
    help="Threat type for generated scenarios.",
)
@click.option(
    "--teams",
    default="red,blue,purple,black",
    show_default=True,
    help="Comma-separated list of teams to activate.",
)
@click.option(
    "--tenant",
    default="default",
    show_default=True,
    help="Tenant ID for the exercise.",
)
@click.option(
    "--exercise-id",
    default=None,
    help="Optional exercise ID (auto-generated if not provided).",
)
@click.option(
    "--json-output",
    is_flag=True,
    default=False,
    help="Output the full exercise result as JSON.",
)
@click.option(
    "--output-file",
    type=click.Path(),
    default=None,
    help="Write JSON result to this file.",
)
def run_exercise(
    scenario_file: Optional[str],
    scenario_name: str,
    threat_type: str,
    teams: str,
    tenant: str,
    exercise_id: Optional[str],
    json_output: bool,
    output_file: Optional[str],
) -> None:
    """Run a full color-team exercise: Red → Blue → Purple → Black.

    \b
    Examples:
        vorsyghta exercise run
        vorsyghta exercise run --scenario templates/finance_bec.yaml
        vorsyghta exercise run --teams red,blue,purple --tenant bank-abc
        vorsyghta exercise run --json-output --output-file results/exercise.json
    """
    team_list = [t.strip().lower() for t in teams.split(",") if t.strip()]

    # Load scenario
    scenario = _load_scenario(scenario_file, scenario_name, threat_type)

    console.print(Panel(
        f"[bold cyan]Vorsyghta Color-Team Exercise[/bold cyan]\n"
        f"Scenario: [green]{scenario.name}[/green]\n"
        f"Teams:    [yellow]{', '.join(team_list)}[/yellow]\n"
        f"Tenant:   [dim]{tenant}[/dim]",
        title="Exercise Starting",
    ))

    result = asyncio.run(_async_run(scenario, team_list, tenant, exercise_id))

    # Display results
    _display_results(result)

    if json_output or output_file:
        result_dict = result.to_dict()
        json_str = json.dumps(result_dict, indent=2, default=str)

        if json_output:
            console.print("\n[bold]Exercise Result JSON:[/bold]")
            console.print(json_str)

        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            Path(output_file).write_text(json_str, encoding="utf-8")
            console.print(f"\n[green]Result written to {output_file}[/green]")

    # Exit with non-zero if exercise failed
    if result.status != "completed":
        console.print(f"[red]Exercise failed: {result.errors}[/red]")
        sys.exit(1)


async def _async_run(scenario, teams, tenant, exercise_id):
    orchestrator = ExerciseOrchestrator(tenant_id=tenant)
    return await orchestrator.run_exercise(
        scenario=scenario,
        teams=teams,
        exercise_id=exercise_id,
    )


def _load_scenario(
    scenario_file: Optional[str],
    scenario_name: str,
    threat_type: str,
) -> ThreatScenario:
    """Load a ThreatScenario from a YAML file or build one from flags."""
    if scenario_file:
        path = Path(scenario_file)
        if not path.exists():
            console.print(f"[red]Scenario file not found: {scenario_file}[/red]")
            sys.exit(1)
        try:
            import yaml
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            return ThreatScenario(
                name=data.get("name", path.stem),
                threat_type=ThreatType(data.get("threat_type", "custom")),
                description=data.get("description", ""),
                target_systems=data.get("target_systems", []),
                attack_vectors=data.get("attack_vectors", []),
                metadata=data.get("metadata", {}),
            )
        except Exception as exc:
            console.print(f"[red]Failed to load scenario file: {exc}[/red]")
            sys.exit(1)

    # Build from flags
    threat_type_map = {
        "phishing": ThreatType.PHISHING,
        "ransomware": ThreatType.RANSOMWARE,
        "insider_threat": ThreatType.INSIDER_THREAT,
        "supply_chain": ThreatType.SUPPLY_CHAIN,
        "apt": ThreatType.APT,
        "custom": ThreatType.CUSTOM,
    }
    tt = threat_type_map.get(threat_type.lower(), ThreatType.CUSTOM)

    return ThreatScenario(
        name=scenario_name,
        threat_type=tt,
        description=(
            f"Automated {threat_type} exercise for pilot validation. "
            "Generated by `vorsyghta exercise run`."
        ),
        target_systems=["email", "wire-transfer-system", "internal-network"],
        attack_vectors=["spear-phishing", "business-email-compromise"],
    )


def _display_results(result) -> None:
    """Print a human-readable exercise summary to the console."""
    status_color = "green" if result.status == "completed" else "red"
    console.print(f"\n[bold]Exercise {result.exercise_id}[/bold] — "
                  f"[{status_color}]{result.status.upper()}[/{status_color}]")

    # Red team summary
    console.print(f"\n[bold red]Red Team[/bold red]: {len(result.red_team_stages)} attack stage(s) executed")

    # Blue team summary
    if result.blue_team_alerts:
        detected = sum(
            1 for a in result.blue_team_alerts
            if a.get("payload", a).get("detected", False)
        )
        total = len(result.blue_team_alerts)
        rate = round(detected / total * 100) if total else 0
        console.print(
            f"[bold blue]Blue Team[/bold blue]: {detected}/{total} alerts detected ({rate}%)"
        )

    # Purple team AAR summary
    if result.aar:
        summary = result.aar.get("summary", "AAR generated.")
        console.print(f"\n[bold purple]Purple Team AAR[/bold purple]:\n  {summary}")

        gaps = result.aar.get("coverage_gaps", [])
        if gaps:
            console.print(f"\n  [yellow]Coverage Gaps ({len(gaps)}):[/yellow]")
            for gap in gaps[:5]:
                console.print(
                    f"    • {gap.get('technique_id')} ({gap.get('tactic', 'unknown')})"
                    f" — {gap.get('stage_name', '')}"
                )
            if len(gaps) > 5:
                console.print(f"    ... and {len(gaps) - 5} more")

        rems = result.aar.get("remediation_recommendations", [])
        if rems:
            console.print(f"\n  [bold]Top Remediation ({min(3, len(rems))}):[/bold]")
            for rem in rems[:3]:
                console.print(f"    {rem['priority']}. [{rem['technique_id']}] {rem['recommendation']}")

    # Black team score
    if result.score:
        overall = result.score.get("overall_score", 0)
        rating = result.score.get("rating", "?")
        console.print(
            f"\n[bold]Black Team Score[/bold]: [green]{overall:.2f}[/green] / 1.00 "
            f"(Grade: [bold]{rating}[/bold])"
        )
        cs = result.score.get("component_scores", {})
        tbl = Table(show_header=True, header_style="bold")
        tbl.add_column("Component")
        tbl.add_column("Score", justify="right")
        for k, v in cs.items():
            tbl.add_row(k.replace("_", " ").title(), f"{v:.3f}")
        console.print(tbl)

    if result.errors:
        console.print(f"\n[red]Errors:[/red]")
        for err in result.errors:
            console.print(f"  • {err}")
