"""CLI commands for the Vorsyghta AI attack-agent subsystem.

Wires the :class:`~vorsyghta.vm.agent.AIAttackAgent` (LLM-driven attack planner
and executor) to Click commands so operators can plan, run, and monitor
autonomous red-team exercises from the terminal.
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.syntax import Syntax

console = Console()
logger = logging.getLogger(__name__)


@click.group(name="agent")
def agent_group():
    """Autonomous AI attack-agent management."""


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _build_agent():
    """Construct an AIAttackAgent with default LLM + Docker VM operator."""
    from vorsyghta.llm.manager import LLMManager
    from vorsyghta.vm.operator import VMOperator
    from vorsyghta.vm.agent import AIAttackAgent
    from vorsyghta.vm.models import InfrastructureConfig, HypervisorType

    llm = LLMManager()
    infra = InfrastructureConfig(hypervisor_type=HypervisorType.DOCKER)
    vm_op = VMOperator(infra)
    return AIAttackAgent(llm_manager=llm, vm_operator=vm_op)


def _load_scenario(config_path: Optional[Path]) -> dict:
    """Load scenario dict from JSON/YAML file, or return a sensible default."""
    if config_path and config_path.exists():
        import json as _json
        try:
            return _json.loads(config_path.read_text())
        except Exception:
            pass
    return {
        "name": "Generic Red-Team Exercise",
        "threat_type": "lateral_movement",
        "max_steps": 20,
        "stealth_level": "medium",
        "objectives": ["initial_access", "privilege_escalation", "data_exfiltration"],
    }


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

@agent_group.command("run")
@click.argument("target_host")
@click.option("--config", "-c", type=click.Path(path_type=Path), help="Scenario config JSON")
@click.option("--scenario", "-s", default="generic", help="Attack scenario name")
@click.option("--attacker-vm", default="attacker-1", show_default=True,
              help="Attacker VM identifier")
@click.option("--max-steps", default=20, show_default=True, help="Maximum agent steps")
@click.option("--timeout", default=60, show_default=True, help="Timeout in minutes")
@click.option("--dry-run", is_flag=True, help="Plan only — do not execute commands")
@click.option("--output", "-o", type=click.Path(path_type=Path), help="Save results to file")
def run_agent(
    target_host: str,
    config: Optional[Path],
    scenario: str,
    attacker_vm: str,
    max_steps: int,
    timeout: int,
    dry_run: bool,
    output: Optional[Path],
):
    """Run an autonomous AI attack agent against TARGET_HOST.

    The agent uses the configured LLM to plan attack steps following MITRE
    ATT&CK tactics (recon → initial access → privilege escalation → impact).

    \b
    Examples:
        vorsyghta agent run 192.168.1.100 --scenario lateral_movement
        vorsyghta agent run 10.0.0.5 --dry-run --max-steps 10
    """
    scenario_dict = _load_scenario(config)
    scenario_dict.setdefault("name", scenario)
    scenario_dict["max_steps"] = max_steps
    scenario_dict["timeout_minutes"] = timeout

    mode_label = "[yellow]DRY RUN[/yellow]" if dry_run else "[red]LIVE[/red]"
    console.print(
        Panel(
            f"[bold]Target:[/bold]      {target_host}\n"
            f"[bold]Scenario:[/bold]    {scenario_dict['name']}\n"
            f"[bold]Attacker VM:[/bold] {attacker_vm}\n"
            f"[bold]Mode:[/bold]        {mode_label}\n"
            f"[bold]Max steps:[/bold]   {max_steps}   "
            f"[bold]Timeout:[/bold] {timeout} min",
            title="Vorsyghta AI Agent",
            border_style="red",
        )
    )

    async def _run():
        try:
            agent = _build_agent()

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                task_id = progress.add_task("Planning attack…", total=None)

                target_info = {"host": target_host, "dry_run": dry_run}
                plan = await agent.plan_attack(scenario_dict, target_info)

                progress.update(task_id, description="Executing attack…")

                if dry_run:
                    progress.update(task_id, description="[green]Plan complete (dry run)[/green]")
                    _display_plan(plan)
                else:
                    result = await agent.execute_attack(
                        plan=plan,
                        attacker_vm=attacker_vm,
                        target_vms=[target_host],
                    )
                    progress.update(task_id, description="[green]Complete[/green]")
                    _display_attack_result(result)

                    if output:
                        result_dict = result.model_dump() if hasattr(result, "model_dump") else vars(result)
                        output.write_text(json.dumps(result_dict, indent=2, default=str))
                        console.print(f"[green]Results saved to {output}[/green]")

        except ImportError as exc:
            console.print(f"[red]Missing dependency:[/red] {exc}")
            raise SystemExit(1)
        except Exception as exc:
            logger.exception("Agent execution failed")
            console.print(f"[red]Agent failed:[/red] {exc}")
            raise SystemExit(1)

    asyncio.run(_run())


@agent_group.command("plan")
@click.argument("target_host")
@click.option("--config", "-c", type=click.Path(path_type=Path))
@click.option("--scenario", "-s", default="generic")
@click.option("--format", "-f", type=click.Choice(["table", "json", "text"]), default="table")
@click.option("--output", "-o", type=click.Path(path_type=Path))
def plan_agent(
    target_host: str,
    config: Optional[Path],
    scenario: str,
    format: str,
    output: Optional[Path],
):
    """Generate a MITRE ATT&CK attack plan WITHOUT executing any commands.

    Produces a step-by-step plan that can be reviewed before live execution.
    """
    scenario_dict = _load_scenario(config)
    scenario_dict.setdefault("name", scenario)
    console.print(f"[cyan]Generating attack plan for[/cyan] [bold]{target_host}[/bold]…")

    async def _plan():
        try:
            agent = _build_agent()
            target_info = {"host": target_host, "dry_run": True}
            plan = await agent.plan_attack(scenario_dict, target_info)

            if format == "json":
                plan_dict = plan.model_dump() if hasattr(plan, "model_dump") else vars(plan)
                rendered = json.dumps(plan_dict, indent=2, default=str)
                console.print(Syntax(rendered, "json", theme="monokai"))
            elif format == "text":
                for i, step in enumerate(plan.steps, 1):
                    console.print(
                        f"{i}. [{step.phase.value}] {step.description}"
                    )
            else:
                _display_plan(plan)

            if output:
                plan_dict = plan.model_dump() if hasattr(plan, "model_dump") else vars(plan)
                output.write_text(json.dumps(plan_dict, indent=2, default=str))
                console.print(f"[green]Plan saved to {output}[/green]")

        except ImportError as exc:
            console.print(f"[red]Missing dependency:[/red] {exc}")
            raise SystemExit(1)
        except Exception as exc:
            logger.exception("Plan generation failed")
            console.print(f"[red]Planning failed:[/red] {exc}")
            raise SystemExit(1)

    asyncio.run(_plan())


@agent_group.command("status")
@click.argument("session_id", required=False)
def agent_status(session_id: Optional[str]):
    """Show the status of running or recent agent sessions."""
    from vorsyghta.core.simulation_logger import SimulationLogger

    log = SimulationLogger()
    sessions = log.list_simulations(limit=20)

    if not sessions:
        console.print("[yellow]No agent sessions found.[/yellow]")
        return

    if session_id:
        sessions = [s for s in sessions if session_id in str(s.get("simulation_id", ""))]
        if not sessions:
            console.print(f"[red]No session found matching ID: {session_id}[/red]")
            return

    table = Table(title="Agent Sessions", show_lines=True)
    table.add_column("Session ID", style="cyan")
    table.add_column("Threat Type", style="yellow")
    table.add_column("Status")
    table.add_column("Stages")
    table.add_column("Timestamp")

    for s in sessions:
        status_str = "[green]Success[/green]" if s.get("success") else "[red]Failed[/red]"
        table.add_row(
            str(s.get("simulation_id", "—"))[:16] + "…",
            s.get("threat_type", "—"),
            status_str,
            str(s.get("completed_stages", "—")),
            str(s.get("timestamp", "—"))[:19],
        )

    console.print(table)


@agent_group.command("abort")
@click.argument("session_id")
@click.confirmation_option(prompt="Abort this agent session?")
def abort_agent(session_id: str):
    """Abort a running agent session by SESSION_ID."""
    abort_flag_path = Path(f"/tmp/vorsyghta-abort-{session_id}")
    abort_flag_path.touch()
    console.print(
        f"[green]Abort signal written.[/green] The agent will stop after its current step.\n"
        f"Flag: {abort_flag_path}"
    )


# ---------------------------------------------------------------------------
# display helpers
# ---------------------------------------------------------------------------

def _display_plan(plan) -> None:
    """Render an AttackPlan as a Rich table."""
    table = Table(title=f"Attack Plan — {plan.name}", show_lines=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Phase", style="yellow")
    table.add_column("Technique", style="cyan")
    table.add_column("Description")
    table.add_column("Commands")

    for i, step in enumerate(plan.steps, 1):
        cmds = "\n".join(step.commands[:3]) if step.commands else "—"
        if len(step.commands) > 3:
            cmds += f"\n… +{len(step.commands) - 3} more"
        table.add_row(
            str(i),
            step.phase.value,
            step.technique_id or "—",
            step.description[:80],
            cmds,
        )

    console.print(table)
    if plan.objectives:
        console.print("[bold]Objectives:[/bold] " + ", ".join(plan.objectives))
    if plan.mitre_techniques:
        console.print("[bold]MITRE techniques:[/bold] " + ", ".join(plan.mitre_techniques))


def _display_attack_result(result) -> None:
    """Render an AttackResult as Rich panels."""
    success = result.success if hasattr(result, "success") else (result.objectives_completed > 0)
    color = "green" if success else "red"
    label = "SUCCESS" if success else "FAILED"

    console.print(
        Panel(
            f"[bold {color}]{label}[/bold {color}]\n"
            f"Objectives completed: {result.objectives_completed} / "
            f"{result.objectives_total}\n"
            f"Steps executed: {result.action_count}\n"
            f"Hosts compromised: {len(result.compromised_hosts)}\n"
            f"Credentials captured: {result.credentials_captured}\n"
            f"Duration: {result.duration_seconds:.1f}s",
            title="Agent Results",
            border_style=color,
        )
    )

    if result.executive_summary:
        console.print(Panel(result.executive_summary, title="Executive Summary",
                            border_style="blue"))

    if result.recommendations:
        console.print("[bold]Recommendations:[/bold]")
        for rec in result.recommendations:
            console.print(f"  • {rec}")
