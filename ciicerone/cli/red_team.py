"""Red Team CLI commands for Ciicerone.

Provides commands for launching and monitoring autonomous penetration
testing flows. By default, attacks run standalone via the
AttackOrchestrator and the local tool server — no external API is
required. Use --legacy to fall back to the external Ciicerone Attack
API (requires CIICERONE_ATTACK_API_URL and CIICERONE_ATTACK_API_TOKEN).
"""

import asyncio
import json
import os
import sys
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.markdown import Markdown

console = Console()


def _get_integration():
    """Get Ciicerone Attack integration instance."""
    from ciicerone.integrations import AttackIntegration

    return AttackIntegration()


def _load_scenario(scenario_path: str) -> dict:
    """Load a scenario from YAML file."""
    import yaml

    with open(scenario_path, "r") as f:
        return yaml.safe_load(f)


async def _auto_generate_payloads(
    scenario_path: str,
    content_type: str,
    variants: int,
) -> Optional[dict]:
    """Auto-generate threat content payloads using the configured LLM provider.

    Args:
        scenario_path: Path to the scenario YAML file
        content_type: Content type (email_phishing, sms, phone_script, web_page, social_post, document)
        variants: Number of variants to generate

    Returns:
        Dict mapping content_type to generated content, or None on failure
    """
    from pathlib import Path
    from ..config.yaml_loader import YAMLConfigLoader
    from ..llm import (
        ContentGenerationService,
        ContentType,
        LLMProvider,
        LLMProviderConfig,
        LLMProviderManager,
        LLMModel,
    )

    loader = YAMLConfigLoader()
    try:
        config_data = loader.load_config(Path(scenario_path))
        scenario = loader.validate_threat_scenario(config_data)
        scenario_data = {
            "name": scenario.metadata.name,
            "threat_type": scenario.threat_type.value if hasattr(scenario.threat_type, "value") else str(scenario.threat_type),
            "description": scenario.metadata.description,
            "difficulty": scenario.difficulty_level,
            "target_profile": config_data.get("target_profile", {}),
            "attack_content": config_data.get("attack_content", {}),
        }
    except Exception as e:
        console.print(f"[red]Failed to load scenario for payload generation: {e}[/red]")
        return None

    provider_manager = LLMProviderManager()

    openai_key = os.environ.get("OPENAI_API_KEY")
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    openrouter_key = os.environ.get("OPENROUTER_API_KEY")
    azure_key = os.environ.get("AZURE_OPENAI_API_KEY")
    azure_endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
    azure_deployment = os.environ.get("AZURE_OPENAI_DEPLOYMENT")
    azure_api_version = os.environ.get("AZURE_OPENAI_API_VERSION")

    providers_configured = 0

    if azure_key and azure_endpoint:
        try:
            from ..llm.providers.azure_provider import AzureOpenAIProvider
            azure_provider = AzureOpenAIProvider({
                "api_key": azure_key,
                "endpoint": azure_endpoint,
                "deployment": azure_deployment or "gpt-4o",
                "api_version": azure_api_version or "2024-10-21",
                "model": azure_deployment or "gpt-4o",
            })
            # Inject directly into manager since LLMProvider enum has no AZURE value
            provider_manager.providers[LLMProvider.OPENAI] = azure_provider
            provider_manager.default_provider = LLMProvider.OPENAI
            providers_configured += 1
        except Exception as e:
            console.print(f"[yellow]Azure OpenAI setup failed: {e}. Trying other providers.[/yellow]")

    if openai_key and providers_configured == 0:
        config = LLMProviderConfig(
            provider=LLMProvider.OPENAI,
            api_key=openai_key,
            default_model=LLMModel.GPT_35_TURBO,
        )
        provider_manager.add_provider(config, set_as_default=providers_configured == 0)
        providers_configured += 1

    if anthropic_key:
        config = LLMProviderConfig(
            provider=LLMProvider.ANTHROPIC,
            api_key=anthropic_key,
            default_model=LLMModel.CLAUDE_3_HAIKU,
        )
        provider_manager.add_provider(config, set_as_default=providers_configured == 0)
        providers_configured += 1

    if openrouter_key:
        config = LLMProviderConfig(
            provider=LLMProvider.OPENROUTER,
            api_key=openrouter_key,
            default_model=LLMModel.GPT_35_TURBO,
        )
        provider_manager.add_provider(config, set_as_default=providers_configured == 0)
        providers_configured += 1

    if providers_configured == 0:
        console.print("[yellow]No LLM provider configured. Set OPENAI_API_KEY, ANTHROPIC_API_KEY, OPENROUTER_API_KEY, or AZURE_OPENAI_API_KEY + AZURE_OPENAI_ENDPOINT.[/yellow]")
        return None

    generation_service = ContentGenerationService(provider_manager)

    try:
        content_type_enum = ContentType(content_type)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Generating {variants} {content_type} payload(s)...", total=None)

            if variants == 1:
                result = await generation_service.generate_content(
                    content_type_enum, scenario_data
                )
                results = [result]
            else:
                results = await generation_service.generate_multiple_variants(
                    content_type_enum, scenario_data, variants
                )

            progress.update(task, description="[green]Payload generation complete[/green]")

        payloads = {}
        valid_results = [r for r in results if r.safety_passed]
        if not valid_results:
            console.print("[yellow]All generated payloads failed safety validation.[/yellow]")
            return None

        for i, result in enumerate(valid_results):
            payloads[f"{content_type}_variant_{i+1}"] = {
                "content": result.content,
                "quality_score": result.quality_score,
                "realism_score": result.realism_score,
                "provider": result.provider.value if hasattr(result.provider, "value") else str(result.provider),
                "model": result.model.value if hasattr(result.model, "value") else str(result.model),
            }

        return payloads

    except Exception as e:
        console.print(f"[red]Payload generation error: {e}[/red]")
        return None
    finally:
        await generation_service.close()


@click.group()
def red_team():
    """Red team operations — autonomous penetration testing.

    By default, attacks run standalone via the AttackOrchestrator and
    the local tool server. Commands that require the external Ciicerone
    Attack API (status, report, steer, stop, list, search) are legacy
    and require CIICERONE_ATTACK_API_URL to be set.

    \b
    Standalone commands:
        attack             Launch an attack via the local tool server
        sequences          List attack sequences from the database
        sequence-status    Get detailed status of an attack sequence
        health             Check tool server health

    \b
    Legacy commands (external API):
        status             Get flow status (requires --legacy context)
        report             Get vulnerability report
        steer              Send steering instruction
        stop               Stop a running flow
        list               List flows
        search             Search past attacks
    """
    pass


@red_team.command()
@click.option("--scenario", "-s", required=True, help="Path to Ciicerone scenario YAML file")
@click.option("--target", "-t", required=True, help="Target URL or IP address")
@click.option("--monitor/--no-monitor", default=True, help="Monitor flow until completion")
@click.option("--output", "-o", help="Save AAR to file path")
@click.option("--payloads", "-p", help="Path to JSON file with LLM-generated threat content payloads")
@click.option("--auto-generate", is_flag=True, help="Auto-generate threat content payloads via LLM before launching attack")
@click.option("--content-type", "-ct", default="email_phishing", help="Content type for auto-generate (email_phishing, sms, phone_script, web_page, social_post, document)")
@click.option("--variants", "-v", type=int, default=1, help="Number of payload variants to auto-generate")
@click.option("--legacy", is_flag=True, default=False, help="Use external Ciicerone Attack API instead of standalone AttackOrchestrator")
@click.option("--tenant", default="default", help="Tenant ID (standalone mode only)")
@click.option("--techniques", help="Comma-separated MITRE technique IDs to execute (standalone mode, overrides scenario)")
@click.option("--timeout", type=int, default=300, help="Timeout per step in seconds (standalone mode)")
def attack(
    scenario: str,
    target: str,
    monitor: bool,
    output: Optional[str],
    payloads: Optional[str],
    auto_generate: bool,
    content_type: str,
    variants: int,
    legacy: bool,
    tenant: str,
    techniques: Optional[str],
    timeout: int,
):
    """Launch an autonomous penetration test.

    By default, uses the standalone AttackOrchestrator which executes
    security tools via the local tool server — no external API required.
    Use --legacy to use the external Ciicerone Attack API.

    \b
    Standalone examples:
        ciicerone red-team attack -s scenarios/web_pentest.yaml -t 10.0.100.10
        ciicerone red-team attack -s scenarios/recon.yaml -t 10.0.100.10 --techniques T1595,T1046,T1190
        ciicerone red-team attack -s scenarios/web_pentest.yaml -t 10.0.100.10 --tenant bank-abc

    \b
    Legacy (external API) examples:
        ciicerone red-team attack -s scenarios/web_pentest.yaml -t http://10.0.100.10 --legacy
        ciicerone red-team attack -s scenarios/phishing.yaml -t http://10.0.100.10 --legacy --auto-generate
    """
    if legacy:
        asyncio.run(_attack_legacy_async(scenario, target, monitor, output, payloads, auto_generate, content_type, variants))
    else:
        asyncio.run(_attack_standalone_async(scenario, target, output, tenant, techniques, timeout))


async def _attack_standalone_async(
    scenario_path: str,
    target: str,
    output: Optional[str],
    tenant: str,
    techniques_override: Optional[str],
    timeout: int,
):
    """Standalone attack using AttackOrchestrator — no external API needed."""
    from ciicerone.core.attack_orchestrator import AttackOrchestrator

    # Load scenario
    try:
        scenario = _load_scenario(scenario_path)
        console.print(f"Loaded scenario: [bold]{scenario.get('name', 'Unknown')}[/bold]")
    except Exception as e:
        console.print(f"[red]Failed to load scenario: {e}[/red]")
        return

    # Determine MITRE techniques
    if techniques_override:
        mitre_techniques = [t.strip().upper() for t in techniques_override.split(",") if t.strip()]
    else:
        # Extract from scenario — look for mitre_techniques or attack_vectors
        mitre_techniques = scenario.get("mitre_techniques", [])
        if not mitre_techniques:
            # Fall back to common web pentest techniques
            mitre_techniques = ["T1595", "T1046", "T1190"]
            console.print(f"[yellow]No MITRE techniques in scenario. Using defaults: {', '.join(mitre_techniques)}[/yellow]")

    if not mitre_techniques:
        console.print("[red]No MITRE techniques to execute. Provide --techniques or add mitre_techniques to the scenario.[/red]")
        return

    console.print(f"[dim]Techniques: {', '.join(mitre_techniques)}[/dim]")
    console.print(f"[dim]Target: {target}[/dim]")

    # Create orchestrator
    try:
        orchestrator = AttackOrchestrator(tenant_id=tenant)
    except Exception as e:
        console.print(f"[red]Failed to initialize AttackOrchestrator: {e}[/red]")
        console.print("[yellow]Ensure the tool server is running (ciicerone mcp start)[/yellow]")
        return

    # Create attack sequence
    console.print("\n[bold cyan]Creating attack sequence...[/bold cyan]")
    try:
        seq_result = await orchestrator.create_attack_sequence_from_scenario(
            scenario_name=scenario.get("name", "Custom Scenario"),
            target=target,
            mitre_techniques=mitre_techniques,
        )
    except Exception as e:
        console.print(f"[red]Failed to create attack sequence: {e}[/red]")
        return

    console.print(Panel(
        f"Sequence ID:  [bold]{seq_result['sequence_id']}[/bold]\n"
        f"Total steps:  {seq_result['total_steps']}\n"
        f"Executable:   {seq_result['executable_steps']}\n"
        f"Skipped:      {seq_result['skipped_steps']}",
        title="Attack Sequence Created",
        border_style="green",
    ))

    # Execute sequence
    console.print("\n[bold cyan]Executing attack sequence...[/bold cyan]")
    try:
        exec_result = await orchestrator.execute_sequence(
            seq_result["sequence_id"],
            timeout_per_step=timeout,
        )
    except Exception as e:
        console.print(f"[red]Failed to execute sequence: {e}[/red]")
        return

    # Display results
    status = exec_result.get("status", "unknown")
    status_color = "green" if status == "completed" else "red"
    console.print(f"\nSequence completed with status: [{status_color}]{status}[/{status_color}]")

    console.print(Panel(
        f"Overall success:    {exec_result.get('overall_success', False)}\n"
        f"Completed steps:    {exec_result.get('completed_steps', 0)}/{exec_result.get('total_steps', 0)}\n"
        f"Successful steps:   {exec_result.get('successful_steps', 0)}\n"
        f"Failed steps:       {exec_result.get('failed_steps', 0)}\n"
        f"Duration:           {exec_result.get('total_duration_seconds', 0):.1f}s\n"
        f"Findings:           {exec_result.get('findings_count', 0)}",
        title="Execution Summary",
        border_style="cyan",
    ))

    # Show step results
    step_results = exec_result.get("step_results", [])
    if step_results:
        step_table = Table(title="Step Results")
        step_table.add_column("Step", style="bold")
        step_table.add_column("Tool")
        step_table.add_column("MITRE")
        step_table.add_column("Success")
        step_table.add_column("Duration", justify="right")
        step_table.add_column("Findings", justify="right")

        for sr in step_results:
            success = sr.get("success", False)
            success_str = f"[green]✓[/green]" if success else f"[red]✗[/red]"
            step_table.add_row(
                sr.get("step_name", "Unknown"),
                sr.get("tool", "—"),
                sr.get("technique", "—"),
                success_str,
                f"{sr.get('duration_seconds', 0):.1f}s",
                str(sr.get("findings_count", 0)),
            )
        console.print(step_table)

    # Save results
    if output:
        with open(output, "w") as f:
            json.dump(exec_result, f, indent=2, default=str)
        console.print(f"\n[green]Results saved to: {output}[/green]")
    else:
        console.print(f"\n[dim]Use --output to save full results to a file[/dim]")
        console.print(f"[dim]Sequence ID for later reference: {seq_result['sequence_id']}[/dim]")


async def _attack_legacy_async(
    scenario_path: str,
    target: str,
    monitor: bool,
    output: Optional[str],
    payloads_path: Optional[str] = None,
    auto_generate: bool = False,
    content_type: str = "email_phishing",
    variants: int = 1,
):
    """Legacy attack using external Ciicerone Attack API."""
    try:
        integration = _get_integration()
    except Exception as e:
        console.print(f"[red]Error: Failed to initialize Ciicerone Attack integration: {e}[/red]")
        console.print("[yellow]Ensure CIICERONE_ATTACK_API_URL and CIICERONE_ATTACK_API_TOKEN are set in .env[/yellow]")
        return

    # Health check
    console.print("Checking Ciicerone Attack connectivity...")
    health = await integration.health_check()
    if health.get("status") != "ok":
        console.print(f"[red]Ciicerone Attack is not reachable: {health}[/red]")
        console.print("[yellow]Ensure Ciicerone Attack is running and CIICERONE_ATTACK_API_URL is correct[/yellow]")
        return
    console.print("[green]Ciicerone Attack is reachable[/green]")

    # Load scenario
    try:
        scenario = _load_scenario(scenario_path)
        console.print(f"Loaded scenario: [bold]{scenario.get('name', 'Unknown')}[/bold]")
    except Exception as e:
        console.print(f"[red]Failed to load scenario: {e}[/red]")
        return

    target_info = {"url": target, "ip": target.replace("http://", "").replace("https://", "").split(":")[0]}

    # Resolve payloads
    payloads_data = None

    if payloads_path:
        try:
            with open(payloads_path, "r") as f:
                payloads_data = json.load(f)
            console.print(f"[green]Loaded payloads from: {payloads_path}[/green]")
        except Exception as e:
            console.print(f"[red]Failed to load payloads file: {e}[/red]")
            return

    if auto_generate:
        console.print("\n[bold cyan]Auto-generating threat content payloads...[/bold cyan]")
        try:
            payloads_data = await _auto_generate_payloads(scenario_path, content_type, variants)
            if payloads_data:
                console.print(f"[green]Generated {len(payloads_data)} payload(s) of type '{content_type}'[/green]")
            else:
                console.print("[yellow]Payload generation failed. Continuing without custom payloads.[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Auto-generate error: {e}. Continuing without custom payloads.[/yellow]")
            payloads_data = None

    # Launch flow
    console.print("\nLaunching Ciicerone Attack attack flow...")
    try:
        flow = await integration.launch_attack(scenario, target_info, payloads=payloads_data)
    except Exception as e:
        console.print(f"[red]Failed to launch flow: {e}[/red]")
        return

    console.print(Panel(
        f"Flow ID:   [bold]{flow.flow_id}[/bold]\n"
        f"Name:      {flow.name}\n"
        f"Target:    {flow.target}\n"
        f"Status:    [yellow]{flow.status}[/yellow]",
        title="Ciicerone Attack Flow Created",
        border_style="green",
    ))

    if not monitor:
        console.print("\n[dim]Flow launched. Use 'ciicerone red-team flow --status <flow_id>' to monitor.[/dim]")
        return

    # Monitor flow
    console.print("\nMonitoring flow (press Ctrl+C to stop)...")
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Waiting for flow completion...", total=None)

            final_flow = await integration.monitor_flow(
                flow.flow_id,
                poll_interval=10,
                timeout=3600,
            )
            progress.update(task, description=f"Flow {final_flow.status}")

    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoring stopped. Flow is still running.[/yellow]")
        console.print(f"Resume with: ciicerone red-team flow --status {flow.flow_id}")
        return

    # Show results
    console.print(f"\nFlow completed with status: [bold]{final_flow.status}[/bold]")

    if final_flow.status == "completed":
        console.print("\nGenerating After Action Review...")
        try:
            aar = await integration.generate_aar(flow.flow_id, scenario)

            # Display summary
            console.print(Panel(
                aar.get("executive_summary", "No summary available"),
                title="Executive Summary",
                border_style="blue",
            ))

            # Vulnerabilities table
            vulns = aar.get("vulnerabilities", [])
            if vulns:
                vuln_table = Table(title="Vulnerabilities Found")
                vuln_table.add_column("Title", style="bold")
                vuln_table.add_column("Severity", style="red")
                vuln_table.add_column("Type")

                for v in vulns[:10]:
                    vuln_table.add_row(
                        str(v.get("title", "Unknown")),
                        str(v.get("severity", "unknown")),
                        str(v.get("type", "unknown")),
                    )
                console.print(vuln_table)

            # Objectives
            objectives = aar.get("objectives_met", [])
            if objectives:
                obj_table = Table(title="Objectives Assessment")
                obj_table.add_column("Objective")
                obj_table.add_column("Status", style="bold")
                obj_table.add_column("Confidence")

                for obj in objectives:
                    status = obj.get("status", "unknown")
                    color = "green" if status == "likely_met" else "red"
                    obj_table.add_row(
                        obj.get("objective", ""),
                        f"[{color}]{status}[/{color}]",
                        obj.get("confidence", "unknown"),
                    )
                console.print(obj_table)

            # Save AAR
            if output:
                with open(output, "w") as f:
                    json.dump(aar, f, indent=2, default=str)
                console.print(f"\nAAR saved to: [bold]{output}[/bold]")
            else:
                console.print("\n[dim]Use --output to save the full AAR to a file[/dim]")

        except Exception as e:
            console.print(f"[red]Failed to generate AAR: {e}[/red]")


@red_team.command()
@click.option("--flow-id", "-f", required=True, help="Ciicerone Attack flow ID")
def status(flow_id: str):
    """Get the status of a Ciicerone Attack flow.

    Example:
        ciicerone red-team flow -f abc123
    """
    asyncio.run(_status_async(flow_id))


async def _status_async(flow_id: str):
    try:
        integration = _get_integration()
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return

    try:
        flow = await integration.client.get_flow_status(flow_id)
    except Exception as e:
        console.print(f"[red]Failed to get flow status: {e}[/red]")
        return

    console.print(Panel(
        f"Flow ID:    [bold]{flow.flow_id}[/bold]\n"
        f"Name:       {flow.name}\n"
        f"Status:     [bold]{flow.status}[/bold]\n"
        f"Target:     {flow.target}\n"
        f"Created:    {flow.created_at or 'N/A'}\n"
        f"Updated:    {flow.updated_at or 'N/A'}\n"
        f"Tasks:      {len(flow.tasks)}",
        title="Ciicerone Attack Flow Status",
        border_style="cyan",
    ))

    if flow.tasks:
        task_table = Table(title="Tasks")
        task_table.add_column("Task", style="bold")
        task_table.add_column("Status")
        task_table.add_column("Agent")

        for task in flow.tasks:
            task_status = task.get("status", "unknown")
            color = "green" if task_status == "done" else "yellow" if task_status == "running" else "dim"
            task_table.add_row(
                task.get("name", "Unknown"),
                f"[{color}]{task_status}[/{color}]",
                task.get("agent_type", "unknown"),
            )
        console.print(task_table)


@red_team.command()
@click.option("--flow-id", "-f", required=True, help="Ciicerone Attack flow ID")
@click.option("--output", "-o", help="Save report to file path")
def report(flow_id: str, output: Optional[str]):
    """Get the vulnerability report for a completed flow.

    Example:
        ciicerone red-team report -f abc123 -o report.md
    """
    asyncio.run(_report_async(flow_id, output))


async def _report_async(flow_id: str, output: Optional[str]):
    try:
        integration = _get_integration()
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return

    try:
        report_data = await integration.client.get_flow_report(flow_id)
    except Exception as e:
        console.print(f"[red]Failed to get report: {e}[/red]")
        return

    if report_data.report_markdown:
        if output:
            with open(output, "w") as f:
                f.write(report_data.report_markdown)
            console.print(f"Report saved to: [bold]{output}[/bold]")
        else:
            console.print(Markdown(report_data.report_markdown))
    else:
        console.print("[yellow]No report available. Flow may not be completed yet.[/yellow]")

    # Show vulnerabilities summary
    if report_data.vulnerabilities:
        vuln_table = Table(title=f"Vulnerabilities ({len(report_data.vulnerabilities)})")
        vuln_table.add_column("Title", style="bold")
        vuln_table.add_column("Severity", style="red")
        vuln_table.add_column("Type")

        for v in report_data.vulnerabilities:
            vuln_table.add_row(
                str(v.get("title", "Unknown")),
                str(v.get("severity", "unknown")),
                str(v.get("type", "unknown")),
            )
        console.print(vuln_table)

    if report_data.recommendations:
        console.print("\n[bold]Recommendations:[/bold]")
        for rec in report_data.recommendations:
            console.print(f"  • {rec}")


@red_team.command()
@click.option("--flow-id", "-f", required=True, help="Active Ciicerone Attack flow ID")
@click.option("--instruction", "-i", required=True, help="Steering instruction for the agent")
def steer(flow_id: str, instruction: str):
    """Send a steering instruction to an active Ciicerone Attack flow.

    Allows real-time guidance of the AI agent during execution.

    Example:
        ciicerone red-team steer -f abc123 -i "Focus on SQL injection vulnerabilities"
    """
    asyncio.run(_steer_async(flow_id, instruction))


async def _steer_async(flow_id: str, instruction: str):
    try:
        integration = _get_integration()
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return

    try:
        success = await integration.steer_flow(flow_id, instruction)
        if success:
            console.print(f"[green]Instruction sent to flow {flow_id}[/green]")
            console.print(f"  Instruction: [italic]{instruction}[/italic]")
        else:
            console.print("[red]Failed to send instruction[/red]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@red_team.command()
@click.option("--flow-id", "-f", required=True, help="Ciicerone Attack flow ID to stop")
def stop(flow_id: str):
    """Stop a running Ciicerone Attack flow.

    Example:
        ciicerone red-team stop -f abc123
    """
    asyncio.run(_stop_async(flow_id))


async def _stop_async(flow_id: str):
    try:
        integration = _get_integration()
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return

    try:
        success = await integration.stop_flow(flow_id)
        if success:
            console.print(f"[green]Flow {flow_id} stopped[/green]")
        else:
            console.print("[red]Failed to stop flow[/red]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@red_team.command(name="list")
@click.option("--limit", "-l", default=20, help="Maximum number of flows to list")
def list_flows(limit: int):
    """List all Ciicerone Attack flows.

    Example:
        ciicerone red-team list --limit 10
    """
    asyncio.run(_list_flows_async(limit))


async def _list_flows_async(limit: int):
    try:
        integration = _get_integration()
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return

    try:
        flows = await integration.list_flows(limit)
    except Exception as e:
        console.print(f"[red]Failed to list flows: {e}[/red]")
        return

    if not flows:
        console.print("[yellow]No Ciicerone Attack flows found[/yellow]")
        return

    table = Table(title=f"Ciicerone Attack Flows ({len(flows)})")
    table.add_column("Flow ID", style="bold")
    table.add_column("Name")
    table.add_column("Status")
    table.add_column("Target")
    table.add_column("Created")

    for flow in flows:
        status = flow.status
        color = "green" if status == "completed" else "yellow" if status == "active" else "red" if status == "failed" else "dim"
        table.add_row(
            flow.flow_id,
            flow.name,
            f"[{color}]{status}[/{color}]",
            flow.target,
            flow.created_at or "N/A",
        )

    console.print(table)


@red_team.command()
@click.option("--query", "-q", required=True, help="Search query for past attack patterns")
@click.option("--limit", "-l", default=10, help="Maximum results")
def search(query: str, limit: int):
    """Search Ciicerone Attack's memory for past attack patterns.

    Queries the vector store for similar past attacks and findings.

    Example:
        ciicerone red-team search -q "SQL injection on web applications" --limit 5
    """
    asyncio.run(_search_async(query, limit))


async def _search_async(query: str, limit: int):
    try:
        integration = _get_integration()
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return

    try:
        entries = await integration.search_past_attacks(query, limit)
    except Exception as e:
        console.print(f"[red]Search failed: {e}[/red]")
        return

    if not entries:
        console.print("[yellow]No matching entries found[/yellow]")
        return

    console.print(f"\n[bold]Found {len(entries)} matching entries:[/bold]\n")
    for i, entry in enumerate(entries, 1):
        console.print(Panel(
            entry.content[:500] + ("..." if len(entry.content) > 500 else ""),
            title=f"#{i} (score: {entry.embedding_score:.2f})",
            border_style="blue",
        ))


@red_team.command()
@click.option("--legacy", is_flag=True, default=False, help="Check external Ciicerone Attack API instead of local tool server")
def health(legacy: bool):
    """Check if the attack infrastructure is reachable and healthy.

    By default, checks the local tool server (standalone mode).
    Use --legacy to check the external Ciicerone Attack API.

    Example:
        ciicerone red-team health
        ciicerone red-team health --legacy
    """
    if legacy:
        asyncio.run(_health_legacy_async())
    else:
        asyncio.run(_health_standalone_async())


async def _health_standalone_async():
    """Check tool server health for standalone mode."""
    from ciicerone.core.tool_server_client import get_tool_server_client

    try:
        client = get_tool_server_client()
        healthy = await client.health_check()
        if healthy:
            console.print("[green]Tool server is healthy and reachable[/green]")
            console.print(f"  URL: {client.url}")
        else:
            console.print(f"[red]Tool server is not reachable at {client.url}[/red]")
            console.print("[yellow]Start it with: ciicerone mcp start[/yellow]")
    except Exception as e:
        console.print(f"[red]Failed to check tool server: {e}[/red]")
        console.print("[yellow]Start it with: ciicerone mcp start[/yellow]")


async def _health_legacy_async():
    try:
        integration = _get_integration()
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return

    result = await integration.health_check()

    if result.get("status") == "ok":
        console.print("[green]Ciicerone Attack is healthy and reachable[/green]")
        console.print(f"  URL: {os.environ.get('CIICERONE_ATTACK_API_URL', 'Not set')}")
    else:
        console.print(f"[red]Ciicerone Attack health check failed: {result}[/red]")
        console.print("[yellow]Ensure Ciicerone Attack is running and CIICERONE_ATTACK_API_URL is set[/yellow]")


# ---------------------------------------------------------------------------
# Standalone commands — query attack sequences from the database
# ---------------------------------------------------------------------------

@red_team.command()
@click.option("--limit", "-l", default=20, help="Maximum number of sequences to list")
@click.option("--tenant", default="default", help="Filter by tenant ID")
def sequences(limit: int, tenant: str):
    """List attack sequences from the database (standalone mode).

    Example:
        ciicerone red-team sequences --limit 10
    """
    asyncio.run(_sequences_async(limit, tenant))


async def _sequences_async(limit: int, tenant: str):
    from sqlalchemy import select, desc
    from ciicerone.db.models.tool_tracking import AttackSequenceRecord

    try:
        from ciicerone.db.session import get_session
    except ImportError:
        console.print("[red]Database session module not available.[/red]")
        return

    try:
        async with get_session() as session:
            result = await session.execute(
                select(AttackSequenceRecord)
                .where(AttackSequenceRecord.tenant_id == tenant)
                .order_by(desc(AttackSequenceRecord.created_at))
                .limit(limit)
            )
            seqs = result.scalars().all()
    except Exception as e:
        console.print(f"[red]Failed to query sequences: {e}[/red]")
        return

    if not seqs:
        console.print("[yellow]No attack sequences found.[/yellow]")
        return

    table = Table(title=f"Attack Sequences ({len(seqs)})")
    table.add_column("Sequence ID", style="bold")
    table.add_column("Name")
    table.add_column("Status")
    table.add_column("Target")
    table.add_column("Steps", justify="right")
    table.add_column("Success", justify="right")
    table.add_column("Created")

    for seq in seqs:
        status = seq.sequence_status
        color = "green" if status == "completed" else "yellow" if status == "running" else "red" if status == "failed" else "dim"
        table.add_row(
            seq.sequence_id,
            seq.name,
            f"[{color}]{status}[/{color}]",
            seq.target_system or "—",
            str(seq.completed_steps + seq.failed_steps),
            str(seq.successful_steps),
            str(seq.created_at) if seq.created_at else "N/A",
        )

    console.print(table)


@red_team.command(name="sequence-status")
@click.option("--sequence-id", "-s", required=True, help="Attack sequence ID")
def sequence_status(sequence_id: str):
    """Get detailed status of an attack sequence (standalone mode).

    Example:
        ciicerone red-team sequence-status -s seq_abc123
    """
    asyncio.run(_sequence_status_async(sequence_id))


async def _sequence_status_async(sequence_id: str):
    from sqlalchemy import select
    from ciicerone.db.models.tool_tracking import AttackSequenceRecord, AttackSequenceStepRecord

    try:
        from ciicerone.db.session import get_session
    except ImportError:
        console.print("[red]Database session module not available.[/red]")
        return

    try:
        async with get_session() as session:
            seq_result = await session.execute(
                select(AttackSequenceRecord).where(AttackSequenceRecord.sequence_id == sequence_id)
            )
            seq = seq_result.scalar_one_or_none()

            if not seq:
                console.print(f"[red]Sequence not found: {sequence_id}[/red]")
                return

            steps_result = await session.execute(
                select(AttackSequenceStepRecord)
                .where(AttackSequenceStepRecord.sequence_id == sequence_id)
                .order_by(AttackSequenceStepRecord.step_order)
            )
            steps = steps_result.scalars().all()
    except Exception as e:
        console.print(f"[red]Failed to query sequence: {e}[/red]")
        return

    status = seq.sequence_status
    status_color = "green" if status == "completed" else "yellow" if status == "running" else "red" if status == "failed" else "dim"

    console.print(Panel(
        f"Sequence ID:    [bold]{seq.sequence_id}[/bold]\n"
        f"Name:           {seq.name}\n"
        f"Status:         [{status_color}]{status}[/{status_color}]\n"
        f"Target:         {seq.target_system or 'N/A'}\n"
        f"Scenario:       {seq.scenario_name or 'N/A'}\n"
        f"Total steps:    {seq.total_steps}\n"
        f"Completed:      {seq.completed_steps}\n"
        f"Successful:     {seq.successful_steps}\n"
        f"Failed:         {seq.failed_steps}\n"
        f"Duration:       {seq.total_duration_seconds or 0:.1f}s\n"
        f"Overall success: {seq.overall_success}\n"
        f"Created:        {seq.created_at or 'N/A'}",
        title="Attack Sequence Status",
        border_style="cyan",
    ))

    if steps:
        step_table = Table(title="Steps")
        step_table.add_column("#", justify="right")
        step_table.add_column("Step", style="bold")
        step_table.add_column("Tool")
        step_table.add_column("MITRE")
        step_table.add_column("Status")
        step_table.add_column("Duration", justify="right")

        for step in steps:
            s_status = step.step_status
            s_color = "green" if s_status == "completed" else "yellow" if s_status == "running" else "red" if s_status == "failed" else "dim"
            step_table.add_row(
                str(step.step_order),
                step.step_name,
                step.tool_name or "—",
                step.mitre_technique_id or "—",
                f"[{s_color}]{s_status}[/{s_color}]",
                f"{step.duration_seconds or 0:.1f}s" if step.duration_seconds else "—",
            )
        console.print(step_table)

    if seq.key_findings:
        try:
            findings = json.loads(seq.key_findings) if isinstance(seq.key_findings, str) else seq.key_findings
            console.print(f"\n[bold]Key Findings ({len(findings)}):[/bold]")
            for f in findings[:10]:
                console.print(f"  • {f}")
        except Exception:
            pass
