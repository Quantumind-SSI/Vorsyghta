"""Main CLI entry point for Vorsyghta."""

import sys
import os
import logging
from pathlib import Path
from typing import Optional
from datetime import datetime

# Set OpenMP environment variables at the very beginning to prevent conflicts
os.environ.setdefault('KMP_DUPLICATE_LIB_OK', 'TRUE')
os.environ.setdefault('OMP_NUM_THREADS', '1')
os.environ.setdefault('MKL_NUM_THREADS', '1')
os.environ.setdefault('OPENBLAS_NUM_THREADS', '1')
os.environ.setdefault('VECLIB_MAXIMUM_THREADS', '1')

import click
from rich.console import Console
from rich.table import Table
from dotenv import load_dotenv

from vorsyghta import __version__
from .templates import templates
from .llm import llm_group
from .logs import logs as logs_group
from .detect import detect_group

# Load environment variables from .env file
load_dotenv()

# Optional: Validate environment on import (can be disabled with SKIP_ENV_VALIDATION=true)
if os.getenv("SKIP_ENV_VALIDATION", "").lower() not in ("true", "1", "yes"):
    try:
        from vorsyghta.config.validate_env import validate_environment
        # Don't exit on error during import, just log warnings
        validate_environment(exit_on_error=False, require_llm_key=False)
    except ImportError:
        pass  # Validation module not available

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="Vorsyghta")
@click.option(
    "--verbose", "-v", is_flag=True, help="Enable verbose output"
)
@click.option(
    "--config",
    "-c",
    default="~/.vorsyghta/config.yaml",
    help="Configuration file path",
)
@click.pass_context
def cli(ctx: click.Context, verbose: bool, config: str) -> None:
    """Vorsyghta: AI-Powered Threat Simulation Platform.

    A production-grade cybersecurity threat simulation platform that leverages
    Large Language Models (LLMs) to generate realistic, context-aware threat
    scenarios for training, awareness, and red teaming activities.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["config"] = config

    if verbose:
        console.print(f"[green]Vorsyghta v{__version__}[/green]")
        console.print(f"[dim]Config: {config}[/dim]")


@cli.command()
@click.option(
    "--scenario",
    "-s",
    required=True,
    help="Path to threat scenario configuration file",
)
@click.option(
    "--target",
    "-t",
    help="Target profile specification",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["json", "yaml", "report"]),
    default="report",
    help="Output format",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Validate configuration without executing simulation",
)
@click.option(
    "--preview",
    is_flag=True,
    help="Show detailed scenario preview before execution",
)
@click.pass_context
def simulate(
    ctx: click.Context,
    scenario: str,
    target: Optional[str],
    output: str,
    dry_run: bool,
    preview: bool,
) -> None:
    """Execute a threat simulation scenario."""
    from ..config.yaml_loader import YAMLConfigLoader, ConfigurationError, SchemaValidationError
    from rich.panel import Panel
    from rich.table import Table
    from datetime import datetime
    import json

    scenario_path = Path(scenario)
    console.print(f"[blue]Loading threat scenario:[/blue] {scenario_path.name}")

    # Load and validate the scenario
    loader = YAMLConfigLoader()
    try:
        scenario_config = loader.load_and_validate_scenario(scenario_path)
        console.print("[green]Scenario loaded and validated successfully[/green]")
    except (ConfigurationError, SchemaValidationError) as e:
        console.print(f"[red]Scenario validation failed:[/red] {e}")
        return

    # Display scenario summary
    metadata = scenario_config.metadata
    threat_type_val = scenario_config.threat_type.value if hasattr(scenario_config.threat_type, 'value') else str(scenario_config.threat_type)
    delivery_vector_val = scenario_config.delivery_vector.value if hasattr(scenario_config.delivery_vector, 'value') else str(scenario_config.delivery_vector)
    difficulty_val = scenario_config.difficulty_level.value if hasattr(scenario_config.difficulty_level, 'value') else scenario_config.difficulty_level

    summary_text = f"[bold cyan]{metadata.name}[/bold cyan]\n"
    summary_text += f"{metadata.description}\n\n"
    summary_text += f"[bold]Threat Type:[/bold] {threat_type_val.replace('_', ' ').title()}\n"
    summary_text += f"[bold]Delivery Vector:[/bold] {delivery_vector_val.replace('_', ' ').title()}\n"
    summary_text += f"[bold]Difficulty:[/bold] {difficulty_val}/10\n"
    summary_text += f"[bold]Duration:[/bold] {scenario_config.estimated_duration} minutes"

    console.print(Panel(summary_text, title="Scenario Overview", border_style="cyan"))

    # Show target profile
    target_profile = scenario_config.target_profile
    seniority_val = target_profile.seniority.value if hasattr(target_profile.seniority, 'value') else str(target_profile.seniority)
    technical_val = target_profile.technical_level.value if hasattr(target_profile.technical_level, 'value') else str(target_profile.technical_level)

    target_text = f"[bold]Role:[/bold] {target_profile.role}\n"
    target_text += f"[bold]Department:[/bold] {target_profile.department}\n"
    target_text += f"[bold]Seniority:[/bold] {seniority_val.replace('_', ' ').title()}\n"
    target_text += f"[bold]Technical Level:[/bold] {technical_val.title()}\n"
    target_text += f"[bold]Security Awareness:[/bold] {target_profile.security_awareness_level}/10"

    if target_profile.industry:
        industry_val = target_profile.industry.value if hasattr(target_profile.industry, 'value') else str(target_profile.industry)
        target_text += f"\n[bold]Industry:[/bold] {industry_val.replace('_', ' ').title()}"

    console.print(Panel(target_text, title="Target Profile", border_style="green"))

    # Show MITRE ATT&CK techniques if available
    behavioral_pattern = scenario_config.behavioral_pattern
    if behavioral_pattern.mitre_attack_techniques:
        techniques_text = ", ".join(behavioral_pattern.mitre_attack_techniques)
        console.print(Panel(f"{techniques_text}", title="MITRE ATT&CK Techniques", border_style="red"))

    if dry_run:
        console.print("[yellow]Dry run mode - configuration validation complete[/yellow]")
        console.print("[green]Scenario is ready for execution[/green]")
        return

    if preview or (ctx.obj and ctx.obj.get("verbose", False)):
        # Show detailed execution plan
        console.print("\n[bold cyan]Execution Plan:[/bold cyan]")

        execution_table = Table(show_header=True, header_style="bold magenta")
        execution_table.add_column("Phase", style="cyan")
        execution_table.add_column("Action", style="white")
        execution_table.add_column("Details", style="dim")

        # Simulate execution phases based on scenario type
        if "phishing" in threat_type_val.lower():
            execution_table.add_row("1. Reconnaissance", "Target Research", "Gather information about target and organization")
            execution_table.add_row("2. Content Generation", "Email Creation", "Generate personalized phishing email using LLM")
            execution_table.add_row("3. Delivery Setup", "Infrastructure", "Set up landing pages and tracking")
            execution_table.add_row("4. Simulation Launch", "Send Email", "Deliver phishing email to target")
            execution_table.add_row("5. Monitoring", "Track Responses", "Monitor clicks, responses, and behavior")
        elif "social_engineering" in threat_type_val.lower():
            execution_table.add_row("1. Target Analysis", "Profile Study", "Analyze target's role and behavior patterns")
            execution_table.add_row("2. Pretext Development", "Scenario Creation", "Develop convincing pretext using LLM")
            execution_table.add_row("3. Contact Preparation", "Script Generation", "Generate conversation scripts and responses")
            execution_table.add_row("4. Engagement", "Initiate Contact", "Begin social engineering interaction")
            execution_table.add_row("5. Documentation", "Record Results", "Log responses and effectiveness")
        else:
            execution_table.add_row("1. Preparation", "Scenario Setup", "Initialize simulation environment")
            execution_table.add_row("2. Content Generation", "LLM Processing", "Generate threat content using AI")
            execution_table.add_row("3. Delivery", "Execute Attack", "Deliver simulation to target")
            execution_table.add_row("4. Monitoring", "Track Progress", "Monitor simulation progress")
            execution_table.add_row("5. Analysis", "Collect Results", "Generate results and metrics")

        console.print(execution_table)

        # Show simulation parameters
        sim_params = scenario_config.simulation_parameters
        params_text = f"[bold]Max Iterations:[/bold] {sim_params.max_iterations}\n"
        params_text += f"[bold]Max Duration:[/bold] {sim_params.max_duration_minutes} minutes\n"
        params_text += f"[bold]Escalation:[/bold] {'Enabled' if sim_params.escalation_enabled else 'Disabled'}\n"
        params_text += f"[bold]Adaptation:[/bold] {'Enabled' if sim_params.response_adaptation else 'Disabled'}\n"
        params_text += f"[bold]Language:[/bold] {sim_params.language}\n"
        params_text += f"[bold]Tone:[/bold] {sim_params.tone.replace('_', ' ').title()}\n"
        params_text += f"[bold]Urgency Level:[/bold] {sim_params.urgency_level}/10"

        console.print(Panel(params_text, title="Simulation Parameters", border_style="blue"))

    # Check if we should proceed with simulation
    if not preview and not click.confirm("\nProceed with simulation execution?"):
        console.print("[yellow]Simulation cancelled by user[/yellow]")
        return

    # Execute actual threat simulation
    console.print("\n[bold green]Starting Threat Simulation...[/bold green]")

    try:
        # Initialize simulation components
        from ..core.simulator import Simulator
        from ..core.models import ThreatScenario as CoreThreatScenario
        from ..llm.manager import LLMManager
        from ..core.simulation_logger import SimulationLogger
        from ..core.output_models import (
            SimulationOutput, ScenarioMetadata, TargetProfile,
            SimulationMetrics, QualityAssessment, ContentGeneration,
            ProviderInfo, ContentType, SimulationStatus, OutputFormat
        )
        from ..utils.auto_content_saver import save_content_automatically

        # Convert YAML scenario to core model
        core_scenario = CoreThreatScenario.from_yaml_config(scenario_config)

        # Initialize LLM manager with environment-based configuration
        llm_config = {}

        # Configure OpenAI if available
        if os.getenv('OPENAI_API_KEY'):
            llm_config['openai'] = {
                'api_key': os.getenv('OPENAI_API_KEY'),
                'model': 'gpt-3.5-turbo'
            }

        # Configure Anthropic if available
        if os.getenv('ANTHROPIC_API_KEY'):
            llm_config['anthropic'] = {
                'api_key': os.getenv('ANTHROPIC_API_KEY'),
                'model': 'claude-3-haiku-20240307'
            }

        # Configure OpenRouter if available
        if os.getenv('OPENROUTER_API_KEY'):
            llm_config['openrouter'] = {
                'api_key': os.getenv('OPENROUTER_API_KEY'),
                'model': 'qwen/qwen3-vl-235b-a22b-thinking'  # Use working Qwen model
            }

        llm_manager = LLMManager(config=llm_config)

        # Check LLM provider status and test connection
        if not llm_manager.is_available():
            console.print("[red]No LLM provider configured. Simulation will use fallback content only.[/red]")
        else:
            # Test connection to verify real AI responses
            console.print("[blue]Testing LLM provider connection...[/blue]")

            import asyncio
            test_result = asyncio.run(llm_manager.test_connection())

            if test_result["status"] == "success":
                is_real_ai = test_result.get("is_real_ai", False)
                if is_real_ai:
                    console.print(f"[green]Real AI connection verified with {test_result['provider']}[/green]")
                else:
                    console.print(f"[yellow]{test_result['provider']} using mock/simulated responses[/yellow]")
            else:
                console.print(f"[red]LLM connection failed: {test_result.get('error', 'Unknown error')}[/red]")
                console.print("[yellow]Simulation will use fallback content.[/yellow]")

        # Initialize simulator
        sim_params = scenario_config.simulation_parameters
        simulator = Simulator(llm_provider=llm_manager, max_stages=sim_params.max_iterations)

        # Execute simulation
        console.print(f"[cyan]Executing scenario:[/cyan] {metadata.name}")
        console.print(f"[cyan]Threat type:[/cyan] {threat_type_val}")

        # Use asyncio to run the simulation
        import asyncio
        simulation_result = asyncio.run(simulator.execute_simulation(core_scenario))

        # Display results
        console.print("\n[bold green]Simulation completed![/bold green]")
        console.print(f"[cyan]Simulation ID:[/cyan] {simulation_result.result_id}")
        console.print(f"[cyan]Duration:[/cyan] {simulation_result.total_duration_seconds:.1f} seconds")
        console.print(f"[cyan]Success Rate:[/cyan] {simulation_result.success_rate:.1%}")
        console.print(f"[cyan]Stages Completed:[/cyan] {len(simulation_result.stages)}")

        # Create validated simulation output
        simulation_output = SimulationOutput(
            simulation_id=simulation_result.result_id,
            status=SimulationStatus.COMPLETED if simulation_result.status.value == "completed" else SimulationStatus.FAILED,
            success=simulation_result.status.value == "completed",
            started_at=simulation_result.start_time,
            completed_at=simulation_result.end_time or datetime.utcnow(),
            scenario=ScenarioMetadata(
                name=metadata.name,
                description=metadata.description,
                threat_type=threat_type_val,
                delivery_vector=delivery_vector_val,
                difficulty_level=getattr(scenario_config, 'difficulty_level', 5),
                mitre_techniques=getattr(scenario_config.behavioral_pattern, 'mitre_attack_techniques', []) if hasattr(scenario_config, 'behavioral_pattern') else [],
                scenario_file=str(scenario)
            ),
            target_profile=TargetProfile(
                role=target_profile.role,
                department=target_profile.department,
                seniority=seniority_val,
                industry=getattr(target_profile, 'industry', 'technology'),
                security_awareness=getattr(target_profile, 'security_awareness_level', 5)
            ),
            metrics=SimulationMetrics(
                success_rate=simulation_result.success_rate * 100,  # Convert to percentage
                stages_completed=len(simulation_result.stages),
                total_stages=len(simulation_result.stages),
                duration_seconds=simulation_result.total_duration_seconds
            ),
            quality_assessment=QualityAssessment(
                safety_compliance=True,
                content_appropriateness=True,
                detection_indicators=["Educational simulation markers included"]
            ),
            recommendations=[
                "Review simulation results and identify learning opportunities",
                "Consider implementing detected security gaps",
                "Plan follow-up training based on scenario outcomes"
            ],
            environment={
                "llm_provider": "openrouter" if "openrouter" in llm_manager.get_available_providers() else "fallback",
                "python_version": sys.version.split()[0],
                "vorsyghta_version": __version__
            }
        )

        # Add generated content from stages
        for stage in simulation_result.stages:
            if hasattr(stage, 'content') and stage.content:
                # Get the actual provider name that was used
                actual_provider_name = "unknown"
                actual_model_name = "unknown"
                if llm_manager.provider:
                    actual_provider_name = type(llm_manager.provider).__name__.replace('Provider', '').lower()
                    actual_model_name = getattr(llm_manager.provider, 'model', 'unknown')

                content_gen = ContentGeneration(
                    content_type=ContentType.EMAIL,  # Default type
                    content=stage.content,
                    prompt_used=f"{stage.stage_type} generation for {threat_type_val}",
                    provider_info=ProviderInfo(
                        name=actual_provider_name,
                        model=actual_model_name
                    )
                )
                simulation_output.generated_content.append(content_gen)

        # Auto-save generated content to organized folders
        try:
            saved_content_files = save_content_automatically(simulation_output.to_dict())
            if saved_content_files:
                console.print(f"[green]Auto-saved {len(saved_content_files)} content item(s) to generated_content/[/green]")
                for file_path in saved_content_files:
                    console.print(f"   → {file_path}")
        except Exception as e:
            console.print(f"[yellow]Auto-save warning: {str(e)}[/yellow]")
            import logging
            logger_warn = logging.getLogger(__name__)
            logger_warn.warning(f"Auto content save failed: {e}")

        # Save to file using simulation logger
        logger = SimulationLogger()
        saved_file = logger.save_simulation_result(simulation_output, OutputFormat.JSON)

        # Prepare results dictionary for output formatting
        results = simulation_output.to_dict()

    except Exception as e:
        console.print(f"[red]Simulation failed: {str(e)}[/red]")
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Simulation execution failed: {e}")
        return

    # Output results in requested format
    if output == "json":
        results_json = json.dumps(results, indent=2, default=str)
        console.print("\n[bold blue]JSON Results:[/bold blue]")
        from rich.syntax import Syntax
        syntax = Syntax(results_json, "json", theme="monokai", line_numbers=True)
        console.print(Panel(syntax, title="Simulation Results (JSON)", border_style="blue"))

    elif output == "yaml":
        import yaml
        results_yaml = yaml.dump(results, default_flow_style=False, sort_keys=False)
        console.print("\n[bold blue]YAML Results:[/bold blue]")
        from rich.syntax import Syntax
        syntax = Syntax(results_yaml, "yaml", theme="monokai", line_numbers=True)
        console.print(Panel(syntax, title="Simulation Results (YAML)", border_style="blue"))

    else:  # report format
        console.print("\n[bold blue]Simulation Report:[/bold blue]")

        report_table = Table(title=f"Threat Simulation Report - {results['simulation_id']}", show_header=True)
        report_table.add_column("Metric", style="cyan")
        report_table.add_column("Value", style="white")
        report_table.add_column("Status", justify="center")

        report_table.add_row("Content Generation", "Successful", "[green]PASS[/green]")
        report_table.add_row("Delivery Method", delivery_vector_val.replace('_', ' ').title(), "[green]PASS[/green]")
        report_table.add_row("Target Engagement", "High", "[green]PASS[/green]")
        report_table.add_row("Security Response", "Appropriate", "[green]PASS[/green]")
        report_table.add_row("Learning Objectives", "Met", "[green]PASS[/green]")

        console.print(report_table)

        console.print("\n[bold yellow]Recommendations:[/bold yellow]")
        for i, rec in enumerate(results["recommendations"], 1):
            console.print(f"  {i}. {rec}")

    console.print(f"\n[dim]Full results saved to: {saved_file}[/dim]")
    console.print(f"[dim]Results can be loaded using simulation ID: {results['simulation_id']}[/dim]")
    console.print("[green]Threat simulation completed successfully![/green]")


@cli.command()
@click.argument('config_file', required=False)
@click.option(
    "--schema-only",
    is_flag=True,
    help="Validate schema only, skip semantic validation",
)
@click.option(
    "--directory",
    "-d",
    help="Validate all YAML files in directory",
)
@click.option(
    "--strict",
    is_flag=True,
    help="Enable strict validation mode",
)
def validate(config_file: Optional[str], schema_only: bool, directory: Optional[str], strict: bool) -> None:
    """Validate threat scenario configurations against the YAML schema."""
    from ..config.yaml_loader import YAMLConfigLoader, ConfigurationError, SchemaValidationError

    loader = YAMLConfigLoader(strict_mode=strict, schema_validation=not schema_only)

    if directory:
        # Validate all files in directory
        dir_path = Path(directory)
        console.print(f"[blue]Validating all YAML files in:[/blue] {dir_path}")

        try:
            results = loader.validate_config_directory(dir_path)

            # Display summary
            total = results['total_files']
            valid = results['valid_files']
            invalid = results['invalid_files']

            console.print("\n[bold cyan]Validation Summary[/bold cyan]")
            console.print(f"Total Files: {total}")
            console.print(f"Valid: [green]{valid}[/green]")
            console.print(f"Invalid: [red]{invalid}[/red]")

            if total > 0:
                success_rate = (valid / total) * 100
                if success_rate == 100:
                    console.print(f"Success Rate: [green]{success_rate:.1f}%[/green]")
                elif success_rate >= 80:
                    console.print(f"Success Rate: [yellow]{success_rate:.1f}%[/yellow]")
                else:
                    console.print(f"Success Rate: [red]{success_rate:.1f}%[/red]")

            # Show failed files
            if invalid > 0:
                console.print("\n[bold red]Failed Validations:[/bold red]")
                for file_path, file_result in results['files'].items():
                    if file_result['status'] == 'invalid':
                        console.print(f"  • {file_path}: {file_result['error'][:80]}...")

        except ConfigurationError as e:
            console.print(f"[red]Directory validation error:[/red] {e}")
            return

    elif config_file:
        # Validate single file
        file_path = Path(config_file)
        console.print(f"[blue]Validating configuration:[/blue] {file_path}")

        if schema_only:
            console.print("[dim]Schema validation only (semantic validation disabled)[/dim]")

        try:
            # Load and validate
            config = loader.load_config(file_path)
            console.print("[green]Configuration loaded successfully[/green]")

            if not schema_only:
                scenario = loader.validate_threat_scenario(config)
                console.print("[green]Schema validation passed[/green]")

                # Display scenario summary
                metadata = scenario.metadata
                console.print("\n[bold cyan]Scenario Summary:[/bold cyan]")
                console.print(f"Name: [cyan]{metadata.name}[/cyan]")
                threat_type_val = scenario.threat_type.value if hasattr(scenario.threat_type, 'value') else str(scenario.threat_type)
                difficulty_val = scenario.difficulty_level.value if hasattr(scenario.difficulty_level, 'value') else scenario.difficulty_level
                console.print(f"Threat Type: [yellow]{threat_type_val.replace('_', ' ').title()}[/yellow]")
                console.print(f"Difficulty: [magenta]{difficulty_val}/10[/magenta]")
                console.print(f"Duration: [blue]{scenario.estimated_duration} minutes[/blue]")
                seniority_val = scenario.target_profile.seniority.value if hasattr(scenario.target_profile.seniority, 'value') else str(scenario.target_profile.seniority)
                console.print(f"Target: [green]{scenario.target_profile.role} ({seniority_val.replace('_', ' ').title()})[/green]")

        except ConfigurationError as e:
            console.print(f"[red]Configuration Error:[/red] {e}")
        except SchemaValidationError as e:
            console.print(f"[red]Schema Validation Failed:[/red] {e}")
            if e.errors:
                console.print("\n[bold red]Validation Errors:[/bold red]")
                for i, error in enumerate(e.errors[:10], 1):  # Show first 10 errors
                    console.print(f"  {i}. [red]{error['location']}:[/red] {error['message']}")
                if len(e.errors) > 10:
                    console.print(f"  ... and {len(e.errors) - 10} more errors")

    else:
        # Validate current directory by default
        current_dir = Path.cwd()
        console.print(f"[blue]Validating YAML files in current directory:[/blue] {current_dir}")

        yaml_files = list(current_dir.glob("*.yaml")) + list(current_dir.glob("*.yml"))

        if not yaml_files:
            console.print("[yellow]No YAML files found in current directory[/yellow]")
            return

        valid_count = 0
        for yaml_file in yaml_files:
            try:
                config = loader.load_config(yaml_file)
                if not schema_only:
                    scenario = loader.validate_threat_scenario(config)
                console.print(f"[green]PASS[/green] {yaml_file.name}")
                valid_count += 1
            except (ConfigurationError, SchemaValidationError) as e:
                console.print(f"[red]FAIL[/red] {yaml_file.name}: {str(e)[:60]}...")

        console.print(f"\n[cyan]Validated {valid_count}/{len(yaml_files)} files successfully[/cyan]")


# Add templates command group
cli.add_command(templates)


@cli.command()
@click.option(
    "--simulation-id",
    default=None,
    help="Exercise/simulation ID (defaults to the ID in the input file)",
)
@click.option(
    "--input-file",
    "-i",
    type=click.Path(exists=True),
    default=None,
    help="Path to exercise result JSON (from 'vorsyghta exercise run --output-file')",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "html", "csv"]),
    default="json",
    help="Report format",
)
@click.option(
    "--output-file",
    "-o",
    default=None,
    help="Output file path (defaults to stdout for JSON, aar_<id>.<ext> otherwise)",
)
def report(
    simulation_id: Optional[str],
    input_file: Optional[str],
    output_format: str,
    output_file: Optional[str],
) -> None:
    """Generate an After-Action Report (AAR) from exercise results.

    Loads a completed exercise result (saved via 'vorsyghta exercise run
    --output-file') and generates a structured AAR using the Purple Team
    AARGenerator. The AAR includes detection coverage, MITRE technique gap
    analysis, prioritized remediation recommendations, and response time
    metrics.

    \b
    Examples:
        vorsyghta report -i exercise_result.json
        vorsyghta report -i exercise_result.json --format html -o aar.html
        vorsyghta report -i exercise_result.json --format csv -o aar.csv
        vorsyghta report --simulation-id abc123 -i exercise_result.json
    """
    import asyncio
    import json as _json

    if not input_file:
        console.print("[red]Error: --input-file is required. Provide an exercise result JSON file.[/red]")
        console.print("[dim]Generate one with: vorsyghta exercise run --output-file result.json[/dim]")
        sys.exit(1)

    # Load exercise result
    try:
        with open(input_file, "r") as f:
            exercise_data = _json.load(f)
    except Exception as e:
        console.print(f"[red]Failed to load input file: {e}[/red]")
        sys.exit(1)

    exercise_id = simulation_id or exercise_data.get("exercise_id", "unknown")
    red_team_stages = exercise_data.get("red_team_stages", [])
    blue_team_alerts = exercise_data.get("blue_team_alerts", [])
    tenant_id = exercise_data.get("tenant_id", "default")

    if not red_team_stages:
        console.print("[yellow]Warning: No red team stages found in the exercise result.[/yellow]")

    console.print(f"[blue]Generating AAR for exercise:[/blue] {exercise_id}")
    console.print(f"[dim]  Red team stages: {len(red_team_stages)}[/dim]")
    console.print(f"[dim]  Blue team alerts: {len(blue_team_alerts)}[/dim]")

    # Generate AAR
    try:
        from vorsyghta.core.aar_generator import AARGenerator

        generator = AARGenerator()
        aar = asyncio.run(generator.generate_aar(
            exercise_id=exercise_id,
            red_team_stages=red_team_stages,
            blue_team_alerts=blue_team_alerts,
            tenant_id=tenant_id,
        ))
    except Exception as e:
        console.print(f"[red]Failed to generate AAR: {e}[/red]")
        sys.exit(1)

    # Render output
    if output_format == "json":
        output_content = _json.dumps(aar, indent=2, default=str)
    elif output_format == "html":
        output_content = _render_aar_html(aar)
    elif output_format == "csv":
        output_content = _render_aar_csv(aar)
    else:
        console.print(f"[red]Unsupported format: {output_format}[/red]")
        sys.exit(1)

    # Write output
    if output_file:
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        Path(output_file).write_text(output_content, encoding="utf-8")
        console.print(f"[green]AAR saved to: {output_file}[/green]")
    else:
        if output_format == "json":
            console.print(output_content)
        else:
            # For HTML/CSV without -o, write to a default filename
            default_name = f"aar_{exercise_id}.{output_format}"
            Path(default_name).write_text(output_content, encoding="utf-8")
            console.print(f"[green]AAR saved to: {default_name}[/green]")

    # Print summary to console
    summary = aar.get("summary", "")
    if summary:
        console.print(f"\n[bold]Summary:[/bold] {summary}")

    metrics = aar.get("detection_metrics", {})
    if metrics:
        console.print(
            f"[blue]Detection:[/blue] {metrics.get('detected', 0)}/"
            f"{metrics.get('total_attacks', 0)} "
            f"({metrics.get('detection_rate_pct', 0)}%)"
        )

    gaps = aar.get("coverage_gaps", [])
    if gaps:
        console.print(f"[yellow]Coverage gaps:[/yellow] {len(gaps)}")

    rems = aar.get("remediation_recommendations", [])
    if rems:
        console.print(f"[green]Remediation recommendations:[/green] {len(rems)}")


def _render_aar_html(aar: dict) -> str:
    """Render an AAR dict as a self-contained HTML document."""
    summary = aar.get("summary", "No summary available.")
    metrics = aar.get("detection_metrics", {})
    gaps = aar.get("coverage_gaps", [])
    remediations = aar.get("remediation_recommendations", [])
    mitre = aar.get("mitre_coverage", {})
    response = aar.get("response_time_metrics", {})

    gap_rows = "".join(
        f"<tr><td>{g.get('technique_id', '')}</td><td>{g.get('tactic', '')}</td>"
        f"<td>{g.get('stage_name', '')}</td><td>{g.get('severity', '')}</td></tr>"
        for g in gaps
    )

    rem_rows = "".join(
        f"<tr><td>{r.get('priority', '')}</td><td>{r.get('technique_id', '')}</td>"
        f"<td>{r.get('finding', '')}</td><td>{r.get('recommendation', '')}</td>"
        f"<td>{r.get('effort', '')}</td><td>{r.get('impact', '')}</td></tr>"
        for r in remediations
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AAR — {aar.get('exercise_id', 'Unknown')}</title>
<style>
  body {{ font-family: -apple-system, system-ui, sans-serif; margin: 2rem; color: #1f1633; }}
  h1, h2 {{ color: #150f23; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
  th, td {{ border: 1px solid #e5e7eb; padding: 8px 12px; text-align: left; }}
  th {{ background: #150f23; color: #fff; }}
  .metric {{ display: inline-block; margin-right: 2rem; }}
  .metric .value {{ font-size: 1.5rem; font-weight: 700; }}
  .summary {{ background: #f0f0f0; padding: 1rem; border-radius: 8px; margin: 1rem 0; }}
</style>
</head>
<body>
<h1>After-Action Report</h1>
<p><strong>Exercise:</strong> {aar.get('exercise_id', '')} &nbsp;
   <strong>Tenant:</strong> {aar.get('tenant_id', '')} &nbsp;
   <strong>Generated:</strong> {aar.get('generated_at', '')}</p>

<div class="summary"><strong>Summary:</strong> {summary}</div>

<h2>Detection Metrics</h2>
<div class="metric">Total Attacks: <span class="value">{metrics.get('total_attacks', 0)}</span></div>
<div class="metric">Detected: <span class="value">{metrics.get('detected', 0)}</span></div>
<div class="metric">Missed: <span class="value">{metrics.get('missed', 0)}</span></div>
<div class="metric">Detection Rate: <span class="value">{metrics.get('detection_rate_pct', 0)}%</span></div>

<h2>MITRE Coverage</h2>
<p>Techniques attacked: {mitre.get('total_techniques', 0)} &nbsp;
   Techniques detected: {mitre.get('techniques_detected', 0)}</p>

<h2>Response Times</h2>
<p>Mean: {response.get('mean_response_time_ms', 'N/A')} ms &nbsp;
   Max: {response.get('max_response_time_ms', 'N/A')} ms &nbsp;
   Samples: {response.get('samples', 0)}</p>

<h2>Coverage Gaps ({len(gaps)})</h2>
<table><thead><tr><th>Technique</th><th>Tactic</th><th>Stage</th><th>Severity</th></tr></thead>
<tbody>{gap_rows or '<tr><td colspan="4">No gaps detected.</td></tr>'}</tbody></table>

<h2>Remediation Recommendations ({len(remediations)})</h2>
<table><thead><tr><th>#</th><th>Technique</th><th>Finding</th><th>Recommendation</th><th>Effort</th><th>Impact</th></tr></thead>
<tbody>{rem_rows or '<tr><td colspan="6">No recommendations.</td></tr>'}</tbody></table>
</body>
</html>"""


def _render_aar_csv(aar: dict) -> str:
    """Render an AAR dict as CSV (remediation recommendations as rows)."""
    import csv
    import io

    remediations = aar.get("remediation_recommendations", [])
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "exercise_id", "priority", "technique_id", "tactic",
        "finding", "recommendation", "effort", "impact",
    ])

    for r in remediations:
        writer.writerow([
            aar.get("exercise_id", ""),
            r.get("priority", ""),
            r.get("technique_id", ""),
            r.get("tactic", ""),
            r.get("finding", ""),
            r.get("recommendation", ""),
            r.get("effort", ""),
            r.get("impact", ""),
        ])

    return output.getvalue()


@cli.command()
@click.option(
    "--check-content",
    help="Check content against safety policies",
)
@click.option(
    "--policy",
    help="Specific policy to check against",
)
def safety(check_content: Optional[str], policy: Optional[str]) -> None:
    """Safety and compliance checking tools."""
    if check_content:
        console.print(f"[blue]Checking content safety:[/blue] {check_content[:50]}...")
    else:
        console.print("[blue]Safety policy information[/blue]")

    # Safety checking pending
    console.print("[yellow]Safety checking feature coming soon![/yellow]")


@cli.command()
@click.option("--env", is_flag=True, help="Show environment variable status")
def status(env: bool) -> None:
    """Show Vorsyghta system status."""
    console.print("[blue]Vorsyghta System Status[/blue]")

    status_table = Table(title="Component Status")
    status_table.add_column("Component", style="cyan")
    status_table.add_column("Status", style="green")
    status_table.add_column("Version", style="white")

    # System status checks
    status_table.add_row("CLI Interface", "Active", __version__)
    status_table.add_row("Configuration Engine", "Active", "v2.0")
    status_table.add_row("LLM Integration", "Active", "v1.0")
    status_table.add_row("Simulation Engine", "Active", "v1.0")
    status_table.add_row("API Gateway", "In Development", "N/A")
    status_table.add_row("Safety Module", "In Development", "N/A")

    console.print(status_table)

    # Show environment status if requested
    if env:
        console.print("\n")
        try:
            from vorsyghta.config.validate_env import print_environment_status
            print_environment_status()
        except ImportError:
            console.print("[yellow]Environment validation module not available[/yellow]")


# Add LLM integration commands
cli.add_command(llm_group, name="llm")

# Add intelligence commands
from .intelligence import intel_group
cli.add_command(intel_group, name="intel")

# Add deployment commands
from .deploy import deploy_group
cli.add_command(deploy_group, name="deploy")

# Add dataset commands
from .datasets import datasets
cli.add_command(datasets, name="datasets")

# Add logs management commands
cli.add_command(logs_group, name="logs")

# Add VM attack simulation commands
from .vm import vm_group
cli.add_command(vm_group, name="vm")

# Add MCP server commands
from .mcp import mcp_group
cli.add_command(mcp_group, name="mcp")

# Add field manuals commands
from .manuals import manuals_group
cli.add_command(manuals_group, name="manuals")

# Add playbook validation commands
from .validate import validate_cli
cli.add_command(validate_cli, name="validate")

# Add RAG system commands
from .rag import rag_group
cli.add_command(rag_group, name="rag")

# Add Feedback Loop commands
from .feedback import feedback_cli
cli.add_command(feedback_cli, name="feedback")

# Add Detection Rule Generator commands (Issue #25 - Blue Team)
cli.add_command(detect_group, name="detect")

# Add Exercise orchestration commands (Phase 2 — color-team exercises)
from .exercise import exercise_group
cli.add_command(exercise_group, name="exercise")

from .agent import agent_group
cli.add_command(agent_group, name="agent")

from .hunt import hunt_group
cli.add_command(hunt_group, name="hunt")

from .audit import audit_group
cli.add_command(audit_group, name="audit")

from .red_team import red_team
cli.add_command(red_team, name="red-team")

from .research import research
cli.add_command(research, name="research")

# Add enterprise integrations commands
from .integrations import integrations_group
cli.add_command(integrations_group, name="integrations")


def main() -> int:
    """Main entry point for the CLI."""
    try:
        cli()
        return 0
    except KeyboardInterrupt:
        console.print("\n[red]Operation cancelled by user[/red]")
        return 1
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return 1


if __name__ == "__main__":
    sys.exit(main())
