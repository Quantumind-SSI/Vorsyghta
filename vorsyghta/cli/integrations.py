"""Enterprise integrations CLI commands for Vorsyghta.

Exposes the existing enterprise platform integrations (Microsoft 365,
Proofpoint, KnowBe4, Slack) through the command line:

    vorsyghta integrations list                       — list available integrations
    vorsyghta integrations test <platform>            — test connectivity for a platform
    vorsyghta integrations test-all                   — test all platforms
    vorsyghta integrations deploy <platform> -c <f>   — deploy content through a platform
    vorsyghta integrations metrics <platform> <id>    — get campaign metrics
    vorsyghta integrations auth <platform>            — authenticate with a platform

Configuration is read from environment variables:
    M365_TENANT_ID / M365_CLIENT_ID / M365_CLIENT_SECRET
    PROOFPOINT_API_KEY / PROOFPOINT_BASE_URL
    KNOWBE4_API_KEY / KNOWBE4_BASE_URL
    SLACK_BOT_TOKEN
"""
import asyncio
import json
import os
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


SUPPORTED_PLATFORMS = ["microsoft365", "proofpoint", "knowbe4", "slack"]


def _load_platform_config() -> dict:
    """Load platform configuration from environment variables."""
    config = {}

    m365_tenant = os.getenv("M365_TENANT_ID")
    m365_client = os.getenv("M365_CLIENT_ID")
    m365_secret = os.getenv("M365_CLIENT_SECRET")
    if m365_tenant and m365_client and m365_secret:
        config["microsoft365"] = {
            "tenant_id": m365_tenant,
            "client_id": m365_client,
            "client_secret": m365_secret,
        }

    proofpoint_key = os.getenv("PROOFPOINT_API_KEY")
    if proofpoint_key:
        config["proofpoint"] = {
            "api_key": proofpoint_key,
            "base_url": os.getenv(
                "PROOFPOINT_BASE_URL", "https://tap-api-v2.proofpoint.com"
            ),
        }

    knowbe4_key = os.getenv("KNOWBE4_API_KEY")
    if knowbe4_key:
        config["knowbe4"] = {
            "api_key": knowbe4_key,
            "base_url": os.getenv("KNOWBE4_BASE_URL", "https://us.api.knowbe4.com"),
        }

    slack_token = os.getenv("SLACK_BOT_TOKEN")
    if slack_token:
        config["slack"] = {"bot_token": slack_token}

    return config


def _get_manager():
    """Build a PlatformIntegrationManager from the current environment."""
    from vorsyghta.deployment.integrations import PlatformIntegrationManager

    return PlatformIntegrationManager(_load_platform_config())


@click.group(name="integrations")
def integrations_group():
    """Enterprise integration operations.

    Manage and interact with enterprise security platform integrations
    (Microsoft 365, Proofpoint, KnowBe4, Slack).

    \b
    Commands:
        list        List available integrations and their status
        test        Test connectivity for a single platform
        test-all    Test connectivity for all configured platforms
        deploy      Deploy content through a platform
        metrics     Get campaign metrics from a platform
        auth        Authenticate with a platform
    """
    pass


@integrations_group.command(name="list")
def list_integrations():
    """List available integrations and their status."""
    manager = _get_manager()
    available = manager.get_available_platforms()

    table = Table(title="Enterprise Integrations")
    table.add_column("Platform", style="bold cyan")
    table.add_column("Configured", justify="center")
    table.add_column("Authenticated", justify="center")

    for platform in SUPPORTED_PLATFORMS:
        configured = platform in manager.integrations
        authenticated = False
        if configured:
            integration = manager.integrations[platform]
            authenticated = getattr(integration, "_authenticated", False)

        configured_str = "[green]Yes[/green]" if configured else "[red]No[/red]"
        auth_str = "[green]Yes[/green]" if authenticated else "[dim]No[/dim]"
        table.add_row(platform, configured_str, auth_str)

    console.print(table)
    console.print(
        f"\n[dim]Configured: {len(available)}/{len(SUPPORTED_PLATFORMS)} platforms[/dim]"
    )
    if not available:
        console.print(
            "[yellow]No platforms configured. Set the required environment "
            "variables to enable integrations.[/yellow]"
        )


@integrations_group.command(name="test")
@click.argument("platform")
def test_platform(platform: str):
    """Test connectivity for a single platform."""
    if platform not in SUPPORTED_PLATFORMS:
        console.print(
            f"[red]Unsupported platform '{platform}'.[/red] "
            f"Supported: {', '.join(SUPPORTED_PLATFORMS)}"
        )
        return
    asyncio.run(_test_platform_async(platform))


async def _test_platform_async(platform: str):
    manager = _get_manager()
    if platform not in manager.integrations:
        console.print(
            f"[red]Platform '{platform}' is not configured.[/red] "
            "Set the required environment variables to enable it."
        )
        return

    console.print(f"Testing connectivity for [bold]{platform}[/bold]...")
    try:
        result = await manager.test_platform_connectivity(platform)
    except Exception as e:
        console.print(f"[red]Connectivity test failed: {e}[/red]")
        return

    status_val = result.get("status", "unknown")
    status_color = "green" if status_val == "healthy" else "red"

    console.print(Panel(
        f"Platform:        [bold]{result.get('platform', platform)}[/bold]\n"
        f"Authentication:  {result.get('authentication', False)}\n"
        f"Status:          [{status_color}]{status_val}[/{status_color}]\n"
        f"Timestamp:       {result.get('timestamp', '—')}"
        + (f"\nError:           [red]{result.get('error', '')}[/red]"
           if result.get("error") else ""),
        title=f"Connectivity Test — {platform}",
        border_style=status_color,
    ))


@integrations_group.command(name="test-all")
def test_all():
    """Test connectivity for all configured platforms."""
    asyncio.run(_test_all_async())


async def _test_all_async():
    manager = _get_manager()
    available = manager.get_available_platforms()

    if not available:
        console.print(
            "[yellow]No platforms configured. Set the required environment "
            "variables to enable integrations.[/yellow]"
        )
        return

    console.print(f"Testing connectivity for [bold]{len(available)}[/bold] platform(s)...\n")

    table = Table(title="Connectivity Test Results")
    table.add_column("Platform", style="bold cyan")
    table.add_column("Authentication", justify="center")
    table.add_column("Status")
    table.add_column("Details")

    healthy = []
    failed = []

    for platform in available:
        try:
            result = await manager.test_platform_connectivity(platform)
            auth_ok = result.get("authentication", False)
            status_val = result.get("status", "unknown")
            error = result.get("error", "")

            auth_str = "[green]✓[/green]" if auth_ok else "[red]✗[/red]"
            status_color = "green" if status_val == "healthy" else "red"
            details = error if error else "—"

            table.add_row(platform, auth_str, f"[{status_color}]{status_val}[/{status_color}]", details)

            if status_val == "healthy":
                healthy.append(platform)
            else:
                failed.append(platform)
        except Exception as e:
            table.add_row(platform, "[red]✗[/red]", "[red]error[/red]", str(e))
            failed.append(platform)

    console.print(table)
    console.print(
        f"\n[green]Healthy: {len(healthy)}[/green]  [red]Failed: {len(failed)}[/red]"
    )


@integrations_group.command(name="deploy")
@click.argument("platform")
@click.option("--content", "-c", "content_path", required=True,
              help="Path to JSON file with content to deploy")
@click.option("--targets", "-t", "targets_path",
              help="Path to JSON file with targets list (defaults to content's 'targets' field)")
def deploy(platform: str, content_path: str, targets_path: Optional[str]):
    """Deploy content through a platform.

    The content JSON file should contain the content fields (subject,
    body_html, sender_email, etc.). Targets may be embedded in the
    content file under a 'targets' key or supplied separately via
    --targets.
    """
    if platform not in SUPPORTED_PLATFORMS:
        console.print(
            f"[red]Unsupported platform '{platform}'.[/red] "
            f"Supported: {', '.join(SUPPORTED_PLATFORMS)}"
        )
        return
    asyncio.run(_deploy_async(platform, content_path, targets_path))


async def _deploy_async(platform: str, content_path: str, targets_path: Optional[str]):
    # Load content
    try:
        with open(content_path, "r") as f:
            content = json.load(f)
    except Exception as e:
        console.print(f"[red]Failed to load content file: {e}[/red]")
        return

    # Resolve targets
    if targets_path:
        try:
            with open(targets_path, "r") as f:
                targets = json.load(f)
        except Exception as e:
            console.print(f"[red]Failed to load targets file: {e}[/red]")
            return
    elif "targets" in content:
        targets = content.pop("targets")
    else:
        console.print(
            "[red]No targets provided. Use --targets or include a 'targets' "
            "key in the content file.[/red]"
        )
        return

    manager = _get_manager()
    if platform not in manager.integrations:
        console.print(
            f"[red]Platform '{platform}' is not configured.[/red] "
            "Set the required environment variables to enable it."
        )
        return

    console.print(f"Deploying content via [bold]{platform}[/bold] to {len(targets)} target(s)...")
    try:
        result = await manager.deploy_through_platform(platform, content, targets)
    except Exception as e:
        console.print(f"[red]Deployment failed: {e}[/red]")
        return

    status_val = result.status.value if hasattr(result.status, "value") else str(result.status)
    status_color = "green" if status_val in ("completed", "active") else "yellow"

    console.print(Panel(
        f"Deployment ID:    [bold]{result.deployment_id}[/bold]\n"
        f"Channel:          {result.channel.value if hasattr(result.channel, 'value') else result.channel}\n"
        f"Status:           [{status_color}]{status_val}[/{status_color}]\n"
        f"Targets attempted: {result.targets_attempted}\n"
        f"Targets successful: [green]{result.targets_successful}[/green]\n"
        f"Targets failed:    [red]{result.targets_failed}[/red]\n"
        f"Duration:          {result.deployment_duration_seconds:.2f}s",
        title=f"Deployment Result — {platform}",
        border_style=status_color,
    ))

    if result.tracking_ids:
        console.print(f"[dim]Tracking IDs: {', '.join(result.tracking_ids)}[/dim]")


@integrations_group.command(name="metrics")
@click.argument("platform")
@click.argument("campaign_id")
def metrics(platform: str, campaign_id: str):
    """Get campaign metrics from a platform."""
    if platform not in SUPPORTED_PLATFORMS:
        console.print(
            f"[red]Unsupported platform '{platform}'.[/red] "
            f"Supported: {', '.join(SUPPORTED_PLATFORMS)}"
        )
        return
    asyncio.run(_metrics_async(platform, campaign_id))


async def _metrics_async(platform: str, campaign_id: str):
    manager = _get_manager()
    if platform not in manager.integrations:
        console.print(
            f"[red]Platform '{platform}' is not configured.[/red] "
            "Set the required environment variables to enable it."
        )
        return

    console.print(
        f"Fetching metrics for campaign [bold]{campaign_id}[/bold] from {platform}..."
    )
    try:
        metrics = await manager.integrations[platform].get_campaign_metrics(campaign_id)
    except Exception as e:
        console.print(f"[red]Failed to get metrics: {e}[/red]")
        return

    table = Table(title=f"Campaign Metrics — {campaign_id}")
    table.add_column("Metric", style="bold cyan")
    table.add_column("Value", justify="right")

    table.add_row("Emails sent", str(metrics.emails_sent))
    table.add_row("Emails delivered", str(metrics.emails_delivered))
    table.add_row("Emails opened", str(metrics.emails_opened))
    table.add_row("Links clicked", str(metrics.links_clicked))
    table.add_row("Attachments downloaded", str(metrics.attachments_downloaded))
    table.add_row("Credentials submitted", str(metrics.credentials_submitted))
    table.add_row("Verification attempts", str(metrics.verification_attempts))
    table.add_row("Training effectiveness", f"{metrics.training_effectiveness_score:.2f}")
    table.add_row("Awareness improvement", f"{metrics.security_awareness_improvement:.2f}")

    console.print(table)


@integrations_group.command(name="auth")
@click.argument("platform")
def auth(platform: str):
    """Authenticate with a platform."""
    if platform not in SUPPORTED_PLATFORMS:
        console.print(
            f"[red]Unsupported platform '{platform}'.[/red] "
            f"Supported: {', '.join(SUPPORTED_PLATFORMS)}"
        )
        return
    asyncio.run(_auth_async(platform))


async def _auth_async(platform: str):
    manager = _get_manager()
    if platform not in manager.integrations:
        console.print(
            f"[red]Platform '{platform}' is not configured.[/red] "
            "Set the required environment variables to enable it."
        )
        return

    console.print(f"Authenticating with [bold]{platform}[/bold]...")
    try:
        success = await manager.integrations[platform].authenticate()
    except Exception as e:
        console.print(f"[red]Authentication failed: {e}[/red]")
        return

    if success:
        console.print(f"[green]Successfully authenticated with {platform}.[/green]")
    else:
        console.print(f"[red]Authentication failed for {platform}.[/red]")
