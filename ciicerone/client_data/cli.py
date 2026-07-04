"""CLI commands for client data management."""

import asyncio
import json
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ciicerone.client_data.config import ClientDataConfig
from ciicerone.client_data.manager import ClientDataManager
from ciicerone.client_data.enrichment import ClientDataEnricher
from ciicerone.config.loader import load_config
from ciicerone.config.yaml_loader import YAMLConfigLoader

console = Console()


def _load_manager(config_path: str) -> ClientDataManager:
    config = load_config(config_path)
    raw_client_data = config.model_dump().get("client_data", {})
    tenant_count = len(raw_client_data.get("tenants", []))
    source_count = sum(len(t.get("sources", [])) for t in raw_client_data.get("tenants", []))
    console.print(f"[dim]Config: {config_path} | tenants={tenant_count} | raw_sources={source_count} | enabled={raw_client_data.get('enabled')}[/dim]")
    client_data_config = ClientDataConfig.model_validate(raw_client_data)
    manager = ClientDataManager(client_data_config)
    console.print(f"[dim]Manager registered sources: {len(manager._sources)}[/dim]")
    return manager


@click.group(name="client-data")
@click.pass_context
def client_data(ctx: click.Context):
    """Manage client data sources and enrichment."""
    pass


@client_data.command()
@click.option("--config", "-c", default=None, help="Path to configuration file")
@click.pass_context
@click.option("--tenant", "-t", default="default", help="Tenant ID to sync")
@click.option("--source", "-s", help="Sync a specific source by name")
def sync(ctx: click.Context, config: Optional[str], tenant: str, source: Optional[str]):
    """Sync client data sources."""
    config_path = config or ctx.obj.get("config", "config.yaml")
    asyncio.run(_sync_async(config_path, tenant, source))


async def _sync_async(config_path: str, tenant_id: str, source_name: Optional[str]):
    manager = _load_manager(config_path)
    if source_name:
        results = [await manager.sync_source(source_name)]
    else:
        results = await manager.sync_all(tenant_id)
    for result in results:
        color = "green" if result.status == "success" else "yellow" if result.status == "partial" else "red"
        console.print(f"[{color}]{result.source_name}: {result.status}[/{color}]")
        if result.errors:
            for error in result.errors:
                console.print(f"[red]  - {error}[/red]")


@client_data.command(name="list")
@click.option("--config", "-c", default=None, help="Path to configuration file")
@click.pass_context
@click.option("--tenant", "-t", help="Filter by tenant ID")
def list_sources(ctx: click.Context, config: Optional[str], tenant: Optional[str]):
    """List configured client data sources."""
    config_path = config or ctx.obj.get("config", "config.yaml")
    manager = _load_manager(config_path)
    sources = manager.list_sources(tenant)
    table = Table(title="Client Data Sources")
    table.add_column("Name")
    table.add_column("Tenant")
    table.add_column("Type")
    table.add_column("Enabled")
    for source in sources:
        if tenant is None or source["tenant_id"] == tenant:
            table.add_row(source["name"], source["tenant_id"], source["type"], str(source["enabled"]))
    console.print(table)


@client_data.command()
@click.option("--config", "-c", default=None, help="Path to configuration file")
@click.pass_context
@click.option("--tenant", "-t", required=True, help="Tenant ID")
def show(ctx: click.Context, config: Optional[str], tenant: str):
    """Show the synced client profile for a tenant."""
    config_path = config or ctx.obj.get("config", "config.yaml")
    manager = _load_manager(config_path)
    profile = manager.get_profile(tenant)
    if not profile:
        console.print(f"[red]No profile found for tenant: {tenant}[/red]")
        return
    summary = (
        f"Employees: {len(profile.employees)}\n"
        f"Assets: {len(profile.assets)}\n"
        f"Documents: {len(profile.documents)}\n"
        f"Network Topology: {'yes' if profile.network_topology else 'no'}\n"
        f"Synced At: {profile.synced_at}"
    )
    console.print(Panel(summary, title=f"Profile: {tenant}"))


@client_data.command()
@click.option("--config", "-c", default=None, help="Path to configuration file")
@click.pass_context
@click.option("--tenant", "-t", required=True, help="Tenant ID")
@click.option("--scenario", "-s", required=True, help="Path to scenario YAML file")
@click.option("--output", "-o", help="Path to save enriched scenario JSON")
@click.option("--recon", is_flag=True, help="Enable company reconnaissance via OSINT")
def enrich(ctx: click.Context, config: Optional[str], tenant: str, scenario: str, output: Optional[str], recon: bool):
    """Enrich a scenario with client data."""
    config_path = config or ctx.obj.get("config", "config.yaml")
    asyncio.run(_enrich_async(config_path, tenant, scenario, output, recon))


async def _enrich_async(
    config_path: str, tenant_id: str, scenario_path: str, output: Optional[str], recon: bool
):
    manager = _load_manager(config_path)
    profile = manager.get_profile(tenant_id)
    if not profile:
        console.print(f"[red]No profile found for tenant: {tenant_id}. Run sync first.[/red]")
        return

    loader = YAMLConfigLoader()
    try:
        scenario_config = loader.load_and_validate_scenario(Path(scenario_path))
    except Exception as e:
        console.print(f"[red]Failed to load scenario: {e}[/red]")
        return

    from ciicerone.client_data.recon import CompanyReconAgent

    enricher = ClientDataEnricher(
        profile,
        recon_agent=CompanyReconAgent() if recon else None,
    )
    enriched = await enricher.enrich_scenario(scenario_config, enable_recon=recon)
    data = enriched.model_dump()

    if output:
        with open(output, "w") as f:
            json.dump(data, f, indent=2, default=str)
        console.print(f"[green]Enriched scenario saved to {output}[/green]")
    else:
        console.print(json.dumps(data, indent=2, default=str))
