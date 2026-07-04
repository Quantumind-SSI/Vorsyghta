"""FastAPI router for client data."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException

from ciicerone.client_data.config import ClientDataConfig
from ciicerone.client_data.manager import ClientDataManager
from ciicerone.config.loader import load_config

router = APIRouter(prefix="/client-data", tags=["client-data"])


def _get_manager(config_path: str = "config.yaml") -> ClientDataManager:
    config = load_config(config_path)
    client_data_config = ClientDataConfig.model_validate(
        config.model_dump().get("client_data", {})
    )
    return ClientDataManager(client_data_config)


@router.get("/sources")
async def list_sources(tenant_id: Optional[str] = None) -> Dict[str, Any]:
    """List configured client data sources."""
    manager = _get_manager()
    return {
        "tenant_id": tenant_id,
        "sources": manager.list_sources(tenant_id),
    }


@router.post("/sync")
async def sync_sources(tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Sync client data sources."""
    manager = _get_manager()
    results = await manager.sync_all(tenant_id)
    return [r.model_dump() for r in results]


@router.post("/sync/{source_name}")
async def sync_source(source_name: str) -> Dict[str, Any]:
    """Sync a specific client data source."""
    manager = _get_manager()
    result = await manager.sync_source(source_name)
    return result.model_dump()


@router.get("/profile/{tenant_id}")
async def get_profile(tenant_id: str) -> Dict[str, Any]:
    """Get the synced client profile for a tenant."""
    manager = _get_manager()
    profile = manager.get_profile(tenant_id)
    if not profile:
        raise HTTPException(status_code=404, detail=f"No profile for tenant {tenant_id}")
    return profile.model_dump()


@router.post("/enrich/{tenant_id}")
async def enrich_scenario(
    tenant_id: str,
    scenario: Dict[str, Any],
    enable_recon: bool = False,
) -> Dict[str, Any]:
    """Enrich a scenario with client data and optional company recon."""
    from ciicerone.client_data.enrichment import ClientDataEnricher
    from ciicerone.client_data.recon import CompanyReconAgent
    from ciicerone.config.models import ThreatScenario

    manager = _get_manager()
    profile = manager.get_profile(tenant_id)
    if not profile:
        raise HTTPException(status_code=404, detail=f"No profile for tenant {tenant_id}")

    try:
        scenario_obj = ThreatScenario.model_validate(scenario)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid scenario: {e}")

    enricher = ClientDataEnricher(
        profile,
        recon_agent=CompanyReconAgent() if enable_recon else None,
    )
    enriched = await enricher.enrich_scenario(scenario_obj, enable_recon=enable_recon)
    return enriched.model_dump()
