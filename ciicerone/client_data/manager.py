"""Multi-tenant client data manager."""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ciicerone.client_data.config import (
    ClientDataConfig,
    ClientDataSourceConfig,
    SecretProvider,
    SourceType,
)
from ciicerone.client_data.credentials import CredentialProvider, EnvCredentialProvider
from ciicerone.client_data.models import ClientProfile, SyncResult
from ciicerone.client_data.sources import ClientDataSource, GenericApiSource, Gns3Source
from ciicerone.client_data.sources.cloud import (
    S3Source,
    AzureBlobSource,
    GcsSource,
    OneDriveSource,
    GoogleDriveSource,
    SharePointSource,
)
from ciicerone.client_data.sources.crm import (
    SalesforceSource,
    HubSpotSource,
    Microsoft365CrmSource,
    GoogleWorkspaceCrmSource,
)

logger = logging.getLogger(__name__)


class ClientDataManager:
    """Orchestrate client data sources and profiles."""

    def __init__(self, config: ClientDataConfig):
        self.config = config
        self.storage_path = Path(config.storage_path).expanduser()
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._credential_providers: Dict[str, CredentialProvider] = {}
        self._sources: Dict[str, ClientDataSource] = {}
        self._profiles: Dict[str, ClientProfile] = {}
        self._register_default_providers()
        self._register_sources()
        self._load_profiles()

    def _register_default_providers(self) -> None:
        self._credential_providers[SecretProvider.ENV.value] = EnvCredentialProvider()

    def register_provider(self, name: str, provider: CredentialProvider) -> None:
        self._credential_providers[name] = provider

    def _get_credential_provider(self, provider_name: Optional[str]) -> CredentialProvider:
        name = provider_name or self.config.default_secret_provider.value
        provider = self._credential_providers.get(name)
        if provider is None:
            logger.warning(f"Credential provider {name} not found, falling back to env")
            return self._credential_providers[SecretProvider.ENV.value]
        return provider

    def _register_sources(self) -> None:
        logger.info(f"Registering sources for {len(self.config.tenants)} tenants")
        for tenant in self.config.tenants:
            logger.info(f"Tenant {tenant.tenant_id}: {len(tenant.sources)} source configs")
            for source_config in tenant.sources:
                logger.info(f"Source {source_config.name}: enabled={source_config.enabled}, type={source_config.type}")
                if not source_config.enabled:
                    continue
                source_config.tenant_id = tenant.tenant_id
                provider = self._get_credential_provider(None)
                source = self._build_source(source_config, provider)
                if source:
                    self._sources[source_config.name] = source
                    logger.info(f"Registered source {source_config.name}")
                else:
                    logger.warning(f"Failed to build source {source_config.name} (type={source_config.type})")

    def _build_source(
        self,
        config: ClientDataSourceConfig,
        provider: CredentialProvider,
    ) -> Optional[ClientDataSource]:
        mapping = {
            SourceType.API: GenericApiSource,
            SourceType.GNS3: Gns3Source,
            SourceType.S3: S3Source,
            SourceType.AZURE_BLOB: AzureBlobSource,
            SourceType.GCS: GcsSource,
            SourceType.ONEDRIVE: OneDriveSource,
            SourceType.GOOGLE_DRIVE: GoogleDriveSource,
            SourceType.SHAREPOINT: SharePointSource,
            SourceType.SALESFORCE: SalesforceSource,
            SourceType.HUBSPOT: HubSpotSource,
            SourceType.MICROSOFT365: Microsoft365CrmSource,
            SourceType.GOOGLE_WORKSPACE: GoogleWorkspaceCrmSource,
        }
        cls = mapping.get(config.type)
        if cls is None:
            return None
        return cls(config, provider)  # type: ignore[abstract]

    async def sync_source(self, source_name: str) -> SyncResult:
        source = self._sources.get(source_name)
        if not source:
            return SyncResult(
                source_name=source_name,
                tenant_id="unknown",
                status="failed",
                errors=["Source not found"],
            )
        result = await source.sync()
        if result.status in ("success", "partial"):
            profile = await source.fetch()
            profile.synced_at = datetime.utcnow()
            self._merge_profile(source.config.tenant_id, profile)
        return result

    def _merge_profile(self, tenant_id: str, profile: ClientProfile) -> None:
        existing = self._profiles.get(tenant_id)
        if existing is None:
            self._profiles[tenant_id] = profile
        else:
            existing.employees.extend(profile.employees)
            existing.assets.extend(profile.assets)
            existing.documents.extend(profile.documents)
            if profile.network_topology:
                existing.network_topology = profile.network_topology
            existing.synced_at = profile.synced_at
        self._save_profiles()

    async def sync_all(self, tenant_id: Optional[str] = None) -> List[SyncResult]:
        results = []
        for name, source in self._sources.items():
            if tenant_id and source.config.tenant_id != tenant_id:
                continue
            results.append(await self.sync_source(name))
        return results

    def get_profile(self, tenant_id: str) -> Optional[ClientProfile]:
        return self._profiles.get(tenant_id)

    def _profiles_file(self) -> Path:
        return self.storage_path / "profiles.json"

    def _save_profiles(self) -> None:
        data = {}
        for tenant_id, profile in self._profiles.items():
            data[tenant_id] = profile.model_dump(mode="json")
        try:
            self._profiles_file().write_text(json.dumps(data, indent=2, default=str))
        except Exception as e:
            logger.warning(f"Failed to save profiles: {e}")

    def _load_profiles(self) -> None:
        path = self._profiles_file()
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text())
            for tenant_id, profile_data in data.items():
                self._profiles[tenant_id] = ClientProfile.model_validate(profile_data)
            logger.info(f"Loaded {len(self._profiles)} profiles from {path}")
        except Exception as e:
            logger.warning(f"Failed to load profiles from {path}: {e}")

    def list_sources(self, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return [
            {
                "name": name,
                "tenant_id": source.config.tenant_id,
                "type": source.config.type,
                "enabled": source.config.enabled,
            }
            for name, source in self._sources.items()
            if tenant_id is None or source.config.tenant_id == tenant_id
        ]
