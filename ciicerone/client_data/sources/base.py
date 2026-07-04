"""Base class for client data source adapters."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Optional

from ciicerone.client_data.config import ClientDataSourceConfig, SecretRef
from ciicerone.client_data.credentials import CredentialProvider
from ciicerone.client_data.models import ClientProfile, SyncResult


class ClientDataSource(ABC):
    """Abstract base for all client data sources."""

    def __init__(
        self,
        config: ClientDataSourceConfig,
        credentials: CredentialProvider,
    ):
        self.config = config
        self.credentials = credentials
        self._authenticated = False

    @abstractmethod
    async def authenticate(self) -> bool:
        """Authenticate with the source and return success status."""
        pass

    @abstractmethod
    async def fetch(self) -> ClientProfile:
        """Fetch data from the source and return a normalized profile."""
        pass

    @abstractmethod
    def normalize(self, raw_data: Any) -> ClientProfile:
        """Convert raw source data into a normalized ClientProfile."""
        pass

    async def sync(self) -> SyncResult:
        """Authenticate, fetch, and normalize data."""
        result = SyncResult(
            source_name=self.config.name,
            tenant_id=self.config.tenant_id,
            status="failed",
        )
        try:
            self._authenticated = await self.authenticate()
            if not self._authenticated:
                result.errors.append("Authentication failed")
                result.completed_at = datetime.utcnow()
                return result

            profile = await self.fetch()
            result.employees_count = len(profile.employees)
            result.assets_count = len(profile.assets)
            result.documents_count = len(profile.documents)
            result.status = "success" if not result.errors else "partial"
            result.completed_at = datetime.utcnow()
        except Exception as e:
            result.errors.append(str(e))
            result.completed_at = datetime.utcnow()
        return result

    async def _resolve_secret(self, ref: Optional[SecretRef]) -> str:
        if ref is None:
            return ""
        return await self.credentials.get_required(ref)
