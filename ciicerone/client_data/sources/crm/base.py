"""Base class for CRM adapters."""

from datetime import datetime
from typing import Any, Dict, List

from ciicerone.client_data.config import ClientDataSourceConfig
from ciicerone.client_data.credentials import CredentialProvider
from ciicerone.client_data.models import ClientProfile, Employee
from ciicerone.client_data.sources.base import ClientDataSource


class BaseCrmSource(ClientDataSource):
    """Base adapter for CRM sources."""

    def __init__(
        self,
        config: ClientDataSourceConfig,
        credentials: CredentialProvider,
    ):
        super().__init__(config, credentials)
        self.max_records = self.config.settings.get("max_records", 1000)

    def normalize(self, raw_contacts: List[Dict[str, Any]]) -> ClientProfile:
        return ClientProfile(
            tenant_id=self.config.tenant_id,
            employees=[self._to_employee(c) for c in raw_contacts[: self.max_records]],
        )

    def _to_employee(self, data: Dict[str, Any]) -> Employee:
        return Employee(
            source_id=str(data.get("id", "")),
            email=data.get("email", ""),
            name=data.get("name", ""),
            role=data.get("role", ""),
            department=data.get("department", ""),
            phone=data.get("phone"),
            manager=data.get("manager"),
            location=data.get("location"),
            metadata=data.get("metadata", {}),
        )
