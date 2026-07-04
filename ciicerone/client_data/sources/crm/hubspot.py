"""HubSpot CRM source adapter."""

from typing import Any, Dict, List

import httpx

from ciicerone.client_data.config import ClientDataSourceConfig
from ciicerone.client_data.credentials import CredentialProvider
from ciicerone.client_data.models import Employee
from .base import BaseCrmSource


class HubSpotSource(BaseCrmSource):
    """Fetch contacts from HubSpot CRM API."""

    def __init__(
        self,
        config: ClientDataSourceConfig,
        credentials: CredentialProvider,
    ):
        super().__init__(config, credentials)
        self.base_url = "https://api.hubapi.com"
        self.timeout = 60

    async def authenticate(self) -> bool:
        api_key = await self._resolve_secret(self.config.credentials.api_key)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(
                f"{self.base_url}/integrations/v1/me",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            return resp.status_code == 200

    async def fetch(self) -> Any:
        api_key = await self._resolve_secret(self.config.credentials.api_key)
        headers = {"Authorization": f"Bearer {api_key}"}
        contacts: List[Dict[str, Any]] = []
        url = f"{self.base_url}/crm/v3/objects/contacts"
        params: Dict[str, Any] = {"limit": min(100, self.max_records), "properties": "firstname,lastname,email,jobtitle,department,phone"}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            while url and len(contacts) < self.max_records:
                resp = await client.get(url, headers=headers, params=params)
                resp.raise_for_status()
                data = resp.json()
                contacts.extend(data.get("results", []))
                url = data.get("paging", {}).get("next", {}).get("link")
                params = {}
        return self.normalize(
            [
                {
                    "id": c.get("id"),
                    "name": self._build_name(c.get("properties", {})),
                    "email": c.get("properties", {}).get("email"),
                    "role": c.get("properties", {}).get("jobtitle"),
                    "department": c.get("properties", {}).get("department"),
                    "phone": c.get("properties", {}).get("phone"),
                    "metadata": {"properties": c.get("properties", {})},
                }
                for c in contacts
            ]
        )

    def _to_employee(self, data: Dict[str, Any]) -> Employee:
        properties = data.get("properties", {})
        return Employee(
            source_id=str(data.get("id", "")),
            email=properties.get("email", ""),
            name=self._build_name(properties),
            role=properties.get("jobtitle", ""),
            department=properties.get("department", ""),
            phone=properties.get("phone"),
            metadata={"properties": properties},
        )

    def _build_name(self, properties: Dict[str, str]) -> str:
        first = properties.get("firstname", "")
        last = properties.get("lastname", "")
        return f"{first} {last}".strip()
