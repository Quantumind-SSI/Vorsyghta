"""Microsoft 365 CRM source adapter."""

from typing import Any, Dict, List

import httpx

from vorsyghta.client_data.config import ClientDataSourceConfig
from vorsyghta.client_data.credentials import CredentialProvider
from .base import BaseCrmSource


class Microsoft365CrmSource(BaseCrmSource):
    """Fetch users from Microsoft 365 Graph API."""

    def __init__(
        self,
        config: ClientDataSourceConfig,
        credentials: CredentialProvider,
    ):
        super().__init__(config, credentials)
        self.base_url = "https://graph.microsoft.com/v1.0"
        self.timeout = 60

    async def authenticate(self) -> bool:
        headers = await self._build_headers()
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(f"{self.base_url}/organization", headers=headers)
            return resp.status_code == 200

    async def _build_headers(self) -> Dict[str, str]:
        token = await self._resolve_secret(self.config.credentials.token)
        return {"Authorization": f"Bearer {token}"}

    async def fetch(self) -> Any:
        headers = await self._build_headers()
        users: List[Dict[str, Any]] = []
        url = f"{self.base_url}/users"
        params: Dict[str, Any] = {"$select": "id,displayName,mail,jobTitle,department,officeLocation,manager", "$top": 100}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            while url and len(users) < self.max_records:
                resp = await client.get(url, headers=headers, params=params)
                resp.raise_for_status()
                data = resp.json()
                users.extend(data.get("value", []))
                url = data.get("@odata.nextLink")
                params = {}
        return self.normalize(
            [
                {
                    "id": u.get("id"),
                    "name": u.get("displayName"),
                    "email": u.get("mail"),
                    "role": u.get("jobTitle"),
                    "department": u.get("department"),
                    "location": u.get("officeLocation"),
                    "manager": u.get("manager", {}).get("displayName") if isinstance(u.get("manager"), dict) else None,
                    "metadata": {"userPrincipalName": u.get("userPrincipalName")},
                }
                for u in users
            ]
        )
