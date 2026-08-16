"""Google Workspace CRM source adapter."""

from typing import Any, Dict, List

import httpx

from vorsyghta.client_data.config import ClientDataSourceConfig
from vorsyghta.client_data.credentials import CredentialProvider
from .base import BaseCrmSource


class GoogleWorkspaceCrmSource(BaseCrmSource):
    """Fetch users from Google Workspace Directory API."""

    def __init__(
        self,
        config: ClientDataSourceConfig,
        credentials: CredentialProvider,
    ):
        super().__init__(config, credentials)
        self.base_url = "https://admin.googleapis.com/admin/directory/v1"
        self.timeout = 60

    async def authenticate(self) -> bool:
        headers = await self._build_headers()
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(
                f"{self.base_url}/users",
                headers=headers,
                params={"domain": self.config.settings.get("domain", "")},
            )
            return resp.status_code == 200

    async def _build_headers(self) -> Dict[str, str]:
        token = await self._resolve_secret(self.config.credentials.token)
        return {"Authorization": f"Bearer {token}"}

    async def fetch(self) -> Any:
        headers = await self._build_headers()
        users: List[Dict[str, Any]] = []
        next_token = None
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            while len(users) < self.max_records:
                params = {"maxResults": 100, "domain": self.config.settings.get("domain", "")}
                if next_token:
                    params["pageToken"] = next_token
                resp = await client.get(f"{self.base_url}/users", headers=headers, params=params)
                resp.raise_for_status()
                data = resp.json()
                users.extend(data.get("users", []))
                next_token = data.get("nextPageToken")
                if not next_token:
                    break
        return self.normalize(
            [
                {
                    "id": u.get("id"),
                    "name": u.get("name", {}).get("fullName"),
                    "email": u.get("primaryEmail"),
                    "role": u.get("organizations", [{}])[0].get("title") if u.get("organizations") else None,
                    "department": u.get("organizations", [{}])[0].get("department") if u.get("organizations") else None,
                    "location": u.get("locations", [{}])[0].get("area") if u.get("locations") else None,
                    "manager": u.get("relations", [{}])[0].get("value") if u.get("relations") else None,
                    "metadata": {"isAdmin": u.get("isAdmin", False)},
                }
                for u in users
            ]
        )
