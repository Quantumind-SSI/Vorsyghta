"""Salesforce CRM source adapter."""

from typing import Any, Dict, List

import httpx

from vorsyghta.client_data.config import ClientDataSourceConfig
from vorsyghta.client_data.credentials import CredentialProvider
from .base import BaseCrmSource


class SalesforceSource(BaseCrmSource):
    """Fetch contacts from Salesforce REST API."""

    def __init__(
        self,
        config: ClientDataSourceConfig,
        credentials: CredentialProvider,
    ):
        super().__init__(config, credentials)
        self.base_url = self.config.settings.get("base_url", "https://login.salesforce.com")
        self.api_version = self.config.settings.get("api_version", "v60.0")
        self.timeout = 60
        self._access_token = None
        self._instance_url = None

    async def authenticate(self) -> bool:
        username = await self._resolve_secret(self.config.credentials.username)
        password = await self._resolve_secret(self.config.credentials.password)
        token = await self._resolve_secret(self.config.credentials.token)
        client_id = await self._resolve_secret(self.config.credentials.client_id)
        client_secret = await self._resolve_secret(self.config.credentials.client_secret)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/services/oauth2/token",
                data={
                    "grant_type": "password",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "username": username,
                    "password": f"{password}{token}",
                },
            )
            if resp.status_code != 200:
                return False
            data = resp.json()
            self._access_token = data.get("access_token")
            self._instance_url = data.get("instance_url")
            return True

    async def fetch(self) -> Any:
        headers = {"Authorization": f"Bearer {self._access_token}"}
        query = (
            "SELECT Id, Name, Email, Title, Department, Phone, Manager__c "
            "FROM Contact LIMIT {max}"
        ).format(max=self.max_records)
        url = f"{self._instance_url}/services/data/{self.api_version}/query"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(url, headers=headers, params={"q": query})
            resp.raise_for_status()
            records = resp.json().get("records", [])
        return self.normalize(
            [
                {
                    "id": r.get("Id"),
                    "name": r.get("Name"),
                    "email": r.get("Email"),
                    "role": r.get("Title", ""),
                    "department": r.get("Department", ""),
                    "phone": r.get("Phone"),
                    "manager": r.get("Manager__c"),
                    "metadata": {"attributes": r.get("attributes", {})},
                }
                for r in records
            ]
        )
