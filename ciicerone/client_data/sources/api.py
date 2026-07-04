"""Generic REST/GraphQL API adapter."""

import base64
from typing import Any, Dict, List, Optional

import httpx

from ciicerone.client_data.config import ClientDataSourceConfig
from ciicerone.client_data.credentials import CredentialProvider
from ciicerone.client_data.models import (
    Asset,
    ClientProfile,
    Document,
    Employee,
)
from .base import ClientDataSource


class GenericApiSource(ClientDataSource):
    """Generic API source supporting REST or GraphQL."""

    def __init__(
        self,
        config: ClientDataSourceConfig,
        credentials: CredentialProvider,
    ):
        super().__init__(config, credentials)
        self.protocol = self.config.settings.get("protocol", "rest")
        self.base_url = self.config.settings.get("base_url", "")
        self.timeout = self.config.settings.get("timeout_seconds", 60)

    async def authenticate(self) -> bool:
        try:
            headers = await self._build_headers()
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                url = self.config.settings.get("health_url") or self.base_url
                resp = await client.get(url, headers=headers)
                return resp.status_code < 400
        except Exception:
            return False

    async def _build_headers(self) -> Dict[str, str]:
        headers = {}
        auth_type = self.config.settings.get("auth_type", "bearer")
        if auth_type == "bearer" and self.config.credentials.token:
            token = await self._resolve_secret(self.config.credentials.token)
            headers["Authorization"] = f"Bearer {token}"
        elif auth_type == "api_key" and self.config.credentials.api_key:
            key = await self._resolve_secret(self.config.credentials.api_key)
            header_name = self.config.settings.get("api_key_header", "X-API-Key")
            headers[header_name] = key
        elif auth_type == "basic" and self.config.credentials.username:
            user = await self._resolve_secret(self.config.credentials.username)
            pw = await self._resolve_secret(self.config.credentials.password)
            value = base64.b64encode(f"{user}:{pw}".encode()).decode()
            headers["Authorization"] = f"Basic {value}"
        return headers

    async def fetch(self) -> ClientProfile:
        headers = await self._build_headers()
        if self.protocol == "graphql":
            raw = await self._fetch_graphql(headers)
        else:
            raw = await self._fetch_rest(headers)
        return self.normalize(raw)

    async def _fetch_rest(self, headers: Dict[str, str]) -> Any:
        endpoint = self.config.settings.get("endpoint", "")
        url = f"{self.base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            return resp.json()

    async def _fetch_graphql(self, headers: Dict[str, str]) -> Any:
        query = self.config.settings.get("query", "")
        variables = self.config.settings.get("variables", {})
        url = self.config.settings.get("graphql_url") or f"{self.base_url.rstrip('/')}/graphql"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                url,
                headers={**headers, "Content-Type": "application/json"},
                json={"query": query, "variables": variables},
            )
            resp.raise_for_status()
            return resp.json()

    def normalize(self, raw_data: Any) -> ClientProfile:
        mapping = self.config.settings.get("mapping", {})
        return ClientProfile(
            tenant_id=self.config.tenant_id,
            employees=self._map_employees(raw_data, mapping.get("employees", {})),
            assets=self._map_assets(raw_data, mapping.get("assets", {})),
            documents=self._map_documents(raw_data, mapping.get("documents", {})),
        )

    def _map_employees(self, data: Any, mapping: Dict[str, str]) -> List[Employee]:
        items = self._extract_items(data, mapping.get("root", "employees"))
        return [
            Employee(
                source_id=str(self._resolve(item, mapping.get("id", "id"))),
                email=self._resolve(item, mapping.get("email", "email")),
                name=self._resolve(item, mapping.get("name", "name")),
                role=self._resolve(item, mapping.get("role", "role")),
                department=self._resolve(item, mapping.get("department", "department")),
            )
            for item in items
        ]

    def _map_assets(self, data: Any, mapping: Dict[str, str]) -> List[Asset]:
        items = self._extract_items(data, mapping.get("root", "assets"))
        return [
            Asset(
                source_id=str(self._resolve(item, mapping.get("id", "id"))),
                name=self._resolve(item, mapping.get("name", "name")),
                asset_type=self._resolve(item, mapping.get("type", "type")),
                ip_address=self._resolve(item, mapping.get("ip", "ip_address")),
            )
            for item in items
        ]

    def _map_documents(self, data: Any, mapping: Dict[str, str]) -> List[Document]:
        items = self._extract_items(data, mapping.get("root", "documents"))
        return [
            Document(
                source_id=str(self._resolve(item, mapping.get("id", "id"))),
                name=self._resolve(item, mapping.get("name", "name")),
                path=self._resolve(item, mapping.get("path", "path")),
                mime_type=self._resolve(item, mapping.get("mime_type", "mime_type")),
            )
            for item in items
        ]

    def _extract_items(self, data: Any, path: str) -> List[Any]:
        if not path:
            return data if isinstance(data, list) else [data]
        current = data
        for key in path.split("."):
            if isinstance(current, dict):
                current = current.get(key, [])
            else:
                return []
        return current if isinstance(current, list) else [current]

    def _resolve(self, data: Any, path: str) -> str:
        if not path:
            return ""
        current = data
        for key in path.split("."):
            if isinstance(current, dict):
                current = current.get(key, "")
            else:
                return ""
        return str(current) if current is not None else ""
