"""Microsoft SharePoint source adapter."""

from typing import Any, Dict, List

import httpx

from vorsyghta.client_data.config import ClientDataSourceConfig
from vorsyghta.client_data.credentials import CredentialProvider
from .base import BaseCloudStorageSource


class SharePointSource(BaseCloudStorageSource):
    """List files from a SharePoint site via Microsoft Graph API."""

    def __init__(
        self,
        config: ClientDataSourceConfig,
        credentials: CredentialProvider,
    ):
        super().__init__(config, credentials)
        self.base_url = "https://graph.microsoft.com/v1.0"
        self.site_id = self.config.settings.get("site_id", "")
        self.drive_id = self.config.settings.get("drive_id", "")
        self.timeout = 60

    async def authenticate(self) -> bool:
        headers = await self._build_headers()
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(f"{self.base_url}/sites/{self.site_id}", headers=headers)
            return resp.status_code == 200

    async def _build_headers(self) -> Dict[str, str]:
        token = await self._resolve_secret(self.config.credentials.token)
        return {"Authorization": f"Bearer {token}"}

    async def fetch(self) -> Any:
        headers = await self._build_headers()
        files: List[Dict[str, Any]] = []
        url = f"{self.base_url}/sites/{self.site_id}/drives/{self.drive_id}/root/children"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            while url and len(files) < self.max_files:
                resp = await client.get(url, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                for item in data.get("value", []):
                    if "folder" not in item:
                        files.append(self._item_to_doc(item))
                url = data.get("@odata.nextLink")
        return self.normalize(files)

    def _item_to_doc(self, item: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": item.get("id", ""),
            "name": item.get("name", ""),
            "path": item.get("webUrl", ""),
            "mime_type": item.get("file", {}).get("mimeType"),
            "size_bytes": item.get("size"),
            "last_modified": item.get("lastModifiedDateTime"),
            "metadata": {"drive_id": self.drive_id, "site_id": self.site_id},
        }
