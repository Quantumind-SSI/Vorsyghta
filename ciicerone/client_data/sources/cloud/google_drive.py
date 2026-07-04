"""Google Drive source adapter."""

from typing import Any, Dict, List, Optional

import httpx

from ciicerone.client_data.config import ClientDataSourceConfig
from ciicerone.client_data.credentials import CredentialProvider
from .base import BaseCloudStorageSource


class GoogleDriveSource(BaseCloudStorageSource):
    """List files from Google Drive API."""

    def __init__(
        self,
        config: ClientDataSourceConfig,
        credentials: CredentialProvider,
    ):
        super().__init__(config, credentials)
        self.base_url = "https://www.googleapis.com/drive/v3"
        self.timeout = 60

    async def authenticate(self) -> bool:
        headers = await self._build_headers()
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(f"{self.base_url}/about?fields=user", headers=headers)
            return resp.status_code == 200

    async def _build_headers(self) -> Dict[str, str]:
        token = await self._resolve_secret(self.config.credentials.token)
        return {"Authorization": f"Bearer {token}"}

    async def fetch(self) -> Any:
        headers = await self._build_headers()
        files: List[Dict[str, Any]] = []
        next_page_token: Optional[str] = None
        fields = "nextPageToken,files(id,name,mimeType,size,modifiedTime,webViewLink)"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            while len(files) < self.max_files:
                params: Dict[str, Any] = {"pageSize": 100, "fields": fields}
                if next_page_token:
                    params["pageToken"] = next_page_token
                resp = await client.get(f"{self.base_url}/files", headers=headers, params=params)
                resp.raise_for_status()
                data = resp.json()
                for item in data.get("files", []):
                    if item.get("mimeType") != "application/vnd.google-apps.folder":
                        files.append(self._item_to_doc(item))
                next_page_token = data.get("nextPageToken")
                if not next_page_token:
                    break
        return self.normalize(files)

    def _item_to_doc(self, item: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": item.get("id", ""),
            "name": item.get("name", ""),
            "path": item.get("webViewLink", ""),
            "mime_type": item.get("mimeType"),
            "size_bytes": item.get("size"),
            "last_modified": item.get("modifiedTime"),
            "metadata": {},
        }
