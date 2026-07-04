"""Azure Blob Storage source adapter."""

from typing import Any

from ciicerone.client_data.config import ClientDataSourceConfig
from ciicerone.client_data.credentials import CredentialProvider
from .base import BaseCloudStorageSource


class AzureBlobSource(BaseCloudStorageSource):
    """List blobs from an Azure container as documents."""

    def __init__(
        self,
        config: ClientDataSourceConfig,
        credentials: CredentialProvider,
    ):
        super().__init__(config, credentials)
        self.account_url = self.config.settings.get("account_url", "")
        self._client = None

    def _get_client(self):
        if self._client is None:
            from azure.identity import DefaultAzureCredential
            from azure.storage.blob import BlobServiceClient

            url = self.account_url or f"https://{self.bucket}.blob.core.windows.net"
            self._client = BlobServiceClient(
                account_url=url,
                credential=DefaultAzureCredential(),
            )
        return self._client

    async def authenticate(self) -> bool:
        try:
            next(self._get_client().list_containers())
            return True
        except Exception:
            return False

    async def fetch(self) -> Any:
        container_client = self._get_client().get_container_client(self.bucket)
        files = []
        for blob in container_client.list_blobs(name_starts_with=self.prefix):
            files.append(
                {
                    "id": blob.name,
                    "name": blob.name.split("/")[-1],
                    "path": f"azure://{self.bucket}/{blob.name}",
                    "mime_type": blob.content_settings.content_type if blob.content_settings else None,
                    "size_bytes": blob.size,
                    "last_modified": blob.last_modified,
                    "metadata": blob.metadata,
                }
            )
        return self.normalize(files)
