"""Google Cloud Storage source adapter."""

from typing import Any

from ciicerone.client_data.config import ClientDataSourceConfig
from ciicerone.client_data.credentials import CredentialProvider
from .base import BaseCloudStorageSource


class GcsSource(BaseCloudStorageSource):
    """List objects from a GCS bucket as documents."""

    def __init__(
        self,
        config: ClientDataSourceConfig,
        credentials: CredentialProvider,
    ):
        super().__init__(config, credentials)
        self.project_id = self.config.settings.get("project_id", "")
        self._client = None

    def _get_client(self):
        if self._client is None:
            from google.cloud import storage

            self._client = storage.Client(project=self.project_id)
        return self._client

    async def authenticate(self) -> bool:
        try:
            self._get_client().list_buckets()
            return True
        except Exception:
            return False

    async def fetch(self) -> Any:
        bucket = self._get_client().bucket(self.bucket)
        blobs = bucket.list_blobs(prefix=self.prefix)
        files = []
        for blob in blobs:
            files.append(
                {
                    "id": blob.name,
                    "name": blob.name.split("/")[-1],
                    "path": f"gs://{self.bucket}/{blob.name}",
                    "mime_type": blob.content_type,
                    "size_bytes": blob.size,
                    "last_modified": blob.updated,
                    "metadata": blob.metadata,
                }
            )
        return self.normalize(files)
