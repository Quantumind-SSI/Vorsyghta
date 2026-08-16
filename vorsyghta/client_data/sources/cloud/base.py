"""Base class for cloud storage adapters."""

from datetime import datetime
from typing import Any, Dict, List

from vorsyghta.client_data.config import ClientDataSourceConfig
from vorsyghta.client_data.credentials import CredentialProvider
from vorsyghta.client_data.models import ClientProfile, Document
from vorsyghta.client_data.sources.base import ClientDataSource


class BaseCloudStorageSource(ClientDataSource):
    """Base adapter for cloud storage sources."""

    def __init__(
        self,
        config: ClientDataSourceConfig,
        credentials: CredentialProvider,
    ):
        super().__init__(config, credentials)
        self.bucket = self.config.settings.get("bucket", "")
        self.prefix = self.config.settings.get("prefix", "")
        self.max_files = self.config.settings.get("max_files", 1000)

    def normalize(self, raw_files: List[Dict[str, Any]]) -> ClientProfile:
        return ClientProfile(
            tenant_id=self.config.tenant_id,
            documents=[self._to_document(f) for f in raw_files[: self.max_files]],
        )

    def _to_document(self, file_data: Dict[str, Any]) -> Document:
        last_modified = file_data.get("last_modified")
        if isinstance(last_modified, str):
            try:
                last_modified = datetime.fromisoformat(last_modified.replace("Z", "+00:00"))
            except ValueError:
                last_modified = None
        return Document(
            source_id=file_data.get("id", ""),
            name=file_data.get("name", ""),
            path=file_data.get("path", ""),
            mime_type=file_data.get("mime_type"),
            size_bytes=file_data.get("size_bytes"),
            last_modified=last_modified,
            metadata=file_data.get("metadata", {}),
        )
