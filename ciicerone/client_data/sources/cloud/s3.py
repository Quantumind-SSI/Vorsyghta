"""AWS S3 source adapter."""

from typing import Any, Dict, List

from ciicerone.client_data.config import ClientDataSourceConfig
from ciicerone.client_data.credentials import CredentialProvider
from .base import BaseCloudStorageSource


class S3Source(BaseCloudStorageSource):
    """List objects from an S3 bucket as documents."""

    def __init__(
        self,
        config: ClientDataSourceConfig,
        credentials: CredentialProvider,
    ):
        super().__init__(config, credentials)
        self.region = self.config.settings.get("region", "us-east-1")
        self._client = None

    def _get_client(self):
        if self._client is None:
            import boto3

            self._client = boto3.client("s3", region_name=self.region)
        return self._client

    async def authenticate(self) -> bool:
        try:
            self._get_client().list_buckets()
            return True
        except Exception:
            return False

    async def fetch(self) -> Any:
        paginator = self._get_client().get_paginator("list_objects_v2")
        files = []
        for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix):
            for obj in page.get("Contents", []):
                files.append(
                    {
                        "id": obj["Key"],
                        "name": obj["Key"].split("/")[-1],
                        "path": f"s3://{self.bucket}/{obj['Key']}",
                        "mime_type": None,
                        "size_bytes": obj.get("Size"),
                        "last_modified": obj.get("LastModified"),
                        "metadata": {"etag": obj.get("ETag", "")},
                    }
                )
        return self.normalize(files)
