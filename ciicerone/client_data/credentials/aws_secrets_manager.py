"""AWS Secrets Manager credential provider."""

from typing import Optional

import boto3
from botocore.exceptions import ClientError

from ciicerone.client_data.config import SecretRef
from .base import CredentialProvider


class AwsSecretsManagerProvider(CredentialProvider):
    """Resolve secrets from AWS Secrets Manager."""

    def __init__(self, region_name: str = "us-east-1"):
        self.region_name = region_name
        self._client = None

    def _get_client(self):
        if self._client is None:
            self._client = boto3.client("secretsmanager", region_name=self.region_name)
        return self._client

    async def get_secret(self, ref: SecretRef) -> Optional[str]:
        try:
            response = self._get_client().get_secret_value(SecretId=ref.name)
            return response.get("SecretString")
        except ClientError:
            return None
