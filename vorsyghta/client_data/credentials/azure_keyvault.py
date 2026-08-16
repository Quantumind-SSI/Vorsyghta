"""Azure Key Vault credential provider."""

from typing import Optional

from vorsyghta.client_data.config import SecretRef
from .base import CredentialProvider


class AzureKeyVaultProvider(CredentialProvider):
    """Resolve secrets from Azure Key Vault."""

    def __init__(self, vault_url: str):
        self.vault_url = vault_url
        self._client = None

    def _get_client(self):
        if self._client is None:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient

            self._client = SecretClient(
                vault_url=self.vault_url,
                credential=DefaultAzureCredential(),
            )
        return self._client

    async def get_secret(self, ref: SecretRef) -> Optional[str]:
        client = self._get_client()
        version = ref.version or ""
        secret = client.get_secret(ref.name, version=version)
        return secret.value
