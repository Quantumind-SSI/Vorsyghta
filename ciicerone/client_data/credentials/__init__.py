"""Credential providers for client data integrations."""

from .base import CredentialProvider
from .env import EnvCredentialProvider
from .azure_keyvault import AzureKeyVaultProvider
from .hashi_vault import HashiCorpVaultProvider
from .aws_sm import AWSSecretsManagerProvider

__all__ = [
    "CredentialProvider",
    "EnvCredentialProvider",
    "AzureKeyVaultProvider",
    "HashiCorpVaultProvider",
    "AWSSecretsManagerProvider",
]
