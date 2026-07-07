"""Unified secret manager.

``SecretManager`` chains multiple :class:`CredentialProvider` instances
together and resolves secrets in priority order. It also provides a
``from_env`` factory that builds a provider chain from environment
variables:

    1. HashiCorp Vault   (if ``VAULT_URL`` and ``VAULT_TOKEN`` are set)
    2. Azure Key Vault   (if ``AZURE_KEY_VAULT_URL`` is set)
    3. AWS Secrets Mgr   (if ``AWS_REGION`` and ``AWS_ACCESS_KEY_ID`` are set)
    4. Environment vars  (always, as a final fallback)

Only metadata (names, found/not found, provider used) is ever logged —
secret values themselves are never written to logs.
"""

from __future__ import annotations

import logging
import os
from typing import Dict, List, Optional

from ciicerone.client_data.config import SecretRef
from ciicerone.client_data.credentials.base import CredentialProvider

logger = logging.getLogger(__name__)


class SecretManager:
    """Chain-of-responsibility secret resolver.

    Parameters
    ----------
    providers:
        Ordered list of credential providers. Providers earlier in the
        list take priority; the first provider that returns a non-``None``
        value wins.
    """

    def __init__(self, providers: List[CredentialProvider]) -> None:
        if not providers:
            raise ValueError("SecretManager requires at least one provider")
        self.providers: List[CredentialProvider] = list(providers)

    # ------------------------------------------------------------------
    # Core resolution
    # ------------------------------------------------------------------
    async def get_secret(
        self, name: str, version: Optional[str] = None
    ) -> Optional[str]:
        """Try each provider in order; return the first non-None value."""
        ref = SecretRef(name=name, version=version)
        for provider in self.providers:
            provider_name = getattr(provider, "provider_name", type(provider).__name__)
            try:
                value = await provider.get_secret(ref)
            except Exception as exc:
                # A misbehaving provider should not break the whole chain.
                logger.warning(
                    "Provider %s raised while resolving secret %s: %s",
                    provider_name,
                    name,
                    exc,
                )
                continue
            if value is not None:
                logger.info(
                    "Secret %s resolved by provider %s", name, provider_name
                )
                return value
        logger.info("Secret %s not found by any provider", name)
        return None

    async def get_required(
        self, name: str, version: Optional[str] = None
    ) -> str:
        """Like :meth:`get_secret` but raise if no provider returns a value."""
        value = await self.get_secret(name, version=version)
        if value is None:
            raise ValueError(f"Required secret not found: {name}")
        return value

    async def get_many(
        self, names: List[str]
    ) -> Dict[str, Optional[str]]:
        """Resolve a batch of secrets.

        Resolution is sequential to preserve provider-side ordering and
        to keep log lines readable. Each secret is resolved independently
        — a failure for one name does not affect the others.
        """
        results: Dict[str, Optional[str]] = {}
        for name in names:
            results[name] = await self.get_secret(name)
        return results

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    def list_providers(self) -> List[Dict[str, str]]:
        """Return metadata about each provider in the chain (no secrets)."""
        info: List[Dict[str, str]] = []
        for idx, provider in enumerate(self.providers):
            provider_name = getattr(
                provider, "provider_name", type(provider).__name__
            )
            entry: Dict[str, str] = {
                "priority": str(idx),
                "name": provider_name,
                "type": type(provider).__name__,
            }
            # Surface non-secret configuration where available.
            for attr in ("vault_url", "mount_path", "region", "vault_url"):
                val = getattr(provider, attr, None)
                if val is not None:
                    entry[attr] = str(val)
            info.append(entry)
        return info

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------
    @classmethod
    def from_env(cls) -> "SecretManager":
        """Build a provider chain from environment variables."""
        providers: List[CredentialProvider] = []

        vault_url = os.getenv("VAULT_URL")
        vault_token = os.getenv("VAULT_TOKEN")
        if vault_url and vault_token:
            from ciicerone.client_data.credentials.hashi_vault import (
                HashiCorpVaultProvider,
            )

            providers.append(
                HashiCorpVaultProvider(
                    vault_url=vault_url,
                    token=vault_token,
                    mount_path=os.getenv("VAULT_MOUNT_PATH", "secret"),
                )
            )
            logger.info("SecretManager: HashiCorp Vault provider enabled")

        azure_url = os.getenv("AZURE_KEY_VAULT_URL")
        if azure_url:
            from ciicerone.client_data.credentials.azure_keyvault import (
                AzureKeyVaultProvider,
            )

            providers.append(AzureKeyVaultProvider(vault_url=azure_url))
            logger.info("SecretManager: Azure Key Vault provider enabled")

        aws_region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
        aws_key_id = os.getenv("AWS_ACCESS_KEY_ID")
        if aws_region and aws_key_id:
            from ciicerone.client_data.credentials.aws_sm import (
                AWSSecretsManagerProvider,
            )

            providers.append(
                AWSSecretsManagerProvider(
                    region=aws_region,
                    access_key_id=aws_key_id,
                    secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", ""),
                )
            )
            logger.info("SecretManager: AWS Secrets Manager provider enabled")

        # Env provider is always the final fallback.
        from ciicerone.client_data.credentials.env import EnvCredentialProvider

        providers.append(EnvCredentialProvider())

        logger.info(
            "SecretManager configured with %d provider(s): %s",
            len(providers),
            [getattr(p, "provider_name", type(p).__name__) for p in providers],
        )
        return cls(providers)
