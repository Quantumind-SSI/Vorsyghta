"""HashiCorp Vault credential provider.

Reads secrets from a HashiCorp Vault KV v2 secrets engine using the
Vault REST API over HTTP. No ``hvac`` dependency is required — only
``httpx`` which is already a project dependency.

Authentication is performed via a static Vault token supplied through
the ``X-Vault-Token`` header. The provider is async-friendly: each
``get_secret`` call issues a single HTTP GET to the KV v2 data endpoint.
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx

from vorsyghta.client_data.config import SecretRef, SecretProvider
from .base import CredentialProvider

logger = logging.getLogger(__name__)


class HashiCorpVaultProvider(CredentialProvider):
    """Resolve secrets from a HashiCorp Vault KV v2 store.

    Parameters
    ----------
    vault_url:
        Base URL of the Vault server, e.g. ``https://vault.example.com:8200``.
    token:
        Vault token used for authentication (sent as ``X-Vault-Token``).
    mount_path:
        Mount path of the KV v2 secrets engine. Defaults to ``secret``.
    """

    provider_name = "hashi_vault"

    def __init__(
        self,
        vault_url: str,
        token: str,
        mount_path: str = "secret",
    ) -> None:
        self.vault_url = vault_url.rstrip("/")
        self.token = token
        self.mount_path = mount_path.strip("/")
        # A shared client is fine; callers may replace it for testing.
        self._client = httpx.AsyncClient(timeout=30.0)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _build_url(self, path: str, version: Optional[str] = None) -> str:
        """Build the KV v2 data read URL for *path*."""
        url = f"{self.vault_url}/v1/{self.mount_path}/data/{path.lstrip('/')}"
        if version:
            url += f"?version={version}"
        return url

    def _headers(self) -> dict:
        return {
            "X-Vault-Token": self.token,
            "Accept": "application/json",
        }

    # ------------------------------------------------------------------
    # CredentialProvider interface
    # ------------------------------------------------------------------
    async def get_secret(self, ref: SecretRef) -> Optional[str]:
        """Read a secret from Vault's KV v2 store.

        The secret ``name`` is interpreted as the Vault path. If the
        stored secret is a JSON object with multiple keys, the value of
        a ``value`` key is returned; otherwise the first value is used.
        """
        path = ref.name
        version = ref.version
        url = self._build_url(path, version=version)
        logger.debug(
            "Vault provider requesting secret: path=%s version=%s",
            path,
            version or "latest",
        )
        try:
            response = await self._client.get(url, headers=self._headers())
        except httpx.HTTPError as exc:
            logger.warning(
                "Vault request failed for path=%s: %s", path, exc
            )
            return None

        if response.status_code == 404:
            logger.info("Vault secret not found: path=%s", path)
            return None
        if response.status_code == 403:
            logger.warning("Vault access denied for path=%s", path)
            return None
        if response.status_code >= 400:
            logger.warning(
                "Vault returned HTTP %s for path=%s", response.status_code, path
            )
            return None

        try:
            payload = response.json()
        except ValueError:
            logger.warning("Vault response was not valid JSON for path=%s", path)
            return None

        data = payload.get("data", {}).get("data", {})
        if not isinstance(data, dict):
            # Unexpected shape — return as-is if it's a string.
            return data if isinstance(data, str) else None

        if not data:
            logger.info("Vault secret %s contained no data fields", path)
            return None

        # Prefer an explicit "value" key, otherwise the first value.
        if "value" in data:
            return data["value"]
        return next(iter(data.values()))

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()
