"""Credential provider interface."""

from abc import ABC, abstractmethod
from typing import Optional

from ciicerone.client_data.config import SecretRef


class CredentialProvider(ABC):
    """Abstract credential provider."""

    @abstractmethod
    async def get_secret(self, ref: SecretRef) -> Optional[str]:
        """Resolve a secret reference to a string value."""
        pass

    async def get_required(self, ref: SecretRef) -> str:
        value = await self.get_secret(ref)
        if value is None:
            raise ValueError(f"Secret not found: {ref.name}")
        return value
