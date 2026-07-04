"""Environment variable credential provider."""

import os
from typing import Optional

from .base import CredentialProvider
from ciicerone.client_data.config import SecretRef


class EnvCredentialProvider(CredentialProvider):
    """Resolve secrets from environment variables."""

    async def get_secret(self, ref: SecretRef) -> Optional[str]:
        return os.environ.get(ref.name)
