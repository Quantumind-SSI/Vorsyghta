"""Configuration models for client data integrations."""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SourceType(str, Enum):
    API = "api"
    GNS3 = "gns3"
    SALESFORCE = "salesforce"
    HUBSPOT = "hubspot"
    MICROSOFT365 = "microsoft365"
    GOOGLE_WORKSPACE = "google_workspace"
    S3 = "s3"
    AZURE_BLOB = "azure_blob"
    GCS = "gcs"
    ONEDRIVE = "onedrive"
    GOOGLE_DRIVE = "google_drive"
    SHAREPOINT = "sharepoint"


class SecretProvider(str, Enum):
    ENV = "env"
    AZURE_KEYVAULT = "azure_keyvault"
    AWS_SECRETS_MANAGER = "aws_secrets_manager"


class SecretRef(BaseModel):
    provider: SecretProvider = SecretProvider.ENV
    name: str = Field(..., description="Environment variable name or secret key")
    version: Optional[str] = None


class CredentialSet(BaseModel):
    api_key: Optional[SecretRef] = None
    client_id: Optional[SecretRef] = None
    client_secret: Optional[SecretRef] = None
    tenant_id: Optional[SecretRef] = None
    username: Optional[SecretRef] = None
    password: Optional[SecretRef] = None
    token: Optional[SecretRef] = None
    region: Optional[str] = None


class ClientDataSourceConfig(BaseModel):
    name: str
    type: SourceType
    enabled: bool = True
    tenant_id: str = "default"
    credentials: CredentialSet = Field(default_factory=CredentialSet)
    settings: Dict[str, Any] = Field(default_factory=dict)
    sync_interval_minutes: Optional[int] = None
    pii_scrub: bool = True


class ClientDataTenantConfig(BaseModel):
    tenant_id: str = "default"
    name: str = ""
    sources: List[ClientDataSourceConfig] = Field(default_factory=list)


class ClientDataConfig(BaseModel):
    enabled: bool = False
    storage_path: str = "~/.ciicerone/client_data"
    default_secret_provider: SecretProvider = SecretProvider.ENV
    tenants: List[ClientDataTenantConfig] = Field(default_factory=list)
