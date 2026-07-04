"""CRM source adapters."""

from .base import BaseCrmSource
from .salesforce import SalesforceSource
from .hubspot import HubSpotSource
from .microsoft365 import Microsoft365CrmSource
from .google_workspace import GoogleWorkspaceCrmSource

__all__ = [
    "BaseCrmSource",
    "SalesforceSource",
    "HubSpotSource",
    "Microsoft365CrmSource",
    "GoogleWorkspaceCrmSource",
]
