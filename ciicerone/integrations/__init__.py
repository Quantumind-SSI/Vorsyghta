"""External integrations for Ciicerone.

Provides clients and wrappers for third-party security platforms:
    - attack: Ciicerone Attack autonomous penetration testing system
    - siem: SIEM platform clients (Splunk, Elastic, Sentinel, QRadar)
"""

from .attack_client import AttackClient
from .attack import AttackIntegration
from .attack_mapper import AttackMapper
from .siem_client import SIEMClient, SIEMEvent, SIEMAlert, SIEMCorrelationRule

__all__ = [
    "AttackClient",
    "AttackIntegration",
    "AttackMapper",
    "SIEMClient",
    "SIEMEvent",
    "SIEMAlert",
    "SIEMCorrelationRule",
]
