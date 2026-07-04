"""Enrich ThreatScenario and TargetProfile from client data."""

import logging
from typing import Optional

from ciicerone.client_data.models import ClientProfile, Employee
from ciicerone.client_data.recon import CompanyReconAgent
from ciicerone.config.models import TargetProfile, ThreatScenario

logger = logging.getLogger(__name__)


class ClientDataEnricher:
    """Apply client profile data to threat scenarios."""

    def __init__(
        self,
        profile: ClientProfile,
        recon_agent: Optional[CompanyReconAgent] = None,
    ):
        self.profile = profile
        self.recon_agent = recon_agent

    async def enrich_scenario(
        self,
        scenario: ThreatScenario,
        enable_recon: bool = False,
    ) -> ThreatScenario:
        enriched = scenario.model_copy(deep=True)
        target = self._pick_target(enriched.target_profile)
        if target:
            enriched.target_profile = self._apply_employee(enriched.target_profile, target)
        if self.profile.network_topology:
            enriched.custom_parameters["client_network_topology"] = (
                self.profile.network_topology.model_dump()
            )
        if self.profile.assets:
            enriched.custom_parameters["client_assets"] = [
                a.model_dump() for a in self.profile.assets[:10]
            ]
        enriched.custom_parameters["client_tenant_id"] = self.profile.tenant_id
        enriched.custom_parameters["client_name"] = self.profile.name
        if self.profile.employees:
            enriched.custom_parameters["client_employees"] = [
                {
                    "name": e.name,
                    "role": e.role,
                    "department": e.department,
                    "email": e.email,
                }
                for e in self.profile.employees[:5]
            ]

        if enable_recon and self.recon_agent:
            recon_data = await self.recon_agent.recon_company(self.profile, enriched)
            if recon_data:
                enriched.custom_parameters["company_recon"] = recon_data

        return enriched

    def _pick_target(self, existing: TargetProfile) -> Optional[Employee]:
        if existing.role:
            by_role = [
                e for e in self.profile.employees if existing.role.lower() in e.role.lower()
            ]
            if by_role:
                return by_role[0]
        if existing.department:
            by_dept = [
                e
                for e in self.profile.employees
                if existing.department.lower() in e.department.lower()
            ]
            if by_dept:
                return by_dept[0]
        if self.profile.employees:
            return self.profile.employees[0]
        return None

    def _apply_employee(self, target: TargetProfile, employee: Employee) -> TargetProfile:
        if employee.role:
            target.role = employee.role
        if employee.department:
            target.department = employee.department
        if employee.seniority:
            target.seniority = employee.seniority
        if employee.technical_level:
            target.technical_level = employee.technical_level
        if employee.interests:
            target.interests = employee.interests
        if employee.security_awareness_level:
            target.security_awareness_level = employee.security_awareness_level
        if employee.company_name:
            target.company_name = employee.company_name
        return target
