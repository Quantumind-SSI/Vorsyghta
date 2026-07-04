"""Company reconnaissance agent for client data enrichment."""

import logging
from typing import Any, Dict, Optional

from ciicerone.client_data.models import ClientProfile
from ciicerone.config.models import ThreatScenario
from ciicerone.intelligence.services import OSINTService

logger = logging.getLogger(__name__)


class CompanyReconAgent:
    """Performs OSINT reconnaissance on a target company."""

    def __init__(self, osint_service: Optional[OSINTService] = None):
        self.osint_service = osint_service or OSINTService()

    def _resolve_target(self, profile: ClientProfile, scenario: ThreatScenario) -> Optional[str]:
        target = None
        if scenario.target_profile.company_name:
            target = scenario.target_profile.company_name
        if not target and profile.employees:
            domain = self._email_domain(profile.employees[0].email)
            if domain:
                target = domain
        if not target and profile.name:
            target = self._guess_domain(profile.name)
        return target

    def _email_domain(self, email: str) -> Optional[str]:
        if "@" in email:
            return email.split("@")[-1]
        return None

    def _guess_domain(self, company_name: str) -> str:
        cleaned = company_name.lower().replace(" ", "").replace(",", "").replace(".", "")
        return f"{cleaned}.com"

    async def recon_company(
        self,
        profile: ClientProfile,
        scenario: ThreatScenario,
    ) -> Optional[Dict[str, Any]]:
        target = self._resolve_target(profile, scenario)
        if not target:
            logger.warning("No target company/domain found for recon")
            return None

        try:
            result = await self.osint_service.comprehensive_reconnaissance(
                target=target,
                recon_types=["company", "domain"],
            )
            company = result.company_intelligence
            if not company:
                return None
            return {
                "company_name": company.company_name,
                "domain": company.domain,
                "industry": company.industry,
                "company_size": company.company_size,
                "headquarters": company.headquarters,
                "business_description": company.business_description,
                "recent_news": company.recent_news[:5],
                "linkedin_company_page": company.linkedin_company_page,
                "twitter_accounts": company.twitter_accounts,
                "confidence_level": company.confidence_level.value,
                "sources": [s.value for s in company.sources],
            }
        except Exception as e:
            logger.warning(f"Company recon failed for {target}: {e}")
            return None
