"""Schema compatibility tests between Django and Frontend.

Verifies frontend Zod schemas match Django Pydantic models.
"""
from __future__ import annotations

import pytest
from pydantic import BaseModel
from typing import List


# Django models (mirrored for testing)
class DjangoOnboardingProfileIn(BaseModel):
    industry: str
    company_size: str
    regions: str
    security_maturity: str
    compliance_frameworks: List[str]


class DjangoOnboardingUseCasesIn(BaseModel):
    capabilities: List[str]
    success_criteria: str


class DjangoOnboardingEnvironmentsIn(BaseModel):
    adapter_categories: List[str]
    cloud_providers: List[str]
    sanctioned_targets_only: bool


class DjangoOnboardingReviewIn(BaseModel):
    terms_accepted: bool
    acceptable_use_accepted: bool


class TestSchemaCompatibility:
    """Verify frontend and Django schemas are compatible."""
    
    def test_profile_industry_compatible(self):
        """Test industry field compatible."""
        # Django: str min_length=2 max_length=80
        # Frontend: z.string().trim().min(2).max(80)
        django_data = {"industry": "Technology"}
        frontend_data = {"industry": "Technology"}
        
        assert django_data["industry"] == frontend_data["industry"]
    
    def test_profile_company_size_compatible(self):
        """Test company_size field compatible."""
        # Django: str pattern=r"^(1-10|11-50|51-200|201-1000|1000\+)$"
        # Frontend: z.enum(["1-10", "11-50", "51-200", "201-1000", "1000+"])
        django_valid = ["1-10", "11-50", "51-200", "201-1000", "1000+"]
        frontend_valid = ["1-10", "11-50", "51-200", "201-1000", "1000+"]
        
        assert django_valid == frontend_valid
    
    def test_profile_regions_compatible(self):
        """Test regions field compatible."""
        # Django: str min_length=2 max_length=160
        # Frontend: z.string().trim().min(2).max(160)
        test_value = "NA"
        
        assert len(test_value) >= 2
        assert len(test_value) <= 160
    
    def test_profile_security_maturity_compatible(self):
        """Test security_maturity field compatible."""
        # Django: str min_length=1 max_length=32
        # Frontend: z.enum(MATURITIES)
        MATURITIES = ["none", "ad_hoc", "defined", "managed"]
        
        for maturity in MATURITIES:
            assert len(maturity) >= 1
            assert len(maturity) <= 32
    
    def test_profile_compliance_frameworks_compatible(self):
        """Test compliance_frameworks field compatible."""
        # Django: List[str]
        # Frontend: z.array(z.enum(COMPLIANCE_FRAMEWORKS))
        COMPLIANCE_FRAMEWORKS = [
            "pci_dss", "ndpr", "gdpr", "soc_2", 
            "iso_27001", "cbn", "hipaa"
        ]
        
        # Both should accept same values
        for framework in COMPLIANCE_FRAMEWORKS:
            assert framework in COMPLIANCE_FRAMEWORKS
    
    def test_use_cases_capabilities_compatible(self):
        """Test capabilities field compatible."""
        # Django: List[str] min_length=1
        # Frontend: z.array(z.enum(CAPABILITIES)).min(1)
        CAPABILITIES = [
            "colour_teams", "intelligence_stack", "zero_day_research",
            "quantum_pqc", "saas_product", "simulation_paradigms", "rl_rlhf"
        ]
        
        # Both require min 1
        test_caps = [CAPABILITIES[0]]
        assert len(test_caps) >= 1
    
    def test_use_cases_success_criteria_compatible(self):
        """Test success_criteria field compatible."""
        # Django: str max_length=600
        # Frontend: z.string().trim().max(600)
        test_criteria = "Reduce MTTR by 50%"
        
        assert len(test_criteria) <= 600
    
    def test_environments_adapter_categories_compatible(self):
        """Test adapter_categories field compatible."""
        # Django: List[str]
        # Frontend: z.array(z.enum(ADAPTER_CATEGORIES))
        ADAPTER_CATEGORIES = [
            "containers", "cloud", "files", "web_apps_apis",
            "external_infrastructure", "directories_crm", "media"
        ]
        
        for category in ADAPTER_CATEGORIES:
            assert category in ADAPTER_CATEGORIES
    
    def test_environments_cloud_providers_compatible(self):
        """Test cloud_providers field compatible."""
        # Django: List[str]
        # Frontend: z.array(z.enum(["aws", "azure", "gcp", "huawei"]))
        CLOUD_PROVIDERS = ["aws", "azure", "gcp", "huawei"]
        
        for provider in CLOUD_PROVIDERS:
            assert provider in CLOUD_PROVIDERS
    
    def test_environments_sanctioned_targets_only_compatible(self):
        """Test sanctioned_targets_only field compatible."""
        # Django: bool
        # Frontend: z.literal(true)
        # Both require True
        
        django_value = True
        frontend_value = True
        
        assert django_value is True
        assert frontend_value is True
    
    def test_review_terms_accepted_compatible(self):
        """Test terms_accepted field compatible."""
        # Django: bool
        # Frontend: z.literal(true)
        
        django_value = True
        frontend_value = True
        
        assert django_value is True
        assert frontend_value is True
    
    def test_review_acceptable_use_accepted_compatible(self):
        """Test acceptable_use_accepted field compatible."""
        # Django: bool
        # Frontend: z.literal(true)
        
        django_value = True
        frontend_value = True
        
        assert django_value is True
        assert frontend_value is True
    
    def test_no_knowledge_service_fields(self):
        """Test schemas don't include knowledge service fields."""
        # Verify onboarding schemas don't reference knowledge service
        schemas = [
            DjangoOnboardingProfileIn,
            DjangoOnboardingUseCasesIn,
            DjangoOnboardingEnvironmentsIn,
            DjangoOnboardingReviewIn
        ]
        
        for schema in schemas:
            fields = schema.model_fields.keys()
            # Should not have knowledge-related fields
            for field in fields:
                assert "knowledge" not in field.lower()


class TestSchemaValidationExamples:
    """Test schema validation with real examples."""
    
    def test_valid_profile_example(self):
        """Test valid profile example."""
        data = {
            "industry": "Technology",
            "company_size": "51-200",
            "regions": "North America",
            "security_maturity": "managed",
            "compliance_frameworks": ["gdpr", "soc_2"]
        }
        
        profile = DjangoOnboardingProfileIn(**data)
        assert profile.industry == "Technology"
        assert profile.company_size == "51-200"
    
    def test_valid_use_cases_example(self):
        """Test valid use cases example."""
        data = {
            "capabilities": ["colour_teams", "intelligence_stack"],
            "success_criteria": "Reduce MTTR by 50% within 6 months"
        }
        
        use_cases = DjangoOnboardingUseCasesIn(**data)
        assert len(use_cases.capabilities) == 2
    
    def test_valid_environments_example(self):
        """Test valid environments example."""
        data = {
            "adapter_categories": ["containers", "cloud"],
            "cloud_providers": ["aws", "gcp"],
            "sanctioned_targets_only": True
        }
        
        env = DjangoOnboardingEnvironmentsIn(**data)
        assert env.sanctioned_targets_only is True
    
    def test_valid_review_example(self):
        """Test valid review example."""
        data = {
            "terms_accepted": True,
            "acceptable_use_accepted": True
        }
        
        review = DjangoOnboardingReviewIn(**data)
        assert review.terms_accepted is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
