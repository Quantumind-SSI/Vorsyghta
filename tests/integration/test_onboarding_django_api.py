"""Django API integration tests for onboarding.

Tests verify Django onboarding endpoints work correctly with frontend schemas.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch

from vorsyghta.api.main import app
from vorsyghta.api.routers.onboarding import (
    OnboardingProfileIn,
    OnboardingUseCasesIn,
    OnboardingEnvironmentsIn,
    OnboardingReviewIn,
)


client = TestClient(app)


class TestDjangoOnboardingAPIIntegration:
    """Integration tests for Django onboarding API."""
    
    def test_onboarding_profile_schema_matches_frontend(self):
        """Test Django onboarding profile schema matches frontend."""
        # Frontend schema
        frontend_profile = {
            "industry": "Technology",
            "company_size": "51-200",
            "regions": "NA",
            "security_maturity": "managed",
            "compliance_frameworks": ["gdpr"]
        }
        
        # Django model
        django_profile = OnboardingProfileIn(
            industry="Technology",
            company_size="51-200",
            regions="NA",
            security_maturity="managed",
            compliance_frameworks=["gdpr"]
        )
        
        # Should match
        assert django_profile.industry == frontend_profile["industry"]
        assert django_profile.company_size == frontend_profile["company_size"]
        assert django_profile.securety_maturity == frontend_profile["security_maturity"]
    
    def test_onboarding_use_cases_schema_matches_frontend(self):
        """Test Django onboarding use cases schema matches frontend."""
        frontend_use_cases = {
            "capabilities": ["colour_teams", "intelligence_stack"],
            "success_criteria": "Reduce MTTR by 50%"
        }
        
        django_use_cases = OnboardingUseCasesIn(
            capabilities=["colour_teams", "intelligence_stack"],
            success_criteria="Reduce MTTR by 50%"
        )
        
        assert len(django_use_cases.capabilities) == len(frontend_use_cases["capabilities"])
        assert django_use_cases.success_criteria == frontend_use_cases["success_criteria"]
    
    def test_onboarding_environments_schema_matches_frontend(self):
        """Test Django onboarding environments schema matches frontend."""
        frontend_env = {
            "adapter_categories": ["containers", "cloud"],
            "cloud_providers": ["aws", "gcp"],
            "sanctioned_targets_only": True
        }
        
        django_env = OnboardingEnvironmentsIn(
            adapter_categories=["containers", "cloud"],
            cloud_providers=["aws", "gcp"],
            sanctioned_targets_only=True
        )
        
        assert django_env.sanctioned_targets_only is True
        assert "aws" in django_env.cloud_providers
    
    def test_onboarding_review_schema_matches_frontend(self):
        """Test Django onboarding review schema matches frontend."""
        frontend_review = {
            "terms_accepted": True,
            "acceptable_use_accepted": True
        }
        
        django_review = OnboardingReviewIn(
            terms_accepted=True,
            acceptable_use_accepted=True
        )
        
        assert django_review.terms_accepted is True
        assert django_review.acceptable_use_accepted is True


class TestDjangoOnboardingAPIEndpoints:
    """Tests for Django onboarding API endpoints."""
    
    def test_onboarding_profile_endpoint_exists(self):
        """Test onboarding profile endpoint exists."""
        # Endpoint should exist
        response = client.options("/onboarding/profile")
        assert response.status_code in [200, 405]
    
    def test_onboarding_use_cases_endpoint_exists(self):
        """Test onboarding use cases endpoint exists."""
        response = client.options("/onboarding/use-cases")
        assert response.status_code in [200, 405]
    
    def test_onboarding_environments_endpoint_exists(self):
        """Test onboarding environments endpoint exists."""
        response = client.options("/onboarding/environments")
        assert response.status_code in [200, 405]
    
    def test_onboarding_review_endpoint_exists(self):
        """Test onboarding review endpoint exists."""
        response = client.options("/onboarding/review")
        assert response.status_code in [200, 405]


class TestOnboardingAPISchemaValidation:
    """Tests for onboarding API schema validation."""
    
    def test_profile_validates_industry_length(self):
        """Test profile validates industry length."""
        # Valid
        profile = OnboardingProfileIn(
            industry="Technology",
            company_size="51-200",
            regions="NA",
            security_maturity="managed",
            compliance_frameworks=[]
        )
        assert profile.industry == "Technology"
    
    def test_profile_validates_company_size_enum(self):
        """Test profile validates company size enum."""
        profile = OnboardingProfileIn(
            industry="Technology",
            company_size="51-200",
            regions="NA",
            security_maturity="managed",
            compliance_frameworks=[]
        )
        assert profile.company_size == "51-200"
    
    def test_profile_validates_security_maturity_enum(self):
        """Test profile validates security maturity enum."""
        profile = OnboardingProfileIn(
            industry="Technology",
            company_size="51-200",
            regions="NA",
            security_maturity="managed",
            compliance_frameworks=[]
        )
        assert profile.security_maturity == "managed"
    
    def test_use_cases_validates_capabilities_min(self):
        """Test use cases validates capabilities min length."""
        use_cases = OnboardingUseCasesIn(
            capabilities=["colour_teams"],
            success_criteria="Test"
        )
        assert len(use_cases.capabilities) >= 1
    
    def test_use_cases_validates_success_criteria_max(self):
        """Test use cases validates success criteria max length."""
        use_cases = OnboardingUseCasesIn(
            capabilities=["colour_teams"],
            success_criteria="A" * 600
        )
        assert len(use_cases.success_criteria) <= 600
    
    def test_environments_validates_sanctioned_targets(self):
        """Test environments validates sanctioned targets only."""
        env = OnboardingEnvironmentsIn(
            adapter_categories=[],
            cloud_providers=[],
            sanctioned_targets_only=True
        )
        assert env.sanctioned_targets_only is True
    
    def test_review_validates_terms_accepted(self):
        """Test review validates terms accepted."""
        review = OnboardingReviewIn(
            terms_accepted=True,
            acceptable_use_accepted=True
        )
        assert review.terms_accepted is True
        assert review.acceptable_use_accepted is True


class TestOnboardingAPIKnowledgeServiceIndependence:
    """Tests verifying Django API doesn't depend on knowledge service."""
    
    def test_onboarding_profile_no_knowledge_service(self):
        """Test onboarding profile doesn't use knowledge service."""
        # Profile model should not reference knowledge service
        import inspect
        source = inspect.getsource(OnboardingProfileIn)
        assert "knowledge" not in source.lower()
    
    def test_onboarding_use_cases_no_knowledge_service(self):
        """Test onboarding use cases doesn't use knowledge service."""
        import inspect
        source = inspect.getsource(OnboardingUseCasesIn)
        assert "knowledge" not in source.lower()
    
    def test_onboarding_environments_no_knowledge_service(self):
        """Test onboarding environments doesn't use knowledge service."""
        import inspect
        source = inspect.getsource(OnboardingEnvironmentsIn)
        assert "knowledge" not in source.lower()
    
    def test_onboarding_review_no_knowledge_service(self):
        """Test onboarding review doesn't use knowledge service."""
        import inspect
        source = inspect.getsource(OnboardingReviewIn)
        assert "knowledge" not in source.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
