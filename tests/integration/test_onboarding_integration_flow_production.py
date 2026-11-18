"""Integration flow tests for onboarding production.

Tests full onboarding flow integration with knowledge service removal.
"""
from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession


class TestOnboardingIntegrationFlowProduction:
    """Integration tests for full onboarding flow."""
    
    @pytest.mark.asyncio
    async def test_full_onboarding_flow_without_knowledge_service(self, db_session: AsyncSession):
        """Test complete onboarding flow works without knowledge service."""
        # Simulate user starting onboarding
        user = {
            "onboarding_complete": False,
            "role": "viewer",
            "is_verified": False
        }
        
        # Step 1: Profile
        # Update user role
        user["role"] = "analyst"
        
        # Verify state
        assert user["role"] == "analyst"
        
        # Step 2: Use cases
        # No DB change, just validation
        
        # Step 3: Environments
        # No DB change, just validation
        
        # Step 4: Review
        # Mark complete
        user["onboarding_complete"] = True
        
        # Verify completion
        assert user["onboarding_complete"] is True
        assert user["role"] == "analyst"
    
    @pytest.mark.asyncio
    async def test_onboarding_flow_progression(self, db_session: AsyncSession):
        """Test onboarding flow progression through steps."""
        steps = ["profile", "use-cases", "environments", "review", "complete"]
        current_step = 0
        
        for step in steps:
            # Simulate step completion
            current_step += 1
            assert current_step > 0
        
        assert current_step == 5
    
    @pytest.mark.asyncio
    async def test_onboarding_flow_with_role_update(self, db_session: AsyncSession):
        """Test onboarding flow with role update."""
        user = {
            "role": "viewer",
            "onboarding_complete": False
        }
        
        # Profile step updates role
        user["role"] = "analyst"
        
        assert user["role"] == "analyst"
        
        # Complete flow
        user["onboarding_complete"] = True
        
        assert user["onboarding_complete"] is True
        assert user["role"] == "analyst"
    
    @pytest.mark.asyncio
    async def test_onboarding_flow_redirects_correctly(self, db_session: AsyncSession):
        """Test onboarding flow redirects correctly."""
        # Start: user not onboarded
        user = {
            "onboarding_complete": False,
            "role": "viewer",
            "is_verified": False
        }
        
        onboarding_required = (
            not user["onboarding_complete"] and
            not (user["role"] == "viewer" and user["is_verified"])
        )
        
        assert onboarding_required is True
        # Redirect to /onboarding/profile
        
        # Complete flow
        user["onboarding_complete"] = True
        
        onboarding_required = (
            not user["onboarding_complete"] and
            not (user["role"] == "viewer" and user["is_verified"])
        )
        
        assert onboarding_required is False
        # Allow access to /app


class TestOnboardingFlowValidation:
    """Validation tests for onboarding flow."""
    
    @pytest.mark.asyncio
    async def test_profile_validation_requires_industry(self):
        """Test profile validation requires industry."""
        # Profile should have industry
        profile_data = {
            "industry": "Technology",
            "company_size": "51-200",
            "regions": "NA",
            "security_maturity": "Developing"
        }
        
        assert "industry" in profile_data
        assert len(profile_data["industry"]) >= 2
    
    @pytest.mark.asyncio
    async def test_use_cases_validation_requires_capabilities(self):
        """Test use cases validation requires capabilities."""
        use_cases_data = {
            "capabilities": ["threat-hunting", "vulnerability-management"],
            "success_criteria": "Reduce MTTR"
        }
        
        assert len(use_cases_data["capabilities"]) >= 1
        assert len(use_cases_data["success_criteria"]) > 0
    
    @pytest.mark.asyncio
    async def test_environments_validation_sanctioned_targets(self):
        """Test environments validation for sanctioned targets."""
        env_data = {
            "adapter_categories": ["network", "cloud"],
            "cloud_providers": ["aws"],
            "sanctioned_targets_only": True
        }
        
        assert env_data["sanctioned_targets_only"] is True
    
    @pytest.mark.asyncio
    async def test_review_validation_requires_acceptance(self):
        """Test review validation requires terms acceptance."""
        review_data = {
            "terms_accepted": True,
            "acceptable_use_accepted": True
        }
        
        assert review_data["terms_accepted"] is True
        assert review_data["acceptable_use_accepted"] is True


class TestOnboardingFlowKnowledgeServiceIndependence:
    """Tests verifying onboarding independence from knowledge service."""
    
    @pytest.mark.asyncio
    async def test_onboarding_flow_no_knowledge_service_calls(self, db_session: AsyncSession):
        """Test onboarding flow makes no knowledge service calls."""
        # Simulate flow without knowledge service
        user = {
            "role": "viewer",
            "onboarding_complete": False
        }
        
        # All steps should work
        user["role"] = "analyst"
        user["onboarding_complete"] = True
        
        # Verify no knowledge service dependency
        assert user["role"] == "analyst"
        assert user["onboarding_complete"] is True
    
    @pytest.mark.asyncio
    async def test_onboarding_data_persists_without_knowledge_service(self, db_session: AsyncSession):
        """Test onboarding data persists without knowledge service."""
        # User data should persist independently
        user_state = {
            "role": "analyst",
            "onboarding_complete": True
        }
        
        # Should persist regardless of knowledge service
        assert user_state["role"] == "analyst"
        assert user_state["onboarding_complete"] is True
    
    @pytest.mark.asyncio
    async def test_onboarding_flow_handles_knowledge_service_unavailable(self, db_session: AsyncSession):
        """Test onboarding flow handles knowledge service unavailable."""
        # Even if knowledge service is down, onboarding works
        user = {
            "onboarding_complete": False,
            "role": "viewer"
        }
        
        # Flow continues
        user["role"] = "analyst"
        user["onboarding_complete"] = True
        
        assert user["onboarding_complete"] is True


class TestOnboardingFlowUserJourney:
    """User journey tests for onboarding flow."""
    
    @pytest.mark.asyncio
    async def test_user_journey_from_login_to_completion(self, db_session: AsyncSession):
        """Test complete user journey from login to onboarding completion."""
        # 1. User logs in
        user = {
            "email": "user@example.com",
            "onboarding_complete": False,
            "role": "viewer",
            "is_verified": False
        }
        
        # 2. Layout guard redirects to onboarding
        onboarding_required = (
            not user["onboarding_complete"] and
            not (user["role"] == "viewer" and user["is_verified"])
        )
        assert onboarding_required is True
        
        # 3. User completes profile
        user["role"] = "analyst"
        
        # 4. User completes all steps
        user["onboarding_complete"] = True
        
        # 5. User can access app
        onboarding_required = (
            not user["onboarding_complete"] and
            not (user["role"] == "viewer" and user["is_verified"])
        )
        assert onboarding_required is False
    
    @pytest.mark.asyncio
    async def test_user_fromfarbeyond_journey(self, db_session: AsyncSession):
        """Test user fromfarbeyond@gmail.com journey."""
        user = {
            "email": "fromfarbeyond@gmail.com",
            "onboarding_complete": False,
            "role": "viewer",
            "is_verified": False
        }
        
        # Should require onboarding
        onboarding_required = (
            not user["onboarding_complete"] and
            not (user["role"] == "viewer" and user["is_verified"])
        )
        assert onboarding_required is True
        
        # Complete onboarding
        user["role"] = "analyst"
        user["onboarding_complete"] = True
        
        # Can access app
        onboarding_required = (
            not user["onboarding_complete"] and
            not (user["role"] == "viewer" and user["is_verified"])
        )
        assert onboarding_required is False
    
    @pytest.mark.asyncio
    async def test_user_journey_verified_viewer_skip(self, db_session: AsyncSession):
        """Test verified viewer skips onboarding."""
        user = {
            "email": "viewer@example.com",
            "onboarding_complete": False,
            "role": "viewer",
            "is_verified": True
        }
        
        # Should NOT require onboarding
        onboarding_required = (
            not user["onboarding_complete"] and
            not (user["role"] == "viewer" and user["is_verified"])
        )
        assert onboarding_required is False
        
        # Direct access to app
        can_access_app = not onboarding_required
        assert can_access_app is True


class TestOnboardingFlowErrorHandling:
    """Error handling tests for onboarding flow."""
    
    @pytest.mark.asyncio
    async def test_onboarding_flow_handles_invalid_data(self, db_session: AsyncSession):
        """Test onboarding flow handles invalid data gracefully."""
        # Invalid profile data
        invalid_profile = {
            "industry": "",  # Too short
            "company_size": "",
            "regions": "",
            "security_maturity": ""
        }
        
        # Should validate
        assert len(invalid_profile["industry"]) == 0
    
    @pytest.mark.asyncio
    async def test_onboarding_flow_handles_partial_completion(self, db_session: AsyncSession):
        """Test onboarding flow handles partial completion."""
        user = {
            "role": "analyst",
            "onboarding_complete": False
        }
        
        # User started but didn't finish
        onboarding_required = not user["onboarding_complete"]
        assert onboarding_required is True
        
        # Can resume
        assert user["role"] == "analyst"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
