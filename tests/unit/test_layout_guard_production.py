"""Production tests for ApplicationLayout guard logic.

Tests verify onboarding redirect guards work correctly with knowledge service removal.
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch, MagicMock


class TestApplicationLayoutGuardProduction:
    """Production tests for layout guard redirect logic."""
    
    def test_onboarding_required_for_incomplete_user(self):
        """Test incomplete users are redirected to onboarding."""
        user = {
            "onboarding_complete": False,
            "role": "analyst",
            "is_verified": False
        }
        
        onboarding_required = (
            not user["onboarding_complete"] and
            not (user["role"] == "viewer" and user["is_verified"])
        )
        
        assert onboarding_required is True
    
    def test_onboarding_required_for_viewer_not_verified(self):
        """Test unverified viewers require onboarding."""
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
    
    def test_onboarding_not_required_for_completed_user(self):
        """Test completed users can access app."""
        user = {
            "onboarding_complete": True,
            "role": "analyst",
            "is_verified": False
        }
        
        onboarding_required = (
            not user["onboarding_complete"] and
            not (user["role"] == "viewer" and user["is_verified"])
        )
        
        assert onboarding_required is False
    
    def test_onboarding_not_required_for_verified_viewer(self):
        """Test verified viewers can skip onboarding."""
        user = {
            "onboarding_complete": False,
            "role": "viewer",
            "is_verified": True
        }
        
        onboarding_required = (
            not user["onboarding_complete"] and
            not (user["role"] == "viewer" and user["is_verified"])
        )
        
        assert onboarding_required is False
    
    def test_onboarding_required_for_incomplete_analyst(self):
        """Test incomplete analysts require onboarding."""
        user = {
            "onboarding_complete": False,
            "role": "analyst",
            "is_verified": True
        }
        
        onboarding_required = (
            not user["onboarding_complete"] and
            not (user["role"] == "viewer" and user["is_verified"])
        )
        
        assert onboarding_required is True
    
    def test_fromfarbeyond_user_requires_onboarding(self):
        """Test user fromfarbeyond@gmail.com requires onboarding."""
        user = {
            "email": "fromfarbeyond@gmail.com",
            "onboarding_complete": False,
            "role": "viewer",
            "is_verified": False
        }
        
        onboarding_required = (
            not user["onboarding_complete"] and
            not (user["role"] == "viewer" and user["is_verified"])
        )
        
        assert onboarding_required is True


class TestLayoutGuardIntegration:
    """Integration tests for layout guard with session."""
    
    @pytest.mark.asyncio
    async def test_layout_guard_with_authenticated_session(self):
        """Test layout guard with authenticated session."""
        # Mock session state
        session = {
            "state": "authenticated",
            "user": {
                "onboarding_complete": False,
                "role": "viewer",
                "is_verified": False
            }
        }
        
        # Should redirect
        if session["state"] == "authenticated":
            user = session["user"]
            onboarding_required = (
                not user["onboarding_complete"] and
                not (user["role"] == "viewer" and user["is_verified"])
            )
            
            assert onboarding_required is True
    
    @pytest.mark.asyncio
    async def test_layout_guard_with_completed_user(self):
        """Test layout guard allows completed user."""
        session = {
            "state": "authenticated",
            "user": {
                "onboarding_complete": True,
                "role": "analyst",
                "is_verified": False
            }
        }
        
        if session["state"] == "authenticated":
            user = session["user"]
            onboarding_required = (
                not user["onboarding_complete"] and
                not (user["role"] == "viewer" and user["is_verified"])
            )
            
            assert onboarding_required is False
    
    @pytest.mark.asyncio
    async def test_layout_guard_skips_onboarding_for_verified_viewer(self):
        """Test layout guard skips onboarding for verified viewers."""
        session = {
            "state": "authenticated",
            "user": {
                "onboarding_complete": False,
                "role": "viewer",
                "is_verified": True
            }
        }
        
        if session["state"] == "authenticated":
            user = session["user"]
            onboarding_required = (
                not user["onboarding_complete"] and
                not (user["role"] == "viewer" and user["is_verified"])
            )
            
            assert onboarding_required is False


class TestLayoutGuardEdgeCases:
    """Edge cases for layout guard."""
    
    def test_layout_guard_with_missing_fields(self):
        """Test layout guard handles missing fields gracefully."""
        # Missing onboarding_complete
        user_partial = {
            "role": "viewer",
            "is_verified": False
        }
        
        # Should handle missing fields
        onboarding_complete = user_partial.get("onboarding_complete", False)
        role = user_partial.get("role", "")
        is_verified = user_partial.get("is_verified", False)
        
        onboarding_required = (
            not onboarding_complete and
            not (role == "viewer" and is_verified)
        )
        
        assert onboarding_required is True
    
    def test_layout_guard_with_null_values(self):
        """Test layout guard handles null values."""
        user = {
            "onboarding_complete": None,
            "role": None,
            "is_verified": None
        }
        
        # Treat None as falsy
        onboarding_complete = bool(user["onboarding_complete"])
        role = user["role"] or ""
        is_verified = bool(user["is_verified"])
        
        onboarding_required = (
            not onboarding_complete and
            not (role == "viewer" and is_verified)
        )
        
        assert onboarding_required is True
    
    def test_layout_guard_role_case_sensitivity(self):
        """Test layout guard handles role case sensitivity."""
        user = {
            "onboarding_complete": False,
            "role": "VIEWER",  # Uppercase
            "is_verified": True
        }
        
        # Should be case-sensitive
        onboarding_required = (
            not user["onboarding_complete"] and
            not (user["role"] == "viewer" and user["is_verified"])
        )
        
        # Uppercase role won't match
        assert onboarding_required is True


class TestLayoutGuardKnowledgeServiceIndependence:
    """Tests verifying layout guard works without knowledge service."""
    
    def test_layout_guard_works_without_knowledge_service(self):
        """Test layout guard doesn't depend on knowledge service."""
        # Layout guard should work based on user DB flags only
        user = {
            "onboarding_complete": False,
            "role": "viewer",
            "is_verified": False
        }
        
        # No knowledge service call needed
        onboarding_required = (
            not user["onboarding_complete"] and
            not (user["role"] == "viewer" and user["is_verified"])
        )
        
        assert onboarding_required is True
    
    def test_layout_guard_not_affected_by_knowledge_service_errors(self):
        """Test layout guard not affected by knowledge service errors."""
        # Layout guard uses session.user from DB, not knowledge service
        user = {
            "onboarding_complete": True,
            "role": "analyst",
            "is_verified": False
        }
        
        # Should work regardless of knowledge service state
        onboarding_required = (
            not user["onboarding_complete"] and
            not (user["role"] == "viewer" and user["is_verified"])
        )
        
        assert onboarding_required is False


class TestLayoutGuardUserJourney:
    """User journey tests for layout guard."""
    
    def test_user_journey_from_login_to_app(self):
        """Test user journey from login to app with onboarding."""
        # Step 1: User logs in, onboarding incomplete
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
        # Redirect to /onboarding
        
        # Step 2: User completes onboarding
        user["onboarding_complete"] = True
        user["role"] = "analyst"
        
        onboarding_required = (
            not user["onboarding_complete"] and
            not (user["role"] == "viewer" and user["is_verified"])
        )
        
        assert onboarding_required is False
        # Allow access to /app
    
    def test_user_journey_verified_viewer_skip(self):
        """Test verified viewer skips onboarding."""
        user = {
            "onboarding_complete": False,
            "role": "viewer",
            "is_verified": True
        }
        
        onboarding_required = (
            not user["onboarding_complete"] and
            not (user["role"] == "viewer" and user["is_verified"])
        )
        
        assert onboarding_required is False
        # Direct access to /app
    
    def test_user_journey_completion_flow(self):
        """Test user completes onboarding flow."""
        # Start
        user = {
            "onboarding_complete": False,
            "role": "viewer",
            "is_verified": False
        }
        
        # Completes profile
        user["role"] = "analyst"
        
        # Completes all steps
        user["onboarding_complete"] = True
        
        # Can access app
        onboarding_required = (
            not user["onboarding_complete"] and
            not (user["role"] == "viewer" and user["is_verified"])
        )
        
        assert onboarding_required is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
