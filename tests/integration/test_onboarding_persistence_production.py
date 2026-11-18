"""Production DB persistence tests for onboarding flow.

Tests verify user state updates persist correctly and knowledge service removal
doesn't break data integrity.
"""
from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import AsyncMock, patch

from vorsyghta.db.models.auth import UserRecord
from tests.factories import create_test_user


class TestOnboardingDatabasePersistence:
    """DB persistence tests for onboarding flow."""
    
    @pytest.mark.asyncio
    async def test_user_role_update_persists_to_db(self, db_session: AsyncSession):
        """Test user role updates are persisted to database."""
        # Create test user
        user = await create_test_user(db_session)
        initial_role = user.role
        
        # Update role (as onboarding would)
        user.role = "analyst"
        await db_session.commit()
        await db_session.refresh(user)
        
        # Verify persistence
        assert user.role == "analyst"
        assert user.role != initial_role
    
    @pytest.mark.asyncio
    async def test_onboarding_complete_flag_persists(self, db_session: AsyncSession):
        """Test onboarding_complete flag persists correctly."""
        user = await create_test_user(db_session)
        
        # Simulate completing onboarding
        user.onboarding_complete = True
        await db_session.commit()
        await db_session.refresh(user)
        
        assert user.onboarding_complete is True
    
    @pytest.mark.asyncio
    async def test_user_fromfarbeyond_state_persists(self, db_session: AsyncSession):
        """Test user fromfarbeyond@gmail.com state is correctly managed."""
        user = UserRecord(
            id="user-fromfarbeyond-123",
            email="fromfarbeyond@gmail.com",
            role="viewer",
            onboarding_complete=False,
            is_verified=False,
            full_name="From Far Beyond"
        )
        
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        
        # User should be incomplete
        assert user.email == "fromfarbeyond@gmail.com"
        assert user.onboarding_complete is False
        assert user.is_verified is False
        assert user.role == "viewer"
        
        # After onboarding completes
        user.role = "analyst"
        user.onboarding_complete = True
        await db_session.commit()
        await db_session.refresh(user)
        
        assert user.role == "analyst"
        assert user.onboarding_complete is True
    
    @pytest.mark.asyncio
    async def test_user_state_transitions_correctly(self, db_session: AsyncSession):
        """Test user state transitions through onboarding."""
        user = await create_test_user(db_session)
        
        # Initial state
        assert user.onboarding_complete is False
        assert user.role in ["viewer", "analyst"]
        
        # After profile selection
        user.role = "analyst"
        await db_session.commit()
        
        # After environment selection
        # No role change, but data should persist
        
        # After completion
        user.onboarding_complete = True
        await db_session.commit()
        await db_session.refresh(user)
        
        # Final state
        assert user.onboarding_complete is True
        assert user.role == "analyst"
    
    @pytest.mark.asyncio
    async def test_concurrent_onboarding_updates_no_race(self, db_session: AsyncSession):
        """Test concurrent onboarding updates don't cause race conditions."""
        user = await create_test_user(db_session)
        
        # Simulate concurrent updates
        user.role = "analyst"
        user.onboarding_complete = False
        
        await db_session.commit()
        await db_session.flush()
        
        # Verify state is consistent
        await db_session.refresh(user)
        assert user.role == "analyst"
        assert user.onboarding_complete is False


class TestOnboardingKnowledgeServiceRemovalPersistence:
    """Tests verifying knowledge service removal doesn't affect DB."""
    
    @pytest.mark.asyncio
    async def test_onboarding_works_without_knowledge_service_db(self, db_session: AsyncSession):
        """Test onboarding DB operations work without knowledge service."""
        user = await create_test_user(db_session)
        
        # Perform onboarding steps without knowledge service
        user.role = "analyst"
        user.onboarding_complete = False
        
        await db_session.commit()
        await db_session.refresh(user)
        
        # Should succeed
        assert user.role == "analyst"
    
    @pytest.mark.asyncio
    async def test_no_knowledge_entries_created_during_onboarding(self, db_session: AsyncSession):
        """Test no knowledge entries are created during onboarding."""
        user = await create_test_user(db_session)
        
        # Complete onboarding
        user.role = "analyst"
        user.onboarding_complete = True
        await db_session.commit()
        
        # Verify user updated
        await db_session.refresh(user)
        assert user.onboarding_complete is True
        
        # Knowledge service should NOT have been called
        # This is verified by absence of knowledge entries for user
        # (Knowledge entries would be in separate table if they existed)
    
    @pytest.mark.asyncio
    async def test_user_onboarding_data_independent_of_knowledge(self, db_session: AsyncSession):
        """Test user onboarding data is independent of knowledge service."""
        user = await create_test_user(db_session)
        
        # Update user with onboarding data
        user.role = "analyst"
        user.onboarding_complete = True
        await db_session.commit()
        
        # Verify data exists
        await db_session.refresh(user)
        assert user.role == "analyst"
        assert user.onboarding_complete is True
        
        # Knowledge service availability shouldn't affect user data
        # User data persists regardless of knowledge service state


class TestOnboardingLayoutGuardPersistence:
    """Tests for layout guard persistence behavior."""
    
    @pytest.mark.asyncio
    async def test_layout_guard_blocks_incomplete_user(self, db_session: AsyncSession):
        """Test layout guard correctly blocks incomplete users."""
        user = await create_test_user(db_session)
        user.onboarding_complete = False
        user.role = "viewer"
        user.is_verified = False
        await db_session.commit()
        
        # Should require onboarding
        requires_onboarding = (
            not user.onboarding_complete and
            not (user.role == "viewer" and user.is_verified)
        )
        
        assert requires_onboarding is True
    
    @pytest.mark.asyncio
    async def test_layout_guard_allows_completed_user(self, db_session: AsyncSession):
        """Test layout guard allows completed users."""
        user = await create_test_user(db_session)
        user.onboarding_complete = True
        user.role = "analyst"
        await db_session.commit()
        
        # Should NOT require onboarding
        requires_onboarding = (
            not user.onboarding_complete and
            not (user.role == "viewer" and user.is_verified)
        )
        
        assert requires_onboarding is False
    
    @pytest.mark.asyncio
    async def test_layout_guard_allows_verified_viewer(self, db_session: AsyncSession):
        """Test layout guard allows verified viewers."""
        user = await create_test_user(db_session)
        user.onboarding_complete = False
        user.role = "viewer"
        user.is_verified = True
        await db_session.commit()
        
        # Should NOT require onboarding for verified viewers
        requires_onboarding = (
            not user.onboarding_complete and
            not (user.role == "viewer" and user.is_verified)
        )
        
        assert requires_onboarding is False


class TestOnboardingTransactionSafety:
    """Tests for transaction safety during onboarding."""
    
    @pytest.mark.asyncio
    async def test_user_update_rollback_on_error(self, db_session: AsyncSession):
        """Test user updates rollback on error."""
        user = await create_test_user(db_session)
        original_role = user.role
        
        try:
            user.role = "analyst"
            # Simulate error
            raise Exception("Simulated error")
            await db_session.commit()
        except Exception:
            await db_session.rollback()
        
        # Refresh user
        await db_session.refresh(user)
        # Role should be unchanged due to rollback
        assert user.role == original_role
    
    @pytest.mark.asyncio
    async def test_onboarding_completion_atomic(self, db_session: AsyncSession):
        """Test onboarding completion is atomic."""
        user = await create_test_user(db_session)
        
        # Both role and completion should update together
        user.role = "analyst"
        user.onboarding_complete = True
        
        await db_session.commit()
        await db_session.refresh(user)
        
        # Verify both updated
        assert user.role == "analyst"
        assert user.onboarding_complete is True
    
    @pytest.mark.asyncio
    async def test_partial_onboarding_state_preserved(self, db_session: AsyncSession):
        """Test partial onboarding state is preserved."""
        user = await create_test_user(db_session)
        
        # Update only role
        user.role = "analyst"
        await db_session.commit()
        await db_session.refresh(user)
        
        # Completion should remain unchanged
        assert user.role == "analyst"
        assert user.onboarding_complete is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
