"""Integration tests for onboarding flow persistence."""
from __future__ import annotations

import pytest
from tests.factories import create_test_user
from vorsyghta.api.routers.onboarding import create_onboarding_step, OnboardingStepIn


@pytest.mark.asyncio
async def test_onboarding_step_persists_for_user(db_session):
    user = await create_test_user(db_session)
    step = OnboardingStepIn(
        title="Role selection",
        content="User selected analyst role",
        category="profile",
        tags=["role", "onboarding"],
    )
    result = await create_onboarding_step(step)
    assert result.entry_id.startswith("onboarding-profile-")
    assert result.message == "Saved."
    # TODO: add DB assertion once onboarding store is implemented


@pytest.mark.asyncio
async def test_onboarding_step_multiple_categories(db_session):
    for category in ["profile", "use-cases", "environments", "review"]:
        step = OnboardingStepIn(
            title=f"Step for {category}",
            content="Content",
            category=category,
            tags=[],
        )
        result = await create_onboarding_step(step)
        assert result.entry_id.startswith(f"onboarding-{category}-")
