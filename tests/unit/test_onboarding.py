"""Unit tests for onboarding API router."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from vorsyghta.api.main import app
from vorsyghta.api.routers.onboarding import create_onboarding_step, OnboardingStepIn


client = TestClient(app)


def test_create_onboarding_step_success():
    payload = {
        "title": "Role selection",
        "content": "User selected analyst role for onboarding",
        "category": "profile",
        "tags": ["role", "onboarding"],
    }
    resp = client.post("/api/onboarding/step", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert "entry_id" in data
    assert data["entry_id"].startswith("onboarding-profile-")
    assert data["message"] == "Saved."


def test_create_onboarding_step_missing_fields():
    resp = client.post("/api/onboarding/step", json={"title": "x"})
    assert resp.status_code == 422


def test_create_onboarding_step_empty_title():
    payload = {
        "title": "",
        "content": "content",
        "category": "profile",
        "tags": [],
    }
    resp = client.post("/api/onboarding/step", json=payload)
    assert resp.status_code == 422


def test_onboarding_step_in_validation():
    with pytest.raises(ValidationError):
        OnboardingStepIn(title="t", content="c", category="cat", tags=["a"] * 33)


@pytest.mark.asyncio
async def test_create_onboarding_step_direct():
    step = OnboardingStepIn(
        title="Test",
        content="Content",
        category="profile",
        tags=["a"],
    )
    result = await create_onboarding_step(step)
    assert result.entry_id.startswith("onboarding-profile-")
    assert result.message == "Saved."
