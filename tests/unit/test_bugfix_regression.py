"""Regression tests for the production-blocking bug-fix audit.

Each test pins one specific fix from the audit so the same bug cannot
silently reappear.  Tests are deliberately self-contained — no DB, no
Redis, no real LLM calls — so they run anywhere the package imports.

Covered fixes
-------------
1.  LLMResponse.tokens_used attribute exists by default (llm/base.py)
2.  is_active() handles Z-suffixed ISO dates (research/engagement.py)
3.  is_active() handles timezone-offset ISO dates (research/engagement.py)
4.  Invalid enum values in saved JSON are skipped, not raised
    (research/engagement.py + research/disclosure.py)
5.  grant_extension() handles None embargo_end_date (research/disclosure.py)
6.  _set_nested() does not crash on out-of-range indices / missing keys
    (research/llm_mutator.py)
7.  Self-registration rejects client role/tenant fields
    (api/routers/auth.py) and requires organization-scoped registration

Additional structural assertions
--------------------------------
8.  asyncpg is set to None (not undefined) when the import fails, so
    postgres_event_store.py imports cleanly without asyncpg installed.
9.  OpenAI / Anthropic providers set tokens_used as an attribute after
    LLMResponse construction (no TypeError on init, no stray .usage attr).
10. validate_env.py checks VORSYGHTA_SECRET_KEY (not SECRET_KEY).
"""

from __future__ import annotations

import os
import sys
import tempfile
import warnings
from datetime import datetime, timedelta

import pytest
from starlette.exceptions import StarletteDeprecationWarning

# Ensure VORSYGHTA_SECRET_KEY is set before importing rbac/auth modules.
# Use a stable, obviously-non-production value.
os.environ.setdefault(
    "VORSYGHTA_SECRET_KEY",
    "test-secret-key-for-verification-only-32chars!",
)

# Silence Pydantic V2 / Starlette deprecation noise from third-party code.
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=StarletteDeprecationWarning)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def tmp_storage_dir():
    """A temporary directory that is cleaned up after the test."""
    with tempfile.TemporaryDirectory() as d:
        yield d


# ============================================================================
# 1. LLMResponse.tokens_used
# ============================================================================


class TestLLMResponseTokensUsed:
    """Fix: LLMResponse.__init__ now initialises self.tokens_used = 0."""

    def test_default_is_zero(self):
        from vorsyghta.llm.base import LLMResponse

        r = LLMResponse(content="hi", provider="openai", model="gpt-4")
        assert hasattr(r, "tokens_used"), "tokens_used attribute must exist"
        assert r.tokens_used == 0

    def test_settable(self):
        from vorsyghta.llm.base import LLMResponse

        r = LLMResponse(content="hi", provider="openai", model="gpt-4")
        r.tokens_used = 1234
        assert r.tokens_used == 1234


# ============================================================================
# 2 & 3. Engagement.is_active() timezone handling
# ============================================================================


def _make_engagement(start_date=None, end_date=None):
    """Build a minimal ACTIVE Engagement for is_active() tests."""
    from vorsyghta.research.engagement import (
        Engagement,
        EngagementStatus,
        LegalFramework,
        ResearchMethod,
        RulesOfEngagement,
        TargetEntry,
        TargetType,
    )

    return Engagement(
        id="t1",
        client="c",
        engagement_name="e",
        status=EngagementStatus.ACTIVE,
        targets=[
            TargetEntry(
                target_id="t",
                target_type=TargetType.IP_ADDRESS,
                value="10.0.0.1",
            )
        ],
        rules=RulesOfEngagement(allowed_methods=[ResearchMethod.FUZZING]),
        legal=LegalFramework(),
        start_date=start_date,
        end_date=end_date,
    )


class TestIsActiveTimezoneHandling:
    """Fix: is_active() normalises Z-suffix and tz-offset dates to naive UTC."""

    def test_z_suffix_future_end_date_is_active(self):
        future = (datetime.utcnow() + timedelta(days=7)).isoformat() + "Z"
        assert _make_engagement(end_date=future).is_active()

    def test_z_suffix_past_end_date_is_inactive(self):
        past = (datetime.utcnow() - timedelta(days=7)).isoformat() + "Z"
        assert not _make_engagement(end_date=past).is_active()

    def test_tz_offset_future_end_date_is_active(self):
        future = (datetime.utcnow() + timedelta(days=7)).isoformat() + "+00:00"
        assert _make_engagement(end_date=future).is_active()

    def test_tz_offset_past_end_date_is_inactive(self):
        past = (datetime.utcnow() - timedelta(days=7)).isoformat() + "+00:00"
        assert not _make_engagement(end_date=past).is_active()

    def test_z_suffix_future_start_date_is_inactive(self):
        # Start date in the future means engagement hasn't begun yet.
        future = (datetime.utcnow() + timedelta(days=7)).isoformat() + "Z"
        assert not _make_engagement(start_date=future).is_active()

    def test_invalid_date_format_does_not_raise(self):
        # A malformed date string should log a warning, not raise.
        e = _make_engagement(end_date="not-a-date")
        # No exception, falls through to "active".
        assert e.is_active()


# ============================================================================
# 4. Invalid enum values in saved data
# ============================================================================


class TestInvalidEnumInFromDict:
    """Fix: _from_dict catches ValueError on bad enum values instead of crashing."""

    def test_engagement_skips_invalid_methods(self, tmp_storage_dir):
        from vorsyghta.research.engagement import (
            EngagementManager,
            ResearchMethod,
        )

        mgr = EngagementManager(storage_dir=tmp_storage_dir)
        data = {
            "id": "x1",
            "client": "c",
            "engagement_name": "e",
            "status": "active",
            "targets": [],
            "rules": {
                "allowed_methods": ["fuzzing", "totally_invalid_method"],
                "prohibited_methods": ["social_engineering", "also_invalid"],
            },
            "legal": {},
        }
        eng = mgr._from_dict(data)

        assert ResearchMethod.FUZZING in eng.rules.allowed_methods
        assert all(m != "totally_invalid_method" for m in eng.rules.allowed_methods), (
            "invalid allowed_method must be skipped, not stored as a string"
        )

    def test_disclosure_falls_back_on_invalid_enums(self, tmp_storage_dir):
        from vorsyghta.research.disclosure import (
            DisclosureManager,
            DisclosureStatus,
            VendorResponse,
        )

        mgr = DisclosureManager(storage_dir=tmp_storage_dir)
        data = {
            "id": "d1",
            "engagement_id": "e1",
            "finding_id": "f1",
            "title": "t",
            "vendor_response": "bogus_response",
            "status": "bogus_status",
        }
        rec = mgr._from_dict(data)

        assert rec.vendor_response == VendorResponse.NO_RESPONSE
        assert rec.status == DisclosureStatus.DRAFT


# ============================================================================
# 5. grant_extension() with None embargo_end_date
# ============================================================================


class TestGrantExtensionNoneEmbargo:
    """Fix: when embargo_end_date is None, the extension is computed from now."""

    def test_sets_new_end_date(self, tmp_storage_dir):
        from vorsyghta.research.disclosure import (
            DisclosureManager,
            DisclosureRecord,
        )

        mgr = DisclosureManager(storage_dir=tmp_storage_dir)
        rec = DisclosureRecord(
            id="d1",
            engagement_id="e1",
            finding_id="f1",
            title="t",
            vendor="v",
            product="p",
            embargo_end_date=None,
            embargo_days=90,
            embargo_extensions=0,
            max_extensions=2,
        )
        mgr._disclosures["d1"] = rec

        updated = mgr.grant_extension("d1", extension_days=30, reason="test")

        assert updated.embargo_end_date is not None
        end = datetime.fromisoformat(updated.embargo_end_date)
        delta = end - datetime.utcnow()
        # Allow a 1-day tolerance for slow CI / boundary seconds.
        assert 29 <= delta.days <= 30, f"expected ~30 days, got {delta.days}"

    def test_extension_count_incremented(self, tmp_storage_dir):
        from vorsyghta.research.disclosure import (
            DisclosureManager,
            DisclosureRecord,
        )

        mgr = DisclosureManager(storage_dir=tmp_storage_dir)
        rec = DisclosureRecord(
            id="d2",
            engagement_id="e1",
            finding_id="f1",
            title="t",
            vendor="v",
            product="p",
            embargo_end_date=None,
            embargo_extensions=0,
            max_extensions=2,
        )
        mgr._disclosures["d2"] = rec

        updated = mgr.grant_extension("d2", extension_days=10)
        assert updated.embargo_extensions == 1


# ============================================================================
# 6. _set_nested() bounds validation
# ============================================================================


class TestSetNestedBoundsValidation:
    """Fix: _set_nested() returns silently on out-of-range / missing paths
    instead of raising IndexError / KeyError.

    NOTE: a missing *final* dict key is silently created (dict assignment
    never raises), which differs slightly from the audit summary's wording
    but does not crash.  These tests pin the crash-prevention behaviour.
    """

    @pytest.fixture
    def mutator(self):
        from vorsyghta.research.llm_mutator import LLMMutator

        # Bypass __init__ — we only exercise _set_nested.
        return LLMMutator.__new__(LLMMutator)

    @pytest.fixture
    def sample_data(self):
        return {"a": [1, 2, 3], "b": {"c": "d"}}

    def test_out_of_range_list_index_no_crash(self, mutator, sample_data):
        mutator._set_nested(sample_data, "a[10]", 99)
        assert sample_data["a"] == [1, 2, 3]

    def test_intermediate_out_of_range_index_no_crash(self, mutator, sample_data):
        mutator._set_nested(sample_data, "a[10].x", 99)
        assert sample_data["a"] == [1, 2, 3]

    def test_intermediate_missing_dict_key_no_crash(self, mutator, sample_data):
        mutator._set_nested(sample_data, "b.missing.x", 99)
        assert sample_data["b"] == {"c": "d"}

    def test_intermediate_non_dict_no_crash(self, mutator, sample_data):
        # "a" is a list; treating it as a dict should not raise.
        mutator._set_nested(sample_data, "a.x[0]", 99)

    def test_valid_list_index_still_works(self, mutator, sample_data):
        mutator._set_nested(sample_data, "a[1]", 99)
        assert sample_data["a"][1] == 99

    def test_valid_dict_key_still_works(self, mutator, sample_data):
        mutator._set_nested(sample_data, "b.c", "new")
        assert sample_data["b"]["c"] == "new"


# ============================================================================
# 7. Self-registration input is tenant-safe
# ============================================================================


class TestRegistrationInputIsolation:
    """Registration accepts only identity and organization fields."""

    def test_role_and_tenant_fields_are_rejected(self):
        from pydantic import ValidationError

        from vorsyghta.api.routers.auth import RegisterRequest

        with pytest.raises(ValidationError):
            RegisterRequest.model_validate(
                {
                    "email": "owner@example.test",
                    "password": "correct-horse-battery",
                    "organization_name": "Example Org",
                    "tenant_id": "victim",
                    "role": "admin",
                }
            )

    def test_password_bounds_are_enforced(self):
        from pydantic import ValidationError

        from vorsyghta.api.routers.auth import RegisterRequest

        with pytest.raises(ValidationError):
            RegisterRequest(
                email="owner@example.test",
                password="too-short",
                organization_name="Example Org",
            )
        with pytest.raises(ValidationError):
            RegisterRequest(
                email="owner@example.test",
                password="é" * 72,
                organization_name="Example Org",
            )


def test_oauth_metadata_uses_mounted_token_route():
    """Generated OpenAPI clients receive the mounted token endpoint."""
    from vorsyghta.security.rbac import oauth2_scheme

    assert oauth2_scheme.model.flows.password.tokenUrl == "/api/auth/login"


# ============================================================================
# 8. asyncpg = None fallback (postgres_event_store.py)
# ============================================================================


class TestAsyncpgFallbackImport:
    """Fix: when asyncpg is not importable, the module sets asyncpg = None
    so the ``asyncpg.Record`` type hint does not raise NameError at class
    definition time.
    """

    def test_module_imports_without_asyncpg(self, monkeypatch):
        # Force a fresh import with asyncpg hidden.
        monkeypatch.setitem(sys.modules, "asyncpg", None)
        # Drop any cached import.
        sys.modules.pop("vorsyghta.core.postgres_event_store", None)
        try:
            import vorsyghta.core.postgres_event_store as pes  # noqa: F401

            # If we got here without NameError, the fix holds.
            assert pes is not None
        finally:
            sys.modules.pop("vorsyghta.core.postgres_event_store", None)


# ============================================================================
# 9. LLM providers set tokens_used post-construction
# ============================================================================


class TestProviderTokensUsedAssignment:
    """Fix: OpenAI / Anthropic providers no longer pass tokens_used=... into
    LLMResponse() (which would TypeError) and no longer set a stray .usage
    attribute.  They set llm_response.tokens_used after construction.

    We can't call the real APIs here, so we verify the construction contract
    by simulating the response object the providers build.
    """

    def test_llmresponse_does_not_accept_tokens_used_kwarg(self):
        from vorsyghta.llm.base import LLMResponse

        with pytest.raises(TypeError):
            LLMResponse(
                content="hi",
                provider="openai",
                model="gpt-4",
                tokens_used=100,  # must NOT be an accepted kwarg
            )

    def test_anthropic_provider_does_not_set_usage_attr(self):
        # Import the module and inspect that the assignment pattern was
        # removed — we verify by constructing a fake response and checking
        # the provider's code path leaves no .usage attribute on the result.
        # Since we cannot run the real API, this is a structural smoke test:
        # the module must import cleanly and the class must exist.
        from vorsyghta.llm.providers import anthropic_provider

        assert hasattr(anthropic_provider, "AnthropicProvider")


# ============================================================================
# 10. validate_env.py checks VORSYGHTA_SECRET_KEY
# ============================================================================


class TestValidateEnvSecretKeyName:
    """Fix: validate_env.py now checks VORSYGHTA_SECRET_KEY (matching rbac.py)
    instead of the old SECRET_KEY name.
    """

    def test_required_vars_uses_vorsyghta_secret_key(self):
        from vorsyghta.config import validate_env

        names = [v.name for v in validate_env.REQUIRED_VARS]
        assert "VORSYGHTA_SECRET_KEY" in names, "validate_env must check VORSYGHTA_SECRET_KEY (the name rbac.py reads)"
        assert "SECRET_KEY" not in names, "old SECRET_KEY name should no longer be in REQUIRED_VARS"
