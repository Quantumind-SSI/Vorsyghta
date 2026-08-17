"""Grounded unit tests for Azure LLM provider hardening.

These tests exercise the real provider construction and LLMManager wiring code
paths (no over-mocking of the logic under test). They assert the resiliency and
correctness properties added by the Azure-provider hardening:

  1. Timeout/retry bounds: both AzureOpenAIProvider and PydanticAIProvider build
     their underlying AsyncAzureOpenAI client with the configured request
     timeout and a capped retry count, sourced from config.yaml.
  2. Fail-safe coercion: malformed timeout/retry config can never disable the
     timeout or produce a negative retry count; values fall back to safe
     defaults (Power of 10 rule 2 — bounded loops/waits).
  3. Config propagation: LLMManager forwards timeout_seconds/retry_attempts from
     the azure block into the provider config it constructs.
  4. LLMManager footgun guard: LLMManager(cfg) treats a dict passed positionally
     as config, and a non-provider object is rejected rather than silently
     becoming self.provider.

The Azure endpoints are dummy values; no network calls are made — the OpenAI
SDK builds its client lazily and we only inspect the client's configured
transport parameters, so these tests are hermetic and CI-safe.
"""
from __future__ import annotations

from typing import Any, Dict

import pytest

from vorsyghta.llm.base import BaseLLMProvider, LLMResponse
from vorsyghta.llm.providers.azure_provider import AzureOpenAIProvider
from vorsyghta.llm.providers.pydantic_ai_provider import PydanticAIProvider
from vorsyghta.llm.manager import LLMManager


# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #
def _azure_cfg(**overrides: Any) -> Dict[str, Any]:
    """A complete, valid Azure provider config with optional overrides."""
    cfg: Dict[str, Any] = {
        "api_key": "test-key",
        "endpoint": "https://ciicerone-openai.openai.azure.com/",
        "deployment": "gpt-4o",
        "api_version": "2024-10-21",
        "model": "gpt-4o",
        "timeout_seconds": 45,
        "retry_attempts": 2,
    }
    cfg.update(overrides)
    return cfg


# --------------------------------------------------------------------------- #
# AzureOpenAIProvider — timeout/retry wiring
# --------------------------------------------------------------------------- #
class TestAzureProviderResiliency:
    def test_config_values_are_parsed(self) -> None:
        provider = AzureOpenAIProvider(_azure_cfg(timeout_seconds=30, retry_attempts=5))
        assert provider.timeout_seconds == 30.0
        assert provider.max_retries == 5

    def test_client_uses_configured_timeout_and_retries(self) -> None:
        provider = AzureOpenAIProvider(_azure_cfg(timeout_seconds=45, retry_attempts=2))
        client = provider._get_client()
        # The AsyncAzureOpenAI client must reflect the configured bounds.
        assert client.timeout == 45.0
        assert client.max_retries == 2

    def test_defaults_applied_when_absent(self) -> None:
        cfg = _azure_cfg()
        cfg.pop("timeout_seconds")
        cfg.pop("retry_attempts")
        provider = AzureOpenAIProvider(cfg)
        assert provider.timeout_seconds == 60.0
        assert provider.max_retries == 3

    def test_non_numeric_timeout_falls_back(self) -> None:
        provider = AzureOpenAIProvider(_azure_cfg(timeout_seconds="oops"))
        assert provider.timeout_seconds == 60.0

    def test_zero_or_negative_timeout_rejected(self) -> None:
        assert AzureOpenAIProvider(_azure_cfg(timeout_seconds=0)).timeout_seconds == 60.0
        assert AzureOpenAIProvider(_azure_cfg(timeout_seconds=-10)).timeout_seconds == 60.0

    def test_negative_retries_rejected(self) -> None:
        assert AzureOpenAIProvider(_azure_cfg(retry_attempts=-1)).max_retries == 3

    def test_non_numeric_retries_falls_back(self) -> None:
        assert AzureOpenAIProvider(_azure_cfg(retry_attempts="two")).max_retries == 3

    def test_zero_retries_is_valid(self) -> None:
        # Zero retries is a legitimate operator choice (fail fast).
        assert AzureOpenAIProvider(_azure_cfg(retry_attempts=0)).max_retries == 0

    def test_model_info_reports_bounds(self) -> None:
        info = AzureOpenAIProvider(_azure_cfg()).get_model_info()
        assert info["timeout_seconds"] == 45.0
        assert info["max_retries"] == 2
        assert info["configured"] is True

    def test_missing_credentials_raise(self) -> None:
        with pytest.raises(ValueError):
            AzureOpenAIProvider(_azure_cfg(api_key=""))
        with pytest.raises(ValueError):
            AzureOpenAIProvider(_azure_cfg(endpoint=""))


# --------------------------------------------------------------------------- #
# PydanticAIProvider — timeout/retry wiring
# --------------------------------------------------------------------------- #
class TestPydanticAIProviderResiliency:
    def test_config_values_are_parsed(self) -> None:
        provider = PydanticAIProvider(_azure_cfg(timeout_seconds=30, retry_attempts=5))
        assert provider.timeout_seconds == 30.0
        assert provider.max_retries == 5

    def test_built_client_uses_configured_bounds(self) -> None:
        provider = PydanticAIProvider(_azure_cfg(timeout_seconds=45, retry_attempts=2))
        client = provider._build_openai_client()
        assert client.timeout == 45.0
        assert client.max_retries == 2

    def test_model_builds_with_bounded_client(self) -> None:
        # pydantic_ai is an optional runtime dependency: the LLMManager degrades
        # gracefully when it is absent (see LLMManager._initialize_providers).
        # Only the model-construction path actually imports it, so skip rather
        # than fail when the package is not installed in the test environment.
        pytest.importorskip("pydantic_ai")
        provider = PydanticAIProvider(_azure_cfg())
        model = provider._get_model()
        # The pydantic-ai model must be constructed; a second call is cached.
        assert model is provider._get_model()

    def test_defaults_applied_when_absent(self) -> None:
        cfg = _azure_cfg()
        cfg.pop("timeout_seconds")
        cfg.pop("retry_attempts")
        provider = PydanticAIProvider(cfg)
        assert provider.timeout_seconds == 60.0
        assert provider.max_retries == 3

    def test_malformed_values_fall_back(self) -> None:
        provider = PydanticAIProvider(_azure_cfg(timeout_seconds="x", retry_attempts=-9))
        assert provider.timeout_seconds == 60.0
        assert provider.max_retries == 3

    def test_model_info_reports_bounds(self) -> None:
        info = PydanticAIProvider(_azure_cfg()).get_model_info()
        assert info["timeout_seconds"] == 45.0
        assert info["max_retries"] == 2

    def test_missing_credentials_raise(self) -> None:
        with pytest.raises(ValueError):
            PydanticAIProvider(_azure_cfg(api_key=""))


# --------------------------------------------------------------------------- #
# LLMManager — config propagation + footgun guards
# --------------------------------------------------------------------------- #
class TestLLMManagerAzureWiring:
    def _manager_config(self, **azure_overrides: Any) -> Dict[str, Any]:
        return {
            "default_provider": "azure",
            "azure": _azure_cfg(**azure_overrides),
        }

    def test_manager_forwards_timeout_and_retries(self) -> None:
        manager = LLMManager(config=self._manager_config(timeout_seconds=90, retry_attempts=4))
        azure = manager.get_provider("azure")
        assert azure is not None
        assert azure.timeout_seconds == 90.0
        assert azure.max_retries == 4

    def test_manager_forwards_bounds_to_pydantic_ai(self) -> None:
        manager = LLMManager(config=self._manager_config(timeout_seconds=90, retry_attempts=4))
        pyd = manager.get_provider("pydantic_ai")
        assert pyd is not None
        assert pyd.timeout_seconds == 90.0
        assert pyd.max_retries == 4

    def test_manager_defaults_when_bounds_absent(self) -> None:
        cfg = self._manager_config()
        cfg["azure"].pop("timeout_seconds")
        cfg["azure"].pop("retry_attempts")
        manager = LLMManager(config=cfg)
        azure = manager.get_provider("azure")
        assert azure.timeout_seconds == 60.0
        assert azure.max_retries == 3

    def test_positional_dict_treated_as_config(self) -> None:
        # LLMManager(cfg) footgun: a dict passed positionally must be treated as
        # config, and self.provider must end up a concrete provider.
        manager = LLMManager(self._manager_config())
        assert isinstance(manager.provider, BaseLLMProvider)
        assert manager.provider.timeout_seconds == 45.0

    def test_non_provider_object_rejected(self) -> None:
        # A random object passed as provider is ignored (not left as self.provider).
        manager = LLMManager(provider=object(), config=self._manager_config())
        assert isinstance(manager.provider, BaseLLMProvider)

    def test_explicit_provider_instance_preserved(self) -> None:
        forced = AzureOpenAIProvider(_azure_cfg(timeout_seconds=15))
        manager = LLMManager(provider=forced)
        assert manager.provider is forced
        assert manager.provider.timeout_seconds == 15.0
