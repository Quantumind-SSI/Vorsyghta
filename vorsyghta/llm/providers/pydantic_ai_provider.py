"""pydantic-ai backed LLM provider (strict, typed) for Azure OpenAI.

This provider implements the application's ``BaseLLMProvider`` contract on top
of ``pydantic_ai`` so that agentic paths (notably the red team) reason through a
strict, typed model client rather than ad-hoc HTTP. It targets the PRODUCTION
Azure OpenAI deployment (``vorsyghta-openai`` / ``gpt-4o``) and is drop-in
compatible with ``LLMManager`` and the red-team agent's ``self.llm`` seam.

Why pydantic-ai:
  * Typed model + provider objects (``OpenAIChatModel`` + ``AzureProvider``).
  * Native structured-output support via ``result_type`` for callers that want
    validated objects instead of free text.
  * One consistent agent runtime across the platform's agentic teams.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional, Type, TypeVar

from ..base import BaseLLMProvider, LLMResponse

logger = logging.getLogger(__name__)

T = TypeVar("T")


class PydanticAIProvider(BaseLLMProvider):
    """Azure OpenAI provider implemented with pydantic-ai.

    Config keys (falling back to AZURE_OPENAI_* env vars):
      - endpoint     : Azure OpenAI endpoint URL (required)
      - deployment   : Azure deployment name, e.g. ``gpt-4o`` (required)
      - api_version  : Azure API version (default ``2024-10-21``)
      - api_key      : Azure OpenAI key (required; usually injected from Key Vault)
      - model        : logical model name for reporting (defaults to deployment)
      - temperature  : default sampling temperature
      - max_tokens   : default max output tokens
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.endpoint = config.get("endpoint") or os.getenv("AZURE_OPENAI_ENDPOINT", "")
        self.deployment = (
            config.get("deployment")
            or os.getenv("AZURE_OPENAI_DEPLOYMENT")
            or config.get("model", "")
        )
        self.api_version = (
            config.get("api_version")
            or os.getenv("AZURE_OPENAI_API_VERSION", "2024-10-21")
        )
        self.api_key = config.get("api_key") or os.getenv("AZURE_OPENAI_API_KEY", "")
        self.model = config.get("model", self.deployment)
        self.temperature = float(config.get("temperature", 0.7))
        self.max_tokens = int(config.get("max_tokens", 3000))

        # Resiliency bounds shared with AzureOpenAIProvider: every request is
        # time-bounded and SDK-level retries are capped (Power of 10 rule 2).
        self.timeout_seconds = self._coerce_positive_float(
            config.get("timeout_seconds"), default=60.0, name="timeout_seconds"
        )
        self.max_retries = self._coerce_non_negative_int(
            config.get("retry_attempts"), default=3, name="retry_attempts"
        )

        # Preconditions (fail loud, not silent).
        if not self.endpoint:
            raise ValueError("PydanticAIProvider requires an Azure endpoint")
        if not self.deployment:
            raise ValueError("PydanticAIProvider requires an Azure deployment name")
        if not self.api_key:
            raise ValueError("PydanticAIProvider requires an Azure API key")

        self._model = None  # lazily built OpenAIChatModel

    @staticmethod
    def _coerce_positive_float(value: Any, default: float, name: str) -> float:
        """Return a strictly-positive float, falling back to ``default``.

        Rejects non-numeric, zero, and negative values so a misconfiguration
        can never disable the request timeout.
        """
        try:
            coerced = float(value) if value is not None else default
        except (TypeError, ValueError):
            logger.warning("Invalid pydantic_ai %s=%r; using %s", name, value, default)
            return default
        if coerced <= 0:
            logger.warning("Non-positive pydantic_ai %s=%r; using %s", name, value, default)
            return default
        return coerced

    @staticmethod
    def _coerce_non_negative_int(value: Any, default: int, name: str) -> int:
        """Return a non-negative int (retry count), falling back to ``default``."""
        try:
            coerced = int(value) if value is not None else default
        except (TypeError, ValueError):
            logger.warning("Invalid pydantic_ai %s=%r; using %s", name, value, default)
            return default
        if coerced < 0:
            logger.warning("Negative pydantic_ai %s=%r; using %s", name, value, default)
            return default
        return coerced

    def _build_openai_client(self):
        """Build a bounded AsyncAzureOpenAI client (timeout + capped retries).

        Passing an explicit client to ``AzureProvider`` is the supported way to
        control transport-level resiliency; without it pydantic-ai builds a
        default client with no request timeout.
        """
        from openai import AsyncAzureOpenAI

        return AsyncAzureOpenAI(
            api_key=self.api_key,
            azure_endpoint=self.endpoint,
            api_version=self.api_version,
            timeout=self.timeout_seconds,
            max_retries=self.max_retries,
        )

    def _get_model(self):
        """Build (once) the pydantic-ai OpenAIChatModel over AzureProvider."""
        if self._model is None:
            from pydantic_ai.models.openai import OpenAIChatModel
            from pydantic_ai.providers.azure import AzureProvider

            provider = AzureProvider(openai_client=self._build_openai_client())
            self._model = OpenAIChatModel(self.deployment, provider=provider)
        return self._model

    async def generate_content(
        self,
        prompt: str,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ) -> LLMResponse:
        """Generate free-text content via pydantic-ai. Implements BaseLLMProvider.

        Args:
            prompt: The user prompt.
            max_tokens: Optional override for output token budget.
            temperature: Optional override for sampling temperature.

        Returns:
            LLMResponse with ``content``, ``provider='pydantic_ai'``, ``model``.
        """
        assert isinstance(prompt, str) and prompt, "prompt must be a non-empty str"
        from pydantic_ai import Agent
        from pydantic_ai.settings import ModelSettings

        settings = ModelSettings(
            temperature=self.temperature if temperature is None else temperature,
            max_tokens=self.max_tokens if max_tokens is None else max_tokens,
        )
        agent = Agent(self._get_model(), model_settings=settings)
        result = await agent.run(prompt)
        return LLMResponse(
            content=str(result.output),
            provider="pydantic_ai",
            model=self.model,
        )

    async def generate_typed(
        self,
        prompt: str,
        result_type: Type[T],
        system_prompt: Optional[str] = None,
    ) -> T:
        """Generate a VALIDATED, typed object via pydantic-ai's result_type.

        This is the strict path: the model's output is parsed and validated
        against ``result_type`` (a pydantic model / dataclass). On validation
        failure pydantic-ai raises, so callers never receive fabricated or
        malformed structures.

        Args:
            prompt: The user prompt.
            result_type: The pydantic model / type to validate the output into.
            system_prompt: Optional system instructions.

        Returns:
            An instance of ``result_type``.
        """
        assert isinstance(prompt, str) and prompt, "prompt must be a non-empty str"
        from pydantic_ai import Agent

        agent = Agent(
            self._get_model(),
            output_type=result_type,
            system_prompt=system_prompt or "",
        )
        result = await agent.run(prompt)
        return result.output

    async def generate(self, prompt: str) -> str:
        """Convenience string interface used by the red-team agent seam.

        The red-team agent's ``_generate_llm_response`` prefers ``.generate``;
        expose it so the agent is powered by pydantic-ai + Azure gpt-4o.
        """
        response = await self.generate_content(prompt)
        return response.content

    def is_available(self) -> bool:
        """True when endpoint/deployment/key are all present."""
        return bool(self.endpoint and self.deployment and self.api_key)

    def get_model_info(self) -> Dict[str, Any]:
        return {
            "provider": "pydantic_ai",
            "backend": "azure_openai",
            "model": self.model,
            "deployment": self.deployment,
            "endpoint": self.endpoint,
            "api_version": self.api_version,
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
        }
