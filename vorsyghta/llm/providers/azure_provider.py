"""Azure OpenAI provider implementation for Vorsyghta."""

import asyncio
import logging
from typing import Dict, Any, Optional
from datetime import datetime

from ..base import BaseLLMProvider, LLMResponse

logger = logging.getLogger(__name__)


class AzureOpenAIProvider(BaseLLMProvider):
    """Azure OpenAI LLM provider implementation.

    Azure OpenAI uses a deployment-based URL format and api-key
    authentication instead of Bearer tokens.
    """

    def __init__(self, config: Dict[str, Any]):
        """Initialize Azure OpenAI provider.

        Args:
            config: Configuration dictionary with Azure OpenAI settings:
                - api_key: Azure OpenAI API key
                - endpoint: Azure OpenAI endpoint (e.g. https://<resource>.openai.azure.com)
                - deployment: Deployment name (e.g. gpt-4o)
                - api_version: API version (e.g. 2024-10-21)
                - model: Model name (optional, defaults to deployment name)
        """
        super().__init__(config)
        self.api_key = config.get('api_key')
        self.endpoint = config.get('endpoint', '')
        self.deployment = config.get('deployment', config.get('model', 'gpt-4o'))
        self.api_version = config.get('api_version', '2024-10-21')
        self.model = config.get('model', self.deployment)
        self._client = None

        if not self.api_key:
            raise ValueError("Azure OpenAI API key is required")
        if not self.endpoint:
            raise ValueError("Azure OpenAI endpoint is required")
        if not self.deployment:
            raise ValueError("Azure OpenAI deployment name is required")

    def _get_client(self):
        """Get or create Azure OpenAI client."""
        if self._client is None:
            try:
                from openai import AsyncAzureOpenAI
                self._client = AsyncAzureOpenAI(
                    api_key=self.api_key,
                    azure_endpoint=self.endpoint,
                    api_version=self.api_version,
                )
            except ImportError:
                raise ImportError(
                    "OpenAI SDK not installed. Install with: pip install openai"
                )
        return self._client

    async def generate_content(
        self,
        prompt: str,
        max_tokens: int = 1000,
        temperature: float = 0.7,
        **kwargs
    ) -> LLMResponse:
        """Generate content using Azure OpenAI API.

        Args:
            prompt: The prompt to send to Azure OpenAI
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            **kwargs: Additional parameters

        Returns:
            LLMResponse with generated content
        """
        try:
            client = self._get_client()

            system_message = kwargs.get(
                'system_message',
                "You are a cybersecurity expert assistant for threat simulation and security training."
            )

            messages = [
                {"role": "system", "content": system_message},
                {"role": "user", "content": prompt}
            ]

            response = await client.chat.completions.create(
                model=self.deployment,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
                **{k: v for k, v in kwargs.items() if k not in ['system_message']}
            )

            content = response.choices[0].message.content

            llm_response = LLMResponse(
                content=content,
                provider="azure",
                model=self.model,
            )
            llm_response.tokens_used = response.usage.total_tokens if response.usage else 0
            llm_response.metadata = {
                "temperature": temperature,
                "max_tokens": max_tokens,
                "prompt_length": len(prompt),
                "finish_reason": response.choices[0].finish_reason,
                "deployment": self.deployment,
                "api_version": self.api_version,
                "endpoint": self.endpoint,
                "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                "total_tokens": response.usage.total_tokens if response.usage else 0,
            }
            llm_response.is_real_ai = True

            logger.info(
                f"Azure OpenAI response received: {len(content)} chars, "
                f"{llm_response.tokens_used} tokens"
            )
            return llm_response

        except ImportError as e:
            logger.error(f"OpenAI SDK not available: {e}")
            raise
        except Exception as e:
            logger.error(f"Azure OpenAI content generation failed: {e}")
            raise

    async def validate_connection(self) -> bool:
        """Validate connection to Azure OpenAI API."""
        try:
            client = self._get_client()

            response = await client.chat.completions.create(
                model=self.deployment,
                messages=[{"role": "user", "content": "test"}],
                max_tokens=5
            )

            return response.choices[0].message.content is not None

        except Exception as e:
            logger.error(f"Azure OpenAI connection validation failed: {e}")
            return False

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model."""
        return {
            "provider": "azure",
            "model": self.model,
            "deployment": self.deployment,
            "endpoint": self.endpoint,
            "api_version": self.api_version,
            "configured": bool(self.api_key and self.endpoint and self.deployment)
        }
