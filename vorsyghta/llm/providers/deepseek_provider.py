"""DeepSeek LLM provider for Vorsyghta.

This provider integrates with DeepSeek's API for cyber security tasks.
Supports both DeepSeek-V3 (reasoning) and DeepSeek-R1 (step-by-step) models.
"""

import logging
import asyncio
import aiohttp
from typing import Optional, Dict, Any, List

from ..base import BaseLLMProvider, LLMResponse

logger = logging.getLogger(__name__)


class DeepSeekProvider(BaseLLMProvider):
    """DeepSeek API provider for threat simulation and security analysis."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize DeepSeek provider.

        Args:
            config: Configuration with api_key, model, etc.
        """
        super().__init__(config)
        self.api_key = config.get('api_key')
        self.model = config.get('model', 'deepseek-v3')
        self.base_url = config.get('base_url', 'https://api.deepseek.com')
        self._session: Optional[aiohttp.ClientSession] = None

        if not self.api_key:
            logger.warning("DeepSeek API key not provided - provider will fail")

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session with connection pooling."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def cleanup(self):
        """Clean up resources."""
        if self._session and not self._session.closed:
            await self._session.close()

    def is_available(self) -> bool:
        """Check if DeepSeek provider is available."""
        return bool(self.api_key)

    async def generate_content(
        self,
        prompt: str,
        scenario_type: str = "general",
        max_tokens: int = 1000,
        temperature: float = 0.7,
        **kwargs
    ) -> Optional[LLMResponse]:
        """Generate content using DeepSeek API.

        Args:
            prompt: The prompt to send to DeepSeek
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            **kwargs: Additional parameters (system_message, etc.)

        Returns:
            LLMResponse with generated content
        """
        session = await self._get_session()

        # Build messages for chat completion
        system_message = kwargs.get('system_message',
            "You are an expert cybersecurity assistant for threat simulation and security testing. "
            "You have deep knowledge of MITRE ATT&CK framework, offensive and defensive security techniques. "
            "Always provide detailed, actionable responses with specific security tool commands and methodologies. "
            "You understand how to work safely within lab environments for authorized security testing."
        )

        messages = [
            {"role": "system", "content": system_message},
            {"role": "user", "content": prompt}
        ]

        # Build request payload
        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        # Add any additional parameters
        for key, value in kwargs.items():
            if key not in ['system_message', 'scenario_type']:
                payload[key] = value

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        try:
            url = f"{self.base_url}/v1/chat/completions"

            logger.debug(f"DeepSeek API call to {url} with model {self.model}")

            async with session.post(url, json=payload, headers=headers, timeout=30) as response:
                if response.status != 200:
                    error_text = await response.text()
                    logger.error(f"DeepSeek API error {response.status}: {error_text}")
                    return None

                data = await response.json()

            # Parse response - DeepSeek uses same format as OpenAI
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")

            llm_response = LLMResponse(
                content=content,
                provider="deepseek",
                model=self.model,
                metadata={
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                    "prompt_length": len(prompt),
                    "finish_reason": data.get("choices", [{}])[0].get("finish_reason", ""),
                }
            )

            # Extract token usage
            usage = data.get("usage", {})
            if usage:
                llm_response.tokens_used = usage.get("total_tokens", 0)
                llm_response.metadata.update({
                    "prompt_tokens": usage.get("prompt_tokens", 0),
                    "completion_tokens": usage.get("completion_tokens", 0),
                })

            llm_response.is_real_ai = True

            logger.info(f"DeepSeek API response: {len(content)} chars, "
                       f"{llm_response.tokens_used} tokens")
            return llm_response

        except asyncio.TimeoutError:
            logger.error(f"DeepSeek API timeout after 30 seconds")
            return None
        except Exception as e:
            logger.error(f"DeepSeek content generation failed: {e}")
            return None

    async def validate_connection(self) -> bool:
        """Validate connection to DeepSeek API."""
        try:
            session = await self._get_session()

            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }

            url = f"{self.base_url}/v1/models"

            async with session.get(url, headers=headers, timeout=10) as response:
                return response.status == 200

        except Exception as e:
            logger.error(f"DeepSeek connection validation failed: {e}")
            return False

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model."""
        return {
            "provider": "deepseek",
            "model": self.model,
            "base_url": self.base_url,
            "configured": bool(self.api_key),
            "recommended_models": {
                "deepseek-v3-73b": "deepseek-v3",
                "deepseek-r1-7b": "deepseek-r1",
            }
        }

    async def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """Generate response from prompt (required by base class)."""
        result = await self.generate_content(prompt, **kwargs)
        if result is None:
            return LLMResponse("Error: Failed to generate content from DeepSeek")
        return result
