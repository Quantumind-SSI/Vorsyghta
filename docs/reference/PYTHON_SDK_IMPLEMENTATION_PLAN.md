# ThreatGPT Python SDK - Core Implementation Plan

**Version:** 1.0.0  
**Date:** December 9, 2025  
**Timeline:** 6 Weeks (January - February 2026)  
**Status:** Planning Phase

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Current State Assessment](#current-state-assessment)
3. [SDK Architecture](#sdk-architecture)
4. [Implementation Phases](#implementation-phases)
5. [Week-by-Week Breakdown](#week-by-week-breakdown)
6. [File Structure](#file-structure)
7. [Testing Strategy](#testing-strategy)
8. [Documentation Plan](#documentation-plan)
9. [Success Criteria](#success-criteria)

---

## Executive Summary

This plan outlines the implementation of the **ThreatGPT Python SDK**, transforming the existing core components into a production-ready, developer-friendly SDK that provides intuitive, type-safe access to all ThreatGPT capabilities.

### Goals

- ✅ Create unified `ThreatGPTClient` and `AsyncThreatGPTClient` interfaces
- ✅ Implement resource-based API design (scenarios, simulations, templates, etc.)
- ✅ Add comprehensive error handling, retries, and authentication
- ✅ Achieve 90%+ test coverage
- ✅ Provide excellent documentation and examples
- ✅ Package for PyPI distribution

### Key Deliverables

1. **SDK Client Interface** - Main entry point with resource organization
2. **Resource Classes** - Scenarios, Simulations, Templates, Intelligence, Datasets
3. **Authentication Layer** - API key, OAuth, environment variable support
4. **Error Handling** - Custom exceptions, retry logic, rate limiting
5. **Type Safety** - Full Pydantic models and type hints
6. **Documentation** - API reference, guides, examples
7. **Testing Suite** - Unit, integration, and E2E tests
8. **PyPI Package** - Production-ready distribution

---

## Current State Assessment

### ✅ What Exists

**Core Components:**
- `ThreatSimulator` - Main simulation orchestrator
- `ThreatScenario` - Scenario data model
- `SimulationResult` - Result tracking
- `LLMManager` - Multi-provider LLM management
- `ConfigurationLoader` - YAML configuration

**Infrastructure:**
- LLM provider integrations (7 providers)
- Dataset processors (Enron, PhishTank, etc.)
- Intelligence services (OSINT)
- Template system (YAML-based)
- CLI interface
- FastAPI REST API

### ❌ What's Missing (SDK Layer)

**Critical Gaps:**
1. **No unified SDK client interface** - Direct class usage is clunky
2. **No resource-based organization** - No logical grouping
3. **Inconsistent async/sync support** - Some methods only async
4. **Limited error handling** - Basic exceptions
5. **No retry logic** - Manual retry implementation needed
6. **No authentication abstraction** - Direct API key management
7. **No pagination helpers** - Manual pagination
8. **Limited SDK documentation** - Only internal docs
9. **No SDK-specific examples** - Only CLI examples

### 🎯 What We'll Build

A complete SDK layer that wraps existing functionality with:
- Intuitive client interface
- Resource-based organization
- Comprehensive error handling
- Production-ready features
- Excellent developer experience

---

## SDK Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────────┐
│                    ThreatGPT Python SDK                      │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────┐      ┌──────────────────┐             │
│  │ ThreatGPTClient │      │ AsyncThreatGPT   │             │
│  │    (Sync)       │      │    Client        │             │
│  └────────┬────────┘      └────────┬─────────┘             │
│           │                         │                        │
│           └────────┬────────────────┘                        │
│                    │                                         │
│       ┌────────────┴────────────┐                           │
│       │    Resource Layer       │                           │
│       ├─────────────────────────┤                           │
│       │ • Scenarios             │                           │
│       │ • Simulations           │                           │
│       │ • Templates             │                           │
│       │ • Intelligence          │                           │
│       │ • Datasets              │                           │
│       │ • Deployments           │                           │
│       └────────────┬────────────┘                           │
│                    │                                         │
│       ┌────────────┴────────────┐                           │
│       │    Core Layer           │                           │
│       ├─────────────────────────┤                           │
│       │ • ThreatSimulator       │                           │
│       │ • LLMManager            │                           │
│       │ • ConfigurationLoader   │                           │
│       │ • Template Manager      │                           │
│       └─────────────────────────┘                           │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Directory Structure

```
src/threatgpt/
├── sdk/                          # NEW: SDK layer
│   ├── __init__.py               # SDK exports
│   ├── client.py                 # ThreatGPTClient (sync)
│   ├── async_client.py           # AsyncThreatGPTClient
│   ├── auth.py                   # Authentication handlers
│   ├── config.py                 # SDK configuration
│   ├── exceptions.py             # SDK-specific exceptions
│   ├── pagination.py             # Pagination helpers
│   ├── retry.py                  # Retry logic
│   ├── validators.py             # Input validation
│   │
│   ├── resources/                # Resource classes
│   │   ├── __init__.py
│   │   ├── base.py               # Base resource class
│   │   ├── scenarios.py          # Scenario operations
│   │   ├── simulations.py        # Simulation operations
│   │   ├── templates.py          # Template operations
│   │   ├── intelligence.py       # Intelligence operations
│   │   ├── datasets.py           # Dataset operations
│   │   └── deployments.py        # Deployment operations
│   │
│   ├── models/                   # SDK-specific models
│   │   ├── __init__.py
│   │   ├── scenario.py           # Scenario models
│   │   ├── simulation.py         # Simulation models
│   │   ├── template.py           # Template models
│   │   ├── response.py           # Response wrappers
│   │   └── pagination.py         # Pagination models
│   │
│   └── utils/                    # SDK utilities
│       ├── __init__.py
│       ├── serialization.py      # JSON/YAML serialization
│       ├── validation.py         # Validation helpers
│       └── formatting.py         # Output formatting
│
├── core/                         # Existing core (minimal changes)
├── llm/                          # Existing LLM layer
├── config/                       # Existing config
├── datasets/                     # Existing datasets
├── intelligence/                 # Existing intelligence
├── deployment/                   # Existing deployment
└── __init__.py                   # Update with SDK exports
```

---

## Implementation Phases

### Phase 1: Foundation (Week 1-2)
**Goal:** Core SDK infrastructure and client interface

**Deliverables:**
- SDK directory structure
- Base client classes (sync + async)
- Authentication layer
- Exception hierarchy
- Configuration management
- Base resource class

### Phase 2: Resource Implementation (Week 3-4)
**Goal:** Implement all resource classes

**Deliverables:**
- ScenariosResource (CRUD + from_template)
- SimulationsResource (execute, monitor, results)
- TemplatesResource (list, validate, load)
- IntelligenceResource (gather, analyze)
- DatasetsResource (download, process, analyze)
- DeploymentsResource (deploy, status, integrations)

### Phase 3: Advanced Features (Week 5)
**Goal:** Production-ready features

**Deliverables:**
- Retry logic with exponential backoff
- Rate limiting
- Pagination helpers
- Batch operations
- Webhook support
- Progress callbacks
- Caching layer

### Phase 4: Testing & Documentation (Week 6)
**Goal:** Quality assurance and documentation

**Deliverables:**
- Unit tests (90%+ coverage)
- Integration tests
- E2E tests
- API reference documentation
- User guide with examples
- Migration guide from direct usage
- PyPI packaging

---

## Week-by-Week Breakdown

### Week 1: SDK Foundation Part 1

#### Day 1-2: Client Interface & Authentication

**Files to Create:**
- `src/threatgpt/sdk/__init__.py`
- `src/threatgpt/sdk/client.py`
- `src/threatgpt/sdk/async_client.py`
- `src/threatgpt/sdk/auth.py`
- `src/threatgpt/sdk/config.py`

**Implementation:**

```python
# src/threatgpt/sdk/client.py
"""ThreatGPT SDK - Main Client Interface"""

import logging
from typing import Optional, Dict, Any, Union
from pathlib import Path

from threatgpt.sdk.auth import AuthHandler
from threatgpt.sdk.config import SDKConfig
from threatgpt.sdk.resources import (
    ScenariosResource,
    SimulationsResource,
    TemplatesResource,
    IntelligenceResource,
    DatasetsResource,
    DeploymentsResource,
)
from threatgpt.core.simulator import ThreatSimulator
from threatgpt.llm.manager import LLMManager

logger = logging.getLogger(__name__)


class ThreatGPTClient:
    """Main ThreatGPT SDK client for synchronous operations.
    
    This client provides a unified, resource-based interface to all
    ThreatGPT capabilities including scenario management, simulation
    execution, template operations, and intelligence gathering.
    
    Example:
        Basic usage with API key:
        
        >>> from threatgpt import ThreatGPTClient
        >>> client = ThreatGPTClient(api_key="your-key")
        >>> scenario = client.scenarios.create(
        ...     name="Executive Phishing",
        ...     threat_type="spear_phishing"
        ... )
        >>> result = client.simulations.execute(scenario.id)
        
        Using configuration file:
        
        >>> client = ThreatGPTClient(config_path="~/.threatgpt/config.yaml")
        >>> scenarios = client.scenarios.list(limit=10)
        
        Template-based workflow:
        
        >>> scenario = client.scenarios.from_template(
        ...     "templates/executive_phishing.yaml",
        ...     company_name="Acme Corp"
        ... )
        >>> result = client.simulations.execute(scenario.id)
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        config_path: Optional[Union[str, Path]] = None,
        timeout: int = 60,
        max_retries: int = 3,
        enable_caching: bool = True,
        log_level: str = "INFO",
        **kwargs
    ):
        """Initialize ThreatGPT client.
        
        Args:
            api_key: API key for authentication. If not provided, will look for
                    THREATGPT_API_KEY environment variable.
            base_url: Base URL for API. Defaults to production API.
            config_path: Path to configuration YAML file. If provided, loads
                        settings from file.
            timeout: Request timeout in seconds (default: 60)
            max_retries: Maximum retry attempts for failed requests (default: 3)
            enable_caching: Enable response caching (default: True)
            log_level: Logging level (default: INFO)
            **kwargs: Additional configuration options
        
        Raises:
            AuthenticationError: If API key is invalid or missing
            ConfigurationError: If configuration is invalid
        """
        # Load configuration
        self.config = SDKConfig.from_args(
            api_key=api_key,
            base_url=base_url,
            config_path=config_path,
            timeout=timeout,
            max_retries=max_retries,
            enable_caching=enable_caching,
            **kwargs
        )
        
        # Setup logging
        logging.basicConfig(level=getattr(logging, log_level.upper()))
        self.logger = logger
        
        # Initialize authentication
        self.auth = AuthHandler(api_key=self.config.api_key)
        
        # Initialize core components
        self._llm_manager = None
        self._simulator = None
        
        # Initialize resources
        self.scenarios = ScenariosResource(self)
        self.simulations = SimulationsResource(self)
        self.templates = TemplatesResource(self)
        self.intelligence = IntelligenceResource(self)
        self.datasets = DatasetsResource(self)
        self.deployments = DeploymentsResource(self)
        
        self.logger.info("ThreatGPT SDK initialized successfully")
    
    @property
    def simulator(self) -> ThreatSimulator:
        """Access to core simulator instance.
        
        Returns:
            ThreatSimulator instance
        """
        if self._simulator is None:
            self._simulator = ThreatSimulator(
                llm_provider=self.llm_manager,
                max_stages=self.config.max_stages
            )
        return self._simulator
    
    @property
    def llm_manager(self) -> LLMManager:
        """Access to LLM manager instance.
        
        Returns:
            LLMManager instance
        """
        if self._llm_manager is None:
            self._llm_manager = LLMManager(config=self.config.llm_config)
        return self._llm_manager
    
    def health_check(self) -> Dict[str, Any]:
        """Check API and component health status.
        
        Returns:
            Dict containing health status of all components
            
        Example:
            >>> health = client.health_check()
            >>> print(f"API Status: {health['api']}")
        """
        return {
            "api": "healthy",
            "simulator": "healthy" if self._simulator else "not_initialized",
            "llm_manager": "healthy" if self._llm_manager else "not_initialized",
            "version": self.config.version,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def close(self):
        """Clean up resources and close connections.
        
        Should be called when done using the client to properly
        release resources.
        
        Example:
            >>> client = ThreatGPTClient()
            >>> try:
            ...     # Use client
            ...     pass
            ... finally:
            ...     client.close()
        """
        if self._llm_manager:
            # Cleanup LLM manager resources
            pass
        self.logger.info("ThreatGPT SDK closed")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.close()
    
    def __repr__(self) -> str:
        """String representation."""
        return f"ThreatGPTClient(base_url={self.config.base_url})"
```

```python
# src/threatgpt/sdk/auth.py
"""Authentication handling for ThreatGPT SDK"""

import os
from typing import Optional, Dict
from datetime import datetime, timedelta

from threatgpt.sdk.exceptions import AuthenticationError


class AuthHandler:
    """Handle authentication for SDK requests.
    
    Supports multiple authentication methods:
    - API Key (Bearer token)
    - Environment variables
    - OAuth 2.0 (future)
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize auth handler.
        
        Args:
            api_key: API key for authentication
            
        Raises:
            AuthenticationError: If no valid auth method found
        """
        self.api_key = api_key or self._load_from_env()
        
        if not self.api_key:
            raise AuthenticationError(
                "No API key provided. Set THREATGPT_API_KEY environment "
                "variable or pass api_key parameter."
            )
        
        self._token_cache: Optional[str] = None
        self._token_expiry: Optional[datetime] = None
    
    def _load_from_env(self) -> Optional[str]:
        """Load API key from environment variables."""
        return os.getenv("THREATGPT_API_KEY") or os.getenv("THREAT_GPT_API_KEY")
    
    def get_headers(self) -> Dict[str, str]:
        """Get authentication headers for requests.
        
        Returns:
            Dict of HTTP headers with authentication
        """
        return {
            "Authorization": f"Bearer {self.api_key}",
            "X-ThreatGPT-SDK": "python",
            "X-ThreatGPT-SDK-Version": "0.1.0"
        }
    
    def validate(self) -> bool:
        """Validate authentication credentials.
        
        Returns:
            True if credentials are valid
            
        Raises:
            AuthenticationError: If credentials are invalid
        """
        # TODO: Implement actual validation
        if not self.api_key or len(self.api_key) < 10:
            raise AuthenticationError("Invalid API key format")
        return True
```

#### Day 3-4: Exception Hierarchy & Configuration

**Files to Create:**
- `src/threatgpt/sdk/exceptions.py`
- `src/threatgpt/sdk/config.py` (complete)

```python
# src/threatgpt/sdk/exceptions.py
"""SDK-specific exceptions"""

from typing import Optional, Dict, Any


class ThreatGPTError(Exception):
    """Base exception for all ThreatGPT SDK errors."""
    
    def __init__(self, message: str, **kwargs):
        super().__init__(message)
        self.message = message
        self.details = kwargs


class AuthenticationError(ThreatGPTError):
    """Authentication failed or credentials invalid."""
    pass


class AuthorizationError(ThreatGPTError):
    """User not authorized to perform action."""
    pass


class ValidationError(ThreatGPTError):
    """Input validation failed."""
    
    def __init__(self, message: str, errors: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.errors = errors or {}


class ResourceNotFoundError(ThreatGPTError):
    """Requested resource not found."""
    
    def __init__(self, resource_type: str, resource_id: str):
        message = f"{resource_type} with ID '{resource_id}' not found"
        super().__init__(message)
        self.resource_type = resource_type
        self.resource_id = resource_id


class RateLimitError(ThreatGPTError):
    """API rate limit exceeded."""
    
    def __init__(self, retry_after: Optional[int] = None):
        message = "API rate limit exceeded"
        if retry_after:
            message += f". Retry after {retry_after} seconds"
        super().__init__(message)
        self.retry_after = retry_after


class APIError(ThreatGPTError):
    """General API error."""
    
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class TimeoutError(ThreatGPTError):
    """Request timed out."""
    pass


class ConnectionError(ThreatGPTError):
    """Failed to connect to API."""
    pass


class ConfigurationError(ThreatGPTError):
    """SDK configuration error."""
    pass


class SimulationError(ThreatGPTError):
    """Simulation execution error."""
    pass


class TemplateError(ThreatGPTError):
    """Template loading or validation error."""
    pass


class DatasetError(ThreatGPTError):
    """Dataset operation error."""
    pass


class IntelligenceError(ThreatGPTError):
    """Intelligence gathering error."""
    pass
```

#### Day 5: Base Resource Class & Retry Logic

**Files to Create:**
- `src/threatgpt/sdk/resources/base.py`
- `src/threatgpt/sdk/retry.py`

```python
# src/threatgpt/sdk/resources/base.py
"""Base resource class for all SDK resources"""

import logging
from typing import TYPE_CHECKING, Any, Dict, Optional

if TYPE_CHECKING:
    from threatgpt.sdk.client import ThreatGPTClient

logger = logging.getLogger(__name__)


class BaseResource:
    """Base class for all SDK resource classes.
    
    Provides common functionality like request handling,
    error processing, and authentication.
    """
    
    def __init__(self, client: 'ThreatGPTClient'):
        """Initialize resource.
        
        Args:
            client: Parent ThreatGPT client instance
        """
        self._client = client
        self.logger = logger
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers for requests."""
        return self._client.auth.get_headers()
    
    def _handle_error(self, error: Exception) -> None:
        """Handle and transform errors.
        
        Args:
            error: Exception to handle
            
        Raises:
            Appropriate SDK exception
        """
        # Error transformation logic
        self.logger.error(f"Error in {self.__class__.__name__}: {error}")
        raise
    
    def _validate_id(self, resource_id: str, resource_type: str) -> None:
        """Validate resource ID format.
        
        Args:
            resource_id: ID to validate
            resource_type: Type of resource
            
        Raises:
            ValidationError: If ID is invalid
        """
        from threatgpt.sdk.exceptions import ValidationError
        
        if not resource_id or not isinstance(resource_id, str):
            raise ValidationError(
                f"Invalid {resource_type} ID: must be a non-empty string"
            )
```

```python
# src/threatgpt/sdk/retry.py
"""Retry logic with exponential backoff"""

import time
import logging
from typing import Callable, Type, Tuple, Optional
from functools import wraps

logger = logging.getLogger(__name__)


def retry_with_backoff(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    retry_on: Tuple[Type[Exception], ...] = (Exception,)
):
    """Decorator for retrying functions with exponential backoff.
    
    Args:
        max_retries: Maximum number of retry attempts
        base_delay: Initial delay in seconds
        max_delay: Maximum delay in seconds
        exponential_base: Base for exponential calculation
        retry_on: Tuple of exception types to retry on
    
    Example:
        >>> @retry_with_backoff(max_retries=3)
        >>> def flaky_function():
        ...     # Function that might fail
        ...     pass
    """
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            while retries <= max_retries:
                try:
                    return func(*args, **kwargs)
                except retry_on as e:
                    retries += 1
                    if retries > max_retries:
                        logger.error(f"Max retries ({max_retries}) exceeded for {func.__name__}")
                        raise
                    
                    delay = min(base_delay * (exponential_base ** (retries - 1)), max_delay)
                    logger.warning(
                        f"Attempt {retries}/{max_retries} failed for {func.__name__}. "
                        f"Retrying in {delay:.2f}s. Error: {e}"
                    )
                    time.sleep(delay)
            
            return None  # Should never reach here
        
        return wrapper
    return decorator


async def async_retry_with_backoff(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    retry_on: Tuple[Type[Exception], ...] = (Exception,)
):
    """Async version of retry decorator."""
    import asyncio
    
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            retries = 0
            while retries <= max_retries:
                try:
                    return await func(*args, **kwargs)
                except retry_on as e:
                    retries += 1
                    if retries > max_retries:
                        logger.error(f"Max retries ({max_retries}) exceeded for {func.__name__}")
                        raise
                    
                    delay = min(base_delay * (exponential_base ** (retries - 1)), max_delay)
                    logger.warning(
                        f"Attempt {retries}/{max_retries} failed for {func.__name__}. "
                        f"Retrying in {delay:.2f}s. Error: {e}"
                    )
                    await asyncio.sleep(delay)
            
            return None
        
        return wrapper
    return decorator
```

### Week 2: SDK Foundation Part 2

#### Day 6-7: Async Client & Pagination

**Files to Create:**
- `src/threatgpt/sdk/async_client.py`
- `src/threatgpt/sdk/pagination.py`
- `src/threatgpt/sdk/models/pagination.py`

```python
# src/threatgpt/sdk/async_client.py
"""Async ThreatGPT SDK Client"""

import asyncio
import logging
from typing import Optional, Dict, Any, Union
from pathlib import Path

from threatgpt.sdk.client import ThreatGPTClient

logger = logging.getLogger(__name__)


class AsyncThreatGPTClient:
    """Async ThreatGPT SDK client for async/await operations.
    
    Provides the same interface as ThreatGPTClient but with
    async methods for non-blocking operations.
    
    Example:
        Context manager usage (recommended):
        
        >>> from threatgpt import AsyncThreatGPTClient
        >>> async with AsyncThreatGPTClient(api_key="your-key") as client:
        ...     scenario = await client.scenarios.create(
        ...         name="Executive Phishing",
        ...         threat_type="spear_phishing"
        ...     )
        ...     result = await client.simulations.execute(scenario.id)
        
        Concurrent operations:
        
        >>> async with AsyncThreatGPTClient() as client:
        ...     scenarios = await client.scenarios.list(limit=5)
        ...     results = await asyncio.gather(*[
        ...         client.simulations.execute(s.id)
        ...         for s in scenarios.items
        ...     ])
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        **kwargs
    ):
        """Initialize async ThreatGPT client.
        
        Args:
            api_key: API key for authentication
            **kwargs: Additional configuration options (same as ThreatGPTClient)
        """
        # Similar initialization to sync client
        self._sync_client = ThreatGPTClient(api_key=api_key, **kwargs)
        self.logger = logger
        
        # Initialize async resources
        # TODO: Implement async resource classes
    
    async def __aenter__(self):
        """Context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        await self.close()
    
    async def close(self):
        """Clean up resources and close connections."""
        # Cleanup async resources
        self.logger.info("Async ThreatGPT SDK closed")
    
    async def health_check(self) -> Dict[str, Any]:
        """Async health check."""
        # Implement async health check
        pass
```

```python
# src/threatgpt/sdk/models/pagination.py
"""Pagination models"""

from typing import Generic, TypeVar, List, Optional
from pydantic import BaseModel, Field

T = TypeVar('T')


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response wrapper.
    
    Example:
        >>> response = client.scenarios.list(limit=10)
        >>> print(f"Total: {response.total}")
        >>> for scenario in response.items:
        ...     print(scenario.name)
        >>> 
        >>> # Get next page
        >>> if response.has_next:
        ...     next_page = response.next()
    """
    
    items: List[T] = Field(description="List of items in current page")
    total: int = Field(description="Total number of items")
    page: int = Field(default=1, description="Current page number")
    page_size: int = Field(default=20, description="Items per page")
    has_next: bool = Field(default=False, description="Whether there's a next page")
    has_prev: bool = Field(default=False, description="Whether there's a previous page")
    
    @property
    def total_pages(self) -> int:
        """Calculate total number of pages."""
        return (self.total + self.page_size - 1) // self.page_size
    
    class Config:
        arbitrary_types_allowed = True
```

#### Day 8-10: SDK Models

**Files to Create:**
- `src/threatgpt/sdk/models/__init__.py`
- `src/threatgpt/sdk/models/scenario.py`
- `src/threatgpt/sdk/models/simulation.py`
- `src/threatgpt/sdk/models/template.py`
- `src/threatgpt/sdk/models/response.py`

### Week 3-4: Resource Implementation

#### Week 3: Core Resources

**Day 11-13: Scenarios Resource**

```python
# src/threatgpt/sdk/resources/scenarios.py
"""Scenario management resource"""

from typing import Optional, List, Dict, Any, Union
from pathlib import Path

from threatgpt.sdk.resources.base import BaseResource
from threatgpt.sdk.models.scenario import Scenario, ScenarioCreate, ScenarioUpdate
from threatgpt.sdk.models.pagination import PaginatedResponse
from threatgpt.sdk.exceptions import ValidationError, ResourceNotFoundError
from threatgpt.core.models import ThreatType, ThreatScenario


class ScenariosResource(BaseResource):
    """Manage threat scenarios.
    
    Provides methods for creating, retrieving, updating, and deleting
    threat scenarios, as well as creating scenarios from templates.
    """
    
    def create(
        self,
        name: str,
        threat_type: Union[str, ThreatType],
        description: Optional[str] = None,
        difficulty_level: int = 5,
        **kwargs
    ) -> Scenario:
        """Create a new threat scenario.
        
        Args:
            name: Scenario name
            threat_type: Type of threat (phishing, malware, etc.)
            description: Optional description
            difficulty_level: Difficulty from 1-10
            **kwargs: Additional scenario parameters
            
        Returns:
            Created Scenario object
            
        Raises:
            ValidationError: If parameters are invalid
            APIError: If creation fails
            
        Example:
            >>> scenario = client.scenarios.create(
            ...     name="Executive Phishing Campaign",
            ...     threat_type=ThreatType.SPEAR_PHISHING,
            ...     description="Target C-level executives",
            ...     difficulty_level=8,
            ...     target_profile={
            ...         "role": "CEO",
            ...         "department": "executive"
            ...     }
            ... )
            >>> print(f"Created scenario: {scenario.id}")
        """
        # Validate inputs
        if not name:
            raise ValidationError("Scenario name is required")
        
        if difficulty_level < 1 or difficulty_level > 10:
            raise ValidationError("Difficulty level must be between 1 and 10")
        
        # Create scenario using core simulator
        scenario_data = ThreatScenario(
            name=name,
            threat_type=threat_type,
            description=description or "",
            metadata=kwargs
        )
        
        # TODO: Store in database if API mode
        # For now, return wrapped scenario
        return Scenario.from_threat_scenario(scenario_data)
    
    def get(self, scenario_id: str) -> Scenario:
        """Retrieve a scenario by ID.
        
        Args:
            scenario_id: Scenario ID
            
        Returns:
            Scenario object
            
        Raises:
            ResourceNotFoundError: If scenario not found
            
        Example:
            >>> scenario = client.scenarios.get("scenario-123")
            >>> print(scenario.name)
        """
        self._validate_id(scenario_id, "Scenario")
        
        # TODO: Implement retrieval logic
        raise ResourceNotFoundError("Scenario", scenario_id)
    
    def list(
        self,
        limit: int = 20,
        offset: int = 0,
        threat_type: Optional[ThreatType] = None,
        difficulty_min: Optional[int] = None,
        difficulty_max: Optional[int] = None,
        **filters
    ) -> PaginatedResponse[Scenario]:
        """List scenarios with pagination and filtering.
        
        Args:
            limit: Maximum items per page (default: 20)
            offset: Number of items to skip (default: 0)
            threat_type: Filter by threat type
            difficulty_min: Minimum difficulty level
            difficulty_max: Maximum difficulty level
            **filters: Additional filters
            
        Returns:
            Paginated list of scenarios
            
        Example:
            >>> scenarios = client.scenarios.list(
            ...     limit=10,
            ...     threat_type=ThreatType.PHISHING,
            ...     difficulty_min=5
            ... )
            >>> for scenario in scenarios.items:
            ...     print(f"{scenario.name} (difficulty: {scenario.difficulty})")
        """
        # TODO: Implement list logic
        pass
    
    def update(
        self,
        scenario_id: str,
        **updates
    ) -> Scenario:
        """Update a scenario.
        
        Args:
            scenario_id: Scenario ID
            **updates: Fields to update
            
        Returns:
            Updated Scenario object
            
        Example:
            >>> scenario = client.scenarios.update(
            ...     "scenario-123",
            ...     name="Updated Name",
            ...     difficulty_level=9
            ... )
        """
        self._validate_id(scenario_id, "Scenario")
        # TODO: Implement update logic
        pass
    
    def delete(self, scenario_id: str) -> bool:
        """Delete a scenario.
        
        Args:
            scenario_id: Scenario ID
            
        Returns:
            True if deleted successfully
            
        Example:
            >>> client.scenarios.delete("scenario-123")
            True
        """
        self._validate_id(scenario_id, "Scenario")
        # TODO: Implement delete logic
        pass
    
    def from_template(
        self,
        template_path: Union[str, Path],
        **variables
    ) -> Scenario:
        """Create scenario from YAML template.
        
        Args:
            template_path: Path to YAML template file
            **variables: Template variables to substitute
            
        Returns:
            Created Scenario object
            
        Raises:
            TemplateError: If template loading fails
            ValidationError: If template is invalid
            
        Example:
            >>> scenario = client.scenarios.from_template(
            ...     "templates/executive_phishing.yaml",
            ...     company_name="Acme Corp",
            ...     target_email="ceo@acme.com",
            ...     urgency_level=8
            ... )
            >>> print(f"Created from template: {scenario.name}")
        """
        from threatgpt.config.yaml_loader import YAMLConfigLoader
        from threatgpt.sdk.exceptions import TemplateError
        
        try:
            loader = YAMLConfigLoader()
            template_config = loader.load_and_validate_scenario(Path(template_path))
            
            # Apply variables
            # TODO: Implement variable substitution
            
            # Convert to SDK scenario model
            scenario = Scenario.from_config(template_config)
            return scenario
            
        except Exception as e:
            raise TemplateError(f"Failed to load template: {e}")
    
    def validate(self, scenario: Union[Scenario, Dict[str, Any]]) -> bool:
        """Validate a scenario configuration.
        
        Args:
            scenario: Scenario object or dict to validate
            
        Returns:
            True if valid
            
        Raises:
            ValidationError: If validation fails with details
            
        Example:
            >>> scenario_data = {
            ...     "name": "Test Scenario",
            ...     "threat_type": "phishing"
            ... }
            >>> client.scenarios.validate(scenario_data)
            True
        """
        # TODO: Implement validation logic
        pass
```

**Day 14-15: Simulations Resource**

```python
# src/threatgpt/sdk/resources/simulations.py
"""Simulation execution and monitoring resource"""

from typing import Optional, List, Callable, Dict, Any
from datetime import datetime

from threatgpt.sdk.resources.base import BaseResource
from threatgpt.sdk.models.simulation import SimulationResult, SimulationStatus
from threatgpt.sdk.exceptions import SimulationError
from threatgpt.core.models import ThreatScenario


class SimulationsResource(BaseResource):
    """Execute and monitor threat simulations.
    
    Provides methods for executing simulations, monitoring progress,
    and retrieving results.
    """
    
    def execute(
        self,
        scenario_id: str,
        max_stages: Optional[int] = None,
        enable_adaptation: bool = True,
        callbacks: Optional[Dict[str, Callable]] = None,
        **options
    ) -> SimulationResult:
        """Execute a threat simulation.
        
        Args:
            scenario_id: ID of scenario to simulate
            max_stages: Maximum simulation stages
            enable_adaptation: Enable adaptive behavior
            callbacks: Optional callbacks for events
            **options: Additional simulation options
            
        Returns:
            SimulationResult with execution details
            
        Raises:
            ResourceNotFoundError: If scenario not found
            SimulationError: If execution fails
            
        Example:
            >>> result = client.simulations.execute(
            ...     "scenario-123",
            ...     max_stages=5,
            ...     callbacks={
            ...         "on_stage_complete": lambda s: print(f"Stage {s.type} done"),
            ...         "on_complete": lambda r: print("Simulation complete")
            ...     }
            ... )
            >>> print(f"Status: {result.status}")
        """
        # Get scenario
        scenario = self._client.scenarios.get(scenario_id)
        
        # Execute using core simulator
        try:
            # TODO: Implement async execution if needed
            import asyncio
            result = asyncio.run(
                self._client.simulator.execute_simulation(scenario.to_threat_scenario())
            )
            
            return SimulationResult.from_core_result(result)
        except Exception as e:
            raise SimulationError(f"Simulation execution failed: {e}")
    
    def get_result(self, simulation_id: str) -> SimulationResult:
        """Get simulation result by ID."""
        # TODO: Implement
        pass
    
    def list_results(
        self,
        scenario_id: Optional[str] = None,
        status: Optional[SimulationStatus] = None,
        **filters
    ) -> List[SimulationResult]:
        """List simulation results with filtering."""
        # TODO: Implement
        pass
    
    def monitor(
        self,
        simulation_id: str,
        callback: Callable[[Dict[str, Any]], None]
    ):
        """Monitor simulation progress in real-time."""
        # TODO: Implement
        pass
```

**Day 16-17: Templates Resource**

#### Week 4: Additional Resources

**Day 18-20: Intelligence, Datasets, Deployments Resources**

### Week 5: Advanced Features

**Day 21-23: Batch Operations, Caching, Rate Limiting**

**Day 24-25: Webhook Support, Progress Callbacks**

### Week 6: Testing & Documentation

**Day 26-28: Testing Suite**

**Day 29-30: Documentation & PyPI Release**

---

## Testing Strategy

### Unit Tests (Target: 90% coverage)

```python
# tests/sdk/test_client.py
"""Unit tests for ThreatGPT SDK client"""

import pytest
from threatgpt import ThreatGPTClient
from threatgpt.sdk.exceptions import AuthenticationError


def test_client_initialization():
    """Test client initializes correctly."""
    client = ThreatGPTClient(api_key="test-key")
    assert client is not None
    assert client.config.api_key == "test-key"


def test_client_no_api_key():
    """Test client raises error without API key."""
    with pytest.raises(AuthenticationError):
        ThreatGPTClient()


def test_client_context_manager():
    """Test client works as context manager."""
    with ThreatGPTClient(api_key="test-key") as client:
        assert client is not None


def test_health_check():
    """Test health check returns status."""
    client = ThreatGPTClient(api_key="test-key")
    health = client.health_check()
    assert "api" in health
    assert health["api"] == "healthy"


# tests/sdk/resources/test_scenarios.py
def test_create_scenario(client):
    """Test scenario creation."""
    scenario = client.scenarios.create(
        name="Test Scenario",
        threat_type="phishing"
    )
    assert scenario.name == "Test Scenario"


def test_scenario_from_template(client, tmp_path):
    """Test creating scenario from template."""
    # Create temp template
    template_path = tmp_path / "test_template.yaml"
    template_path.write_text("""
metadata:
  name: Test Template
threat_type: phishing
""")
    
    scenario = client.scenarios.from_template(str(template_path))
    assert scenario.name == "Test Template"
```

### Integration Tests

```python
# tests/integration/test_full_workflow.py
"""Integration tests for complete workflows"""

import pytest
from threatgpt import ThreatGPTClient


@pytest.mark.integration
def test_complete_simulation_workflow(client):
    """Test complete scenario creation to simulation."""
    # Create scenario
    scenario = client.scenarios.create(
        name="Integration Test",
        threat_type="phishing"
    )
    
    # Execute simulation
    result = client.simulations.execute(scenario.id)
    
    # Verify results
    assert result.status in ["completed", "running"]
```

---

## Documentation Plan

### 1. API Reference (Auto-generated)

```bash
# Generate API docs with Sphinx
cd docs
sphinx-apidoc -o api ../src/threatgpt/sdk
make html
```

### 2. User Guide

Create comprehensive guides:
- Getting Started
- Authentication
- Working with Scenarios
- Executing Simulations
- Template Usage
- Advanced Features
- Error Handling
- Best Practices

### 3. Code Examples

Repository: `examples/sdk/`

```
examples/sdk/
├── quickstart.py
├── async_example.py
├── template_example.py
├── batch_operations.py
├── intelligence_integration.py
├── error_handling.py
└── advanced_usage.py
```

---

## Success Criteria

### Functional Requirements ✅
- [ ] ThreatGPTClient and AsyncThreatGPTClient implemented
- [ ] All 6 resource classes complete
- [ ] Authentication working with API key and env vars
- [ ] Exception hierarchy complete
- [ ] Retry logic with exponential backoff
- [ ] Pagination support
- [ ] Template loading from YAML

### Quality Requirements ✅
- [ ] 90%+ test coverage
- [ ] All tests passing
- [ ] Type hints on all public APIs
- [ ] Docstrings on all public methods
- [ ] No critical security issues (Bandit)
- [ ] Code formatted (Black, isort)

### Documentation Requirements ✅
- [ ] API reference documentation
- [ ] User guide with examples
- [ ] Migration guide
- [ ] Changelog
- [ ] README with quick start

### Distribution Requirements ✅
- [ ] PyPI package published
- [ ] Version pinned dependencies
- [ ] Installation tested on Python 3.11+
- [ ] Works on Windows, macOS, Linux

---

## Timeline Summary

| Week | Focus | Deliverables |
|------|-------|--------------|
| **Week 1** | Foundation | Client, Auth, Exceptions, Base Classes |
| **Week 2** | Foundation | Async Client, Pagination, Models |
| **Week 3** | Resources | Scenarios, Simulations, Templates |
| **Week 4** | Resources | Intelligence, Datasets, Deployments |
| **Week 5** | Advanced | Batch Ops, Caching, Webhooks |
| **Week 6** | Quality | Tests, Docs, PyPI Release |

**Total Duration:** 6 weeks  
**Target Completion:** Mid-February 2026  
**Team Size:** 1-2 developers

---

## Next Steps

1. ✅ Review and approve implementation plan
2. ✅ Set up development environment
3. ✅ Create GitHub project board for tracking
4. ✅ Begin Week 1 implementation
5. ✅ Schedule weekly progress reviews

---

**Document Version:** 1.0.0  
**Last Updated:** December 9, 2025  
**Maintained By:** ThreatGPT Team
