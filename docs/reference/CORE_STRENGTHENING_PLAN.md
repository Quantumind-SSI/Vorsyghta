# ThreatGPT Core Strengthening Plan

**Version:** 1.0.0  
**Date:** December 9, 2025  
**Timeline:** 6 Weeks (Pre-SDK Implementation)  
**Status:** Implementation Ready

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Current State Analysis](#current-state-analysis)
3. [Critical Areas for Strengthening](#critical-areas-for-strengthening)
4. [Week-by-Week Implementation Plan](#week-by-week-implementation-plan)
5. [Technical Debt Resolution](#technical-debt-resolution)
6. [Quality Assurance Strategy](#quality-assurance-strategy)
7. [Performance Optimization](#performance-optimization)
8. [Success Criteria](#success-criteria)

---

## Executive Summary

This plan outlines a **6-week intensive effort** to strengthen the core foundation of ThreatGPT before SDK implementation. The focus is on eliminating technical debt, improving code quality, enhancing test coverage, optimizing performance, and solidifying architectural patterns.

### Primary Goals

1. **Achieve 85%+ Test Coverage** across all core modules
2. **Eliminate Critical Technical Debt** (TODOs, FIXMEs, code duplication)
3. **Optimize Performance** (reduce latency by 30%, improve throughput)
4. **Harden Security** (penetration testing, vulnerability scanning)
5. **Improve Code Quality** (type hints, documentation, linting)
6. **Refactor Design Patterns** (consistent architecture across modules)

### Expected Outcomes

- **Robust Core**: Production-ready, battle-tested foundation
- **High Quality**: 85%+ test coverage, zero critical issues
- **Better Performance**: 30% faster execution, reduced memory footprint
- **Clean Architecture**: Consistent patterns, minimal duplication
- **SDK Ready**: Stable core for SDK implementation

---

## Current State Analysis

### ✅ Strengths

**Architecture:**
- Well-structured module organization
- Clear separation of concerns (core, llm, datasets, deployment)
- Abstract base classes for extensibility
- Async/await patterns throughout

**LLM Integration:**
- Support for 7 different providers
- Connection pooling implemented
- Rate limiting and retry logic
- Fallback mechanisms

**Configuration:**
- YAML-based configuration
- Pydantic validation
- Environment variable support

**Datasets:**
- Multiple dataset processors
- Base class eliminates duplication
- Async download with progress tracking

### ⚠️ Weaknesses

**Testing:**
- ❌ **Minimal test coverage** (~15% estimated)
- ❌ Only 1 test file found (`tests/unit/test_cli.py`)
- ❌ No integration tests
- ❌ No load/performance tests
- ❌ No fixture infrastructure

**Error Handling:**
- ⚠️ Inconsistent exception usage
- ⚠️ Some bare `except` blocks
- ⚠️ Limited context in errors
- ⚠️ No structured error logging

**Code Quality:**
- ⚠️ Missing type hints in some areas
- ⚠️ Incomplete docstrings
- ⚠️ Some complex functions need refactoring
- ⚠️ No automated code quality checks

**Performance:**
- ⚠️ No caching layer
- ⚠️ Potential N+1 query patterns
- ⚠️ No request batching
- ⚠️ Limited connection pooling optimization

**Security:**
- ⚠️ No security scanning in CI/CD
- ⚠️ API key handling needs review
- ⚠️ Input validation gaps
- ⚠️ No rate limiting on API endpoints

**Documentation:**
- ⚠️ Limited inline documentation
- ⚠️ Some complex algorithms lack comments
- ⚠️ Missing architecture diagrams
- ⚠️ No troubleshooting guides

---

## Critical Areas for Strengthening

### 1. Testing Infrastructure (Priority: CRITICAL)

**Current State:** ~15% coverage, minimal test suite  
**Target State:** 85%+ coverage, comprehensive test suite

**Gaps:**
- No test fixtures or mocks
- Missing unit tests for core modules
- No integration tests
- No performance benchmarks
- No CI/CD test automation

### 2. Error Handling & Logging (Priority: HIGH)

**Current State:** Basic exception hierarchy, inconsistent usage  
**Target State:** Comprehensive error handling, structured logging

**Gaps:**
- Inconsistent exception types
- Limited error context
- No centralized error tracking
- Insufficient logging in critical paths

### 3. Performance & Scalability (Priority: HIGH)

**Current State:** Functional but not optimized  
**Target State:** Optimized for production workloads

**Gaps:**
- No caching layer
- Suboptimal database queries
- Limited connection pooling
- No request batching

### 4. Security Hardening (Priority: HIGH)

**Current State:** Basic security measures  
**Target State:** Production-grade security

**Gaps:**
- No automated security scanning
- API key exposure risks
- Missing input validation
- No penetration testing

### 5. Code Quality & Maintainability (Priority: MEDIUM)

**Current State:** Good structure, needs polish  
**Target State:** Exemplary code quality

**Gaps:**
- Incomplete type hints
- Missing docstrings
- Complex functions need refactoring
- No automated linting

### 6. Documentation (Priority: MEDIUM)

**Current State:** Basic documentation exists  
**Target State:** Comprehensive documentation

**Gaps:**
- Limited API documentation
- Missing architecture diagrams
- No troubleshooting guides
- Incomplete developer docs

---

## Week-by-Week Implementation Plan

### Week 1: Testing Foundation & Infrastructure

**Theme:** Build robust testing infrastructure

#### Day 1-2: Testing Framework Setup

**Objectives:**
- Set up pytest with all plugins
- Create test directory structure
- Implement test fixtures
- Configure coverage reporting

**Tasks:**

1. **Install Testing Dependencies**
```bash
pip install pytest pytest-asyncio pytest-cov pytest-mock pytest-xdist faker factory-boy
```

2. **Create Test Structure**
```
tests/
├── conftest.py                 # Global fixtures
├── fixtures/
│   ├── __init__.py
│   ├── llm_fixtures.py         # Mock LLM responses
│   ├── scenario_fixtures.py    # Test scenarios
│   ├── config_fixtures.py      # Test configurations
│   └── database_fixtures.py    # Mock DB connections
├── unit/
│   ├── test_core/
│   │   ├── test_simulator.py
│   │   ├── test_models.py
│   │   ├── test_exceptions.py
│   │   └── test_template_manager.py
│   ├── test_llm/
│   │   ├── test_manager.py
│   │   ├── test_base_provider.py
│   │   ├── test_openai_provider.py
│   │   ├── test_anthropic_provider.py
│   │   └── test_enhanced_prompts.py
│   ├── test_config/
│   │   ├── test_loader.py
│   │   ├── test_validator.py
│   │   └── test_models.py
│   └── test_datasets/
│       ├── test_base_processor.py
│       └── test_manager.py
├── integration/
│   ├── test_simulation_workflow.py
│   ├── test_llm_integration.py
│   ├── test_dataset_processing.py
│   └── test_api_endpoints.py
├── performance/
│   ├── test_load.py
│   ├── test_concurrent_simulations.py
│   └── test_memory_usage.py
└── e2e/
    ├── test_full_simulation.py
    └── test_cli_workflows.py
```

3. **Create Global Fixtures** (`tests/conftest.py`)
```python
"""Global test fixtures for ThreatGPT test suite."""

import pytest
import asyncio
from pathlib import Path
from typing import Dict, Any
from unittest.mock import Mock, AsyncMock

from threatgpt.core.simulator import ThreatSimulator
from threatgpt.core.models import ThreatScenario, ThreatType
from threatgpt.llm.manager import LLMManager
from threatgpt.llm.base import BaseLLMProvider, LLMResponse
from threatgpt.config.loader import ThreatGPTConfig


# ==========================================
# Pytest Configuration
# ==========================================

def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "slow: Slow tests")
    config.addinivalue_line("markers", "performance: Performance tests")
    config.addinivalue_line("markers", "requires_api_key: Tests requiring API keys")


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# ==========================================
# Mock LLM Provider
# ==========================================

class MockLLMProvider(BaseLLMProvider):
    """Mock LLM provider for testing."""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config or {})
        self.call_count = 0
        self.responses = []
    
    async def generate_content(
        self, 
        prompt: str, 
        max_tokens: int = 1000,
        temperature: float = 0.7,
        **kwargs
    ) -> LLMResponse:
        """Generate mock response."""
        self.call_count += 1
        
        content = f"Mock LLM response #{self.call_count} for prompt: {prompt[:50]}..."
        
        response = LLMResponse(
            content=content,
            provider="mock",
            model="mock-model-v1"
        )
        response.is_real_ai = False
        
        self.responses.append(response)
        return response
    
    def is_available(self) -> bool:
        return True


@pytest.fixture
def mock_llm_provider():
    """Provide mock LLM provider."""
    return MockLLMProvider()


@pytest.fixture
def mock_llm_manager(mock_llm_provider):
    """Provide mock LLM manager."""
    manager = LLMManager(provider=mock_llm_provider)
    return manager


# ==========================================
# Test Scenarios
# ==========================================

@pytest.fixture
def simple_threat_scenario():
    """Provide simple threat scenario for testing."""
    return ThreatScenario(
        name="Test Phishing Scenario",
        threat_type=ThreatType.PHISHING,
        description="Basic phishing test scenario",
        severity="medium",
        target_systems=["email"],
        attack_vectors=["social_engineering"]
    )


@pytest.fixture
def complex_threat_scenario():
    """Provide complex threat scenario for testing."""
    return ThreatScenario(
        name="Advanced APT Scenario",
        threat_type=ThreatType.APT,
        description="Multi-stage advanced persistent threat",
        severity="critical",
        target_systems=["network", "endpoints", "data"],
        attack_vectors=["phishing", "lateral_movement", "data_exfiltration"],
        metadata={
            "mitre_attack": ["T1566.001", "T1078", "T1041"],
            "difficulty": 9,
            "estimated_duration": 120
        }
    )


# ==========================================
# Test Configuration
# ==========================================

@pytest.fixture
def test_config():
    """Provide test configuration."""
    return ThreatGPTConfig(
        llm={
            "default_provider": "mock",
            "mock": {
                "api_key": "test-key",
                "model": "mock-model-v1"
            }
        }
    )


@pytest.fixture
def test_config_file(tmp_path):
    """Create temporary config file for testing."""
    config_path = tmp_path / "test_config.yaml"
    config_content = """
llm:
  default_provider: "mock"
  mock:
    api_key: "test-key"
    model: "mock-model-v1"

simulation:
  max_stages: 5
  enable_safety_checks: true

logging:
  level: "DEBUG"
  enable_console_logging: true
"""
    config_path.write_text(config_content)
    return config_path


# ==========================================
# Simulator Fixtures
# ==========================================

@pytest.fixture
def threat_simulator(mock_llm_manager):
    """Provide threat simulator with mock LLM."""
    return ThreatSimulator(
        llm_provider=mock_llm_manager,
        max_stages=5
    )


# ==========================================
# Template Fixtures
# ==========================================

@pytest.fixture
def sample_template_yaml(tmp_path):
    """Create sample YAML template for testing."""
    template_path = tmp_path / "test_template.yaml"
    template_content = """
metadata:
  name: "Test Executive Phishing"
  description: "Test template for executive phishing"
  version: "1.0.0"
  author: "Test Suite"

threat_type: spear_phishing
delivery_vector: email
difficulty_level: 7
estimated_duration: 30

target_profile:
  role: "CEO"
  seniority: "c_level"
  department: "executive"
  technical_level: "moderate"

behavioral_pattern:
  mitre_attack_techniques:
    - "T1566.001"
  psychological_triggers:
    - "authority"
    - "urgency"
"""
    template_path.write_text(template_content)
    return template_path


# ==========================================
# Database Fixtures
# ==========================================

@pytest.fixture
def mock_database():
    """Provide mock database connection."""
    db = Mock()
    db.execute = AsyncMock(return_value=[])
    db.fetch = AsyncMock(return_value=[])
    db.fetchrow = AsyncMock(return_value=None)
    return db


# ==========================================
# Cleanup Fixtures
# ==========================================

@pytest.fixture(autouse=True)
def cleanup_test_files(tmp_path):
    """Automatically cleanup test files after each test."""
    yield
    # Cleanup code here if needed
```

4. **Configure pytest** (`pytest.ini`)
```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
asyncio_mode = auto

# Coverage
addopts = 
    --cov=src/threatgpt
    --cov-report=html
    --cov-report=term-missing
    --cov-report=xml
    --cov-branch
    --verbose
    --strict-markers
    --tb=short
    --maxfail=1

# Markers
markers =
    unit: Unit tests
    integration: Integration tests
    slow: Slow tests (>1s)
    performance: Performance benchmark tests
    requires_api_key: Tests requiring real API keys

# Warnings
filterwarnings =
    error
    ignore::DeprecationWarning
    ignore::PendingDeprecationWarning

# Timeout
timeout = 300

# Parallel execution
# Run with: pytest -n auto
# addopts = -n auto
```

**Deliverables:**
- ✅ Complete test infrastructure
- ✅ Global fixtures for mocking
- ✅ pytest configuration
- ✅ Coverage reporting setup

#### Day 3-4: Core Module Unit Tests

**Objectives:**
- Write comprehensive unit tests for core modules
- Achieve 80%+ coverage for `core/` package

**Test Files to Create:**

1. **`tests/unit/test_core/test_simulator.py`**
```python
"""Unit tests for ThreatSimulator."""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime

from threatgpt.core.simulator import ThreatSimulator
from threatgpt.core.models import ThreatScenario, SimulationResult, SimulationStatus
from threatgpt.core.exceptions import SimulationError


@pytest.mark.unit
class TestThreatSimulator:
    """Test suite for ThreatSimulator class."""
    
    def test_simulator_initialization(self, mock_llm_manager):
        """Test simulator initializes correctly."""
        simulator = ThreatSimulator(llm_provider=mock_llm_manager, max_stages=5)
        
        assert simulator.llm_provider is not None
        assert simulator.max_stages == 5
        assert isinstance(simulator._active_simulations, dict)
    
    def test_simulator_initialization_default_llm(self):
        """Test simulator creates default LLM manager if none provided."""
        simulator = ThreatSimulator()
        
        assert simulator.llm_provider is not None
        assert simulator.max_stages == 10  # Default value
    
    @pytest.mark.asyncio
    async def test_execute_simulation_success(
        self,
        threat_simulator,
        simple_threat_scenario
    ):
        """Test successful simulation execution."""
        result = await threat_simulator.execute_simulation(simple_threat_scenario)
        
        assert isinstance(result, SimulationResult)
        assert result.status == SimulationStatus.COMPLETED
        assert result.scenario_id == simple_threat_scenario.scenario_id
        assert result.start_time is not None
        assert result.end_time is not None
        assert len(result.stages) > 0
    
    @pytest.mark.asyncio
    async def test_execute_simulation_invalid_scenario(self, threat_simulator):
        """Test simulation fails with invalid scenario."""
        invalid_scenario = ThreatScenario(
            name="",  # Invalid empty name
            threat_type="phishing"
        )
        
        with pytest.raises(ValueError, match="Scenario must have a valid name"):
            await threat_simulator.execute_simulation(invalid_scenario)
    
    @pytest.mark.asyncio
    async def test_execute_simulation_tracks_active(
        self,
        threat_simulator,
        simple_threat_scenario
    ):
        """Test simulation is tracked in active simulations."""
        # Patch to pause execution
        with patch.object(threat_simulator, '_execute_stages', AsyncMock()):
            result = await threat_simulator.execute_simulation(simple_threat_scenario)
            
            # Should be removed from active after completion
            assert result.result_id not in threat_simulator._active_simulations
    
    @pytest.mark.asyncio
    async def test_execute_simulation_handles_errors(
        self,
        threat_simulator,
        simple_threat_scenario
    ):
        """Test simulation handles errors gracefully."""
        # Force an error during execution
        with patch.object(
            threat_simulator,
            '_execute_stages',
            side_effect=RuntimeError("Test error")
        ):
            result = await threat_simulator.execute_simulation(simple_threat_scenario)
            
            assert result.status == SimulationStatus.FAILED
            assert result.error_message == "Test error"
    
    @pytest.mark.asyncio
    async def test_generate_stage_content(
        self,
        threat_simulator,
        simple_threat_scenario
    ):
        """Test stage content generation."""
        content = await threat_simulator._generate_stage_content(
            simple_threat_scenario,
            "reconnaissance",
            "Initial reconnaissance"
        )
        
        assert isinstance(content, str)
        assert len(content) > 0
    
    def test_simulator_max_stages_limit(self, mock_llm_manager):
        """Test max_stages parameter limits execution."""
        simulator = ThreatSimulator(
            llm_provider=mock_llm_manager,
            max_stages=3
        )
        
        assert simulator.max_stages == 3
```

2. **`tests/unit/test_core/test_models.py`**
```python
"""Unit tests for core data models."""

import pytest
from datetime import datetime
from uuid import UUID

from threatgpt.core.models import (
    ThreatScenario,
    SimulationResult,
    SimulationStage,
    SimulationStatus,
    ThreatType
)


@pytest.mark.unit
class TestThreatScenario:
    """Test suite for ThreatScenario model."""
    
    def test_scenario_creation(self):
        """Test creating a threat scenario."""
        scenario = ThreatScenario(
            name="Test Scenario",
            threat_type=ThreatType.PHISHING,
            description="Test description"
        )
        
        assert scenario.name == "Test Scenario"
        assert scenario.threat_type == ThreatType.PHISHING
        assert scenario.description == "Test description"
        assert isinstance(UUID(scenario.scenario_id), UUID)
        assert isinstance(scenario.created_at, datetime)
    
    def test_scenario_validation_empty_name(self):
        """Test scenario validates name."""
        scenario = ThreatScenario(
            name="  ",  # Whitespace only
            threat_type="phishing"
        )
        
        with pytest.raises(ValueError, match="Scenario name cannot be empty"):
            scenario.__post_init__()
    
    def test_scenario_default_values(self):
        """Test scenario default values."""
        scenario = ThreatScenario(
            name="Test",
            threat_type="phishing"
        )
        
        assert scenario.severity == "medium"
        assert scenario.target_systems == []
        assert scenario.attack_vectors == []
        assert isinstance(scenario.metadata, dict)


@pytest.mark.unit
class TestSimulationResult:
    """Test suite for SimulationResult model."""
    
    def test_result_creation(self):
        """Test creating simulation result."""
        result = SimulationResult(
            status=SimulationStatus.RUNNING,
            scenario_id="test-scenario-id"
        )
        
        assert result.status == SimulationStatus.RUNNING
        assert result.scenario_id == "test-scenario-id"
        assert isinstance(UUID(result.result_id), UUID)
        assert isinstance(result.start_time, datetime)
    
    def test_add_stage(self):
        """Test adding stages to result."""
        result = SimulationResult(
            status=SimulationStatus.RUNNING,
            scenario_id="test"
        )
        
        stage = SimulationStage(
            stage_type="reconnaissance",
            content="Test content",
            timestamp=datetime.utcnow(),
            success=True
        )
        
        result.add_stage(stage)
        
        assert len(result.stages) == 1
        assert result.stages[0] == stage
    
    def test_mark_completed_success(self):
        """Test marking result as completed successfully."""
        result = SimulationResult(
            status=SimulationStatus.RUNNING,
            scenario_id="test"
        )
        
        result.mark_completed(success=True)
        
        assert result.status == SimulationStatus.COMPLETED
        assert result.end_time is not None
        assert result.error_message is None
    
    def test_mark_completed_failure(self):
        """Test marking result as failed."""
        result = SimulationResult(
            status=SimulationStatus.RUNNING,
            scenario_id="test"
        )
        
        result.mark_completed(success=False, error_message="Test error")
        
        assert result.status == SimulationStatus.FAILED
        assert result.end_time is not None
        assert result.error_message == "Test error"
```

**Deliverables:**
- ✅ 20+ unit tests for core modules
- ✅ 80%+ coverage for core package
- ✅ All edge cases covered

#### Day 5: LLM Module Unit Tests

**Objectives:**
- Test LLM manager and providers
- Mock external API calls
- Test connection pooling and retry logic

**Test Files:**
- `tests/unit/test_llm/test_manager.py`
- `tests/unit/test_llm/test_base_provider.py`
- `tests/unit/test_llm/test_enhanced_prompts.py`

**Key Test Scenarios:**
- Provider initialization
- Content generation
- Error handling
- Retry logic
- Fallback providers
- Connection pooling

**Deliverables:**
- ✅ 25+ unit tests for LLM modules
- ✅ 75%+ coverage for llm package

---

### Week 2: Integration Testing & Error Handling

**Theme:** Integration tests and robust error handling

#### Day 6-7: Integration Tests

**Objectives:**
- Create end-to-end integration tests
- Test module interactions
- Validate complete workflows

**Test Files to Create:**

1. **`tests/integration/test_simulation_workflow.py`**
```python
"""Integration tests for complete simulation workflows."""

import pytest
from pathlib import Path

from threatgpt import ThreatGPTClient
from threatgpt.core.simulator import ThreatSimulator
from threatgpt.core.models import ThreatType, SimulationStatus


@pytest.mark.integration
class TestSimulationWorkflow:
    """Integration tests for simulation workflows."""
    
    @pytest.mark.asyncio
    async def test_full_simulation_from_scenario(
        self,
        threat_simulator,
        complex_threat_scenario
    ):
        """Test complete simulation workflow from scenario."""
        result = await threat_simulator.execute_simulation(complex_threat_scenario)
        
        # Verify complete execution
        assert result.status in [SimulationStatus.COMPLETED, SimulationStatus.FAILED]
        assert len(result.stages) > 0
        assert result.end_time is not None
        
        # Verify stages executed in order
        stage_types = [stage.stage_type for stage in result.stages]
        assert "reconnaissance" in stage_types
    
    @pytest.mark.asyncio
    async def test_simulation_from_template(
        self,
        threat_simulator,
        sample_template_yaml
    ):
        """Test simulation from YAML template."""
        from threatgpt.config.yaml_loader import YAMLConfigLoader
        
        # Load template
        loader = YAMLConfigLoader()
        config = loader.load_and_validate_scenario(sample_template_yaml)
        
        # Convert to scenario
        # ... (implementation)
        
        # Execute simulation
        # result = await threat_simulator.execute_simulation(scenario)
        # assert result.status == SimulationStatus.COMPLETED
    
    @pytest.mark.asyncio
    async def test_concurrent_simulations(self, threat_simulator):
        """Test running multiple simulations concurrently."""
        import asyncio
        
        scenarios = [
            ThreatScenario(
                name=f"Concurrent Test {i}",
                threat_type=ThreatType.PHISHING
            )
            for i in range(3)
        ]
        
        # Run concurrently
        results = await asyncio.gather(*[
            threat_simulator.execute_simulation(scenario)
            for scenario in scenarios
        ])
        
        assert len(results) == 3
        assert all(r.status in [SimulationStatus.COMPLETED, SimulationStatus.FAILED] for r in results)
```

**Deliverables:**
- ✅ 15+ integration tests
- ✅ Tests cover major workflows
- ✅ Concurrent execution tested

#### Day 8-9: Error Handling Refactor

**Objectives:**
- Enhance exception hierarchy
- Add structured logging
- Implement error recovery patterns

**Tasks:**

1. **Enhance Exception Classes** (`src/threatgpt/core/exceptions.py`)
```python
"""Enhanced exception hierarchy for ThreatGPT."""

from typing import Optional, Dict, Any
from datetime import datetime


class ThreatGPTError(Exception):
    """Base exception for all ThreatGPT errors.
    
    Provides structured error information including:
    - Error code for programmatic handling
    - Timestamp for debugging
    - Additional context metadata
    - Suggestion for resolution
    """
    
    DEFAULT_CODE = "THREATGPT_ERROR"
    
    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        suggestion: Optional[str] = None
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.DEFAULT_CODE
        self.timestamp = datetime.utcnow()
        self.context = context or {}
        self.suggestion = suggestion
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for logging/API responses."""
        return {
            "error": self.__class__.__name__,
            "code": self.error_code,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "context": self.context,
            "suggestion": self.suggestion
        }
    
    def __str__(self) -> str:
        """Human-readable error message."""
        parts = [f"{self.error_code}: {self.message}"]
        if self.context:
            parts.append(f"Context: {self.context}")
        if self.suggestion:
            parts.append(f"Suggestion: {self.suggestion}")
        return " | ".join(parts)


class RetryableError(ThreatGPTError):
    """Base class for errors that should trigger retry logic."""
    
    def __init__(
        self,
        message: str,
        retry_after: Optional[int] = None,
        **kwargs
    ):
        super().__init__(message, **kwargs)
        self.retry_after = retry_after  # seconds


class NetworkError(RetryableError):
    """Network connectivity error."""
    DEFAULT_CODE = "NETWORK_ERROR"


class TimeoutError(RetryableError):
    """Operation timeout error."""
    DEFAULT_CODE = "TIMEOUT_ERROR"


class RateLimitError(RetryableError):
    """Rate limit exceeded error."""
    DEFAULT_CODE = "RATE_LIMIT_ERROR"


class ResourceNotFoundError(ThreatGPTError):
    """Requested resource not found."""
    DEFAULT_CODE = "RESOURCE_NOT_FOUND"
    
    def __init__(
        self,
        resource_type: str,
        resource_id: str,
        **kwargs
    ):
        message = f"{resource_type} '{resource_id}' not found"
        super().__init__(
            message,
            context={"resource_type": resource_type, "resource_id": resource_id},
            suggestion=f"Verify the {resource_type} ID exists and you have access",
            **kwargs
        )
```

2. **Implement Structured Logging** (`src/threatgpt/utils/logging.py`)
```python
"""Structured logging utilities for ThreatGPT."""

import logging
import json
from datetime import datetime
from typing import Dict, Any
from pathlib import Path


class StructuredLogger:
    """Structured JSON logger for production environments."""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.context: Dict[str, Any] = {}
    
    def add_context(self, **kwargs):
        """Add persistent context to all log messages."""
        self.context.update(kwargs)
    
    def clear_context(self):
        """Clear persistent context."""
        self.context = {}
    
    def _format_message(
        self,
        level: str,
        message: str,
        **kwargs
    ) -> str:
        """Format log message as JSON."""
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": level,
            "message": message,
            "logger": self.logger.name,
            **self.context,
            **kwargs
        }
        return json.dumps(log_data)
    
    def info(self, message: str, **kwargs):
        """Log info message."""
        self.logger.info(self._format_message("INFO", message, **kwargs))
    
    def error(self, message: str, exc_info=None, **kwargs):
        """Log error message."""
        if exc_info:
            kwargs["exception"] = str(exc_info)
            kwargs["exception_type"] = type(exc_info).__name__
        self.logger.error(self._format_message("ERROR", message, **kwargs))
    
    def warning(self, message: str, **kwargs):
        """Log warning message."""
        self.logger.warning(self._format_message("WARNING", message, **kwargs))
    
    def debug(self, message: str, **kwargs):
        """Log debug message."""
        self.logger.debug(self._format_message("DEBUG", message, **kwargs))


def get_structured_logger(name: str) -> StructuredLogger:
    """Get structured logger instance."""
    return StructuredLogger(name)
```

**Deliverables:**
- ✅ Enhanced exception hierarchy
- ✅ Structured logging implemented
- ✅ Error recovery patterns documented

#### Day 10: Configuration & Validation

**Objectives:**
- Strengthen configuration validation
- Add environment-specific configs
- Implement configuration schema validation

**Deliverables:**
- ✅ Robust config validation
- ✅ Environment-specific configs
- ✅ Schema validation

---

### Week 3: Performance Optimization

**Theme:** Optimize for production performance

#### Day 11-12: Caching Layer

**Objectives:**
- Implement Redis caching
- Add in-memory cache
- Cache LLM responses

**Implementation:**

1. **Create Caching Module** (`src/threatgpt/utils/cache.py`)
```python
"""Caching utilities for ThreatGPT."""

import json
import hashlib
from typing import Any, Optional, Callable
from datetime import timedelta
from functools import wraps

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class CacheManager:
    """Unified cache manager with Redis and in-memory fallback."""
    
    def __init__(
        self,
        redis_url: Optional[str] = None,
        default_ttl: int = 3600
    ):
        self.default_ttl = default_ttl
        self._memory_cache: Dict[str, Any] = {}
        self._redis_client = None
        
        if REDIS_AVAILABLE and redis_url:
            self._redis_client = redis.from_url(redis_url)
    
    def _generate_key(self, *args, **kwargs) -> str:
        """Generate cache key from arguments."""
        key_data = json.dumps({"args": args, "kwargs": kwargs}, sort_keys=True)
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        # Try Redis first
        if self._redis_client:
            try:
                value = await self._redis_client.get(key)
                if value:
                    return json.loads(value)
            except Exception:
                pass  # Fall back to memory cache
        
        # Fall back to memory cache
        return self._memory_cache.get(key)
    
    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None
    ):
        """Set value in cache."""
        ttl = ttl or self.default_ttl
        
        # Try Redis first
        if self._redis_client:
            try:
                await self._redis_client.setex(
                    key,
                    ttl,
                    json.dumps(value)
                )
                return
            except Exception:
                pass  # Fall back to memory cache
        
        # Fall back to memory cache
        self._memory_cache[key] = value
    
    def cached(
        self,
        ttl: Optional[int] = None,
        key_func: Optional[Callable] = None
    ):
        """Decorator for caching function results."""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Generate cache key
                if key_func:
                    cache_key = key_func(*args, **kwargs)
                else:
                    cache_key = self._generate_key(func.__name__, *args, **kwargs)
                
                # Try to get from cache
                cached_value = await self.get(cache_key)
                if cached_value is not None:
                    return cached_value
                
                # Execute function
                result = await func(*args, **kwargs)
                
                # Store in cache
                await self.set(cache_key, result, ttl)
                
                return result
            
            return wrapper
        return decorator


# Global cache instance
_cache_manager = None


def get_cache_manager() -> CacheManager:
    """Get global cache manager instance."""
    global _cache_manager
    if _cache_manager is None:
        _cache_manager = CacheManager()
    return _cache_manager
```

**Deliverables:**
- ✅ Redis caching implemented
- ✅ In-memory fallback
- ✅ Cache decorator for functions
- ✅ 30% performance improvement

#### Day 13-14: Database Query Optimization

**Objectives:**
- Optimize database queries
- Implement connection pooling
- Add query result caching

**Tasks:**
- Analyze slow queries
- Add indexes
- Implement batch operations
- Profile query performance

**Deliverables:**
- ✅ 40% faster database queries
- ✅ Connection pool optimized
- ✅ Batch operations implemented

#### Day 15: Load Testing

**Objectives:**
- Create load testing suite
- Identify bottlenecks
- Measure performance improvements

**Tools:**
- Locust for load testing
- cProfile for profiling
- memory_profiler for memory analysis

**Test Scenarios:**
- 100 concurrent simulations
- 1000 API requests/minute
- Memory usage under load

**Deliverables:**
- ✅ Load testing suite
- ✅ Performance benchmarks
- ✅ Bottlenecks identified and fixed

---

### Week 4: Security Hardening

**Theme:** Production-grade security

#### Day 16-17: Security Audit

**Objectives:**
- Run security scanners
- Fix vulnerabilities
- Implement security best practices

**Tasks:**

1. **Install Security Tools**
```bash
pip install bandit safety pip-audit
```

2. **Run Security Scans**
```bash
# Bandit - Python security linter
bandit -r src/threatgpt/ -f json -o security_report.json

# Safety - Check dependencies for vulnerabilities
safety check --json

# pip-audit - Audit Python packages
pip-audit --format json
```

3. **Fix Common Vulnerabilities**
- SQL injection prevention
- XSS protection
- CSRF tokens
- API key encryption
- Input validation

**Deliverables:**
- ✅ Security audit complete
- ✅ All critical vulnerabilities fixed
- ✅ Security scan in CI/CD

#### Day 18-19: Authentication & Authorization

**Objectives:**
- Implement robust auth system
- Add API key rotation
- Role-based access control (RBAC)

**Implementation:**

1. **API Key Management** (`src/threatgpt/auth/api_keys.py`)
```python
"""Secure API key management."""

import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional


class APIKeyManager:
    """Manage API keys securely."""
    
    @staticmethod
    def generate_key(prefix: str = "tgpt") -> str:
        """Generate secure API key."""
        random_part = secrets.token_urlsafe(32)
        return f"{prefix}_{random_part}"
    
    @staticmethod
    def hash_key(api_key: str) -> str:
        """Hash API key for storage."""
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    @staticmethod
    def verify_key(api_key: str, stored_hash: str) -> bool:
        """Verify API key against stored hash."""
        return APIKeyManager.hash_key(api_key) == stored_hash
```

**Deliverables:**
- ✅ Secure authentication system
- ✅ API key management
- ✅ RBAC implemented

#### Day 20: Penetration Testing

**Objectives:**
- Run penetration tests
- Test API security
- Verify input validation

**Test Areas:**
- API endpoints
- Authentication bypass
- Injection attacks
- Rate limiting
- Data exposure

**Deliverables:**
- ✅ Penetration test report
- ✅ All issues fixed
- ✅ Security documentation

---

### Week 5: Code Quality & Refactoring

**Theme:** Exemplary code quality

#### Day 21-22: Type Hints & Documentation

**Objectives:**
- Add type hints everywhere
- Complete docstrings
- Generate API documentation

**Tasks:**

1. **Add Type Hints**
```python
# Before
def process_data(data, options):
    return result

# After
from typing import Dict, Any, List, Optional

def process_data(
    data: List[Dict[str, Any]],
    options: Optional[Dict[str, Any]] = None
) -> ProcessedResult:
    """Process data with optional configuration.
    
    Args:
        data: List of data dictionaries to process
        options: Optional processing configuration
        
    Returns:
        ProcessedResult with processing metadata
        
    Raises:
        ValidationError: If data is invalid
        ProcessingError: If processing fails
        
    Example:
        >>> data = [{"key": "value"}]
        >>> result = process_data(data, {"mode": "fast"})
        >>> print(result.success)
        True
    """
    pass
```

2. **Run Type Checker**
```bash
mypy src/threatgpt/ --strict
```

**Deliverables:**
- ✅ 100% type hint coverage
- ✅ Complete docstrings
- ✅ API documentation generated

#### Day 23-24: Code Refactoring

**Objectives:**
- Refactor complex functions
- Eliminate code duplication
- Improve readability

**Refactoring Targets:**
- Functions >50 lines
- Cyclomatic complexity >10
- Duplicate code blocks
- Deep nesting (>4 levels)

**Tools:**
- radon for complexity analysis
- pylint for code quality
- black for formatting

**Deliverables:**
- ✅ Complex functions refactored
- ✅ Code duplication eliminated
- ✅ Code quality score >9/10

#### Day 25: CI/CD Pipeline

**Objectives:**
- Set up GitHub Actions
- Automated testing
- Code quality checks

**GitHub Actions Workflow** (`.github/workflows/ci.yml`)
```yaml
name: CI/CD Pipeline

on:
  push:
    branches: [ master, develop ]
  pull_request:
    branches: [ master, develop ]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.11, 3.12]
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install -r requirements-dev.txt
    
    - name: Run linting
      run: |
        flake8 src/threatgpt --count --select=E9,F63,F7,F82 --show-source --statistics
        black --check src/threatgpt
        isort --check-only src/threatgpt
    
    - name: Run type checking
      run: |
        mypy src/threatgpt
    
    - name: Run security scan
      run: |
        bandit -r src/threatgpt
        safety check
    
    - name: Run tests
      run: |
        pytest --cov=src/threatgpt --cov-report=xml --cov-report=term
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
        fail_ci_if_error: true
```

**Deliverables:**
- ✅ CI/CD pipeline active
- ✅ Automated testing
- ✅ Quality gates enforced

---

### Week 6: Final Polish & Documentation

**Theme:** Production readiness

#### Day 26-27: Performance Profiling

**Objectives:**
- Profile all critical paths
- Optimize hot spots
- Reduce memory usage

**Profiling Tools:**
```python
# CPU profiling
import cProfile
import pstats

profiler = cProfile.Profile()
profiler.enable()

# Your code here

profiler.disable()
stats = pstats.Stats(profiler)
stats.sort_stats('cumulative')
stats.print_stats(20)

# Memory profiling
from memory_profiler import profile

@profile
def memory_intensive_function():
    pass
```

**Deliverables:**
- ✅ Performance profiles generated
- ✅ Hot spots optimized
- ✅ Memory usage reduced by 20%

#### Day 28-29: Comprehensive Documentation

**Objectives:**
- Complete all documentation
- Create troubleshooting guides
- Write runbooks

**Documentation to Create:**
1. Architecture documentation
2. API reference
3. Deployment guide
4. Troubleshooting guide
5. Performance tuning guide
6. Security best practices

**Deliverables:**
- ✅ Complete documentation
- ✅ Troubleshooting guides
- ✅ Runbooks for operations

#### Day 30: Final Review & Sign-off

**Objectives:**
- Final code review
- Verify all success criteria
- Prepare for SDK implementation

**Review Checklist:**
- [ ] Test coverage ≥ 85%
- [ ] All critical issues resolved
- [ ] Performance targets met
- [ ] Security audit passed
- [ ] Documentation complete
- [ ] CI/CD pipeline working
- [ ] Code quality score ≥ 9/10
- [ ] Zero high-severity bugs

**Deliverables:**
- ✅ Final review complete
- ✅ Sign-off for SDK implementation
- ✅ Release notes prepared

---

## Technical Debt Resolution

### High Priority

1. **Testing Coverage**
   - Current: ~15%
   - Target: 85%+
   - Effort: 2 weeks

2. **Error Handling**
   - Current: Inconsistent
   - Target: Structured and comprehensive
   - Effort: 3 days

3. **Performance**
   - Current: Functional but unoptimized
   - Target: 30% improvement
   - Effort: 5 days

### Medium Priority

4. **Type Hints**
   - Current: ~60%
   - Target: 100%
   - Effort: 2 days

5. **Documentation**
   - Current: Basic
   - Target: Comprehensive
   - Effort: 3 days

6. **Code Quality**
   - Current: Good structure, needs polish
   - Target: Exemplary
   - Effort: 3 days

### Low Priority

7. **Monitoring**
   - Add application monitoring
   - Implement metrics collection
   - Effort: 2 days

8. **Logging**
   - Enhance structured logging
   - Add log aggregation
   - Effort: 2 days

---

## Quality Assurance Strategy

### Code Quality Metrics

| Metric | Current | Target | Tool |
|--------|---------|--------|------|
| Test Coverage | ~15% | 85%+ | pytest-cov |
| Type Coverage | ~60% | 100% | mypy |
| Code Complexity | Varies | <10 | radon |
| Maintainability | B | A | radon |
| Security Score | Unknown | A+ | bandit |
| Documentation | 50% | 100% | interrogate |

### Testing Strategy

**Test Pyramid:**
- **70% Unit Tests**: Fast, isolated, comprehensive
- **20% Integration Tests**: Module interactions
- **10% E2E Tests**: Complete workflows

**Test Types:**
- Unit tests
- Integration tests
- Performance tests
- Security tests
- Load tests
- Chaos testing (future)

### CI/CD Quality Gates

**Gates to Pass:**
1. All tests pass
2. Coverage ≥ 85%
3. No security vulnerabilities
4. Linting passes
5. Type checking passes
6. Code quality ≥ 9/10

---

## Performance Optimization

### Target Metrics

| Metric | Current | Target | Improvement |
|--------|---------|--------|-------------|
| API Latency (p95) | ~200ms | <100ms | 50% |
| Simulation Time | Varies | -30% | 30% |
| Memory Usage | Baseline | -20% | 20% |
| Throughput | Baseline | +40% | 40% |
| Database Queries | Baseline | -40% | 40% |

### Optimization Areas

1. **Caching**
   - Redis for distributed cache
   - In-memory for hot data
   - LLM response caching

2. **Database**
   - Query optimization
   - Index optimization
   - Connection pooling

3. **Async Operations**
   - Concurrent execution
   - Event loop optimization
   - Connection reuse

4. **Memory**
   - Generator usage
   - Resource cleanup
   - Memory leak fixes

---

## Success Criteria

### Must Have (Week 6)

- [x] Test coverage ≥ 85%
- [x] Zero critical bugs
- [x] Zero high-severity security issues
- [x] All CI/CD checks passing
- [x] Performance targets met
- [x] Documentation complete

### Should Have

- [x] Type hints 100%
- [x] Code quality ≥ 9/10
- [x] Load testing complete
- [x] Penetration testing passed
- [x] Monitoring implemented

### Nice to Have

- [ ] Chaos testing framework
- [ ] A/B testing capability
- [ ] Advanced analytics
- [ ] ML model monitoring

---

## Risk Management

### Identified Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Timeline slip | Medium | High | Buffer time, parallel work |
| Performance targets not met | Low | Medium | Early profiling, iterate |
| Breaking changes | Low | High | Comprehensive tests |
| Security issues found | Medium | Critical | Security-first approach |

### Mitigation Strategies

1. **Weekly checkpoints**: Review progress every Friday
2. **Parallel workstreams**: Multiple developers on different areas
3. **Early testing**: Test early and often
4. **Security first**: Security reviews throughout, not just at end

---

## Timeline Summary

| Week | Theme | Key Deliverables |
|------|-------|------------------|
| **Week 1** | Testing Foundation | Test infrastructure, core tests (85% coverage) |
| **Week 2** | Integration & Errors | Integration tests, enhanced error handling |
| **Week 3** | Performance | Caching, optimization (30% improvement) |
| **Week 4** | Security | Security audit, auth system, penetration testing |
| **Week 5** | Code Quality | Type hints, refactoring, CI/CD |
| **Week 6** | Final Polish | Profiling, documentation, final review |

**Total Duration:** 6 weeks  
**Target Completion:** January 20, 2026  
**Team Size:** 2-3 developers  
**SDK Implementation Start:** January 21, 2026

---

## Post-Implementation

### Validation Checklist

Before proceeding to SDK implementation:

- [ ] All tests passing (≥85% coverage)
- [ ] Performance benchmarks met
- [ ] Security audit passed
- [ ] Documentation reviewed
- [ ] Code quality verified
- [ ] Stakeholder sign-off

### Handoff to SDK Team

**Artifacts to Deliver:**
1. Test suite and reports
2. Performance benchmarks
3. Security audit report
4. Architecture documentation
5. API documentation
6. Deployment runbooks

---

## Conclusion

This 6-week core strengthening plan will transform ThreatGPT from a functional prototype into a **production-ready, battle-tested platform**. The comprehensive approach ensures:

- **Reliability**: Extensive testing catches bugs before production
- **Performance**: Optimizations ensure scalability
- **Security**: Hardening protects against threats
- **Quality**: Clean code is maintainable long-term
- **Readiness**: Solid foundation for SDK development

Upon completion, ThreatGPT will be ready for:
1. SDK implementation
2. Enterprise deployment
3. High-volume production traffic
4. Long-term maintenance and evolution

---

**Document Version:** 1.0.0  
**Last Updated:** December 9, 2025  
**Maintained By:** ThreatGPT Team  
**Next Review:** Weekly during implementation
