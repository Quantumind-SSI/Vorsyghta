# ThreatGPT SDK Development Plan

**Version:** 1.0.0  
**Date:** December 9, 2025  
**Status:** Planning Phase

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [SDK Strategy](#sdk-strategy)
3. [Python SDK (Primary)](#python-sdk-primary)
4. [JavaScript/TypeScript SDK](#javascripttypescript-sdk)
5. [Go SDK](#go-sdk)
6. [REST API Client Libraries](#rest-api-client-libraries)
7. [Implementation Roadmap](#implementation-roadmap)
8. [SDK Architecture](#sdk-architecture)
9. [Code Examples](#code-examples)
10. [Distribution & Packaging](#distribution--packaging)

---

## Executive Summary

This document outlines a comprehensive SDK strategy for **ThreatGPT**, enabling developers to integrate threat simulation capabilities into their applications across multiple programming languages and platforms.

### Goals

- **Easy Integration**: Reduce integration time from days to hours
- **Multi-Language Support**: Python, JavaScript/TypeScript, Go, and others
- **Consistent API**: Unified experience across all SDKs
- **Type Safety**: Strong typing and validation in all SDKs
- **Async/Sync Support**: Both paradigms where applicable
- **Enterprise-Ready**: Authentication, error handling, retries, logging

### Target Audiences

1. **Security Automation Engineers**: Automate threat simulations
2. **DevSecOps Teams**: Integrate into CI/CD pipelines
3. **SIEM/SOAR Platforms**: Custom integrations
4. **Security Training Platforms**: Embed threat generation
5. **Red Team Tools**: Programmatic scenario creation
6. **Compliance Tools**: Automated security testing

---

## SDK Strategy

### Phase 1: Core SDKs (Q1 2026)
- ✅ Python SDK (native, already partially implemented)
- 🔄 JavaScript/TypeScript SDK
- 🔄 Go SDK

### Phase 2: Additional Language Support (Q2 2026)
- Java SDK (for enterprise integrations)
- .NET/C# SDK (for Windows environments)
- Ruby SDK (for Rails applications)

### Phase 3: Platform-Specific SDKs (Q3 2026)
- Mobile SDKs (React Native, Flutter)
- Browser Extension SDK
- VS Code Extension SDK

### Phase 4: Ecosystem Integration (Q4 2026)
- Splunk App SDK
- Elastic Stack Plugin
- ServiceNow Integration SDK
- Terraform Provider

---

## Python SDK (Primary)

### Overview

The Python SDK is the **primary, native SDK** for ThreatGPT, offering the most comprehensive feature set and direct access to all platform capabilities.

### Current State

**Partially Implemented:**
- Core simulation engine (`ThreatSimulator`)
- Configuration management (`ConfigurationLoader`)
- Data models (`ThreatScenario`, `SimulationResult`)
- LLM provider abstractions

**Needs Enhancement:**
- Dedicated SDK client interface
- Simplified authentication
- Better async/sync duality
- Comprehensive examples
- SDK-specific documentation

### Architecture

```python
# High-level SDK structure
threatgpt/
├── sdk/
│   ├── __init__.py              # Main SDK exports
│   ├── client.py                # ThreatGPTClient class
│   ├── async_client.py          # AsyncThreatGPTClient class
│   ├── auth.py                  # Authentication handlers
│   ├── resources/               # Resource-based API
│   │   ├── scenarios.py         # Scenario management
│   │   ├── simulations.py       # Simulation execution
│   │   ├── templates.py         # Template operations
│   │   ├── intelligence.py      # OSINT operations
│   │   ├── datasets.py          # Dataset management
│   │   └── deployments.py       # Deployment operations
│   ├── models/                  # SDK-specific models
│   │   ├── scenario.py
│   │   ├── simulation.py
│   │   └── response.py
│   ├── exceptions.py            # SDK exceptions
│   ├── utils.py                 # Helper utilities
│   └── pagination.py            # Pagination support
```

### Implementation Plan

#### 1. Create SDK Client Interface

**File:** `src/threatgpt/sdk/client.py`

```python
"""ThreatGPT SDK Client - Main Entry Point"""

from typing import Optional, Dict, Any
from threatgpt.sdk.resources import (
    ScenariosResource,
    SimulationsResource,
    TemplatesResource,
    IntelligenceResource,
    DatasetsResource,
)
from threatgpt.sdk.auth import AuthHandler
from threatgpt.core.simulator import ThreatSimulator
from threatgpt.llm.manager import LLMManager


class ThreatGPTClient:
    """Main ThreatGPT SDK client for synchronous operations.
    
    Example:
        >>> from threatgpt import ThreatGPTClient
        >>> client = ThreatGPTClient(api_key="your-key")
        >>> scenario = client.scenarios.create(
        ...     name="Executive Phishing",
        ...     threat_type="spear_phishing"
        ... )
        >>> result = client.simulations.execute(scenario.id)
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://api.threatgpt.io/v1",
        config_path: Optional[str] = None,
        timeout: int = 60,
        max_retries: int = 3,
        **kwargs
    ):
        """Initialize ThreatGPT client.
        
        Args:
            api_key: API key for authentication (or set THREATGPT_API_KEY env var)
            base_url: Base URL for API (default: production)
            config_path: Path to configuration file
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts
            **kwargs: Additional configuration options
        """
        self.auth = AuthHandler(api_key)
        self.base_url = base_url
        self.timeout = timeout
        self.max_retries = max_retries
        
        # Initialize resources
        self.scenarios = ScenariosResource(self)
        self.simulations = SimulationsResource(self)
        self.templates = TemplatesResource(self)
        self.intelligence = IntelligenceResource(self)
        self.datasets = DatasetsResource(self)
        
        # Initialize core components
        self._llm_manager = LLMManager(config=kwargs.get('llm_config'))
        self._simulator = ThreatSimulator(
            llm_provider=self._llm_manager,
            max_stages=kwargs.get('max_stages', 10)
        )
    
    @property
    def simulator(self) -> ThreatSimulator:
        """Access to core simulator instance."""
        return self._simulator
    
    def health_check(self) -> Dict[str, Any]:
        """Check API health status."""
        # Implementation
        pass


class AsyncThreatGPTClient:
    """Async ThreatGPT SDK client for async/await operations.
    
    Example:
        >>> from threatgpt import AsyncThreatGPTClient
        >>> async with AsyncThreatGPTClient(api_key="your-key") as client:
        ...     scenario = await client.scenarios.create(
        ...         name="Executive Phishing",
        ...         threat_type="spear_phishing"
        ...     )
        ...     result = await client.simulations.execute(scenario.id)
    """
    
    def __init__(self, api_key: Optional[str] = None, **kwargs):
        """Initialize async ThreatGPT client."""
        # Similar to sync client
        pass
    
    async def __aenter__(self):
        """Context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        await self.close()
    
    async def close(self):
        """Clean up resources."""
        pass
```

#### 2. Resource-Based API Design

**File:** `src/threatgpt/sdk/resources/scenarios.py`

```python
"""Scenario management resource."""

from typing import List, Optional, Dict, Any
from threatgpt.sdk.models import Scenario, ScenarioList
from threatgpt.core.models import ThreatType


class ScenariosResource:
    """Manage threat scenarios."""
    
    def __init__(self, client):
        self._client = client
    
    def create(
        self,
        name: str,
        threat_type: ThreatType,
        description: Optional[str] = None,
        **kwargs
    ) -> Scenario:
        """Create a new threat scenario.
        
        Args:
            name: Scenario name
            threat_type: Type of threat
            description: Optional description
            **kwargs: Additional scenario parameters
            
        Returns:
            Created Scenario object
            
        Example:
            >>> scenario = client.scenarios.create(
            ...     name="Executive Phishing Campaign",
            ...     threat_type=ThreatType.SPEAR_PHISHING,
            ...     description="Target C-level executives",
            ...     difficulty_level=8
            ... )
        """
        # Implementation
        pass
    
    def get(self, scenario_id: str) -> Scenario:
        """Retrieve a scenario by ID."""
        pass
    
    def list(
        self,
        limit: int = 20,
        offset: int = 0,
        threat_type: Optional[ThreatType] = None,
        **filters
    ) -> ScenarioList:
        """List scenarios with pagination and filtering."""
        pass
    
    def update(self, scenario_id: str, **updates) -> Scenario:
        """Update a scenario."""
        pass
    
    def delete(self, scenario_id: str) -> bool:
        """Delete a scenario."""
        pass
    
    def from_template(self, template_path: str, **variables) -> Scenario:
        """Create scenario from YAML template.
        
        Example:
            >>> scenario = client.scenarios.from_template(
            ...     "templates/executive_phishing.yaml",
            ...     company_name="Acme Corp",
            ...     target_email="ceo@acme.com"
            ... )
        """
        pass
```

#### 3. Simplified Usage Examples

```python
# Example 1: Quick Start
from threatgpt import ThreatGPTClient
from threatgpt.core.models import ThreatType

client = ThreatGPTClient(api_key="your-api-key")

# Create and execute simulation
scenario = client.scenarios.create(
    name="Executive Phishing",
    threat_type=ThreatType.SPEAR_PHISHING
)

result = client.simulations.execute(scenario.id)
print(f"Simulation completed: {result.status}")


# Example 2: Template-Based
client = ThreatGPTClient()

scenario = client.scenarios.from_template(
    "templates/executive_phishing.yaml",
    company_name="Acme Corp",
    target_name="John Smith"
)

result = client.simulations.execute(
    scenario.id,
    max_stages=5,
    enable_adaptation=True
)


# Example 3: Async Operations
from threatgpt import AsyncThreatGPTClient

async def run_simulation():
    async with AsyncThreatGPTClient() as client:
        scenarios = await client.scenarios.list(
            threat_type=ThreatType.PHISHING,
            limit=10
        )
        
        results = await asyncio.gather(*[
            client.simulations.execute(s.id)
            for s in scenarios.items
        ])
        
        return results


# Example 4: Intelligence Gathering
client = ThreatGPTClient()

# OSINT reconnaissance
intel = client.intelligence.gather(
    target="john.smith@acme.com",
    sources=["linkedin", "company_website"]
)

# Create scenario with intelligence
scenario = client.scenarios.create(
    name="Targeted Phishing",
    threat_type=ThreatType.SPEAR_PHISHING,
    target_profile=intel.to_profile()
)
```

#### 4. Package Structure

```
threatgpt-sdk/                   # Separate SDK package (optional)
├── setup.py
├── pyproject.toml
├── README.md
├── LICENSE
├── threatgpt_sdk/
│   ├── __init__.py
│   ├── client.py
│   ├── async_client.py
│   ├── auth.py
│   ├── resources/
│   ├── models/
│   ├── exceptions.py
│   └── utils.py
├── examples/
│   ├── quickstart.py
│   ├── async_example.py
│   ├── template_example.py
│   └── intelligence_example.py
├── tests/
└── docs/
```

#### 5. PyPI Distribution

```toml
# pyproject.toml
[project]
name = "threatgpt-sdk"
version = "0.1.0"
description = "Official Python SDK for ThreatGPT threat simulation platform"
authors = [{name = "ThreatGPT Team", email = "okino007@gmail.com"}]
license = {text = "MIT"}
readme = "README.md"
requires-python = ">=3.11"

dependencies = [
    "httpx>=0.25.0",
    "pydantic>=2.5.0",
    "pyyaml>=6.0.1",
    "aiohttp>=3.9.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.4.0",
    "pytest-asyncio>=0.21.0",
    "black>=23.11.0",
    "mypy>=1.7.0",
]

[project.urls]
Homepage = "https://github.com/Thundastormgod/ThreatGpt"
Documentation = "https://docs.threatgpt.io"
Repository = "https://github.com/Thundastormgod/ThreatGpt"
```

---

## JavaScript/TypeScript SDK

### Overview

JavaScript/TypeScript SDK for web applications, Node.js backends, and serverless functions.

### Architecture

```typescript
// Package structure
@threatgpt/sdk/
├── src/
│   ├── index.ts                 // Main exports
│   ├── client.ts                // ThreatGPTClient class
│   ├── auth.ts                  // Authentication
│   ├── resources/               // API resources
│   │   ├── scenarios.ts
│   │   ├── simulations.ts
│   │   ├── templates.ts
│   │   └── intelligence.ts
│   ├── models/                  // TypeScript interfaces
│   │   ├── scenario.ts
│   │   ├── simulation.ts
│   │   └── response.ts
│   ├── errors.ts                // Error classes
│   └── utils.ts                 // Utilities
├── examples/
├── tests/
├── package.json
├── tsconfig.json
└── README.md
```

### Implementation

```typescript
// src/client.ts
import { Scenarios } from './resources/scenarios';
import { Simulations } from './resources/simulations';
import { Templates } from './resources/templates';

export interface ThreatGPTConfig {
  apiKey?: string;
  baseUrl?: string;
  timeout?: number;
  maxRetries?: number;
}

export class ThreatGPTClient {
  public scenarios: Scenarios;
  public simulations: Simulations;
  public templates: Templates;
  
  private apiKey: string;
  private baseUrl: string;
  private timeout: number;
  
  constructor(config: ThreatGPTConfig = {}) {
    this.apiKey = config.apiKey || process.env.THREATGPT_API_KEY || '';
    this.baseUrl = config.baseUrl || 'https://api.threatgpt.io/v1';
    this.timeout = config.timeout || 60000;
    
    // Initialize resources
    this.scenarios = new Scenarios(this);
    this.simulations = new Simulations(this);
    this.templates = new Templates(this);
  }
  
  async request<T>(
    method: string,
    path: string,
    data?: any
  ): Promise<T> {
    // Implementation with fetch/axios
    const response = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: data ? JSON.stringify(data) : undefined,
    });
    
    if (!response.ok) {
      throw new ThreatGPTError(response.statusText);
    }
    
    return response.json();
  }
}

// src/resources/scenarios.ts
import { ThreatGPTClient } from '../client';
import { Scenario, ThreatType, CreateScenarioRequest } from '../models';

export class Scenarios {
  constructor(private client: ThreatGPTClient) {}
  
  async create(request: CreateScenarioRequest): Promise<Scenario> {
    return this.client.request<Scenario>(
      'POST',
      '/scenarios',
      request
    );
  }
  
  async get(scenarioId: string): Promise<Scenario> {
    return this.client.request<Scenario>(
      'GET',
      `/scenarios/${scenarioId}`
    );
  }
  
  async list(options?: ListOptions): Promise<ScenarioList> {
    const params = new URLSearchParams(options as any);
    return this.client.request<ScenarioList>(
      'GET',
      `/scenarios?${params}`
    );
  }
}

// Usage Example
import { ThreatGPTClient, ThreatType } from '@threatgpt/sdk';

const client = new ThreatGPTClient({
  apiKey: 'your-api-key'
});

async function runSimulation() {
  // Create scenario
  const scenario = await client.scenarios.create({
    name: 'Executive Phishing',
    threatType: ThreatType.SPEAR_PHISHING,
    description: 'Target C-level executives'
  });
  
  // Execute simulation
  const result = await client.simulations.execute(scenario.id);
  
  console.log(`Simulation ${result.status}`);
  return result;
}
```

### NPM Package

```json
{
  "name": "@threatgpt/sdk",
  "version": "0.1.0",
  "description": "Official JavaScript/TypeScript SDK for ThreatGPT",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "scripts": {
    "build": "tsc",
    "test": "jest",
    "lint": "eslint src/**/*.ts"
  },
  "keywords": [
    "threatgpt",
    "cybersecurity",
    "threat-simulation",
    "phishing",
    "security"
  ],
  "author": "ThreatGPT Team",
  "license": "MIT",
  "dependencies": {
    "cross-fetch": "^4.0.0",
    "form-data": "^4.0.0"
  },
  "devDependencies": {
    "@types/node": "^20.0.0",
    "typescript": "^5.0.0",
    "jest": "^29.0.0",
    "@typescript-eslint/eslint-plugin": "^6.0.0"
  }
}
```

---

## Go SDK

### Overview

Go SDK for high-performance integrations, microservices, and cloud-native applications.

### Architecture

```go
// Package structure
threatgpt-go/
├── threatgpt/
│   ├── client.go                // Main client
│   ├── scenarios.go             // Scenario operations
│   ├── simulations.go           // Simulation operations
│   ├── templates.go             // Template operations
│   ├── models.go                // Data models
│   ├── errors.go                // Error types
│   └── utils.go                 // Utilities
├── examples/
├── go.mod
├── go.sum
└── README.md
```

### Implementation

```go
// client.go
package threatgpt

import (
    "context"
    "net/http"
    "time"
)

// Client is the main ThreatGPT API client
type Client struct {
    apiKey     string
    baseURL    string
    httpClient *http.Client
    
    Scenarios   *ScenariosService
    Simulations *SimulationsService
    Templates   *TemplatesService
}

// Config for initializing the client
type Config struct {
    APIKey     string
    BaseURL    string
    Timeout    time.Duration
    MaxRetries int
}

// NewClient creates a new ThreatGPT client
func NewClient(config *Config) *Client {
    if config.BaseURL == "" {
        config.BaseURL = "https://api.threatgpt.io/v1"
    }
    if config.Timeout == 0 {
        config.Timeout = 60 * time.Second
    }
    
    client := &Client{
        apiKey:  config.APIKey,
        baseURL: config.BaseURL,
        httpClient: &http.Client{
            Timeout: config.Timeout,
        },
    }
    
    // Initialize services
    client.Scenarios = &ScenariosService{client: client}
    client.Simulations = &SimulationsService{client: client}
    client.Templates = &TemplatesService{client: client}
    
    return client
}

// scenarios.go
package threatgpt

import (
    "context"
    "encoding/json"
)

type ScenariosService struct {
    client *Client
}

type Scenario struct {
    ID          string    `json:"id"`
    Name        string    `json:"name"`
    ThreatType  string    `json:"threat_type"`
    Description string    `json:"description"`
    CreatedAt   time.Time `json:"created_at"`
}

type CreateScenarioRequest struct {
    Name        string `json:"name"`
    ThreatType  string `json:"threat_type"`
    Description string `json:"description,omitempty"`
}

func (s *ScenariosService) Create(ctx context.Context, req *CreateScenarioRequest) (*Scenario, error) {
    body, err := json.Marshal(req)
    if err != nil {
        return nil, err
    }
    
    var scenario Scenario
    err = s.client.request(ctx, "POST", "/scenarios", body, &scenario)
    if err != nil {
        return nil, err
    }
    
    return &scenario, nil
}

func (s *ScenariosService) Get(ctx context.Context, scenarioID string) (*Scenario, error) {
    var scenario Scenario
    err := s.client.request(ctx, "GET", "/scenarios/"+scenarioID, nil, &scenario)
    if err != nil {
        return nil, err
    }
    
    return &scenario, nil
}

// Usage Example
package main

import (
    "context"
    "fmt"
    "log"
    
    "github.com/threatgpt/threatgpt-go/threatgpt"
)

func main() {
    client := threatgpt.NewClient(&threatgpt.Config{
        APIKey: "your-api-key",
    })
    
    ctx := context.Background()
    
    // Create scenario
    scenario, err := client.Scenarios.Create(ctx, &threatgpt.CreateScenarioRequest{
        Name:       "Executive Phishing",
        ThreatType: "spear_phishing",
    })
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Created scenario: %s\n", scenario.ID)
    
    // Execute simulation
    result, err := client.Simulations.Execute(ctx, scenario.ID)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Simulation status: %s\n", result.Status)
}
```

### Go Module

```go
// go.mod
module github.com/threatgpt/threatgpt-go

go 1.21

require (
    github.com/google/uuid v1.5.0
    github.com/stretchr/testify v1.8.4
)
```

---

## REST API Client Libraries

### Additional Language Support

#### Java SDK
```xml
<!-- Maven dependency -->
<dependency>
    <groupId>io.threatgpt</groupId>
    <artifactId>threatgpt-sdk</artifactId>
    <version>0.1.0</version>
</dependency>
```

```java
// Usage
ThreatGPTClient client = new ThreatGPTClient.Builder()
    .apiKey("your-api-key")
    .build();

Scenario scenario = client.scenarios().create(
    CreateScenarioRequest.builder()
        .name("Executive Phishing")
        .threatType(ThreatType.SPEAR_PHISHING)
        .build()
);

SimulationResult result = client.simulations().execute(scenario.getId());
```

#### C#/.NET SDK
```xml
<!-- NuGet package -->
<PackageReference Include="ThreatGPT.SDK" Version="0.1.0" />
```

```csharp
// Usage
var client = new ThreatGPTClient(new ThreatGPTOptions
{
    ApiKey = "your-api-key"
});

var scenario = await client.Scenarios.CreateAsync(new CreateScenarioRequest
{
    Name = "Executive Phishing",
    ThreatType = ThreatType.SpearPhishing
});

var result = await client.Simulations.ExecuteAsync(scenario.Id);
```

#### Ruby SDK
```ruby
# Gemfile
gem 'threatgpt', '~> 0.1.0'

# Usage
client = ThreatGPT::Client.new(api_key: 'your-api-key')

scenario = client.scenarios.create(
  name: 'Executive Phishing',
  threat_type: 'spear_phishing'
)

result = client.simulations.execute(scenario.id)
```

---

## Implementation Roadmap

### Phase 1: Foundation (Q1 2026)

**Month 1: Python SDK Enhancement**
- Week 1-2: Design SDK architecture and API surface
- Week 3: Implement `ThreatGPTClient` and `AsyncThreatGPTClient`
- Week 4: Implement resource classes (Scenarios, Simulations, Templates)

**Month 2: Python SDK Completion**
- Week 1: Authentication, error handling, retries
- Week 2: Documentation and examples
- Week 3: Testing (unit, integration, E2E)
- Week 4: PyPI packaging and release

**Month 3: JavaScript/TypeScript SDK**
- Week 1-2: TypeScript implementation
- Week 3: Testing and documentation
- Week 4: NPM packaging and release

### Phase 2: Additional Languages (Q2 2026)

**Month 4: Go SDK**
- Week 1-2: Core implementation
- Week 3: Testing and examples
- Week 4: Module publishing

**Month 5: Java SDK**
- Week 1-3: Implementation with Maven
- Week 4: Testing and Maven Central release

**Month 6: .NET/C# SDK**
- Week 1-3: Implementation with NuGet
- Week 4: Testing and NuGet release

### Phase 3: Platform Integrations (Q3 2026)

**Months 7-9:**
- Splunk App SDK
- Elastic Stack plugin
- ServiceNow integration
- Terraform provider
- GitHub Actions integration

### Phase 4: Developer Experience (Q4 2026)

**Months 10-12:**
- Interactive documentation
- Code generators
- VS Code extension
- Postman collection
- OpenAPI/Swagger spec

---

## SDK Architecture

### Common Patterns Across All SDKs

#### 1. Resource-Based API
All SDKs organize operations into logical resources:
- `Scenarios`: Manage threat scenarios
- `Simulations`: Execute and monitor simulations
- `Templates`: Template management
- `Intelligence`: OSINT operations
- `Datasets`: Dataset operations
- `Deployments`: Platform deployments

#### 2. Consistent Method Naming
- `create()`: Create new resource
- `get()`: Retrieve by ID
- `list()`: List with pagination
- `update()`: Update resource
- `delete()`: Delete resource

#### 3. Error Handling
```python
# Python
class ThreatGPTError(Exception): pass
class AuthenticationError(ThreatGPTError): pass
class ValidationError(ThreatGPTError): pass
class RateLimitError(ThreatGPTError): pass
class APIError(ThreatGPTError): pass
```

```typescript
// TypeScript
class ThreatGPTError extends Error {}
class AuthenticationError extends ThreatGPTError {}
class ValidationError extends ThreatGPTError {}
```

#### 4. Authentication
Support multiple auth methods:
- API Key (Bearer token)
- OAuth 2.0
- Environment variables
- Configuration files

#### 5. Retry Logic
- Exponential backoff
- Configurable retry attempts
- Idempotency keys

#### 6. Logging & Debugging
- Structured logging
- Debug mode
- Request/response logging

---

## Code Examples

### Python SDK Examples

```python
# Example 1: Basic Usage
from threatgpt import ThreatGPTClient

client = ThreatGPTClient(api_key="your-key")

scenario = client.scenarios.create(
    name="Executive Phishing",
    threat_type="spear_phishing"
)

result = client.simulations.execute(scenario.id)


# Example 2: Template-Based
scenario = client.scenarios.from_template(
    "templates/executive_phishing.yaml",
    company_name="Acme Corp"
)

result = client.simulations.execute(scenario.id)


# Example 3: Async Operations
from threatgpt import AsyncThreatGPTClient

async def run_multiple_simulations():
    async with AsyncThreatGPTClient() as client:
        scenarios = await client.scenarios.list(limit=5)
        
        results = await asyncio.gather(*[
            client.simulations.execute(s.id)
            for s in scenarios.items
        ])
        
        return results


# Example 4: Intelligence Integration
intel = client.intelligence.gather(
    target="john.smith@acme.com",
    sources=["linkedin", "company"]
)

scenario = client.scenarios.create(
    name="Targeted Phishing",
    threat_type="spear_phishing",
    target_profile=intel.to_profile()
)


# Example 5: Batch Operations
scenarios = client.scenarios.create_batch([
    {"name": "Campaign 1", "threat_type": "phishing"},
    {"name": "Campaign 2", "threat_type": "smishing"},
    {"name": "Campaign 3", "threat_type": "vishing"},
])

results = client.simulations.execute_batch([s.id for s in scenarios])


# Example 6: Monitoring & Callbacks
def on_stage_complete(stage):
    print(f"Completed stage: {stage.type}")

result = client.simulations.execute(
    scenario.id,
    callbacks={
        "on_stage_complete": on_stage_complete,
        "on_complete": lambda r: print(f"Done: {r.status}")
    }
)


# Example 7: Dataset Integration
client.datasets.download("enron")
patterns = client.datasets.analyze("enron", extract="email_patterns")

scenario = client.scenarios.create(
    name="Realistic Phishing",
    threat_type="phishing",
    email_patterns=patterns
)
```

### JavaScript/TypeScript Examples

```typescript
// Example 1: Basic Usage
import { ThreatGPTClient, ThreatType } from '@threatgpt/sdk';

const client = new ThreatGPTClient({ apiKey: 'your-key' });

const scenario = await client.scenarios.create({
  name: 'Executive Phishing',
  threatType: ThreatType.SPEAR_PHISHING
});

const result = await client.simulations.execute(scenario.id);


// Example 2: React Integration
import { useThreatGPT } from '@threatgpt/react';

function SimulationComponent() {
  const { scenarios, simulations, loading, error } = useThreatGPT();
  
  const runSimulation = async (scenarioId: string) => {
    const result = await simulations.execute(scenarioId);
    console.log('Simulation complete:', result);
  };
  
  return (
    <div>
      {scenarios.map(s => (
        <button key={s.id} onClick={() => runSimulation(s.id)}>
          Run {s.name}
        </button>
      ))}
    </div>
  );
}


// Example 3: Node.js Server Integration
import express from 'express';
import { ThreatGPTClient } from '@threatgpt/sdk';

const app = express();
const client = new ThreatGPTClient();

app.post('/api/simulations', async (req, res) => {
  try {
    const scenario = await client.scenarios.create(req.body);
    const result = await client.simulations.execute(scenario.id);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
```

### Go SDK Examples

```go
// Example 1: Basic Usage
package main

import (
    "context"
    "log"
    
    "github.com/threatgpt/threatgpt-go/threatgpt"
)

func main() {
    client := threatgpt.NewClient(&threatgpt.Config{
        APIKey: "your-api-key",
    })
    
    ctx := context.Background()
    
    scenario, err := client.Scenarios.Create(ctx, &threatgpt.CreateScenarioRequest{
        Name:       "Executive Phishing",
        ThreatType: threatgpt.ThreatTypeSpearPhishing,
    })
    if err != nil {
        log.Fatal(err)
    }
    
    result, err := client.Simulations.Execute(ctx, scenario.ID)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Simulation status: %s", result.Status)
}


// Example 2: Concurrent Simulations
func runMultipleSimulations(ctx context.Context, client *threatgpt.Client) {
    scenarios, err := client.Scenarios.List(ctx, &threatgpt.ListOptions{
        Limit: 10,
    })
    if err != nil {
        log.Fatal(err)
    }
    
    var wg sync.WaitGroup
    results := make(chan *threatgpt.SimulationResult, len(scenarios.Items))
    
    for _, scenario := range scenarios.Items {
        wg.Add(1)
        go func(s *threatgpt.Scenario) {
            defer wg.Done()
            result, err := client.Simulations.Execute(ctx, s.ID)
            if err != nil {
                log.Printf("Error: %v", err)
                return
            }
            results <- result
        }(scenario)
    }
    
    wg.Wait()
    close(results)
}
```

---

## Distribution & Packaging

### Python (PyPI)

```bash
# Build and publish
python -m build
twine upload dist/*

# Installation
pip install threatgpt-sdk
```

### JavaScript/TypeScript (NPM)

```bash
# Build and publish
npm run build
npm publish

# Installation
npm install @threatgpt/sdk
# or
yarn add @threatgpt/sdk
```

### Go (Go Modules)

```bash
# No build required, use directly
go get github.com/threatgpt/threatgpt-go
```

### Java (Maven Central)

```bash
# Build and publish
mvn clean deploy

# Installation via pom.xml
<dependency>
    <groupId>io.threatgpt</groupId>
    <artifactId>threatgpt-sdk</artifactId>
    <version>0.1.0</version>
</dependency>
```

### .NET (NuGet)

```bash
# Build and publish
dotnet pack
dotnet nuget push ThreatGPT.SDK.0.1.0.nupkg

# Installation
dotnet add package ThreatGPT.SDK
```

---

## Documentation Strategy

### 1. API Reference Documentation
- Auto-generated from code (Sphinx for Python, JSDoc for JS, GoDoc for Go)
- Hosted on docs.threatgpt.io
- Searchable and versioned

### 2. Getting Started Guides
- Quick start for each SDK
- Installation instructions
- Basic examples
- Common use cases

### 3. Code Examples Repository
- GitHub repo: `threatgpt/sdk-examples`
- Examples for each SDK
- Real-world use cases
- Best practices

### 4. Interactive Documentation
- API playground
- Live code examples
- Try before installing

### 5. Video Tutorials
- SDK setup and configuration
- Common workflows
- Advanced features

---

## Testing Strategy

### Unit Tests
- Test all SDK methods
- Mock API responses
- 90%+ code coverage

### Integration Tests
- Test against live API
- E2E scenarios
- CI/CD integration

### Performance Tests
- Benchmark SDK performance
- Connection pooling validation
- Concurrent request handling

### Example Tests

```python
# Python tests
import pytest
from threatgpt import ThreatGPTClient

@pytest.fixture
def client():
    return ThreatGPTClient(api_key="test-key")

def test_create_scenario(client, mock_api):
    scenario = client.scenarios.create(
        name="Test",
        threat_type="phishing"
    )
    assert scenario.name == "Test"
```

```typescript
// TypeScript tests
import { ThreatGPTClient } from '@threatgpt/sdk';

describe('ThreatGPTClient', () => {
  it('should create scenario', async () => {
    const client = new ThreatGPTClient({ apiKey: 'test-key' });
    const scenario = await client.scenarios.create({
      name: 'Test',
      threatType: 'phishing'
    });
    expect(scenario.name).toBe('Test');
  });
});
```

---

## Success Metrics

### Adoption Metrics
- Downloads per month (PyPI, NPM, Go modules)
- Active users
- GitHub stars
- Community contributions

### Quality Metrics
- Test coverage (>90%)
- Documentation coverage (100%)
- Issue resolution time (<48 hours)
- API stability (semantic versioning)

### Performance Metrics
- API response time (<100ms)
- SDK initialization time
- Memory footprint
- Concurrent request handling

---

## Support & Community

### Developer Support
- GitHub Discussions
- Stack Overflow tag
- Discord community
- Email support

### Resources
- SDK documentation
- Code examples
- Video tutorials
- Blog posts

### Contributing
- Open source all SDKs
- Accept community contributions
- Provide contributor guidelines
- Recognize contributors

---

## Conclusion

This SDK plan provides a comprehensive strategy for building multi-language SDKs that make ThreatGPT accessible to developers across different platforms and ecosystems. The phased approach ensures quality while delivering value incrementally.

**Next Steps:**
1. Review and approve SDK plan
2. Prioritize languages based on user demand
3. Begin Python SDK enhancement (Phase 1, Month 1)
4. Set up SDK development infrastructure
5. Create SDK repositories and CI/CD pipelines

---

**Document Version:** 1.0.0  
**Last Updated:** December 9, 2025  
**Maintained By:** ThreatGPT Team
