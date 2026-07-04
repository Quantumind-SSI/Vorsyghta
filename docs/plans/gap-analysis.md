# Gap Analysis: Cyber Threat Simulation Engine Plan vs Ciicerone Codebase

**Date:** 2026-06-28  
**Reference:** `docs/plans/cyber-threat-simulation-engine-plan.md`

---

## Summary

The Ciicerone codebase already implements a significant portion of the plan's orchestration, AI agent, tool abstraction, and telemetry layers. The **quantum threat simulation layer** is entirely absent and represents the largest gap. Several infrastructure components (Celery, OPA, GNS3/Mininet, Kubernetes, honeypots, LocalStack, ELK, Prometheus) are also missing but are less critical given existing alternatives.

---

## Gap Analysis by Layer

### 1. Orchestration Layer

| Component | Plan | Existing | Status |
|-----------|------|----------|--------|
| API Gateway (FastAPI) | Required | `ciicerone/api/main.py` | **Exists** |
| Task Queue (Celery + Redis) | Required | asyncio-based execution | **Partial** — no Celery, but async patterns exist |
| Policy Engine (OPA) | Required | Not present | **Missing** |
| Safety Monitor | Required | `ciicerone/safety/`, `ciicerone/vm/safety.py` | **Exists** — different implementation |
| Event Bus (Redis Pub/Sub) | Required | `ciicerone/core/event_sourcing.py` | **Partial** — event sourcing exists, no Redis pub/sub |
| State Store (PostgreSQL) | Required | `ciicerone/core/postgres_event_store.py` | **Exists** |
| Audit Logging | Required | `ciicerone/core/audit_logger.py` | **Exists** |

### 2. AI Agent Layer

| Component | Plan | Existing | Status |
|-----------|------|----------|--------|
| AI Hacker Agent | Required | `ciicerone/vm/agent.py` (`AIAttackAgent`) | **Exists** |
| Attack Planning | Required | `ciicerone/vm/agent.py` (`plan_attack`) | **Exists** |
| Adaptive Re-planning | Required | `ciicerone/vm/agent.py` (`_analyze_and_adapt`) | **Exists** |
| Memory System (Vector DB) | Required | `ciicerone/rag/` | **Partial** — RAG exists, no Pinecone/Weaviate |
| Multi-Agent Coordinator | Required | `ciicerone/llm/rlhf_multiagent.py` | **Partial** — RLHF multiagent exists, not a coordinator |
| LLM Integration | Required | `ciicerone/llm/manager.py`, providers | **Exists** |
| Fallback Chain | Required | `ciicerone/llm/fallback_chain.py` | **Exists** |
| **Quantum Threat Agent** | Required | **Not present** | **Missing** |
| **Crypto Inventory Scanner** | Required | **Not present** | **Missing** |
| **Quantum Vulnerability Analyzer** | Required | **Not present** | **Missing** |
| **PQC Migration Planner** | Required | **Not present** | **Missing** |
| **Hybrid Crypto Validator** | Required | **Not present** | **Missing** |
| **Quantum Timeline Simulator (Y2Q)** | Required | **Not present** | **Missing** |

### 3. Tool Abstraction Layer

| Component | Plan | Existing | Status |
|-----------|------|----------|--------|
| Network Tools (Nmap) | Required | MCP tools, Ciicerone Attack mapper | **Partial** — via Ciicerone Attack, not standalone |
| Browser Tools (Playwright) | Required | Not present | **Missing** |
| System Tools (Metasploit) | Required | Via Ciicerone Attack integration | **Partial** |
| Cloud Tools (AWS/Azure/GCP) | Required | `ciicerone/client_data/` integrators | **Partial** |
| **Quantum Tools (Qiskit, Cirq)** | Required | **Not present** | **Missing** |
| **Crypto Analysis Tools** | Required | **Not present** | **Missing** |
| **PQC Testing Tools (liboqs)** | Required | **Not present** | **Missing** |
| **Hybrid Crypto Tools (OQS-OpenSSL)** | Required | **Not present** | **Missing** |
| MCP Tool Server | Required | `ciicerone/mcp/` | **Exists** |

### 4. Simulation Environments

| Component | Plan | Existing | Status |
|-----------|------|----------|--------|
| VM Cluster (Proxmox) | Required | `ciicerone/vm/operator.py` | **Exists** — supports Docker, Proxmox, Libvirt |
| Container Orchestration (K8s) | Required | Docker support in VM operator | **Partial** — no K8s |
| Network Emulation (GNS3/Mininet) | Required | Not present | **Missing** |
| Digital Twin (Terraform) | Required | Not present | **Missing** |
| Honeypots | Required | Not present | **Missing** |
| Cloud Simulation (LocalStack) | Required | Not present | **Missing** |
| **Quantum Simulation (Qiskit)** | Required | **Not present** | **Missing** |
| **PQC Test Environment (liboqs)** | Required | **Not present** | **Missing** |
| **Hybrid PQ/TLS Environment** | Required | **Not present** | **Missing** |

### 5. Telemetry & Data Layer

| Component | Plan | Existing | Status |
|-----------|------|----------|--------|
| Event Logger (ELK) | Required | `ciicerone/core/simulation_logger.py` | **Partial** — custom logger, no ELK |
| Metrics (Prometheus) | Required | Not present | **Missing** |
| Training Data Store (Vector DB) | Required | `ciicerone/rag/` | **Partial** |
| Audit Trail | Required | `ciicerone/core/audit_logger.py` | **Exists** |
| **Quantum Vulnerability Dataset** | Required | **Not present** | **Missing** |

### 6. Blue Team Layer

| Component | Plan | Existing | Status |
|-----------|------|----------|--------|
| SIEM | Required | `ciicerone/defense/blue_team/siem_simulator.py`, `ciicerone/integrations/siem_client.py` | **Exists** |
| IDS/IPS | Required | `ciicerone/defense/blue_team/ids_detector.py` | **Exists** |
| EDR | Required | `ciicerone/defense/blue_team/edr_agent.py` | **Exists** |
| Incident Response | Required | `ciicerone/defense/blue_team/incident_response.py` | **Exists** |
| Threat Hunting | Required | `ciicerone/defense/blue_team/threat_hunter.py` | **Exists** |
| Log Analysis | Required | `ciicerone/defense/blue_team/log_analyzer.py` | **Exists** |
| Alert Triage | Required | `ciicerone/defense/blue_team/alert_triage.py` | **Exists** |
| Forensics | Required | `ciicerone/defense/blue_team/forensics.py` | **Exists** |

### 7. API Endpoints

| Endpoint Group | Plan | Existing | Status |
|----------------|------|----------|--------|
| Environment Management | Required | Not present (VM via CLI/MCP) | **Missing** |
| Attack Simulation | Required | `ciicerone/api/main.py` (`/simulations`) | **Partial** |
| AI Agent Control | Required | Not present | **Missing** |
| Training Data | Required | Not present | **Missing** |
| Monitoring | Required | `/health` only | **Partial** |
| **Quantum Threat Simulation** | Required | **Not present** | **Missing** |

---

## Prioritized Implementation Roadmap

### Priority 1: Quantum Threat Simulation Layer (Entirely Missing)

This is the core differentiator and the largest gap. All quantum-related components need to be built:

1. **`ciicerone/quantum/`** — new package
   - `models.py` — Pydantic models for quantum scan results, attack simulations, PQC migration plans
   - `crypto_scanner.py` — `CryptoInventoryScanner` for detecting RSA, ECC, DSA, AES, SHA, HMAC in target environments
   - `vulnerability_analyzer.py` — `QuantumVulnerabilityAnalyzer` using Shor's/Grover's algorithm analysis
   - `pqc_migration_planner.py` — `PQCMigrationPlanner` generating NIST-standard PQC migration recommendations
   - `hybrid_validator.py` — `HybridCryptoValidator` for testing hybrid PQ/TLS deployments
   - `timeline_simulator.py` — `QuantumTimelineSimulator` for Y2Q readiness modeling
   - `agent.py` — `QuantumThreatAgent` orchestrating all the above
   - `__init__.py` — package exports

2. **API endpoints** — `ciicerone/api/routers/quantum.py`
   - `/api/v1/quantum/crypto-scan`
   - `/api/v1/quantum/simulate-attack`
   - `/api/v1/quantum/pqc-migration`
   - `/api/v1/quantum/hybrid-validate`
   - `/api/v1/quantum/y2q-timeline`
   - `/api/v1/quantum/inventory`

3. **CLI commands** — `ciicerone/cli/quantum.py`
   - `ciicerone quantum scan`
   - `ciicerone quantum simulate`
   - `ciicerone quantum migrate`
   - `ciicerone quantum validate`
   - `ciicerone quantum timeline`

4. **Configuration** — Add quantum section to `config.yaml`

### Priority 2: Missing Infrastructure Components

- Celery task queue for distributed execution
- OPA policy engine for RBAC
- Prometheus metrics collection
- Kubernetes integration for container orchestration

### Priority 3: Missing Simulation Environments

- GNS3/Mininet network emulation
- Terraform digital twin
- Honeypots (Cowrie, Honeyd)
- LocalStack cloud simulation

### Priority 4: Missing Tool Integrations

- Playwright browser automation
- Standalone Nmap/Metasploit tool wrappers
- Qiskit/Cirq quantum simulation
- liboqs PQC testing
- OQS-OpenSSL hybrid TLS testing

### Priority 5: Enhanced API & Data

- Full environment management API
- AI agent control API
- Training data export/import API
- Quantum vulnerability dataset (10,000+ samples)
