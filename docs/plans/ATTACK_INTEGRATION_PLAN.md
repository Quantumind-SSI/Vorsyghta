# Ciicerone Attack Integration & Multi-Team Defense Plan

## Executive Summary

Integrate [Ciicerone Attack](https://github.com/vxcontrol/pentagi) as the autonomous offensive engine for Ciicerone,
and build complementary defensive capabilities for Blue, Yellow, and Purple team operations.
This creates a complete red-blue-purple team training and simulation platform.

---

## Part 1: Ciicerone Attack Integration (Red Team / Offensive)

### 1.1 What Ciicerone Attack Provides

Ciicerone Attack is a fully autonomous multi-agent AI penetration testing system with:
- **20+ professional pentesting tools** (nmap, metasploit, sqlmap, hydra, gobuster, nuclei, etc.)
- **Multi-agent architecture**: Orchestrator, Researcher, Developer, Executor agents
- **Sandboxed Docker execution** with complete isolation
- **Smart memory system** with pgvector for long-term attack pattern storage
- **Knowledge graph** via Graphiti/Neo4j for semantic relationship tracking
- **Web intelligence** via built-in scraper browser
- **External search integration** (Tavily, DuckDuckGo, Google, Sploitus, Searxng)
- **REST and GraphQL APIs** with Bearer token auth
- **Detailed reporting** with vulnerability reports and exploitation guides
- **10+ LLM provider support** (OpenAI, Anthropic, Ollama, Bedrock, Gemini, etc.)

### 1.2 Integration Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Ciicerone Platform                     │
│                                                           │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐ │
│  │  CLI / API  │  │  Web UI      │  │  RAG / Knowledge │ │
│  └──────┬──────┘  └──────┬───────┘  └────────┬────────┘ │
│         │                │                    │           │
│  ┌──────▼────────────────▼────────────────────▼────────┐ │
│  │              Ciicerone Orchestrator                   │ │
│  │         (Scenario Manager / Team Coordinator)         │ │
│  └──────┬────────────────┬─────────────────┬───────────┘ │
│         │                │                 │              │
│  ┌──────▼──────┐  ┌─────▼──────┐  ┌───────▼───────────┐ │
│  │  RED TEAM   │  │ BLUE TEAM  │  │  PURPLE TEAM      │ │
│  │  (Ciicerone Attack)  │  │ (Defense)  │  │  (Coordination)   │ │
│  └──────┬──────┘  └─────┬──────┘  └───────┬───────────┘ │
│         │                │                 │              │
│  ┌──────▼──────┐  ┌─────▼──────┐  ┌───────▼───────────┐ │
│  │ Ciicerone Attack API │  │ SIEM/SOC   │  │  Shared AAR       │ │
│  │ (REST/GraphQL)│  │ Simulator  │  │  (After Action    │ │
│  │              │  │            │  │   Review)         │ │
│  └─────────────┘  └────────────┘  └───────────────────┘ │
│                                                           │
│  ┌─────────────────────────────────────────────────────┐ │
│  │              Azure Infrastructure                    │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │ │
│  │  │ Attacker │  │ Target   │  │  Defense VM      │  │ │
│  │  │ VM       │  │ VMs      │  │  (SIEM/IDS/EDR)  │  │ │
│  │  └──────────┘  └──────────┘  └──────────────────┘  │ │
│  └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### 1.3 Integration Steps

#### Phase 1: Ciicerone Attack Deployment (Week 1)

**Step 1: Deploy Ciicerone Attack on Azure**
- Add Ciicerone Attack as a Docker Compose stack on the Azure VM
- Update `scripts/azure_provision.sh` to include Ciicerone Attack services
- Ciicerone Attack requires: 16GB RAM, 100GB disk, Docker + Docker Compose

```yaml
# docker-compose.attack.yml (to be added to project)
services:
  attack:
    image: vxcontrol/pentagi:latest
    ports:
      - "3000:3000"  # Web UI
      - "8080:8080"  # REST API
      - "8081:8081"  # GraphQL API
    environment:
      - OPENAI_API_KEY=${AZURE_OPENAI_API_KEY}
      - OPENAI_BASE_URL=${AZURE_OPENAI_ENDPOINT}
      - OPENAI_MODEL=gpt-4o
      - DATABASE_URL=postgres://attack:attack@attack-db:5432/attack
      - REDIS_URL=redis://attack-redis:6379
    depends_on:
      - attack-db
      - attack-redis

  attack-db:
    image: vxcontrol/pgvector:latest
    environment:
      - POSTGRES_DB=attack
      - POSTGRES_USER=attack
      - POSTGRES_PASSWORD=attack
    volumes:
      - attack-db-data:/var/lib/postgresql/data

  attack-redis:
    image: redis:7-alpine
    volumes:
      - attack-redis-data:/data

volumes:
  attack-db-data:
  attack-redis-data:
```

**Step 2: Create Ciicerone Attack API Client**
- New file: `ciicerone/integrations/attack_client.py`
- REST API client for creating flows, monitoring tasks, retrieving reports
- GraphQL client for complex queries (attack patterns, memory, knowledge graph)

```python
# ciicerone/integrations/attack_client.py (planned)
class AttackClient:
    """Client for Ciicerone Attack REST/GraphQL API."""

    async def create_flow(self, name, description, target, parameters) -> Flow:
        """Create a new pentesting flow."""

    async def get_flow_status(self, flow_id) -> FlowStatus:
        """Get real-time flow execution status."""

    async def get_flow_report(self, flow_id) -> AttackReport:
        """Get detailed vulnerability report."""

    async def list_flows(self) -> List[Flow]:
        """List all pentesting flows."""

    async def steer_flow(self, flow_id, instruction) -> bool:
        """Send steering instruction to active flow (assistant mode)."""

    async def get_flow_artifacts(self, flow_id) -> List[Artifact]:
        """Get artifacts (files, logs, screenshots) from flow."""

    async def search_memory(self, query) -> List[MemoryEntry]:
        """Search Ciicerone Attack's vector store for past attack patterns."""
```

**Step 3: Create Ciicerone Attack Integration Module**
- New file: `ciicerone/integrations/attack.py`
- Wraps Ciicerone Attack client with Ciicerone scenario management
- Maps Ciicerone scenarios to Ciicerone Attack flows
- Translates Ciicerone Attack reports to Ciicerone After Action Reviews

#### Phase 2: Red Team Scenario Integration (Week 2)

**Step 4: Scenario-to-Flow Mapping**
- New file: `ciicerone/integrations/attack_mapper.py`
- Maps Ciicerone YAML scenarios to Ciicerone Attack flow parameters
- Translates MITRE ATT&CK techniques to Ciicerone Attack task descriptions
- Handles target environment configuration

**Step 5: Update CLI**
- Add `ciicerone red-team attack` command
- Add `ciicerone red-team flow --status <flow_id>` command
- Add `ciicerone red-team report <flow_id>` command
- Add `ciicerone red-team steer <flow_id> --instruction "..."` command

**Step 6: Real-time Attack Monitoring**
- WebSocket/SSE integration for live attack feed
- Display attack progress in CLI and Web UI
- Stream Ciicerone Attack agent decisions to Ciicerone audit log

#### Phase 3: Shared Infrastructure (Week 3)

**Step 7: Azure VM Provisioning Update**
- Update `scripts/azure_provision.sh` to deploy:
  - Ciicerone Attack stack (API, DB, Redis, Scraper)
  - Target VMs (DVWA, Metasploitable, Windows靶机)
  - Defense VM (SIEM, IDS/IPS, EDR)
- Network segmentation: attack network (10.0.100.0/24) + defense network (10.0.200.0/24)

**Step 8: Config Integration**
- Add `attack` section to `config.yaml`
- Add environment variables: `CIICERONE_ATTACK_API_URL`, `CIICERONE_ATTACK_API_TOKEN`
- Add to `.env` template

---

## Part 2: Defensive Capabilities (Blue/Yellow/Purple Team)

### 2.1 Blue Team (Defensive Operations)

**Goal**: Detect, respond to, and recover from attacks in real-time.

#### Module: `ciicerone/defense/blue_team/`

```
ciicerone/defense/
├── __init__.py
├── blue_team/
│   ├── __init__.py
│   ├── siem_simulator.py        # Simulated SIEM with log aggregation
│   ├── ids_detector.py          # IDS/IPS detection engine
│   ├── edr_agent.py             # Endpoint detection & response
│   ├── incident_response.py     # Incident response playbooks
│   ├── threat_hunter.py         # Threat hunting with MITRE ATT&CK
│   ├── log_analyzer.py          # Log analysis and correlation
│   ├── alert_triage.py          # Alert prioritization and triage
│   └── forensics.py             # Digital forensics collection
├── yellow_team/
│   ├── __init__.py
│   ├── compliance_checker.py    # Security controls validation
│   ├── architecture_reviewer.py # Security architecture review
│   ├── risk_assessor.py         # Risk assessment engine
│   ├── policy_validator.py      # Policy compliance validation
│   ├── awareness_trainer.py     # Security awareness training
│   └── metrics_collector.py     # Security metrics & KPIs
├── purple_team/
│   ├── __init__.py
│   ├── coordination.py          # Red-Blue coordination engine
│   ├── aar_generator.py         # After Action Review generation
│   ├── detection_validator.py   # Validate detections vs attacks
│   ├── feedback_loop.py         # Red→Blue feedback loop
│   ├── effectiveness_scorer.py  # Score detection effectiveness
│   └── exercise_controller.py   # Purple team exercise orchestrator
└── shared/
    ├── __init__.py
    ├── attack_timeline.py       # Shared attack timeline
    ├── detection_timeline.py    # Shared detection timeline
    └── correlation_engine.py    # Attack↔Detection correlation
```

#### Blue Team Capabilities

| Component | Purpose | Key Features |
|---|---|---|
| **SIEM Simulator** | Aggregate logs from target VMs | Simulate Splunk/Elastic queries, correlation rules |
| **IDS Detector** | Network-based intrusion detection | Snort/Suricata rule simulation, alert generation |
| **EDR Agent** | Endpoint detection & response | Process monitoring, file integrity, behavior analysis |
| **Incident Response** | IR playbooks | NIST 800-61 based, containment/eradication/recovery |
| **Threat Hunter** | Proactive threat hunting | MITRE ATT&CK hypothesis testing, IOC search |
| **Log Analyzer** | Log parsing & correlation | Multi-source log correlation, pattern detection |
| **Alert Triage** | Alert prioritization | Severity scoring, false positive reduction |
| **Forensics** | Digital forensics | Disk imaging, memory capture, timeline reconstruction |

#### Blue Team MCP Tools (new)

```python
# Planned MCP tools for blue team operations
BLUE_TEAM_TOOLS = [
    Tool(name="defense_collect_logs", ...),       # Collect logs from target VMs
    Tool(name="defense_analyze_traffic", ...),    # Analyze network traffic captures
    Tool(name="defense_detect_intrusion", ...),   # Run IDS detection on traffic
    Tool(name="defense_hunt_threat", ...),        # Threat hunt with MITRE technique
    Tool(name="defense_triage_alert", ...),       # Triage and prioritize alerts
    Tool(name="defense_respond_incident", ...),   # Execute IR playbook
    Tool(name="defense_forensic_capture", ...),   # Capture forensic evidence
    Tool(name="defense_query_siem", ...),         # Query simulated SIEM
]
```

### 2.2 Yellow Team (Governance, Risk & Compliance)

**Goal**: Ensure security controls are adequate, compliant, and effective.

#### Yellow Team Capabilities

| Component | Purpose | Key Features |
|---|---|---|
| **Compliance Checker** | Validate security controls | NIST 800-53, ISO 27001, CIS Benchmarks |
| **Architecture Reviewer** | Review security architecture | Attack surface analysis, control gap assessment |
| **Risk Assessor** | Quantify and prioritize risks | Risk scoring, likelihood/impact matrix |
| **Policy Validator** | Validate policy compliance | Policy-to-control mapping, exception tracking |
| **Awareness Trainer** | Security awareness training | Phishing simulations, policy quizzes |
| **Metrics Collector** | Security metrics & KPIs | MTTD, MTTR, detection coverage, training completion |

#### Yellow Team MCP Tools (planned)

```python
YELLOW_TEAM_TOOLS = [
    Tool(name="yellow_check_compliance", ...),    # Check compliance against framework
    Tool(name="yellow_assess_risk", ...),         # Assess risk for scenario
    Tool(name="yellow_review_controls", ...),     # Review security controls
    Tool(name="yellow_validate_policy", ...),     # Validate policy compliance
    Tool(name="yellow_collect_metrics", ...),     # Collect security metrics
    Tool(name="yellow_generate_report", ...),     # Generate GRC report
]
```

### 2.3 Purple Team (Red-Blue Coordination)

**Goal**: Synchronize red and blue team activities for maximum learning.

#### Purple Team Capabilities

| Component | Purpose | Key Features |
|---|---|---|
| **Coordination Engine** | Sync red & blue timelines | Real-time attack↔detection mapping |
| **AAR Generator** | After Action Reviews | Automated AAR from attack + detection data |
| **Detection Validator** | Validate detections vs attacks | Did blue team detect red team's techniques? |
| **Feedback Loop** | Red→Blue improvement | Gap analysis, detection tuning recommendations |
| **Effectiveness Scorer** | Score detection effectiveness | MTTD, coverage %, false positive rate |
| **Exercise Controller** | Orchestrate purple exercises | Scenario setup, timing, scoring, debrief |

#### Purple Team Workflow

```
1. Exercise Setup
   ├── Purple Team Controller defines scenario
   ├── Red Team (Ciicerone Attack) gets attack objectives
   └── Blue Team gets detection objectives (no attack details)

2. Execution
   ├── Red Team executes attack via Ciicerone Attack
   ├── Blue Team monitors/defends in real-time
   └── Purple Team records timeline of both

3. Assessment
   ├── Map each attack step to detection events
   ├── Calculate MTTD (Mean Time To Detect)
   ├── Calculate MTTR (Mean Time To Respond)
   ├── Score detection coverage per MITRE technique
   └── Identify detection gaps

4. After Action Review
   ├── Generate automated AAR report
   ├── Red Team recommendations (attack improvements)
   ├── Blue Team recommendations (detection tuning)
   └── Shared learnings stored in RAG for future exercises
```

---

## Part 3: Implementation Roadmap

### Phase 1: Ciicerone Attack Integration (Weeks 1-3)

| Week | Task | Deliverable |
|---|---|---|
| 1 | Deploy Ciicerone Attack on Azure VM | `docker-compose.attack.yml`, updated `azure_provision.sh` |
| 1 | Create Ciicerone Attack API client | `ciicerone/integrations/attack_client.py` |
| 2 | Scenario-to-flow mapping | `ciicerone/integrations/attack_mapper.py` |
| 2 | CLI red-team commands | Updated `ciicerone/cli/red_team.py` |
| 3 | Real-time monitoring | WebSocket integration, live attack feed |
| 3 | Config & env integration | Updated `config.yaml`, `.env` template |

### Phase 2: Blue Team Module (Weeks 4-6)

| Week | Task | Deliverable |
|---|---|---|
| 4 | SIEM simulator + log analyzer | `ciicerone/defense/blue_team/siem_simulator.py`, `log_analyzer.py` |
| 4 | IDS detector | `ciicerone/defense/blue_team/ids_detector.py` |
| 5 | Incident response + threat hunter | `incident_response.py`, `threat_hunter.py` |
| 5 | EDR agent + forensics | `edr_agent.py`, `forensics.py` |
| 6 | Blue team MCP tools | Updated `ciicerone/mcp/tools/defense_tools.py` |
| 6 | CLI blue-team commands | `ciicerone/cli/blue_team.py` |

### Phase 3: Yellow Team Module (Weeks 7-8)

| Week | Task | Deliverable |
|---|---|---|
| 7 | Compliance + risk assessment | `compliance_checker.py`, `risk_assessor.py` |
| 7 | Architecture review + policy | `architecture_reviewer.py`, `policy_validator.py` |
| 8 | Awareness training + metrics | `awareness_trainer.py`, `metrics_collector.py` |
| 8 | CLI yellow-team commands | `ciicerone/cli/yellow_team.py` |

### Phase 4: Purple Team Module (Weeks 9-10)

| Week | Task | Deliverable |
|---|---|---|
| 9 | Coordination engine + AAR | `coordination.py`, `aar_generator.py` |
| 9 | Detection validator + feedback | `detection_validator.py`, `feedback_loop.py` |
| 10 | Effectiveness scorer + exercise controller | `effectiveness_scorer.py`, `exercise_controller.py` |
| 10 | CLI purple-team commands | `ciicerone/cli/purple_team.py` |

### Phase 5: Integration & Testing (Weeks 11-12)

| Week | Task | Deliverable |
|---|---|---|
| 11 | End-to-end purple team exercise | Full red→blue→purple workflow test |
| 11 | RAG integration | Store AARs, attack patterns, detections in RAG |
| 12 | Documentation | Updated SECURITY_GUIDE.md, API docs, tutorials |
| 12 | Test suite | Unit tests for all new modules, integration tests |

---

## Part 4: Data Flow Architecture

```
Attack Phase:
  Ciicerone Scenario → Ciicerone Attack Flow → Ciicerone Attack Agents → Attack VM → Target VMs
       ↓                    ↓                ↓
  Audit Log          Flow Status       Agent Decisions
                                          ↓
                                    Attack Timeline

Defense Phase:
  Target VMs → Log Collection → SIEM Simulator → IDS Detector → Alert Triage
       ↓              ↓               ↓              ↓              ↓
  Network Capture  Log Store    Correlation    Detection     Prioritized Alerts
                                                                      ↓
                                                              Incident Response

Purple Phase:
  Attack Timeline ──┐
                     ├──→ Correlation Engine ──→ AAR Generator ──→ RAG Store
  Detection Timeline ┘                    ↓                         ↓
                                  Detection Gaps              Future Exercises
                                  Effectiveness Score
                                  Recommendations
```

---

## Part 5: Key Design Decisions

1. **Ciicerone Attack as external service**: Deploy as Docker Compose stack, communicate via REST/GraphQL API. Don't fork or embed Ciicerone Attack code directly.

2. **Shared Azure infrastructure**: Single Azure VM hosts both Ciicerone Attack and defense tools. Network segmentation separates attack and defense networks.

3. **MCP tool pattern**: All new defensive capabilities exposed as MCP tools, consistent with existing attack tools pattern.

4. **RAG integration**: All After Action Reviews, attack patterns, and detection lessons stored in Ciicerone's existing RAG system for future retrieval.

5. **MITRE ATT&CK as common language**: Red team techniques and blue team detections both mapped to MITRE ATT&CK for correlation.

6. **Scenario-driven**: All exercises start from Ciicerone YAML scenarios. Red team gets attack objectives, blue team gets detection objectives.

7. **Real-time + async**: Live monitoring via WebSocket during exercises, async analysis and reporting post-exercise.

---

## Part 6: New Files Summary

### Integration Files
- `ciicerone/integrations/__init__.py`
- `ciicerone/integrations/attack_client.py` — Ciicerone Attack REST/GraphQL API client
- `ciicerone/integrations/attack.py` — High-level Ciicerone Attack integration wrapper
- `ciicerone/integrations/attack_mapper.py` — Scenario-to-flow mapping
- `docker-compose.attack.yml` — Ciicerone Attack Docker Compose stack

### Defense Modules
- `ciicerone/defense/__init__.py`
- `ciicerone/defense/blue_team/` — 8 modules (SIEM, IDS, EDR, IR, hunting, logs, triage, forensics)
- `ciicerone/defense/yellow_team/` — 6 modules (compliance, architecture, risk, policy, awareness, metrics)
- `ciicerone/defense/purple_team/` — 6 modules (coordination, AAR, validation, feedback, scoring, exercise)
- `ciicerone/defense/shared/` — 3 modules (timeline, correlation)

### CLI Commands
- `ciicerone/cli/red_team.py` — Red team CLI (Ciicerone Attack integration)
- `ciicerone/cli/blue_team.py` — Blue team CLI (defensive operations)
- `ciicerone/cli/yellow_team.py` — Yellow team CLI (GRC)
- `ciicerone/cli/purple_team.py` — Purple team CLI (coordination)

### MCP Tools
- `ciicerone/mcp/tools/defense_tools.py` — Blue team MCP tools
- `ciicerone/mcp/tools/yellow_team_tools.py` — Yellow team MCP tools

### Config
- Updated `config.yaml` — attack, defense sections
- Updated `scripts/azure_provision.sh` — Ciicerone Attack + defense VM provisioning
- Updated `.env` template — Ciicerone Attack API credentials

### Tests
- `tests/unit/test_attack_client.py`
- `tests/unit/test_blue_team.py`
- `tests/unit/test_yellow_team.py`
- `tests/unit/test_purple_team.py`
- `tests/integration/test_attack_e2e.py`

---

## Part 7: Success Metrics

| Metric | Target |
|---|---|
| Ciicerone Attack flow creation from Ciicerone scenario | < 5 seconds |
| Real-time attack monitoring latency | < 2 seconds |
| Blue team detection coverage | > 70% of MITRE techniques |
| Purple team AAR generation | < 30 seconds post-exercise |
| Detection gap identification accuracy | > 80% |
| End-to-end exercise completion | < 60 minutes |
| RAG retrieval for past exercise learnings | < 3 seconds |
