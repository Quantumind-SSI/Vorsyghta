# Persistence Layer Fix — Maintainer Assignment

**Goal:** Eliminate root cause #1 from the end-to-end audit — the complete absence of a database persistence layer. Every flow currently loses data on restart.

**Source audit:** `docs/plans/end-to-end-audit.md` section 1.1

---

## Maintainer Roster (from `dev-docs/maintainers/MAINTAINERS_OVERVIEW.md`)

| # | Maintainer | GitHub | Role |
|---|-----------|--------|------|
| 1 | Temi Adebola | @TemidayoA | Red Team Lead |
| 2 | David Onoja | @ocheme1107 | Blue Team Lead (Advanced) |
| 3 | Ibrahim Hassan | — | Blue Team (Foundation) |
| 4 | Ajibola Shokunbi | @jiboo2022 | Core Software Lead |
| 5 | Omolara Oladipupo | @laradipupo | Infrastructure Lead |
| 6 | Lanre Shittu | @Shizoqua | ML/AI Lead |
| 7 | Jeremiah Okino | @okino007 | Compliance Lead |
| 8 | DevRel & PR | — | Developer Relations |

---

## Work Breakdown

The persistence layer fix has three phases. Phase 1 is a hard dependency — nothing else can proceed until the ORM foundation exists. Phases 2 and 3 can be parallelized across maintainers by domain.

### Phase 1: ORM Foundation (BLOCKING — must complete first)

**Owner: Ajibola Shokunbi (@jiboo2022) — Core Software Lead**

This is core infrastructure work that directly aligns with Ajibola's assigned features: Core Architecture Redesign (#2), Event Sourcing Architecture (#11), and Data Processing Pipeline (#8).

| Task | Deliverable | Files |
|------|-------------|-------|
| SQLAlchemy declarative base + engine config | `ciicerone/db/base.py` — declarative base, async engine factory, session factory | New file |
| Async session management | `ciicerone/db/session.py` — `get_session()` async context manager, connection pooling config | New file |
| Database health check | `ciicerone/db/health.py` — ping DB on startup, fail fast with helpful error | New file |
| Event sourcing wiring | Wire `core/event_sourcing.py` `PostgresEventStore` to actually emit events from the simulator. Currently the `Event` class and `EventStore` exist but the simulator never calls them. | Edit `core/simulator.py`, `core/event_sourcing.py` |
| DB package init | `ciicerone/db/__init__.py` — exports | New file |

**Why Ajibola:** Event Sourcing Architecture is explicitly feature #11 in his assignment. The ORM base is core architecture (feature #2). He owns the simulator's internals.

**Support from Omolara Oladipupo (@laradipupo):** Database connection pooling tuning, Docker Compose PostgreSQL configuration, migration runner setup. This aligns with her Infrastructure Lead role (Container Orchestration #1, Monitoring #3).

---

### Phase 2: Domain ORM Models (PARALLEL — after Phase 1)

Each maintainer creates SQLAlchemy ORM models for their domain. Models map to new database tables. All models inherit from the declarative base Ajibola creates in Phase 1.

#### 2A. Red Team / Attack Simulation Models

**Owner: Temi Adebola (@TemidayoA) — Red Team Lead**

Aligns with his Attack Scenario Generator (#1) and MITRE ATT&CK Integration (#2).

| Model | Maps to Pydantic model | Table | Source file with in-memory data |
|-------|----------------------|-------|-------------------------------|
| `AttackPlanRecord` | `vm/models.py:AttackPlan` | `attack_plans` | `vm/agent.py:313` — result never saved |
| `AttackResultRecord` | `vm/models.py:AttackResult` | `attack_results` | `vm/agent.py:313` |
| `AttackStepRecord` | `vm/models.py:AttackStep` | `attack_steps` | `vm/agent.py:347` |
| `AgentStateRecord` | `vm/models.py:AgentState` | `agent_states` | `vm/agent.py:255` |
| `ScenarioRecord` | Red team scenario models | `red_team_scenarios` | New — part of Temi's Attack Scenario Generator feature |

**Wiring tasks (also Temi):**
- `vm/agent.py:execute_attack` — save `AttackResult` to DB after `_generate_report()` returns
- `vm/agent.py:execute_attack` — save `AgentState` snapshots per step for replay
- CLI `vm.py:run_attack` — fetch saved attack results by ID from DB

**Deliverable:** `ciicerone/db/models/red_team.py`

#### 2B. Blue Team Models (Foundation)

**Owner: Ibrahim Hassan — Blue Team (Foundation)**

Aligns with his Security Operations Dashboard (#3), Threat Hunting Framework (#6), and Incident Response Integration (#3).

| Model | Maps to source | Table | Source file with in-memory data |
|-------|---------------|-------|-------------------------------|
| `SIEMLogRecord` | `defense/blue_team/siem_simulator.py:147` | `siem_logs` | `_logs: List[Dict]` — unbounded |
| `SIEMAlertRecord` | `defense/blue_team/siem_simulator.py:148` | `siem_alerts` | `_alerts: List[SIEMAlert]` — unbounded |
| `IDSAlertRecord` | `defense/blue_team/ids_detector.py:169` | `ids_alerts` | `_packet_log: List[NetworkPacket]` — unbounded |
| `EDREventRecord` | `defense/blue_team/edr_agent.py:141-145` | `edr_events` | 5 unbounded lists |
| `HuntResultRecord` | `defense/blue_team/threat_hunter.py:142` | `hunt_results` | `_results: List[HuntResult]` — unbounded |
| `IncidentRecord` | `defense/blue_team/incident_response.py` | `incidents` | Currently a stub — needs implementation + persistence |
| `ForensicArtifactRecord` | `defense/blue_team/forensics.py:62-63` | `forensic_artifacts` | `_artifacts: List[ForensicArtifact]` — unbounded |
| `AlertTriageRecord` | `defense/blue_team/alert_triage.py:75` | `alert_triage` | `_triaged: List[TriagedAlert]` — unbounded |

**Wiring tasks (also Ibrahim):**
- Replace all unbounded `List[]` buffers with DB-backed storage + `deque(maxlen=1000)` for recent-item cache
- `defense/blue_team/siem_simulator.py:ingest_log` — write to `siem_logs` table instead of in-memory list
- `defense/blue_team/threat_hunter.py:_execute_hunt` — persist hunt results to DB
- `defense/blue_team/incident_response.py` — implement incident workflow with DB state tracking (currently a stub)

**Deliverable:** `ciicerone/db/models/blue_team.py`

#### 2C. Blue Team Models (Advanced)

**Owner: David Onoja (@ocheme1107) — Blue Team Lead (Advanced)**

Aligns with his Advanced Threat Intelligence Integration (#2), Signature-Based Detection (#3), and Blue Team Analytics Engine (#5).

| Model | Maps to source | Table | Source file with in-memory data |
|-------|---------------|-------|-------------------------------|
| `ThreatIntelRecord` | `intelligence/services.py:411-450` | `threat_intelligence` | Currently returns canned objects — needs real feed integration + persistence |
| `SignatureRecord` | `blue_team/signature_detection/` (David's planned module) | `detection_signatures` | New — part of David's signature detection feature |
| `IOCRecord` | Red team IOC generation (Temi's feature, David consumes) | `indicators_of_compromise` | Cross-domain — David reads, Temi writes |
| `AnalyticsResultRecord` | `analytics/__init__.py` | `blue_team_analytics` | Currently computed on-demand, not stored |

**Wiring tasks (also David):**
- `intelligence/services.py:ThreatIntelligenceService` — replace canned return objects with real feed queries + DB persistence
- Blue team analytics engine — persist analytics results for historical comparison

**Deliverable:** `ciicerone/db/models/threat_intel.py`

**Coordination with Temi:** IOC records are written by red team (IOC generation) and read by blue team (signature detection). Temi creates the writer, David creates the reader. Both use the same `IOCRecord` model.

#### 2D. Core Simulation Models

**Owner: Ajibola Shokunbi (@jiboo2022) — Core Software Lead**

Aligns with his Data Processing Pipeline (#8) and Advanced Caching Strategy (#12).

| Model | Maps to source | Table | Source file with in-memory data |
|-------|---------------|-------|-------------------------------|
| `SimulationResultRecord` | `core/simulator.py:84` | `simulation_results` | In-memory only — lost on return |
| `SimulationStageRecord` | `core/simulator.py` stage data | `simulation_stages` | In-memory only |
| `CampaignRecord` | `deployment/__init__.py:799` | `campaigns` | In-memory |
| `CampaignMetricRecord` | `deployment/__init__.py:696` | `campaign_metrics` | `self.metrics_storage = {}` — dict, lost on restart |
| `DeploymentRecord` | `deployment/__init__.py` | `deployment_records` | In-memory |

**Wiring tasks (also Ajibola):**
- `core/simulator.py:execute_simulation` — save `SimulationResult` and all stages to DB
- `deployment/__init__.py:ThreatMetricsCollector` — replace `self.metrics_storage = {}` with DB writes
- `deployment/__init__.py:ThreatDeploymentEngine` — persist campaign and deployment records
- Wire template loading: `core/simulator.py` should load scenarios from `ScenarioRecord` (DB) or YAML (file), not create from scratch

**Deliverable:** `ciicerone/db/models/simulation.py`, `ciicerone/db/models/campaign.py`

#### 2E. Intelligence Models

**Owner: Ibrahim Hassan + David Onoja (shared)**

Ibrahim owns threat hunting (which consumes intelligence), David owns threat intelligence integration (which produces it).

| Model | Maps to source | Table | Source file with in-memory data |
|-------|---------------|-------|-------------------------------|
| `IntelligenceProfileRecord` | `intelligence/models.py:IntelligenceProfile` | `intelligence_profiles` | `intelligence/integrations.py:48` — dict cache |
| `CompanyIntelligenceRecord` | `intelligence/models.py:CompanyIntelligence` | `company_intelligence` | Dict cache |
| `OSINTResultRecord` | `intelligence/models.py:OSINTResult` | `osint_results` | Dict cache |

**Wiring tasks:**
- `intelligence/integrations.py:IntelligenceEngine` — replace `self.intelligence_cache = {}` with DB-backed cache
- `intelligence/integrations.py:LLMIntelligenceIntegrator` — wire LLM analysis into pipeline and persist analysis results (currently exists but never called)
- `intelligence/services.py:LinkedInIntelligence` — either implement real API integration or remove the stub and mark the model as `data_available: False` in DB

**Deliverable:** `ciicerone/db/models/intelligence.py`

**Split:** David creates the models and writers (threat intel production). Ibrahim creates the readers and hunting queries (threat intel consumption).

#### 2F. Quantum Assessment Models

**Owner: Lanre Shittu (@Shizoqua) — ML/AI Lead**

The quantum layer is AI/math-adjacent and Lanre owns model management. While quantum isn't explicitly in his feature list, it's the best fit since it involves algorithmic assessment models.

| Model | Maps to source | Table | Source file with in-memory data |
|-------|---------------|-------|-------------------------------|
| `QuantumAssessmentRecord` | `quantum/agent.py:247` | `quantum_assessments` | Returned but never saved |
| `CryptoInventoryRecord` | `quantum/crypto_scanner.py` | `crypto_inventories` | Scan results not persisted |
| `MigrationPlanRecord` | `quantum/pqc_migration_planner.py` | `pqc_migration_plans` | Plans not persisted |
| `Y2QTimelineRecord` | `quantum/timeline_simulator.py` | `y2q_timelines` | Timelines not persisted |

**Wiring tasks (also Lanre):**
- `api/routers/quantum.py:get_inventory` — replace placeholder return with DB query (currently returns static dict)
- `api/routers/quantum.py:assess` — persist assessment results to DB after computation
- `quantum/agent.py:full_assessment` — save all 5 component results to DB

**Deliverable:** `ciicerone/db/models/quantum.py`

#### 2G. Compliance & Audit Models

**Owner: Jeremiah Okino (@okino007) — Compliance Lead**

Aligns with his GDPR (#1), HIPAA (#2), and audit framework features. Also owns the `AuditSink` base class that currently raises `NotImplementedError`.

| Model | Maps to source | Table | Source file |
|-------|---------------|-------|------------|
| `AuditEventRecord` | `core/audit_logger.py:AuditEvent` | `audit.events` (migration already exists!) | `core/audit_logger.py:129` — `AuditSink.write()` raises NotImplementedError |
| `AuditSnapshotRecord` | `core/audit_logger.py` | `audit.snapshots` (migration already exists!) | Same |
| `ComplianceRecordRecord` | `compliance/` (Jeremiah's planned modules) | `compliance_records` | New |
| `DataRetentionRecord` | GDPR/HIPAA data retention | `data_retention_policies` | New |
| `ConsentRecord` | GDPR consent management | `consent_records` | New |

**Wiring tasks (also Jeremiah):**
- `core/audit_logger.py:AuditSink` — implement `DatabaseAuditSink` that writes to `audit.events` table (migration already exists, just needs the model + writer)
- `core/audit_logger.py` — replace `MemoryAuditSink` as default with `DatabaseAuditSink`
- Wire audit logging into all flows (simulation, attack, intelligence, deployment) — every action that modifies state should emit an audit event

**Deliverable:** `ciicerone/db/models/audit.py`, `ciicerone/db/models/compliance.py`

**Key advantage:** The migrations for `audit.events` and `audit.snapshots` already exist in `migrations/versions/`. Jeremiah just needs to create the ORM models that map to them and implement the sink.

---

### Phase 3: Infrastructure & Migrations (PARALLEL with Phase 2)

**Owner: Omolara Oladipupo (@laradipupo) — Infrastructure Lead**

Aligns with her CI/CD Pipeline Infrastructure (#2), Infrastructure as Code (#5), and Monitoring & Observability (#3).

| Task | Deliverable | Details |
|------|-------------|---------|
| Alembic migration for all new tables | `migrations/versions/XXX_persistence_layer.py` | One migration adding all tables from Phase 2. Coordinate with each maintainer to get their table definitions. |
| Docker Compose PostgreSQL config | `docker-compose.yml` | Ensure PostgreSQL service is configured with persistence (volume mount), proper credentials, and health check |
| Connection pooling configuration | `ciicerone/db/session.py` config | Pool size, max overflow, pool timeout, pool recycling — configurable via env vars |
| Database backup/restore scripts | `scripts/db_backup.sh`, `scripts/db_restore.sh` | For production deployments |
| Migration runner in CI/CD | `.github/workflows/` or CI config | Run migrations automatically on deploy |
| Database monitoring | Prometheus metrics for DB | Connection count, query latency, pool utilization |

**Why Omolara:** All database infrastructure (migrations, Docker config, connection pooling, backups, monitoring) is infrastructure work. She owns the deployment and operations layer.

---

### Phase 4: Documentation (After Phase 2-3)

**Owner: DevRel & PR Maintainer**

| Task | Deliverable |
|------|-------------|
| Database schema documentation | `docs/architecture/DATABASE_SCHEMA.md` — ERD, table descriptions, relationships |
| Persistence layer setup guide | `docs/admin-guides/database-setup.md` — PostgreSQL install, migration commands, backup config |
| Update API documentation | Document which endpoints now persist data and how to retrieve historical results |
| Update maintainer onboarding | Update each maintainer's implementation guide with persistence tasks |

---

## Dependency Graph

```
Phase 1 (Ajibola — ORM Foundation)
  │
  ├── Phase 2A (Temi — Red Team models)
  ├── Phase 2B (Ibrahim — Blue Team foundation models)
  ├── Phase 2C (David — Threat intel models)
  ├── Phase 2D (Ajibola — Core simulation models)
  ├── Phase 2E (Ibrahim+David — Intelligence models)
  ├── Phase 2F (Lanre — Quantum models)
  ├── Phase 2G (Jeremiah — Audit/compliance models)
  │
  ├── Phase 3 (Omolara — Migrations & infrastructure) — depends on all Phase 2 models
  │
  └── Phase 4 (DevRel — Documentation) — depends on Phase 3
```

## Cross-Maintainer Coordination Points

1. **IOC flow:** Temi writes IOC records (red team generation) → David reads them (blue team signature detection). Both must agree on `IOCRecord` schema. **Ajibola mediates** as core lead.

2. **Threat intelligence flow:** David writes threat intel records (feed integration) → Ibrahim reads them (threat hunting). Both must agree on `ThreatIntelRecord` schema.

3. **Audit logging:** Jeremiah's `DatabaseAuditSink` must be called by all other maintainers' flows. Each maintainer adds audit event emission to their wiring tasks. **Jeremiah provides the interface, each maintainer integrates it.**

4. **Event sourcing:** Ajibola's event store must be called by the simulator. Temi's attack agent should also emit events. **Ajibola provides the `EventStore` interface, Temi integrates it into `execute_attack`.**

5. **Migration generation:** Omolara needs all table definitions from Phase 2 maintainers to generate the Alembic migration. Each maintainer must deliver their `models.py` file before Omolara can run `alembic revision --autogenerate`.

## Estimated Timeline

| Phase | Owner(s) | Duration | Blocking? |
|-------|---------|----------|-----------|
| Phase 1 | Ajibola | 1-2 weeks | Yes — blocks all Phase 2 |
| Phase 2 | All 7 maintainers (parallel) | 2-3 weeks | No — parallel by domain |
| Phase 3 | Omolara | 1 week | Depends on Phase 2 completion |
| Phase 4 | DevRel | 1 week | Depends on Phase 3 |
| **Total** | | **5-7 weeks** | |

## What This Unblocks

From the end-to-end audit, fixing the persistence layer unblocks:
- **8 critical flow breaks** (all the "results never stored" findings)
- **12 unbounded memory issues** (replaced with DB-backed storage + bounded caches)
- **The event sourcing gap** (Event class exists but unused — now wired)
- **The audit sink stub** (NotImplementedError → DatabaseAuditSink)
- **The quantum inventory placeholder endpoint** (static dict → DB query)
- **The campaign metrics in-memory dict** (→ DB writes)
- **The intelligence cache dict** (→ DB-backed cache)

That's **40+ findings** from the audit resolved by this one root cause fix.
