# Maintainer Timelines — Bank Pilot Readiness

**Date:** 2026-07-03
**Status:** Authoritative — supersedes feature-based timelines in `dev-docs/maintainers/MAINTAINERS_OVERVIEW.md`
**Source of truth:** End-to-end blocker audit conducted 2026-07-03 (see "Blocker Audit" section below)
**Goal:** Make Ciicerone deliver a true end-to-end pilot for a traditional bank — red attack → blue detection → purple after-action → compliance-ready report, on infrastructure a bank security team will approve.

---

## Why This Replaces the Old Timelines

The existing maintainer timelines in `dev-docs/maintainers/MAINTAINERS_OVERVIEW.md` allocate 16–24 weeks of **aspirational feature work** per maintainer (e.g. "13 red team features", "12 compliance features"). They are disconnected from the actual state of the codebase and from what a bank pilot requires. Several assigned features target capabilities that already work (e.g. re-assigning "Local Model Support" to Lanre when Ollama is already functional) while the real blockers — no API auth, no persistence, no end-to-end orchestration, no tamper-evident audit — are not owned by anyone.

This document re-baselines every maintainer's timeline against the **verified blockers** from the 2026-07-03 audit. Feature work from the old plans is deferred until pilot-readiness blockers are cleared.

---

## Blocker Audit Summary (2026-07-03)

Five parallel deep audits verified every claim in `docs/community/PILOT_PROGRAMME_COLD_EMAIL.md` against the codebase. Findings, ranked by severity:

### P0 — Showstoppers (cannot run a real bank pilot)

| # | Blocker | Evidence | Primary Owner |
|---|---------|----------|---------------|
| P0-1 | No end-to-end orchestration: `Simulator` is content-generation only; red→blue→purple→report flow does not exist | `core/simulator.py:290-319` — 7 hardcoded LLM-prompt stages, no blue/purple/report imports | Ajibola |
| P0-2 | 6 of 8 color teams missing/stub (Purple=stub, White/Yellow/Green/Orange/Black=missing) | `docs/plans/color-team-architecture-plan.md:21-30`; no `purple_team*.py`, `aar*.py` files | Lanre, Jeremiah, Omolara, DevRel |
| P0-3 | "Six simulation engine paradigms" claim is false — architecture docs contain code examples that don't exist in the codebase | No `EventQueue`, `BoundedRationality`, NetworkX, nashpy, simpy, mesa in `requirements.txt` | Ajibola |
| P0-4 | No API authentication, no RBAC enforcement, wildcard CORS | `api/main.py:63-65` — `allow_origins=["*"]`, no auth middleware, no User/Role models | Ajibola + Ibrahim |
| P0-5 | No tamper-evident audit trail; `AuditLogger` never called in simulation; `EventStore` defaults to `None` and is never instantiated in production | `core/simulator.py:41` `event_store=None`; only 1 `get_audit_logger()` call in codebase | Jeremiah + Ajibola |
| P0-6 | No database persistence — zero ORM models inherit from `Base`; core models are Pydantic dataclasses; no multi-tenant isolation | `db/base.py:39-41` commented-out example; no `tenant_id` columns | Ajibola + Omolara |
| P0-7 | "No data leaves your environment" claim is false — unconditional external HTTP calls for model downloads | `llm/model_manager.py:428`, `llm/providers/llamacpp_provider.py:443` — `requests.get()` with no air-gap flag | Lanre + Omolara |

### P1 — High (would produce embarrassing output in front of bank)

| # | Blocker | Evidence | Primary Owner |
|---|---------|----------|---------------|
| P1-1 | Purple Team AAR is a stub tied to external "Ciicerone Attack" API; no prioritized remediation, no compliance evidence | `integrations/attack_mapper.py:334-361`; no `core/aar_generator.py` | Lanre |
| P1-2 | No end-to-end tests — `tests/full/` has only `__init__.py` | No `test_e2e*.py` files exist | DevRel + all |
| P1-3 | Demo is a manual CLI tour, not an integrated flow — continues on errors, no shared state | `demos/end_to_end/run_e2e_demo.sh:64-71` | DevRel |
| P1-4 | Enterprise integrations (M365, Proofpoint, KnowBe4, Slack, SIEM) are CLI-only, not wired into API or simulation | `deployment/integrations.py` exists but not referenced in `api/main.py` | Ajibola + Omolara |
| P1-5 | Report generation prints "coming soon!" | `cli/main.py:593` | DevRel + Lanre |
| P1-6 | Red Team requires external "Ciicerone Attack" API — not standalone | `cli/red_team.py:239-243` needs `CIICERONE_ATTACK_API_URL`/`TOKEN` | Temi |

### P2 — Medium (limit functionality, fixable during pilot)

| # | Blocker | Evidence | Primary Owner |
|---|---------|----------|---------------|
| P2-1 | Yellow/Green/Orange/White/Black teams entirely absent | `color-team-architecture-plan.md:27-30` | Omolara, DevRel, Lanre, Jeremiah |
| P2-2 | Detection rule generation (Sigma/Splunk/Elastic/Sentinel) works but uses only 8 MITRE techniques and isn't fed by simulation output | `analytics/detection_rules/generator.py:27-106` | David |
| P2-3 | No rate limiting, no secret-management integration (Vault/KMS), no SSO | `api/main.py` — no middleware | Omolara + Ajibola |

---

## What Is Genuinely Ready (No Work Needed)

These are verified working and should not be re-assigned:
- **Blue team simulators** (SIEM/IDS/EDR/IR/forensics/threat hunting) — real logic, MITRE-mapped rules
- **Ollama local LLM provider** — functional with Docker/K8s GPU support
- **Docker/Kubernetes deployment** — production-grade manifests
- **Detection rule generators** (Sigma/Splunk/Elastic/Sentinel) — functional
- **Event sourcing infrastructure** — implemented and unit-tested (just not wired to production)
- **MITRE ATT&CK database** (`intelligence/mitre_attack.py`, 1462 lines)

---

## Maintainer Roster

| # | Maintainer | GitHub | Role | Pilot-Readiness Focus |
|---|-----------|--------|------|----------------------|
| 1 | Temi Adebola | @TemidayoA | Red Team Lead | Standalone red team capability + bank scenario wiring |
| 2 | David Onoja | @ocheme1107 | Blue Team Lead (Advanced) | Wire blue team into orchestrator + detection rule coverage |
| 3 | Ibrahim Hassan | — | Blue Team (Foundation) | RBAC enforcement + blue team persistence |
| 4 | Ajibola Shokunbi | @jiboo2022 | Core Software Lead | Exercise orchestrator + API auth + ORM + event bus |
| 5 | Omolara Oladipupo | @laradipupo | Infrastructure Lead | Air-gap mode + migrations + multi-tenant infra |
| 6 | Lanre Shittu | @Shizoqua | ML/AI Lead | Purple Team AAR + air-gap model downloads + RLHF |
| 7 | Jeremiah Okino | @okino007 | Compliance Lead | Tamper-evident audit + compliance mapping + White Team |
| 8 | DevRel & PR | — | Developer Relations | E2E tests + demo + honest marketing + Black Team |

---

## Phased Timeline (20 Weeks to Bank-Pilot-Ready)

The timeline is organized as a critical path: **foundation → security → orchestration → teams → pilot validation**. Earlier phases block later ones. Parallel work is called out explicitly.

```
Week  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20
      ├── Phase 0: Foundation ──┤
      │                          ├─ Phase 1: Security & Persistence ─┤
      │                          │                                     ├─ Phase 2: Orchestration ────┤
      │                          │                                     │                              ├─ Phase 3: Teams ──┤
      │                          │                                     │                              │                    ├─ Phase 4: Pilot ──┤
```

---

### Phase 0 — Foundation (Weeks 1–4) | BLOCKING

**Goal:** Establish the substrate that all other work depends on. Without ORM models, an event bus, and a wired event store, nothing else can be end-to-end.

#### Ajibola Shokunbi (@jiboo2022) — Critical Path Owner

| Week | Task | Deliverable | Blocks |
|------|------|-------------|--------|
| 1 | ORM declarative base + async session factory | `ciicerone/db/base.py`, `ciicerone/db/session.py` — already scaffolded, make production-usable | All Phase 1 domain models |
| 1–2 | Wire `EventStore` into `Simulator` by default | Edit `core/simulator.py:41` — remove `None` default; instantiate `PostgresEventStore` in `__init__`; emit events on every stage | P0-5 (audit trail) |
| 2–3 | Build shared event bus | `ciicerone/core/event_bus.py` — NEW. Pub/sub for inter-team communication. This is the foundation for the exercise orchestrator (Phase 2) | P0-1, P0-2 |
| 3–4 | Core simulation ORM models | `ciicerone/db/models/simulation.py` — `SimulationResultRecord`, `SimulationStageRecord` mapping to `core/simulator.py:84` | P0-6 |

**Exit criteria:** `Simulator.execute_simulation()` persists results to PostgreSQL and emits events to `EventStore` on every run. Event bus exists and can publish/subscribe.

#### Omolara Oladipupo (@laradipupo) — Support

| Week | Task | Deliverable |
|------|------|-------------|
| 1–2 | PostgreSQL Docker Compose hardening | `docker-compose.yml` — persistence volumes, connection pooling config, health check |
| 3–4 | Alembic migration for core tables | `migrations/versions/003_persistence_layer.py` — `simulation_results`, `simulation_stages` tables |

---

### Phase 1 — Security & Persistence Hardening (Weeks 5–8)

**Goal:** Make the platform something a bank security team will not reject on first review. API auth, multi-tenant isolation, tamper-evident audit, air-gap mode.

#### Ajibola Shokunbi (@jiboo2022) — API Auth & Multi-Tenancy

| Week | Task | Deliverable | Blocks |
|------|------|-------------|--------|
| 5–6 | API authentication middleware | `api/main.py` — add JWT/OAuth2 dependency; add `User` + `Role` + `Tenant` ORM models; remove `allow_origins=["*"]` | P0-4 |
| 7–8 | Multi-tenant isolation | Add `tenant_id` column to all ORM models; add tenant-aware query filtering; add row-level security policies | P0-6 |

**Exit criteria:** All API endpoints require auth. All DB queries are tenant-scoped. CORS is configured to explicit origins.

#### Ibrahim Hassan — RBAC Enforcement

| Week | Task | Deliverable | Blocks |
|------|------|-------------|--------|
| 5–6 | RBAC enforcement layer | `ciicerone/security/rbac.py` — role definitions (admin, analyst, viewer, pilot-sponsor); permission decorators for API endpoints | P0-4 |
| 7–8 | Blue team ORM models + persistence | `ciicerone/db/models/blue_team.py` — replace all unbounded `List[]` buffers in `defense/blue_team/` with DB-backed storage + `deque(maxlen=1000)` cache | P0-6 |

**Exit criteria:** API endpoints enforce role-based permissions. Blue team modules persist alerts/events/incidents to DB.

#### Jeremiah Okino (@okino007) — Tamper-Evident Audit

| Week | Task | Deliverable | Blocks |
|------|------|-------------|--------|
| 5–6 | Implement `DatabaseAuditSink` | `ciicerone/db/models/audit.py` — ORM models mapping to existing `audit.events` and `audit.snapshots` migrations; implement `AuditSink.write()` (currently raises `NotImplementedError` at `core/audit_logger.py:129`) | P0-5 |
| 6–7 | Add hash-chain integrity to audit events | `core/audit_logger.py` — each event includes `prev_hash` + `event_hash` (SHA-256 chain); add verification endpoint | P0-5 |
| 7–8 | Wire audit logging into simulation flow | Edit `core/simulator.py` — call `get_audit_logger()` on every stage start/complete; add MITRE technique IDs and compliance framework tags to events | P0-5 |

**Exit criteria:** Every simulation action emits a tamper-evident, hash-chained audit event with MITRE + compliance mapping. `AuditSink.write()` no longer raises `NotImplementedError`.

#### Lanre Shittu (@Shizoqua) — Air-Gap Mode

| Week | Task | Deliverable | Blocks |
|------|------|-------------|--------|
| 5–6 | Air-gap flag + external HTTP blocking | `ciicerone/llm/model_manager.py` — add `AIR_GAPPED_MODE` config flag; gate all `requests.get()` calls (lines 428, etc.) behind `if not air_gapped`; fail fast with helpful error if model not pre-loaded | P0-7 |
| 6–7 | Pre-baked model bundle | `docker/ollama-models/` — script to pre-pull and bundle models into a Docker image for offline deployment | P0-7 |
| 7–8 | LlamaCPP provider air-gap | `ciicerone/llm/providers/llamacpp_provider.py:443` — gate `requests.get()` behind air-gap flag | P0-7 |

**Exit criteria:** With `AIR_GAPPED_MODE=true`, no external HTTP calls are made. Models load from pre-baked bundle.

#### Omolara Oladipupo (@laradipupo) — Infra Support

| Week | Task | Deliverable |
|------|------|-------------|
| 5–8 | Alembic migrations for all Phase 1 tables | `migrations/versions/004_auth_tenancy.py`, `005_audit_models.py` — coordinate with each maintainer's table definitions |
| 7–8 | Network-level egress controls | K8s network policy + Docker Compose `internal: true` network for air-gapped deployment |

---

### Phase 2 — End-to-End Orchestration (Weeks 9–14)

**Goal:** Build the `ExerciseOrchestrator` that chains red→blue→purple→report. This is the single most critical gap — without it, the platform is a collection of isolated components, not a simulation platform.

#### Ajibola Shokunbi (@jiboo2022) — Orchestrator

| Week | Task | Deliverable | Blocks |
|------|------|-------------|--------|
| 9–11 | Build `ExerciseOrchestrator` | `ciicerone/core/exercise_orchestrator.py` — NEW. Chains: red team attack generation → publish to event bus → blue team subscribes and runs detection → purple team subscribes and generates AAR → black team observes and scores. Implements `ciicerone exercise run --scenario X --teams all` CLI command | P0-1 |
| 11–12 | Wire Simulator output to Blue Team input | Edit `core/simulator.py` — after each stage's LLM content is generated, publish to event bus; blue team modules subscribe and run detection against the content | P0-1 |
| 13–14 | Wire enterprise integrations into API | Add API endpoints for M365/Proofpoint/KnowBe4/Slack/SIEM — currently CLI-only in `deployment/integrations.py` | P1-4 |

**Exit criteria:** `ciicerone exercise run --scenario templates/finance_bec.yaml --teams red,blue,purple` runs end-to-end: generates attack, blue team detects, purple team produces AAR.

#### Temi Adebola (@TemidayoA) — Standalone Red Team

| Week | Task | Deliverable | Blocks |
|------|------|-------------|--------|
| 9–11 | Standalone red team capability | Decouple red team from external "Ciicerone Attack" API. Build `ciicerone/core/red_team_engine.py` — uses the LLM + MCP tools to generate and execute attack scenarios without external dependency. Keep external API as optional enhancement | P1-6 |
| 11–12 | Red team ORM models + persistence | `ciicerone/db/models/red_team.py` — `AttackPlanRecord`, `AttackResultRecord`, `AttackStepRecord` mapping to `vm/models.py` | P0-6 |
| 13–14 | Bank scenario wiring | Ensure `templates/finance_bec.yaml`, `templates/supply_chain_compromise.yaml`, and `templates/zestpayment/zestpayment_payment_fraud.yaml` run through the orchestrator end-to-end | P1-6 |

**Exit criteria:** Red team runs without `CIICERONE_ATTACK_API_URL`. Bank-relevant scenarios execute and feed the event bus.

#### David Onoja (@ocheme1107) — Blue Team Integration

| Week | Task | Deliverable | Blocks |
|------|------|-------------|--------|
| 9–11 | Blue team subscribes to event bus | Edit `defense/blue_team/siem_simulator.py`, `ids_detector.py`, `edr_agent.py` — subscribe to red team events; run detection rules against incoming attack content; publish alerts back to event bus | P0-1 |
| 11–12 | Expand MITRE technique coverage in detection rules | `analytics/detection_rules/generator.py:27-106` — expand from 8 to 30+ techniques; wire detection rule generation to consume simulation output | P2-2 |
| 13–14 | Threat intel ORM models + persistence | `ciicerone/db/models/threat_intel.py` — `ThreatIntelRecord`, `SignatureRecord`, `IOCRecord`; replace canned returns in `intelligence/services.py:411-450` | P0-6 |

**Exit criteria:** Blue team automatically detects red team attacks via event bus subscription. Detection rules cover 30+ MITRE techniques.

#### Lanre Shittu (@Shizoqua) — Purple Team AAR

| Week | Task | Deliverable | Blocks |
|------|------|-------------|--------|
| 9–11 | Build `AARGenerator` | `ciicerone/core/aar_generator.py` — NEW. Subscribes to event bus; consumes red team attack events + blue team detection events; generates after-action report with: detection gaps, MITRE technique coverage, missed detections, response time metrics | P0-2, P1-1 |
| 11–12 | Build Purple Team CLI | `ciicerone/cli/purple_team.py` — NEW. Commands: `ciicerone purple-team aar generate`, `ciicerone purple-team detection validate` | P0-2 |
| 13–14 | RLHF-driven remediation prioritization | `ciicerone/feedback/` — extend the existing orchestrator to score detection gaps by severity + risk; produce prioritized remediation list in AAR | P1-1 |

**Exit criteria:** Purple Team produces a real AAR with prioritized remediation, fed by actual red/blue event bus data.

---

### Phase 3 — Team Completion & Compliance (Weeks 15–18)

**Goal:** Build the remaining color teams and compliance reporting so the platform matches the cold email's claims. These are P2 — important for a full pilot but not showstoppers for a minimal viable one.

#### Jeremiah Okino (@okino007) — White Team + Compliance Reports

| Week | Task | Deliverable | Blocks |
|------|------|-------------|--------|
| 15–16 | White Team: rules of engagement engine | `ciicerone/core/rules_of_engagement.py` — NEW. Scope validation, exercise approval workflow, real-time rule violation monitoring via event bus subscription | P0-2, P2-1 |
| 16–17 | Compliance report generator | `ciicerone/intelligence/compliance_report.py` — NEW. Maps AAR findings to GDPR/PCI-DSS/SOC2/HIPAA controls; generates compliance-ready report. Replaces `cli/main.py:593` "coming soon!" stub | P1-5 |
| 17–18 | Compliance ORM models | `ciicerone/db/models/compliance.py` — `ComplianceRecord`, `DataRetentionRecord`, `ConsentRecord` | P0-6 |

**Exit criteria:** White Team enforces scope. Compliance report generator produces framework-mapped reports from AAR data.

#### Omolara Oladipupo (@laradipupo) — Yellow + Green Teams

| Week | Task | Deliverable | Blocks |
|------|------|-------------|--------|
| 15–16 | Yellow Team: secure build validation | `ciicerone/core/secure_build_engine.py` — NEW. IaC scanning (Terraform/Docker Compose), CIS benchmark checks, infrastructure hardening validation | P0-2, P2-1 |
| 17–18 | Green Team: remediation tracking | `ciicerone/core/remediation_engine.py` — NEW. Consumes Purple Team AAR remediation items; tracks patch/fix status; verifies remediation via re-simulation | P0-2, P2-1 |

**Exit criteria:** Yellow + Green teams exist and participate in the exercise orchestrator.

#### Lanre Shittu (@Shizoqua) — Orange Team

| Week | Task | Deliverable | Blocks |
|------|------|-------------|--------|
| 15–16 | Orange Team: AI-enriched code review + threat modeling | `ciicerone/core/code_review_engine.py` — NEW. LLM-driven SAST, attack surface analysis, threat model generation from codebase | P0-2, P2-1 |

**Exit criteria:** Orange Team exists and can review code for threats.

#### DevRel & PR — Black Team

| Week | Task | Deliverable | Blocks |
|------|------|-------------|--------|
| 15–18 | Black Team: evaluation + benchmarking | `ciicerone/core/evaluation_engine.py` — NEW. Non-interfering observer; scores exercises (detection rate, response time, coverage); produces post-exercise benchmark report | P0-2, P2-1 |

**Exit criteria:** Black Team scores exercises and produces benchmark reports.

---

### Phase 4 — Pilot Validation (Weeks 19–20)

**Goal:** Prove the platform works end-to-end with real tests, a real demo, and honest marketing materials. This is the gate before approaching any bank.

#### DevRel & PR — Tests, Demo, Marketing

| Week | Task | Deliverable | Blocks |
|------|------|-------------|--------|
| 19 | End-to-end integration test | `tests/full/test_e2e_exercise.py` — NEW. Runs `ciicerone exercise run --scenario templates/finance_bec.yaml --teams all`; asserts: attack generated, blue team detected, AAR produced, compliance report generated, audit trail tamper-evident, all persisted to DB | P1-2 |
| 19 | Rewrite demo as integrated flow | `demos/end_to_end/run_e2e_demo.sh` — replace 19 separate CLI commands with single `ciicerone exercise run` invocation; add assertions; fail on errors instead of continuing | P1-3 |
| 20 | Update cold email + README to match reality | Edit `docs/community/PILOT_PROGRAMME_COLD_EMAIL.md` and `README.md` — align claims with actual capabilities. Either keep eight-teams/six-paradigms claims (now true after Phases 0–3) or hedge them | All P0/P1 |

**Exit criteria:** E2E test passes. Demo runs as single command. Marketing materials match codebase reality.

#### All Maintainers — Final Integration

| Week | Task | Deliverable |
|------|------|-------------|
| 20 | Bank pilot dry-run | Each maintainer runs the full e2e flow against their domain; verify no domain-specific breakage; sign off on pilot readiness |

---

## Per-Maintainer Timeline Summary

### 1. Temi Adebola (@TemidayoA) — Red Team Lead

| Phase | Weeks | Focus | Key Deliverables |
|-------|-------|-------|------------------|
| 0 | 1–4 | Wait for Ajibola's event bus + ORM foundation | — |
| 1 | 5–8 | Wait for security/persistence hardening | — |
| 2 | 9–14 | **Standalone red team + bank scenario wiring** | `core/red_team_engine.py`, `db/models/red_team.py`, decoupled from external API |
| 3 | 15–18 | Support Orange Team (attack surface analysis) | Coordinate with Lanre |
| 4 | 19–20 | Pilot dry-run + sign-off | Verify BEC/supply-chain scenarios run e2e |

**Old timeline:** 16 weeks, 13 features (aspirational)
**New timeline:** 12 active weeks (9–20), 3 critical deliverables (pilot-grounded)

---

### 2. David Onoja (@ocheme1107) — Blue Team Lead (Advanced)

| Phase | Weeks | Focus | Key Deliverables |
|-------|-------|-------|------------------|
| 0 | 1–4 | Wait for event bus + ORM | — |
| 1 | 5–8 | Wait for Ibrahim's blue team persistence | Coordinate on `db/models/blue_team.py` schema |
| 2 | 9–14 | **Wire blue team to event bus + expand detection coverage** | Event bus subscriptions in all 8 blue team modules; MITRE coverage 8→30+; `db/models/threat_intel.py` |
| 3 | 15–18 | Support Purple/White team integration | Coordinate with Lanre (AAR consumes blue alerts) + Jeremiah (compliance maps detections) |
| 4 | 19–20 | Pilot dry-run + sign-off | Verify blue team detects BEC scenario automatically |

**Old timeline:** 12–16 weeks, 7 features
**New timeline:** 12 active weeks (9–20), 3 critical deliverables

---

### 3. Ibrahim Hassan — Blue Team (Foundation)

| Phase | Weeks | Focus | Key Deliverables |
|-------|-------|-------|------------------|
| 0 | 1–4 | Wait for ORM foundation | — |
| 1 | 5–8 | **RBAC enforcement + blue team persistence** | `security/rbac.py`, `db/models/blue_team.py`; replace unbounded `List[]` buffers |
| 2 | 9–14 | Support David's event bus wiring | Coordinate on blue team subscription architecture |
| 3 | 15–18 | Support White Team (auth/RBAC feeds RoE enforcement) | Coordinate with Jeremiah |
| 4 | 19–20 | Pilot dry-run + sign-off | Verify RBAC enforced on all endpoints |

**Old timeline:** 8–12 weeks, 8 features
**New timeline:** 16 active weeks (5–20), 2 critical deliverables + support

---

### 4. Ajibola Shokunbi (@jiboo2022) — Core Software Lead

| Phase | Weeks | Focus | Key Deliverables |
|-------|-------|-------|------------------|
| 0 | 1–4 | **ORM + event store wiring + event bus** | `db/base.py`, `db/session.py`, `core/event_bus.py`; wire `EventStore` into `Simulator` |
| 1 | 5–8 | **API auth + multi-tenancy** | JWT/OAuth2 middleware, `User`/`Role`/`Tenant` models, `tenant_id` on all tables, RLS |
| 2 | 9–14 | **Exercise orchestrator + integration wiring** | `core/exercise_orchestrator.py`; wire Simulator→Blue Team via event bus; API endpoints for integrations |
| 3 | 15–18 | Support all teams (orchestrator is substrate) | — |
| 4 | 19–20 | Pilot dry-run + sign-off | Verify full e2e flow |

**Old timeline:** 20–24 weeks, 13 features
**New timeline:** 20 active weeks (1–20), 7 critical deliverables — **Ajibola is the critical path owner**

---

### 5. Omolara Oladipupo (@laradipupo) — Infrastructure Lead

| Phase | Weeks | Focus | Key Deliverables |
|-------|-------|-------|------------------|
| 0 | 1–4 | **PostgreSQL hardening + core migrations** | Docker Compose PG config, `migrations/003_persistence_layer.py` |
| 1 | 5–8 | **Migrations for auth/tenancy/audit + egress controls** | `migrations/004_auth_tenancy.py`, `005_audit_models.py`; K8s network policies for air-gap |
| 2 | 9–14 | Support orchestrator (infra for multi-team exercises) | — |
| 3 | 15–18 | **Yellow + Green teams** | `core/secure_build_engine.py`, `core/remediation_engine.py` |
| 4 | 19–20 | Pilot dry-run + sign-off | Verify air-gapped deployment works |

**Old timeline:** 20–24 weeks, 8 features
**New timeline:** 20 active weeks (1–20), 5 critical deliverables

---

### 6. Lanre Shittu (@Shizoqua) — ML/AI Lead

| Phase | Weeks | Focus | Key Deliverables |
|-------|-------|-------|------------------|
| 0 | 1–4 | Wait for ORM/event bus | — |
| 1 | 5–8 | **Air-gap mode for model downloads** | `AIR_GAPPED_MODE` flag in `model_manager.py` + `llamacpp_provider.py`; pre-baked model bundle |
| 2 | 9–14 | **Purple Team AAR + RLHF remediation** | `core/aar_generator.py`, `cli/purple_team.py`; RLHF-driven prioritization in `feedback/` |
| 3 | 15–16 | **Orange Team** | `core/code_review_engine.py` |
| 4 | 19–20 | Pilot dry-run + sign-off | Verify AAR generates from real e2e run |

**Old timeline:** 16–20 weeks, 10 features
**New timeline:** 16 active weeks (5–20), 4 critical deliverables

---

### 7. Jeremiah Okino (@okino007) — Compliance Lead

| Phase | Weeks | Focus | Key Deliverables |
|-------|-------|-------|------------------|
| 0 | 1–4 | Wait for ORM + audit migrations | — |
| 1 | 5–8 | **Tamper-evident audit + wire into simulation** | `db/models/audit.py`, `DatabaseAuditSink`; hash-chain integrity; MITRE + compliance tags in events |
| 2 | 9–14 | Support orchestrator (audit events from all teams) | Coordinate with Ajibola on event bus audit subscription |
| 3 | 15–18 | **White Team + compliance report generator** | `core/rules_of_engagement.py`, `intelligence/compliance_report.py`; `db/models/compliance.py` |
| 4 | 19–20 | Pilot dry-run + sign-off | Verify audit trail is tamper-evident and compliance-mapped |

**Old timeline:** 16–20 weeks, 12 features
**New timeline:** 16 active weeks (5–20), 4 critical deliverables

---

### 8. DevRel & PR — Developer Relations

| Phase | Weeks | Focus | Key Deliverables |
|-------|-------|-------|------------------|
| 0 | 1–4 | Wait for foundation | — |
| 1 | 5–8 | Wait for security hardening | — |
| 2 | 9–14 | Document orchestrator + new CLI commands | Update `docs/guides/` with `ciicerone exercise run` usage |
| 3 | 15–18 | **Black Team: evaluation + benchmarking** | `core/evaluation_engine.py`; exercise scoring + benchmark reports |
| 4 | 19–20 | **E2E tests + demo rewrite + honest marketing** | `tests/full/test_e2e_exercise.py`; rewrite `run_e2e_demo.sh`; update cold email + README |

**Old timeline:** 16–20 weeks, 15 features
**New timeline:** 12 active weeks (9–20), 4 critical deliverables

---

## Critical Path

```
Ajibola (Phase 0: ORM + Event Bus + Event Store)
  │
  ├── BLOCKS ──→ Ibrahim (Phase 1: RBAC + Blue persistence)
  ├── BLOCKS ──→ Jeremiah (Phase 1: Audit models + tamper-evidence)
  ├── BLOCKS ──→ Ajibola (Phase 1: API auth + multi-tenancy)
  │
  └── All Phase 1 ──→ Ajibola (Phase 2: Exercise Orchestrator) ── CRITICAL PATH
                        │
                        ├── Temi (Phase 2: Standalone red team)
                        ├── David (Phase 2: Blue team event bus subscription)
                        ├── Lanre (Phase 2: Purple Team AAR)
                        │
                        └── All Phase 2 ──→ Phase 3 (Teams) ──→ Phase 4 (Pilot validation)
```

**Ajibola is the single point of failure for the first 14 weeks.** If his Phase 0 or Phase 2 work slips, the entire timeline slips. Consider pairing him with Omolara on the event bus and with Ibrahim on the API auth to de-risk.

---

## Dependency Matrix

| Upstream | Downstream | Artifact |
|----------|-----------|----------|
| Ajibola (ORM base) | All maintainers (domain models) | `db/base.py` declarative base |
| Ajibola (event bus) | Temi, David, Lanre, Jeremiah | `core/event_bus.py` pub/sub |
| Ajibola (API auth) | Ibrahim (RBAC enforcement) | JWT/OAuth2 middleware + User/Role models |
| Ibrahim (RBAC) | Jeremiah (White Team RoE) | Permission decorators |
| Jeremiah (audit sink) | All maintainers (audit emission) | `DatabaseAuditSink` interface |
| Ajibola (orchestrator) | Temi, David, Lanre | `ExerciseOrchestrator` that teams plug into |
| Temi (red team engine) | David (blue team detection) | Attack events on event bus |
| David (blue team alerts) | Lanre (Purple AAR) | Detection events on event bus |
| Lanre (AAR) | Jeremiah (compliance report) | AAR with detection gaps + remediation |
| All Phase 2 | DevRel (e2e test) | Working end-to-end flow to test |

---

## What Gets Unblocked at Each Phase

| Phase | Unblocks | Audit Findings Resolved |
|-------|----------|------------------------|
| 0 | Persistence, event sourcing, event bus | P0-1 (substrate), P0-5 (event store wired), P0-6 (ORM exists) |
| 1 | API security, multi-tenancy, audit, air-gap | P0-4 (auth/RBAC), P0-5 (tamper-evident audit), P0-6 (multi-tenant), P0-7 (air-gap) |
| 2 | End-to-end orchestration, standalone red, blue integration, purple AAR | P0-1 (orchestration), P0-2 (purple team), P1-1 (AAR), P1-4 (integrations), P1-6 (standalone red) |
| 3 | All 8 color teams, compliance reports | P0-2 (all teams), P0-3 (paradigms — see note below), P1-5 (reports), P2-1 (teams) |
| 4 | Proven e2e, honest marketing | P1-2 (e2e tests), P1-3 (demo) |

### Note on P0-3 (Six Simulation Paradigms)

The "six paradigms" claim (DES, ABM, GAP, GTE, CRE, HME) is false — the architecture docs contain code examples that don't exist in the codebase. Building all six is 4–6 months of work on its own and is **not required for a bank pilot**. The recommendation is:

- **Phase 4:** DevRel updates the cold email and README to replace "six simulation engine paradigms" with accurate claims: "LLM-powered multi-stage attack simulation with MITRE ATT&CK mapping, event-sourced audit trail, and blue team detection validation."
- **Post-pilot (future):** If paradigms are desired, they become a separate roadmap after pilot validation. DES and ABM are the highest-value paradigms for bank scenarios (wire-fraud timing, agent-based insider threat).

---

## Success Criteria — "Bank-Pilot-Ready" Definition of Done

A traditional bank pilot can proceed when ALL of the following are true:

1. **`ciicerone exercise run --scenario templates/finance_bec.yaml --teams red,blue,purple,white,black`** runs end-to-end without errors and produces:
   - Red team attack content (BEC wire-fraud scenario)
   - Blue team detection results (SIEM/IDS/EDR alerts)
   - Purple team after-action report with prioritized remediation
   - White team rules-of-engagement validation
   - Black team exercise score + benchmark report
2. **All API endpoints require authentication** and enforce RBAC (admin/analyst/viewer roles)
3. **All data is persisted to PostgreSQL** with `tenant_id` isolation; no in-memory-only state
4. **Every simulation action emits a tamper-evident, hash-chained audit event** with MITRE technique IDs and compliance framework tags
5. **`AIR_GAPPED_MODE=true` blocks all external HTTP calls**; models load from pre-baked bundle
6. **`tests/full/test_e2e_exercise.py` passes** — proving the above end-to-end
7. **Cold email and README match actual capabilities** — no false claims

---

## Post-Pilot Roadmap (Not in This Timeline)

Deferred until after pilot validation:
- Six simulation engine paradigms (DES, ABM, GAP, GTE, CRE, HME) — 4–6 months
- Advanced RLHF reward model training — 2–3 months
- UI/dashboard (referenced in `docs/plans/ui-engineering-plan.md`) — 3–4 months
- Quantum threat simulation layer (referenced in `docs/plans/cyber-threat-simulation-engine-plan.md`) — 2–3 months
- Multi-region deployment — 1–2 months
- SSO/SAML integration (Azure AD/Entra ID) — 1–2 months (can overlap with pilot if bank demands it)
