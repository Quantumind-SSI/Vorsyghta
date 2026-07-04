# Ciicerone Maintainer Task Briefs & Timeline

**Source:** `dev-docs/maintainers/ThreatScene/maintainers/*_IMPLEMENTATION.md`
**Source of truth:** `docs/plans/maintainer-timelines-bank-pilot-readiness.md`
**Date:** 2026-07-03

This document distills each maintainer's atomic task plan into simple briefs and a consolidated timeline for the 20-week bank-pilot-readiness critical path.

---

## Project Overview

**Goal:** Make Ciicerone deliver a true end-to-end bank pilot: red attack → blue detection → purple after-action → compliance-ready report, on infrastructure a bank security team will approve.

**Total timeline:** 20 weeks

**Phases:**
- **Phase 0 — Foundation (Weeks 1–4):** ORM, event store, event bus
- **Phase 1 — Security & Persistence (Weeks 5–8):** API auth, multi-tenancy, tamper-evident audit, air-gap
- **Phase 2 — Orchestration (Weeks 9–14):** Exercise orchestrator, standalone red team, blue team integration, Purple AAR
- **Phase 3 — Teams & Compliance (Weeks 15–18):** White, Yellow, Green, Orange, Black teams + compliance reports
- **Phase 4 — Pilot Validation (Weeks 19–20):** E2E tests, demo, honest marketing, dry-run

**Critical path owner:** Ajibola Shokunbi (Core Software Lead)

---

## 1. Ajibola Shokunbi — Core Software Lead

- **GitHub:** @jiboo2022
- **Color Team:** Infrastructure / Yellow
- **Active weeks:** 1–20 (full timeline)
- **Focus:** Application-layer substrate that all other maintainers depend on

| Task | Weeks | Brief | Key Deliverables | Blocker Resolved |
|------|-------|-------|------------------|------------------|
| AJIBOLA-001 | 1 | Productionize ORM base and session factory | `db/base.py`, `db/session.py`, `db/health.py`, common columns mixin | P0-6 (no DB persistence) |
| AJIBOLA-002 | 1–2 | Wire EventStore into Simulator by default | `core/simulator.py` emits events; `PostgresEventStore` instantiated | P0-5 (event store unused) |
| AJIBOLA-003 | 2–3 | Build shared event bus | `core/event_bus.py` pub/sub | P0-1, P0-2 (no inter-team communication) |
| AJIBOLA-005 | 3–4 | Core simulation ORM models | `db/models/simulation.py`, `db/models/campaign.py` | P0-6 (no persisted simulation data) |
| AJIBOLA-004 | 5–6 | API authentication middleware | `api/main.py` JWT/OAuth2, `User`/`Role`/`Tenant` models, remove wildcard CORS | P0-4 (no auth) |
| AJIBOLA-006 | 7–8 | Multi-tenant isolation | `db/tenant_filter.py`, `TenantMiddleware`, tenant-scoped queries | P0-6 (no tenant isolation) |
| AJIBOLA-007 | 9–11 | Build Exercise Orchestrator | `core/exercise_orchestrator.py`, `cli/exercise.py`, `db/models/exercise.py` | P0-1 (no end-to-end flow) |
| AJIBOLA-008 | 11–12 | Wire Simulator output to Blue Team via event bus | `core/simulator.py` publishes stage events; blue team consumes | P0-1 (red→blue gap) |
| AJIBOLA-009 | 13–14 | Wire enterprise integrations into API | `api/routers/integrations.py` | P1-4 (CLI-only integrations) |
| AJIBOLA-010 | 19–20 | Pilot dry-run and sign-off | Full e2e verification | P1-2 (no e2e tests) |

---

## 2. Omolara Oladipupo — Infrastructure Lead

- **GitHub:** @laradipupo
- **Color Team:** Yellow / Green
- **Active weeks:** 1–20
- **Focus:** Deployment-layer infrastructure, migrations, air-gap, Yellow/Green teams

| Task | Weeks | Brief | Key Deliverables | Blocker Resolved |
|------|-------|-------|------------------|------------------|
| OMOLARA-001 | 1–2 | Harden PostgreSQL Docker Compose | `docker-compose.yml` persistence, health checks, pool config; backup/restore scripts | P0-6 (DB infra not production-ready) |
| OMOLARA-002 | 3–4 | Alembic migration for persistence layer | `migrations/versions/003_persistence_layer.py` | P0-6 (no migrations for new tables) |
| OMOLARA-003 | 5–8 | Migrations for auth, tenancy, audit, all domain tables | `migrations/versions/004_auth_tenancy.py`, `005_audit_models.py`, etc. | P0-4, P0-5, P0-6 |
| OMOLARA-004 | 7–8 | Network-level egress controls | K8s network policies, Docker Compose `internal` networks for air-gap | P0-7 (external HTTP calls) |
| OMOLARA-005 | 15–16 | Yellow Team: secure build validation | `core/secure_build_engine.py` — IaC scanning, CIS benchmarks, hardening validation | P0-2, P2-1 (Yellow missing) |
| OMOLARA-006 | 17–18 | Green Team: remediation tracking | `core/remediation_engine.py` — tracks AAR remediation items, re-simulation verification | P0-2, P2-1 (Green missing) |
| OMOLARA-007 | 19–20 | Pilot dry-run and sign-off | Verify air-gapped deployment, migrations, backups | P1-2 (no e2e tests) |

---

## 3. Ibrahim Hassan — Blue Team (Foundation)

- **GitHub:** —
- **Color Team:** Blue
- **Active weeks:** 5–20
- **Focus:** RBAC enforcement, blue team persistence, threat hunting, dark web monitoring

| Task | Weeks | Brief | Key Deliverables | Blocker Resolved |
|------|-------|-------|------------------|------------------|
| IBRAHIM-001 | 5–6 | Build RBAC enforcement layer | `security/rbac.py`, `require_permission()` decorator, role→permission mapping | P0-4 (no RBAC) |
| IBRAHIM-002 | 7–8 | Blue team ORM models and persistence | `db/models/blue_team.py`; replace in-memory `List[]` with DB + bounded `deque` caches | P0-6 (no blue team persistence) |
| IBRAHIM-003 | 9–14 | Support event bus wiring persistence | Review DAVID-001 `bus_integration.py`; ensure alerts persist to DB | P0-1 (blue team not connected) |
| IBRAHIM-004 | 9–12 | Threat hunting framework (API + event bus) | Threat hunting API, automated hypothesis generation, IOC search, event bus wiring | P0-1 (blue team not connected) |
| IBRAHIM-005 | 11–14 | Dark web monitoring module | Credential leak detection, breach DB search, payment data exposure, source code leak detection, ransomware monitoring | P0-1 (missing capability) |
| IBRAHIM-006 | 15–18 | White Team auth/RBAC integration | Coordinate with Jeremiah; add `APPROVE_EXERCISE` permission; cross-tenant blocking | P0-2 (White Team missing) |
| IBRAHIM-007 | 19–20 | Pilot dry-run and sign-off | RBAC, persistence, threat hunting, dark web, tenant isolation verification | P1-2 (no e2e tests) |

---

## 4. David Onoja — Blue Team Lead (Advanced)

- **GitHub:** @ocheme1107
- **Color Team:** Blue
- **Active weeks:** 9–20
- **Focus:** Wire blue team modules into orchestrator + expand detection coverage

| Task | Weeks | Brief | Key Deliverables | Blocker Resolved |
|------|-------|-------|------------------|------------------|
| DAVID-001 | 9–11 | Wire blue team modules to event bus | `defense/blue_team/bus_integration.py`; SIEM/IDS/EDR/threat hunter/IR/alert triage subscribe to red team events | P0-1 (blue team isolated) |
| DAVID-002 | 11–12 | Expand MITRE ATT&CK coverage in detection rules | `analytics/detection_rules/generator.py` 8 → 30+ techniques; wire to orchestrator | P2-2 (only 8 techniques) |
| DAVID-003 | 13–14 | Threat intel ORM models + persistence | `db/models/threat_intel.py`; replace canned returns in `intelligence/services.py` | P0-6 (no persistence) |
| DAVID-004 | 15–18 | Support Purple/White team integration | Coordinate with Lanre (AAR consumes blue alerts) and Jeremiah (compliance maps detections) | P0-2 (teams missing) |
| DAVID-005 | 19–20 | Pilot dry-run and sign-off | Verify BEC scenario detection via event bus | P1-2 (no e2e tests) |

---

## 5. Temi Adebola — Red Team Lead

- **GitHub:** @TemidayoA
- **Color Team:** Red
- **Active weeks:** 9–20
- **Focus:** Standalone red team engine + bank scenario wiring

| Task | Weeks | Brief | Key Deliverables | Blocker Resolved |
|------|-------|-------|------------------|------------------|
| TEMI-001 | 9–11 | Build standalone red team engine | `core/red_team_engine.py`; decouple from external "Ciicerone Attack" API | P1-6 (red team requires external API) |
| TEMI-002 | 11–12 | Red team ORM models + persistence | `db/models/red_team.py` — `AttackPlanRecord`, `AttackResultRecord`, etc. | P0-6 (no persistence) |
| TEMI-003 | 13–14 | Wire bank-relevant scenarios to orchestrator | Run BEC, supply-chain, payment fraud scenarios through orchestrator | P0-1 (no end-to-end orchestration) |
| TEMI-004 | 15–16 | Support Orange Team attack surface analysis | Coordinate with Lanre; feed red team patterns to Orange Team threat modeling | P0-2 (Orange missing) |
| TEMI-005 | 19–20 | Pilot dry-run and sign-off | Verify BEC/supply-chain scenarios run e2e without external API | P1-2 (no e2e tests) |

---

## 6. Lanre Shittu — ML/AI Lead

- **GitHub:** @Shizoqua
- **Color Team:** Purple / Orange
- **Active weeks:** 5–20
- **Focus:** Air-gap mode, Purple Team AAR, Orange Team

| Task | Weeks | Brief | Key Deliverables | Blocker Resolved |
|------|-------|-------|------------------|------------------|
| LANRE-001 | 5–6 | Air-gap mode for model downloads | Gate external `requests.get()` in `llm/model_manager.py` and `llamacpp_provider.py` | P0-7 (external HTTP calls) |
| LANRE-002 | 6–7 | Pre-baked model bundle for offline deployment | `docker/ollama-models/`, `scripts/build_airgap_bundle.sh` | P0-7 (no offline models) |
| LANRE-005 | 7–8 | LlamaCPP provider air-gap | Gate `requests.get()` in `llm/providers/llamacpp_provider.py` | P0-7 (external HTTP calls) |
| LANRE-003 | 9–11 | Build Purple Team AAR generator | `core/aar_generator.py`, `cli/purple_team.py`, `db/models/aar.py` | P0-2, P1-1 (Purple stub) |
| LANRE-004 | 13–14 | RLHF-driven remediation prioritization | `feedback/` integration with AAR remediation items | P1-1 (AAR limitations) |
| LANRE-006 | 15–16 | Orange Team: AI-enriched code review + threat modeling | `core/code_review_engine.py` | P0-2, P2-1 (Orange missing) |
| LANRE-007 | 19–20 | Pilot dry-run and sign-off | Verify air-gap + AAR + Orange Team e2e | P1-2 (no e2e tests) |

---

## 7. Jeremiah Okino — Compliance Lead

- **GitHub:** @okino007
- **Color Team:** White
- **Active weeks:** 5–20
- **Focus:** Tamper-evident audit, White Team, compliance reports

| Task | Weeks | Brief | Key Deliverables | Blocker Resolved |
|------|-------|-------|------------------|------------------|
| JEREMIAH-001 | 5–6 | Implement DatabaseAuditSink and audit ORM models | `db/models/audit.py`, `db/audit_sink.py` | P0-5 (AuditSink raises NotImplementedError) |
| JEREMIAH-002 | 6–7 | Hash-chain integrity and tamper detection | `core/audit_verifier.py`, `api/routers/audit.py` | P0-5 (no tamper evidence) |
| JEREMIAH-003 | 7–8 | Wire audit logging into simulation flow | `core/simulator.py`, `core/exercise_orchestrator.py` emit audit events with MITRE + compliance tags | P0-5 (audit logger never called) |
| JEREMIAH-004 | 9–14 | Compliance mapping framework | `core/compliance_mapper.py` maps MITRE techniques to GDPR/PCI-DSS/SOC2/HIPAA controls | P0-5 (no compliance mapping) |
| JEREMIAH-005 | 15–16 | White Team rules of engagement engine | `core/rules_of_engagement.py` — scope validation, exercise approval, real-time violation monitoring | P0-2, P2-1 (White Team missing) |
| JEREMIAH-006 | 16–17 | Compliance report generator | `intelligence/compliance_report.py` — framework-mapped reports from AAR data | P1-5 (report stub) |
| JEREMIAH-007 | 17–18 | Compliance ORM models | `db/models/compliance.py` — `ComplianceRecord`, `DataRetentionRecord`, `ConsentRecord` | P0-6 (no compliance persistence) |
| JEREMIAH-008 | 19–20 | Pilot dry-run and sign-off | Verify audit trail, compliance reports, White Team e2e | P1-2 (no e2e tests) |

---

## 8. DevRel & PR — Developer Relations

- **GitHub:** —
- **Color Team:** Black / Community
- **Active weeks:** 9–20
- **Focus:** E2E tests, demo, honest marketing, Black Team, documentation

| Task | Weeks | Brief | Key Deliverables | Blocker Resolved |
|------|-------|-------|------------------|------------------|
| DEVREL-005 | 9–14 | Document orchestrator and team integration | Docs for `ciicerone exercise run` and team participation | P1-3 (demo/manual docs) |
| DEVREL-004 | 15–18 | Black Team evaluation engine | `core/evaluation_engine.py` — non-interfering observer, exercise scoring, benchmark reports | P0-2, P2-1 (Black Team missing) |
| DEVREL-001 | 19 | End-to-end integration test | `tests/full/test_e2e_exercise.py` — full red→blue→purple→white→black→report flow | P1-2 (no e2e tests) |
| DEVREL-002 | 19 | Rewrite demo as integrated single-command flow | Rewrite `demos/end_to_end/run_e2e_demo.sh` to use `ciicerone exercise run` | P1-3 (demo is manual CLI tour) |
| DEVREL-003 | 20 | Update cold email and README to match reality | `docs/community/PILOT_PROGRAMME_COLD_EMAIL.md`, `README.md` | All P0/P1 (false claims) |
| DEVREL-006 | 20 | Pilot dry-run and sign-off | E2E test passes, demo runs, marketing is accurate | P1-2 (no e2e tests) |

---

## Consolidated 20-Week Timeline

```
Week:  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20
       ├────── Phase 0 ──────┤
       │ Ajibola: ORM/EventStore/EventBus/Simulation models
       │ Omolara: PG hardening + core migrations
       │
       │                    ├────── Phase 1 ──────┤
       │                    │ Ajibola: API auth + multi-tenancy
       │                    │ Ibrahim: RBAC + blue persistence
       │                    │ Jeremiah: Audit sink + hash chain + sim wiring
       │                    │ Lanre: Air-gap mode + pre-baked model bundle
       │                    │ Omolara: Migrations + egress controls
       │
       │                                          ├────── Phase 2 ──────────┤
       │                                          │ Ajibola: Orchestrator + integrations
       │                                          │ Temi: Standalone red team + scenarios
       │                                          │ David: Blue team event bus + detection coverage
       │                                          │ Lanre: Purple AAR + RLHF
       │                                          │ Jeremiah: Compliance mapping
       │                                          │ DevRel: Orchestrator docs
       │
       │                                                                    ├────── Phase 3 ──────┤
       │                                                                    │ Jeremiah: White Team + compliance reports
       │                                                                    │ Omolara: Yellow + Green teams
       │                                                                    │ Lanre: Orange Team
       │                                                                    │ Temi: Orange support
       │                                                                    │ David: Purple/White support
       │                                                                    │ DevRel: Black Team
       │
       │                                                                                          ├────── Phase 4 ──────┤
       │                                                                                          │ DevRel: E2E test + demo + marketing
       │                                                                                          │ All: Pilot dry-run + sign-off
```

---

## Key Dependency Chains

1. **Foundation chain:** `AJIBOLA-001` → `AJIBOLA-002` → `AJIBOLA-003` → `AJIBOLA-005` → all other Phase 1+ tasks
2. **Security chain:** `AJIBOLA-004` → `IBRAHIM-001` → `JEREMIAH-005` (White Team)
3. **Persistence chain:** `AJIBOLA-001` → `AJIBOLA-005` → `IBRAHIM-002` → `DAVID-003` / `TEMI-002`
4. **Orchestration chain:** `AJIBOLA-007` → `TEMI-003` / `DAVID-001` / `LANRE-003` / `DEVREL-004`
5. **Air-gap chain:** `LANRE-001` → `LANRE-002` / `OMOLARA-004`
6. **Audit chain:** `JEREMIAH-001` → `JEREMIAH-002` → `JEREMIAH-003` → `JEREMIAH-004` / `JEREMIAH-006`

---

## Critical Success Criteria

All maintainers converge on these Week 19–20 exit criteria:

1. `ciicerone exercise run --scenario templates/finance_bec.yaml --teams red,blue,purple,white,black` runs end-to-end.
2. All API endpoints require authentication and enforce RBAC.
3. All data is persisted to PostgreSQL with `tenant_id` isolation.
4. Every simulation action emits a tamper-evident, hash-chained audit event.
5. `AIR_GAPPED_MODE=true` blocks all external HTTP calls.
6. `tests/full/test_e2e_exercise.py` passes.
7. Cold email and README match actual capabilities.

---

## Notes

- All old feature-based timelines are superseded by this blocker-grounded plan.
- Feature work from the old plans is deferred until pilot-readiness blockers are cleared.
- Ajibola is the single point of failure for Weeks 1–14; consider pairing with Omolara and Ibrahim to de-risk.
