# Django Rewrite — Software Development Lifecycle Plan

Status: **In progress — Milestone 1 shipped** (2026-10-22)
Supersedes: cost/effort estimate from backend-state review ($1.5–2.5M, 7–9 months, full greenfield).
Approach: **strangler-fig, not big-bang** — the FastAPI stack stays the production system while the
Django app (`vorsyghta/django_apps/`, project package `server/`) grows route-by-route. This cuts
the estimated rewrite cost by ~40–60% versus greenfield, because the frontend API contract, DB
schema, and deployment tooling are preserved.

---

## 1. Phase gates (SDLC)

| Phase | Gate to exit | Status |
|---|---|---|
| **0. Inception** | Rewrite approved; strangler-fig chosen over big-bang (cost + risk) | DONE |
| **1. Environment gate** | `.venv` + Poetry resolve to repo-local env; `pip check` clean; deps sync (`poetry install --extras dev --extras test`) | DONE |
| **2. Scaffolding** | `server/` project, fail-closed settings (`VORSYGHTA_SECRET_KEY` required, no default — closes AUDIT C1 pattern), custom `AUTH_USER_MODEL`, DRF + SimpleJWT wired | DONE |
| **3. Model port (M1 slice)** | `accounts` (Tenant, User) + `audit` (hash-chained AuditEvent) + `api_health` apps; migrations generated; `migrate` green; `manage.py check` clean | DONE |
| **4. API slice (M1)** | `/health/`, `/ready/`, `/auth/register/` (role forced `viewer` — closes self-registration escalation), `/auth/token/*`, `/audit/events/` (auth required — fail-closed) | DONE |
| **5. Verification** | pytest-django suite (8 contract tests) green; existing FastAPI unit suite still green (parallel systems) | IN PROGRESS |
| **6. SDLC artifact** | This document | DONE |
| **7. VCS** | Commit + push milestone 1 to `origin/master` | PENDING |

## 2. Requirements traceability (security invariants carried over)

| Invariant | Source | Django implementation | Test |
|---|---|---|---|
| Fail-closed JWT signing key (C1) | AUDIT_STATE 2026-08-16 | `server/settings.py` raises at import if `VORSYGHTA_SECRET_KEY` unset | settings import gate |
| Self-registration privilege escalation closed | AUDIT_STATE "Verified-good controls" | `RegisterView` forces `role="viewer"`, ignores payload role | `test_register_forces_viewer_role` |
| Audit reads authenticated (fail-closed, C2 class) | AUDIT_STATE C2 | DRF default `IsAuthenticated`; `test_audit_events_require_auth` | `test_audit_events_require_auth` |
| Tamper-evident audit trail | README / audit middleware | `AuditEvent.save()` computes `sha256(prev_hash+…)` chain; `verify_chain()` | `test_audit_hash_chain_invariant` |
| Password hashing (bcrypt) | AUDIT_STATE verified-good | Django `set_password` hashers + validators (min 12, common, numeric) | `test_weak_registration_password_rejected` |
| DB parity (Postgres via `DATABASE_URL`) | docker-compose.yml | `_database_from_url()` maps Postgres/SQLite; same `DATABASE_URL` env | `test_ready_ok` |

## 3. Migration map (FastAPI → Django)

| FastAPI surface | Django target | Milestone |
|---|---|---|
| `/health`, `/ready` | `api_health` views | M1 (done) |
| `/auth/register`, `/auth/token`, JWT | `accounts` + SimpleJWT | M1 (done) |
| `/audit/events` | `audit` app | M1 (done) |
| 33 SQLAlchemy tables | Django models, app-per-domain (teams, intelligence, tooling) | M2–M3 |
| 136 endpoints / 16 routers | DRF routers + viewsets, parity URLs under `/api/` | M2–M5 |
| `VMSafetyController` / fail-closed gate | unchanged Python module, imported by Django layer (no rewrite — reuse per AGENTS.md prime guardrail) | M4 |
| `GuardrailsEngine`, `LLMManager` | reused as-is (framework-agnostic core) | M4 |
| Stripe billing router | `billing` app (models + webhooks) | M5 |
| Alembic 001–004 | Django migrations (single source of truth from M6; FastAPI stack frozen read-only) | M6 |
| Frontend `VORSYGHTA_API_URL` | unchanged (URL parity); proxy cutover only | M6 |

## 4. Effort / cost (strangler-fig, revised)

Original greenfield estimate: 28–36 weeks, $1.5–2.5M. Strangler-fig revision:

- **M1 (done)**: scaffold + auth/health/audit slice — 2 engineer-weeks.
- **M2**: model port for teams/intelligence/tooling — 6 engineer-weeks.
- **M3**: DRF CRUD parity for 6 highest-traffic routers — 8 engineer-weeks.
- **M4**: reuse safety/guardrails/LLM core behind Django services — 4 engineer-weeks.
- **M5**: billing + integrations parity — 5 engineer-weeks.
- **M6**: migration cutover, frontend proxy, frozen FastAPI — 3 engineer-weeks.
- **M7**: hardening (rate limiting, CORS policy, security review vs AUDIT_STATE), load test — 4 engineer-weeks.

Total: ~32 engineer-weeks ≈ 1 senior team (3 eng) for ~10–11 calendar weeks.
Blended cost at $150–220/h ≈ **$180k–$285k** — versus $1.5–2.5M greenfield.

## 5. Quality gates per milestone

1. `poetry install --extras dev --extras test` green; `pip check` clean.
2. `manage.py makemigrations --check` (no drift); `manage.py check` clean.
3. New pytest-django suite green; existing FastAPI suite green until M6 cutover.
4. No new `>=`-unpinned direct deps without lock reconciliation (`poetry lock`).
5. Security invariants table (§2) — every row must have a passing test before cutover.

## 6. Rollback plan

Strangler-fig keeps both stacks deployable until M6. Cutover is a reverse-proxy
configuration change (`VORSYGHTA_API_URL` → Django app), reversible in one
deploy. FastAPI stack is frozen, not deleted, until M7 exit review.
