# Backend State — Living Document

> **Purpose.** Authoritative snapshot of the Vorsyghta backend's engineering state: what is production-ready, what runs only on happy paths, which lazy-initialization paths exist, and which production-grade pattern should replace each. Updated as development moves on (protocol in §9).
>
> **Standard applied.** Production-ready patterns, design, and implementation only. No happy-path-only code, no lazy paths in production flows. Findings are measured (file:line evidence) — anything unverified is flagged.
>
> **Related (point-in-time) docs:** `docs/plans/end-to-end-audit.md` (2026-06-28 findings), `docs/plans/gap-analysis.md` (2026-06-28), `docs/architecture/TEAM_ARCHITECTURE.md` (design). This document supersedes those where findings are re-verified here.

---

## 1. Verdict (as of 2026-10-21, snapshot 2)

Core request path **verified production-ready end-to-end**: event store attached at startup (persisted-replay smoke), DB engine eagerly initialized in lifespan and disposed on shutdown, Redis Streams fan-out + supervised team workers wired into the API process with DLQ routing, and all hand-rolled lazy singletons cut over to the `@lru_cache(maxsize=1)` idiom. Remaining: deferred-import migration (in flight this snapshot), `LocalLLMProvider.__del__` cosmetic guard, broker consumer-group semantics pending validation against real Redis, coverage growth.

## Previous verdict (snapshot 1)

The backend is **structurally production-ready in its core request path** — FastAPI app, SQLAlchemy persistence with migrations, hash-chained audit, RBAC on sensitive routes, Stripe entitlement gating, fail-closed safety gate — and **verified end-to-end for the event pipeline** as of this snapshot (event store factory was dead-on-arrival before 2026-10-21; fixed and smoke-tested).

Remaining production gaps, in priority order:

1. **Redis Streams broker + TeamWorkers are not wired into the API process** (`core/broker/`, `core/worker/` are exercised only inside exercise runs). Stream fan-out across processes does not happen for API activity.
2. **Worker DLQ is a placeholder** — `core/worker/base.py:31-34` swallows handler exceptions (`except Exception: pass`). Poison events are dropped silently.
3. **`RedisStreamsBroker` has no `close()`** — loop-bound aioredis client leak risk (`core/broker/redis_broker.py:38-41`).
4. **35% line coverage** — broad behavior is tested (809 passing), but half the backend is unexercised by tests.
5. Pattern debt: 14 module-level lazy singletons (§6), 258 function-level imports (§6), several first-request constructions that should be eager in the composition root (§5).

---

## 2. Evidence Snapshot

| Metric | Value | Source |
|---|---|---|
| Unit tests | **809 passed**, 48s (excl. `tests/unit/test_auth_flow.py`: 11 tests require Docker testcontainers; unavailable on this machine — environment, not code) | `pytest tests/unit --ignore=tests/unit/test_auth_flow.py`, 2026-10-21 |
| Coverage | 35% lines (`htmlcov/`, `coverage.xml` regenerated each run) | same run |
| API routes | 123 `APIRoute`s at import | `vorsyghta/api/main.py` app scan |
| Migrations | 4 (`migrations/versions/`: 001 events, 002 snapshots, 003 persistence layer, 004 stripe billing) | directory listing |
| TODO/FIXME markers | **0** in `vorsyghta/**/*.py` | grep 2026-10-21 |
| `NotImplementedError` sites | 10, all legitimate: abstract interface methods (`vm/operator.py:728-746` `BaseHypervisor`, `core/audit_logger.py:141` `AuditSink.write`) or fail-closed config guards (`deployment/__init__.py:350,592`) | grep + read |
| Event-store wiring | Startup attach → publish → durable replay verified (smoke test, 2026-10-21): `SqliteEventStore`, `event_type=red_team.attack_stage`, `version=1`; Postgres scheme normalization verified by socket dial | this session |
| Working tree | Uncommitted: `vorsyghta/api/main.py`, `vorsyghta/api/routers/exercise.py`, `vorsyghta/core/contracts/event_store_port.py` (event-store startup wiring + factory fixes); other modified files predate this work | `git status` 2026-10-21 |
| Last commit | `f0c092e` merge: frontend design system, 2026-10-16 | `git log` |

---

## 3. Component State Matrix

Statuses: **PROD-READY** (production patterns, verified) · **READY-WITH-CONFIG** (works; requires credentials/infrastructure) · **PARTIAL** (real but with measured gaps) · **NOT-WIRED** (exists, not in the serving path) · **UNASSESSED** (not re-verified this snapshot).

| Subsystem | Status | Evidence / notes |
|---|---|---|
| FastAPI app, routers, middleware, CORS | PROD-READY | 123 routes; `AuditMiddleware` hash-chain; billing-required route hiding (`main.py:150-190`) |
| Persistence (SQLAlchemy + Alembic) | PROD-READY | `db/models/` ORM models, `db/base.py` engine + `dispose_engine()` on shutdown, 4 migrations, `/ready` gates on DB health. Supersedes end-to-end-audit §1.1 ("zero ORM models" — outdated) |
| Event bus + event store | PROD-READY | `core/event_bus.py` (async pub/sub, best-effort persist), `core/contracts/event_store_port.py` factory. **Fixed 2026-10-21:** Postgres branch called nonexistent `.initialize()` (`create()` already initializes schema) and `postgresql+asyncpg://` DSNs misrouted to SQLite. Store attaches in `lifespan` startup via `get_event_bus()`; orchestrator's `_ensure_event_store` remains fallback |
| Redis Streams broker + TeamWorkers | NOT-WIRED | `core/broker/redis_broker.py`, `core/worker/{base,teams}.py` function only inside exercise flow. No API-process consumer lifecycle; no `close()`; DLQ placeholder (`worker/base.py:31-34`) |
| Exercise orchestrator + 8 color teams | PROD-READY (in-exercise scope) | `core/exercise_orchestrator.py`, team modules subscribe to shared bus; blue-detection is real SIEM/IDS/EDR consumption (TEAM_ARCHITECTURE.md); covered by unit + integration tests |
| LLM layer | PARTIAL | `llm/manager.py` + 8 providers + fallback chain, all guarded for optional deps. Cosmetic defect: `LocalLLMProvider.__del__` references `_is_loaded` before it exists (`llm/providers/local_base.py:316`, observed in smoke logs) |
| Safety (VMSafetyController, VMOperator fail-closed) | PROD-READY | Canonical asset per AGENTS.md; lab-network allowlist + external denylist; not bypassed this session |
| LLM guardrails (GuardrailsEngine) | PROD-READY | Canonical asset per AGENTS.md (`llm/guardrails.py`) |
| Audit logging | PROD-READY | `core/audit_logger.py`: sinks, hash-chain wrap in prod env, flush/close on shutdown |
| RBAC / auth | PROD-READY | `security/rbac.py` deps on all sensitive routes (verified via billing route-map test); JWT config checks in `/ready`. Auth flow tests are Docker-gated (environment) |
| Billing (Stripe) | PROD-READY | `integrations/stripe_billing.py` (`@lru_cache` service), webhooks, entitlement gating, migration 004; billing unit tests green |
| RAG / vector store | READY-WITH-CONFIG | `rag/vectorstore.py` — correct asyncio DCL singleton; requires Neo4j/embedding backend |
| Deployment / campaign (email/SMS) | READY-WITH-CONFIG | Fail-closed `NotImplementedError` when provider unconfigured (`deployment/__init__.py:350,592`) — correct behavior, needs credentials |
| Quantum threat layer | UNASSESSED | Router exists (`api/routers/quantum.py`); gap-analysis (2026-06-28) lists the layer as missing — re-verification pending |
| CLI | PROD-READY (operator tooling) | `cli/` — feedback loop, rag, deploy commands |

---

## 4. Production-Pattern Standard (in-repo exemplars)

These are the **approved patterns** — all already proven in this codebase. New backend code MUST use these; code in §5/§6 migrates toward them.

| Concern | Approved pattern | Exemplar |
|---|---|---|
| Process-wide sync singleton | `@lru_cache(maxsize=1)` accessor | `integrations/stripe_billing.py:369` |
| Async singleton | double-checked lock with `asyncio.Lock` | `rag/vectorstore.py:1150` |
| Construction & lifecycle | **Eager in composition root** (`lifespan`) → `app.state` → `Depends` consumers; close on shutdown | `main.py` `get_simulator`/`get_llm_manager`; `dispose_engine()` |
| Init-once with failure tolerance | idempotent `ensure_*()` or async context-manager lifecycle | `intelligence/mitre_attack.py:356-447` (init state machine), `postgres_event_store.py:__aenter__` |
| Threading lock in async code | PROHIBITED unless no `await` in critical section and documented; prefer `asyncio.Lock` | current violations in §6 |
| Optional heavy dependency | function-level import inside try/except with capability flag | `postgres_event_store.py:14-22` (`ASYNCPG_AVAILABLE`) |
| Deferred construction of I/O clients | constructor injection from `lifespan`; explicit `close()` | `dispose_engine` pattern; **gap:** `RedisStreamsBroker` has no `close()` |
| Fail-closed on missing config | raise with actionable message | `deployment/__init__.py:350`, `vm/operator.py` gate |

---

## 5. Lazy-Path Register (production flows affected)

Each row: current lazy path → required production replacement. Ordered by blast radius.

| # | Site | Current lazy behavior | Required replacement |
|---|---|---|---|
| 1 | `api/routers/exercise.py:46` | Module-level `EventBus()` at import; store attaches at startup (fixed 2026-10-21); import-time warning fires before lifespan | **DONE 2026-10-21 (store at startup)**; bus construction stays module-level by design (lightweight pub/sub registry; test harness uses ASGITransport without lifespan). Import-time warning → OPEN item #6 |
| 2 | `api/routers/disclosure.py:23`, `engagement.py:24` | `_manager` built on first request, no lock | **FIXED 2026-10-21** — `@lru_cache(maxsize=1)` accessors (thread-safe memoization, test-compatible without lifespan) |
| 3 | `api/routers/quantum.py:68` | Heavy `QuantumThreatAgent` on first request | **FIXED 2026-10-21** — `@lru_cache(maxsize=1)` accessor |
| 4 | `api/routers/secrets.py:31`, `sso.py:92-93` | Env-dependent providers parsed on first request; misconfiguration surfaces as request-time 404/500 | **FIXED 2026-10-21** — `@lru_cache(maxsize=1)` accessors; `SecretManager.from_env()` cannot raise (env provider is always the final fallback) |
| 5 | `core/tool_server_client.py:279`, `intelligence/threat_hunting.py:422` | Plain lazy singletons | **FIXED 2026-10-21** — `@lru_cache(maxsize=1)` accessors |
| 6 | `core/audit_logger.py:421`, `safety/content_filter.py:677` | `threading.Lock` DCL in async app | **FIXED 2026-10-21** — both converted to cached accessors; `reset_audit_logger()` uses `cache_clear` (test-fixture compatible); `set_global_filter` kept as explicit override seam |
| 7 | `db/base.py:208-230` | Engine + session factory created on first DB touch | **FIXED 2026-10-21** — `initialize_engine()` called from lifespan startup (fail-fast at boot); accessors remain as test/CLI fallback. Plain `sqlite://` URLs now normalize to `sqlite+aiosqlite://` |
| 8 | `core/broker/redis_broker.py:43` | aioredis client created on first publish; **no `close()`** | **FIXED 2026-10-21** — `aclose()` added; broker constructed + closed in lifespan; supervised workers started/cancelled at shutdown; poison messages dead-lettered to `dlq.<topic>` |
| 9 | `core/exercise_orchestrator.py:100` (`_store_attach_attempted`) | Once-flag lazy attach | **Fallback only** (startup attaches first). Kept as defense-in-depth for non-API entry points |
| 10 | `llm/providers/local_base.py:136` family (`_is_loaded`) | Model load on first generate | Appropriate for model lifecycle — keep; `__del__` guard still OPEN (§7 item 5) |
| 11 | `core/redis_client.py:19` | Per-call retry until reachable | **KEPT BY DESIGN** (readiness endpoint reflects it) |
| 12 | `aws_secrets_manager.py:19`, `config/loader.py:107`, `llm/providers_new.py:86` | Memoized client/config attributes | Harmless memoization; convert to constructor injection when touched |
| 13 | `core/worker/base.py` `_consume` | Handler failures silently swallowed (`except: pass`) | **FIXED 2026-10-21** — failures route to DLQ (`dlq.<topic>`), supervisor restarts crashed workers with backoff; regression-tested (`tests/unit/test_worker_dlq.py`) |

## 6. Deferred-Import Debt

258 function-level `vorsyghta` imports across 59 files. **Legitimate subsets:** optional-dependency guards (try/except around `asyncpg`, `torch`, `transformers`, `llama-cpp`) and genuine circular breaks. **Debt:** everything else — cargo-culted startup deferral and cycle-papering. Rule going forward: a function-level import must carry a comment naming its reason (optional dep / cycle break); otherwise move to module top. Structural fix for cycles: extract shared types, not mid-function imports.

## 7. Happy-Path Register (measured this snapshot)

| # | Finding | Status |
|---|---|---|
| 1 | Event-store factory Postgres branch dead (`store.initialize()` nonexistent) + `postgresql+asyncpg://` misrouting | **FIXED 2026-10-21** (`core/contracts/event_store_port.py:261-269`), smoke-verified |
| 2 | API events unpersisted until first exercise run | **FIXED 2026-10-21** (`api/main.py` lifespan attach, `api/routers/exercise.py:get_event_bus`) |
| 3 | Worker DLQ placeholder — handler exceptions silently dropped (`core/worker/base.py`) | **FIXED 2026-10-21** — handler failures publish to `dlq.<topic>` (DLQ observer wired), supervisor restarts crashed workers; `tests/unit/test_worker_dlq.py` regression tests |
| 4 | `RedisStreamsBroker` no `close()` (`core/broker/redis_broker.py`) | **FIXED 2026-10-21** — `aclose()` added; lifespan closes broker after cancelling workers; poison (undecodable) messages dead-lettered to `dlq.<topic>` |
| 5 | `LocalLLMProvider.__del__` AttributeError on partially-initialized provider (`llm/providers/local_base.py`) | **FIXED 2026-10-21** — guarded with `getattr(self, "_is_loaded", False)` |
| 6 | Import-time "persistence disabled" bus warning (`core/event_bus.py`) fired on every API boot before lifespan attach | **FIXED 2026-10-21** — constructor warning removed; `publish()` logs at debug when no store attached |
| 7 | Historical audit findings (in-memory campaign metrics, email provider gaps, simulation results never stored — `docs/plans/end-to-end-audit.md` §1) | PARTIALLY SUPERSEDED: persistence layer now exists (migration 003, `db/models/`); each item needs individual re-verification against current code |

## 8. Open Decisions (owner: product/human)

- ~~Broker wiring into the API `lifespan`~~ — **DONE 2026-10-21**: fan-out subscribed to all `EventType` topics; `run_all` fails fast when Redis is unreachable so the API serves degraded without fan-out; workers supervised and cancelled at shutdown. Follow-up: integration validation against real Redis (testcontainers) for consumer-group semantics.
- **Quantum layer re-assessment** against `docs/plans/gap-analysis.md`.
- **Auth-flow tests** need Docker on CI/dev machines (testcontainers) or an embedded-Postgres alternative.

## 9. Update Protocol (how this document stays alive)

Update this file **on every merge that touches**: `api/main.py` startup/lifespan, event bus/store or broker/worker, `db/` models or migrations, any singleton accessor, or any file listed in §5/§7.

1. **§2 Evidence Snapshot:** re-run `pytest tests/unit --ignore=tests/unit/test_auth_flow.py -q`; update counts, coverage, commit hash, date.
2. **§3 Matrix:** flip statuses only with new measured evidence (file:line).
3. **§5/§6/§7:** move rows to "FIXED" when the replacement pattern lands; add new lazy/happy paths with file:line on discovery.
4. **Changelog:** append one line per update (date, commit, what changed in this doc).

### Changelog

| Date | Commit | Change |
|---|---|---|
| 2026-10-21 | snapshot 2 (broker + singleton cutover) | Broker + workers + DLQ wired into lifespan; `aclose` + poison dead-lettering; sqlite async-URL normalization; engine eager-init; lazy singletons converted to cached accessors; supervisor + regression tests; 813 unit tests green |
| 2026-10-21 | `f0c092e` + working tree (event-store wiring) | Initial snapshot: event-store startup wiring verified; factory bugs fixed; full lazy/happy-path census; pattern standard established |
