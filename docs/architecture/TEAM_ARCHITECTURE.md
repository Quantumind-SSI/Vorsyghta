# Vorsyghta — Team Architecture & Re-Engineering Plan

> **Platform scope.** Vorsyghta is one platform with **seven capabilities** (the union of every plan in `docs/plans/`): the eight colour teams + exercise orchestrator, the intelligence stack, zero-day research, quantum/PQC readiness, the commercial SaaS product, six simulation paradigms, and RL/RLHF. The canonical, status-annotated statement of that scope lives in **[README § Platform scope — the full target](../../README.md#platform-scope--the-full-target)**. This document is the code-anchored taxonomy for capability #1.

**Status:** Authoritative plan (2026-08-16). Supersedes README marketing claims where they conflict.
**Engineering standard:** SWEBOK v4.0 · NASA Power of 10 · Zero Framework Tolerance (CTO-MCP constitution).
**Prime directive:** *Implementation is the only truth.* No stubs, no fabricated results, no fake detection. Every "result" a CISO sees must be **measured**, not simulated — or explicitly labelled `simulation=true`.

Companion docs: `security-audit/AUDIT_STATE_2026-08-16.md`, `security-audit/BUSINESS_LOGIC_DEEP_DIVE_2026-08-16.md`.

---

## 0. Why this document exists

The business-logic audit established that Vorsyghta is a **real toolkit bolted to a simulated orchestrator**:

- The flagship `ExerciseOrchestrator.run_exercise()` "detects" attacks with a **hash coin-flip**
  (`core/exercise_orchestrator.py:270-274`, `md5(technique_id) % 10 < 7`) mislabeled `source="siem"`.
- The **real** defensive stack (`BlueTeamBusIntegration`, wiring SIEM/IDS/EDR/ThreatHunter/IR/Triage)
  is **instantiated nowhere in production** (`defense/blue_team/bus_integration.py`).
- The **event-sourced audit trail is dead code**: `EventBus` is always built with `event_store=None`
  (`core/exercise_orchestrator.py:94`, `api/routers/exercise.py:46`); `PostgresEventStore.create()`
  appears only in docstrings/tests. Nothing is persisted.
- A latent integration bug: `EventBus._persist_event` calls `event_store.append(event.to_dict())`
  (a **dict**), but `PostgresEventStore.append(event: Event)` expects a typed **`Event`** with
  `aggregate_id`/`version`. Wiring alone is insufficient — an **adapter** is required.

This plan replaces the simulated core with real, integrated, measured team execution.

---

## 1. Team taxonomy (canonical)

Vorsyghta is a **one-stop agentic cybersecurity platform**: a single tool where an
organisation's entire security operation runs as coordinated **teams**. Two taxonomies
exist and are both first-class:

- **§1a Colour teams** — the eight exercise roles (Red…Black) that participate in a
  full-spectrum exercise.
- **§1b Functional teams** — the corporate org-chart mapping (SOC, DFIR, GRC, …) that the
  colour capabilities roll up into for day-to-day operations.

Status legend: **Implemented** = real module wired into the orchestrator/CLI/DB;
**Partial** = engine exists but not fully wired end-to-end or missing CLI/agent;
**Planned** = specified target, not yet built. Per the prime directive, docs never claim
a capability the code does not have — every "result" a CISO sees is measured or explicitly
flagged `simulation=true`.

### 1a. Colour teams (the eight)

| Team | Colour role | Mission | Implementation kind | Primary code anchor | Status |
|---|---|---|---|---|---|
| **Red** | Offense | Simulate real, adaptive attacks across the MITRE ATT&CK kill chain to test defences | **pydantic-ai agent** (plans/adapts) + real tool execution | `vorsyghta/cli/red_team.py`, `vorsyghta/vm/agent.py` (`AIAttackAgent`), `vorsyghta/db/models/red_team.py` | **Implemented** |
| **Blue** | Defense | Detect, correlate, respond, and stop breaches in real time | **Hybrid**: deterministic detection engines (SIEM/IDS/EDR) + agent-assisted triage | `vorsyghta/cli/blue_team.py`, `vorsyghta/defense/blue_team/` (8 modules, `EDRAgent`), `vorsyghta/db/models/blue_team.py` | **Implemented** |
| **Purple** | Integration / Coaching | Correlate Red stages vs Blue alerts, find detection gaps, produce the After-Action Review | **pydantic-ai agent** (gap analysis/correlation) over the shared event store | `vorsyghta/core/aar_generator.py`, orchestrator `_run_purple`/AAR phase | **Implemented** |
| **Yellow** | Builders / Infrastructure | Provision, harden, and validate the sandbox environment every other team operates in; secure-build / IaC | **Deterministic service** (real `VMOperator`) | `vorsyghta/core/yellow_team.py` (`InfrastructureManager`), `vorsyghta/db/models/yellow_team.py` | **Implemented** |
| **Green** | Remediation / Automation | Turn findings (Purple AAR + Black scores) into fixes and detection-as-code; secure-by-default automation bridge (Yellow↔Blue). *Also drives training & awareness from findings.* | **Deterministic service** (remediation/CI/detection-as-code) + agent-assisted fix generation | `vorsyghta/core/green_team.py` (`TrainingAwarenessEngine`; remediation engine **Planned**), `vorsyghta/db/models/green_team.py` | **Partial** |
| **Orange** | Code Review / Governance | Red-team perspective on code **before release** (LLM-enriched SAST, threat modelling, attack-surface reduction). *Also maps exercise findings to compliance frameworks.* | **Hybrid**: real SAST (semgrep/bandit/codeql) + agent enrichment; deterministic compliance mapping | `vorsyghta/core/orange_team.py` (`ComplianceGovernanceEngine`; code-review engine **Planned**), `vorsyghta/db/models/orange_team.py` | **Partial** |
| **White** | Governance / Referee | Set rules of engagement, enforce scope, ensure ethics/compliance, and referee (halt) exercises | **Deterministic service** (control plane, RoE, scoring) | `vorsyghta/core/white_team.py` (`WhiteTeamCoordinator`), `vorsyghta/db/models/white_team.py` | **Implemented** |
| **Black** | Observation / Evaluation | Observe exercises **without interference**, score every team on objective metrics, benchmark against history, emit the unbiased report | **Deterministic service** (read-only scoring over persisted events) | `vorsyghta/core/evaluation_engine.py` (`EvaluationEngine`), orchestrator `_run_black_team`, event `BLACK_TEAM_SCORE`; dedicated CLI/agent **Planned** | **Partial** |

> **Reconciliation note.** Two prior specs disagreed on Green/Orange. The canonical roles above
> restore the one-stop-shop intent: **Green = Remediation/Automation**, **Orange = Code Review /
> Attack-Surface Governance**, **Black = Evaluation** (a full eighth peer). The *currently shipping*
> engines (`green_team.TrainingAwarenessEngine`, `orange_team.ComplianceGovernanceEngine`) cover the
> secondary responsibilities noted in italics; the primary remediation and code-review engines are the
> committed build target (`docs/plans/color-team-architecture-plan.md`). Status flags mark exactly
> what is built today so nothing is overstated.

### 1b. Functional teams (corporate org-chart mapping)

These are the operational teams the colour capabilities compose into. They consume the same typed
event bus and store, so a colour-team exercise and a day-to-day SOC share one substrate.

| Group | Team | Mission | Implementation kind | Primary code anchor | Status |
|---|---|---|---|---|---|
| Ops & Defense | **SOC** (24/7 monitoring) | Continuous alert triage over the event store | Deterministic service (alert pipeline) | `vorsyghta/defense/blue_team/alert_triage.py`, `siem_client` | **Partial** |
| | **DFIR** (forensics & IR) | Incident response, chain-of-custody, real hashing | Deterministic service + agent-assisted analysis | `vorsyghta/defense/blue_team/incident_response.py`, `forensics.py` | **Implemented** |
| | **Vulnerability Management** | Scan orchestration, crash triage, disclosure | Deterministic service (real scanners/fuzzers) | `vorsyghta/research/crash_pipeline.py`, `vuln_report.py`, `disclosure.py` | **Implemented** |
| Eng & Arch | **SecOps / DevSecOps** | Tooling/pipelines, detection-as-code | Deterministic service | `vorsyghta/analytics/detection_rules/` (sigma/splunk/elastic/sentinel) | **Implemented** |
| | **AppSec** | Real SAST + LLM enrichment (feeds Orange) | Deterministic + agent | `vorsyghta/core/orange_team.py`, SAST integrations | **Partial** |
| | **Cloud Security** | Cloud posture (starts Azure) | Deterministic service | `vorsyghta/client_data/sources/cloud/`, deployment configs | **Partial** |
| | **IAM** | RBAC/JWT/SSO, least privilege | Deterministic service | `vorsyghta/security/rbac.py`, `sso.py`, `sso_bridge.py` | **Implemented** |
| Strategy/Risk/Intel | **GRC** | Control-ID mapping with **evidence**, not keyword match | Deterministic service | `vorsyghta/intelligence/compliance.py` | **Implemented** |
| | **Threat Intelligence** | CVE / CISA-KEV feeds, hunt hypotheses | **pydantic-ai agent** + real feeds | `vorsyghta/intelligence/threat_hunting.py`, `mitre_attack.py`, `hunting_frameworks.py` | **Implemented** |
| | **TPRM** (third-party risk) | Vendor posture scoring | Deterministic service | *engine* **Planned** | **Planned** |

**Mapping principle (the hybrid decision):**
> LLM reasoning is used *only* where the task genuinely reasons under uncertainty (offense planning,
> intel synthesis, hunt hypotheses, triage narrative, training/remediation content, code-review
> enrichment). Every path a CISO relies on for **assurance or compliance evidence** is
> **deterministic, typed, asserted, and replayable**. Nondeterminism must never enter the audit
> trail, scoring (Black), IAM, or compliance-evidence (GRC/Orange) paths.

**The one-stop-shop command** ties the colour teams into a single exercise:
> `vorsyghta exercise run --scenario <path> --teams all`
> White sets rules → Yellow provisions → Red attacks → Blue defends → Purple correlates/AAR →
> Green remediates → Orange reviews the rebuild → White verifies scope → **Black scores** →
> results persisted to the replayable event store.

---

## 2. Shared substrate (the spine that connects the teams)

All teams communicate through **one typed contract**, not ad-hoc dicts.

```
                 ┌──────────────────────────────────────────────┐
                 │                 EventBus                       │
   Red ─publish─▶│  typed BusEvent (pydantic)                     │─▶ subscribers (Blue, Purple, SOC…)
                 │  every event → EventStorePort.append(Event)    │
                 └───────────────────────┬──────────────────────┘
                                         │
                            ┌────────────▼─────────────┐
                            │   EventStorePort (proto)  │  ← adapter boundary
                            └────────────┬─────────────┘
                                         │
                    ┌────────────────────┼─────────────────────┐
                    ▼                    ▼                      ▼
          PostgresEventStore     SqliteEventStore        InMemoryEventStore
          (prod, replayable)     (single-node)           (tests only)
```

**Contracts (to be implemented, `core/contracts/`):**
- `BusEvent` hierarchy (already exists in `core/event_types.py`) — the wire format.
- `EventStorePort` — a `typing.Protocol` with `append(event: Event) -> int` and
  `get_events(aggregate_id) -> list[Event]`. This is the seam every store implements.
- `BusEventToEventAdapter` — converts a `BusEvent` (+ tenant/exercise → `aggregate_id`, monotonic
  `version`) into the frozen `Event` the store persists. **Fixes the dict-vs-Event bug.**
- `TeamResult[T]` — generic typed envelope every team returns: `team`, `status`,
  `simulation: bool`, `evidence: list[Evidence]`, `data: T`. The `simulation` flag is mandatory and
  propagates into scoring/reports so fabricated runs can never be shown as measured.

**Persistence guarantee:** `run_exercise` constructs
`EventBus(event_store=PostgresEventStore.create(DATABASE_URL))` (or Sqlite/InMemory by config).
Every published event is appended before handlers run. The trail is replayable for compliance.

---

## 3. Team interface (uniform, testable)

Every team — agent or deterministic — implements one protocol:

```python
class Team(Protocol):
    name: str
    kind: Literal["agent", "service"]
    async def run(self, ctx: ExerciseContext) -> TeamResult: ...
    def subscribe(self, bus: EventBus) -> None: ...   # optional event participation
```

- **Agent teams** wrap a `pydantic_ai.Agent` with a typed `result_type`, guardrailed tools, and a
  system prompt grounded in real context (findings, scenario, MITRE). Output is validated by the
  result model; on validation failure the team returns `status="degraded"`, never fabricated data.
- **Service teams** are plain async classes with precondition/postcondition assertions (Power of 10
  rule 5) and explicit error handling (rule 7). No silent `except: pass`.

---

## 4. Data flow — the loop, wired for real

```
White(RoE/approve) ─▶ Yellow(provision real/sim env) ─▶ Red(agent plans → executes tools)
        │                                                        │ publishes RedTeamAttackStageEvent
        │                                                        ▼
        │                         Blue(real SIEM/IDS/EDR/Hunter via BlueTeamBusIntegration)
        │                                                        │ publishes BlueTeamAlertEvent (measured)
        ▼                                                        ▼
   Purple(agent: correlate red stages vs blue alerts → detection gaps)
        │
        ▼
   Green(turn gaps → detection-as-code) · Orange(agent: training from gaps) · GRC(evidence)
        │
        ▼
   White(score from MEASURED alerts) → ExerciseResult (simulation flag propagated)

   ALL events ──▶ EventBus ──▶ PostgresEventStore  (single replayable audit trail)
```

**Red→Blue is now real:** Blue detection = the actual SIEM/IDS/EDR modules consuming the published
red-team events (they already implement `subscribe_to_event_bus`). The hash coin-flip is deleted.

**Cross-team reads are DB-backed:** Purple/GRC/SOC/reporting read persisted events from the store,
not in-memory dicts — so data survives restarts and is auditable.

---

## 5. Non-negotiable engineering invariants

1. **No fabricated results.** Detection/scoring derive from real module output. Any simulated segment
   sets `simulation=true`, which propagates to every downstream report and API response.
2. **Typed boundaries.** Pydantic models at every team and store boundary; no raw dicts across seams.
3. **Deterministic audit path.** Event sourcing, scoring, IAM, and GRC evidence contain zero LLM calls.
4. **Fail-closed security.** JWT secret has no default (C1); routers require auth (C2); tool args are
   `shlex.quote`d / argv (C3/C4). (Tracked in AUDIT_STATE doc.)
5. **Power of 10:** functions ≤50 lines, cyclomatic ≤10, assertions on pre/postconditions, every
   return checked, bounded loops/retries with backoff.
6. **Tests are part of the deliverable.** Each team ships happy-path + boundary + error-path tests;
   the exercise flow ships an integration test proving events persist and detection is measured.
7. **CTO-MCP scan gate + semantic review.** The scanner catches syntactic stubs; a human/agent
   adversarial review catches *semantic* fakes (the scanner does **not** flag the hash coin-flip).

---

## 6. Milestones (execution order)

| # | Milestone | Definition of done |
|---|---|---|
| **M1** | **Kill the fake core loop** | Delete `_detect_technique`; wire real `BlueTeamBusIntegration` into `ExerciseOrchestrator`; add `BusEventToEventAdapter`; construct `EventBus` with a real store; integration test proves (a) events persisted & replayable, (b) blue alerts come from real modules, (c) `simulation` flag correct. |
| M2 | Shared contracts | `EventStorePort`, `TeamResult`, `Team` protocol, `ExerciseContext` implemented + adopted by existing teams. |
| M3 | Red as pydantic-ai agent | Real agent plans/adapts, executes real tools via MCP; prose-only fallback removed or explicitly `simulation=true`. |
| M4 | Blue real detection wired end-to-end | SIEM/IDS/EDR/Hunter measured detection; EDR telemetry from real red output, not fabricated. |
| M5 | Purple agent | DB-backed gap analysis red-vs-blue. |
| M6 | White/Yellow/Green deterministic services | RoE/scoring, real provisioning, detection-as-code. |
| M7 | Functional teams | SOC, DFIR, VulnMgmt, AppSec, CloudSec, IAM, GRC (real evidence), ThreatIntel agent, TPRM. |
| M8 | Security criticals + hardening | C1–C4 fixed; CI gates (ruff/bandit/pip-audit/CTO-scan) green. |

Each milestone is independently verifiable and leaves the app in a working, honest state.

---

## 7. Tooling discipline (per user mandate)

- **pydantic-ai** — every agent team; typed `result_type`, tool schemas, no free-form dict outputs.
- **CTO-MCP (persona-constitution)** — run `scan_code` before emitting non-trivial code; obey the
  Five Gates (G1–G5). *Known limitation:* syntactic only — pair with adversarial semantic review.
- **Lumena MCP** — persist every architectural decision and milestone state for cross-session memory.
- **Guardrails MCP** — to be located/installed; gate agent inputs/outputs (injection, unsafe tool use)
  before agent teams touch real infrastructure. *(Not yet present on host — flagged.)*

---

## 8. Open items / honest caveats
- Guardrails MCP not yet installed on host; CTO-MCP currently cloned under `/tmp` (ephemeral) — must
  be relocated to a durable path and opencode restarted for MCP servers to load.
- `PostgresEventStore` optimistic-concurrency uses per-aggregate `version`; the adapter must assign a
  monotonic version per `aggregate_id` (exercise) to avoid `ConcurrencyError`.
- Some "real" modules (EDR telemetry, forensics capture) still synthesize inputs; M4 must replace
  fabricated telemetry with genuine red-output-derived events.
```
