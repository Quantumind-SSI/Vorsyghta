# Color Team Architecture: Making Vorsyghta the One-Stop Shop for Agentic Cybersecurity

> **Platform scope.** This is the build target for **capability #1 of seven** in Vorsyghta's full scope: the eight colour teams + exercise orchestrator. See the canonical statement in **[README § Platform scope — the full target](../../README.md#platform-scope--the-full-target)**.

**Date:** 2026-07-01
**Status:** Proposed — build target for the 8-team model.
**Depends on:** `ATTACK_INTEGRATION_PLAN.md`, `rl-and-rlhf-improvement-plan.md`, `ui-engineering-plan.md`

> **Canonical cross-reference.** `docs/architecture/TEAM_ARCHITECTURE.md` §1 is the authoritative,
> code-anchored team taxonomy (with per-team **status** flags). This document is the **build target**
> for the full eight-colour model: **Red, Blue, Purple, Yellow, Green (Remediation/Automation),
> Orange (Code Review / Attack-Surface Governance), White (Referee), Black (Evaluation)** plus the
> functional teams (SOC, DFIR, VulnMgmt, SecOps/DevSecOps, AppSec, CloudSec, IAM, GRC, Threat Intel,
> TPRM). Where the *shipping* engines currently differ (Green today = training/awareness, Orange today
> = compliance/governance), TEAM_ARCHITECTURE.md marks the exact status; this plan defines where they
> are headed.

---

## 1. Vision

Vorsyghta becomes the single platform where an organization's entire cybersecurity operation lives — every color team (Blue, Red, Purple, White, Green, Yellow, Orange, Black) is an **agentic capability** backed by LLM-driven agents, MCP tools, RLHF-trained policies, and a unified CLI/API/UI surface. A user can launch a full-spectrum exercise (Red attacks → Blue defends → Purple coaches → Green remediates → Yellow rebuilds → Orange reviews code → White enforces rules → Black evaluates) from one command:

```bash
vorsyghta exercise run --scenario templates/supply_chain_compromise.yaml --teams all
```

---

## 2. Current State Assessment

| Color Team | Config | CLI | Agent | Playbook Content | Defense Module | Status |
|------------|--------|-----|-------|------------------|----------------|--------|
| **Blue** | `config.yaml` | `vorsyghta/cli/blue_team.py` | `EDRAgent` | `BLUE_TEAM_CONTENT` | `defense/blue_team/` (8 modules) | **Complete** |
| **Red** | `config.yaml` | `vorsyghta/cli/red_team.py` | `AIAttackAgent`, `ReActAgent` | `RED_TEAM_CONTENT` | — | **Complete** |
| **Purple** | `config.yaml` (lines 330-335) | **Missing** | **Missing** | `PURPLE_TEAM_CONTENT` | — | **Partial** (content only) |
| **Yellow** | `config.yaml` (lines 321-328) | **Missing** | **Missing** | `GRC_CONTENT` (adjacent) | — | **Partial** (config only) |
| **Green** | **Missing** | **Missing** | **Missing** | **Missing** | — | **Absent** |
| **Orange** | **Missing** | **Missing** | **Missing** | **Missing** | — | **Absent** |
| **White** | **Missing** | **Missing** | **Missing** | **Missing** | — | **Absent** |
| **Black** | **Missing** | **Missing** | **Missing** | **Missing** | — | **Absent** |

**Key gaps:**
- No RBAC system — `SecurityTeam` enum is content categorization, not access control
- No orchestration layer to run multiple teams in a single exercise
- No shared event bus for real-time team-to-team interaction
- Purple/Yellow have config stubs but no implementation
- 4 teams (Green, Orange, White, Black) are entirely absent

---

## 3. Target Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Vorsyghta Exercise Orchestrator                  │
│          (vorsyghta/core/exercise_orchestrator.py — NEW)             │
├─────────────────────────────────────────────────────────────────────┤
│  White Team (Referee)    │  Black Team (Observer)                     │
│  - Rules of engagement   │  - Non-interfering evaluation              │
│  - Scope enforcement     │  - Performance scoring                     │
│  - Ethics/compliance     │  - Post-exercise report                    │
├─────────────────────────────────────────────────────────────────────┤
│  Red Team          │  Blue Team          │  Purple Team              │
│  - Attack flows    │  - SIEM/IDS/EDR     │  - Detection validation   │
│  - VM execution    │  - IR/Forensics     │  - AAR generation          │
│  - MITRE mapping   │  - Threat hunting   │  - Red↔Blue feedback loop │
├─────────────────────────────────────────────────────────────────────┤
│  Green Team        │  Yellow Team        │  Orange Team              │
│  - Remediation     │  - Secure build     │  - Code vulnerability     │
│  - Patch tracking  │  - Infrastructure  │  - Attack surface reduc.  │
│  - Auto-fix gen    │  - DevSecOps        │  - Pre-release review     │
└─────────────────────────────────────────────────────────────────────┘
         │                    │                    │
         └────────────────────┴────────────────────┘
                              │
                   ┌──────────▼──────────┐
                   │  Shared Event Bus    │
                   │  (vorsyghta/core/    │
                   │   event_bus.py — NEW)│
                   └──────────┬──────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
   ┌────▼────┐         ┌──────▼──────┐        ┌─────▼─────┐
   │ MCP     │         │ RLHF Multi- │        │ RAG /     │
   │ Tools   │         │ Agent System│        │ Memory    │
   └─────────┘         └─────────────┘        └───────────┘
```

---

## 4. Color Team Specifications

### 4.1 Blue Team (Defensive) — EXISTS, ENHANCE

**Current:** Full CLI (`blue-team siem/ids/edr/ir/hunt/logs/triage/forensics`), 8 defense modules, `EDRAgent`.

**Enhancements:**
- Add `blue-team react` command — autonomous blue team agent that ingests Red Team attack events from the event bus and responds in real-time
- Wire `SIEMClient` and `IDSDetector` to subscribe to event bus for live attack correlation
- Add `blue-team playbook` — generate detection playbooks from MITRE techniques (leverages existing `ai_enhanced_playbooks.py`)

**New files:**
- `vorsyghta/defense/blue_team/reactive_agent.py` — autonomous defensive agent

**RBAC permissions:** `blue.team.read`, `blue.team.respond`, `blue.team.isolate`, `blue.team.forensics`

---

### 4.2 Red Team (Offensive) — EXISTS, ENHANCE

**Current:** Full CLI (`red-team attack/status/report/steer/stop/list/search/health`), `AIAttackAgent`, `ReActAgent`, Vorsyghta Attack integration.

**Enhancements:**
- Add `red-team coordinate` — publish attack events to event bus for Blue/Purple consumption
- Add `red-team evade` — LLM-driven evasion refinement based on Blue Team detection (feedback from Purple)
- Wire `AttackIntegration.monitor_flow()` to emit events to the bus at each flow stage

**New files:**
- `vorsyghta/integrations/attack_event_publisher.py` — publishes attack flow events to event bus

**RBAC permissions:** `red.team.attack`, `red.team.steer`, `red.team.report`, `red.team.evade`

---

### 4.3 Purple Team (Collaboration/Coaching) — BUILD

**Role:** Maximize Red and Blue effectiveness. After simulations, help Blue improve detection or help Red improve stealth. The "coach."

**Implementation:**

**New CLI:** `vorsyghta/cli/purple_team.py`
```
vorsyghta purple coordinate  --exercise <id>     # Orchestrate Red↔Blue exercise
vorsyghta purple aar          --exercise <id>     # Generate After Action Review
vorsyghta purple validate     --exercise <id>     # Validate detection coverage
vorsyghta purple feedback     --exercise <id>     # Generate improvement feedback
vorsyghta purple score        --exercise <id>     # Score both teams
vorsyghta purple rubric       --show              # Show scoring rubric
```

**New agent:** `vorsyghta/agents/purple_team_agent.py`
- `PurpleTeamAgent` subscribes to event bus
- Correlates attack events (from Red) with detection events (from Blue)
- Uses LLM to generate AAR with:
  - Detection gaps (Red succeeded, Blue missed)
  - Stealth failures (Blue detected, Red was noisy)
  - Improvement recommendations for both teams
- Stores AAR in RAG for future exercises (leverages existing `store_aar_in_rag` config)

**New module:** `vorsyghta/core/aar_generator.py`
- Structured AAR generation using LLM
- Scoring rubric: detection_rate, response_time, evasion_success, mitre_coverage
- Feeds back into RLHF reward model (per `rl-and-rlhf-improvement-plan.md`)

**Config (already exists, extend):**
```yaml
purple_team:
  enabled: true
  exercise_timeout_minutes: 60
  auto_generate_aar: true
  store_aar_in_rag: true
  correlation_window_seconds: 30
  scoring_rubric:              # NEW
    detection_rate_weight: 0.30
    response_time_weight: 0.20
    evasion_success_weight: 0.20
    mitre_coverage_weight: 0.15
    communication_weight: 0.15
```

**RBAC permissions:** `purple.team.coordinate`, `purple.team.aar`, `purple.team.score`

---

### 4.4 White Team (Rules of Engagement / Referee) — BUILD

**Role:** Set rules of engagement, enforce scope, ensure fairness, compliance, and ethics. The "referee."

**Implementation:**

**New CLI:** `vorsyghta/cli/white_team.py`
```
vorsyghta white rules       --create/--show/--validate   # Manage rules of engagement
vorsyghta white scope       --add/--remove/--check        # Manage attack scope
vorsyghta white approve     --scenario <path>             # Approve scenario for execution
vorsyghta white monitor     --exercise <id>               # Monitor exercise for rule violations
vorsyghta white halt        --exercise <id> --reason      # Halt exercise (referee stop)
vorsyghta white compliance  --exercise <id>               # Check compliance frameworks
```

**New module:** `vorsyghta/core/rules_of_engagement.py`
- `RulesOfEngagement` dataclass:
  - `allowed_targets`: IP ranges, assets (integrates with existing `SafetyController.validate_network()`)
  - `forbidden_techniques`: MITRE technique IDs that are off-limits
  - `time_constraints`: exercise window, blackout periods
  - `data_handling`: what data can be accessed/exfiltrated
  - `compliance_frameworks`: NIST, ISO, PCI-DSS (leverages existing `intelligence/compliance.py`)
- `RoEValidator` checks scenarios against rules before execution
- Integrates with existing `SafetyController.validate_scenario()` for restricted scenario approval

**New agent:** `vorsyghta/agents/white_team_agent.py`
- `WhiteTeamAgent` monitors event bus for rule violations
- Can halt exercise via orchestrator if rules breached
- Generates compliance report post-exercise

**Config:**
```yaml
white_team:
  enabled: true
  require_pre_approval: true
  restricted_scenarios: ["ransomware", "wiper", "destructive", "supply_chain"]
  compliance_frameworks: ["nist_800_53", "iso_27001"]
  auto_halt_on_violation: false  # Require human confirmation
  ethics_review_required: true
```

**RBAC permissions:** `white.team.rules`, `white.team.scope`, `white.team.approve`, `white.team.halt`

---

### 4.5 Green Team (Remediation / Engineering Bridge) — BUILD

**Role:** Fix vulnerabilities found by Red, strengthen systems by collaborating with Yellow. The "contractor" who repairs after the fire.

**Implementation:**

**New CLI:** `vorsyghta/cli/green_team.py`
```
vorsyghta green remediate     --exercise <id>          # Generate remediation plan from AAR
vorsyghta green patch-track   --exercise <id>          # Track patch status of findings
vorsyghta green auto-fix      --finding <id>           # Generate auto-fix code/config
vorsyghta green verify        --fix <id>               # Verify a fix resolves the finding
vorsyghta green backlog       --list/--prioritize      # Manage remediation backlog
vorsyghta green bridge        --to yellow              # Hand off to Yellow Team
```

**New module:** `vorsyghta/core/remediation_engine.py`
- `RemediationEngine` ingests AAR findings and:
  - Maps each finding to a remediation action (leverages existing `mitigation_generator.py`)
  - Generates concrete fix code/config using LLM (patches, config changes, rule updates)
  - Tracks remediation status: `open → in_progress → fixed → verified`
  - Prioritizes by risk score and exploitability
- `PatchTracker` maintains remediation backlog with integration to issue trackers

**New agent:** `vorsyghta/agents/green_team_agent.py`
- `GreenTeamAgent` consumes AAR from Purple Team
- Generates remediation playbooks
- Can hand off to Yellow Team for infrastructure changes

**Config:**
```yaml
green_team:
  enabled: true
  auto_generate_remediation: true
  patch_tracking_enabled: true
  issue_tracker_integration: null  # "jira", "github", "linear"
  prioritization_method: "risk_score"  # or "cvss", "exploitability"
  auto_fix_confidence_threshold: 0.8  # Only auto-apply fixes above this confidence
```

**RBAC permissions:** `green.team.remediate`, `green.team.auto_fix`, `green.team.verify`, `green.team.backlog`

---

### 4.6 Yellow Team (Build / Infrastructure / Secure Code) — BUILD

**Role:** Build infrastructure, develop secure code, fix weaknesses pointed out by Green/Orange. The "castle builders."

**Implementation:**

**New CLI:** `vorsyghta/cli/yellow_team.py`
```
vorsyghta yellow build        --spec <path>            # Build secure infrastructure from spec
vorsyghta yellow harden       --asset <id>             # Apply hardening baseline
vorsyghta yellow review       --from-green <id>        # Review Green Team remediation handoff
vorsyghta yellow iac          --generate/--validate     # Infrastructure-as-Code generation
vorsyghta yellow compliance   --framework <name>       # Map config to compliance framework
vorsyghta yellow deploy       --spec <path>            # Deploy hardened infrastructure
```

**New module:** `vorsyghta/core/secure_build_engine.py`
- `SecureBuildEngine`:
  - Generates IaC (Terraform/Ansible/Docker Compose) from security specs
  - Applies CIS benchmarks and hardening baselines
  - Validates configurations against compliance frameworks (leverages existing `intelligence/compliance.py`)
  - Integrates with existing `docker-compose.yml` and `docker-compose.attack.yml` patterns
- `HardeningProfile` dataclass with benchmark-specific rules

**New agent:** `vorsyghta/agents/yellow_team_agent.py`
- `YellowTeamAgent` receives handoffs from Green Team
- Generates secure infrastructure specs
- Validates builds before deployment

**Config (already exists, extend):**
```yaml
yellow_team:
  enabled: true
  compliance_frameworks: ["nist_800_53", "iso_27001", "cis_benchmarks"]
  risk_assessment_interval: "weekly"
  awareness_training_interval: "monthly"
  iac_provider: "terraform"       # NEW: "terraform", "ansible", "docker_compose"
  hardening_benchmark: "cis"      # NEW
  auto_validate_build: true       # NEW
```

**RBAC permissions:** `yellow.team.build`, `yellow.team.harden`, `yellow.team.deploy`, `yellow.team.compliance`

---

### 4.7 Orange Team (Code Vulnerability / Attack Surface Reduction) — BUILD

**Role:** Provide red team perspective on code during development, before release. The "advisor" at the blueprint phase.

**Implementation:**

**New CLI:** `vorsyghta/cli/orange_team.py`
```
vorsyghta orange review       --code <path>            # Review code for vulnerabilities
vorsyghta orange surface      --reduce <asset>         # Attack surface reduction recommendations
vorsyghta orange threat-model --spec <path>            # Generate threat model from design
vorsyghta orange sast         --code <path>            # Static analysis with LLM enrichment
vorsyghta orange deps         --code <path>            # Dependency vulnerability scan
vorsyghta orange advise       --to yellow              # Advise Yellow Team on findings
```

**New module:** `vorsyghta/core/code_review_engine.py`
- `CodeReviewEngine`:
  - LLM-enriched static analysis (combines traditional SAST with LLM reasoning)
  - Threat modeling from architecture specs (STRIDE methodology)
  - Attack surface mapping and reduction recommendations
  - Dependency vulnerability scanning (integrates with `datasets/` for CVE data)
  - Maps findings to MITRE ATT&CK techniques (leverages existing `intelligence/mitre_attack.py`)
- `ThreatModel` dataclass with STRIDE categories

**New agent:** `vorsyghta/agents/orange_team_agent.py`
- `OrangeTeamAgent` reviews code/designs proactively
- Generates advisory reports for Yellow Team
- Tracks attack surface metrics over time

**Config:**
```yaml
orange_team:
  enabled: true
  sast_tools: ["semgrep", "bandit"]  # External tools to integrate
  threat_modeling_method: "stride"   # "stride", "attack_tree", "pasta"
  dependency_scan_enabled: true
  llm_enrichment: true
  auto_advise_yellow: true
```

**RBAC permissions:** `orange.team.review`, `orange.team.surface`, `orange.team.threat_model`, `orange.team.advise`

---

### 4.8 Black Team (Observation / Evaluation) — BUILD

**Role:** Observe simulations without interference, evaluate performance, write unbiased reports. The "judge."

**Implementation:**

**New CLI:** `vorsyghta/cli/black_team.py`
```
vorsyghta black observe       --exercise <id>          # Observe exercise (read-only)
vorsyghta black evaluate      --exercise <id>          # Evaluate all teams' performance
vorsyghta black report        --exercise <id>          # Generate unbiased evaluation report
vorsyghta black benchmark     --exercise <id>          # Benchmark against historical exercises
vorsyghta black trends        --range <period>         # Show performance trends across exercises
```

**New module:** `vorsyghta/core/evaluation_engine.py`
- `EvaluationEngine`:
  - Collects all events from event bus in read-only mode (no interference)
  - Evaluates each team against objective metrics:
    - Red: attack success rate, stealth, MITRE coverage, time-to-compromise
    - Blue: detection rate, response time, false positive rate, containment time
    - Purple: AAR quality, feedback actionability, improvement measurable
    - Green: remediation completeness, time-to-fix, verification pass rate
    - Yellow: build security score, hardening coverage, compliance alignment
    - Orange: findings per KLOC, attack surface reduction, pre-release catch rate
    - White: rule enforcement accuracy, scope compliance, halt appropriateness
  - Benchmarks against historical exercises (leverages RAG memory)
  - Generates trend analysis across exercises
- `PerformanceBenchmark` dataclass with per-team metrics

**New agent:** `vorsyghta/agents/black_team_agent.py`
- `BlackTeamAgent` subscribes to event bus in read-only mode
- Cannot emit events or call orchestrator actions
- Generates objective evaluation report post-exercise

**Config:**
```yaml
black_team:
  enabled: true
  read_only_mode: true             # Cannot interfere with exercises
  evaluation_metrics:
    red: ["success_rate", "stealth_score", "mitre_coverage", "time_to_compromise"]
    blue: ["detection_rate", "response_time", "fp_rate", "containment_time"]
    purple: ["aar_quality", "feedback_actionability", "improvement_delta"]
    green: ["remediation_completeness", "time_to_fix", "verification_pass_rate"]
    yellow: ["build_security_score", "hardening_coverage", "compliance_alignment"]
    orange: ["findings_per_kloc", "surface_reduction", "pre_release_catch_rate"]
    white: ["rule_enforcement_accuracy", "scope_compliance", "halt_appropriateness"]
  benchmark_against_history: true
  trend_analysis_enabled: true
```

**RBAC permissions:** `black.team.observe`, `black.team.evaluate`, `black.team.report`, `black.team.benchmark`

---

## 5. Exercise Orchestrator (NEW — Core Piece)

**File:** `vorsyghta/core/exercise_orchestrator.py`

This is the central piece that makes Vorsyghta a "one-stop shop." It coordinates all color teams in a single exercise.

### Exercise Lifecycle

```
1. White Team: Define rules of engagement, approve scenario
       ↓
2. Orchestrator: Spin up event bus, initialize all enabled teams
       ↓
3. Red Team: Launch attack (via Vorsyghta Attack or VM agent)
       ↓ (events published to bus)
4. Blue Team: Detect and respond (reactive agent + defense modules)
       ↓ (events published to bus)
5. Purple Team: Correlate attack↔detection, generate real-time feedback
       ↓
6. Green Team: Ingest findings, generate remediation plan
       ↓
7. Yellow Team: Receive handoff from Green, generate hardened rebuild
       ↓
8. Orange Team: Review Yellow's rebuild for vulnerabilities
       ↓
9. White Team: Verify exercise stayed within rules
       ↓
10. Black Team: Generate unbiased evaluation report
       ↓
11. Orchestrator: Store complete exercise in RAG, emit final report
```

### Orchestrator API

```python
class ExerciseOrchestrator:
    """Coordinates multi-team cybersecurity exercises."""

    def __init__(self, config: ExerciseConfig, event_bus: EventBus):
        self.teams: dict[ColorTeam, TeamAgent] = {}
        self.event_bus = event_bus
        self.exercise_id: str

    async def run_exercise(self, scenario: ThreatScenario, teams: list[ColorTeam]) -> ExerciseResult:
        """Run a full-spectrum exercise with specified teams."""

    async def halt_exercise(self, reason: str, halted_by: ColorTeam) -> None:
        """Halt exercise (called by White Team on rule violation)."""

    def get_exercise_state(self) -> ExerciseState:
        """Get real-time exercise state for monitoring."""
```

### Exercise CLI

**New CLI group:** `vorsyghta/cli/exercise.py`
```
vorsyghta exercise run       --scenario <path> [--teams all|red,blue,purple,...]
vorsyghta exercise status    --exercise <id>
vorsyghta exercise halt      --exercise <id> --reason
vorsyghta exercise list      [--filter status]
vorsyghta exercise report    --exercise <id> [--format json|html|pdf]
vorsyghta exercise replay    --exercise <id>   # Replay events from stored exercise
vorsyghta exercise compare   --exercises <id1> <id2>  # Compare two exercises
```

---

## 6. Shared Event Bus (NEW)

**File:** `vorsyghta/core/event_bus.py`

Enables real-time team-to-team communication. Built on the existing `event_sourcing.py` patterns.

```python
class EventBus:
    """In-process pub/sub event bus for team coordination."""

    async def publish(self, event: TeamEvent) -> None:
        """Publish event to all subscribers."""

    async def subscribe(self, team: ColorTeam, handler: Callable) -> None:
        """Subscribe a team to events."""

    def get_events(self, team: Optional[ColorTeam] = None, event_type: Optional[str] = None) -> list[TeamEvent]:
        """Query events (for Black Team observation, replay)."""
```

**Event types:**
- `AttackEvent` — Red Team attack step (technique, target, result, timestamp)
- `DetectionEvent` — Blue Team detection (alert, source, confidence, timestamp)
- `ResponseEvent` — Blue Team response action (containment, isolation, forensic collection)
- `CoordinationEvent` — Purple Team feedback (to Red or Blue)
- `RemediationEvent` — Green Team fix generated/applied
- `BuildEvent` — Yellow Team build/harden action
- `ReviewEvent` — Orange Team code review finding
- `RuleEvent` — White Team rule check/violation
- `EvaluationEvent` — Black Team evaluation metric

All events persisted via existing `postgres_event_store.py` for replay and benchmarking.

---

## 7. RBAC System (NEW)

**File:** `vorsyghta/core/rbac.py`

Currently Vorsyghta has no RBAC. The UI engineering plan calls for `vorsyghta/core/auth.py` with JWT. This plan extends that with color-team-based roles.

### Role Definitions

```python
class ColorTeamRole(str, Enum):
    BLUE_TEAM = "blue_team"
    RED_TEAM = "red_team"
    PURPLE_TEAM = "purple_team"
    WHITE_TEAM = "white_team"
    GREEN_TEAM = "green_team"
    YELLOW_TEAM = "yellow_team"
    ORANGE_TEAM = "orange_team"
    BLACK_TEAM = "black_team"
    EXERCISE_ADMIN = "exercise_admin"  # Can orchestrate exercises
    OBSERVER = "observer"              # Read-only across all teams

class Permission(str, Enum):
    # Blue Team
    BLUE_TEAM_READ = "blue.team.read"
    BLUE_TEAM_RESPOND = "blue.team.respond"
    BLUE_TEAM_ISOLATE = "blue.team.isolate"
    BLUE_TEAM_FORENSICS = "blue.team.forensics"
    # Red Team
    RED_TEAM_ATTACK = "red.team.attack"
    RED_TEAM_STEER = "red.team.steer"
    RED_TEAM_REPORT = "red.team.report"
    # Purple Team
    PURPLE_TEAM_COORDINATE = "purple.team.coordinate"
    PURPLE_TEAM_AAR = "purple.team.aar"
    # White Team
    WHITE_TEAM_RULES = "white.team.rules"
    WHITE_TEAM_APPROVE = "white.team.approve"
    WHITE_TEAM_HALT = "white.team.halt"
    # Green Team
    GREEN_TEAM_REMEDIATE = "green.team.remediate"
    GREEN_TEAM_AUTO_FIX = "green.team.auto_fix"
    # Yellow Team
    YELLOW_TEAM_BUILD = "yellow.team.build"
    YELLOW_TEAM_DEPLOY = "yellow.team.deploy"
    # Orange Team
    ORANGE_TEAM_REVIEW = "orange.team.review"
    ORANGE_TEAM_ADVISE = "orange.team.advise"
    # Black Team
    BLACK_TEAM_OBSERVE = "black.team.observe"
    BLACK_TEAM_REPORT = "black.team.report"
    # Exercise
    EXERCISE_RUN = "exercise.run"
    EXERCISE_HALT = "exercise.halt"
```

### Role → Permission Matrix

| Role | Key Permissions |
|------|----------------|
| `blue_team` | `blue.team.*`, `purple.team.aar` (read) |
| `red_team` | `red.team.*`, `purple.team.aar` (read) |
| `purple_team` | `purple.team.*`, `blue.team.read`, `red.team.report` |
| `white_team` | `white.team.*`, `exercise.halt`, all `.read` |
| `green_team` | `green.team.*`, `yellow.team.build` (request) |
| `yellow_team` | `yellow.team.*`, `orange.team.review` (request) |
| `orange_team` | `orange.team.*`, `yellow.team.compliance` (read) |
| `black_team` | `black.team.*`, all `.read` |
| `exercise_admin` | `exercise.run`, `exercise.halt`, all `.read` |
| `observer` | all `.read` |

### Enforcement

```python
def require_permission(permission: Permission):
    """Decorator for CLI commands and API endpoints."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            user = get_current_user()  # From JWT context (per ui-engineering-plan)
            if not user.has_permission(permission):
                raise PermissionDeniedError(f"Requires {permission.value}")
            return func(*args, **kwargs)
        return wrapper
    return decorator
```

Applied to:
- CLI commands via Click context (`ctx.obj["user"]`)
- API endpoints via FastAPI dependency injection
- MCP tool calls via `MCPAgentClient.call_tool()` pre-check

---

## 8. Agent Architecture Integration

### Existing Agents → Color Team Mapping

| Existing Agent | Color Team | Action |
|----------------|------------|--------|
| `AIAttackAgent` (`vm/agent.py`) | Red | Enhance with event publishing |
| `ReActAgent` (`mcp/agents/`) | Red | Enhance with event publishing |
| `EDRAgent` (`defense/blue_team/`) | Blue | Enhance with event subscription |
| `QuantumThreatAgent` (`quantum/agent.py`) | Red (specialized) | Wire as Red Team sub-capability |
| `CompanyReconAgent` (`client_data/recon.py`) | Red | Wire as Red Team reconnaissance |
| `MultiAgentPromptSystem` (`llm/rlhf_multiagent.py`) | Cross-team | Extend with color team roles |

### New Agents

| New Agent | File | Color Team |
|-----------|------|------------|
| `PurpleTeamAgent` | `vorsyghta/agents/purple_team_agent.py` | Purple |
| `WhiteTeamAgent` | `vorsyghta/agents/white_team_agent.py` | White |
| `GreenTeamAgent` | `vorsyghta/agents/green_team_agent.py` | Green |
| `YellowTeamAgent` | `vorsyghta/agents/yellow_team_agent.py` | Yellow |
| `OrangeTeamAgent` | `vorsyghta/agents/orange_team_agent.py` | Orange |
| `BlackTeamAgent` | `vorsyghta/agents/black_team_agent.py` | Black |
| `ReactiveBlueAgent` | `vorsyghta/defense/blue_team/reactive_agent.py` | Blue |

### RLHF Integration

Extend the `AgentRole` enum in `rlhf_multiagent.py` to include color team roles:

```python
class AgentRole(str, Enum):
    # Existing
    CONTENT_GENERATOR = "content_generator"
    SAFETY_VALIDATOR = "safety_validator"
    QUALITY_ASSESSOR = "quality_assessor"
    MITRE_MAPPER = "mitre_mapper"
    EDUCATIONAL_ENHANCER = "educational_enhancer"
    # NEW: Color team roles
    RED_ATTACKER = "red_attacker"
    BLUE_DEFENDER = "blue_defender"
    PURPLE_COORDINATOR = "purple_coordinator"
    WHITE_REFEREE = "white_referee"
    GREEN_REMEDIATOR = "green_remediator"
    YELLOW_BUILDER = "yellow_builder"
    ORANGE_REVIEWER = "orange_reviewer"
    BLACK_EVALUATOR = "black_evaluator"
```

Each role gets specific reward functions (per `rl-and-rlhf-improvement-plan.md`):
- Red: reward for successful exploitation + stealth (penalize detection)
- Blue: reward for detection speed + accuracy (penalize false positives)
- Purple: reward for actionable feedback + measurable improvement
- Green: reward for fix completeness + verification pass
- Yellow: reward for build security score + compliance alignment
- Orange: reward for findings caught pre-release + attack surface reduction
- White: reward for rule enforcement accuracy
- Black: reward for evaluation objectivity (cross-validated against human scores)

---

## 9. Config Schema (Extended)

Add to `config.yaml`:

```yaml
# Color Team Configuration
color_teams:
  blue_team:
    enabled: true
    reactive_agent: true
    # ... (existing blue_team config)

  red_team:
    enabled: true
    event_publishing: true
    # ... (existing red_team config)

  purple_team:
    enabled: true
    exercise_timeout_minutes: 60
    auto_generate_aar: true
    store_aar_in_rag: true
    correlation_window_seconds: 30
    scoring_rubric:
      detection_rate_weight: 0.30
      response_time_weight: 0.20
      evasion_success_weight: 0.20
      mitre_coverage_weight: 0.15
      communication_weight: 0.15

  white_team:
    enabled: true
    require_pre_approval: true
    restricted_scenarios: ["ransomware", "wiper", "destructive", "supply_chain"]
    compliance_frameworks: ["nist_800_53", "iso_27001"]
    auto_halt_on_violation: false
    ethics_review_required: true

  green_team:
    enabled: true
    auto_generate_remediation: true
    patch_tracking_enabled: true
    issue_tracker_integration: null
    prioritization_method: "risk_score"
    auto_fix_confidence_threshold: 0.8

  yellow_team:
    enabled: true
    compliance_frameworks: ["nist_800_53", "iso_27001", "cis_benchmarks"]
    risk_assessment_interval: "weekly"
    awareness_training_interval: "monthly"
    iac_provider: "terraform"
    hardening_benchmark: "cis"
    auto_validate_build: true

  orange_team:
    enabled: true
    sast_tools: ["semgrep", "bandit"]
    threat_modeling_method: "stride"
    dependency_scan_enabled: true
    llm_enrichment: true
    auto_advise_yellow: true

  black_team:
    enabled: true
    read_only_mode: true
    benchmark_against_history: true
    trend_analysis_enabled: true

# Exercise Orchestrator
exercise:
  enabled: true
  default_teams: ["red", "blue", "purple"]
  event_bus_backend: "memory"  # "memory", "redis", "postgres"
  persist_events: true
  auto_store_in_rag: true

# RBAC
rbac:
  enabled: true
  token_expiry_minutes: 60
  default_role: "observer"
  role_permissions_file: "config/rbac_roles.yaml"
```

---

## 10. CLI Command Registration

Add to `vorsyghta/cli/main.py`:

```python
# Add Purple Team commands
from .purple_team import purple_team
cli.add_command(purple_team, name="purple-team")

# Add White Team commands
from .white_team import white_team
cli.add_command(white_team, name="white-team")

# Add Green Team commands
from .green_team import green_team
cli.add_command(green_team, name="green-team")

# Add Yellow Team commands
from .yellow_team import yellow_team
cli.add_command(yellow_team, name="yellow-team")

# Add Orange Team commands
from .orange_team import orange_team
cli.add_command(orange_team, name="orange-team")

# Add Black Team commands
from .black_team import black_team
cli.add_command(black_team, name="black-team")

# Add Exercise Orchestrator commands
from .exercise import exercise_group
cli.add_command(exercise_group, name="exercise")
```

Final CLI surface:
```
vorsyghta blue-team     # Defensive operations
vorsyghta red-team      # Offensive operations
vorsyghta purple-team   # Collaboration & coaching
vorsyghta white-team    # Rules of engagement & refereeing
vorsyghta green-team    # Remediation & engineering bridge
vorsyghta yellow-team   # Secure build & infrastructure
vorsyghta orange-team   # Code review & attack surface reduction
vorsyghta black-team    # Observation & evaluation
vorsyghta exercise      # Multi-team orchestration (one-stop shop)
```

---

## 11. Implementation Phases

### Phase 1: Foundation (Weeks 1-2)
**Goal:** Event bus, exercise orchestrator, RBAC skeleton

- [ ] `vorsyghta/core/event_bus.py` — pub/sub event bus
- [ ] `vorsyghta/core/exercise_orchestrator.py` — orchestrator core
- [ ] `vorsyghta/core/rbac.py` — role/permission model
- [ ] `vorsyghta/cli/exercise.py` — exercise CLI (`run`, `status`, `halt`, `list`)
- [ ] Wire Red Team attack events → event bus (`attack_event_publisher.py`)
- [ ] Wire Blue Team defense modules → event bus subscription
- [ ] Config schema for `color_teams` and `exercise` sections
- [ ] Tests: event bus, orchestrator lifecycle, RBAC enforcement

### Phase 2: Purple & White Teams (Weeks 3-4)
**Goal:** Collaboration and governance layers

- [ ] `vorsyghta/core/aar_generator.py` — AAR generation
- [ ] `vorsyghta/agents/purple_team_agent.py` — Purple agent
- [ ] `vorsyghta/cli/purple_team.py` — Purple CLI
- [ ] `vorsyghta/core/rules_of_engagement.py` — RoE engine
- [ ] `vorsyghta/agents/white_team_agent.py` — White agent
- [ ] `vorsyghta/cli/white_team.py` — White CLI
- [ ] Integrate Purple AAR → RAG storage
- [ ] Integrate White RoE → SafetyController
- [ ] Tests: AAR generation, RoE validation, rule violation detection

### Phase 3: Green & Yellow Teams (Weeks 5-6)
**Goal:** Remediation and secure rebuild

- [ ] `vorsyghta/core/remediation_engine.py` — remediation generation
- [ ] `vorsyghta/agents/green_team_agent.py` — Green agent
- [ ] `vorsyghta/cli/green_team.py` — Green CLI
- [ ] `vorsyghta/core/secure_build_engine.py` — IaC/hardening
- [ ] `vorsyghta/agents/yellow_team_agent.py` — Yellow agent
- [ ] `vorsyghta/cli/yellow_team.py` — Yellow CLI
- [ ] Green→Yellow handoff via event bus
- [ ] Tests: remediation generation, build validation, handoff flow

### Phase 4: Orange & Black Teams (Weeks 7-8)
**Goal:** Code review and evaluation

- [ ] `vorsyghta/core/code_review_engine.py` — LLM-enriched SAST
- [ ] `vorsyghta/agents/orange_team_agent.py` — Orange agent
- [ ] `vorsyghta/cli/orange_team.py` — Orange CLI
- [ ] `vorsyghta/core/evaluation_engine.py` — performance evaluation
- [ ] `vorsyghta/agents/black_team_agent.py` — Black agent
- [ ] `vorsyghta/cli/black_team.py` — Black CLI
- [ ] Orange→Yellow advisory handoff
- [ ] Black Team benchmarking against RAG history
- [ ] Tests: code review, threat modeling, evaluation metrics

### Phase 5: RLHF Integration (Weeks 9-10)
**Goal:** Train agents with color-team-specific rewards

- [ ] Extend `AgentRole` enum with color team roles
- [ ] Implement per-team reward functions in `reward_model.py` (per RL plan)
- [ ] Wire Purple AAR scores → Red/Blue reward signals
- [ ] Wire Black evaluation → all teams' reward signals
- [ ] Gym environment integration for Red/Blue agents (per RL plan Part B)
- [ ] Tests: reward signal propagation, agent improvement over rounds

### Phase 6: Full-Spectrum Exercise & Polish (Weeks 11-12)
**Goal:** End-to-end multi-team exercises

- [ ] `vorsyghta exercise run --teams all` full lifecycle
- [ ] Exercise replay from stored events
- [ ] Exercise comparison (historical benchmarking)
- [ ] API endpoints for exercise management (per UI plan)
- [ ] UI surfaces for each color team (per UI plan)
- [ ] Documentation: color team user guide, exercise playbook
- [ ] Integration tests: full-spectrum exercise with all 8 teams
- [ ] Performance tests: event bus under load

---

## 12. File Manifest

### New Files (25)

| File | Phase | Purpose |
|------|-------|---------|
| `vorsyghta/core/event_bus.py` | 1 | Pub/sub event bus |
| `vorsyghta/core/exercise_orchestrator.py` | 1 | Multi-team orchestration |
| `vorsyghta/core/rbac.py` | 1 | Role-based access control |
| `vorsyghta/cli/exercise.py` | 1 | Exercise CLI |
| `vorsyghta/integrations/attack_event_publisher.py` | 1 | Red Team event publishing |
| `vorsyghta/defense/blue_team/reactive_agent.py` | 1 | Autonomous Blue agent |
| `vorsyghta/core/aar_generator.py` | 2 | After Action Review generation |
| `vorsyghta/agents/purple_team_agent.py` | 2 | Purple Team agent |
| `vorsyghta/cli/purple_team.py` | 2 | Purple Team CLI |
| `vorsyghta/core/rules_of_engagement.py` | 2 | Rules of engagement engine |
| `vorsyghta/agents/white_team_agent.py` | 2 | White Team agent |
| `vorsyghta/cli/white_team.py` | 2 | White Team CLI |
| `vorsyghta/core/remediation_engine.py` | 3 | Remediation generation |
| `vorsyghta/agents/green_team_agent.py` | 3 | Green Team agent |
| `vorsyghta/cli/green_team.py` | 3 | Green Team CLI |
| `vorsyghta/core/secure_build_engine.py` | 3 | Secure build/IaC engine |
| `vorsyghta/agents/yellow_team_agent.py` | 3 | Yellow Team agent |
| `vorsyghta/cli/yellow_team.py` | 3 | Yellow Team CLI |
| `vorsyghta/core/code_review_engine.py` | 4 | LLM-enriched code review |
| `vorsyghta/agents/orange_team_agent.py` | 4 | Orange Team agent |
| `vorsyghta/cli/orange_team.py` | 4 | Orange Team CLI |
| `vorsyghta/core/evaluation_engine.py` | 4 | Performance evaluation |
| `vorsyghta/agents/black_team_agent.py` | 4 | Black Team agent |
| `vorsyghta/cli/black_team.py` | 4 | Black Team CLI |
| `vorsyghta/agents/__init__.py` | 2 | Agents package init |

### Modified Files (8)

| File | Phase | Changes |
|------|-------|---------|
| `vorsyghta/cli/main.py` | 1-4 | Register 7 new CLI commands |
| `vorsyghta/core/team_playbooks.py` | 2-4 | Add GREEN, YELLOW, ORANGE, WHITE, BLACK content |
| `vorsyghta/llm/rlhf_multiagent.py` | 5 | Extend `AgentRole` with color team roles |
| `vorsyghta/integrations/attack.py` | 1 | Wire `monitor_flow()` to event bus |
| `vorsyghta/mcp/safety/controller.py` | 2 | Integrate RoE validation |
| `config.yaml` | 1 | Add `color_teams`, `exercise`, `rbac` sections |
| `vorsyghta/core/models.py` | 1 | Add `ColorTeam`, `TeamEvent`, `ExerciseResult` models |
| `vorsyghta/api/main.py` | 6 | Register exercise/team API routers |

### New Test Files (6)

| File | Phase |
|------|-------|
| `tests/unit/test_event_bus.py` | 1 |
| `tests/unit/test_exercise_orchestrator.py` | 1 |
| `tests/unit/test_rbac.py` | 1 |
| `tests/integration/test_purple_team.py` | 2 |
| `tests/integration/test_full_exercise.py` | 6 |
| `tests/unit/test_evaluation_engine.py` | 4 |

---

## 13. How This Makes Vorsyghta the One-Stop Shop

| Capability | Before | After |
|------------|--------|-------|
| Run an attack | `red-team attack` | `exercise run --teams red` |
| Defend against attack | `blue-team siem/edr/...` (manual) | `exercise run --teams blue` (autonomous reactive agent) |
| Get collaboration feedback | Manual AAR | `exercise run --teams red,blue,purple` (auto AAR) |
| Enforce rules of engagement | `SafetyController` (basic) | `exercise run --teams red,blue,white` (full RoE) |
| Fix vulnerabilities found | Manual | `exercise run --teams red,blue,purple,green` (auto remediation) |
| Rebuild securely | Manual | `exercise run --teams green,yellow` (auto IaC + hardening) |
| Review code for vulns | Manual | `orange-team review --code <path>` |
| Evaluate exercise quality | Manual | `exercise run --teams all` (Black Team auto-evaluation) |
| Full-spectrum exercise | Impossible | `exercise run --teams all` (all 8 teams coordinated) |
| Access control | None | RBAC with color team roles |
| Agent training | Content-only RLHF | Per-team reward functions, gym env for Red/Blue |
| Historical benchmarking | RAG search | Black Team trend analysis across exercises |

**The single command `vorsyghta exercise run --scenario <path> --teams all` runs a complete cybersecurity exercise: White sets rules → Red attacks → Blue defends → Purple coaches → Green remediates → Yellow rebuilds → Orange reviews → White verifies → Black evaluates → results stored in RAG.**

---

## 14. Dependencies on Existing Plans

| Plan | Dependency |
|------|------------|
| `ATTACK_INTEGRATION_PLAN.md` | Red Team attack flows feed the event bus; Vorsyghta Attack API is the offensive engine |
| `rl-and-rlhf-improvement-plan.md` | Reward model improvements (Part A) are extended with per-team rewards; Gym env (Part B) trains Red/Blue agents |
| `ui-engineering-plan.md` | Auth system (`core/auth.py`) is extended with RBAC; UI surfaces needed for each color team and exercise management |
| `gap-analysis.md` | Quantum threat agent wires as a Red Team sub-capability; OPA policy engine maps to White Team RoE enforcement |

---

## 15. Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Event bus becomes bottleneck under load | Start with in-memory, add Redis backend in Phase 6 |
| LLM cost for 8 concurrent agents | Use fallback chain (`llm/fallback_chain.py`); cheaper models for Orange/Green code review, premium for Red/Blue reasoning |
| Agent coordination deadlocks | Orchestrator enforces timeouts per phase; White Team can halt |
| RBAC over-engineering for CLI-only use | RBAC optional via config; defaults to `exercise_admin` when disabled |
| Remediation auto-fix introduces bugs | Confidence threshold (0.8 default); human approval for fixes below threshold; Green Team verify step |
| Scope creep | Phased delivery; each phase delivers standalone value |
