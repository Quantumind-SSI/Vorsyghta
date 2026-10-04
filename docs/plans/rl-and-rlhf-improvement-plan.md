# RL & RLHF Improvement Plan

> **Platform scope.** This document defines **capability #7 of seven** in Vorsyghta's full scope: the learned reward model and gymnasium `CyberAttackEnv`. See the canonical statement in **[README § Platform scope — the full target](../../README.md#platform-scope--the-full-target)**.

Concrete, file-by-file implementation plan for two efforts:

- **Part A (short-term):** Replace the handcrafted linear reward model in `RLHFOptimizer` with a real learned reward model.
- **Part B (medium-term):** Wrap the VM attack environment in a gym-style interface so attack agents can be trained with RL.

---

## Part A: Real Reward Model for RLHFOptimizer

### Problem

`vorsyghta/llm/rlhf_multiagent.py` `RLHFOptimizer` (lines 44-336) uses a handcrafted linear reward model:

- `_extract_content_features` (lines 148-196): counts keywords like "company", "urgent", "deadline" to produce feature scores.
- `_calculate_reward` (lines 198-206): dot product of features with hand-tuned weights.
- `_update_reward_model` (lines 114-146): manual gradient descent on the linear model.
- `_apply_policy_update` (lines 296-319): epsilon-greedy selection between 5 hardcoded template string variations (comment says "LLM generation to be implemented").

This is not a learned reward model. It cannot generalize beyond the hardcoded keyword lists.

### Approach: Dual reward model (LLM-as-judge + scikit-learn fallback)

The codebase already has LLM providers (`vorsyghta/llm/base.py` `BaseLLMProvider`) and the multi-agent system already uses LLM evaluation (`_agent_evaluate`, lines 604-654). The cleanest path is to reuse that infrastructure for the reward model, with a scikit-learn classifier as an offline-trained fallback when no LLM is available.

### File-by-file changes

#### 1. New file: `vorsyghta/llm/reward_model.py`

A `RewardModel` abstraction with two implementations:

```
class RewardModel(ABC):
    async def score(self, content: str, prompt: str, content_type: str) -> float
    def update(self, feedback: HumanFeedback, content: str, prompt: str) -> None
    def save(self, path: str) -> None
    def load(self, path: str) -> None

class LLMJudgeRewardModel(RewardModel):
    # Uses an LLM provider to score content on the same dimensions
    # the existing reward weights cover (realism, effectiveness, safety,
    # educational_value, technical_accuracy, creativity).
    # Returns a 0-1 score. Caches scores to avoid redundant API calls.
    # Prompt is a structured rubric asking the LLM to rate each dimension
    # and return JSON {"realism": 0.8, "effectiveness": 0.7, ...}.

class SklearnRewardModel(RewardModel):
    # A GradientBoostingRegressor (scikit-learn, already in requirements.txt)
    # trained on (content_features -> human_rating) pairs.
    # Features: TF-IDF vectors of content + the existing handcrafted features
    # as supplementary numeric features.
    # update() appends to training buffer; retrains every N samples.
    # Falls back to handcrafted features if too few samples (<50).

class HybridRewardModel(RewardModel):
    # Uses LLMJudgeRewardModel when an LLM provider is available.
    # Falls back to SklearnRewardModel when no LLM (offline mode).
    # Blends both when both are available (weighted average, LLM weighted higher).
```

Key design decisions:
- Reuse `HumanFeedback` dataclass (lines 22-31) as the training signal — no schema changes needed.
- Reuse the existing dimension names from `_initialize_reward_weights` (lines 61-82) as the LLM rubric dimensions, so downstream code that reads `reward_model_weights` still works.
- `scikit-learn` is already in `requirements.txt` (line 36). No new dependencies for the fallback path.

#### 2. Edit: `vorsyghta/llm/rlhf_multiagent.py`

Modify `RLHFOptimizer`:

- **`__init__` (line 53):** Accept an optional `reward_model: Optional[RewardModel]` and optional `llm_provider: Optional[BaseLLMProvider]`. If `reward_model` is None, construct a `HybridRewardModel(llm_provider=llm_provider)`. Keep `reward_model_weights` for backward compatibility / inspection, but stop using it for scoring.
- **`_update_reward_model` (lines 114-146):** Replace the manual gradient descent with `self.reward_model.update(feedback, content, prompt)`. Keep the logging.
- **`_calculate_reward` (lines 198-206):** Replace with `await self.reward_model.score(content, prompt, content_type)`. Since this is now async, update callers (`optimize_prompt_template` line 235, `_generate_with_rlhf` in `advanced_integration.py`).
- **`_extract_content_features` (lines 148-196):** Keep as a public method `extract_content_features` — the `SklearnRewardModel` uses it as supplementary numeric features, and it's useful for debugging/inspection.
- **`_generate_template_variations` (lines 252-279):** Replace the 5 hardcoded string replacements with actual LLM generation. Use `self.llm_provider` (if available) to generate N variations of the template by prompting the LLM to rewrite the template with different strategies (add reasoning, add examples, add quality criteria, etc.). Fall back to the existing hardcoded variations if no LLM provider.
- **`_apply_policy_update` (lines 296-319):** Keep the epsilon-greedy selection but rename to `_select_template` to stop mislabeling it as "policy gradient". The comment on line 302 already says "policy gradient-style" — make the name honest.

Make `_calculate_reward` async (it now calls the LLM). Update callers:
- `optimize_prompt_template` line 235: `predicted_score = await self._calculate_reward(features)` → `predicted_score = await self.reward_model.score(variation, current_template, content_type)`. The feature extraction moves inside the reward model.
- `advanced_integration.py` `_generate_with_rlhf` (around line 354): update to await the now-async reward calculation.

#### 3. Edit: `vorsyghta/llm/advanced_integration.py`

- **`__init__` (line 57):** Pass `llm_provider` to `RLHFOptimizer` so it can construct the `HybridRewardModel`. The `AdvancedPromptEngineering` class doesn't currently hold an LLM provider — it receives one per-call in `generate_advanced_content`. Two options:
  - **Option 1 (preferred):** Pass `llm_provider` to `RLHFOptimizer` lazily in `_generate_with_rlhf` by setting `self.rlhf_optimizer.set_llm_provider(llm_provider)` at the start of that method.
  - **Option 2:** Add `llm_provider` to `AdvancedPromptEngineering.__init__`. More invasive.
- **`_generate_with_rlhf` (around line 354):** Update to handle async reward scoring. The method already calls `self.rlhf_optimizer.optimize_prompt_template` which is already async, so the async reward call fits naturally.

#### 4. New file: `tests/unit/test_reward_model.py`

Test patterns following `tests/unit/test_model_fallback_chain.py` conventions (MockProvider, AsyncMock, pytest-asyncio):

- `test_llm_judge_reward_model_scores_content`: Mock LLM returns JSON rubric scores, verify composite score is 0-1 and weighted correctly.
- `test_sklearn_reward_model_trains_on_feedback`: Feed 60 mock `HumanFeedback` samples, verify model retrains and predictions change.
- `test_sklearn_reward_model_fallback_with_few_samples`: With <50 samples, verify it falls back to handcrafted features.
- `test_hybrid_reward_model_blends_scores`: Both LLM and sklearn available, verify weighted blend.
- `test_hybrid_reward_model_falls_back_without_llm`: No LLM provider, verify sklearn-only path.
- `test_reward_model_save_load`: Train, save, load, verify predictions match.
- `test_rlhf_optimizer_uses_learned_reward_model`: Integration test — verify `RLHFOptimizer` delegates scoring to `RewardModel` instead of the linear model.

### Dependencies

- **No new dependencies.** `scikit-learn` is already in `requirements.txt` (line 36). LLM providers already integrated.
- Optional: add `joblib` for model save/load (scikit-learn models use pickle by default; joblib is a scikit-learn dependency so it's already installed transitively).

### Verification

```bash
pytest tests/unit/test_reward_model.py -v
pytest tests/unit/ -k "rlhf or reward" -v
ruff check vorsyghta/llm/reward_model.py vorsyghta/llm/rlhf_multiagent.py
mypy vorsyghta/llm/reward_model.py
```

### Scope estimate

- 1 new file (~250 lines): `vorsyghta/llm/reward_model.py`
- 1 edited file: `vorsyghta/llm/rlhf_multiagent.py` (~80 lines changed)
- 1 edited file: `vorsyghta/llm/advanced_integration.py` (~15 lines changed)
- 1 new test file (~300 lines): `tests/unit/test_reward_model.py`

---

## Part B: Gym-Style Wrapper for VM Attack Environment

### Problem

`vorsyghta/vm/agent.py` `AIAttackAgent` executes attacks via LLM reasoning on real VMs. It has no gym-style interface — no `reset()`, `step()`, state vector, action space, or reward function. There's no way to run training episodes or learn a policy. The agent's "policy" is an LLM prompt, not a learned function.

The existing data models are close to what's needed but not structured for RL:

- `AgentState` (models.py lines 170-194): has `compromised_hosts`, `collected_credentials`, `discovered_services`, `action_history`, `command_history` — good raw state data, but not a vector/observation.
- `AttackResult` (models.py lines 197-232): has `success`, `objectives_completed`, `success_rate`, `mitre_techniques_used`, `alerts_generated`, `detection_coverage` — good raw reward signal data, but not a scalar reward.
- `CommandResult` (models.py lines 103-122): has `exit_code`, `stdout`, `stderr` — the per-step outcome.
- `AttackStep` (models.py lines 125-143): has `phase`, `technique_id`, `commands`, `success_indicators` — close to an action representation.

### Approach: Gymnasium-compatible environment wrapping AIAttackAgent

Build a `CyberAttackEnv` that wraps the existing `AIAttackAgent` + `VMOperator` and exposes the standard gym interface (`reset`, `step`, `render`, `close`). Use `gymnasium` (the maintained successor to `gym`) as the interface, but keep it optional so the core platform doesn't require it.

### File-by-file changes

#### 1. New dependency: `gymnasium` (optional)

Add to `pyproject.toml` optional-dependencies and `requirements.txt` under a new section:

```toml
[project.optional-dependencies]
rl = [
    "gymnasium>=0.29.0",
    "stable-baselines3>=2.2.0",  # for PPO/DQN training (Part B phase 2)
]
```

Add to `requirements.txt`:
```
# ================================
# Reinforcement Learning (Optional)
# ================================
# Install with: pip install -r requirements.txt[rl]
# gymnasium>=0.29.0
# stable-baselines3>=2.2.0
```

Keep these optional — the env wrapper works without them by exposing a minimal interface that doesn't inherit from `gymnasium.Env` (see below).

#### 2. New file: `vorsyghta/vm/rl/__init__.py`

```
from .environment import CyberAttackEnv, CyberAttackEnvConfig
from .observation import ObservationEncoder, ObservationSpace
from .action import ActionSpace, AttackAction, ActionEncoder
from .reward import RewardFunction, RewardConfig

__all__ = [
    "CyberAttackEnv", "CyberAttackEnvConfig",
    "ObservationEncoder", "ObservationSpace",
    "ActionSpace", "AttackAction", "ActionEncoder",
    "RewardFunction", "RewardConfig",
]
```

#### 3. New file: `vorsyghta/vm/rl/action.py`

Define the action space. Actions map to attack commands the agent can execute on the VM.

```
@dataclass
class AttackAction:
    command: str           # The shell command to execute
    phase: AttackPhase     # MITRE phase
    technique_id: str      # MITRE technique ID
    target_vm: str         # Which VM to target

class ActionSpace:
    """Discrete action space over a curated set of attack commands.
    
    Phase 1: A fixed catalog of ~100 common attack commands mapped to MITRE
    techniques (nmap scans, impacket calls, hydra, sqlmap, etc.) — derived
    from the tools listed in agent.py ATTACK_PLANNING_PROMPT (lines 38-44).
    
    Phase 2: Extend with LLM-generated actions (the agent proposes a command,
    the action space validates it against the safety controller).
    
    The catalog is loaded from a YAML file (vorsyghta/vm/rl/action_catalog.yaml)
    so it's extensible without code changes.
    """
    def __init__(self, catalog_path: str, safety_controller: VMSafetyController)
    def sample() -> AttackAction
    def contains(action: AttackAction) -> bool
    def n() -> int  # number of discrete actions
```

Design decision: start with a **discrete** action space (a catalog of commands) rather than continuous. This matches how the existing agent works (it executes discrete commands) and is compatible with DQN/PPO out of the box. Continuous action generation (free-form LLM commands) is a Phase 2 extension.

#### 4. New file: `vorsyghta/vm/rl/action_catalog.yaml`

YAML catalog of attack commands mapped to MITRE techniques. Structure:

```yaml
actions:
  - id: nmap_full_scan
    command: "nmap -sV -p- {target_ip}"
    phase: reconnaissance
    technique_id: T1595.001
    technique_name: "Active Scanning: Scanning IP Blocks"
    parameters: [target_ip]
    
  - id: hydra_ssh
    command: "hydra -l {username} -P {wordlist} ssh://{target_ip}"
    phase: credential_access
    technique_id: T1110.001
    technique_name: "Brute Force: Password Cracking"
    parameters: [target_ip, username, wordlist]
    
  # ... ~100 entries covering recon, initial_access, execution,
  # persistence, priv_escalation, credential_access, lateral_movement,
  # collection, exfiltration
```

#### 5. New file: `vorsyghta/vm/rl/observation.py`

Encode `AgentState` into a fixed-size observation vector.

```
class ObservationEncoder:
    """Encodes AgentState into a fixed-size numeric observation vector.
    
    Observation components (each normalized to 0-1):
    - Current phase (one-hot encoded, 14 phases from AttackPhase enum)
    - Number of compromised hosts (normalized by max_hosts)
    - Number of collected credentials (normalized by max_creds)
    - Number of discovered services (normalized by max_services)
    - Number of completed objectives (normalized by total_objectives)
    - Number of commands executed (normalized by max_steps)
    - Last command exit code (0=success, 1=failure, -1=blocked)
    - Detection indicators present (binary flags for each IOC type)
    
    Total observation dimension: ~50-80 depending on config.
    """
    def __init__(self, config: CyberAttackEnvConfig)
    def encode(state: AgentState, last_result: Optional[CommandResult]) -> np.ndarray
    @property
    def dim(self) -> int
```

Design decision: start with a **handcrafted feature vector** (like the existing `_extract_content_features` approach but for attack state). This is fast, debuggable, and works with any RL algorithm. A learned observation encoder (e.g., embedding command outputs via an LLM) is a Phase 2 extension.

#### 6. New file: `vorsyghta/vm/rl/reward.py`

```
@dataclass
class RewardConfig:
    # Per-step rewards
    command_success: float = 0.1        # command exited 0
    command_failure: float = -0.05      # command exited non-zero
    command_blocked: float = -0.1       # safety controller blocked it
    
    # Discovery rewards
    new_host_discovered: float = 0.5
    new_service_discovered: float = 0.2
    new_credential_found: float = 1.0
    
    # Progress rewards
    host_compromised: float = 2.0
    objective_completed: float = 5.0
    
    # Stealth penalties (negative reward for being detected)
    alert_generated: float = -0.5
    detection_coverage_hit: float = -1.0
    
    # Episode end rewards
    all_objectives_completed: float = 10.0
    timeout_penalty: float = -2.0
    error_penalty: float = -1.0
    
    # Per-step time penalty (encourages efficiency)
    step_penalty: float = -0.01

class RewardFunction:
    """Calculates reward from state transitions.
    
    Compares previous AgentState to current AgentState to compute
    delta-based rewards (new hosts, new creds, new alerts, etc.).
    Also incorporates CommandResult success/failure.
    """
    def __init__(self, config: RewardConfig)
    def calculate(
        self,
        prev_state: AgentState,
        curr_state: AgentState,
        command_result: CommandResult,
        step_result: Dict[str, Any],  # from _execute_step
        episode_done: bool,
    ) -> float
```

Design decision: reward shaping is the hardest part of RL for cybersecurity. Start with a **simple dense reward** (per-step deltas) with clear positive signals for progress (hosts compromised, creds found) and negative signals for detection (alerts generated). The `alerts_generated` and `detection_coverage` fields in `AttackResult` (models.py lines 231-232) provide the detection signal — but these are only populated at episode end in the current code. **This requires modifying `AIAttackAgent._analyze_and_adapt` to populate detection indicators per-step** (see file change #8 below).

#### 7. New file: `vorsyghta/vm/rl/environment.py`

The main environment class.

```
@dataclass
class CyberAttackEnvConfig:
    scenario: Dict[str, Any]           # Attack scenario (from YAML template)
    target_info: Dict[str, Any]        # Target environment info
    attacker_vm: str                   # VM ID of attacker
    target_vms: List[str]              # VM IDs of targets
    max_steps: int = 50                # Max steps per episode
    reward_config: RewardConfig = field(default_factory=RewardConfig)
    restore_snapshot_between_episodes: bool = True  # reset VM state via snapshot
    use_gymnasium: bool = True         # If True, inherit from gymnasium.Env

class CyberAttackEnv:
    """Gym-style environment for cyber attack simulation.
    
    Wraps AIAttackAgent + VMOperator into a standard RL interface.
    
    If gymnasium is installed, inherits from gymnasium.Env and registers
    spaces properly. If not, exposes the same interface without inheritance
    (duck-typing) so the core platform works without the RL dependency.
    
    Lifecycle:
        reset() -> observation, info
            - Restores VM snapshots (if configured)
            - Creates fresh AgentState
            - Optionally generates a new attack plan via LLM
            - Returns initial observation
        
        step(action) -> observation, reward, terminated, truncated, info
            - Maps AttackAction to a command
            - Executes via AIAttackAgent._execute_step (or directly via VMOperator)
            - Updates AgentState via _analyze_and_adapt
            - Calculates reward via RewardFunction
            - Checks termination (all objectives, timeout, max steps, error)
            - Returns observation, reward, terminated, truncated, info
        
        render() -> None
            - Logs current state (text mode) or captures screenshot (rgb mode)
        
        close() -> None
            - Cleans up VMs (optional: destroy or leave running)
    """
    def __init__(
        self,
        agent: AIAttackAgent,
        vm_operator: VMOperator,
        config: CyberAttackEnvConfig,
    )
    
    async def reset(self) -> Tuple[np.ndarray, Dict[str, Any]]
    async def step(self, action: AttackAction) -> Tuple[np.ndarray, float, bool, bool, Dict]
    async def render(self, mode: str = "text") -> None
    async def close(self) -> None
```

Key design decisions:
- **Async gym interface:** Gymnasium's standard interface is sync. Since `VMOperator` and `AIAttackAgent` are fully async, the env methods are async. This means it won't work directly with `stable-baselines3` (which expects sync envs). **Solution:** provide an `AsyncToSyncWrapper` that runs the async env in an event loop (Phase 1), or use an async-compatible RL library like `CleanRL` or `tianshou` (Phase 2). Document this clearly.
- **Snapshot-based reset:** The existing `AIAttackAgent.execute_attack` already creates pre-attack snapshots (agent.py lines 269-273). `reset()` restores these snapshots to get a clean state. This is critical for RL — each episode must start from the same (or similar) state.
- **Action execution:** `step()` calls `AIAttackAgent._execute_step` with a single-step `AttackStep` constructed from the `AttackAction`. This reuses all the existing command refinement, safety validation, and result analysis logic.

#### 8. Edit: `vorsyghta/vm/agent.py`

Modify `AIAttackAgent` to support single-step execution and per-step detection tracking:

- **New method `execute_single_action(action: AttackAction) -> Tuple[CommandResult, Dict]`:** Executes a single action (command) on the current VM, runs `_analyze_and_adapt` to update state, and returns the result + analysis. This is what `CyberAttackEnv.step()` calls. It's a thin wrapper around the existing `_execute_step` + `_analyze_and_adapt` that works with a single command instead of a full `AttackStep`.
- **Modify `_analyze_and_adapt` (lines 437-490):** Currently only updates `compromised_hosts`, `collected_credentials`, `discovered_services`. Add per-step detection indicator tracking: store `analysis.get("detection_indicators", [])` into `self.state` as a new field `detection_indicators: List[str]`. This feeds the reward function's stealth penalty.
- **New method `get_state_snapshot() -> AgentState`:** Returns a deep copy of the current `AgentState`. The env needs this to compute reward deltas (prev vs curr state).
- **New method `reset_state() -> None`:** Clears `self.state`, `self.attack_log`, `self._current_plan`. Used by `CyberAttackEnv.reset()`.

#### 9. Edit: `vorsyghta/vm/models.py`

Add `detection_indicators` field to `AgentState`:

```python
@dataclass
class AgentState:
    # ... existing fields ...
    detection_indicators: List[str] = field(default_factory=list)  # NEW
```

#### 10. New file: `vorsyghta/vm/rl/async_wrapper.py`

```
class AsyncToSyncEnv:
    """Wraps CyberAttackEnv (async) into a sync gymnasium-compatible interface.
    
    Runs async methods in an event loop so the env can be used with
    stable-baselines3, which expects sync envs.
    
    Usage:
        async_env = CyberAttackEnv(agent, vm_op, config)
        sync_env = AsyncToSyncEnv(async_env)
        model = PPO("MlpPolicy", sync_env, verbose=1)
        model.learn(total_timesteps=10000)
    """
```

#### 11. New file: `vorsyghta/vm/rl/training.py` (Phase 2)

```
class AttackAgentTrainer:
    """Trains an RL policy on CyberAttackEnv.
    
    Phase 2 — uses stable-baselines3 PPO or DQN.
    
    Phase 1 scope: just the env + a random-agent baseline that samples
    actions from ActionSpace and runs episodes to verify the env works.
    """
    def __init__(self, env: CyberAttackEnv, algorithm: str = "ppo")
    def train(self, total_timesteps: int = 10000) -> Any  # returns trained policy
    def evaluate(self, n_episodes: int = 10) -> Dict[str, float]
    def save_policy(self, path: str) -> None
    def load_policy(self, path: str) -> None
```

#### 12. New file: `tests/unit/test_cyber_attack_env.py`

Test patterns following `test_model_fallback_chain.py` (MockProvider, AsyncMock):

- `test_env_reset_returns_initial_observation`: Mock VMOperator, verify reset returns correct observation shape and info dict.
- `test_env_step_executes_action`: Mock VMOperator.execute_command to return canned output, verify step returns (obs, reward, terminated, truncated, info).
- `test_env_step_updates_state`: Execute a scan action, mock LLM analysis to return new hosts, verify observation reflects updated state.
- `test_reward_function_progress`: Verify reward increases when new host is compromised.
- `test_reward_function_stealth_penalty`: Verify reward decreases when detection indicators are present.
- `test_reward_function_blocked_command`: Verify negative reward when safety controller blocks a command.
- `test_env_terminates_on_all_objectives`: Mock all objectives completed, verify terminated=True.
- `test_env_terminates_on_max_steps`: Run max_steps actions, verify truncated=True.
- `test_env_snapshot_restore_on_reset`: Verify VMOperator.restore_snapshot is called on reset.
- `test_observation_encoder_dimension`: Verify encoded observation has correct fixed dimension.
- `test_action_space_contains_valid_action`: Verify a catalog action passes contains() check.
- `test_action_space_rejects_unsafe_action`: Verify an action with a blocked command fails contains() check.
- `test_async_to_sync_wrapper`: Verify sync wrapper correctly delegates to async env.
- `test_random_agent_baseline`: Run 5 episodes with random action sampling, verify no crashes and rewards are computed.

### Dependencies

- **New optional dependency:** `gymnasium>=0.29.0` (for the gym interface inheritance and space definitions)
- **New optional dependency (Phase 2 only):** `stable-baselines3>=2.2.0` (for PPO/DQN training)
- Both are optional — the env works without them via duck-typing.
- `numpy` already in `requirements.txt` (line 34) — needed for observation vectors.

### Verification

```bash
# Phase 1 (env + random agent baseline)
pytest tests/unit/test_cyber_attack_env.py -v
ruff check vorsyghta/vm/rl/
mypy vorsyghta/vm/rl/environment.py

# Phase 2 (with RL training, requires optional deps)
pip install gymnasium stable-baselines3
pytest tests/unit/test_cyber_attack_env.py -v -k "training or ppo or dqn"
```

### Scope estimate

**Phase 1 (env + observation + action + reward + random baseline):**
- 7 new files (~1200 lines total): `vorsyghta/vm/rl/{__init__,action,observation,reward,environment,async_wrapper}.py` + `action_catalog.yaml`
- 1 edited file: `vorsyghta/vm/agent.py` (~60 lines changed)
- 1 edited file: `vorsyghta/vm/models.py` (~3 lines added)
- 1 new test file (~400 lines): `tests/unit/test_cyber_attack_env.py`
- 2 edited files: `pyproject.toml`, `requirements.txt` (optional deps)

**Phase 2 (RL training with stable-baselines3):**
- 1 new file (~200 lines): `vorsyghta/vm/rl/training.py`
- Extended tests in `test_cyber_attack_env.py` (~150 lines added)

---

## Implementation Order

1. **Part A first** — it's smaller, has no new dependencies, and directly improves existing functionality. The reward model abstraction also benefits Part B (the `RewardFunction` in the gym env could use the same `RewardModel` interface for learned reward shaping later).

2. **Part B Phase 1** — env + observation + action + reward + random agent baseline. This proves the interface works end-to-end without needing RL training infrastructure.

3. **Part B Phase 2** — RL training with stable-baselines3. This requires the optional `gymnasium` + `stable-baselines3` deps and a working VM lab environment to run real episodes.

---

## Risks & Open Questions

### Part A
- **LLM-as-judge cost:** Scoring every template variation via LLM adds API calls. Mitigation: cache scores, batch evaluations, and fall back to sklearn model for high-volume runs.
- **Scikit-learn model cold start:** With <50 feedback samples, the model can't train. Mitigation: fall back to handcrafted features (already implemented in the existing code).

### Part B
- **Async vs sync gym interface:** Gymnasium is sync, VM operations are async. The `AsyncToSyncWrapper` handles this but adds complexity. Alternative: use `tianshou` or `CleanRL` which support async. Decision: wrapper for Phase 1 (broad compatibility), evaluate async-native RL libs for Phase 2.
- **Episode reset cost:** Restoring VM snapshots is slow (seconds to minutes per reset). This limits training throughput. Mitigation: (1) use Docker containers (faster snapshot/restore than Proxmox), (2) batch parallel envs, (3) accept slower training for cyber RL (episodes are expensive but informative).
- **Reward shaping is hard:** The proposed dense reward may lead to reward hacking (agent finds a way to trigger "new host discovered" without actually compromising anything). Mitigation: validate rewards against ground truth (actual VM state) not just LLM analysis of command output.
- **Action space coverage:** A fixed catalog of ~100 commands limits what the agent can do. The existing LLM-based agent can generate arbitrary commands. Mitigation: Phase 2 extends the action space with LLM-generated actions validated by the safety controller.
- **Real VM requirement:** Training requires a running VM lab. This can't be done in CI. Mitigation: (1) unit tests use mocked VMOperator, (2) integration tests run against Docker-based lab with a documented setup script, (3) training is a manual/CI-on-demand step, not part of the test suite.
