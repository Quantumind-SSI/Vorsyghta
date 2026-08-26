# AGENTS.md — Operating Guardrails for AI Agents on Vorsyghta

Any AI agent (coding assistant, the platform's own LLM, or an autonomous team
agent) working in this repository MUST load and obey these rules. They are
binding. They exist because reusing what already exists is cheaper, safer, and
more correct than re-creating it.

## THE PRIME GUARDRAIL — Discover before you create. Ask before you add.

**Do NOT create any new artifact that already exists in this project.** Before
writing a new file, target, script, service, model, config, or tool, you MUST
first search the repository for an existing one and use it. If something
genuinely does not exist and needs to be created, **STOP and ask the human for
explicit approval before creating it.**

"Artifact" includes, at minimum: scripts, modules, classes, docker/compose
services, victim/target machines, scenarios, tests harnesses, config files,
CLI commands, API routes, and documentation files.

### Mandatory pre-creation checklist (run every time)
1. `grep` / `glob` the repo for the capability by name AND by synonym
   (e.g. "target", "victim", "vuln", "harness", "runner", "scenario").
2. Check the canonical locations below.
3. If found → use it. Do not wrap, shadow, or duplicate it.
4. If not found → present a one-line proposal and **wait for a yes** before
   creating anything.

## MANDATORY DEVELOPMENT ENVIRONMENT GATE

Before editing code, generating artifacts, running tests/builds/migrations, or
performing any other development action, every agent MUST verify the project
environment. Read-only repository discovery needed to locate the environment is
the only exception.

1. Work from the repository root and use the repository-local `.venv` only.
   Never run project Python commands with the system/global Python environment.
   If `.venv` or `.venv/bin/poetry` is absent, bootstrap `.venv` with a Python
   version allowed by `pyproject.toml`, install Poetry inside that environment,
   and do not begin development work until the remaining checks pass.
2. Confirm Poetry resolves to the local environment with
   `POETRY_VIRTUALENVS_IN_PROJECT=true .venv/bin/poetry env info --path`; the
   returned path MUST be this repository's `.venv`.
3. Synchronize all declared application, development, and test modules before
   proceeding with
   `POETRY_VIRTUALENVS_IN_PROJECT=true .venv/bin/poetry install --extras dev --extras test`.
   If the lockfile is stale, stop development work, reconcile `pyproject.toml`
   and `poetry.lock`, then repeat the install.
4. Confirm dependency integrity with
   `.venv/bin/python -m pip check` and verify the imports needed by the task.
   Missing or incompatible modules are a blocker: install and declare them in
   the existing dependency configuration before any development work continues.
5. Run Python, pytest, lint, migration, and application commands through
   `.venv/bin/poetry run ...` (or after explicitly activating `.venv`).

## Canonical existing assets — USE THESE, do not recreate

| Need | Use the existing asset | Do NOT create |
|---|---|---|
| Pentest **victim machine** | `docker/targets/juice-shop.yml` (OWASP Juice Shop, sanctioned) | a new vulnerable app / target server |
| Run a **pentest end-to-end** | `scripts/run_sanctioned_target.sh` (`--attack` / `--dry-run`) | a new pentest driver script |
| Pentest **scenario** | `templates/sanctioned_targets/juice_shop_web_pentest.yaml` | a new scenario file |
| **Attack orchestration** | `vorsyghta/core/attack_orchestrator.py` | a parallel orchestrator |
| **Red-team agent** | `vorsyghta/vm/agent.py` (`AIAttackAgent`) | a new agent |
| **Command safety gate** | `vorsyghta/vm/safety.py` (`VMSafetyController`) + `VMOperator.execute_command` (fail-closed) | a new safety check |
| **LLM input/output guardrails** | `vorsyghta/llm/guardrails.py` (`GuardrailsEngine`) | a new guardrail engine |
| **LLM providers / model routing** | `vorsyghta/llm/manager.py` + `vorsyghta/llm/providers/` | a new provider layer |
| **Offensive tool exposure** | `vorsyghta/mcp/tools/attack_tools.py`, `discovery_tools.py` | a new tool wrapper |
| **Findings / vuln reporting** | `vorsyghta/research/vuln_report.py` | a new reporter |

## LLM SCOPE BOUNDS — the platform's AI must stay in-application

The application's own LLM (OpenRouter/`openai/gpt-5.1-chat` by default, see
`config.yaml`) and any agent it drives MUST remain within Vorsyghta's scope:

- **Targets:** only sanctioned targets labelled
  `com.vorsyghta.role: sanctioned-target` (e.g. Juice Shop) or hosts inside the
  configured lab networks. Never production, never external IPs. This is
  enforced by `VMSafetyController` (lab-network allowlist, external-destination
  denylist) and the fail-closed gate in `VMOperator.execute_command`.
- **Commands:** must pass `VMSafetyController.validate_command()`. Destructive
  ops, pipe-to-shell, and external C2 are blocked. Do not add bypass paths.
- **Outputs:** run generated LLM content through `GuardrailsEngine.validate()`
  (PII, credentials, injection). Do not emit unvalidated model output into
  audit, scoring, IAM, or compliance-evidence paths.
- **No new capabilities without approval:** the LLM/agent may not install
  packages, spin up new services, reach new networks, or create new files on
  its own. Those require human approval.

## NO FABRICATION (inherited from the constitution)

Every result must be **measured** or explicitly flagged `simulation=true`.
Never invent findings, test results, or tool output. If a tool/target/key is
missing, say so and stop — do not simulate success.

## VERSION CONTROL

All real work lands in git and is pushed to `origin`
(`https://github.com/QuantmindSSI/Vorsyghta.git`). Scratch/experimental files
belong in `/tmp/opencode`, never committed. Do not leave app logic outside the
repo.

## WHEN IN DOUBT

Ask. A one-line question to the human is always cheaper than an unauthorized
artifact that has to be found and removed later.
