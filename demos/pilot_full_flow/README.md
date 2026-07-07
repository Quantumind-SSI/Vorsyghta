# Ciicerone Pilot Demo — Full 8-Team Color-Team Flow

A highly technical demo for maintainers showing the entire Ciicerone application
in full flow across all 8 color teams.

## Quick Start

```bash
# Full demo (offline, mocked LLM — no API keys needed)
bash demos/pilot_full_flow/run_pilot_demo.sh

# Skip the 8-team exercise run (faster, just shows system state)
bash demos/pilot_full_flow/run_pilot_demo.sh --quick

# Use real LLM (requires Ollama or API keys)
bash demos/pilot_full_flow/run_pilot_demo.sh --live
```

## What This Demo Shows

### 10 Phases

| Phase | Team/Area | What's Demonstrated |
|---|---|---|
| 0 | Pre-flight | Python imports, 31 ORM tables, Alembic migrations, OpenAPI schema, CLI groups |
| 1 | Yellow Team | Infrastructure provisioning (6 components), validation, resource monitoring |
| 2 | White Team | 7 ROE rules, scope approval, ROE violation detection, risk scoring (0-100) |
| 3 | All 8 Teams | Full orchestrated exercise: Yellow→White→Red→Blue→Purple→Black→Green→Orange |
| 4 | Purple Team | AAR report generation (JSON, HTML, CSV output formats) |
| 5 | Integrations | M365, Proofpoint, KnowBe4, Slack — API + CLI status |
| 6 | SSO | OIDC + SAML provider configuration, group-to-role mapping, API endpoints |
| 7 | Vault/KMS | HashiCorp Vault, Azure KeyVault, AWS SM, Env — provider chain |
| 8 | Red Team | AttackOrchestrator CLI (standalone, no external API) |
| 9 | Tests | Regression (25), extended color teams (52), E2E (24) |
| 10 | Git | Commit history, working tree status |

### Output Files

The demo writes to `demos/pilot_full_flow/output/`:
- `exercise_result.json` — full 8-team exercise result
- `aar_report.json` — AAR in JSON format
- `aar_report.html` — AAR in HTML format
- `aar_report.csv` — AAR in CSV format

## Requirements

- Python 3.11+
- ciicerone installed (`pip install -e .`)
- No API keys required for offline mode (LLM calls are mocked)
- For `--live` mode: Ollama running locally or `OPENROUTER_API_KEY` / `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` set

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    ExerciseOrchestrator                         │
│                                                                 │
│  Yellow → White → Red → Blue → Purple → Black → Green → Orange  │
│  (provision)  (ROE)  (attack) (detect) (AAR)  (score) (train) (comply) │
│                                                                 │
│  All teams communicate via EventBus with typed events           │
│  All results collected in ExerciseResult                        │
└─────────────────────────────────────────────────────────────────┘
```

## Color Team Responsibilities

| Team | Role | Module |
|---|---|---|
| Red | Attack simulation | `vm/agent.py`, `core/attack_orchestrator.py` |
| Blue | Detection & response | `defense/blue_team/` (8 modules) |
| Purple | After-action report | `core/aar_generator.py` |
| Black | Exercise scoring | `core/evaluation_engine.py` |
| White | ROE & governance | `core/white_team.py` |
| Yellow | Infrastructure | `core/yellow_team.py` |
| Green | Training & awareness | `core/green_team.py` |
| Orange | Compliance & regulatory | `core/orange_team.py` |
