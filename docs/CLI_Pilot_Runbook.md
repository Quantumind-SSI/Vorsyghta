# Ciicerone CLI — Pilot Programme Runbook

> Comprehensive runbook and CLI reference for running a safe, auditable pilot using the Ciicerone CLI.

---

## Overview
This runbook documents full CLI commands, examples, end-to-end pilot flow, safety & approval checklists, automation snippets, KPIs, and deliverables. It is intended for pilot operators: red-team leads, blue-team leads, SOC engineers, platform admins, and legal/risk reviewers.

**Important:** Always run simulations and attack steps only in isolated labs, test tenants, or air-gapped environments. Never target production systems or customer environments.

---

## Audience & Goals
- Audience: Pilot Lead, Red/Blue Team, Platform Engineer, SOC.
- Goals: Validate scenario design; run controlled threat simulations; measure detection fidelity; produce After-Action Reports (AARs); hand over remediations and training materials.

---

## Prerequisites
- Python environment with project dependencies installed (see project README).
- Local config: `~/.ciicerone/config.yaml` (or pass `-c/--config`).
- LLM keys if using AI features:
  - `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY` (export in environment or config).
- Verified isolated lab or test tenant with SIEM / EDR ingestion.
- Approvals from Legal, Risk, and SOC (documented).

---

## Helpful file paths in this repo
- Runbook created here: `docs/CLI_Pilot_Runbook.md`
- Templates folder: `ciicerone/cli/templates.py` and generated templates in `templates/` (use `ciicerone templates`)
- Example scenarios (project may include `scenarios/` or `demos/` folders)

---

## Core CLI command groups (top-level)
- `ciicerone simulate` — execute a threat simulation scenario
- `ciicerone validate` — validate YAML scenario/playbook files
- `ciicerone exercise run` — orchestrate color-team exercises
- `ciicerone report` — generate After-Action Report (AAR)
- `ciicerone llm` — LLM provider utilities and tests
- `ciicerone deploy` — deploy campaigns and delivery templates
- `ciicerone detect` — detection rule generation/validation/conversion
- `ciicerone logs` — list/show/archive/validate logs
- `ciicerone vm` — lab VM management and controlled attacks (lab-only)
- `ciicerone agent` — autonomous agent planning & execution
- `ciicerone rag` — retrieval-augmented generation helpers
- `ciicerone templates` — list and manage templates
- `ciicerone feedback` — feedback loop / learning management
- Domain groups: `intel`, `hunt`, `audit`, `research`, `manuals`, `integrations`, `red-team`, `blue-team`

---

## Key commands with examples
(Use `ciicerone <command> --help` for live options)

### Validate scenarios
- Single file:
```
ciicerone validate path/to/scenario.yaml
```
- Directory (strict mode):
```
ciicerone validate -d ./scenarios --strict
```

### Preview / Dry-run simulation
```
ciicerone simulate -s scenario.yaml --dry-run --preview
```

### Execute simulation (interactive)
```
ciicerone simulate -s scenario.yaml -t "Sales" -o report
```

### Exercise orchestration
```
ciicerone exercise run --config exercise_config.yaml --output-file exercise_result.json
```

### Generate AAR
```
ciicerone report -i exercise_result.json --format html -o aar_my_pilot.html
```

### Deploy campaign (staged)
```
ciicerone deploy campaign --template <template-id> --target <profile>
ciicerone deploy status --campaign <id>
```

### Lab VM management (lab-only)
```
ciicerone vm setup --profile pilot-lab
ciicerone vm start-lab --lab pilot-lab
ciicerone vm attack --lab pilot-lab --stage phishing
ciicerone vm stop-lab --lab pilot-lab
```

### Detection rules
```
ciicerone detect generate --technique T1234 --format sigma
ciicerone detect validate --rules ./rules.yml
ciicerone detect convert --in legacy --out sigma
```

### Logs & evidence
```
ciicerone logs list --source siem
ciicerone logs show --id <log-id>
ciicerone logs archive --output pilot_logs_2026-07-xx.tar.gz
```

---

## Full Pilot Programme Flow (detailed)
This section expands phases and recommended operator actions with checkpoints and approval gates.

### Phase A — Setup & approvals (1–3 days)
1. Create Pilot Plan: stakeholders, goals, KPIs, timeline, scope, exclusions.
2. Legal & Risk sign-off (attach written approval in project docs).
3. Provision isolated lab(s) & test tenants; validate SIEM/EDR ingestion.
4. Create accounts and communication plans; define kill-switch and rollback.

### Phase B — Scenario authoring (1–3 days)
1. Scaffold templates: `ciicerone templates list-all` → `ciicerone templates use <id>`.
2. Author scenarios YAML and embed metadata (owner, MITRE techniques, duration, difficulty).
3. Validate authoring: `ciicerone validate -d ./scenarios --strict`.
4. Peer review and finalize scenarios.

### Phase C — Dry-runs & Blue-team rehearsal (1–2 days)
1. Dry-run previews for each scenario:
   - `ciicerone simulate -s scenario.yaml --dry-run --preview`
2. Blue-team rehearsals: deploy detection rules to test SIEM/EDR and verify alerts.
3. Triage and iterate until detection fidelity acceptable.

### Phase D — Controlled execution (staged)
Goal: increase scope gradually while protecting production.

- Stage D0 — Smoke & Sanity (hours)
  - Validate configs and logs. Approvals checked. Test monitoring and escalation.

- Stage D1 — Small cohort (1–2 days)
  - Run on a small subset in test tenant: `ciicerone simulate -s scenario.yaml` (interactive).
  - Collect `exercise_result.json`, monitor SIEM/EDR, confirm alerts.

- Stage D2 — Full pilot campaign (2–5 days)
  - Deploy campaigns via `ciicerone deploy campaign`, rotate scenarios, monitor continuously.
  - Use `ciicerone deploy monitor` and `ciicerone logs` to collect evidence.

### Phase E — Evidence collection & analysis
1. Centralize artifacts: `exercise_result.json`, saved generated content, logs archive.
2. Run AAR generation: `ciicerone report -i exercise_result.json --format html -o aar.html`.
3. Produce MITRE mapping, detection gap analysis, and prioritized remediation list.

### Phase F — Remediation, training & handover
1. Create remediation tickets with owners and deadlines.
2. Use sanitized examples for blue-team training from generated content.
3. Integrate detection rule CI/CD to deploy validated rules.
4. Final handover: AAR, artifacts, playbooks, and a follow-up schedule.

---

## Safety & Approval Checklist (required before any live run)
- Written legal sign-off for scope and targets.
- Risk assessment & scope document approved.
- Confirmed isolated lab / test tenant (no production exposure).
- SIEM / EDR ingestion validated and monitored.
- On-call SOC contacts and communication windows defined.
- Kill-switch / rollback procedures tested.
- Data handling and retention policy agreed; evidence chain-of-custody planned.

---

## Roles & Responsibilities
- Pilot Lead: coordination, approvals, reporting.
- Red-team operator: scenario authoring, lab execution (lab-only).
- Blue-team lead: detection, validation, monitoring.
- Platform engineer: environment provisioning, integration, kill-switch.
- Legal & Risk: sign-off and compliance.
- SOC on-call: real-time monitoring and response.

---

## Timeline (example 3–4 week pilot)
- Week 0: Approvals, environment setup.
- Week 1: Authoring, validation, rehearsals.
- Week 2: Small cohort runs and iterate detections.
- Week 3: Full pilot, AAR generation, training.
- Week 4: Remediation, handover, metrics review.

---

## Automation / CI snippet (example)
Run these steps in CI for repeatable pilot runs (pseudo-yaml):

```yaml
steps:
  - name: Validate scenarios
    run: ciicerone validate -d ./scenarios --strict

  - name: Preview
    run: ciicerone simulate -s ./scenarios/sample.yaml --dry-run --preview

  - name: Execute exercise
    run: ciicerone exercise run --config ciicerone_exercise_config.yaml --output-file results/exercise_result.json

  - name: Generate AAR
    run: ciicerone report -i results/exercise_result.json --format json -o results/aar.json

  - name: Archive evidence
    run: tar -czf artifacts/pilot_artifacts_$(date +%F).tar.gz results/ generated_content/ pilot_logs/
```

---

## KPIs & Metrics
- Detection rate (% simulated attacks detected)
- Mean time to detect (MTTD)
- Mean time to respond (MTTR)
- False positive rate for detection rules
- Number of staff trained and learning outcomes
- Remediation completion rate and time to remediate

---

## Artifact naming & storage
- `exercise_result_<id>.json`
- `aar_<id>.html` / `aar_<id>.csv`
- `pilot_logs_<date>.tar.gz`
- `generated_content/<scenario_id>_<timestamp>.json`
- Store artifacts in a secure, access-controlled artifact storage (S3, internal share).

---

## Safe operation notes
- Never run `ciicerone vm attack` or live delivery against production systems.
- Use `--dry-run` and `--preview` liberally during development.
- Maintain an audit log of all CLI runs (stdout + exit codes).

---

## Deliverables from this runbook
- Playbook and checklist for safe pilot execution.
- CLI command cheat-sheet with examples.
- Automation snippet for CI pipelines.
- Evidence & reporting naming conventions.

---

## Where this file lives
Project path: `docs/CLI_Pilot_Runbook.md` (relative to repository root).
Absolute path in your environment:
`/home/azureuser/Ciicerone/docs/CLI_Pilot_Runbook.md`

---

## Next steps
- Commit and version this document as part of the repo. Consider adding it to release notes and the maintainer docs.
- If you want, I can also:
  - Export this to PDF
  - Add a pilot approval checklist JSON or YAML
  - Generate scaffold scenario YAMLs under `demos/` for immediate testing

---

*Generated by Copilot CLI session.*
