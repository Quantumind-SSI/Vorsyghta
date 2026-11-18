# Vorsyghta Content Bible

**Version:** 1.0  
**Last Updated:** 2026-11-08  
**Owner:** Product & Brand

> This bible is the single source of truth for all written, spoken and UI content for Vorsyghta. It synthesizes README.md, docs/architecture/TEAM_ARCHITECTURE.md, docs/guides/, frontend screens, templates/, and config.yaml. It is authoritative for tone, messaging, terminology and product descriptions. Never create marketing copy without consulting this document.

---

## 1. Brand Overview

### Name
**Vorsyghta** (noun) — *a guide who leads the way.*

### Tagline
Run authorized security validation. Keep the evidence.

### One-line positioning
The one-stop agentic cyber platform: simulate adversaries, defend with evidence, and hunt zero-days — in one closed loop.

### Mission
Guide security teams from “we ran a phishing test once a year” to “we continuously simulate, detect, hunt, discover zero-days, and prove our controls against realistic adversaries.”

### Vision
A measurable, replayable security operations platform where every result is either measured or explicitly flagged `simulation=true`, enabling CISOs to defend numbers to a board or auditor.

### Values
- **Authorized use only** — sanctioned targets, lab networks, human approval
- **Evidence first** — measured > simulated > generated > unavailable
- **Honesty guarantee** — never fabricate results; simulation flag propagates to reports
- **Open-core** — Apache-2.0 core, commercial enterprise modules
- **Self-hostable** — local model support, air-gapped deployment

---

## 2. Product Scope — The Seven Capabilities

Vorsyghta is one platform with seven capabilities. Status is stated per capability.

| # | Capability | Deliverable | Status |
|---|------------|-------------|--------|
| 1 | Eight colour teams + orchestrator | `vorsyghta exercise run --scenario <path> --teams all` runs White → Yellow → Red → Blue → Purple → Green → Orange → White → Black over one typed event bus | Shipped (partial) |
| 2 | Intelligence stack | OSINT enrichment, dark-web exposure monitoring, MITRE ATT&CK v14, event-sourced audit trail, hypothesis-driven threat hunting, auto-generated detection rules, digital-twin ingestion | Shipped (partial) |
| 3 | Zero-day research | Coverage-guided fuzzing, SAST, binary analysis, LLM-guided mutation, crash triage, responsible disclosure workflow | Shipped |
| 4 | Quantum / PQC readiness | Crypto inventory, Shor/Grover risk analysis, NIST PQC migration planning, hybrid PQ/TLS validation | Shipped (partial) |
| 5 | Commercial SaaS product | Next.js app, Stripe billing, engagements → assessments → findings → reports workflow. Tiers: Team · Enterprise · Mission | In build |
| 6 | Six simulation paradigms | DES, ABM, GAP, GTE, CRE, HME | Planned |
| 7 | RL / RLHF | Learned reward model, gymnasium-compatible `CyberAttackEnv` | Planned |

All details originate from README.md#platform-scope--the-full-target and docs/architecture/TEAM_ARCHITECTURE.md.

---

## 3. The Teams

### Colour Teams (Exercise Roles)

| Team | Role | Mission | Status |
|------|------|---------|--------|
| 🔴 Red | Offense | Adaptive, MITRE-mapped attack simulation on isolated VMs | Implemented |
| 🔵 Blue | Defense | Real-time detection, correlation, response | Implemented |
| 🟣 Purple | Integration / Coaching | Correlate Red vs Blue, find gaps, generate AAR | Implemented |
| 🟡 Yellow | Builders / Infrastructure | Provision, harden, validate sandbox | Implemented |
| 🟢 Green | Remediation / Automation | Turn findings into fixes & detection-as-code | Partial |
| 🟠 Orange | Code Review / Governance | Pre-release SAST + threat modelling, compliance mapping | Partial |
| ⚪ White | Governance / Referee | Rules of engagement, scope enforcement | Implemented |
| ⚫ Black | Observation / Evaluation | Non-interfering scoring & benchmarking | Partial |

### Functional Teams (Org mapping)
SOC · DFIR · Vulnerability Management · SecOps/DevSecOps · AppSec · Cloud Security · IAM · GRC · Threat Intelligence · TPRM.

Full taxonomy in docs/architecture/TEAM_ARCHITECTURE.md §1.

---

## 4. Audience Personas

| Audience | Need | What Vorsyghta gives |
|----------|------|----------------------|
| Red Team Leads | Autonomous, LLM-driven attack agents that plan, execute, adapt across MITRE ATT&CK kill chain | `vorsyghta/vm/agent.py` AIAttackAgent, MCP tools, VM operator |
| Vulnerability Researchers | Fuzzing, SAST, binary analysis, AI-guided mutation, crash triage | `vorsyghta/research/` pipeline |
| CISOs & Heads of Security | Continuous measurable posture, quantified detection coverage, executive reports | Event-sourced audit trail, Black scoring, compliance mapping |
| Blue Team / SOC Managers | MITRE hunt hypotheses, auto-generated detection rules, NIST 800-61 playbooks | BlueTeam, Purple AAR, detection rules |
| Compliance & GRC Leads | Immutable replayable audit trail | EventStorePort, PostgresEventStore |
| Security Researchers / Academics | Extensible agentic threat simulation & zero-day research | MCP interface, simulation paradigms |

---

## 5. Tone of Voice

### Core principles
- **Authorized. Measured. Validated.** Not cinematic. Industrial control-room tone.
- Evidence contract is visible: every result carries provenance.
- No fabrication. Simulation must be explicit.
- Clear, technical, honest. No superlatives without proof.
- Human approval is a product boundary. Never imply automation replaces judgment.

### Do
- Use “authorized”, “measured”, “explicit states”, “evidence first”.
- Speak in controls: scope, authorize, execute, observe, improve.
- Distinguish Provenance states: Measured / Simulated / Generated / Validated / Unavailable.
- Reference MITRE ATT&CK v14, CWE, CVSS.

### Don’t
- Don’t claim “AI solves security”.
- Don’t use emojis in UI copy except marketing hero.
- Don’t hide simulation flag.
- Don’t use “could potentially”. Prove it or don’t report.

---

## 6. Messaging Pillars

1. **One-stop agentic operations** — eight colour teams, one typed event bus.
2. **Evidence, not theatre** — every result carries provenance; CISO-defensible.
3. **Beyond known CVEs** — real fuzzing/SAST/binary analysis with LLM-guided mutation.
4. **Open core, deployable anywhere** — self-hostable, local models, air-gapped.
5. **Continuous, measurable posture** — live OSINT, dark-web monitoring, ATT&CK coverage.

---

## 7. Product Messaging

### Landing page core copy
- H1: Run authorized security validation. Keep the evidence.
- Lead: Vorsyghta helps security teams scope, execute, observe, and report controlled adversarial assessments with human approval and explicit result provenance.
- CTA: Start trial / Request demo

### Evidence contract vocabulary
- **Measured**: A named tool or data source produced the record.
- **Simulated**: Deterministic scenario produced the result.
- **Generated**: Model generated or summarized the content.
- **Validated**: Analyst reviewed evidence and disposition.
- **Unavailable**: Dependency failed or did not return valid data.

### Brand visual system
- Primary Action: Orange #ff7a1a
- Signal Cyan: #2bbfd7
- Midnight Canvas: #0b0f14
- Warm Paper: #f5f3f0
- Steel Border: #2c3e50
- Mood: Futuristic Megastructures, control-room industrial.

Source: frontend/src/app/brand/page.tsx

### Pricing tiers
- **Team** $299/mo — Up to 5 users, self-hostable, local model support, MITRE mapping
- **Enterprise** Custom — SSO & audit logs, dedicated support, on-prem deployment
- **Mission** Contact us — Air-gapped, custom compliance, 24/7 ops

Source: frontend/src/app/pricing/page.tsx

---

## 8. UI Route Map & Copy Conventions

Public/Marketing: `/`, `/brand`, `/pricing`, `/start-trial`, `/legal/terms`, `/legal/privacy`, `/legal/acceptable-use`

Auth: `/sign-in`, `/register`, `/forgot-password` — no `/reset-password` screen yet.

Onboarding: `/onboarding/*` and `/onboarding-enterprise/*` (welcome, org, identity, team, environments, integrations, compliance, workspace, verify, review, first-value)

App: `/app`, `/app/templates`, `/app/templates/[category]/[name]`, `/app/environments`, `/app/intelligence`, `/app/exercises`, `/app/disclosures`, `/app/findings`, `/app/settings/billing`

Copy conventions:
- Use Title Case for page headings.
- Buttons: Start trial, Request demo, View pricing.
- Evidence states are always labelled on result views.

---

## 9. Terminology Glossary

- **Colour team** — exercise role in full-spectrum exercise.
- **EventBus** — typed bus where teams publish/subscribe; every event → EventStore.
- **Provenance** — Measured / Simulated / Generated / Validated / Unavailable.
- **Sanctioned target** — target labelled `com.vorsyghta.role: sanctioned-target` e.g., Juice Shop.
- **MCP server** — Model Context Protocol exposing VM control, command execution, attack/discovery tools.
- **AAR** — After-Action Review generated by Purple team.
- **ExerciseOrchestrator** — runs White→Black workflow.
- **Simulation flag** — `simulation=true` must propagate to reports.

---

## 10. Template Content Standards

Scenario YAML must include:
- metadata.name, description, version, author, tags
- threat_type, delivery_vector, difficulty_level, estimated_duration
- target_profile.role, department, seniority, security_awareness_level
- behavioral_pattern.mitre_attack_techniques, psychological_triggers, social_engineering_tactics
- simulation_parameters.max_iterations, compliance_mode, content_filtering, audit_logging

Example: templates/executive_phishing.yaml

---

## 11. Safety & Compliance Messaging

- Authorization is a product boundary.
- Vorsyghta is for sanctioned targets and configured lab networks.
- Frontend foundation is read-only; no attack execution controls exposed.
- Human approval remains explicit.
- External destinations fail closed.
- Unavailable data is never replaced with synthetic success.

Source: frontend/src/app/page.tsx safety section; AGENTS.md safety guardrails.

---

## 12. Writing Rules

- Never invent findings. Measured or flagged simulation.
- Use active voice, concise sentences.
- Prefer “evidence” over “data”.
- Use MITRE technique IDs e.g., T1566.001.
- Compliance mappings: PCI-DSS, NDPR, GDPR, SOC 2, ISO 27001, CBN.
- For reports, use structured findings with CWE, CVSS, reproduction steps, PoC.

---

## 13. Example Copy Snippets

**Hero eyebrow:** Authorized use / evidence first

**Principle strip:** Self-hostable · Local model support · MITRE ATT&CK mapping · Open-core repository

**Workflow steps:** Scope → Authorize → Execute → Observe → Improve

**Final CTA:** Make every security result answerable.

---

## 14. References

- README.md — Platform scope, capabilities, architecture
- docs/architecture/TEAM_ARCHITECTURE.md — Team taxonomy, invariants
- docs/guides/USER_GUIDE.md — Installation, CLI, templates
- frontend/src/app/page.tsx — Landing copy and evidence contract
- frontend/src/app/brand/page.tsx — Visual identity
- frontend/src/app/pricing/page.tsx — Pricing tiers
- templates/executive_phishing.yaml — Template schema
- config.yaml — LLM providers, safety, simulation settings
- AGENTS.md — Safety guardrails, prime directive

---

**Maintained by:** Product / Engineering  
**Next review:** 2026-12-08
