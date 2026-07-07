# Ciicerone

**The agentic cyber threat simulation platform that unifies red, blue, and purple team operations — and closes the loop with intelligence, detection, and compliance.**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0 + Commercial](https://img.shields.io/badge/license-Apache%202.0%20%2B%20Commercial-blue.svg)](LICENSE)
[![FastAPI](https://img.shields.io/badge/API-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20v14-red.svg)](https://attack.mitre.org/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](docs/community/CONTRIBUTING.md)

> **Ciicerone** (noun) — *a guide who leads the way.* We guide security teams from "we ran a phishing test once a year" to "we continuously simulate, detect, hunt, and prove our controls against realistic adversaries."

---

## Licensing — Read This First

Ciicerone is **open-core**. The simulation engine, CLI, YAML template system, and basic LLM provider abstraction are open source under **Apache 2.0**. The intelligence stack, event-sourced audit trail, blue team modules, multi-team orchestration, enterprise integrations, and other production-grade capabilities are licensed commercially.

- **Open source core** — see [`LICENSE`](LICENSE) (Apache 2.0).
- **Commercial modules** — see [`docs/licensing/COMPONENT_MATRIX.md`](docs/licensing/COMPONENT_MATRIX.md) for the full component-by-component breakdown and commercial terms.

This README describes the platform's capabilities. Not all capabilities described are part of the open-source release.

---

## Why Ciicerone Exists

Most security programs are stitched together from disconnected tools: a phishing simulator here, a SIEM there, a red team engagement once a quarter, a compliance spreadsheet somewhere else. The result is a **broken feedback loop** — offensive findings never reach defenders in time, defenders can't validate detections against realistic attacks, and executives can't prove their security posture to regulators, auditors, or boards with anything more convincing than a static report.

Ciicerone replaces that patchwork with a single platform where **every team operates from one source of truth**. It generates context-aware threats, executes them autonomously, captures defensive telemetry, correlates the two, and produces audit-ready evidence — all from one CLI, one API, and one event-sourced audit trail.

### The problem, in one paragraph

Adversaries are adaptive, well-resourced, and use your own public footprint (LinkedIn, GitHub, leaked credentials, dark web listings) against you. Static, once-a-year tests don't reflect how modern attackers actually operate, and they almost never exercise the full chain from intrusion → detection → response → compliance reporting. Ciicerone was built to close that gap end-to-end.

---

## Who It's For

Ciicerone is designed for security leaders who need to **prove** resilience, not just claim it.

| Audience | What Ciicerone gives them |
|---|---|
| **CISOs & Heads of Security** | A continuous, measurable security posture baseline; quantified detection coverage mapped to MITRE ATT&CK; executive-ready reports that translate technical findings into business risk. |
| **CIOs & CTOs** | A single platform that replaces 3–5 siloed tools; runs on your own infrastructure with local LLMs so no sensitive data leaves your environment. |
| **CROs & Risk Officers (Banks, Fintech, Insurance)** | Audit-ready evidence mapped to PCI-DSS, NDPR, GDPR, SOC 2, ISO 27001, and CBN risk-management requirements; breach-notification readiness with 72-hour SLA support. |
| **Compliance & GRC Leads** | An immutable, replayable event-sourced audit trail that satisfies regulators directly — no more rebuilding timelines from scattered logs. |
| **Red Team Leads** | Autonomous, LLM-driven attack agents that plan, execute, and adapt across the full MITRE ATT&CK kill chain — enriched with live OSINT and dark web intelligence on the actual target. |
| **Blue Team / SOC Managers** | Pre-built MITRE hunt hypotheses, auto-generated Sigma/Splunk/Elastic/Sentinel detection rules from simulated TTPs, and NIST 800-61 incident-response playbooks. |
| **Security Researchers & Academics** | An extensible framework for agentic threat simulation research — multiple simulation paradigms, RLHF-driven scenario refinement, and a clean tool interface. |

---

## What Makes Ciicerone Different

Generic phishing platforms run canned scenarios. Ciicerone runs **targeted, intelligence-enriched, closed-loop simulations**.

### 1. The Intelligence Stack — a single source of truth *(commercial)*

Every team consumes and produces intelligence through one bidirectional pipeline:

- **OSINT engine** — live reconnaissance (LinkedIn, GitHub, WHOIS/DNS, company websites, social media) feeds directly into LLM-generated payloads tailored to the *actual* target.
- **Dark web monitor** — continuous scanning of breach databases and dark web sources for leaked credentials, payment data, customer PII, API keys, and source code, mapped to compliance frameworks.
- **MITRE ATT&CK v14 full coverage** — every technique, sub-technique, tactic, procedure, detection, and mitigation mapped and queryable, with D3FEND mappings for defensive coverage analysis.
- **Event-sourced audit trail** — every simulation event persisted to an immutable PostgreSQL event log with optimistic concurrency and replay for state reconstruction.
- **Hypothesis-driven threat hunting** — pre-built MITRE ATT&CK hunt hypotheses executed across SIEM/EDR data, with results fed back into simulation refinement.
- **Automated detection rule generation** — Sigma, Splunk, Elastic, and Sentinel rules auto-generated from the exact TTPs simulated, so blue team validates coverage against the same techniques red team executes.

### 2. Agentic, not scripted

LLM agents plan multi-step attacks, execute them on sandboxed VMs, interpret command output, and adapt the next action — mirroring the OODA cycle and NIST 800-61 lifecycle. Scenarios behave like real adversaries, not canned scripts.

### 3. Multi-team by design *(commercial)*

A single command launches a full-spectrum exercise across all color teams:

```bash
ciicerone exercise run --scenario templates/supply_chain_compromise.yaml --teams all
```

| Team | Role |
|---|---|
| **Red** | Autonomous attack generation & execution (phishing, BEC, smishing, supply-chain, credential stuffing) |
| **Blue** | SIEM/IDS/EDR detection, threat hunting, incident response, forensics, alert triage |
| **Purple** | Detection validation, after-action reviews (AAR), RLHF-driven feedback loop |
| **White** | Rules of engagement, scope enforcement, ethics & compliance |
| **Yellow** | Secure build & infrastructure validation |
| **Green** | Remediation tracking and patch verification |
| **Orange** | AI-enriched code review and attack-surface reduction |
| **Black** | Evaluation, benchmarking, and reporting |

### 4. Runs fully offline

Sensitive environment? Run entirely on your own infrastructure with **local LLMs** — no API keys, no internet, no data leaving your network. The same platform also supports OpenAI, Anthropic, and OpenRouter when cloud LLMs are acceptable.

### 5. Built against your real infrastructure, not a synthetic lab *(commercial)*

Ciicerone ingests your actual network topology, cloud configuration (AWS/Azure/GCP IAM, security groups, bucket permissions, Kubernetes RBAC), and employee directory — then runs simulations against a **digital twin** of your environment. Phishing targets real employees with correct roles; lateral movement follows real subnets and firewall rules; cloud attacks test your actual IAM policies.

---

## The Business Case

Ciicerone translates technical security activity into financial and regulatory outcomes leadership can act on.

| Capability | Business Impact | Financial Implication |
|---|---|---|
| Dark web credential monitoring | Detects leaked employee/customer credentials before exploitation | Prevents account takeover fraud. Average credential breach cost: **$4.5M** (IBM). Early detection saves ~**$1.2M** on average. |
| Payment data exposure scanning | Identifies card data listings on dark web marketplaces before mass fraud | Avoids PCI-DSS fines (**$5K–$100K/month**), card reissuance (**$3–$10/card**). For a 500K-card portfolio, one prevented breach saves **$1.5M–$5M**. |
| OSINT-enriched phishing simulations | Employees train against attacks referencing real executives, products, events | Reduces real phishing click rates by **60–70%** (SANS). One prevented BEC saves **$1.7M** average (FBI IC3). |
| Automated detection rule generation | Blue team gets Sigma/Splunk/Elastic/Sentinel rules for every simulated TTP, no manual writing | Cuts MTTD from **hours to minutes**. Each undetected minute costs ~**$200/min** in exfiltration impact. |
| Hypothesis-driven threat hunting | Proactively finds adversary activity before alerts fire | Reduces dwell time from **~21 days to <1 day**. Each dwell-day saved ≈ **$40K** in breach cost. |
| Event-sourced audit trail | Immutable, replayable log of all simulation activity | Eliminates audit-prep cost (**$50K–$200K** per cycle). Satisfies NDPR 72-hour notification, PCI-DSS Req 10, CBN reporting simultaneously. |
| Continuous compliance posture | Every simulation produces compliance-mapped evidence (PCI-DSS, NDPR, CBN, ISO 27001) | Reduces cyber-insurance premiums **15–25%** with demonstrated continuous controls validation. |

---

## Quick Start (Open Source Core)

The open-source core lets you define YAML threat scenarios, run simulations against any supported LLM provider, and generate threat content — all locally.

### Prerequisites

- Python 3.11+
- An LLM provider key (OpenRouter, OpenAI, or Anthropic) **or** a local Ollama instance
- Git

### Install

```bash
git clone https://github.com/ciicerone-AI/Ciicerone.git
cd Ciicerone

python -m venv .venv
source .venv/bin/activate          # Windows: .\.venv\Scripts\Activate.ps1

pip install -r requirements.txt     # or: pip install -e .
```

### Configure

```bash
# Cloud LLM (pick one)
export OPENROUTER_API_KEY="your-key-here"
# export OPENAI_API_KEY="..."
# export ANTHROPIC_API_KEY="..."

# Or run fully offline with Ollama
#   1. Install Ollama:  https://ollama.com
#   2. Pull a model:    ollama pull llama3.1:70b
#   3. Set in config.yaml:  llm.provider: ollama
```

Edit `config.yaml` to select your provider, output directory, and safety settings.

### Verify & run

```bash
ciicerone --help
ciicerone templates validate-all
ciicerone simulate -s templates/executive_phishing.yaml --dry-run   # no API calls
ciicerone simulate -s templates/executive_phishing.yaml             # live generation
```

### Create your own scenario

```bash
cp templates/sample_phishing_template.yaml templates/my_scenario.yaml
# edit my_scenario.yaml ...
ciicerone templates show my_scenario --validate
ciicerone simulate -s templates/my_scenario.yaml
```

---

## Template System

Threat scenarios are defined as version-controllable YAML — readable by humans, diffable in git, and validated by the CLI.

```yaml
template_id: executive_phishing_v1
name: "Executive Phishing Campaign"
threat_type: phishing
severity: high
target_role: executive

scenario:
  sender_persona: "CFO Office"
  urgency_level: high
  social_engineering_tactics: [authority, urgency, fear]
  context:
    industry: technology
    quarter: Q4

generation:
  max_tokens: 800
  temperature: 0.7

safety:
  content_filtering: true
  pii_masking: true
  disclaimer_required: true
```

---

## Technology Stack

- **Language:** Python 3.11+
- **API & async:** FastAPI, Starlette, uvicorn, asyncio, aiohttp, httpx
- **LLM providers:** OpenAI, Anthropic, OpenRouter, Ollama (local/offline)
- **Data & persistence:** PostgreSQL, SQLAlchemy 2.0 async, Alembic, Redis, SQLite
- **Validation & config:** Pydantic v2, YAML schemas
- **Observability:** structlog, Prometheus client
- **Security:** python-jose, passlib/bcrypt, cryptography, Bandit
- **Deployment:** Docker, Docker Compose, Kubernetes
- **Code quality:** black, isort, flake8, mypy, pre-commit, pytest

---

## Security, Safety & Responsible Use

Ciicerone is a **defensive** security platform. It is built for authorized security testing, training, control validation, and compliance — never for malicious activity.

- **Safety framework** — content filtering, unsafe-keyword blocking, and PII masking.
- **Authorized use cases** — security awareness training, authorized red/purple team exercises, control validation, compliance evidence, research and education.
- **Prohibited use cases** — actual attacks, unauthorized access, harassment, bypassing security controls, any illegal activity.
- **Compliance mappings** — GDPR, PCI-DSS, NDPR, SOC 2, ISO 27001, and CBN risk-management.

See [`SECURITY.md`](SECURITY.md) for vulnerability reporting.

---

## Documentation

| Topic | Link |
|---|---|
| User guide | [`docs/guides/USER_GUIDE.md`](docs/guides/USER_GUIDE.md) |
| Developer guide | [`docs/guides/DEVELOPER_GUIDE.md`](docs/guides/DEVELOPER_GUIDE.md) |
| Security guide | [`docs/guides/SECURITY_GUIDE.md`](docs/guides/SECURITY_GUIDE.md) |
| API reference | [`docs/api/API_DOCUMENTATION.md`](docs/api/API_DOCUMENTATION.md) |
| Configuration reference | [`docs/reference/CONFIGURATION_REFERENCE.md`](docs/reference/CONFIGURATION_REFERENCE.md) |
| Compliance | [`docs/compliance/README.md`](docs/compliance/README.md) |
| Licensing & component matrix | [`docs/licensing/COMPONENT_MATRIX.md`](docs/licensing/COMPONENT_MATRIX.md) |

---

## Contributing

We welcome contributions to the open-source core. The commercial modules are not accepting external contributions at this time.

- **Contributing guide:** [`docs/community/CONTRIBUTING.md`](docs/community/CONTRIBUTING.md)
- **Code of Conduct:** [`docs/community/CODE_OF_CONDUCT.md`](docs/community/CODE_OF_CONDUCT.md)
- **Security policy:** [`SECURITY.md`](SECURITY.md)
- **Issues & feature requests:** [GitHub Issues](https://github.com/ciicerone-AI/Ciicerone/issues)
- **Discussions:** [GitHub Discussions](https://github.com/ciicerone-AI/Ciicerone/discussions)

```bash
# Dev setup
git clone https://github.com/ciicerone-AI/Ciicerone.git && cd Ciicerone
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pre-commit install
pytest
```

---

## Commercial Licensing & Enterprise

For enterprise licensing, pilot programmes, or to access the commercial modules (intelligence stack, event-sourced audit trail, blue team suite, multi-team orchestration, enterprise integrations), contact **commercial@ciicerone.io** or see [`docs/licensing/COMPONENT_MATRIX.md`](docs/licensing/COMPONENT_MATRIX.md).

---

## License

The open-source core is licensed under **Apache 2.0**. Commercial modules are separately licensed. See [`LICENSE`](LICENSE) and [`docs/licensing/COMPONENT_MATRIX.md`](docs/licensing/COMPONENT_MATRIX.md) for details.

---

*Ciicerone — guide your security teams from simulation to resilience.*
