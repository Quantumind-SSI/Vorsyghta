# Ciicerone

**The agentic cyber platform that unifies threat simulation, red team operations, and zero-day vulnerability research — closing the loop between offense, defense, and intelligence.**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0 + Commercial](https://img.shields.io/badge/license-Apache%202.0%20%2B%20Commercial-blue.svg)](LICENSE)
[![FastAPI](https://img.shields.io/badge/API-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20v14-red.svg)](https://attack.mitre.org/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](docs/community/CONTRIBUTING.md)

> **Ciicerone** (noun) — *a guide who leads the way.* We guide security teams from "we ran a phishing test once a year" to "we continuously simulate, detect, hunt, discover zero-days, and prove our controls against realistic adversaries."

---

## What Ciicerone Actually Is

Ciicerone is not just a phishing simulator or a training platform. It is a **full-spectrum agentic cyber operations platform** with three core pillars:

### 1. Threat Simulation & Red Team Operations

LLM-driven agents plan and execute multi-stage attacks across the MITRE ATT&CK kill chain — phishing, BEC, smishing, supply-chain compromise, credential stuffing, lateral movement — on isolated VM infrastructure. The AI attack agent adapts its strategy based on live results, mirroring the OODA loop of real adversaries.

**What's implemented:**
- AI attack agent (`ciicerone/vm/agent.py`) — ReAct-style reasoning, autonomous multi-step attack planning, adaptive command refinement
- Attack orchestrator (`ciicerone/core/attack_orchestrator.py`) — MITRE technique-to-tool mapping, automated finding extraction
- MCP server (`ciicerone/mcp/`) — Model Context Protocol server exposing VM control, command execution, and attack tools to AI agents
- VM operator (`ciicerone/vm/operator.py`) — Proxmox, KVM, Docker hypervisor support; SSH/WinRM execution; snapshot management
- Offensive tools — nmap, nuclei, gobuster, hydra, sqlmap, curl, metasploit (via VM templates)
- GUI automation (`ciicerone/mcp/tools/computer_use.py`) — screenshots, mouse/keyboard input for GUI-targeted attacks
- Safety controls (`ciicerone/mcp/safety/`) — network isolation, command blocklists, rate limiting, scenario approval, audit logging

### 2. Zero-Day Vulnerability Research

Ciicerone's discovery toolchain extends beyond known-vulnerability scanning into finding **new** vulnerabilities. The MCP server exposes fuzzing, static analysis, and binary analysis tools to AI agents, who can autonomously run campaigns, triage crashes, and generate vulnerability reports.

**What's implemented:**
- **Fuzzing tools** (`ciicerone/mcp/tools/discovery_tools.py`):
  - AFL++ — coverage-guided fuzzing with crash collection
  - libFuzzer — in-process LLVM fuzzing for instrumented targets
  - honggfuzz — hardware-based fuzzing for closed-source binaries
  - Network protocol fuzzing — radamsa-based mutation for TCP/UDP services
  - ffuf — high-speed web content and parameter fuzzing
  - API fuzzing — OpenAPI/Swagger grammar-based fuzzing with schemathesis
- **Static analysis (SAST)**:
  - Semgrep — 30+ language support, OWASP/CWE rulesets
  - CodeQL — GitHub's semantic code analysis with custom queries
  - Bandit — Python-specific security linting
- **Binary analysis**:
  - Ghidra headless — decompilation, function discovery, vulnerability pattern scanning
  - radare2 — reverse engineering, ROP gadget discovery, security mitigation checks
  - Binary diffing — compare binary versions to find patched vulnerabilities
- **Crash triage pipeline** (`ciicerone/research/crash_pipeline.py`):
  - Collect crashes from fuzzing campaigns
  - Deduplicate by stack trace signature
  - Triage under GDB — classify crash type, assess exploitability
  - Map to CWE IDs and estimate CVSS scores
  - Prioritize by severity
- **LLM-guided mutation** (`ciicerone/research/llm_mutator.py`):
  - Grammar-aware mutation (JSON, XML, structured data)
  - Protocol-aware mutation (HTTP, binary protocols)
  - Boundary value testing
  - Injection payload generation (SQLi, XSS, command injection, path traversal)
  - Semantic mutation — LLM generates edge-case inputs that pass parsing but trigger bugs
  - Crash-guided mutation — uses previous crash info to explore similar code paths
- **Vulnerability reporting** (`ciicerone/research/vuln_report.py`):
  - Structured findings with CWE, CVSS, reproduction steps, PoC
  - Markdown and JSON output for client delivery
  - Executive summaries with severity breakdowns

### 3. Blue Team, Intelligence & Compliance

- **Detection rule generation** — Sigma, Splunk, Elastic, Sentinel rules auto-generated from simulated TTPs
- **Threat hunting** — MITRE ATT&CK hunt hypotheses, CVE intelligence, CISA KEV catalogue
- **SIEM integration** — Splunk, Elastic Security, Microsoft Sentinel, IBM QRadar
- **Event-sourced audit trail** — immutable PostgreSQL event log with replay
- **Compliance mapping** — PCI-DSS, NDPR, GDPR, SOC 2, ISO 27001, CBN

---

## Licensing — Read This First

Ciicerone is **open-core**. The simulation engine, CLI, YAML template system, basic LLM provider abstraction, and the zero-day discovery toolchain are open source under **Apache 2.0**. The intelligence stack, event-sourced audit trail, blue team modules, multi-team orchestration, enterprise integrations, and other production-grade capabilities are licensed commercially.

- **Open source core** — see [`LICENSE`](LICENSE) (Apache 2.0).
- **Commercial modules** — see [`docs/licensing/COMPONENT_MATRIX.md`](docs/licensing/COMPONENT_MATRIX.md) for the full component-by-component breakdown and commercial terms.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Ciicerone Platform                        │
├─────────────────┬───────────────────┬───────────────────────────┤
│  Threat Sim     │  Zero-Day Research│  Blue Team & Intel        │
│                 │                   │                           │
│  AI Attack Agent│  Fuzzing Engine   │  Detection Rules          │
│  Attack Orch.   │  SAST Analysis    │  Threat Hunting           │
│  VM Operator    │  Binary Analysis  │  SIEM Integration         │
│  MCP Server     │  Crash Pipeline   │  CVE Intelligence         │
│  Safety Ctrl.   │  LLM Mutator      │  Audit Trail              │
│                 │  Vuln Reporting   │  Compliance Mapping       │
├─────────────────┴───────────────────┴───────────────────────────┤
│                     MCP Tool Interface                           │
│  VM Lifecycle │ Command Exec │ Attack Tools │ Discovery Tools   │
├─────────────────────────────────────────────────────────────────┤
│                     VM Infrastructure                           │
│     Proxmox VE │ Libvirt/KVM │ Docker │ AWS │ Azure │ GCP       │
├─────────────────────────────────────────────────────────────────┤
│                     LLM Provider Layer                          │
│     OpenAI │ Anthropic │ OpenRouter │ Azure OpenAI │ Ollama     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Who It's For

| Audience | What Ciicerone gives them |
|---|---|
| **Red Team Leads** | Autonomous, LLM-driven attack agents that plan, execute, and adapt across the full MITRE ATT&CK kill chain — enriched with live OSINT and dark web intelligence. |
| **Vulnerability Researchers** | Fuzzing, SAST, and binary analysis tools exposed through the MCP interface. AI-guided mutation, automated crash triage, and structured vulnerability reporting. |
| **CISOs & Heads of Security** | Continuous, measurable security posture baseline; quantified detection coverage mapped to MITRE ATT&CK; executive-ready reports. |
| **Blue Team / SOC Managers** | Pre-built MITRE hunt hypotheses, auto-generated detection rules from simulated TTPs, NIST 800-61 incident-response playbooks. |
| **Compliance & GRC Leads** | Immutable, replayable event-sourced audit trail that satisfies regulators — no more rebuilding timelines from scattered logs. |
| **Security Researchers & Academics** | Extensible framework for agentic threat simulation and zero-day research — multiple simulation paradigms, LLM-guided fuzzing, clean tool interface. |

---

## Quick Start

### Prerequisites

- Python 3.11+
- An LLM provider key (OpenRouter, OpenAI, Anthropic, or Azure OpenAI) **or** a local Ollama instance
- For VM-based operations: Proxmox VE, libvirt/KVM, or Docker
- For zero-day research: attacker VM with AFL++, radare2, Ghidra, semgrep installed

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
# export AZURE_OPENAI_API_KEY="..."

# Or run fully offline with Ollama
#   1. Install Ollama:  https://ollama.com
#   2. Pull a model:    ollama pull llama3.1:70b
#   3. Set in config.yaml:  llm.provider: ollama

# For VM operations (Proxmox)
export PROXMOX_HOST="192.168.1.100"
export PROXMOX_TOKEN_NAME="automation"
export PROXMOX_TOKEN_VALUE="your-token"

# For SSH access to attacker VMs
export CIICERONE_VM_USERNAME="root"
export CIICERONE_VM_PASSWORD="your-password"
```

Edit `config.yaml` to select your provider, output directory, and safety settings.

### Run Threat Simulations

```bash
ciicerone --help
ciicerone templates validate-all
ciicerone simulate -s templates/executive_phishing.yaml --dry-run   # no API calls
ciicerone simulate -s templates/executive_phishing.yaml             # live generation
```

### Run the MCP Server (for AI-driven attacks and zero-day research)

```bash
# Start the MCP server (stdio transport for AI agents)
python -m ciicerone.mcp.server --log-level INFO
```

The MCP server exposes tools that AI agents can call:
- **VM lifecycle**: `vm_create`, `vm_start`, `vm_stop`, `vm_destroy`, `vm_list`, `vm_status`
- **Command execution**: `vm_execute`, `vm_execute_script`
- **Snapshots**: `vm_snapshot_create`, `vm_snapshot_restore`, `vm_snapshot_list`, `vm_snapshot_delete`
- **GUI automation**: `vm_screenshot`, `vm_mouse_click`, `vm_keyboard_type`, `vm_keyboard_key`
- **Attack tools**: `attack_nmap_scan`, `attack_port_check`, `attack_gobuster`, `attack_nuclei`, `attack_hydra`, `attack_curl`
- **Discovery tools**: `discovery_afl_fuzz`, `discovery_libfuzzer`, `discovery_honggfuzz`, `discovery_network_fuzz`, `discovery_ffuf`, `discovery_api_fuzz`, `discovery_semgrep`, `discovery_codeql`, `discovery_bandit`, `discovery_ghidra_headless`, `discovery_radare2`, `discovery_binary_diff`, `discovery_crash_collect`, `discovery_crash_triage`

### Zero-Day Research Workflow

```python
import asyncio
from ciicerone.research.crash_pipeline import CrashPipeline
from ciicerone.research.llm_mutator import LLMMutator, MutationStrategy
from ciicerone.research.vuln_report import ReportGenerator

async def zero_day_campaign():
    # 1. Generate smart mutations with LLM
    mutator = LLMMutator(llm_manager=your_llm_manager)
    mutations = await mutator.generate_mutations(
        seed_input=b'{"user": "admin", "action": "login"}',
        strategy=MutationStrategy.COMBINED,
        target_description="JSON API endpoint accepting user login",
        count=100,
    )

    # 2. Run fuzzing campaign via MCP (on attacker VM)
    # ... use discovery_afl_fuzz or discovery_network_fuzz tool ...

    # 3. Collect and triage crashes
    pipeline = CrashPipeline(ssh_username="root", ssh_password="...")
    catalog = await pipeline.collect_and_triage(
        findings_dir="/tmp/afl_findings",
        target_binary="/tmp/target",
        attacker_vm_ip="10.0.100.5",
        fuzzer="afl",
    )

    # 4. Generate vulnerability report
    generator = ReportGenerator()
    report = generator.generate_from_catalog(
        catalog,
        client="Client Name",
        engagement_id="ENG-2024-001",
        target_description="Target binary v1.2.3",
    )
    report.save("vulnerability_report.md")
    report.save("vulnerability_report.json", format="json")

asyncio.run(zero_day_campaign())
```

### Sanctioned Target Pentest (Discovery Pipeline Validation)

To validate the red-team attack + discovery toolchain against a target with
**known ground truth**, Ciicerone ships a compose fragment for OWASP Juice
Shop — a sanctioned, intentionally-vulnerable training target with ~100
documented challenges and a scoreboard. This lets you prove the agent actually
finds vulnerabilities (compare `vuln_report.py` output against the challenge
list) rather than hallucinating.

> **Caveat:** Juice Shop has *known, intentional* vulnerabilities. It validates
> the *discovery pipeline* (find -> triage -> structured CWE/CVSS report) — it
> is **not** zero-day research. Genuine zero-day work targets real software in
> a sanctioned engagement scope and uses `disclosure.py` for responsible
> disclosure / CVE assignment.

```bash
# 1. Bring up the Ciicerone stack + Juice Shop target (dry-run, prints the attack command)
bash scripts/run_sanctioned_target.sh --target juice-shop --keep

# 2. Launch the attack directly (requires a reachable tool server)
bash scripts/run_sanctioned_target.sh --target juice-shop --attack --keep

# Or run the red-team CLI manually against the host-mapped target:
ciicerone red-team attack \
  -s templates/sanctioned_targets/juice_shop_web_pentest.yaml \
  -t http://localhost:3000 \
  -o juice_shop_findings.json

# Tear down when done:
bash scripts/run_sanctioned_target.sh --down
```

Files:
- `docker/targets/juice-shop.yml` — compose fragment (Juice Shop on `ciicerone-network`)
- `templates/sanctioned_targets/juice_shop_web_pentest.yaml` — scenario template
- `scripts/run_sanctioned_target.sh` — harness (bring-up + health-wait + attack)

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

## Discovery Toolchain Details

### Fuzzing Tools

| Tool | MCP Tool Name | Use Case |
|------|--------------|----------|
| AFL++ | `discovery_afl_fuzz` | Coverage-guided fuzzing of binaries with source code |
| libFuzzer | `discovery_libfuzzer` | In-process fuzzing of LLVM-instrumented harnesses |
| honggfuzz | `discovery_honggfuzz` | Hardware-based fuzzing of closed-source binaries |
| Network Fuzzer | `discovery_network_fuzz` | Mutated packet fuzzing for TCP/UDP services |
| ffuf | `discovery_ffuf` | Web directory, file, parameter, and vhost fuzzing |
| API Fuzzer | `discovery_api_fuzz` | OpenAPI/Swagger grammar-based API fuzzing |

### Static Analysis Tools

| Tool | MCP Tool Name | Use Case |
|------|--------------|----------|
| Semgrep | `discovery_semgrep` | Multi-language SAST with OWASP/CWE rulesets |
| CodeQL | `discovery_codeql` | Semantic code analysis with custom queries |
| Bandit | `discovery_bandit` | Python-specific security linting |

### Binary Analysis Tools

| Tool | MCP Tool Name | Use Case |
|------|--------------|----------|
| Ghidra Headless | `discovery_ghidra_headless` | Decompilation, function discovery, vuln pattern scanning |
| radare2 | `discovery_radare2` | RE, ROP gadgets, security mitigation checks, decompilation |
| Binary Diff | `discovery_binary_diff` | Compare binary versions to find patched vulnerabilities |

### Crash Triage

| Tool | MCP Tool Name | Use Case |
|------|--------------|----------|
| Crash Collect | `discovery_crash_collect` | Collect and deduplicate crashes from fuzzing campaigns |
| Crash Triage | `discovery_crash_triage` | GDB-based root cause analysis and exploitability assessment |

### LLM-Guided Mutation Strategies

| Strategy | Description |
|----------|-------------|
| `grammar_aware` | Parse structured input (JSON, XML) and mutate individual fields |
| `protocol_aware` | Mutate HTTP and binary protocol fields |
| `boundary_testing` | Generate boundary values for numeric fields |
| `injection_testing` | Generate SQLi, XSS, command injection, path traversal payloads |
| `semantic_mutation` | LLM generates semantically valid but edge-case inputs |
| `crash_guided` | Use previous crash info to explore similar code paths |
| `combined` | Use multiple strategies together |

---

## Multi-Team Operations

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

---

## Technology Stack

- **Language:** Python 3.11+
- **API & async:** FastAPI, Starlette, uvicorn, asyncio, aiohttp, httpx
- **LLM providers:** OpenAI, Anthropic, OpenRouter, Azure OpenAI, Ollama (local/offline)
- **MCP:** Model Context Protocol server for AI agent tool calling
- **VM infrastructure:** Proxmox VE, libvirt/KVM, Docker, AWS, Azure, GCP
- **SSH:** asyncssh for remote command execution
- **Fuzzing:** AFL++, libFuzzer, honggfuzz, radamsa
- **SAST:** Semgrep, CodeQL, Bandit
- **Binary analysis:** Ghidra headless, radare2
- **Data & persistence:** PostgreSQL, SQLAlchemy 2.0 async, Alembic, Redis, SQLite
- **Validation & config:** Pydantic v2, YAML schemas
- **Observability:** structlog, Prometheus client
- **Security:** python-jose, passlib/bcrypt, cryptography, Bandit
- **Deployment:** Docker, Docker Compose, Kubernetes
- **Code quality:** black, isort, flake8, mypy, pre-commit, pytest

---

## Security, Safety & Responsible Use

Ciicerone is a **defensive** security platform. It is built for authorized security testing, training, control validation, compliance, and vulnerability research — never for malicious activity.

- **Safety framework** — content filtering, unsafe-keyword blocking, PII masking, network isolation (attacks restricted to allowed networks), command blocklists, rate limiting, scenario approval for destructive operations, full audit logging.
- **Authorized use cases** — security awareness training, authorized red/purple team exercises, control validation, compliance evidence, vulnerability research under authorized scope, research and education.
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
| Agentic threat simulation research | [`docs/research/agentic-threat-simulation-framework.md`](docs/research/agentic-threat-simulation-framework.md) |

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

*Ciicerone — guide your security teams from simulation to resilience to discovery.*
