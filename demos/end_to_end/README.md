# Vorsyghta End-to-End Demo: "Project Nightfall"

A single narrative-driven script that exercises **every** Vorsyghta feature area
in the context of one authorized red-team engagement against a fictional company,
**Acme Corp**.

> This demo is offline-safe by default. No API keys, no Ollama, no cloud
> credentials are required. Use `--live` and/or `--recon` to enable real LLM
> generation and OSINT gathering.

## The Story

You are a security consultant engaged by Acme Corp to run an authorized
spear-phishing assessment against their CFO, **Alice Johnson**. The engagement
codename is **Project Nightfall**. The demo walks the full lifecycle of the
engagement across 19 phases:

| Phase | Feature Area | What Happens |
|-------|--------------|--------------|
| 1 | `status`, `client-data` | Confirm platform is up; ingest Acme's employee directory & network topology |
| 2 | `intel` | List OSINT sources; optionally gather intelligence on `acme-corp.com` |
| 3 | `templates`, `validate` | Browse scenario templates; validate the Project Nightfall scenario |
| 4 | `client-data enrich` | Enrich the scenario with real Acme employees and network assets |
| 5 | `simulate` | Dry-run the execution plan; optionally generate live phishing content |
| 6 | `llm` | Test configured LLM providers (connectivity + auth) |
| 7 | `red-team` | Vorsyghta Attack health check; map scenario → autonomous attack flow |
| 8 | `detect` | Generate Sigma/Splunk/Elastic/Sentinel detection rules from the scenario |
| 9 | `blue-team` | SIEM, IDS, EDR, incident response, threat hunting, log analysis, triage, forensics |
| 10 | `rag` | Initialize RAG; ingest MITRE ATT&CK; generate a tactical response playbook |
| 11 | `manuals` | Generate Blue Team + SOC field manuals for the financial sector |
| 12 | `validate playbook` | Validate the response playbook against NIST CSF + MITRE ATT&CK |
| 13 | `feedback` | Inspect the continuous-improvement feedback loop |
| 14 | `datasets` | Browse the cybersecurity dataset catalog (PhishTank, Enron, MITRE) |
| 15 | `vm` | Check the VM attack-simulation lab status |
| 16 | `mcp` | Inspect MCP tools for AI-driven VM control; export tool schemas |
| 17 | `deploy` | List deployment platforms; run a campaign in **test mode** (no real delivery) |
| 18 | `logs` | Review stored simulation results and statistics |
| 19 | `safety` | Confirm safety & compliance controls |

## Files

```
demos/end_to_end/
├── README.md                                  ← this file
├── run_e2e_demo.sh                            ← the narrative demo script
├── scenarios/
│   └── acme_cfo_spear_phishing.yaml           ← Project Nightfall scenario
├── sample_logs/
│   └── auth.log                               ← captured Acme Corp auth log (blue team)
├── targets.json                               ← deployment campaign targets
├── content.json                               ← deployment campaign content
└── output/                                    ← generated artifacts land here
```

## Run the Demo

### Prerequisites

- Python 3.11+
- Vorsyghta installed: `pip install -e .` from the repo root

### Default (offline-safe)

```bash
cd /path/to/Vorsyghta   # repo root
bash demos/end_to_end/run_e2e_demo.sh
```

This runs every phase in dry-run / offline mode. Some commands (Vorsyghta Attack,
Neo4j-backed RAG, real SIEM) will report "not configured" — this is expected
and still demonstrates the full CLI surface.

### With live LLM generation

```bash
# Option A: local Ollama
ollama serve &
bash demos/end_to_end/run_e2e_demo.sh --live

# Option B: cloud provider (set in .env)
export OPENROUTER_API_KEY="sk-or-..."
bash demos/end_to_end/run_e2e_demo.sh --live
```

### With OSINT company recon

```bash
bash demos/end_to_end/run_e2e_demo.sh --recon
```

Requires internet access. Triggers the `CompanyReconAgent` to gather OSINT on
the target domain derived from the employee email domain.

### Combine both

```bash
bash demos/end_to_end/run_e2e_demo.sh --live --recon
```

## Expected Output

The script prints a banner per phase and runs each command with a helper that
never aborts the whole demo on a single step's error. At the end it prints a
checklist of all 19 feature areas exercised and lists the artifacts generated
in `output/`, which typically include:

- `enriched_scenario.json` — scenario enriched with Acme Corp client data
- `detection_rules/` — Sigma, Splunk, Elastic, Sentinel rule files
- `tactical_playbook.md` — RAG-generated response playbook
- `field_manuals/blue_team/` and `field_manuals/soc/` — generated manuals
- `playbook_validation_report.md` — validation report
- `mcp_tool_schema.json` — exported MCP tool schemas
- `acme_osint.json` — (only with `--recon`) gathered OSINT

## Notes

- The demo reuses the local HTTP server from `demos/client_data/` on port
  `8765` to serve the Acme Corp employee directory. The script starts and
  stops this server automatically.
- Commands that depend on external services (Vorsyghta Attack, Neo4j, real SIEM/SOAR)
  will print a "not configured" message rather than failing the script.
- The deployment campaign in Phase 17 always runs in `--test-mode` (safe, no
  real email delivery) regardless of flags.
- This demo complements `demos/full_platform/run_full_demo.sh` (which is a
  flat feature tour) by adding a coherent narrative and custom scenario data.
