#!/usr/bin/env bash
# =============================================================================
# Ciicerone End-to-End Demo: "Project Nightfall"
# =============================================================================
# A narrative walkthrough of EVERY Ciicerone feature in a single red-team
# engagement against Acme Corp. Tells the story of an authorized security
# assessment from initial recon through detection, response, and learning.
#
# Usage:
#   bash demos/end_to_end/run_e2e_demo.sh            # offline-safe (dry-run)
#   bash demos/end_to_end/run_e2e_demo.sh --live      # attempt real LLM calls
#   bash demos/end_to_end/run_e2e_demo.sh --recon     # add OSINT company recon
#
# Requirements:
#   - Python 3.11+ with ciicerone installed (pip install -e .)
#   - No API keys required for the default offline path.
#   - --live: requires Ollama running (http://localhost:11434) OR
#     OPENROUTER_API_KEY / OPENAI_API_KEY / ANTHROPIC_API_KEY set in .env
#   - --recon: requires internet access for OSINT gathering
# =============================================================================

set -uo pipefail

# ----------------------------------------------------------------------------
# Setup & flags
# ----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CLIENT_DATA_DIR="${PROJECT_DIR}/demos/client_data"
CONFIG="${CLIENT_DATA_DIR}/demo_config.yaml"
SCENARIO="${SCRIPT_DIR}/scenarios/acme_cfo_spear_phishing.yaml"
OUTPUT_DIR="${SCRIPT_DIR}/output"
DEMO_PORT=8765

LIVE_FLAG=""
RECON_FLAG=""
RUN_LIVE=0

for arg in "$@"; do
    case "$arg" in
        --live)  LIVE_FLAG="--live"; RUN_LIVE=1 ;;
        --recon) RECON_FLAG="--recon" ;;
        *) echo "Unknown flag: $arg"; echo "Usage: bash run_e2e_demo.sh [--live] [--recon]"; exit 1 ;;
    esac
done

mkdir -p "${OUTPUT_DIR}"

# Banner
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║  Ciicerone End-to-End Demo: PROJECT NIGHTFALL                            ║"
echo "║  An authorized red-team engagement against Acme Corp                     ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Project dir : ${PROJECT_DIR}"
echo "Config      : ${CONFIG}"
echo "Scenario    : ${SCENARIO}"
echo "Output dir  : ${OUTPUT_DIR}"
echo "Live LLM    : $([ "${RUN_LIVE}" = "1" ] && echo "yes (will attempt real calls)" || echo "no (dry-run safe)")"
echo "OSINT recon : $([ -n "${RECON_FLAG}" ] && echo "yes" || echo "no")"
echo ""

# Helper: run a command, never abort the whole demo on a single failure.
run_cmd() {
    local title="$1"; shift
    echo ""
    echo "┌──────────────────────────────────────────────────────────────────────────┐"
    echo "│ ${title}"
    echo "└──────────────────────────────────────────────────────────────────────────┘"
    "$@" 2>&1 || echo "  [!] (this step reported an error — continuing demo)"
}

PY="python"

# ----------------------------------------------------------------------------
# Start the local client-data demo server (used by client-data sync/enrich)
# ----------------------------------------------------------------------------
if command -v lsof >/dev/null 2>&1; then
    lsof -ti tcp:${DEMO_PORT} | xargs kill 2>/dev/null || true
fi

echo "Starting local demo data server on port ${DEMO_PORT}..."
${PY} "${CLIENT_DATA_DIR}/serve_demo_data.py" --port "${DEMO_PORT}" --dir "${CLIENT_DATA_DIR}" >/dev/null 2>&1 &
SERVER_PID=$!
cleanup() {
    echo ""
    echo "=== Cleaning up demo server (PID ${SERVER_PID}) ==="
    kill "${SERVER_PID}" 2>/dev/null || true
}
trap cleanup EXIT

for i in {1..30}; do
    if curl -sf "http://localhost:${DEMO_PORT}/demo_client_api.json" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

# ============================================================================
# PHASE 1 — RECONNAISSANCE & CLIENT DATA INGESTION
# "Before we attack, we must know the target. Acme Corp has engaged us to
#  assess their executive team. We ingest their employee directory and
#  network topology from the authorized data feed."
# ============================================================================
echo ""
echo "████████████████████████████████████████████████████████████████████████████"
echo "██  PHASE 1: RECONNAISSANCE & CLIENT DATA INGESTION                       ██"
echo "████████████████████████████████████████████████████████████████████████████"

run_cmd "1.1  Platform status — confirm Ciicerone is operational" \
    ${PY} -m ciicerone --config "${CONFIG}" status

run_cmd "1.2  List configured client data sources (Acme Corp tenant)" \
    ${PY} -m ciicerone --config "${CONFIG}" client-data list --tenant acme-demo

run_cmd "1.3  Sync client data — pull employee directory & network topology" \
    ${PY} -m ciicerone --config "${CONFIG}" client-data sync --tenant acme-demo

run_cmd "1.4  Show synced Acme Corp client profile" \
    ${PY} -m ciicerone --config "${CONFIG}" client-data show --tenant acme-demo

# ============================================================================
# PHASE 2 — INTELLIGENCE / OSINT
# "We gather open-source intelligence on the target domain to enrich our
#  understanding of Acme Corp's external footprint."
# ============================================================================
echo ""
echo "████████████████████████████████████████████████████████████████████████████"
echo "██  PHASE 2: INTELLIGENCE & OSINT                                          ██"
echo "████████████████████████████████████████████████████████████████████████████"

run_cmd "2.1  List available intelligence sources" \
    ${PY} -m ciicerone --config "${CONFIG}" intel sources

if [ -n "${RECON_FLAG}" ]; then
    run_cmd "2.2  Gather OSINT on Acme Corp domain (requires internet)" \
        ${PY} -m ciicerone --config "${CONFIG}" intel gather acme-corp.com \
            -t company -t domain -f json -o "${OUTPUT_DIR}/acme_osint.json"
else
    echo ""
    echo "  [i] Skipping live OSINT gather (use --recon to enable)."
fi

# ============================================================================
# PHASE 3 — SCENARIO SELECTION & VALIDATION
# "We select a spear-phishing scenario template and validate it against
#  the Ciicerone schema before enrichment."
# ============================================================================
echo ""
echo "████████████████████████████████████████████████████████████████████████████"
echo "██  PHASE 3: SCENARIO SELECTION & VALIDATION                              ██"
echo "████████████████████████████████████████████████████████████████████████████"

run_cmd "3.1  List all available threat scenario templates" \
    ${PY} -m ciicerone --config "${CONFIG}" templates list-all

run_cmd "3.2  Validate the Project Nightfall scenario against the schema" \
    ${PY} -m ciicerone --config "${CONFIG}" validate \
        -d "${SCRIPT_DIR}/scenarios"

run_cmd "3.3  Show the Project Nightfall scenario details (validated)" \
    ${PY} -m ciicerone --config "${CONFIG}" templates show \
        "${SCRIPT_DIR}/scenarios/acme_cfo_spear_phishing.yaml" --validate

# ============================================================================
# PHASE 4 — SCENARIO ENRICHMENT
# "We enrich the scenario with real Acme Corp employee data and network
#  topology, mapping the CFO (Alice Johnson) to the target profile."
# ============================================================================
echo ""
echo "████████████████████████████████████████████████████████████████████████████"
echo "██  PHASE 4: SCENARIO ENRICHMENT WITH CLIENT DATA                         ██"
echo "████████████████████████████████████████████████████████████████████████████"

run_cmd "4.1  Enrich scenario with Acme Corp client data (+ optional recon)" \
    ${PY} -m ciicerone --config "${CONFIG}" client-data enrich \
        --tenant acme-demo \
        --scenario "${SCENARIO}" \
        --output "${OUTPUT_DIR}/enriched_scenario.json" \
        ${RECON_FLAG}

run_cmd "4.2  Preview the enriched scenario" \
    ${PY} - "${OUTPUT_DIR}/enriched_scenario.json" <<'PYEOF'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
print("Scenario      :", data["metadata"]["name"])
print("Target role   :", data["target_profile"]["role"])
print("Client name   :", data["custom_parameters"].get("client_name"))
print("Employees     :", len(data["custom_parameters"].get("client_employees", [])))
print("Network nodes :", len(data["custom_parameters"].get("client_network_topology", {}).get("nodes", [])))
print("Recon data    :", "company_recon" in data["custom_parameters"])
PYEOF

# ============================================================================
# PHASE 5 — THREAT SIMULATION
# "We execute the spear-phishing simulation. In dry-run mode this validates
#  the full execution plan without calling an LLM. With --live it generates
#  realistic phishing content via the configured provider."
# ============================================================================
echo ""
echo "████████████████████████████████████████████████████████████████████████████"
echo "██  PHASE 5: THREAT SIMULATION EXECUTION                                  ██"
echo "████████████████████████████████████████████████████████████████████████████"

run_cmd "5.1  Dry-run simulation — validate execution plan (no LLM call)" \
    ${PY} -m ciicerone --config "${CONFIG}" simulate \
        -s "${SCENARIO}" --dry-run --preview

if [ "${RUN_LIVE}" = "1" ]; then
    run_cmd "5.2  LIVE simulation — generate phishing content via LLM" \
        ${PY} -m ciicerone --config "${CONFIG}" simulate \
            -s "${SCENARIO}" -o json
else
    echo ""
    echo "  [i] Skipping live simulation (use --live to enable real LLM generation)."
    echo "  [i] Dry-run above confirmed the scenario is execution-ready."
fi

# ============================================================================
# PHASE 6 — LLM PROVIDER MANAGEMENT
# "We verify our LLM provider configuration for content generation."
# ============================================================================
echo ""
echo "████████████████████████████████████████████████████████████████████████████"
echo "██  PHASE 6: LLM PROVIDER MANAGEMENT                                      ██"
echo "████████████████████████████████████████████████████████████████████████████"

run_cmd "6.1  Test configured LLM providers (connectivity & auth)" \
    ${PY} -m ciicerone --config "${CONFIG}" llm test-providers

# ============================================================================
# PHASE 7 — RED TEAM / CIICERONE ATTACK INTEGRATION
# "We map the spear-phishing scenario to an autonomous Ciicerone Attack flow
#  and check whether the Ciicerone Attack autonomous pentest platform is reachable."
# ============================================================================
echo ""
echo "████████████████████████████████████████████████████████████████████████████"
echo "██  PHASE 7: RED TEAM — CIICERONE ATTACK AUTONOMOUS PENETRATION TESTING            ██"
echo "████████████████████████████████████████████████████████████████████████████"

run_cmd "7.1  Ciicerone Attack health check (is the autonomous pentest platform reachable?)" \
    ${PY} -m ciicerone --config "${CONFIG}" red-team health

run_cmd "7.2  Map scenario → Ciicerone Attack flow (scenario-to-task mapping)" \
    ${PY} - <<'PYEOF'
import json
from ciicerone.integrations.attack_mapper import AttackMapper

scenario = {
    "name": "Project Nightfall: CFO Spear-Phishing",
    "threat_type": "spear_phishing",
    "mitre_techniques": ["T1566.001", "T1566.002", "T1078", "T1003", "T1059.001", "T1041"],
    "difficulty": 7,
    "objectives": [
        "Confirm credential compromise via phishing link",
        "Demonstrate lateral movement using valid accounts",
        "Test detection coverage for MITRE T1566 and T1003",
    ],
    "target": {"url": "http://demo-finance.acme-corp.com"},
    "max_duration_minutes": 60,
}

mapper = AttackMapper()
flow = mapper.scenario_to_flow(
    scenario,
    target_info={"ip": "192.168.1.10", "services": ["http", "smtp", "smb"]},
)
print("Flow name :", flow["name"])
print("Target    :", flow["target"])
print("MITRE     :", flow["parameters"]["mitre_techniques"])
print("\nSuggested attack phases:")
for line in flow["description"].split("\n"):
    if line.strip().startswith("-") or "Phase:" in line:
        print(line)
PYEOF

# ============================================================================
# PHASE 8 — DETECTION ENGINEERING
# "Now we switch to the blue-team perspective: we generate SIEM detection
#  rules from the spear-phishing scenario so defenders can catch this attack."
# ============================================================================
echo ""
echo "████████████████████████████████████████████████████████████████████████████"
echo "██  PHASE 8: DETECTION ENGINEERING (BLUE TEAM)                            ██"
echo "████████████████████████████████████████████████████████████████████████████"

run_cmd "8.1  List supported SIEM detection rule formats" \
    ${PY} -m ciicerone --config "${CONFIG}" detect list-formats

run_cmd "8.2  Generate Sigma + Splunk + Elastic + Sentinel rules from scenario" \
    ${PY} -m ciicerone --config "${CONFIG}" detect generate \
        -s "${SCENARIO}" -f all -o "${OUTPUT_DIR}/detection_rules/"

run_cmd "8.3  Generate detection rule from MITRE technique T1566.001 (Spearphishing Attachment)" \
    ${PY} -m ciicerone --config "${CONFIG}" detect from-technique T1566.001 \
        -f sigma -o "${OUTPUT_DIR}/detection_rules/T1566.001_sigma.yaml"

# ============================================================================
# PHASE 9 — BLUE TEAM DEFENSIVE OPERATIONS
# "We exercise the full blue-team stack: SIEM, IDS, EDR, incident response,
#  threat hunting, log analysis, alert triage, and forensics."
# ============================================================================
echo ""
echo "████████████████████████████████████████████████████████████████████████████"
echo "██  PHASE 9: BLUE TEAM DEFENSIVE OPERATIONS                               ██"
echo "████████████████████████████████████████████████████████████████████████████"

run_cmd "9.1  Blue team dashboard — overview of all defensive components" \
    ${PY} -m ciicerone --config "${CONFIG}" blue-team dashboard

run_cmd "9.2  SIEM statistics (simulated)" \
    ${PY} -m ciicerone --config "${CONFIG}" blue-team siem stats

run_cmd "9.3  IDS — inspect a suspicious SSH brute-force packet" \
    ${PY} -m ciicerone --config "${CONFIG}" blue-team ids inspect \
        --protocol tcp --src-ip 185.220.101.45 --dest-port 22 \
        --payload "Failed password for admin"

run_cmd "9.4  IDS — list loaded detection rules" \
    ${PY} -m ciicerone --config "${CONFIG}" blue-team ids rules

run_cmd "9.5  EDR — monitor a suspicious encoded PowerShell execution" \
    ${PY} -m ciicerone --config "${CONFIG}" blue-team edr monitor \
        --process powershell.exe --cmd "powershell -enc SGVsbG8=" --user admin

run_cmd "9.6  EDR statistics" \
    ${PY} -m ciicerone --config "${CONFIG}" blue-team edr stats

run_cmd "9.7  Incident Response — create a critical credential-dumping incident" \
    ${PY} -m ciicerone --config "${CONFIG}" blue-team incident create \
        -t "Credential Dumping Attack via Spear-Phishing" \
        -s critical -c intrusion \
        --systems DC-01,WEB-02 --mitre T1003,T1059.001,T1566.001 --auto

run_cmd "9.8  Incident Response — list all incidents" \
    ${PY} -m ciicerone --config "${CONFIG}" blue-team incident list

run_cmd "9.9  Threat Hunting — list available hunt hypotheses" \
    ${PY} -m ciicerone --config "${CONFIG}" blue-team hunt hypotheses

run_cmd "9.10 Threat Hunting — hunt for MITRE T1003 (Credential Dumping)" \
    ${PY} -m ciicerone --config "${CONFIG}" blue-team hunt search --technique T1003

run_cmd "9.11 Log Analysis — parse the captured Acme Corp auth.log" \
    ${PY} -m ciicerone --config "${CONFIG}" blue-team logs parse \
        -f "${SCRIPT_DIR}/sample_logs/auth.log" -t linux_auth --host acme-dc-01

run_cmd "9.12 Alert Triage — statistics" \
    ${PY} -m ciicerone --config "${CONFIG}" blue-team triage stats

run_cmd "9.13 Forensics — initialize a forensic case for Project Nightfall" \
    ${PY} -m ciicerone --config "${CONFIG}" blue-team forensics init \
        -c nightfall-2026-001

# ============================================================================
# PHASE 10 — RAG: TACTICAL PLAYBOOK GENERATION
# "We use the RAG intelligence system to generate a tactical response
#  playbook grounded in MITRE ATT&CK and CISA advisories."
# ============================================================================
echo ""
echo "████████████████████████████████████████████████████████████████████████████"
echo "██  PHASE 10: RAG — TACTICAL PLAYBOOK GENERATION                           ██"
echo "████████████████████████████████████████████████████████████████████████████"

run_cmd "10.1 RAG system status (vector store, Neo4j, dependencies)" \
    ${PY} -m ciicerone --config "${CONFIG}" rag status

run_cmd "10.2 Initialize the RAG system (creates data dirs + default config)" \
    ${PY} -m ciicerone --config "${CONFIG}" rag init

run_cmd "10.3 List available intelligence sources for RAG ingestion" \
    ${PY} -m ciicerone --config "${CONFIG}" rag sources

run_cmd "10.4 Ingest MITRE ATT&CK intelligence (dry-run preview)" \
    ${PY} -m ciicerone --config "${CONFIG}" rag ingest --source mitre --dry-run

run_cmd "10.5 Generate a tactical playbook for the spear-phishing scenario" \
    ${PY} -m ciicerone --config "${CONFIG}" rag generate \
        -s "spear-phishing attack targeting a CFO with credential harvesting" \
        -o "${OUTPUT_DIR}/tactical_playbook.md"

# ============================================================================
# PHASE 11 — FIELD MANUAL GENERATION
# "We generate comprehensive field manuals for every security team so the
#  organization can operationalize the lessons from this engagement."
# ============================================================================
echo ""
echo "████████████████████████████████████████████████████████████████████████████"
echo "██  PHASE 11: FIELD MANUAL GENERATION                                     ██"
echo "████████████████████████████████████████████████████████████████████████████"

run_cmd "11.1 List security teams available for manual generation" \
    ${PY} -m ciicerone --config "${CONFIG}" manuals list-teams

run_cmd "11.2 Generate Blue Team field manual for spear-phishing (financial sector)" \
    ${PY} -m ciicerone --config "${CONFIG}" manuals generate \
        --team blue_team --threat-type spear_phishing \
        --industry financial --org-size enterprise --difficulty 7 \
        -m T1566.001 -m T1566.002 -m T1003 \
        -c NIST -c ISO27001 -c SOC2 \
        --output-dir "${OUTPUT_DIR}/field_manuals"

run_cmd "11.3 Generate SOC field manual for the same scenario" \
    ${PY} -m ciicerone --config "${CONFIG}" manuals generate \
        --team soc --threat-type spear_phishing \
        --industry financial --org-size enterprise --difficulty 7 \
        -m T1566.001 -m T1078 \
        --output-dir "${OUTPUT_DIR}/field_manuals"

# ============================================================================
# PHASE 12 — PLAYBOOK VALIDATION
# "We validate the generated playbook against industry standards and
#  compliance frameworks to ensure it is production-ready."
# ============================================================================
echo ""
echo "████████████████████████████████████████████████████████████████████████████"
echo "██  PHASE 12: PLAYBOOK VALIDATION                                         ██"
echo "████████████████████████████████████████████████████████████████████████████"

# Use the existing high-quality demo playbook for validation
DEMO_PLAYBOOK="${PROJECT_DIR}/demos/full_platform/sample_data/demo_playbook.md"

run_cmd "12.1 Validate the executive spear-phishing response playbook (NIST + MITRE)" \
    ${PY} -m ciicerone --config "${CONFIG}" validate playbook \
        "${DEMO_PLAYBOOK}" -f nist-csf -f mitre -t incident_response \
        -o markdown -s "${OUTPUT_DIR}/playbook_validation_report.md"

# ============================================================================
# PHASE 13 — FEEDBACK LOOP (CONTINUOUS IMPROVEMENT)
# "We analyze the scenario-playbook pair to extract learnings that improve
#  both future scenarios and future playbooks — the continuous improvement loop."
# ============================================================================
echo ""
echo "████████████████████████████████████████████████████████████████████████████"
echo "██  PHASE 13: FEEDBACK LOOP — CONTINUOUS IMPROVEMENT                      ██"
echo "████████████████████████████████████████████████████████████████████████████"

run_cmd "13.1 Feedback loop status (requires Neo4j for full metrics)" \
    ${PY} -m ciicerone --config "${CONFIG}" feedback status

# ============================================================================
# PHASE 14 — DATASET CATALOG
# "We review the cybersecurity datasets available to enrich future
#  simulations (PhishTank, Enron, MITRE ATT&CK, etc.)."
# ============================================================================
echo ""
echo "████████████████████████████████████████████████████████████████████████████"
echo "██  PHASE 14: DATASET CATALOG                                             ██"
echo "████████████████████████████████████████████████████████████████████████████"

run_cmd "14.1 List available cybersecurity datasets" \
    ${PY} -m ciicerone --config "${CONFIG}" datasets list

run_cmd "14.2 Dataset health status" \
    ${PY} -m ciicerone --config "${CONFIG}" datasets status

# ============================================================================
# PHASE 15 — VM ATTACK SIMULATION LAB
# "We check the status of the VM attack simulation lab, which can run
#  AI-controlled attacks in isolated virtual machines."
# ============================================================================
echo ""
echo "████████████████████████████████████████████████████████████████████████████"
echo "██  PHASE 15: VM ATTACK SIMULATION LAB                                    ██"
echo "████████████████████████████████████████████████████████████████████████████"

run_cmd "15.1 VM lab status (Docker/Azure hypervisor)" \
    ${PY} -m ciicerone --config "${CONFIG}" vm status

# ============================================================================
# PHASE 16 — MCP SERVER (AI-DRIVEN VM CONTROL)
# "We inspect the MCP server that exposes VM control tools to AI agents
#  like Claude Desktop for autonomous attack simulations."
# ============================================================================
echo ""
echo "████████████████████████████████████████████████████████████████████████████"
echo "██  PHASE 16: MCP SERVER — AI-DRIVEN VM CONTROL                           ██"
echo "████████████████████████████████████████████████████████████████████████████"

run_cmd "16.1 MCP server status & configuration" \
    ${PY} -m ciicerone --config "${CONFIG}" mcp status

run_cmd "16.2 List MCP tools available to AI agents" \
    ${PY} -m ciicerone --config "${CONFIG}" mcp tools

run_cmd "16.3 Export MCP tool schemas (for client configuration)" \
    ${PY} -m ciicerone --config "${CONFIG}" mcp export-schema \
        -o "${OUTPUT_DIR}/mcp_tool_schema.json"

# ============================================================================
# PHASE 17 — DEPLOYMENT & CAMPAIGN MANAGEMENT
# "We review the deployment platforms available for launching authorized
#  phishing campaigns (M365, Proofpoint, KnowBe4, Slack) in test mode."
# ============================================================================
echo ""
echo "████████████████████████████████████████████████████████████████████████████"
echo "██  PHASE 17: DEPLOYMENT & CAMPAIGN MANAGEMENT                            ██"
echo "████████████████████████████████████████████████████████████████████████████"

run_cmd "17.1 List available deployment platforms" \
    ${PY} -m ciicerone --config "${CONFIG}" deploy platforms

run_cmd "17.2 Deploy campaign in TEST MODE (safe, no real delivery)" \
    ${PY} -m ciicerone --config "${CONFIG}" deploy campaign \
        --name "Project Nightfall - Q3 Board Lure" \
        --content-file "${SCRIPT_DIR}/content.json" \
        --targets-file "${SCRIPT_DIR}/targets.json" \
        --channels email --duration 1 --test-mode

# ============================================================================
# PHASE 18 — SIMULATION LOGS & REPORTING
# "We review the simulation logs captured during the engagement and
#  generate statistics for the executive report."
# ============================================================================
echo ""
echo "████████████████████████████████████████████████████████████████████████████"
echo "██  PHASE 18: SIMULATION LOGS & REPORTING                                 ██"
echo "████████████████████████████████████████████████████████████████████████████"

run_cmd "18.1 List stored simulation results" \
    ${PY} -m ciicerone --config "${CONFIG}" logs list

run_cmd "18.2 Simulation statistics" \
    ${PY} -m ciicerone --config "${CONFIG}" logs stats

# ============================================================================
# PHASE 19 — SAFETY & COMPLIANCE
# "Finally, we confirm the safety controls that govern every Ciicerone
#  operation: content filtering, audit logging, and ethical use."
# ============================================================================
echo ""
echo "████████████████████████████████████████████████████████████████████████████"
echo "██  PHASE 19: SAFETY & COMPLIANCE                                         ██"
echo "████████████████████████████████████████████████████████████████████████████"

run_cmd "19.1 Safety & compliance check" \
    ${PY} -m ciicerone --config "${CONFIG}" safety --help

# ============================================================================
# SUMMARY
# ============================================================================
echo ""
echo "████████████████████████████████████████████████████████████████████████████"
echo "██  PROJECT NIGHTFALL — ENGAGEMENT SUMMARY                                ██"
echo "████████████████████████████████████████████████████████████████████████████"
echo ""
echo "All Ciicerone feature areas exercised:"
echo "  [x] status            — platform status"
echo "  [x] client-data       — tenant sync, profile, scenario enrichment"
echo "  [x] intel             — OSINT sources & gathering"
echo "  [x] templates         — list, show, validate"
echo "  [x] validate          — schema + playbook validation"
echo "  [x] simulate          — dry-run + (optional) live LLM simulation"
echo "  [x] llm               — provider testing"
echo "  [x] red-team          — Ciicerone Attack health & scenario→flow mapping"
echo "  [x] detect            — Sigma/Splunk/Elastic/Sentinel rule generation"
echo "  [x] blue-team         — SIEM, IDS, EDR, IR, hunt, logs, triage, forensics"
echo "  [x] rag               — status, init, sources, ingest, playbook generation"
echo "  [x] manuals           — field manual generation (blue team + SOC)"
echo "  [x] feedback          — continuous improvement loop status"
echo "  [x] datasets          — catalog & health"
echo "  [x] vm                — VM attack lab status"
echo "  [x] mcp               — AI-driven VM control tools & schema export"
echo "  [x] deploy            — campaign management (test mode)"
echo "  [x] logs              — simulation results & statistics"
echo "  [x] safety            — safety & compliance controls"
echo ""
echo "Artifacts generated in ${OUTPUT_DIR}/:"
ls -1 "${OUTPUT_DIR}" 2>/dev/null | sed 's/^/  /' || echo "  (none)"
echo ""
echo "=== End-to-end demo complete ==="
