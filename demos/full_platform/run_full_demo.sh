#!/usr/bin/env bash
# Full-platform demo script for Vorsyghta.
# Showcases all major feature areas: client-data, red-team, blue-team,
# intel, detect, feedback, rag, datasets, vm, mcp, logs, templates, validate, status.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_DATA_DIR="${SCRIPT_DIR}/../client_data"
CONFIG="${CLIENT_DATA_DIR}/demo_config.yaml"
DEMO_PORT=8765

RECON_FLAG=""
if [[ "${1:-}" == "--recon" ]]; then
    RECON_FLAG="--recon"
    echo "=== Vorsyghta full-platform demo (with company recon) ==="
else
    echo "=== Vorsyghta full-platform demo ==="
fi
echo "Config: ${CONFIG}"
echo ""

# Ensure the client-data demo server is not already running.
if command -v lsof >/dev/null 2>&1; then
    lsof -ti tcp:${DEMO_PORT} | xargs kill 2>/dev/null || true
fi

# Start the client-data demo server.
python "${CLIENT_DATA_DIR}/serve_demo_data.py" --port "${DEMO_PORT}" --dir "${CLIENT_DATA_DIR}" &
SERVER_PID=$!
cleanup() {
    echo ""
    echo "=== Cleaning up demo server (PID ${SERVER_PID}) ==="
    kill "${SERVER_PID}" 2>/dev/null || true
}
trap cleanup EXIT

for i in {1..30}; do
    if curl -sf "http://localhost:${DEMO_PORT}/demo_client_api.json" >/dev/null; then
        break
    fi
    sleep 0.1
done

run_cmd() {
    echo ""
    echo "=== $1 ==="
    shift
    "$@" || true
}

# 1. Core platform
run_cmd "1. Platform status" \
    python -m vorsyghta --config "${CONFIG}" status

# 2. Templates
run_cmd "2. List scenario templates" \
    python -m vorsyghta --config "${CONFIG}" templates list-all

# 3. Validation
run_cmd "3. Validate a demo playbook" \
    python -m vorsyghta --config "${CONFIG}" validate playbook \
        "${SCRIPT_DIR}/sample_data/demo_playbook.md"

# 4. Client data
run_cmd "4a. List client data sources" \
    python -m vorsyghta --config "${CONFIG}" client-data list --tenant acme-demo

run_cmd "4b. Sync client data sources" \
    python -m vorsyghta --config "${CONFIG}" client-data sync --tenant acme-demo

run_cmd "4c. Show synced client profile" \
    python -m vorsyghta --config "${CONFIG}" client-data show --tenant acme-demo

run_cmd "4d. Enrich demo scenario" \
    python -m vorsyghta --config "${CONFIG}" client-data enrich \
        --tenant acme-demo \
        --scenario "${CLIENT_DATA_DIR}/demo_scenario.yaml" \
        --output "${SCRIPT_DIR}/enriched_scenario.json" \
        ${RECON_FLAG}

# 5. Red team (Vorsyghta Attack integration)
run_cmd "5. Red team health" \
    python -m vorsyghta --config "${CONFIG}" red-team health

run_cmd "5b. Vorsyghta Attack task mapping" \
    python - <<PY
import json
from vorsyghta.integrations.attack_mapper import AttackMapper

scenario = {
    "name": "Executive Spear-Phishing",
    "threat_type": "spear_phishing",
    "mitre_techniques": ["T1589", "T1566.001", "T1566.002", "T1078", "T1003", "T1059", "T1041"],
    "difficulty": 6,
    "objectives": [
        "Confirm credential compromise via phishing link",
        "Demonstrate lateral movement using valid accounts",
        "Test detection coverage for MITRE T1566 and T1003"
    ],
    "target": {"url": "http://demo-finance.acme-corp.com"},
    "max_duration_minutes": 60,
}

mapper = AttackMapper()
flow = mapper.scenario_to_flow(scenario, target_info={"ip": "192.168.1.10", "services": ["http", "smtp"]})
print("Flow name:", flow["name"])
print("Target:", flow["target"])
print("MITRE techniques:", flow["parameters"]["mitre_techniques"])
print("\nSuggested attack phases:")
for line in flow["description"].split("\n"):
    if line.strip().startswith("-") or "Phase:" in line:
        print(line)
PY

# 6. Blue team
run_cmd "6a. Blue team dashboard" \
    python -m vorsyghta --config "${CONFIG}" blue-team dashboard

run_cmd "6b. IDS rules" \
    python -m vorsyghta --config "${CONFIG}" blue-team ids rules

run_cmd "6c. IDS inspect sample alert" \
    python -m vorsyghta --config "${CONFIG}" blue-team ids inspect \
        --protocol tcp --src-ip 10.0.0.5 --dest-port 22 \
        --payload "Failed password for admin"

run_cmd "6d. EDR monitor sample process" \
    python -m vorsyghta --config "${CONFIG}" blue-team edr monitor \
        --process powershell.exe --cmd "powershell -enc SGVsbG8=" --user admin

run_cmd "6e. Create incident response" \
    python -m vorsyghta --config "${CONFIG}" blue-team incident create \
        -t "Credential Dumping Attack" -s critical -c intrusion \
        --systems DC-01,WEB-02 --mitre T1003,T1059 --auto

# 7. Intelligence
run_cmd "7. Intelligence sources" \
    python -m vorsyghta --config "${CONFIG}" intel sources

# 8. Detection engineering
run_cmd "8. Detection rule formats" \
    python -m vorsyghta --config "${CONFIG}" detect list-formats

# 9. RAG
run_cmd "9. RAG status" \
    python -m vorsyghta --config "${CONFIG}" rag status

# 10. Feedback
run_cmd "10. Feedback loop help" \
    python -m vorsyghta --config "${CONFIG}" feedback --help

# 11. Datasets
run_cmd "11. Dataset catalog" \
    python -m vorsyghta --config "${CONFIG}" datasets list

# 12. VM
run_cmd "12. VM lab status" \
    python -m vorsyghta --config "${CONFIG}" vm status

# 13. MCP
run_cmd "13. MCP server status" \
    python -m vorsyghta --config "${CONFIG}" mcp status

# 14. Logs
run_cmd "14. Simulation logs" \
    python -m vorsyghta --config "${CONFIG}" logs list

# 15. Safety
run_cmd "15. Safety check" \
    python -m vorsyghta --config "${CONFIG}" safety --help

# 16. Preview enriched scenario
if [[ -f "${SCRIPT_DIR}/enriched_scenario.json" ]]; then
    run_cmd "16. Preview enriched scenario" \
        python - <<PY
import json
from pathlib import Path
with open("${SCRIPT_DIR}/enriched_scenario.json") as f:
    data = json.load(f)
print("Scenario:", data["metadata"]["name"])
print("Target role:", data["target_profile"]["role"])
print("Client name:", data["custom_parameters"].get("client_name"))
print("Employees:", len(data["custom_parameters"].get("client_employees", [])))
print("Network nodes:", len(data["custom_parameters"].get("client_network_topology", {}).get("nodes", [])))
print("Recon data:", "company_recon" in data["custom_parameters"])
PY
fi

echo ""
echo "=== Full-platform demo complete ==="
