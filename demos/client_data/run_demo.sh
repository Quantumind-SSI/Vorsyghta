#!/usr/bin/env bash
# Demo script for Ciicerone client-data enrichment.
# Runs a local HTTP server, syncs client data, and enriches a demo scenario.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CONFIG="${SCRIPT_DIR}/demo_config.yaml"
DEMO_PORT=8765
RECON_FLAG=""

if [[ "${1:-}" == "--recon" ]]; then
    RECON_FLAG="--recon"
    echo "=== Ciicerone client-data demo (with company recon) ==="
else
    echo "=== Ciicerone client-data demo ==="
fi
echo "Project dir: ${PROJECT_DIR}"
echo "Config:      ${CONFIG}"
echo ""

echo "Project dir: ${PROJECT_DIR}"
echo "Config:      ${CONFIG}"
echo ""

# Kill any existing process on the demo port to avoid "Address already in use".
if command -v lsof >/dev/null 2>&1; then
    lsof -ti tcp:${DEMO_PORT} | xargs kill 2>/dev/null || true
fi

# Start the local demo HTTP server in the background.
python "${SCRIPT_DIR}/serve_demo_data.py" --port "${DEMO_PORT}" --dir "${SCRIPT_DIR}" &
SERVER_PID=$!

# Ensure the server is killed when the script exits.
cleanup() {
    echo ""
    echo "=== Cleaning up demo server (PID ${SERVER_PID}) ==="
    kill "${SERVER_PID}" 2>/dev/null || true
}
trap cleanup EXIT

# Wait for the server to be ready.
for i in {1..30}; do
    if curl -sf "http://localhost:${DEMO_PORT}/demo_client_api.json" >/dev/null; then
        break
    fi
    sleep 0.1
done

echo "=== 1. List configured client data sources ==="
python -m ciicerone --config "${CONFIG}" client-data list

echo ""
echo "=== 2. Sync client data sources for tenant 'acme-demo' ==="
python -m ciicerone --config "${CONFIG}" client-data sync --tenant acme-demo

echo ""
echo "=== 3. Show synced client profile ==="
python -m ciicerone --config "${CONFIG}" client-data show --tenant acme-demo

echo ""
echo "=== 4. Enrich demo scenario with client data ==="
python -m ciicerone --config "${CONFIG}" client-data enrich \
    --tenant acme-demo \
    --scenario "${SCRIPT_DIR}/demo_scenario.yaml" \
    --output "${SCRIPT_DIR}/enriched_scenario.json" \
    ${RECON_FLAG}

echo ""
echo "=== 5. Preview enriched scenario target profile ==="
python - <<PY
import json
from pathlib import Path
with open("${SCRIPT_DIR}/enriched_scenario.json") as f:
    data = json.load(f)
print("Target role:", data["target_profile"]["role"])
print("Target department:", data["target_profile"]["department"])
print("Client name:", data["custom_parameters"].get("client_name"))
print("Employees:", len(data["custom_parameters"].get("client_employees", [])))
print("Network topology nodes:", len(data["custom_parameters"].get("client_network_topology", {}).get("nodes", [])))
print("Client assets:", len(data["custom_parameters"].get("client_assets", [])))
PY

echo ""
echo "=== Demo complete ==="
echo "Enriched scenario saved to: ${SCRIPT_DIR}/enriched_scenario.json"
