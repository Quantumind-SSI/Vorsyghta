#!/usr/bin/env bash
# =============================================================================
# Vorsyghta Docker Integration Harness
# =============================================================================
# Brings up the FULL Vorsyghta stack in your local Docker network using the
# DEV image built from ./Dockerfile (which bakes in all code, infra wiring,
# migrations, tests, and demos), then runs the Docker-native acceptance gate
# against it to produce REAL, proven results backed by Azure OpenAI.
#
# Stack brought up (from docker-compose.yml + integration override):
#   postgres, redis, ollama, vorsyghta-api, prometheus, grafana
#
# Flow:
#   1. Validate .env has the required Azure OpenAI + secret vars
#   2. Build the vorsyghta-api image locally from ./Dockerfile
#      (--client-image: instead pull ghcr.io/quantumindssi/vorsyghta:latest
#       and skip the local build — see docker/docker-compose.client-image.yml)
#   3. docker compose up -d (full stack)
#   4. Wait for the API health endpoint to report healthy
#   5. Seed an analyst user (so the gate can run a REAL exercise)
#   6. Run demos/pilot_full_flow/run_docker_acceptance.sh against localhost:8001
#   7. Collect proven-result artifacts (exercise JSON, AAR JSON, gate log)
#   8. Tear down (unless --keep)
#
# Usage:
#   bash scripts/run_docker_integration.sh                  # build locally + run
#   bash scripts/run_docker_integration.sh --keep           # run, leave stack up
#   bash scripts/run_docker_integration.sh --no-build       # skip image rebuild
#   bash scripts/run_docker_integration.sh --client-image   # pull ghcr.io image, no build
#   bash scripts/run_docker_integration.sh --down           # just tear down the stack
#
# Required .env entries:
#   AZURE_OPENAI_API_KEY, AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_DEPLOYMENT
#   VORSYGHTA_SECRET_KEY
#   POSTGRES_PASSWORD, GRAFANA_ADMIN_PASSWORD, PGADMIN_PASSWORD
#
# Optional .env entries (only used with --client-image):
#   CLIENT_IMAGE_TAG=latest   (ghcr.io tag to pull)
# =============================================================================
set -euo pipefail

# ---- Defaults -------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_BASE="$ROOT_DIR/docker-compose.yml"
COMPOSE_OVERRIDE="$ROOT_DIR/docker/docker-compose.integration.yml"
COMPOSE_CLIENT_IMAGE="$ROOT_DIR/docker/docker-compose.client-image.yml"
GATE="$ROOT_DIR/demos/pilot_full_flow/run_docker_acceptance.sh"
OUTPUT_DIR="$ROOT_DIR/demos/pilot_full_flow/output"
API_PORT="${API_PORT:-8001}"
API_BASE="http://localhost:${API_PORT}"
TS=$(date +%Y%m%d_%H%M%S)
RUN_DIR="$OUTPUT_DIR/integration_${TS}"

KEEP=0
NO_BUILD=0
DOWN_ONLY=0
CLIENT_IMAGE=0
CLIENT_IMAGE_TAG="${CLIENT_IMAGE_TAG:-latest}"
CLIENT_IMAGE_REF="ghcr.io/quantumindssi/vorsyghta:${CLIENT_IMAGE_TAG}"

GREEN='\033[0;32m'
RED='\033[0;31m'
BOLD='\033[1m'
YELLOW='\033[0;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}>>${NC} $1"; }
warn()  { echo -e "${YELLOW}>>${NC} $1"; }
err()   { echo -e "${RED}!!${NC} $1" >&2; }
die()   { err "$1"; exit 1; }

# ---- Arg parsing ----------------------------------------------------------
for arg in "$@"; do
    case "$arg" in
        --keep)         KEEP=1 ;;
        --no-build)     NO_BUILD=1 ;;
        --down)         DOWN_ONLY=1 ;;
        --client-image) CLIENT_IMAGE=1 ;;
        -h|--help)
            sed -n '2,40p' "$0"
            exit 0
            ;;
        *) die "Unknown arg: $arg (try --help)" ;;
    esac
done

cd "$ROOT_DIR"

COMPOSE=(docker compose -f "$COMPOSE_BASE" -f "$COMPOSE_OVERRIDE")
if [ "$CLIENT_IMAGE" -eq 1 ]; then
    COMPOSE+=( -f "$COMPOSE_CLIENT_IMAGE" )
fi

# ---- Just tear down? ------------------------------------------------------
if [ "$DOWN_ONLY" -eq 1 ]; then
    info "Tearing down the integration stack..."
    "${COMPOSE[@]}" down -v --remove-orphans
    info "Done."
    exit 0
fi

# ---- .env validation ------------------------------------------------------
[ -f "$ROOT_DIR/.env" ] || die "No .env found at $ROOT_DIR/.env. Copy .env.example and fill in Azure OpenAI + secret values."

# shellcheck disable=SC1091
set -a; . "$ROOT_DIR/.env"; set +a

require_var() {
    local name="$1"
    local val="${!name:-}"
    [ -n "$val" ] || die "$name is not set in .env (required for real LLM integration)."
    case "$val" in
        your_*_here|changeme*) die "$name is still the placeholder value — set a real value in .env." ;;
    esac
}

require_var AZURE_OPENAI_API_KEY
require_var AZURE_OPENAI_ENDPOINT
require_var AZURE_OPENAI_DEPLOYMENT
require_var VORSYGHTA_SECRET_KEY
require_var POSTGRES_PASSWORD
require_var GRAFANA_ADMIN_PASSWORD

info "Env validated: AZURE_OPENAI_ENDPOINT=$AZURE_OPENAI_ENDPOINT AZURE_OPENAI_DEPLOYMENT=$AZURE_OPENAI_DEPLOYMENT"

# ---- Output dir -----------------------------------------------------------
mkdir -p "$RUN_DIR"

# ---- Build / pull ---------------------------------------------------------
if [ "$CLIENT_IMAGE" -eq 1 ]; then
    info "Pulling pre-built client image: $CLIENT_IMAGE_REF ..."
    docker pull "$CLIENT_IMAGE_REF" 2>&1 | tee "$RUN_DIR/pull.log"
    info "Image pulled. Local build skipped (--client-image)."
elif [ "$NO_BUILD" -eq 0 ]; then
    info "Building vorsyghta-api image from ./Dockerfile (dev image with all code/infra)..."
    "${COMPOSE[@]}" build vorsyghta-api 2>&1 | tee "$RUN_DIR/build.log"
else
    info "Skipping image build (--no-build)."
fi

# ---- Bring up the stack ---------------------------------------------------
info "Bringing up the full stack (postgres, redis, ollama, vorsyghta-api, prometheus, grafana)..."
"${COMPOSE[@]}" up -d 2>&1 | tee "$RUN_DIR/up.log"

# ---- Wait for API health --------------------------------------------------
info "Waiting for API to become healthy at $API_BASE/health ..."
HEALTHY=0
for i in $(seq 1 60); do
    STATUS=$(curl -s --max-time 5 "$API_BASE/health" 2>/dev/null | python3 -c "import sys,json
try: print(json.load(sys.stdin).get('status',''))
except Exception: print('')" 2>/dev/null || true)
    if [ "$STATUS" = "healthy" ]; then
        HEALTHY=1
        info "API healthy after ${i}0s."
        break
    fi
    sleep 10
done
if [ "$HEALTHY" -eq 0 ]; then
    err "API did not become healthy in time. Last few API logs:"
    "${COMPOSE[@]}" logs --tail=50 vorsyghta-api >&2 || true
    die "Stack came up but API is not healthy."
fi

# Save the health snapshot as a proven artifact.
curl -s "$API_BASE/health" | python3 -m json.tool > "$RUN_DIR/health.json" || true

# ---- Seed analyst ---------------------------------------------------------
info "Seeding analyst user (so the gate can run a REAL exercise)..."
SEED_EMAIL="${SEED_ANALYST_EMAIL:-analyst@vorsyghta.local}"
SEED_PASSWORD="${SEED_ANALYST_PASSWORD:-Analyst123!}"
"${COMPOSE[@]}" exec -T vorsyghta-api python -m vorsyghta.db.seed 2>&1 | tee "$RUN_DIR/seed.log" || \
    warn "Seeder exited non-zero — continuing (user may already exist)."

# ---- Run the acceptance gate ----------------------------------------------
info "Running Docker-native acceptance gate against $API_BASE ..."
if bash "$GATE" "$API_BASE" "$SEED_EMAIL" "$SEED_PASSWORD" 2>&1 | tee "$RUN_DIR/acceptance_gate.log"; then
    GATE_RC=0
    info "Acceptance gate PASSED."
else
    GATE_RC=$?
    err "Acceptance gate FAILED (exit $GATE_RC)."
fi

# ---- Collect proven-result artifacts --------------------------------------
info "Collecting proven-result artifacts to $RUN_DIR ..."
# Exercise + AAR JSONs stashed by the gate in /tmp.
cp /tmp/vorsyghta_exercise_*.json "$RUN_DIR/" 2>/dev/null && info "  exercise result JSON collected" || warn "  no exercise JSON found in /tmp"
cp /tmp/vorsyghta_aar_*.json "$RUN_DIR/" 2>/dev/null && info "  AAR JSON collected" || warn "  no AAR JSON found in /tmp"
# Stack state snapshot.
"${COMPOSE[@]}" ps > "$RUN_DIR/compose_ps.txt" 2>&1 || true
"${COMPOSE[@]}" logs --tail=200 vorsyghta-api > "$RUN_DIR/api_logs.txt" 2>&1 || true
# OpenAPI schema as a proven artifact (proves router surface).
curl -s "$API_BASE/openapi.json" > "$RUN_DIR/openapi.json" 2>/dev/null || true

# Write a small manifest.
{
    echo "Vorsyghta Docker Integration Run — $TS"
    echo "API_BASE: $API_BASE"
    echo "AZURE_OPENAI_ENDPOINT: ${AZURE_OPENAI_ENDPOINT}"
    echo "AZURE_OPENAI_DEPLOYMENT: ${AZURE_OPENAI_DEPLOYMENT}"
    echo "Image source: $([ "$CLIENT_IMAGE" -eq 1 ] && echo "pulled ($CLIENT_IMAGE_REF)" || echo "local build")"
    echo "Gate exit code: $GATE_RC"
    echo "Artifacts:"
    ls -1 "$RUN_DIR"
} > "$RUN_DIR/MANIFEST.txt"

# ---- Teardown -------------------------------------------------------------
if [ "$KEEP" -eq 1 ]; then
    info "Stack left running (--keep). Tear down later with: bash scripts/run_docker_integration.sh --down"
else
    info "Tearing down the stack..."
    "${COMPOSE[@]}" down -v --remove-orphans
fi

echo ""
echo -e "${BOLD}========================================================================${NC}"
echo -e "${BOLD}  INTEGRATION RUN COMPLETE${NC}"
echo -e "${BOLD}========================================================================${NC}"
echo "  Artifacts:  $RUN_DIR"
echo "  Gate exit:  $GATE_RC"
echo ""
if [ "$GATE_RC" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}REAL PROVEN RESULTS: all acceptance checks passed against the live Docker stack.${NC}"
    exit 0
else
    echo -e "  ${RED}${BOLD}One or more acceptance checks failed — review $RUN_DIR/acceptance_gate.log.${NC}"
    exit "$GATE_RC"
fi
