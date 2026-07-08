#!/usr/bin/env bash
# =============================================================================
# Ciicerone — Sanctioned Target Pentest Harness
# =============================================================================
# Brings up the Ciicerone stack PLUS a sanctioned, intentionally-vulnerable
# target container (OWASP Juice Shop by default), waits for both to be
# healthy, then either:
#   * prints the exact `ciicerone red-team attack` command to point the
#     attack agent at the target (--dry-run, the default), OR
#   * launches the attack directly (--attack) if a tool server is reachable.
#
# This validates the red-team + discovery toolchain against a target with
# KNOWN ground truth (Juice Shop's ~100 documented challenges + scoreboard),
# so you can prove the agent actually found vulnerabilities rather than
# hallucinating — compare vuln_report.py output against the challenge list.
#
# IMPORTANT: Juice Shop is a TRAINING target published for authorized testing.
# This harness is for the local Juice Shop container ONLY. It is NOT a
# zero-day research harness — genuine zero-day work targets real software in
# a sanctioned engagement scope and uses disclosure.py for responsible
# disclosure / CVE assignment.
#
# Flow:
#   1. Validate .env (same vars as run_docker_integration.sh)
#   2. Bring up the stack + sanctioned target via docker compose
#   3. Wait for Ciicerone API health (localhost:API_PORT)
#   4. Wait for Juice Shop health (localhost:JUICE_SHOP_PORT)
#   5. Print / launch the red-team attack command against the target
#
# Usage:
#   bash scripts/run_sanctioned_target.sh                          # dry-run
#   bash scripts/run_sanctioned_target.sh --target juice-shop      # explicit target
#   bash scripts/run_sanctioned_target.sh --attack                 # launch the attack
#   bash scripts/run_sanctioned_target.sh --keep                   # leave stack up
#   bash scripts/run_sanctioned_target.sh --down                   # tear down
#   bash scripts/run_sanctioned_target.sh --client-image           # use ghcr.io image
#
# Required .env entries (same as run_docker_integration.sh):
#   CIICERONE_SECRET_KEY, POSTGRES_PASSWORD, GRAFANA_ADMIN_PASSWORD
#   (+ AZURE_OPENAI_* if you want real LLM-backed exercise runs)
#
# Optional .env entries:
#   JUICE_SHOP_PORT=3000          (host port for the Juice Shop target)
#   JUICE_SHOP_IMAGE_TAG=latest   (Juice Shop image tag)
#   API_PORT=8001                 (host port for the Ciicerone API)
#   CIICERONE_TOOL_SERVER_URL     (tool server for --attack mode)
# =============================================================================
set -uo pipefail

# ---- Defaults -------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_BASE="$ROOT_DIR/docker-compose.yml"
COMPOSE_OVERRIDE="$ROOT_DIR/docker/docker-compose.integration.yml"
COMPOSE_CLIENT_IMAGE="$ROOT_DIR/docker/docker-compose.client-image.yml"
COMPOSE_TARGET_DIR="$ROOT_DIR/docker/targets"
OUTPUT_DIR="$ROOT_DIR/demos/pilot_full_flow/output"
API_PORT="${API_PORT:-8001}"
JUICE_SHOP_PORT="${JUICE_SHOP_PORT:-3000}"
API_BASE="http://localhost:${API_PORT}"
TS=$(date +%Y%m%d_%H%M%S)
RUN_DIR="$OUTPUT_DIR/sanctioned_${TS}"

TARGET="juice-shop"
KEEP=0
DOWN_ONLY=0
ATTACK=0
CLIENT_IMAGE=0
CLIENT_IMAGE_TAG="${CLIENT_IMAGE_TAG:-latest}"

GREEN='\033[0;32m'
RED='\033[0;31m'
BOLD='\033[1m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}>>${NC} $1"; }
warn()  { echo -e "${YELLOW}>>${NC} $1"; }
err()   { echo -e "${RED}!!${NC} $1" >&2; }
die()   { err "$1"; exit 1; }

# ---- Arg parsing ----------------------------------------------------------
# Use a while loop so `shift` actually advances the positional params — a
# `for arg in "$@"` loop snapshots $@ at start and ignores shifts, causing
# `--target juice-shop` to re-process `juice-shop` as an unknown arg.
while [ $# -gt 0 ]; do
    case "$1" in
        --target)        shift; TARGET="${1:-juice-shop}" ;;
        --keep)          KEEP=1 ;;
        --attack)        ATTACK=1 ;;
        --down)          DOWN_ONLY=1 ;;
        --client-image)  CLIENT_IMAGE=1 ;;
        -h|--help)
            sed -n '2,55p' "$0"
            exit 0
            ;;
        *) die "Unknown arg: $1 (try --help)" ;;
    esac
    shift || true
done

# Resolve the target compose fragment.
case "$TARGET" in
    juice-shop|juice_shop)
        COMPOSE_TARGET="$COMPOSE_TARGET_DIR/juice-shop.yml"
        SCENARIO="$ROOT_DIR/templates/sanctioned_targets/juice_shop_web_pentest.yaml"
        TARGET_HOST_PORT="$JUICE_SHOP_PORT"
        TARGET_HEALTH_PATH="/"
        TARGET_NAME="OWASP Juice Shop"
        ;;
    *)
        die "Unknown sanctioned target: '$TARGET'. Available: juice-shop"
        ;;
esac
[ -f "$COMPOSE_TARGET" ] || die "Target compose fragment not found: $COMPOSE_TARGET"
[ -f "$SCENARIO" ]       || die "Scenario template not found: $SCENARIO"

cd "$ROOT_DIR"

COMPOSE=(docker compose -f "$COMPOSE_BASE" -f "$COMPOSE_OVERRIDE" -f "$COMPOSE_TARGET")
if [ "$CLIENT_IMAGE" -eq 1 ]; then
    COMPOSE+=( -f "$COMPOSE_CLIENT_IMAGE" )
fi

# ---- Just tear down? ------------------------------------------------------
if [ "$DOWN_ONLY" -eq 1 ]; then
    info "Tearing down the sanctioned-target stack..."
    "${COMPOSE[@]}" down -v --remove-orphans
    info "Done."
    exit 0
fi

# ---- .env validation ------------------------------------------------------
[ -f "$ROOT_DIR/.env" ] || die "No .env found at $ROOT_DIR/.env. Copy .env.example and fill in required values."
# shellcheck disable=SC1091
set -a; . "$ROOT_DIR/.env"; set +a

require_var() {
    local name="$1"
    local val="${!name:-}"
    [ -n "$val" ] || die "$name is not set in .env (required)."
    case "$val" in
        your_*_here|changeme*) die "$name is still the placeholder value — set a real value in .env." ;;
    esac
}
require_var CIICERONE_SECRET_KEY
require_var POSTGRES_PASSWORD
require_var GRAFANA_ADMIN_PASSWORD

mkdir -p "$RUN_DIR"

# ---- Bring up the stack + target ------------------------------------------
info "Bringing up the Ciicerone stack + sanctioned target ($TARGET_NAME)..."
if [ "$CLIENT_IMAGE" -eq 1 ]; then
    info "  using pre-built client image (ghcr.io/quantumindssi/ciicerone:${CLIENT_IMAGE_TAG})"
fi
"${COMPOSE[@]}" up -d 2>&1 | tee "$RUN_DIR/up.log"

# ---- Wait for Ciicerone API health ----------------------------------------
info "Waiting for Ciicerone API at $API_BASE/health ..."
API_HEALTHY=0
for i in $(seq 1 60); do
    STATUS=$(curl -s --max-time 5 "$API_BASE/health" 2>/dev/null | python3 -c "import sys,json
try: print(json.load(sys.stdin).get('status',''))
except Exception: print('')" 2>/dev/null || true)
    if [ "$STATUS" = "healthy" ]; then
        API_HEALTHY=1
        info "Ciicerone API healthy after ${i}0s."
        break
    fi
    sleep 10
done
if [ "$API_HEALTHY" -eq 0 ]; then
    err "Ciicerone API did not become healthy in time."
    "${COMPOSE[@]}" logs --tail=50 ciicerone-api >&2 || true
    die "Stack came up but API is not healthy."
fi

# ---- Wait for sanctioned target health ------------------------------------
TARGET_BASE="http://localhost:${TARGET_HOST_PORT}"
info "Waiting for sanctioned target ($TARGET_NAME) at $TARGET_BASE$TARGET_HEALTH_PATH ..."
TARGET_HEALTHY=0
for i in $(seq 1 30); do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$TARGET_BASE$TARGET_HEALTH_PATH" 2>/dev/null || true)
    if [ "$CODE" = "200" ]; then
        TARGET_HEALTHY=1
        info "$TARGET_NAME healthy after ${i}0s (HTTP $CODE)."
        break
    fi
    sleep 10
done
if [ "$TARGET_HEALTHY" -eq 0 ]; then
    err "$TARGET_NAME did not become healthy in time (last HTTP code: ${CODE:-none})."
    "${COMPOSE[@]}" logs --tail=50 juice-shop >&2 || true
    die "Sanctioned target is not healthy."
fi

# Save a target snapshot as a proven artifact.
curl -s "$TARGET_BASE/" > "$RUN_DIR/target_index.html" 2>/dev/null || true
"${COMPOSE[@]}" ps > "$RUN_DIR/compose_ps.txt" 2>&1 || true

# ---- Build the red-team attack command ------------------------------------
ATTACK_CMD="ciicerone red-team attack -s \"$SCENARIO\" -t \"$TARGET_BASE\" -o \"$RUN_DIR/findings.json\""

echo ""
echo -e "${BOLD}========================================================================${NC}"
echo -e "${BOLD}  SANCTIONED TARGET READY — $TARGET_NAME${NC}"
echo -e "${BOLD}========================================================================${NC}"
echo -e "  Ciicerone API:  $API_BASE"
echo -e "  Target:         $TARGET_BASE  ($TARGET_NAME)"
echo -e "  Scenario:       $SCENARIO"
echo -e "  Artifacts:      $RUN_DIR"
echo ""
echo -e "  ${CYAN}Red-team attack command:${NC}"
echo -e "  $ATTACK_CMD"
echo ""

# ---- Launch the attack? ---------------------------------------------------
if [ "$ATTACK" -eq 1 ]; then
    info "Launching red-team attack (--attack)..."
    # Ensure the tool server URL is exported for the orchestrator client.
    export CIICERONE_TOOL_SERVER_URL="${CIICERONE_TOOL_SERVER_URL:-}"
    if [ -z "$CIICERONE_TOOL_SERVER_URL" ]; then
        warn "CIICERONE_TOOL_SERVER_URL is not set — the orchestrator will fall back to"
        warn "the default tool server. If it is unreachable, the attack steps will fail."
    fi
    if eval "$ATTACK_CMD" 2>&1 | tee "$RUN_DIR/attack.log"; then
        info "Attack completed. Findings: $RUN_DIR/findings.json"
    else
        RC=$?
        err "Attack exited non-zero (exit $RC). See $RUN_DIR/attack.log"
    fi
else
    info "Dry-run mode (default). Re-run with --attack to launch the attack."
    info "Or copy the command above into a shell with a configured tool server."
fi

# ---- Teardown -------------------------------------------------------------
if [ "$KEEP" -eq 1 ]; then
    info "Stack left running (--keep). Tear down later with:"
    echo "    bash scripts/run_sanctioned_target.sh --down"
else
    info "Tearing down the stack..."
    "${COMPOSE[@]}" down -v --remove-orphans
fi

echo ""
echo -e "${BOLD}  GROUND-TRUTH CHECK:${NC} compare findings.json against the $TARGET_NAME"
echo -e "  scoreboard / challenge list to measure discovery-pipeline recall."
echo ""
