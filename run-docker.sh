#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
docker compose -f docker-compose.yml up -d postgres redis ollama
docker compose -f docker-compose.yml up -d vorsyghta-api
docker compose -f docker-compose.yml --profile web up -d vorsyghta-web
echo "Vorsyghta API: http://localhost:8001"
echo "Vorsyghta Web: http://localhost:3000"
