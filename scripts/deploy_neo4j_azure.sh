#!/usr/bin/env bash
# Deploy Neo4j on Azure Container Instances for Vorsyghta RAG.

set -euo pipefail

RESOURCE_GROUP="${RESOURCE_GROUP:-vorsyghta-rg}"
LOCATION="${LOCATION:-eastus2}"
CONTAINER_NAME="${CONTAINER_NAME:-vorsyghta-neo4j}"
NEO4J_PASSWORD="${NEO4J_PASSWORD:-password}"
DNS_LABEL="${DNS_LABEL:-vorsyghta-neo4j-$(date +%s)}"

echo "[INFO] Deploying Neo4j to Azure Container Instances..."
echo "[INFO] Resource group: ${RESOURCE_GROUP}"
echo "[INFO] Location: ${LOCATION}"
echo "[INFO] Container name: ${CONTAINER_NAME}"

# Ensure Azure CLI is authenticated.
if ! az account show >/dev/null 2>&1; then
    echo "[ERROR] Not logged in to Azure. Run 'az login' first."
    exit 1
fi

# Create resource group if it doesn't exist.
if ! az group show --name "${RESOURCE_GROUP}" >/dev/null 2>&1; then
    echo "[INFO] Creating resource group ${RESOURCE_GROUP}..."
    az group create --name "${RESOURCE_GROUP}" --location "${LOCATION}" -o table
fi

# Deploy Neo4j container.
echo "[INFO] Creating Neo4j container..."
az container create \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${CONTAINER_NAME}" \
    --image neo4j:5.20.0-community \
    --os-type Linux \
    --cpu 2 \
    --memory 4 \
    --ports 7474 7687 \
    --dns-name-label "${DNS_LABEL}" \
    --environment-variables NEO4J_AUTH="neo4j/${NEO4J_PASSWORD}" \
    --location "${LOCATION}" \
    -o table

# Get the FQDN.
FQDN=$(az container show \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${CONTAINER_NAME}" \
    --query "ipAddress.fqdn" \
    -o tsv)

echo ""
echo "[OK] Neo4j deployed successfully!"
echo ""
echo "Connection details:"
echo "  Browser URL: http://${FQDN}:7474"
echo "  Bolt URI:    bolt://${FQDN}:7687"
echo "  Username:    neo4j"
echo "  Password:    ${NEO4J_PASSWORD}"
echo ""
echo "Set environment variables before running Vorsyghta RAG:"
echo "  export NEO4J_URI=bolt://${FQDN}:7687"
echo "  export NEO4J_USER=neo4j"
echo "  export NEO4J_PASSWORD=${NEO4J_PASSWORD}"
