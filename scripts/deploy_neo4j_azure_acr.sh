#!/usr/bin/env bash
# Deploy Neo4j on Azure Container Instances using Azure Container Registry
# to avoid Docker Hub rate limits and registry errors.

set -euo pipefail

RESOURCE_GROUP="${RESOURCE_GROUP:-ciicerone-rg}"
LOCATION="${LOCATION:-eastus2}"
ACR_NAME="${ACR_NAME:-ciiceroneacr$(date +%s)}"
CONTAINER_NAME="${CONTAINER_NAME:-ciicerone-neo4j}"
NEO4J_PASSWORD="${NEO4J_PASSWORD:-password}"
DNS_LABEL="${DNS_LABEL:-ciicerone-neo4j-$(date +%s)}"

echo "[INFO] Deploying Neo4j via Azure Container Registry..."
echo "[INFO] Resource group: ${RESOURCE_GROUP}"
echo "[INFO] ACR name: ${ACR_NAME}"
echo "[INFO] Container name: ${CONTAINER_NAME}"

if ! az account show >/dev/null 2>&1; then
    echo "[ERROR] Not logged in to Azure. Run 'az login' first."
    exit 1
fi

if ! az group show --name "${RESOURCE_GROUP}" >/dev/null 2>&1; then
    az group create --name "${RESOURCE_GROUP}" --location "${LOCATION}" -o table
fi

# Create Azure Container Registry.
echo "[INFO] Creating Azure Container Registry..."
az acr create \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${ACR_NAME}" \
    --sku Basic \
    --location "${LOCATION}" \
    --admin-enabled true \
    -o table

# Import Neo4j image into ACR.
echo "[INFO] Importing Neo4j image into ACR..."
az acr import \
    --name "${ACR_NAME}" \
    --source docker.io/library/neo4j:5.20.0-community \
    --image neo4j:5.20.0-community \
    -o table

# Get ACR credentials.
ACR_LOGIN_SERVER=$(az acr show --name "${ACR_NAME}" --query "loginServer" -o tsv)
ACR_USERNAME=$(az acr credential show --name "${ACR_NAME}" --query "username" -o tsv)
ACR_PASSWORD=$(az acr credential show --name "${ACR_NAME}" --query "passwords[0].value" -o tsv)

# Deploy ACI using the cached image.
echo "[INFO] Deploying Neo4j container from ACR..."
az container create \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${CONTAINER_NAME}" \
    --image "${ACR_LOGIN_SERVER}/neo4j:5.20.0-community" \
    --os-type Linux \
    --cpu 2 \
    --memory 4 \
    --ports 7474 7687 \
    --dns-name-label "${DNS_LABEL}" \
    --environment-variables NEO4J_AUTH="neo4j/${NEO4J_PASSWORD}" \
    --registry-login-server "${ACR_LOGIN_SERVER}" \
    --registry-username "${ACR_USERNAME}" \
    --registry-password "${ACR_PASSWORD}" \
    --location "${LOCATION}" \
    -o table

FQDN=$(az container show \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${CONTAINER_NAME}" \
    --query "ipAddress.fqdn" \
    -o tsv)

echo ""
echo "[OK] Neo4j deployed successfully via ACR!"
echo ""
echo "Connection details:"
echo "  Browser URL: http://${FQDN}:7474"
echo "  Bolt URI:    bolt://${FQDN}:7687"
echo "  Username:    neo4j"
echo "  Password:    ${NEO4J_PASSWORD}"
echo ""
echo "Set environment variables:"
echo "  export NEO4J_URI=bolt://${FQDN}:7687"
echo "  export NEO4J_USER=neo4j"
echo "  export NEO4J_PASSWORD=${NEO4J_PASSWORD}"
