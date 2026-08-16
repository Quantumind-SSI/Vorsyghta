#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Vorsyghta Blue Team Azure Infrastructure Deployment Script
#
# Provisions:
#   1. Log Analytics Workspace (for Microsoft Sentinel SIEM)
#   2. Azure Database for PostgreSQL (incident/alert/artifact persistence)
#   3. Storage Account (forensic evidence storage)
#   4. Cosmos DB (document-based blue team data)
#
# All resources are deployed to vorsyghta-rg in eastus2.
# ============================================================

RESOURCE_GROUP="vorsyghta-rg"
LOCATION="eastus2"
PREFIX="vorsyghta"
POSTGRES_ADMIN_USER="vorsyghta_admin"
POSTGRES_ADMIN_PASSWORD="Ci1cer0ne!Secure2024"
COSMOS_DB_NAME="vorsyghta-blue-team"
STORAGE_ACCOUNT_NAME="vorsyghtaforensics"

echo "[INFO] Deploying Blue Team infrastructure to Azure..."
echo "[INFO] Resource Group: ${RESOURCE_GROUP}"
echo "[INFO] Location: ${LOCATION}"
echo ""

# Ensure resource group exists
echo "[INFO] Ensuring resource group exists..."
az group create --name "${RESOURCE_GROUP}" --location "${LOCATION}" --output table

# ============================================================
# Register required resource providers (idempotent)
# ============================================================
echo "[INFO] Ensuring Azure resource providers are registered..."

wait_for_provider() {
    local namespace="$1"
    local state
    state=$(az provider show --namespace "${namespace}" --query "registrationState" -o tsv 2>/dev/null || echo "NotRegistered")
    if [ "${state}" != "Registered" ]; then
        echo "[INFO] Registering ${namespace}..."
        az provider register --namespace "${namespace}" 2>/dev/null || true
        echo -n "[INFO] Waiting for ${namespace} to register..."
        while true; do
            state=$(az provider show --namespace "${namespace}" --query "registrationState" -o tsv 2>/dev/null || echo "Registering")
            if [ "${state}" = "Registered" ]; then
                echo " Done."
                break
            fi
            echo -n "."
            sleep 10
        done
    else
        echo "[OK] ${namespace} already registered."
    fi
}

wait_for_provider "Microsoft.OperationalInsights"
wait_for_provider "Microsoft.DBforPostgreSQL"
wait_for_provider "Microsoft.Storage"
wait_for_provider "Microsoft.DocumentDB"

# ============================================================
# 1. Log Analytics Workspace (for Sentinel SIEM)
# ============================================================
WORKSPACE_NAME="${PREFIX}-logs"

echo ""
echo "[1/4] Log Analytics Workspace: ${WORKSPACE_NAME}..."
if az monitor log-analytics workspace show --resource-group "${RESOURCE_GROUP}" --workspace-name "${WORKSPACE_NAME}" --query "provisioningState" -o tsv 2>/dev/null | grep -qi "succeeded"; then
    echo "[OK] Workspace already exists, skipping creation."
else
    az monitor log-analytics workspace create \
        --resource-group "${RESOURCE_GROUP}" \
        --workspace-name "${WORKSPACE_NAME}" \
        --location "${LOCATION}" \
        --sku PerGB2018 \
        --retention-time 90 \
        --output table
fi

WORKSPACE_ID=$(az monitor log-analytics workspace show \
    --resource-group "${RESOURCE_GROUP}" \
    --workspace-name "${WORKSPACE_NAME}" \
    --query "customerId" -o tsv)

WORKSPACE_KEY=$(az monitor log-analytics workspace get-shared-keys \
    --resource-group "${RESOURCE_GROUP}" \
    --workspace-name "${WORKSPACE_NAME}" \
    --query "primarySharedKey" -o tsv)

echo "[OK] Log Analytics Workspace created"
echo "     Workspace ID: ${WORKSPACE_ID}"
echo "     Workspace Key: ${WORKSPACE_KEY:0:10}..."

# Enable Sentinel (Microsoft.SecurityInsights) on the workspace
echo "[INFO] Enabling Microsoft Sentinel on workspace..."
az sentinel onboarding create \
    --resource-group "${RESOURCE_GROUP}" \
    --workspace-name "${WORKSPACE_NAME}" \
    --output none 2>/dev/null || echo "[WARN] Sentinel onboarding may require manual activation in portal"

# ============================================================
# 2. Azure Database for PostgreSQL (Flexible Server)
# ============================================================
POSTGRES_SERVER_NAME="${PREFIX}-postgres"

echo ""
echo "[2/4] PostgreSQL Flexible Server: ${POSTGRES_SERVER_NAME}..."
POSTGRES_SUCCESS=false
if az postgres flexible-server show --resource-group "${RESOURCE_GROUP}" --name "${POSTGRES_SERVER_NAME}" --query "provisioningState" -o tsv 2>/dev/null | grep -qi "succeeded"; then
    echo "[OK] PostgreSQL server already exists, skipping creation."
    POSTGRES_SUCCESS=true
else
    # Try multiple regions since some are restricted
    for PG_REGION in eastus centralus westus2 westus3 southcentralus; do
        echo "[INFO] Trying PostgreSQL in ${PG_REGION}..."
        if az postgres flexible-server create \
            --resource-group "${RESOURCE_GROUP}" \
            --name "${POSTGRES_SERVER_NAME}" \
            --location "${PG_REGION}" \
            --admin-user "${POSTGRES_ADMIN_USER}" \
            --admin-password "${POSTGRES_ADMIN_PASSWORD}" \
            --sku-name Standard_D2ds_v4 \
            --tier GeneralPurpose \
            --storage-size 64 \
            --version 15 \
            --public-access 0.0.0.0 \
            --yes \
            --output table 2>&1; then
            POSTGRES_SUCCESS=true
            echo "[OK] PostgreSQL created in ${PG_REGION}"
            break
        else
            echo "[WARN] PostgreSQL deployment failed in ${PG_REGION}, trying next region..."
        fi
    done
fi

if [ "${POSTGRES_SUCCESS}" = true ]; then
    POSTGRES_FQDN=$(az postgres flexible-server show \
        --resource-group "${RESOURCE_GROUP}" \
        --name "${POSTGRES_SERVER_NAME}" \
        --query "fullyQualifiedDomainName" -o tsv)

    # Create blue team database
    echo "[INFO] Creating blue_team database..."
    az postgres flexible-server db create \
        --resource-group "${RESOURCE_GROUP}" \
        --server-name "${POSTGRES_SERVER_NAME}" \
        --database-name "blue_team" \
        --output table 2>/dev/null || true

    echo "[OK] PostgreSQL ready"
    echo "     FQDN: ${POSTGRES_FQDN}"
    echo "     Database: blue_team"
    echo "     Admin User: ${POSTGRES_ADMIN_USER}"
else
    echo "[WARN] PostgreSQL could not be deployed in any region."
    echo "[WARN] Falling back to Cosmos DB for all persistence."
    POSTGRES_FQDN=""
fi

# ============================================================
# 3. Storage Account (for forensic evidence)
# ============================================================
# Storage account names must be lowercase, alphanumeric, max 24 chars
STORAGE_NAME="${PREFIX}forensics001"

echo ""
echo "[3/4] Storage Account: ${STORAGE_NAME}..."
if az storage account show --resource-group "${RESOURCE_GROUP}" --name "${STORAGE_NAME}" --query "provisioningState" -o tsv 2>/dev/null | grep -qi "succeeded"; then
    echo "[OK] Storage account already exists, skipping creation."
else
    az storage account create \
        --resource-group "${RESOURCE_GROUP}" \
        --name "${STORAGE_NAME}" \
        --location "${LOCATION}" \
        --sku Standard_LRS \
        --kind StorageV2 \
        --access-tier Hot \
        --output table
fi

# Create containers for forensic evidence
echo "[INFO] Creating blob containers..."
az storage container create \
    --account-name "${STORAGE_NAME}" \
    --name "forensic-evidence" \
    --output none 2>/dev/null || true

az storage container create \
    --account-name "${STORAGE_NAME}" \
    --name "disk-images" \
    --output none 2>/dev/null || true

az storage container create \
    --account-name "${STORAGE_NAME}" \
    --name "memory-dumps" \
    --output none 2>/dev/null || true

az storage container create \
    --account-name "${STORAGE_NAME}" \
    --name "network-captures" \
    --output none 2>/dev/null || true

az storage container create \
    --account-name "${STORAGE_NAME}" \
    --name "log-archives" \
    --output none 2>/dev/null || true

STORAGE_KEY=$(az storage account keys list \
    --resource-group "${RESOURCE_GROUP}" \
    --account-name "${STORAGE_NAME}" \
    --query "[0].value" -o tsv)

echo "[OK] Storage Account created"
echo "     Account: ${STORAGE_NAME}"
echo "     Key: ${STORAGE_KEY:0:10}..."
echo "     Containers: forensic-evidence, disk-images, memory-dumps, network-captures, log-archives"

# ============================================================
# 4. Cosmos DB (for document-based blue team data)
# ============================================================
COSMOS_NAME="${PREFIX}-blueteam-db"

echo ""
echo "[4/4] Cosmos DB account: ${COSMOS_NAME}..."
if az cosmosdb show --resource-group "${RESOURCE_GROUP}" --name "${COSMOS_NAME}" --query "provisioningState" -o tsv 2>/dev/null | grep -qi "succeeded"; then
    echo "[OK] Cosmos DB already exists, skipping creation."
else
    az cosmosdb create \
        --resource-group "${RESOURCE_GROUP}" \
        --name "${COSMOS_NAME}" \
        --locations regionName="${LOCATION}" failoverPriority=0 isZoneRedundant=False \
        --kind GlobalDocumentDB \
        --default-consistency-level Session \
        --output table
fi

# Create database
echo "[INFO] Creating Cosmos DB database: blue_team..."
az cosmosdb sql database create \
    --resource-group "${RESOURCE_GROUP}" \
    --account-name "${COSMOS_NAME}" \
    --name "blue_team" \
    --throughput 400 \
    --output table

# Create containers
echo "[INFO] Creating Cosmos DB containers..."
for container in incidents alerts forensic-artifacts hunt-results triage-results; do
    az cosmosdb sql container create \
        --resource-group "${RESOURCE_GROUP}" \
        --account-name "${COSMOS_NAME}" \
        --database-name "blue_team" \
        --name "${container}" \
        --partition-key-path "/id" \
        --output none 2>/dev/null || true
done

COSMOS_ENDPOINT=$(az cosmosdb show \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${COSMOS_NAME}" \
    --query "documentEndpoint" -o tsv)

COSMOS_KEY=$(az cosmosdb keys list \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${COSMOS_NAME}" \
    --query "primaryMasterKey" -o tsv)

echo "[OK] Cosmos DB created"
echo "     Endpoint: ${COSMOS_ENDPOINT}"
echo "     Key: ${COSMOS_KEY:0:10}..."
echo "     Database: blue_team"
echo "     Containers: incidents, alerts, forensic-artifacts, hunt-results, triage-results"

# ============================================================
# Summary & .env output
# ============================================================
echo ""
echo "=============================================================="
echo "[OK] Blue Team infrastructure deployed successfully!"
echo "=============================================================="
echo ""
echo "Add the following to your .env file:"
echo ""
echo "# === Blue Team Azure Infrastructure ==="
echo "# Log Analytics / Sentinel"
echo "SIEM_PLATFORM=sentinel"
echo "SIEM_URL=https://api.loganalytics.io"
echo "SIEM_API_TOKEN=\${AZURE_BEARER_TOKEN}"
echo "SIEM_INDEX=${WORKSPACE_ID}"
echo "AZURE_LOG_ANALYTICS_WORKSPACE_ID=${WORKSPACE_ID}"
echo "AZURE_LOG_ANALYTICS_KEY=${WORKSPACE_KEY}"
echo ""
echo "# PostgreSQL"
if [ -n "${POSTGRES_FQDN:-}" ]; then
    echo "POSTGRES_HOST=${POSTGRES_FQDN}"
    echo "POSTGRES_PORT=5432"
    echo "POSTGRES_DB=blue_team"
    echo "POSTGRES_USER=${POSTGRES_ADMIN_USER}"
    echo "POSTGRES_PASSWORD=${POSTGRES_ADMIN_PASSWORD}"
else
    echo "# PostgreSQL not deployed — using Cosmos DB for persistence"
fi
echo ""
echo "# Storage Account (forensic evidence)"
echo "AZURE_STORAGE_ACCOUNT=${STORAGE_NAME}"
echo "AZURE_STORAGE_KEY=${STORAGE_KEY}"
echo ""
echo "# Cosmos DB"
echo "AZURE_COSMOS_ENDPOINT=${COSMOS_ENDPOINT}"
echo "AZURE_COSMOS_KEY=${COSMOS_KEY}"
echo "AZURE_COSMOS_DATABASE=blue_team"
echo ""
echo "=============================================================="
