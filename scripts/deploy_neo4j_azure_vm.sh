#!/usr/bin/env bash
# Deploy Neo4j on an Azure VM as a fallback when ACI registry fails.

set -euo pipefail

RESOURCE_GROUP="${RESOURCE_GROUP:-vorsyghta-rg}"
LOCATION="${LOCATION:-eastus2}"
VM_NAME="${VM_NAME:-vorsyghta-neo4j-vm}"
NEO4J_PASSWORD="${NEO4J_PASSWORD:-password}"

echo "[INFO] Deploying Neo4j on Azure VM..."
echo "[INFO] Resource group: ${RESOURCE_GROUP}"
echo "[INFO] VM name: ${VM_NAME}"

if ! az account show >/dev/null 2>&1; then
    echo "[ERROR] Not logged in to Azure. Run 'az login' first."
    exit 1
fi

if ! az group show --name "${RESOURCE_GROUP}" >/dev/null 2>&1; then
    az group create --name "${RESOURCE_GROUP}" --location "${LOCATION}" -o table
fi

# Cloud-init script to install Docker and run Neo4j.
CLOUD_INIT_FILE=$(mktemp)
cat > "${CLOUD_INIT_FILE}" <<EOF
#!/bin/bash
set -e
apt-get update
apt-get install -y ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=\$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \$(. /etc/os-release && echo \"\$VERSION_CODENAME\") stable" > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
mkdir -p /neo4j/data /neo4j/logs
docker run -d \
    --name neo4j \
    --restart unless-stopped \
    -p 7474:7474 -p 7687:7687 \
    -v /neo4j/data:/data \
    -v /neo4j/logs:/logs \
    -e NEO4J_AUTH="neo4j/${NEO4J_PASSWORD}" \
    neo4j:5.20.0-community
EOF

# Create VM with cloud-init.
az vm create \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${VM_NAME}" \
    --location "${LOCATION}" \
    --image "Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest" \
    --size Standard_B2s \
    --admin-username azureuser \
    --generate-ssh-keys \
    --custom-data "${CLOUD_INIT_FILE}" \
    --public-ip-sku Standard \
    --nsg-rule SSH \
    -o table

rm -f "${CLOUD_INIT_FILE}"

# Open Neo4j ports.
az vm open-port \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${VM_NAME}" \
    --port 7474 7687 \
    -o table

IP=$(az vm show \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${VM_NAME}" \
    --show-details \
    --query "publicIps" \
    -o tsv)

echo ""
echo "[OK] Neo4j VM deployed."
echo ""
echo "Connection details:"
echo "  Browser URL: http://${IP}:7474"
echo "  Bolt URI:    bolt://${IP}:7687"
echo "  Username:    neo4j"
echo "  Password:    ${NEO4J_PASSWORD}"
echo ""
echo "Set environment variables:"
echo "  export NEO4J_URI=bolt://${IP}:7687"
echo "  export NEO4J_USER=neo4j"
echo "  export NEO4J_PASSWORD=${NEO4J_PASSWORD}"
