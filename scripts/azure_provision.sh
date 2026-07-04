#!/usr/bin/env bash
#
# Azure Provisioning Script for Ciicerone Sandbox
#
# Provisions an Ubuntu VM with Docker, deploys:
#   - Phantom Kali sandbox tool-server (port 8080)
#   - DVWA vulnerable target (port 80)
#
# Usage: bash azure_provision.sh
# Environment variables:
#   CIICERONE_LOCATION   - Azure region (default: eastus2)
#   CIICERONE_VM_SIZE    - VM size (default: Standard_D4s_v3)
#

set -euo pipefail

LOCATION="${CIICERONE_LOCATION:-eastus2}"
VM_SIZE="${CIICERONE_VM_SIZE:-Standard_D8s_v3}"  # 8 vCPUs, 32GB RAM for Ciicerone Attack + targets
RESOURCE_GROUP="ciicerone-rg"
VNET_NAME="ciicerone-vnet"
SUBNET_NAME="ciicerone-subnet"
NSG_NAME="ciicerone-nsg"
PUBLIC_IP_NAME="ciicerone-pip"
NIC_NAME="ciicerone-nic"
VM_NAME="ciicerone-sandbox"
ADMIN_USER="ciicerone"

ok()   { echo -e "\033[32m[OK]\033[0m   $1"; }
info() { echo -e "\033[36m[INFO]\033[0m $1"; }
err()  { echo -e "\033[31m[ERR]\033[0m  $1"; }

# ---------------------------------------------------------------------------
# 1. Pre-flight checks
# ---------------------------------------------------------------------------
info "Checking Azure CLI..."
if ! command -v az &>/dev/null; then
    err "Azure CLI (az) not found. Install: brew install azure-cli"
    exit 1
fi

if ! az account show &>/dev/null; then
    err "Not logged in to Azure. Run: az login"
    exit 1
fi
ok "Azure CLI authenticated"

# ---------------------------------------------------------------------------
# 2. Create resource group
# ---------------------------------------------------------------------------
info "Creating resource group '$RESOURCE_GROUP' in '$LOCATION'..."
RG_LOCATION=$(az group show --name "$RESOURCE_GROUP" --query location -o tsv 2>/dev/null || echo "")
if [ -z "$RG_LOCATION" ]; then
    az group create --name "$RESOURCE_GROUP" --location "$LOCATION" -o table
    ok "Resource group created"
else
    ok "Resource group already exists in $RG_LOCATION"
fi

# ---------------------------------------------------------------------------
# 3. Network: VNet, Subnet, NSG
# ---------------------------------------------------------------------------
info "Creating virtual network..."
VNET_EXISTS=$(az network vnet show --resource-group "$RESOURCE_GROUP" --name "$VNET_NAME" --query name -o tsv 2>/dev/null || echo "")
if [ -z "$VNET_EXISTS" ]; then
    az network vnet create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$VNET_NAME" \
        --address-prefixes 10.0.0.0/16 \
        --subnet-name "$SUBNET_NAME" \
        --subnet-prefixes 10.0.100.0/24 \
        -o table
    if [ $? -ne 0 ]; then
        err "Failed to create virtual network"
        exit 1
    fi
fi
ok "Virtual network ready"

info "Creating network security group..."
NSG_EXISTS=$(az network nsg show --resource-group "$RESOURCE_GROUP" --name "$NSG_NAME" --query name -o tsv 2>/dev/null || echo "")
if [ -z "$NSG_EXISTS" ]; then
    az network nsg create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$NSG_NAME" \
        -o table
    if [ $? -ne 0 ]; then
        err "Failed to create NSG"
        exit 1
    fi
fi
ok "NSG ready"

info "Adding NSG rules (SSH + tool-server)..."
# SSH rule
az network nsg rule create \
    --resource-group "$RESOURCE_GROUP" \
    --nsg-name "$NSG_NAME" \
    --name "AllowSSH" \
    --priority 1000 \
    --source-address-prefixes "*" \
    --destination-port-ranges 22 \
    --access Allow \
    --protocol Tcp \
    --direction Inbound \
    -o table 2>/dev/null || true

# Tool-server rule (port 8080)
az network nsg rule create \
    --resource-group "$RESOURCE_GROUP" \
    --nsg-name "$NSG_NAME" \
    --name "AllowToolServer" \
    --priority 1010 \
    --source-address-prefixes "*" \
    --destination-port-ranges 8080 \
    --access Allow \
    --protocol Tcp \
    --direction Inbound \
    -o table 2>/dev/null || true

# Ciicerone Attack Web UI (port 3000)
az network nsg rule create \
    --resource-group "$RESOURCE_GROUP" \
    --nsg-name "$NSG_NAME" \
    --name "AllowAttackUI" \
    --priority 1020 \
    --source-address-prefixes "*" \
    --destination-port-ranges 3000 \
    --access Allow \
    --protocol Tcp \
    --direction Inbound \
    -o table 2>/dev/null || true

# Ciicerone Attack REST API (port 8080 - already allowed above, Ciicerone Attack uses same port)
# Ciicerone Attack GraphQL API (port 8081)
az network nsg rule create \
    --resource-group "$RESOURCE_GROUP" \
    --nsg-name "$NSG_NAME" \
    --name "AllowAttackGraphQL" \
    --priority 1030 \
    --source-address-prefixes "*" \
    --destination-port-ranges 8081 \
    --access Allow \
    --protocol Tcp \
    --direction Inbound \
    -o table 2>/dev/null || true
ok "NSG rules configured (SSH, Tool Server, Ciicerone Attack UI, Ciicerone Attack GraphQL)"

# ---------------------------------------------------------------------------
# 4. Public IP + NIC
# ---------------------------------------------------------------------------
info "Creating public IP..."
PIP_EXISTS=$(az network public-ip show --resource-group "$RESOURCE_GROUP" --name "$PUBLIC_IP_NAME" --query name -o tsv 2>/dev/null || echo "")
if [ -z "$PIP_EXISTS" ]; then
    az network public-ip create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$PUBLIC_IP_NAME" \
        --allocation-method Static \
        --sku Standard \
        -o table
    if [ $? -ne 0 ]; then
        err "Failed to create public IP"
        exit 1
    fi
fi
ok "Public IP ready"

info "Creating network interface..."
NIC_EXISTS=$(az network nic show --resource-group "$RESOURCE_GROUP" --name "$NIC_NAME" --query name -o tsv 2>/dev/null || echo "")
if [ -z "$NIC_EXISTS" ]; then
    az network nic create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$NIC_NAME" \
        --vnet-name "$VNET_NAME" \
        --subnet "$SUBNET_NAME" \
        --network-security-group "$NSG_NAME" \
        --public-ip-address "$PUBLIC_IP_NAME" \
        -o table
    if [ $? -ne 0 ]; then
        err "Failed to create network interface"
        exit 1
    fi
fi
ok "NIC ready"

# ---------------------------------------------------------------------------
# 5. Create VM with cloud-init
# ---------------------------------------------------------------------------
CLOUD_INIT=$(cat <<'CLOUDINIT'
#cloud-config
package_upgrade: true
packages:
  - docker.io
  - docker-compose
  - python3-pip
  - git
runcmd:
  - systemctl enable docker
  - systemctl start docker
  - usermod -aG docker ciicerone
  - pip3 install fastapi uvicorn pydantic
  - |
    cat > /opt/tool_server.py << 'PYEOF'
    from fastapi import FastAPI
    from pydantic import BaseModel
    import subprocess, shlex

    app = FastAPI(title="Ciicerone Tool Server")

    ALLOWED = ["nmap", "whois", "dig", "curl", "wget", "ping", "traceroute",
               "nikto", "dirb", "gobuster", "hydra", "sqlmap", "masscan",
               "whatweb", "wpscan", "theharvester", "amass"]

    class CmdReq(BaseModel):
        command: str
        timeout: int = 300

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/tools")
    async def tools():
        return {"tools": ALLOWED}

    @app.post("/execute")
    async def execute(req: CmdReq):
        parts = shlex.split(req.command)
        if not parts or parts[0] not in ALLOWED:
            return {"error": f"Tool not allowed. Available: {ALLOWED}"}
        try:
            result = subprocess.run(
                parts, capture_output=True, text=True, timeout=req.timeout
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"error": "Command timed out"}
        except Exception as e:
            return {"error": str(e)}
    PYEOF
  - |
    cat > /etc/systemd/system/tool-server.service << 'SVCEOF'
    [Unit]
    Description=Ciicerone Tool Server
    After=network.target
    [Service]
    Type=simple
    ExecStart=/usr/bin/python3 -m uvicorn /opt/tool_server:app --host 0.0.0.0 --port 8080
    Restart=always
    RestartSec=5
    [Install]
    WantedBy=multi-user.target
    SVCEOF
  - systemctl daemon-reload
  - systemctl enable tool-server
  - systemctl start tool-server
  - chmod 666 /var/run/docker.sock
  - docker run -d --name dvwa -p 80:80 vulnerables/web-dvwa
  - |
    # Deploy Ciicerone Attack stack
    mkdir -p /opt/attack
    cat > /opt/attack/.env << 'ENVEOF'
    AZURE_OPENAI_API_KEY=9WZrpwTXNYg8pP5Ly30SbfqRpRDYyLzrzlO6pjNlV092LeGgD9ARJQQJ99CFACHYHv6XJ3w3AAABACOGddkc
    AZURE_OPENAI_ENDPOINT=https://ciicerone-openai.openai.azure.com/
    AZURE_OPENAI_DEPLOYMENT=gpt-4o
    ENVEOF
    cat > /opt/attack/docker-compose.yml << 'DCEOF'
    services:
      attack:
        image: ciiceroneacr1782424350.azurecr.io/ciicerone-attack:latest
        container_name: ciicerone-attack
        ports:
          - "8080:8080"
        env_file:
          - .env
        environment:
          - OPENAI_API_KEY=${AZURE_OPENAI_API_KEY}
          - OPENAI_BASE_URL=${AZURE_OPENAI_ENDPOINT}
          - OPENAI_MODEL=${AZURE_OPENAI_DEPLOYMENT:-gpt-4o}
          - DATABASE_URL=postgres://attack:attack@attack-db:5432/attack?sslmode=disable
          - REDIS_URL=redis://attack-redis:6379
          - SECRET_KEY=ciicerone-attack-secret-2024
          - API_TOKEN=ciicerone-attack-token
          - DOCKER_HOST=unix:///var/run/docker.sock
        volumes:
          - /var/run/docker.sock:/var/run/docker.sock
          - attack-data:/app/data
        depends_on:
          - attack-db
          - attack-redis
        restart: unless-stopped
        networks:
          - attack-net
      attack-db:
        image: vxcontrol/pgvector:latest
        container_name: ciicerone-attack-db
        environment:
          - POSTGRES_DB=attack
          - POSTGRES_USER=attack
          - POSTGRES_PASSWORD=attack
        volumes:
          - attack-db-data:/var/lib/postgresql/data
        healthcheck:
          test: ["CMD-SHELL", "pg_isready -U attack"]
          interval: 10s
          timeout: 5s
          retries: 5
        restart: unless-stopped
        networks:
          - attack-net
      attack-redis:
        image: redis:7-alpine
        container_name: ciicerone-attack-redis
        volumes:
          - attack-redis-data:/data
        restart: unless-stopped
        networks:
          - attack-net
    volumes:
      attack-data:
      attack-db-data:
      attack-redis-data:
    networks:
      attack-net:
        driver: bridge
    DCEOF
  - az acr login --name ciiceroneacr1782424350
  - docker-compose -f /opt/attack/docker-compose.yml up -d
CLOUDINIT
)

info "Creating VM '$VM_NAME' (this takes 3-5 minutes)..."
VM_EXISTS=$(az vm show --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --query name -o tsv 2>/dev/null || echo "")
if [ -n "$VM_EXISTS" ]; then
    ok "VM already exists, skipping creation"
else
    az vm create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$VM_NAME" \
        --image Ubuntu2404 \
        --size "$VM_SIZE" \
        --admin-username "$ADMIN_USER" \
        --generate-ssh-keys \
        --nics "$NIC_NAME" \
        --custom-data "$CLOUD_INIT" \
        --assign-identity \
        -o table
    if [ $? -ne 0 ]; then
        err "Failed to create VM"
        exit 1
    fi
    ok "VM created"
fi

# ---------------------------------------------------------------------------
# 6a. Grant VM managed identity AcrPull on ACR
# ---------------------------------------------------------------------------
info "Assigning AcrPull role to VM for ACR access..."
VM_PRINCIPAL=$(az vm show --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --query identity.principalId -o tsv 2>/dev/null || echo "")
ACR_ID=$(az acr show --name ciiceroneacr1782424350 --query id -o tsv 2>/dev/null || echo "")
if [ -n "$VM_PRINCIPAL" ] && [ -n "$ACR_ID" ]; then
    az role assignment create --assignee "$VM_PRINCIPAL" --role AcrPull --scope "$ACR_ID" -o table 2>/dev/null || true
    ok "AcrPull role assigned to VM"
else
    info "Skipping AcrPull assignment - VM may not have managed identity or ACR not found"
fi

# ---------------------------------------------------------------------------
# 6. Get public IP and display connection info
# ---------------------------------------------------------------------------
PUBLIC_IP=$(az network public-ip show \
    --resource-group "$RESOURCE_GROUP" \
    --name "$PUBLIC_IP_NAME" \
    --query ipAddress -o tsv 2>/dev/null || echo "")

echo ""
echo "=============================================="
ok "Azure sandbox provisioned successfully!"
echo "=============================================="
echo ""
echo "  SSH:           ssh ${ADMIN_USER}@${PUBLIC_IP}"
echo "  Tool Server:   http://${PUBLIC_IP}:8080"
echo "  DVWA Target:   http://${PUBLIC_IP}"
echo "  Ciicerone Attack UI:    http://${PUBLIC_IP}:3000"
echo "  Ciicerone Attack API:   http://${PUBLIC_IP}:8080"
echo "  Ciicerone Attack GQL:   http://${PUBLIC_IP}:8081"
echo ""
echo "  Set in .env:"
echo "    CIICERONE_TOOL_SERVER_URL=http://${PUBLIC_IP}:8080"
echo "    CIICERONE_ATTACK_API_URL=http://${PUBLIC_IP}:8080"
echo "    CIICERONE_ATTACK_GRAPHQL_URL=http://${PUBLIC_IP}:8081"
echo "    CIICERONE_ATTACK_API_TOKEN=ciicerone-attack-token"
echo ""
echo "  Cleanup:"
echo "    az group delete --name ${RESOURCE_GROUP} --yes --no-wait"
echo ""
