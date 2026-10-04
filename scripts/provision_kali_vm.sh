#!/usr/bin/env bash
#
# Provision a SANCTIONED Kali Linux attacker VM on Azure
# =====================================================
# Stands up a real, native amd64 Kali Linux VM from the official Kali
# marketplace image and deploys the canonical Vorsyghta tool server
# (docker/targets/tool_server.py) on port 9090 so the AttackOrchestrator /
# ToolServerClient can drive the on-box offensive arsenal.
#
# Design / safety choices (differs from the legacy scripts/azure_provision.sh):
#   - Official Kali image "kali-linux:kali:<sku>" (native x86_64, full arsenal).
#   - NO hardcoded secrets. SSH via --generate-ssh-keys. The tool server needs
#     no API key. (The legacy script leaked an Azure OpenAI key — do not reuse.)
#   - NSG is LOCKED to the operator's current public IP for BOTH SSH (22) and
#     the tool server (9090). The tool server is unauthenticated by design, so
#     network isolation is the control — never open 9090 to 0.0.0.0/0.
#   - Deploys the *canonical* tool_server.py (base64-injected from the repo at
#     provision time), not a hand-rewritten copy — single source of truth.
#   - Tags the VM com.vorsyghta.role=tool-server / com.vorsyghta.sanctioned=true.
#
# Usage:
#   bash scripts/provision_kali_vm.sh              # create + deploy
#   VORSYGHTA_KALI_SKU=kali-2026-1 bash scripts/provision_kali_vm.sh
#   bash scripts/provision_kali_vm.sh --destroy    # tear the RG down
#
# Env overrides:
#   VORSYGHTA_LOCATION   Azure region        (default: eastus2)
#   VORSYGHTA_VM_SIZE    VM size             (default: Standard_D4s_v3)
#   VORSYGHTA_KALI_SKU   Kali image SKU      (default: kali-2026-2)
#   VORSYGHTA_RG         Resource group      (default: vorsyghta-kali-rg)
#   VORSYGHTA_ADMIN_IP   Allowed inbound CIDR/IP (default: auto-detected /32)
#
set -euo pipefail

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
LOCATION="${VORSYGHTA_LOCATION:-eastus2}"
VM_SIZE="${VORSYGHTA_VM_SIZE:-Standard_D4s_v3}"
KALI_SKU="${VORSYGHTA_KALI_SKU:-kali-2026-2}"
RESOURCE_GROUP="${VORSYGHTA_RG:-vorsyghta-kali-rg}"

VNET_NAME="vorsyghta-kali-vnet"
SUBNET_NAME="vorsyghta-kali-subnet"
NSG_NAME="vorsyghta-kali-nsg"
PUBLIC_IP_NAME="vorsyghta-kali-pip"
NIC_NAME="vorsyghta-kali-nic"
VM_NAME="vorsyghta-kali"
ADMIN_USER="kaliadmin"
TOOL_PORT="9090"

KALI_PUBLISHER="kali-linux"
KALI_OFFER="kali"
IMAGE_URN="${KALI_PUBLISHER}:${KALI_OFFER}:${KALI_SKU}:latest"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TOOL_SERVER_SRC="${REPO_ROOT}/docker/targets/tool_server.py"

ok()   { echo -e "\033[32m[OK]\033[0m   $1"; }
info() { echo -e "\033[36m[INFO]\033[0m $1"; }
warn() { echo -e "\033[33m[WARN]\033[0m $1"; }
err()  { echo -e "\033[31m[ERR]\033[0m  $1"; }

# --------------------------------------------------------------------------- #
# Teardown mode
# --------------------------------------------------------------------------- #
if [ "${1:-}" = "--destroy" ]; then
    warn "Deleting resource group '${RESOURCE_GROUP}' (all Kali VM resources)..."
    az group delete --name "${RESOURCE_GROUP}" --yes --no-wait
    ok "Delete requested (running in background)."
    exit 0
fi

# --------------------------------------------------------------------------- #
# 1. Pre-flight
# --------------------------------------------------------------------------- #
info "Pre-flight checks..."
command -v az >/dev/null 2>&1 || { err "Azure CLI (az) not found. brew install azure-cli"; exit 1; }
az account show >/dev/null 2>&1 || { err "Not logged in to Azure. Run: az login"; exit 1; }
[ -f "${TOOL_SERVER_SRC}" ] || { err "Canonical tool server not found at ${TOOL_SERVER_SRC}"; exit 1; }
SUB_ID="$(az account show --query id -o tsv)"
ok "Azure authenticated (subscription ${SUB_ID})"

# Operator public IP for the NSG allowlist (fail-closed: never fall back to *).
ADMIN_IP="${VORSYGHTA_ADMIN_IP:-}"
if [ -z "${ADMIN_IP}" ]; then
    ADMIN_IP="$(curl -fsS https://api.ipify.org 2>/dev/null || true)"
fi
if [ -z "${ADMIN_IP}" ]; then
    err "Could not determine your public IP for the NSG allowlist."
    err "Set VORSYGHTA_ADMIN_IP=<your.ip.addr.ess> and re-run. Refusing to open 0.0.0.0/0."
    exit 1
fi
case "${ADMIN_IP}" in */*) ADMIN_CIDR="${ADMIN_IP}";; *) ADMIN_CIDR="${ADMIN_IP}/32";; esac
ok "Locking inbound SSH + tool-server to ${ADMIN_CIDR}"

# Base64 of the canonical tool server (macOS/Linux compatible, single line).
TOOL_SERVER_B64="$(base64 < "${TOOL_SERVER_SRC}" | tr -d '\n')"

# --------------------------------------------------------------------------- #
# 2. Accept Kali marketplace image terms
# --------------------------------------------------------------------------- #
info "Accepting marketplace terms for ${IMAGE_URN}..."
az vm image terms accept --urn "${IMAGE_URN}" -o none 2>/dev/null \
    || { err "Could not accept terms for ${IMAGE_URN}. Check the SKU exists: az vm image list --publisher ${KALI_PUBLISHER} --all -o table"; exit 1; }
ok "Marketplace terms accepted"

# --------------------------------------------------------------------------- #
# 3. Resource group
# --------------------------------------------------------------------------- #
info "Creating resource group '${RESOURCE_GROUP}' in '${LOCATION}'..."
if [ -z "$(az group show --name "${RESOURCE_GROUP}" --query name -o tsv 2>/dev/null || echo "")" ]; then
    az group create --name "${RESOURCE_GROUP}" --location "${LOCATION}" -o none
fi
ok "Resource group ready"

# --------------------------------------------------------------------------- #
# 4. Network: VNet + Subnet + NSG (locked to operator IP)
# --------------------------------------------------------------------------- #
info "Creating virtual network..."
if [ -z "$(az network vnet show -g "${RESOURCE_GROUP}" -n "${VNET_NAME}" --query name -o tsv 2>/dev/null || echo "")" ]; then
    az network vnet create -g "${RESOURCE_GROUP}" -n "${VNET_NAME}" \
        --address-prefixes 10.30.0.0/16 \
        --subnet-name "${SUBNET_NAME}" --subnet-prefixes 10.30.1.0/24 -o none
fi
ok "VNet ready"

info "Creating network security group..."
if [ -z "$(az network nsg show -g "${RESOURCE_GROUP}" -n "${NSG_NAME}" --query name -o tsv 2>/dev/null || echo "")" ]; then
    az network nsg create -g "${RESOURCE_GROUP}" -n "${NSG_NAME}" -o none
fi
az network nsg rule create -g "${RESOURCE_GROUP}" --nsg-name "${NSG_NAME}" \
    --name AllowSSHFromOperator --priority 1000 \
    --source-address-prefixes "${ADMIN_CIDR}" --destination-port-ranges 22 \
    --access Allow --protocol Tcp --direction Inbound -o none
az network nsg rule create -g "${RESOURCE_GROUP}" --nsg-name "${NSG_NAME}" \
    --name AllowToolServerFromOperator --priority 1010 \
    --source-address-prefixes "${ADMIN_CIDR}" --destination-port-ranges "${TOOL_PORT}" \
    --access Allow --protocol Tcp --direction Inbound -o none
ok "NSG rules configured (22 + ${TOOL_PORT} from ${ADMIN_CIDR} only)"

info "Creating public IP + NIC..."
if [ -z "$(az network public-ip show -g "${RESOURCE_GROUP}" -n "${PUBLIC_IP_NAME}" --query name -o tsv 2>/dev/null || echo "")" ]; then
    az network public-ip create -g "${RESOURCE_GROUP}" -n "${PUBLIC_IP_NAME}" \
        --allocation-method Static --sku Standard -o none
fi
if [ -z "$(az network nic show -g "${RESOURCE_GROUP}" -n "${NIC_NAME}" --query name -o tsv 2>/dev/null || echo "")" ]; then
    az network nic create -g "${RESOURCE_GROUP}" -n "${NIC_NAME}" \
        --vnet-name "${VNET_NAME}" --subnet "${SUBNET_NAME}" \
        --network-security-group "${NSG_NAME}" --public-ip-address "${PUBLIC_IP_NAME}" -o none
fi
ok "Public IP + NIC ready"

# --------------------------------------------------------------------------- #
# 5. cloud-init: deploy canonical tool server on :9090 + ensure arsenal
# --------------------------------------------------------------------------- #
CLOUD_INIT_FILE="$(mktemp /tmp/vorsyghta-kali-cloudinit.XXXXXX.yml)"
trap 'rm -f "${CLOUD_INIT_FILE}"' EXIT

cat > "${CLOUD_INIT_FILE}" <<CLOUDINIT
#cloud-config
package_update: true
write_files:
  - path: /opt/tool-server/tool_server.py
    encoding: b64
    permissions: '0644'
    content: ${TOOL_SERVER_B64}
  - path: /etc/systemd/system/tool-server.service
    permissions: '0644'
    content: |
      [Unit]
      Description=Vorsyghta Kali Tool Server
      After=network-online.target
      Wants=network-online.target
      [Service]
      Type=simple
      WorkingDirectory=/opt/tool-server
      ExecStart=/opt/tool-server/venv/bin/python -m uvicorn tool_server:app --host 0.0.0.0 --port ${TOOL_PORT} --workers 1
      Restart=always
      RestartSec=5
      [Install]
      WantedBy=multi-user.target
runcmd:
  - export DEBIAN_FRONTEND=noninteractive
  - apt-get update
  - apt-get install -y --no-install-recommends python3-venv python3-pip nmap nikto dirb whatweb gobuster hydra sqlmap ffuf nuclei whois dnsutils iputils-ping traceroute curl wget
  - python3 -m venv /opt/tool-server/venv
  - /opt/tool-server/venv/bin/pip install --no-cache-dir --upgrade pip
  - /opt/tool-server/venv/bin/pip install --no-cache-dir fastapi uvicorn pydantic
  - systemctl daemon-reload
  - systemctl enable --now tool-server
  - 'echo vorsyghta-kali-ready > /opt/tool-server/READY'
CLOUDINIT

ok "cloud-init generated (canonical tool server, port ${TOOL_PORT})"

# --------------------------------------------------------------------------- #
# 6. Create the Kali VM
# --------------------------------------------------------------------------- #
info "Creating Kali VM '${VM_NAME}' from ${IMAGE_URN} (3-5 min)..."
if [ -n "$(az vm show -g "${RESOURCE_GROUP}" -n "${VM_NAME}" --query name -o tsv 2>/dev/null || echo "")" ]; then
    ok "VM already exists, skipping creation"
else
    az vm create \
        --resource-group "${RESOURCE_GROUP}" \
        --name "${VM_NAME}" \
        --image "${IMAGE_URN}" \
        --plan-name "${KALI_SKU}" --plan-product "${KALI_OFFER}" --plan-publisher "${KALI_PUBLISHER}" \
        --size "${VM_SIZE}" \
        --admin-username "${ADMIN_USER}" \
        --generate-ssh-keys \
        --nics "${NIC_NAME}" \
        --os-disk-size-gb 64 \
        --custom-data "${CLOUD_INIT_FILE}" \
        --tags com.vorsyghta.role=tool-server com.vorsyghta.sanctioned=true \
        -o none
    ok "VM created"
fi

PUBLIC_IP="$(az network public-ip show -g "${RESOURCE_GROUP}" -n "${PUBLIC_IP_NAME}" --query ipAddress -o tsv 2>/dev/null || echo "")"

# --------------------------------------------------------------------------- #
# 7. Output
# --------------------------------------------------------------------------- #
echo ""
echo "=================================================================="
ok "Sanctioned Kali VM provisioned"
echo "=================================================================="
echo "  Image:            ${IMAGE_URN} (native amd64)"
echo "  SSH:              ssh ${ADMIN_USER}@${PUBLIC_IP}"
echo "  Tool server:      http://${PUBLIC_IP}:${TOOL_PORT}  (from ${ADMIN_CIDR} only)"
echo ""
echo "  cloud-init installs the arsenal + starts the tool server in the"
echo "  background. Give it 3-8 min, then verify:"
echo "    curl -s http://${PUBLIC_IP}:${TOOL_PORT}/health"
echo "    curl -s http://${PUBLIC_IP}:${TOOL_PORT}/tools"
echo ""
echo "  Wire Vorsyghta to it:"
echo "    export VORSYGHTA_TOOL_SERVER_URL=http://${PUBLIC_IP}:${TOOL_PORT}"
echo ""
echo "  Tear down (stops billing):"
echo "    bash scripts/provision_kali_vm.sh --destroy"
echo "=================================================================="
