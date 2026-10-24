#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "[*] Initializing Terraform..."
terraform init

echo "[*] Planning..."
terraform plan -out=tfplan

echo "[*] Applying..."
terraform apply tfplan

echo "[*] Outputs:"
terraform output

echo "[*] Setting Key Vault secrets..."
KV_NAME="vorsyghta-kv"
RG_NAME="vorsyghta-rg"

# Get OpenAI keys from Azure
OPENAI_KEY=$(az cognitiveservices account keys list --name vorsyghta-openai --resource-group $RG_NAME --query key1 -o tsv)

az keyvault secret set --vault-name $KV_NAME --name azure-openai-api-key --value "$OPENAI_KEY"
az keyvault secret set --vault-name $KV_NAME --name azure-openai-endpoint --value "https://vorsyghta-openai.openai.azure.com/"
az keyvault secret set --vault-name $KV_NAME --name azure-openai-deployment --value "gpt-4o"

echo "[OK] Azure resources provisioned and secrets set in Key Vault"
