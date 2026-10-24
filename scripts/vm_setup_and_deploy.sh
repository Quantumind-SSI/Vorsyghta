#!/usr/bin/env bash
set -euo pipefail

echo "[*] Updating packages..."
sudo apt update

echo "[*] Installing Docker CE and Compose..."
sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin git

echo "[*] Adding user to docker group..."
sudo usermod -aG docker $USER

echo "[*] Verifying Docker..."
docker --version
docker compose version

echo "[*] Cloning Vorsyghta repo..."
cd ${HOME}
if [ -d "Vorsyghta" ]; then
  rm -rf Vorsyghta
fi
git clone https://github.com/QuantmindSSI/Vorsyghta.git

echo "[*] Deploying Vorsyghta..."
cd Vorsyghta
docker compose up -d

echo "[OK] Vorsyghta deployed. Check status with: docker compose ps"
