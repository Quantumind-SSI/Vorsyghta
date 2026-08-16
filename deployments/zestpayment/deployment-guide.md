# ZestPayment Vorsyghta Deployment Guide

## Overview

This guide covers deploying Vorsyghta on Huawei Cloud CCE for ZestPayment's
cloud security threat simulation platform.

## Prerequisites

- Huawei Cloud account with CCE (Cloud Container Engine) access
- NVIDIA GPU-enabled ECS instance (T4 minimum, A10/A100 preferred)
- Huawei SWR (Software Repository for Container) access
- Domain: `vorsyghta.com` with DNS control
- Microsoft 365 tenant (for email delivery and directory integration)
- PCI-DSS compliance documentation

## Architecture

```
                    ┌─────────────────────────────┐
                    │     Huawei ELB (443/8000)    │
                    │     SSL Termination + WAF    │
                    └──────────┬──────────────────┘
                               │
                    ┌──────────▼──────────────────┐
                    │   CCE Cluster (2+ nodes)     │
                    │  ┌──────────────────────┐   │
                    │  │  vorsyghta-api (x2)  │   │
                    │  │  FastAPI + Workers   │   │
                    │  └──────────┬───────────┘   │
                    │             │                │
                    │  ┌──────────▼───────────┐   │
                    │  │  ollama (GPU node)   │   │
                    │  │  LLM: llama3:70b     │   │
                    │  └──────────────────────┘   │
                    └──────────────────────────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
     ┌────────▼──────┐ ┌──────▼───────┐ ┌──────▼───────┐
     │  EVS (100GB)  │ │ SFS (50GB)   │ │  OBS (Logs)  │
     │  App Data     │ │  Datasets    │ │  90-day ret  │
     └───────────────┘ └──────────────┘ └──────────────┘
```

## Step 1: Create CCE Cluster

```bash
# Create CCE cluster via Huawei Cloud Console or CLI
# Minimum: 2 nodes, 4 vCPU, 8GB RAM each
# Ubuntu 22.04 or equivalent

# Add GPU node for Ollama
# Instance type: GPU-enabled (e.g., p2v.2.large)
# GPU: NVIDIA T4 minimum (24GB VRAM)
```

## Step 2: Configure Container Registry

```bash
# Login to Huawei SWR
docker login -u <username> -p <password> swr.ng-west-1.myhuaweicloud.com

# Tag and push Vorsyghta image
docker tag vorsyghta:latest swr.ng-west-1.myhuaweicloud.com/vorsyghta/vorsyghta:latest
docker push swr.ng-west-1.myhuaweicloud.com/vorsyghta/vorsyghta:latest

# Create image pull secret in cluster
kubectl create secret docker-registry swr-credentials \
  --namespace vorsyghta \
  --docker-server=swr.ng-west-1.myhuaweicloud.com \
  --docker-username=<username> \
  --docker-password=<password>
```

## Step 3: Configure Secrets

```bash
# Create Kubernetes secrets (or use Huawei DEW for production)
kubectl create secret generic vorsyghta-secrets \
  --namespace vorsyghta \
  --from-literal=JWT_SECRET_KEY=$(openssl rand -hex 32) \
  --from-literal=M365_TENANT_ID=<your-tenant-id> \
  --from-literal=M365_CLIENT_ID=<your-client-id> \
  --from-literal=M365_CLIENT_SECRET=<your-client-secret> \
  --from-literal=DB_HOST=<db-host> \
  --from-literal=DB_USER=<db-user> \
  --from-literal=DB_PASSWORD=<db-password>
```

## Step 4: Deploy to Cluster

```bash
# Create namespace
kubectl apply -f deployments/zestpayment/kubernetes-manifests.yaml

# Verify deployment
kubectl get pods -n vorsyghta
kubectl get svc -n vorsyghta
kubectl get ingress -n vorsyghta

# Check API health
kubectl port-forward svc/vorsyghta-api 8000:443 -n vorsyghta
curl -k https://localhost:8000/health
```

## Step 5: Pull LLM Model on Ollama

```bash
# Exec into Ollama pod and pull model
kubectl exec -it deployment/ollama -n vorsyghta -- ollama pull llama3:70b

# Verify model is loaded
kubectl exec -it deployment/ollama -n vorsyghta -- ollama list
```

## Step 6: Configure DNS & SSL

```bash
# Create A record pointing to ELB external IP
# vorsyghta.com -> <ELB_EXTERNAL_IP>

# Verify DNS resolution
nslookup vorsyghta.com

# SSL certificate should be configured on ELB
# Use Huawei Cloud SCM or company PKI
```

## Step 7: Configure Microsoft 365 Integration

1. Register an app in Entra ID (Azure AD)
2. Grant permissions: `Mail.Send`, `User.Read.All`
3. Create client secret
4. Update Kubernetes secrets with tenant ID, client ID, client secret

## Step 8: Verify Deployment

```bash
# Run a test simulation
vorsyghta simulate --scenario templates/zestpayment/payment_fraud.yaml

# Check quantum threat scan
vorsyghta quantum scan --target vorsyghta.com

# Check API endpoints
curl -k https://vorsyghta.com/api/v1/quantum/inventory
```

## Monitoring

- **Prometheus metrics**: `https://vorsyghta.com/metrics`
- **Logs**: Huawei LTS (Log Tank Service)
- **Health**: `https://vorsyghta.com/health`

## Compliance Notes

- All payment data is redacted (PAN, PII)
- Audit logs retained for 90 days minimum
- Data residency: Nigeria (ng-west-1 region)
- PCI-DSS mode enforces strict safety controls
- No real payment processing during simulations
