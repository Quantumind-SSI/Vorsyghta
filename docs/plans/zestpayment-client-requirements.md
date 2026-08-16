# Vorsyghta Cloud Security Threat Simulation Platform
## ZestPayment Engagement — Client Requirements Document

**Prepared for:** ZestPayment  
**Prepared by:** Vorsyghta Security Team  
**Date:** June 2026  
**Contact:** admin@vorsyghta.com  
**Platform URL:** https://vorsyghta.com  

---

## 1. Overview

This document outlines the requirements from ZestPayment to successfully deploy and operate the Vorsyghta AI-powered threat simulation platform. Vorsyghta will simulate realistic cyber attacks against ZestPayment's payment infrastructure — including payment fraud, API abuse, cloud misconfiguration, and data breach scenarios — to validate security controls, test incident response, and ensure PCI-DSS and NDPR compliance.

The engagement spans **8–12 weeks** across three phases: Discovery, Data Collection & AI Configuration, and Integration & Testing.

---

## 2. Personnel Requirements

ZestPayment must assign the following personnel to support the engagement:

### 2.1 Project Sponsor

| Item | Detail |
|------|--------|
| **Role** | CISO or Head of Information Security |
| **Time Commitment** | 4–6 hours total (across engagement) |
| **Responsibilities** | Executive sponsorship, resource approval, risk acceptance, cross-functional coordination |
| **Key Deliverable** | Signed project charter and risk acceptance form |

### 2.2 Technical Project Manager

| Item | Detail |
|------|--------|
| **Role** | Technical Project Manager |
| **Time Commitment** | 20–30 hours total (across engagement) |
| **Responsibilities** | Project coordination, technical team management, timeline and milestone tracking, liaison between ZestPayment and Vorsyghta teams |
| **Key Deliverable** | Weekly status reports, milestone sign-offs |

### 2.3 Cloud Infrastructure Engineer

| Item | Detail |
|------|--------|
| **Role** | Cloud Infrastructure Engineer |
| **Time Commitment** | 15–20 hours total |
| **Responsibilities** | Provide infrastructure access, assist with CCE configuration, network setup, security group configuration, GPU instance provisioning |
| **Key Deliverable** | Infrastructure access credentials, network topology documentation |

### 2.4 Security & Compliance Officer

| Item | Detail |
|------|--------|
| **Role** | Security/Compliance Officer |
| **Time Commitment** | 10–15 hours total |
| **Responsibilities** | Provide PCI-DSS scope documentation, NDPR compliance requirements, audit reports, incident response playbooks |
| **Key Deliverable** | Compliance documentation package, IR playbook review |

### 2.5 Payment Platform Engineer

| Item | Detail |
|------|--------|
| **Role** | Payment Platform Engineer |
| **Time Commitment** | 10–15 hours total |
| **Responsibilities** | Document payment workflows, provide test API access, configure test environment, assist with webhook configuration |
| **Key Deliverable** | Test environment access, API documentation, payment workflow diagrams |

### 2.6 Developer/Ecosystem Lead

| Item | Detail |
|------|--------|
| **Role** | Developer/Ecosystem Lead |
| **Time Commitment** | 5–10 hours total |
| **Responsibilities** | Provide API documentation, SDK details, webhook configuration, rate limiting policies |
| **Key Deliverable** | API specification, SDK inventory, webhook endpoint list |

---

## 3. Infrastructure Requirements

ZestPayment must provision or provide access to the following Huawei Cloud resources:

### 3.1 Compute Resources

| Resource | Specification | Purpose |
|----------|--------------|---------|
| **CCE Cluster** | Minimum 2 nodes, 4 vCPU / 8GB RAM each, Ubuntu 22.04 | Vorsyghta API and worker containers |
| **GPU Instance** | NVIDIA T4 minimum (A10/A100 preferred), 24GB VRAM, 100GB SSD | Local LLM hosting via Ollama |

### 3.2 Container Registry

| Requirement | Detail |
|-------------|--------|
| **Preferred** | Huawei SWR (Software Repository for Container) |
| **Alternative** | Docker Hub with IP whitelisting |
| **Access Needed** | Push/pull permissions for Docker images |
| **Credentials** | Authentication credentials for Vorsyghta deployment |

### 3.3 Storage

| Storage Type | Capacity | Purpose |
|-------------|----------|---------|
| **Persistent Volume (EVS)** | 100GB minimum | Application data, generated content, logs |
| **Dataset Storage (SFS Turbo)** | 50GB minimum | Payment fraud patterns, compliance frameworks, security standards |
| **Object Storage (OBS)** | As needed | Long-term log retention (90-day minimum), audit compliance |

### 3.4 Networking

| Requirement | Detail |
|-------------|--------|
| **VPC** | Dedicated VPC for Vorsyghta cluster |
| **Subnets** | Subnet allocation for containers, network segmentation for payment processing |
| **Security Groups** | Inbound: 8000 (API), 443 (HTTPS), 22 (SSH restricted). Outbound: LLM endpoint, payment processor APIs, banking network, update repositories, monitoring endpoints |
| **Load Balancer** | Huawei ELB with listener for 443/8000, health checks, SSL termination |
| **WAF** | WAF integration for payment security (recommended) |

### 3.5 Secrets Management

| Requirement | Detail |
|-------------|--------|
| **Preferred** | Huawei DEW (Data Encryption Workshop) / KMS |
| **Alternative** | Native Kubernetes secrets (basic deployment only) |
| **Secrets to Store** | LLM API keys, payment processor API keys, database credentials, integration tokens, email service credentials |

---

## 4. LLM Access Configuration

ZestPayment must choose **one** of the following four paths for LLM access:

### Path A: Huawei ModelArts MaaS / Pangu LLM (Recommended for CBN Entities)

| Requirement | Detail |
|-------------|--------|
| **API Endpoint URL** | Huawei ModelArts inference endpoint |
| **API Key** | Authentication key for ModelArts service |
| **Network** | Endpoint whitelisting in configuration |
| **Benefit** | Huawei-first posture, data sovereignty |
| **Complexity** | Low |

### Path B: Internal AI Gateway (LiteLLM, Portkey, vLLM)

| Requirement | Detail |
|-------------|--------|
| **Gateway URL** | Internal AI gateway endpoint |
| **Authentication Token** | Gateway access token |
| **Network** | Outbound network rules to gateway |
| **Benefit** | Internal control and data privacy |
| **Complexity** | Medium |

### Path C: Self-Hosted Ollama (Default — No External Dependencies)

| Requirement | Detail |
|-------------|--------|
| **GPU ECS Instance** | As specified in Section 3.1 |
| **Network** | No external dependencies required |
| **Model Management** | Local model management via Ollama |
| **Benefit** | Complete offline capability and data sovereignty |
| **Complexity** | High (Vorsyghta team handles setup) |

### Path D: External LLM APIs (Least Likely for CBN Entities)

| Requirement | Detail |
|-------------|--------|
| **API Keys** | OpenAI, Anthropic, or OpenRouter credentials |
| **Network** | Egress allow-list through NAT gateway, domain whitelisting |
| **Benefit** | Wide model selection |
| **Complexity** | Low |
| **Note** | Least likely for CBN-regulated entities due to data sovereignty concerns |

---

## 5. Data & Documentation Requirements

ZestPayment must provide the following documentation during Phase 1 (Discovery):

### 5.1 Cloud Architecture

- [ ] Primary cloud provider and regions used
- [ ] Multi-region deployment strategy
- [ ] Cloud account hierarchy and organization structure
- [ ] Compliance certifications (PCI-DSS, ISO 27001)
- [ ] Disaster recovery and backup configurations
- [ ] Network security group configurations
- [ ] Container orchestration setup (CCE configuration)

### 5.2 Payment Processing Security

- [ ] Payment gateway architecture diagram
- [ ] Transaction processing workflows
- [ ] Settlement and reconciliation system documentation
- [ ] Fraud detection and prevention system details
- [ ] Customer authentication methods inventory
- [ ] PCI-DSS compliance level and scope
- [ ] Tokenization and encryption methods
- [ ] 3D Secure implementation details
- [ ] Fraud detection algorithms and thresholds
- [ ] Transaction monitoring rules
- [ ] Key management system details

### 5.3 Authentication Systems

- [ ] Multi-factor authentication configurations
- [ ] Biometric authentication methods
- [ ] OAuth and token-based authentication setup
- [ ] Session management policies
- [ ] Password security requirements

### 5.4 API Ecosystem

- [ ] REST API endpoints and documentation
- [ ] SDK implementations and versions
- [ ] Webhook configurations and endpoints
- [ ] Rate limiting and throttling policies
- [ ] API authentication and authorization mechanisms

### 5.5 Data Protection

- [ ] End-to-end encryption implementations
- [ ] Data masking and tokenization policies
- [ ] Audit logging configurations
- [ ] Data retention and deletion policies
- [ ] Customer data flows and storage locations

### 5.6 Regulatory Compliance

- [ ] PCI-DSS compliance level and scope documentation
- [ ] GDPR/NDPR data protection measures
- [ ] AML/KYC requirements
- [ ] Central Bank of Nigeria (CBN) regulations
- [ ] Cross-border payment regulations
- [ ] Data storage locations and residency requirements
- [ ] Cross-border data transfer policies
- [ ] Data sovereignty considerations
- [ ] Security audit schedules
- [ ] Penetration testing programs
- [ ] Vulnerability management processes
- [ ] Incident response procedures and playbooks
- [ ] Regulatory reporting requirements

### 5.7 Threat Intelligence

- [ ] Known attack surfaces and vulnerabilities
- [ ] Historical security incident data
- [ ] Third-party integration risks
- [ ] Customer data flows and storage documentation

---

## 6. Integration Access Requirements

### 6.1 Microsoft 365 (Email Delivery)

| Requirement | Detail |
|-------------|--------|
| **Entra ID App Registration** | Required for Graph API access |
| **Permissions** | `Mail.Send` (delegated or application), `User.Read.All` |
| **Credentials** | Tenant ID, Client ID, Client Secret |
| **Sender Address** | admin@vorsyghta.com |
| **Purpose** | Simulation email delivery, staff targeting by department |

### 6.2 Directory Integration (Choose One)

| Option | Requirements | Complexity |
|--------|-------------|------------|
| **Entra ID Graph API** (preferred) | Graph API access, read-only permissions, API authentication | Medium |
| **CSV Upload** | Structured CSV with columns: email, name, department, role, payment access level | Low |
| **LDAP Read Access** | LDAP server address, bind credentials, schema mapping | Medium |

### 6.3 Test Environment Access

| Requirement | Detail |
|-------------|--------|
| **Test/Staging Environment** | Access to ZestPayment test environment for simulation execution |
| **Payment Processor API** | Test API credentials (non-production) |
| **Banking Network** | Test connectivity for settlement simulation |
| **Webhook Endpoints** | Test webhook endpoints for simulation notification delivery |

### 6.4 SIEM Integration (Optional)

| Requirement | Detail |
|-------------|--------|
| **SIEM Platform** | Splunk, Microsoft Sentinel, QRadar, or Huawei LTS |
| **Integration Endpoint** | API or syslog endpoint for log forwarding |
| **Format** | CEF, JSON, or native format |

---

## 7. DNS & SSL Requirements

### 7.1 Domain

Vorsyghta already owns and manages the `vorsyghta.com` domain. The following DNS records will be configured by the Vorsyghta team:

| Record | Type | Value | Status |
|--------|------|-------|--------|
| `vorsyghta.com` | A | ELB external IP address | Vorsyghta-managed |
| `www.vorsyghta.com` | CNAME | `vorsyghta.com` | Vorsyghta-managed |
| `vorsyghta.com` | MX | `vorsyghta-com.mail.protection.outlook.com` | Vorsyghta-managed |

**No action required from ZestPayment.**

### 7.2 SSL Certificate

The SSL certificate for `vorsyghta.com` is managed by the Vorsyghta team.

| Requirement | Detail | Status |
|-------------|--------|--------|
| **Source** | Public Certificate Authority | Vorsyghta-managed |
| **Termination** | Huawei ELB | Vorsyghta-managed |
| **Renewal** | Automated | Vorsyghta-managed |
| **Compliance** | PCI-DSS compliant encryption standards | Vorsyghta-managed |

**No action required from ZestPayment.**

---

## 8. Observability Requirements

### 8.1 Logging

| Requirement | Detail |
|-------------|--------|
| **Format** | Structured JSON logs |
| **Retention** | Minimum 90 days |
| **Destination** | Huawei LTS (Log Tank Service) |
| **Compliance Logging** | PCI-DSS audit trail, payment transaction logging, access control logging, security event correlation |

### 8.2 Metrics

| Requirement | Detail |
|-------------|--------|
| **Endpoint** | /metrics (Prometheus format) |
| **Collection** | Prometheus or compatible |
| **Payment-Specific Metrics** | Transaction processing rates, fraud detection alerts, API response times, payment success/failure rates |

---

## 9. Compliance & Data Handling

### 9.1 Data Classification

| Requirement | Detail |
|-------------|--------|
| **Data Classification** | Confidential |
| **Encryption at Rest** | Required |
| **Encryption in Transit** | Required |
| **PAN Redaction** | All payment account numbers redacted in simulations |
| **PII Redaction** | All personally identifiable information redacted |
| **Data Residency** | Nigeria (ng-west-1 region) — no cross-border data transfer |
| **Audit Log Retention** | Minimum 90 days |

### 9.2 Prohibited Actions

The following actions are **strictly prohibited** during all simulations:

- Real payment processing
- Actual fund transfers
- Real customer data exposure
- Production system disruption

### 9.3 Approval Requirements

The following simulation types require explicit approval from the ZestPayment Project Sponsor:

- External network scanning
- Phishing simulations targeting staff
- API abuse testing

---

## 10. Timeline

| Phase | Duration | Key Activities | ZestPayment Involvement |
|-------|----------|---------------|------------------------|
| **Phase 1: Discovery** | 2–3 weeks | Architecture mapping, security documentation, compliance review, threat scenario validation | High — provide documentation, attend meetings |
| **Phase 2: Data Collection & AI Config** | 4–6 weeks | Platform deployment, LLM configuration, threat scenario development, simulation testing | Medium — provide access, review scenarios |
| **Phase 3: Integration & Testing** | 2–3 weeks | Test environment integration, end-to-end simulation execution, refinement, training, handover | Medium — provide test access, attend training |
| **Total** | 8–12 weeks | | |

> **POC Acceleration**: Timeline can be reduced by up to 50% if Huawei Cloud resources are pre-provisioned before Phase 1 begins.

---

## 11. Expected Outcomes

### Threat Simulation Capabilities

- **Realistic Payment Fraud Scenarios** — Based on actual payment platform threats
- **Cloud-Specific Attack Vectors** — Reflecting modern cloud infrastructure risks
- **Regulatory Compliance Testing** — Validating PCI-DSS and financial regulations
- **API Security Assessment** — Testing developer integration security
- **Customer Data Protection** — Simulating data breach and privacy scenarios
- **Quantum Threat Assessment** — Identifying quantum-vulnerable cryptographic implementations

### Business Benefits

- **Enhanced Security Awareness** — Training for payment platform threats
- **Compliance Validation** — Testing against regulatory requirements
- **Risk Reduction** — Early identification of security gaps
- **Incident Response Preparation** — Realistic breach simulation training
- **Developer Security Education** — API security best practices
- **Post-Quantum Readiness** — PQC migration planning and Y2Q timeline assessment

---

## 12. Next Steps

1. **Review and acknowledge** this requirements document
2. **Assign personnel** as outlined in Section 2
3. **Provision infrastructure** as outlined in Section 3 (or confirm pre-provisioning for accelerated timeline)
4. **Select LLM access path** as outlined in Section 4
5. **Begin data collection** — provide documentation listed in Section 5
6. **Schedule Discovery Meeting** — kickoff with ZestPayment technical team

---

## 13. Contact

| Item | Detail |
|------|--------|
| **Vorsyghta Contact** | admin@vorsyghta.com |
| **Platform URL** | https://vorsyghta.com |
| **Document Version** | 1.0 |
| **Date** | June 2026 |

---

*This document contains confidential information intended solely for ZestPayment. Please do not distribute without authorization from admin@vorsyghta.com.*
