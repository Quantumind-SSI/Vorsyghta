# The Vorsyghta Intelligence Stack

The Intelligence Stack is Vorsyghta's proprietary differentiator — a unified, event-sourced threat intelligence pipeline that connects every team, every simulation, and every detection back to a single source of truth. Unlike traditional security tools that silo intelligence within individual teams, Vorsyghta's stack flows intelligence **bidirectionally** across red team, blue team, ML/AI, compliance, and infrastructure, creating a closed-loop system where each team's output becomes another team's input.

## Why It's Proprietary

No other platform combines:

- **OSINT-driven simulation enrichment** — live reconnaissance (LinkedIn, GitHub, company websites, social media, domain/WHOIS, DNS) feeds directly into LLM-generated threat payloads tailored to the actual target
- **Dark web exposure monitoring** — continuous scanning of breach databases (HaveIBeenPwned, DeHashed) and commercial dark web APIs (Recorded Future, ZeroFox, Flare) for leaked credentials, payment data, customer PII, API keys, and source code
- **MITRE ATT&CK v14 full coverage** — every technique, sub-technique, tactic, procedure, detection, and mitigation mapped and queryable, with D3FEND mappings for defensive coverage analysis
- **Event-sourced audit trail** — every simulation event (start, stage, completion, failure) persisted to an immutable PostgreSQL event log with optimistic concurrency control and event replay for aggregate reconstruction
- **Hypothesis-driven threat hunting** — pre-built MITRE ATT&CK hunt hypotheses executed across SIEM and EDR data, with results fed back into simulation refinement
- **Automated detection rule generation** — Sigma, Splunk, Elastic, and Sentinel rules auto-generated from simulated TTPs, closing the gap between red team execution and blue team detection

## How Each Team Uses It

```
                    ┌─────────────────────────────────┐
                    │   Vorsyghta Intelligence Stack   │
                    │                                  │
                    │  OSINT  │  Dark Web  │  MITRE   │
                    │  Engine │  Monitor   │  ATT&CK  │
                    │         │            │  Engine  │
                    │  Event  │  Threat    │  Detect  │
                    │  Store  │  Hunter    │  Rules   │
                    └──┬──┬──┬──┬──┬──┬──┬──┬───────────┘
                       │  │  │  │  │  │  │  │
          Red Team ───┘  │  │  │  │  │  │  └─── Compliance
          Blue Team ─────┘  │  │  │  │  └────── Infrastructure
          ML/AI ───────────┘  │  │  └───────── Core Engine
          Client Recon ───────┘  └──────────── Threat Hunting
```

| Team | What They Consume | What They Produce |
|---|---|---|
| **Red Team** | OSINT profiles, dark web exposures, MITRE TTPs, company intelligence | Simulated attack scenarios, credential stuffing payloads, phishing lures enriched with leaked data |
| **Blue Team** | Simulated TTPs, MITRE hunt hypotheses, detection gaps, event-sourced timelines | Confirmed/dispelled hunt hypotheses, SIEM detection rules, forensic artifacts, IR playbooks |
| **ML/AI** | Intelligence-enriched scenarios, target behavioural profiles, dark web data types | LLM-generated threat content (phishing, SMS, voice, web, social, documents) tuned to real target context |
| **Compliance** | Dark web exposure findings, event-sourced audit trail, PCI-DSS/NDPR/CBN impact assessments | Breach notification readiness, regulatory audit packages, compliance gap reports |
| **Infrastructure** | Event store health, simulation lifecycle events, persistence layer status | Immutable event log integrity, database migrations, deployment observability |
| **Core Engine** | All intelligence outputs (OSINT, dark web, threat intel, MITRE mappings) | Event-sourced simulation orchestration with full audit trail and replay capability |

## How It Improves Security Posture

### 1. From Generic to Targeted Simulations

Traditional platforms run canned scenarios. Vorsyghta's OSINT engine gathers live intelligence on the target organisation — employee profiles from LinkedIn, technology stack from website scraping, domain records from WHOIS/DNS, social media activity patterns — and feeds this directly into the LLM prompt context. The result: phishing emails that reference actual executives, data exfiltration scenarios that target the real database architecture, and credential stuffing attacks using domains and email patterns specific to the organisation.

### 2. From Reactive to Proactive Detection

Blue team doesn't wait for an alert. The threat hunter module runs pre-built MITRE ATT&CK hypotheses (credential dumping, C2 beaconing, persistence mechanisms, log clearing, brute force) across SIEM and EDR data. Each hunt produces confirmed or dispelled findings with affected systems and IOCs, feeding back into the simulation engine to refine future scenarios. Detection rules are auto-generated from the exact TTPs simulated, so blue team validates detection coverage against the same techniques red team executes.

### 3. From Unknown to Known Exposure

The dark web monitor continuously scans breach databases and dark web sources for leaked credentials, payment data, customer PII, API keys, and source code specific to the target organisation. Findings are classified by exposure type (credential leak, payment data leak, database dump, ransomware claim, selling access), severity-scored, and mapped to compliance frameworks (PCI-DSS, NDPR, ISO-27001). Each finding includes recommended remediation actions — from password resets to card reissuance to regulatory notification.

### 4. From Point-in-Time to Continuous Audit

Every simulation event — from `SimulationStarted` through each `StageStarted`/`StageCompleted`/`StageFailed` to `SimulationCompleted` or `SimulationFailed` — is persisted to an immutable PostgreSQL event store with optimistic concurrency control. This creates a tamper-evident audit trail that can be replayed to reconstruct any simulation's state at any point in time. Compliance teams extract this trail directly for regulatory audits, eliminating the gap between security operations and compliance reporting.

## Direct Business & Financial Implications

| Intelligence Capability | Business Impact | Financial Implication |
|---|---|---|
| **Dark web credential monitoring** | Detects leaked employee/customer credentials before they're exploited | Prevents account takeover fraud. Average cost of a credential breach: **$4.5M** (IBM Cost of a Data Breach Report). Early detection reduces breach cost by **$1.2M** on average. |
| **Payment data exposure scanning** | Identifies card data listings on dark web marketplaces before mass fraud | Avoids PCI-DSS fines (**$5,000–$100,000/month** for non-compliance), card brand penalties, and reissuance costs (**$3–$10 per card**). For a fintech processing 500K cards, preventing one breach saves **$1.5M–$5M** in direct costs. |
| **OSINT-enriched phishing simulations** | Employees train against attacks referencing real executives, products, and company events | Reduces click rates on actual phishing by **60-70%** (SANS Institute). For a 500-employee fintech, preventing one BEC attack saves **$1.7M** average (FBI IC3). |
| **Automated detection rule generation** | Blue team gets Sigma/Splunk/Elastic/Sentinel rules for every simulated TTP without manual writing | Reduces mean time to detect (MTTD) from **hours to minutes**. Each minute of undetected breach activity costs approximately **$200/minute** in data exfiltration impact. |
| **Threat hunting with MITRE hypotheses** | Proactively finds adversary activity before it triggers alerts | Reduces dwell time. Average dwell time without proactive hunting: **21 days**. With hypothesis-driven hunting: **<1 day**. Each day of dwell reduction saves approximately **$40,000** in breach costs. |
| **Event-sourced audit trail** | Immutable, replayable log of all simulation activity for regulators | Eliminates compliance audit preparation costs (**$50K–$200K** per audit cycle). Satisfies NDPR 72-hour breach notification, PCI-DSS Req 10, and CBN incident reporting requirements simultaneously. |
| **NDPR breach notification readiness** | Dark web findings mapped to NDPR requirements with 72-hour notification SLAs | Avoids NDPR penalties (**up to 2% of annual revenue** or **₦10M**, whichever is greater). For a fintech with ₦5B revenue, this is **₦100M** in direct penalty avoidance. |
| **Continuous compliance posture** | Every simulation produces compliance-mapped evidence (PCI-DSS, NDPR, CBN, ISO-27001) | Reduces cyber insurance premiums by **15-25%** with demonstrated continuous controls validation. For a fintech paying ₦50M/year in premiums, this saves **₦7.5M–₦12.5M** annually. |

## Client Infrastructure Requirements for Network Threat Simulation

The Intelligence Stack doesn't just gather external OSINT — it also ingests the client's own network and cloud infrastructure data to build accurate, high-fidelity threat simulations. This is what separates Vorsyghta from generic simulation platforms: simulations are executed against a **digital twin** of the client's actual environment, not a synthetic lab.

### Network Infrastructure (On-Premises & Hybrid)

Clients provide network topology data that Vorsyghta ingests via the `ClientDataManager` and `Gns3Source` adapter. The following data is required and consumed:

| Data Point | Source | How It's Used in Simulation |
|---|---|---|
| **Network topology** | GNS3 `.gns3` project files, manual export | Parsed into `NetworkTopology` model with nodes, links, and subnets — drives attack path modelling (GAP paradigm) and lateral movement scenarios |
| **Network nodes** | GNS3 topology export | Each node (router, switch, firewall, host, server) becomes a `NetworkNode` with type, console port, and properties — used to map blast radius and identify critical path assets |
| **Network links** | GNS3 topology export | Parsed into `NetworkLink` objects with source/target and link type — drives DES timing simulations for malware propagation and traffic modelling |
| **Subnets** | GNS3 topology, manual CIDR list | Extracted from node IP configurations — used to scope simulation boundaries, model segmentation failures, and test cross-subnet lateral movement |
| **Firewall rules** | Client firewall export (iptables, pfSense, Cisco ASA, Palo Alto) | Ingested as asset metadata — used to model firewall bypass techniques, test rule misconfigurations, and simulate exfiltration over allowed ports |
| **Routing tables** | Client router export | Used to model traffic flow paths, identify asymmetric routing issues, and simulate routing table manipulation attacks |
| **DNS configuration** | Client DNS server export | Used to simulate DNS poisoning, DNS tunneling, and domain hijacking scenarios against the client's actual DNS infrastructure |
| **VPN configuration** | Client VPN gateway export | Used to simulate VPN credential stuffing, split-tunneling exploits, and VPN bypass attacks |
| **Network assets** | Client asset inventory, GNS3 nodes | Each asset (server, workstation, appliance) becomes an `Asset` with IP, OS, services, and tags — drives target selection for red team scenarios and detection rule placement for blue team |
| **Exposed services** | Client port scan, service inventory | Service list per asset (SSH, RDP, HTTP, SMB, etc.) — used to identify initial access vectors and simulate exploitation of specific services |

### Cloud Infrastructure (AWS, Azure, GCP)

Clients provide cloud infrastructure data via cloud storage source adapters (`S3Source`, `AzureBlobSource`, `GcsSource`) and API integrations. The following data is required:

| Data Point | Cloud Provider | How It's Used in Simulation |
|---|---|---|
| **Cloud account structure** | AWS (accounts, Orgs), Azure (subscriptions, tenants), GCP (projects, folders) | Used to model multi-account attack paths, privilege escalation across accounts, and blast radius analysis |
| **IAM policies and roles** | AWS IAM, Azure RBAC, GCP IAM | Ingested to simulate privilege escalation, role assumption chains, and over-permissioned access — maps to MITRE ATT&CK T1078 (Valid Accounts) and T1098 (Account Manipulation) |
| **Network security groups / Security groups** | AWS SGs, Azure NSGs, GCP firewall rules | Used to model cloud firewall bypass, test segmentation between tiers (web/app/data), and simulate lateral movement within VPCs/VNets |
| **VPC / VNet topology** | AWS VPC, Azure VNet, GCP VPC | Subnets, route tables, peering connections — used to model cross-VPC lateral movement, peering abuse, and hybrid network attack paths |
| **Storage bucket permissions** | S3 buckets, Azure Blob containers, GCS buckets | Used to simulate public bucket exposure, unauthorized data access, and data exfiltration via storage APIs — maps to MITRE ATT&CK T1530 (Data from Cloud Storage) |
| **Compute instances** | EC2, Azure VMs, GCE instances | Instance metadata (IP, OS, IAM role, security group) — used to simulate instance compromise, IMDS exploitation (SSRF to metadata service), and lateral movement from compromised instances |
| **Kubernetes clusters** | EKS, AKS, GKE | Cluster configuration, RBAC, network policies — used to simulate container escape, pod-to-pod lateral movement, and RBAC privilege escalation |
| **Serverless functions** | AWS Lambda, Azure Functions, GCP Cloud Functions | Function permissions and triggers — used to simulate function hijacking, event injection, and privilege escalation via serverless |
| **API Gateway configuration** | AWS API Gateway, Azure API Management, GCP API Gateway | API routes, authentication methods, rate limits — used to simulate API abuse, authentication bypass, and rate limit evasion |
| **Cloud logging / monitoring** | CloudTrail, Azure Monitor, GCP Cloud Audit Logs | Log configuration and retention — used to test detection coverage for cloud TTPs and simulate log tampering / trail disabling |
| **Secrets management** | AWS Secrets Manager, Azure KeyVault, GCP Secret Manager | Secret inventory and access policies — used to simulate secret extraction, rotation failure exploitation, and cross-service credential abuse |
| **CDN and WAF configuration** | CloudFront, Azure Front Door, GCP Cloud CDN | WAF rules, origin configurations — used to simulate WAF bypass, origin IP discovery, and cache poisoning attacks |

### Data Ingestion Pipeline

```
    Client Environment
    │
    ├── GNS3 Topology Export (.gns3)
    │   └──► Gns3Source ──► NetworkTopology (nodes, links, subnets)
    │                        └──► Assets (routers, switches, firewalls, hosts)
    │
    ├── Cloud Infrastructure Export
    │   ├── AWS ────► S3Source ──► Asset inventory, IAM policies, SG rules
    │   ├── Azure ──► AzureBlobSource ──► VM list, NSG rules, RBAC assignments
    │   └── GCP ────► GcsSource ──► Project list, firewall rules, service accounts
    │
    ├── CRM / Identity Sources
    │   ├── Salesforce ──► Employee profiles, org structure
    │   ├── HubSpot ─────► Employee profiles, department mapping
    │   ├── Microsoft 365 ► Employee directory, Azure AD groups
    │   └── Google Workspace ► Employee directory, Google Groups
    │
    ├── Document Sources
    │   ├── OneDrive / SharePoint / Google Drive
    │   └──► Document inventory (policies, architecture diagrams, configs)
    │
    └── Manual Configuration
        └──► ClientProfile YAML (assets, subnets, exposed services)
                │
                ▼
        ClientDataManager
                │
                ├── enrich_scenario() ──► Injects network topology, assets,
                │                         employees, and documents into
                │                         simulation custom_parameters
                │
                ├── CompanyReconAgent ──► OSINT enrichment layered on top
                │                         of client-provided infrastructure
                │
                └── OSINTService ───────► Dark web monitoring + MITRE mapping
                                          against client's actual assets
```

### How Infrastructure Data Feeds the Simulation Engine

When `ClientDataEnrichment.enrich_scenario()` runs, the client's infrastructure data is injected directly into the scenario's `custom_parameters`:

- **`client_network_topology`** — full `NetworkTopology` model (nodes, links, subnets) — the simulation engine uses this to generate realistic lateral movement paths, model segmentation failures, and calculate blast radius
- **`client_assets`** — list of `Asset` objects (IPs, OS, services) — the LLM prompt context includes actual asset inventory so generated phishing emails reference real server names, and exfiltration scenarios target actual database hosts
- **`client_employees`** — employee directory (name, role, department, email) — phishing simulations target actual employees with correct roles and departments, not synthetic personas
- **`client_tenant_id` / `client_name`** — multi-tenant isolation — ensures simulations are scoped to the correct client environment and audit trail is properly attributed

This infrastructure data is then combined with OSINT and dark web findings to produce simulations that are both **externally informed** (what the adversary knows from public sources) and **internally accurate** (what the actual environment looks like).

### Security Posture Improvements from Infrastructure Integration

| Capability | Without Client Infrastructure | With Client Infrastructure |
|---|---|---|
| **Lateral movement simulation** | Generic subnet ranges, synthetic hosts | Real subnets, actual switch/router topology, accurate VLAN segmentation |
| **Phishing target selection** | Random email generation | Actual employee directory with roles, departments, and seniority levels |
| **Attack path modelling** | Theoretical attack graphs | Real network links, firewall rule sets, and routing tables drive the graph |
| **Cloud attack simulation** | Generic cloud TTPs | Client's actual IAM policies, security groups, and bucket permissions tested |
| **Detection rule placement** | Rules generated for generic infrastructure | Rules tuned to client's actual SIEM, EDR, and cloud logging configuration |
| **Blast radius analysis** | Estimated impact zones | Calculated from real network topology — exact hosts and subnets affected |
| **Compliance evidence** | Generic control validation | Validated against client's actual firewall rules, IAM policies, and audit log configuration |

## The Closed-Loop Intelligence Cycle

```
    ┌──────────┐
    │  OSINT   │──── Gather target intelligence (LinkedIn, GitHub,
    │  Engine  │     domain, social media, company website)
    └────┬─────┘
         │
         ▼
    ┌──────────┐
    │  Dark    │──── Scan breach databases and dark web sources for
    │  Web     │     leaked credentials, payment data, PII, API keys
    │  Monitor │
    └────┬─────┘
         │
         ▼
    ┌──────────┐
    │  MITRE   │──── Map intelligence to ATT&CK techniques, tactics,
    │  ATT&CK  │     procedures; identify coverage gaps
    │  Engine  │
    └────┬─────┘
         │
         ▼
    ┌──────────┐
    │  LLM     │──── Generate context-aware threat payloads (phishing,
    │  Content │     SMS, voice, web, social, documents) enriched
    │  Engine  │     with live OSINT and dark web findings
    └────┬─────┘
         │
         ▼
    ┌──────────┐
    │  Simu-   │──── Execute multi-stage simulation with event sourcing;
    │  lation  │     every stage persisted to immutable audit trail
    │  Engine  │
    └────┬─────┘
         │
         ▼
    ┌──────────┐
    │  Threat  │──── Hunt for simulated TTPs across SIEM/EDR data
    │  Hunter  │     using MITRE hypotheses; confirm or dispel
    └────┬─────┘
         │
         ▼
    ┌──────────┐
    │  Detect  │──── Auto-generate Sigma/Splunk/Elastic/Sentinel rules
    │  Rules   │     from simulated TTPs; validate blue team coverage
    └────┬─────┘
         │
         ▼
    ┌──────────┐
    │  Compli- │──── Map findings to PCI-DSS, NDPR, CBN, ISO-27001;
    │  ance    │     prepare breach notifications and audit packages
    └────┬─────┘
         │
         └───────────────►  Feed back into OSINT Engine
                           (refine target profiles, update
                            exposure monitoring, close the loop)
```

## CLI Access

```bash
# Gather comprehensive intelligence on a target
vorsyghta intel gather zestpayment.com --types profile company dark_web

# Search dark web for leaked ZestPayment confidential data
vorsyghta intel dark-web "ZestPayment" -d zestpayment.com -k credentials payment database

# Enhance a threat scenario with live intelligence
vorsyghta intel enhance templates/zestpayment/zestpayment_data_breach.yaml zestpayment.com

# List available intelligence sources
vorsyghta intel sources

# Execute threat hunting hypotheses
vorsyghta blue-team hunt search --technique T1003
vorsyghta blue-team hunt search --all
```

## Related Documentation

- [MITRE ATT&CK Full Coverage](../../dev-docs/architecture/ENGINE_PARADIGMS_AND_FIDELITY_LEVELS.md)
- [Kill Chain Intelligence Output](../../dev-docs/architecture/VORSYGHTA_KILL_CHAIN_INTELLIGENCE_OUTPUT.md)
- [Intelligence Reporting Capabilities](../../dev-docs/architecture/VORSYGHTA_INTELLIGENCE_REPORTING_CAPABILITIES.md)
- [Detection Rule Generation](../../dev-docs/architecture/DETECTION_RULE_GENERATION_MECHANISM.md)
- [Event Sourcing Implementation](../../vorsyghta/core/event_sourcing.py)
- [Dark Web Monitor Service](../../vorsyghta/intelligence/services.py)
- [ZestPayment Dark Web Monitoring Template](../../templates/zestpayment/zestpayment_dark_web_monitoring.yaml)
