# Vorsyghta Blue Team — SOC Analyst Onboarding Guide

**Version:** 1.0  
**Audience:** SOC Analysts, Tier 1–3  
**Prerequisites:** Basic security knowledge, CLI familiarity, access to Vorsyghta environment  

---

## Table of Contents

1. [What Is Vorsyghta Blue Team?](#1-what-is-vorsyghta-blue-team)
2. [Architecture Overview](#2-architecture-overview)
3. [Environment Setup](#3-environment-setup)
4. [Your First Day: Verification & Connectivity](#4-your-first-day-verification--connectivity)
5. [Core Modules — Deep Dive](#5-core-modules--deep-dive)
   - [5.1 SIEM Operations](#51-siem-operations)
   - [5.2 IDS/IPS Detection](#52-idsips-detection)
   - [5.3 EDR Endpoint Monitoring](#53-edr-endpoint-monitoring)
   - [5.4 Alert Triage & Prioritization](#54-alert-triage--prioritization)
   - [5.5 Incident Response](#55-incident-response)
   - [5.6 Threat Hunting](#56-threat-hunting)
   - [5.7 Log Analysis](#57-log-analysis)
   - [5.8 Digital Forensics](#58-digital-forensics)
6. [The SOC Dashboard](#6-the-soc-dashboard)
7. [Detection Rule Generation](#7-detection-rule-generation)
8. [MITRE ATT&CK Mapping](#8-mitre-attck-mapping)
9. [Daily Workflows by Tier](#9-daily-workflows-by-tier)
10. [API Access](#10-api-access)
11. [Glossary](#11-glossary)
12. [Cheat Sheet](#12-cheat-sheet)

---

## 1. What Is Vorsyghta Blue Team?

Vorsyghta Blue Team is the **defensive operations module** of the Vorsyghta AI-powered threat simulation platform. It provides SOC analysts with a unified toolkit for:

- **SIEM integration** — Query logs and alerts from Splunk, Elastic, Microsoft Sentinel, or QRadar
- **IDS/IPS detection** — Snort/Suricata-style rule engine with 10 pre-built detection rules
- **EDR monitoring** — Endpoint process, file, registry, and network connection monitoring
- **Alert triage** — Automated prioritization (P1–P4), false positive reduction, and recommended actions
- **Incident response** — NIST 800-61 playbooks for intrusion, malware, phishing, data breach, and DDoS
- **Threat hunting** — MITRE ATT&CK hypothesis-based hunting with 8 pre-built hypotheses
- **Log analysis** — Multi-source parsing (Linux auth, syslog, Windows security, Apache, Nginx) with correlation
- **Digital forensics** — Evidence collection, chain of custody, hash verification, and timeline reconstruction

All capabilities are accessible via **CLI** (`vorsyghta blue-team`) and **REST API**.

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                   SOC Analyst Workstation                │
│                                                          │
│  vorsyghta blue-team <command>    REST API (FastAPI)     │
│         │                              │                 │
└─────────┼──────────────────────────────┼─────────────────┘
          │                              │
          ▼                              ▼
┌─────────────────────────────────────────────────────────┐
│                   Vorsyghta Blue Team                    │
│                                                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │   SIEM   │ │   IDS    │ │   EDR    │ │  Triage  │   │
│  │ Simulator│ │ Detector │ │  Agent   │ │  Engine  │   │
│  └────┬─────┘ └──────────┘ └──────────┘ └──────────┘   │
│       │                                                 │
│  ┌────▼─────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │  SIEM    │ │ Incident │ │  Threat  │ │   Log    │   │
│  │  Client  │ │ Response │ │  Hunter  │ │ Analyzer │   │
│  └────┬─────┘ └──────────┘ └──────────┘ └──────────┘   │
│       │                                                 │
│  ┌────▼─────┐ ┌──────────────────────────────────┐     │
│  │Forensics │ │  Detection Rule Generator        │     │
│  │Collector │ │  (Splunk, Elastic, Sentinel,     │     │
│  └──────────┘ │   Sigma, QRadar)                 │     │
│               └──────────────────────────────────┘     │
└─────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────┐
│              External SIEM Platforms                     │
│                                                         │
│  Splunk  │  Elastic  │  Sentinel  │  QRadar  │  Generic │
└─────────────────────────────────────────────────────────┘
```

### Key Design Principles

- **Simulator-first**: All modules work without a real SIEM connected. The `SIEMSimulator` provides simulated logs and alerts for training and testing.
- **Real SIEM optional**: When `SIEM_PLATFORM` and `SIEM_URL` environment variables are set, the system connects to your actual SIEM (Splunk, Elastic, Sentinel, or QRadar).
- **MITRE ATT&CK throughout**: Every alert, hunt, and incident maps to MITRE ATT&CK techniques.
- **NIST 800-61 IR**: Incident response playbooks follow the NIST 800-61 lifecycle: Preparation → Detection → Containment → Eradication → Recovery → Post-Incident.

---

## 3. Environment Setup

### 3.1 Prerequisites

- Python 3.10+
- Vorsyghta installed (`pip install -e .` or `poetry install`)
- Environment variables configured (see `.env.example`)

### 3.2 Environment Variables

Configure these in your `.env` file or shell environment:

```bash
# === SIEM Configuration (optional — simulator works without these) ===

# Platform: splunk, elastic, sentinel, qradar, generic
SIEM_PLATFORM=sentinel
SIEM_URL=https://api.loganalytics.io/v1/workspaces/your-workspace-id
SIEM_API_TOKEN=your-api-token          # For Splunk, Elastic, QRadar
SIEM_USERNAME=your-username             # For Splunk, Elastic (if not using token)
SIEM_PASSWORD=your-password             # For Splunk, Elastic (if not using token)
SIEM_INDEX=main                         # Default index/namespace

# === Microsoft Sentinel (if using Sentinel) ===
# Auth uses AzureCliCredential automatically — run `az login` first
# SIEM_URL format: https://api.loganalytics.io/v1/workspaces/{workspaceId}

# === Logging ===
VORSYGHTA_LOG_LEVEL=INFO                # DEBUG, INFO, WARNING, ERROR
VORSYGHTA_LOG_FORMAT=json               # json or text
```

### 3.3 Verify Installation

```bash
# Check Vorsyghta is installed
vorsyghta --version

# Check blue-team command is available
vorsyghta blue-team --help

# You should see:
# SIEM, IDS, EDR, incident response, threat hunting, log analysis,
# alert triage, and digital forensics capabilities.
```

---

## 4. Your First Day: Verification & Connectivity

### Step 1: Check the Blue Team Dashboard

```bash
vorsyghta blue-team dashboard
```

This shows a summary of all blue team components:

```
╭─────────────────── Blue Team Status ───────────────────╮
│ Blue Team Dashboard                                     │
│                                                         │
│ SIEM: 0 logs, 0 alerts, simulator                       │
│ IDS: 0 alerts, 10 rules                                 │
│ EDR: 0 alerts on localhost                              │
│ IR: 0 incidents ({})                                    │
│ Threat Hunt: 0 hunts, 0 confirmed                       │
│ Triage: 0 triaged, 0 P1, 0% FP rate                    │
╰─────────────────────────────────────────────────────────╯
```

> **Note:** If SIEM shows "simulator", no real SIEM is connected. This is normal for first-time setup.

### Step 2: Test SIEM Connectivity (if configured)

```bash
vorsyghta blue-team siem connect
```

Expected output with a connected SIEM:
```
Testing connection to sentinel at https://api.loganalytics.io/...
✓ SIEM connection successful
  Platform: sentinel
  URL: https://api.loganalytics.io/v1/workspaces/...
```

If no SIEM is configured:
```
No SIEM configured. Set SIEM_URL and SIEM_PLATFORM env vars.
Supported platforms: splunk, elastic, sentinel, qradar, generic
```

### Step 3: Explore Available Components

```bash
# List all blue team subcommands
vorsyghta blue-team --help

# Explore each module
vorsyghta blue-team siem --help
vorsyghta blue-team ids --help
vorsyghta blue-team edr --help
vorsyghta blue-team incident --help
vorsyghta blue-team hunt --help
vorsyghta blue-team logs --help
vorsyghta blue-team triage --help
vorsyghta blue-team forensics --help
```

---

## 5. Core Modules — Deep Dive

### 5.1 SIEM Operations

The SIEM module is your primary window into security events. It connects to real SIEM platforms or falls back to a built-in simulator.

#### Supported Platforms

| Platform | Auth Method | Environment Variables |
|----------|-------------|----------------------|
| **Splunk** | Bearer token or Basic auth | `SIEM_PLATFORM=splunk`, `SIEM_URL`, `SIEM_API_TOKEN` |
| **Elastic Security** | API key or Basic auth | `SIEM_PLATFORM=elastic`, `SIEM_URL`, `SIEM_API_TOKEN` |
| **Microsoft Sentinel** | Azure CLI credential (auto-refresh) | `SIEM_PLATFORM=sentinel`, `SIEM_URL`, run `az login` |
| **IBM QRadar** | SEC token | `SIEM_PLATFORM=qradar`, `SIEM_URL`, `SIEM_API_TOKEN` |
| **Generic** | Bearer token | `SIEM_PLATFORM=generic`, `SIEM_URL`, `SIEM_API_TOKEN` |

#### Commands

**Test connectivity:**
```bash
vorsyghta blue-team siem connect
```

**Search logs:**
```bash
# Search for failed logins in the last hour
vorsyghta blue-team siem search -q "failed login" -h 1 -l 100

# Search with JSON output (for piping to other tools)
vorsyghta blue-team siem search -q "T1003" -h 24 -j
```

**Get alerts:**
```bash
# Get all critical alerts
vorsyghta blue-team siem alerts -s critical -l 50

# Get new (unacknowledged) alerts
vorsyghta blue-team siem alerts --status new
```

**View SIEM statistics:**
```bash
vorsyghta blue-team siem stats
```

#### How It Works

The `SIEMClient` (`vorsyghta/integrations/siem_client.py`) is an async HTTP client that:
1. Reads platform config from environment variables
2. Builds platform-specific auth headers (Bearer, Basic, API key, SEC, Azure AD)
3. Translates queries into platform-specific API calls
4. Returns normalized `SIEMEvent` and `SIEMAlert` objects

For Sentinel specifically, it uses `AzureCliCredential` for automatic token refresh and queries the Log Analytics API at `/v1/workspaces/{workspaceId}/query` with GET parameters.

When no SIEM is configured, the `SIEMSimulator` (`vorsyghta/defense/blue_team/siem_simulator.py`) provides:
- Simulated log ingestion from multiple sources
- Correlation rules that generate alerts
- Alert lifecycle management (new → acknowledged → resolved)
- Statistics and reporting

---

### 5.2 IDS/IPS Detection

The IDS module simulates a Snort/Suricata-style network detection engine with pre-built rules mapped to MITRE ATT&CK.

#### Pre-Built Detection Rules

| Rule ID | Name | Severity | MITRE | Port |
|---------|------|----------|-------|------|
| IDS-001 | SQL Injection | critical | T1190 | 80/443 |
| IDS-002 | XSS Attempt | high | T1185 | 80/443 |
| IDS-003 | Directory Traversal | high | T1083 | 80/443 |
| IDS-004 | Command Injection | critical | T1059 | 80/443 |
| IDS-005 | SSH Brute Force | high | T1110 | 22 |
| IDS-006 | HTTP Brute Force | high | T1110 | 80/443 |
| IDS-007 | RDP Brute Force | high | T1110 | 3389 |
| IDS-008 | DNS Exfiltration | critical | T1048 | 53 |
| IDS-009 | C2 Beacon | high | T1071 | — |
| IDS-010 | Credential Dumping (LSASS) | critical | T1003 | — |

#### Commands

**Inspect a packet against IDS rules:**
```bash
vorsyghta blue-team ids inspect \
  --protocol tcp \
  --src-ip 10.0.0.5 \
  --src-port 12345 \
  --dest-ip 192.168.1.10 \
  --dest-port 80 \
  --payload "GET /?id=1' OR '1'='1"
```

**List all IDS rules:**
```bash
vorsyghta blue-team ids rules
```

**View IDS statistics:**
```bash
vorsyghta blue-team ids stats
```

#### When to Use

- **Simulate network traffic inspection** during threat hunts
- **Validate detection coverage** for specific attack patterns
- **Test new detection rules** before deploying to production IDS
- **Training scenarios** — show analysts what alerts look like for specific attacks

---

### 5.3 EDR Endpoint Monitoring

The EDR module monitors endpoint activity for suspicious processes, file modifications, registry changes, and network connections.

#### What It Detects

**Suspicious processes** (by name): mimikatz, procdump, pwdump, hashcat, john, hydra, medusa, ncat, netcat, nmap, masscan, responder, impacket, crackmapexec, evil-winrm, bloodhound, sharpshound, rubeus, kekeo, lsassy

**Suspicious command-line patterns** (20 patterns):

| Pattern | MITRE | Severity |
|---------|-------|----------|
| PowerShell encoded command (`-enc`) | T1059 | high |
| PowerShell execution policy bypass | T1059 | high |
| CertUtil for file decoding | T1105 | medium |
| Registry hive dumping (`reg save HKLM`) | T1003 | critical |
| NTDS.dit extraction | T1003 | critical |
| Volume shadow copy deletion | T1490 | critical |
| Mimikatz invocation | T1003 | critical |
| User account creation | T1136 | high |
| WMI process creation | T1047 | high |
| PowerShell download cradle | T1105 | high |
| ...and 10 more | | |

**Suspicious file paths**: Hidden files in /tmp, executables in Temp/AppData, Startup folder persistence

**Suspicious registry keys**: Run key persistence, Winlogon Shell modification, IFEO injection, Service image path modification

#### Commands

**Monitor a process execution:**
```bash
vorsyghta blue-team edr monitor \
  --process "powershell.exe" \
  --cmd "powershell -enc SGVsbG8gV29ybGQ=" \
  --pid 1234 \
  --user "admin" \
  --parent "explorer.exe"
```

Expected output if suspicious:
```
[HIGH] PowerShell encoded command
  Detected encoded PowerShell command execution (MITRE T1059)
```

**View EDR statistics:**
```bash
vorsyghta blue-team edr stats
```

---

### 5.4 Alert Triage & Prioritization

The triage engine is your **alert noise reduction** tool. It scores alerts on a 0–100 scale, assigns priority levels (P1–P4), detects false positives, and recommends actions.

#### Priority Levels

| Priority | Score Range | Meaning | Action |
|----------|-------------|---------|--------|
| **P1** | 70–100 | Critical — immediate response | Escalate to IR team. Initiate containment. |
| **P2** | 50–69 | High priority | Assign analyst within 15 minutes. |
| **P3** | 30–49 | Standard | Review within 1 hour. |
| **P4** | 0–29 | Low priority | Monitor for pattern escalation. |

#### Scoring Factors

| Factor | Score Impact |
|--------|-------------|
| Severity: critical | +40 |
| Severity: high | +30 |
| Severity: medium | +20 |
| Severity: low | +10 |
| MITRE high-priority technique (T1003, T1190, T1486, etc.) | +15 per technique |
| Other MITRE technique | +5 per technique |
| New (unacknowledged) alert | +5 |
| Related events > 3 | +10 |
| Rule has history of false positives (>5) | -2 per FP (max -20) |
| **False positive detected** | Score × 0.1 |

#### False Positive Detection

The engine automatically flags alerts as false positives if they match:
- Known vulnerability scanners (Nessus, Qualys, Rapid7, Nuclei)
- Internal monitoring systems
- Health check requests
- Load balancer health checks
- Backup system activity
- Known scanner IP addresses

#### Commands

**Get triaged alerts:**
```bash
# Get all triaged alerts sorted by priority
vorsyghta blue-team triage alerts

# Filter by severity
vorsyghta blue-team triage alerts -s critical

# Limit results
vorsyghta blue-team triage alerts -l 50
```

**View triage statistics:**
```bash
vorsyghta blue-team triage stats
```

Output:
```
╭──────────────── Triage Stats ────────────────╮
│ Alert Triage Statistics                       │
│                                               │
│ Total Triaged: 150                            │
│ P1 (Critical): 12                             │
│ P2 (High): 34                                 │
│ False Positives: 45                           │
│ FP Rate: 30.0%                                │
│                                               │
│ By Priority: {"P1": 12, "P2": 34, ...}       │
╰───────────────────────────────────────────────╯
```

---

### 5.5 Incident Response

The IR module provides **NIST 800-61 based playbooks** for 5 incident categories. Each playbook walks through the full IR lifecycle with automated and manual steps.

#### Incident Categories & Playbooks

| Category | Steps | Automated Steps | Phases |
|----------|-------|-----------------|--------|
| **Intrusion** | 13 | 6 | Detection → Containment → Eradication → Recovery → Post-Incident |
| **Malware** | 10 | 4 | Detection → Containment → Eradication → Recovery → Post-Incident |
| **Phishing** | 8 | 6 | Detection → Containment → Eradication → Recovery → Post-Incident |
| **Data Breach** | 9 | 3 | Detection → Containment → Eradication → Recovery → Post-Incident |
| **DDoS** | 7 | 4 | Detection → Containment → Eradication → Recovery → Post-Incident |

#### Incident Lifecycle

```
open → investigating → contained → eradicated → resolved → closed
```

#### Commands

**Create an incident:**
```bash
vorsyghta blue-team incident create \
  --title "SQL Injection Attack on Payment API" \
  --severity critical \
  --category intrusion \
  --systems "web-server-01,api-gateway-02" \
  --mitre "T1190,T1059" \
  --description "SQL injection detected against /api/v1/payments endpoint" \
  --auto
```

The `--auto` flag automatically executes all automated steps (containment actions like isolating systems, blocking IPs, disabling accounts).

**Show incident details:**
```bash
vorsyghta blue-team incident show INC-20260630-0001
```

Output shows the full playbook with step completion status:
```
Step       Phase          Action                        Done  Result
IR-001     detection      Identify entry point          ○
IR-002     detection      Assess scope                  ○
IR-003     containment    Isolate affected systems      ✓     Automated execution: Isolate...
IR-004     containment    Block attacker IPs            ✓     Automated execution: Block...
IR-005     containment    Disable compromised accounts  ✓     Automated execution: Disable...
...
```

**List incidents:**
```bash
# All incidents
vorsyghta blue-team incident list

# Filter by status
vorsyghta blue-team incident list --status investigating

# Filter by severity
vorsyghta blue-team incident list --severity critical
```

**Execute a specific step manually:**
```bash
vorsyghta blue-team incident execute INC-20260630-0001 IR-001 --result "Entry point: SQL injection via /api/v1/payments"
```

**Generate post-incident report:**
```bash
vorsyghta blue-team incident report INC-20260630-0001
```

**Add lessons learned:**
```bash
vorsyghta blue-team incident lesson INC-20260630-0001 --lesson "Need WAF rule for SQL injection on payment API"
```

#### IR Phases Explained

| Phase | What Happens | Automated? |
|-------|-------------|------------|
| **Detection** | Identify entry point, assess scope, classify attack | Manual — requires analyst judgment |
| **Containment** | Isolate systems, block IPs, disable accounts, quarantine emails | Automated — immediate action to stop the bleeding |
| **Eradication** | Remove malware, patch vulnerabilities, reset credentials, block domains | Mixed — some automated, some require human action |
| **Recovery** | Restore from backup, verify integrity, monitor for re-infection | Mixed — monitoring is automated |
| **Post-Incident** | Post-incident review, update detection rules, user training, notify stakeholders | Manual — documentation and improvement |

---

### 5.6 Threat Hunting

The threat hunting module enables **proactive** threat detection using MITRE ATT&CK hypotheses. Instead of waiting for alerts, you actively search for indicators of compromise.

#### Pre-Built Hunt Hypotheses

| ID | MITRE | Technique | What It Hunts | Confidence |
|----|-------|-----------|---------------|------------|
| HUNT-001 | T1003 | Credential Dumping | LSASS access, procdump, mimikatz, NTDS.dit extraction | 0.8 |
| HUNT-002 | T1059 | Command & Scripting | Suspicious PowerShell, cmd.exe, wscript execution | 0.7 |
| HUNT-003 | T1071 | C2 Communication | Beaconing, checkin, heartbeat patterns | 0.6 |
| HUNT-004 | T1053 | Scheduled Task Persistence | schtasks, crontab, systemctl enable, at commands | 0.6 |
| HUNT-005 | T1110 | Brute Force | Multiple failed authentications | 0.7 |
| HUNT-006 | T1041 | Exfiltration Over C2 | Large data transfers to external IPs | 0.5 |
| HUNT-007 | T1070 | Indicator Removal | Log clearing, wevtutil cl, rm auth.log, auditpol /clear | 0.8 |
| HUNT-008 | T1547 | Autostart Persistence | Registry Run keys, Startup folder, Winlogon Shell | 0.7 |

#### Commands

**List available hunt hypotheses:**
```bash
vorsyghta blue-team hunt hypotheses
```

**Hunt for a specific MITRE technique:**
```bash
vorsyghta blue-team hunt search --technique T1003
```

**Execute a specific hypothesis:**
```bash
vorsyghta blue-team hunt search --hypothesis-id HUNT-001
```

**Execute all hypotheses (full hunt sweep):**
```bash
vorsyghta blue-team hunt search --all
```

Output:
```
Hunting for technique T1003...
[T1003: CONFIRMED] Credential Dumping
  CONFIRMED: Threat hunting for T1003 (Credential Dumping) found 3 matching events.
  Affected systems: web-server-01, db-server-02.
  Immediate investigation recommended.
  Findings: 3
  Affected: web-server-01, db-server-02
```

#### How It Works

1. Each hypothesis has a **query** (SIEM search string) and **data sources** (EDR, SIEM, network logs, etc.)
2. If a SIEM client is connected, the hunter queries the SIEM for the last 24 hours
3. Matching events are collected as findings
4. If findings exist (and aren't simulated), the hypothesis is **confirmed**
5. Results include affected systems, IOCs found, and a summary

#### IOC Search

After hunting, you can search for specific IOCs across all hunt results:

```python
from vorsyghta.defense.blue_team.threat_hunter import ThreatHunter

hunter = ThreatHunter()
# ... execute hunts ...

results = hunter.search_iocs(["10.0.0.5", "malware.exe", "abc123hash"])
# Returns dict mapping each IOC to matching findings
```

---

### 5.7 Log Analysis

The log analyzer parses and correlates logs from multiple sources into a normalized schema.

#### Supported Log Types

| Log Type | Description | Patterns Detected |
|----------|-------------|-------------------|
| `linux_auth` | Linux authentication logs | Failed/successful passwords, invalid users, sudo commands |
| `linux_syslog` | Linux syslog | Errors, crashes, segfaults |
| `windows_security` | Windows Event logs | Auth failures (4625), auth success (4624), process creation (4688) |
| `apache_access` | Apache access logs | SQL injection patterns, path traversal, suspicious user agents |
| `nginx_access` | Nginx access logs | Similar to Apache + additional patterns |

#### Commands

**Parse a log file:**
```bash
vorsyghta blue-team logs parse \
  --file /var/log/auth.log \
  --type linux_auth \
  --host web-server-01
```

Output:
```
Parsed 1,247 entries from /var/log/auth.log

Correlation Findings: 3
  [high] Brute Force Attack: 50+ failed logins from 10.0.0.5 in 5 minutes
  [medium] Suspicious Sudo Activity: sudo command by non-admin user
  [low] After-Hours Login: Login at 02:30 outside normal hours

Stats: {"total_entries": 1247, "by_type": {"auth_failed": 52, ...}}
```

**Search parsed logs:**
```bash
vorsyghta blue-team logs search \
  --query "failed password" \
  --file /var/log/auth.log \
  --type linux_auth
```

#### Correlation Findings

The analyzer automatically correlates events across sources to detect:
- **Brute force attacks** — Multiple failed logins from same IP
- **Suspicious sudo activity** — Sudo commands by non-standard users
- **After-hours access** — Logins outside normal working hours
- **SQL injection patterns** — In web server access logs
- **Path traversal attempts** — In web server access logs
- **Suspicious user agents** — Known attack tool signatures

---

### 5.8 Digital Forensics

The forensics module provides evidence collection, chain of custody tracking, hash verification, and timeline reconstruction.

#### Evidence Types

| Type | Description |
|------|-------------|
| `file_copy` | Individual file collected as evidence |
| `disk_image` | Full disk image (raw, dd, E01) |
| `memory_dump` | RAM capture for volatility analysis |
| `network_capture` | PCAP or network flow data |
| `log_capture` | Log files preserved as evidence |
| `registry_dump` | Windows registry hive export |

#### Chain of Custody

Every artifact maintains a chain of custody log:
```
timestamp: 2026-06-30T10:00:00Z
action: collected
actor: vorsyghta-forensics
detail: File collected from web-server-01
```

#### Commands

**Initialize a forensic case:**
```bash
vorsyghta blue-team forensics init --case-id CASE-2026-001
```

**Collect a file as evidence:**
```bash
vorsyghta blue-team forensics collect \
  --file /var/log/auth.log \
  --source web-server-01
```

Output:
```
Collected: FA-CASE-2026-001-0001
  Type: file_copy
  Source: web-server-01
  Size: 45678 bytes
  SHA256: a1b2c3d4e5f6...
```

**Generate forensic case report:**
```bash
vorsyghta blue-team forensics report --case-id CASE-2026-001
```

**View forensics statistics:**
```bash
vorsyghta blue-team forensics stats
```

#### Forensic Timeline

The forensics collector builds a timeline from multiple evidence sources:

```python
from vorsyghta.defense.blue_team.forensics import ForensicsCollector

fc = ForensicsCollector(case_id="CASE-2026-001")

# Collect evidence
fc.collect_file("/var/log/auth.log", "web-server-01")
fc.register_disk_image("/evidence/disk-web01.raw", "web-server-01")
fc.register_memory_dump("/evidence/mem-web01.dmp", "web-server-01")

# Build timeline
timeline = fc.build_timeline(log_entries)
# Returns sorted timeline with MITRE technique mappings
```

---

## 6. The SOC Dashboard

The dashboard provides a single-view summary of all blue team components:

```bash
vorsyghta blue-team dashboard
```

```
╭─────────────────── Blue Team Status ───────────────────╮
│ Blue Team Dashboard                                     │
│                                                         │
│ SIEM: 12,450 logs, 89 alerts, connected                 │
│ IDS: 156 alerts, 10 rules                               │
│ EDR: 23 alerts on web-server-01                         │
│ IR: 5 incidents ({"investigating": 2, "contained": 1}) │
│ Threat Hunt: 8 hunts, 3 confirmed                       │
│ Triage: 89 triaged, 12 P1, 28% FP rate                  │
╰─────────────────────────────────────────────────────────╯
```

**What to look for:**
- **SIEM connected vs simulator** — Are you looking at real data?
- **P1 alert count** — Any P1 alerts need immediate attention
- **FP rate** — High FP rate (>40%) means detection rules need tuning
- **Confirmed threats** — Any confirmed hunts need IR escalation
- **Active incidents** — Incidents in "investigating" or "contained" status need follow-up

---

## 7. Detection Rule Generation

Vorsyghta includes a detection rule generator that creates platform-specific rules from MITRE ATT&CK techniques.

### Supported Output Formats

| Format | Module | Target Platform |
|--------|--------|----------------|
| **Splunk SPL** | `analytics/detection_rules/splunk.py` | Splunk searches |
| **Elastic KQL/EQL** | `analytics/detection_rules/elastic.py` | Elastic Security |
| **Sentinel KQL** | `analytics/detection_rules/sentinel.py` | Microsoft Sentinel |
| **Sigma** | `analytics/detection_rules/sigma.py` | Generic Sigma rules |
| **Validator** | `analytics/detection_rules/validator.py` | Rule validation |

### Usage

```python
from vorsyghta.analytics.detection_rules import RuleGenerator, RuleFormat

generator = RuleGenerator()

# Generate a Splunk SPL rule for credential dumping
rule = generator.generate(
    technique_id="T1003",
    platform="windows",
    output_format=RuleFormat.SPLUNK,
)

# Generate a Sentinel KQL rule
rule = generator.generate(
    technique_id="T1059",
    platform="windows",
    output_format=RuleFormat.SENTINEL,
)
```

---

## 8. MITRE ATT&CK Mapping

Every detection, alert, hunt, and incident in Vorsyghta Blue Team maps to MITRE ATT&CK techniques. This provides a common language for describing threats.

### High-Priority Techniques (weighted +15 in triage scoring)

| Technique | Name | Why High Priority |
|-----------|------|-------------------|
| T1003 | Credential Dumping | Direct path to domain compromise |
| T1190 | Exploit Public-Facing Application | Initial access vector |
| T1486 | Data Encrypted for Impact | Ransomware |
| T1567 | Exfiltration to Cloud Storage | Data theft |
| T1041 | Exfiltration Over C2 Channel | Data theft |
| T1078 | Valid Accounts | Stealthy persistence |
| T1136 | Create Account | Persistence |
| T1547 | Boot/Logon Autostart | Persistence |
| T1059 | Command & Scripting Interpreter | Execution |
| T1071 | Application Layer Protocol | C2 communication |

---

## 9. Daily Workflows by Tier

### Tier 1 Analyst — Alert Triage & Initial Response

```
┌──────────────────────────────────────────────────────────┐
│  DAILY WORKFLOW — TIER 1                                 │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  1. Check dashboard                                      │
│     $ vorsyghta blue-team dashboard                      │
│                                                          │
│  2. Pull triaged alerts                                  │
│     $ vorsyghta blue-team triage alerts                  │
│                                                          │
│  3. Focus on P1 alerts first                             │
│     - Review recommended action                          │
│     - Check related alerts                               │
│     - If real → create incident (escalate to T2)         │
│     - If false positive → mark as FP                     │
│                                                          │
│  4. Review P2 alerts                                     │
│     - Investigate within 15 minutes                      │
│     - Correlate with SIEM search                         │
│                                                          │
│  5. Check SIEM for new alerts                            │
│     $ vorsyghta blue-team siem alerts --status new       │
│                                                          │
│  6. End-of-shift: review triage stats                    │
│     $ vorsyghta blue-team triage stats                   │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### Tier 2 Analyst — Investigation & Incident Response

```
┌──────────────────────────────────────────────────────────┐
│  DAILY WORKFLOW — TIER 2                                 │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  1. Review escalated incidents                           │
│     $ vorsyghta blue-team incident list --status         │
│       investigating                                      │
│                                                          │
│  2. Investigate using SIEM search                        │
│     $ vorsyghta blue-team siem search -q "T1003" -h 24   │
│                                                          │
│  3. Deep-dive with log analysis                          │
│     $ vorsyghta blue-team logs parse -f /var/log/auth    │
│       -t linux_auth                                      │
│                                                          │
│  4. Execute IR playbook steps                            │
│     $ vorsyghta blue-team incident execute INC-... IR-   │
│       001 --result "Entry point: SQL injection"          │
│                                                          │
│  5. Collect forensic evidence                            │
│     $ vorsyghta blue-team forensics collect -f /var/log  │
│       /auth.log -s web-server-01                         │
│                                                          │
│  6. Generate incident report                             │
│     $ vorsyghta blue-team incident report INC-...        │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### Tier 3 Analyst — Threat Hunting & Detection Engineering

```
┌──────────────────────────────────────────────────────────┐
│  DAILY WORKFLOW — TIER 3                                 │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  1. Run proactive threat hunts                           │
│     $ vorsyghta blue-team hunt search --all              │
│                                                          │
│  2. Review confirmed hunt results                        │
│     - If confirmed → create incident for T2              │
│     - If disproved → document and move on                │
│                                                          │
│  3. Tune detection rules based on FP data                │
│     $ vorsyghta blue-team triage stats                   │
│     - High FP rate → review and tune rules               │
│                                                          │
│  4. Generate new detection rules                         │
│     - Use detection rule generator for new techniques    │
│     - Validate with IDS simulator                        │
│                                                          │
│  5. Add new hunt hypotheses                              │
│     - Based on new threat intel                          │
│     - Based on lessons learned from incidents            │
│                                                          │
│  6. Post-incident review                                 │
│     - Review lessons learned                             │
│     - Update playbooks                                   │
│     - Update detection rules                             │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## 10. API Access

All blue team capabilities are also available via REST API.

### Base URL

```
http://vorsyghta.com/api/v1/blue-team/
```

### Key Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/blue-team/siem/stats` | SIEM statistics |
| GET | `/api/v1/blue-team/siem/alerts` | Get SIEM alerts |
| POST | `/api/v1/blue-team/siem/search` | Search SIEM logs |
| GET | `/api/v1/blue-team/ids/rules` | List IDS rules |
| POST | `/api/v1/blue-team/ids/inspect` | Inspect a packet |
| GET | `/api/v1/blue-team/edr/stats` | EDR statistics |
| GET | `/api/v1/blue-team/triage/alerts` | Get triaged alerts |
| GET | `/api/v1/blue-team/triage/stats` | Triage statistics |
| POST | `/api/v1/blue-team/incident/create` | Create incident |
| GET | `/api/v1/blue-team/incident/{id}` | Get incident details |
| POST | `/api/v1/blue-team/incident/{id}/execute` | Execute IR step |
| GET | `/api/v1/blue-team/incident/{id}/report` | Generate report |
| GET | `/api/v1/blue-team/hunt/hypotheses` | List hunt hypotheses |
| POST | `/api/v1/blue-team/hunt/search` | Execute hunt |
| POST | `/api/v1/blue-team/logs/parse` | Parse log file |
| POST | `/api/v1/blue-team/forensics/collect` | Collect evidence |
| GET | `/api/v1/blue-team/forensics/{case_id}/report` | Forensic report |
| GET | `/api/v1/blue-team/dashboard` | Full dashboard |

### Example API Call

```bash
# Get triaged alerts via API
curl -H "Authorization: Bearer $JWT_TOKEN" \
  https://vorsyghta.com/api/v1/blue-team/triage/alerts?severity=critical

# Create incident via API
curl -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{
    "title": "SQL Injection Attack",
    "severity": "critical",
    "category": "intrusion",
    "affected_systems": ["web-server-01"],
    "mitre_techniques": ["T1190"]
  }' \
  https://vorsyghta.com/api/v1/blue-team/incident/create
```

---

## 11. Glossary

| Term | Definition |
|------|------------|
| **SIEM** | Security Information and Event Management — centralized log aggregation, correlation, and alerting |
| **IDS/IPS** | Intrusion Detection System / Intrusion Prevention System — network traffic inspection |
| **EDR** | Endpoint Detection and Response — host-level process, file, and registry monitoring |
| **IOC** | Indicator of Compromise — artifact (IP, hash, domain, file) indicating malicious activity |
| **MITRE ATT&CK** | Knowledge base of adversary tactics, techniques, and procedures (TTPs) |
| **NIST 800-61** | National Institute of Standards and Technology incident response framework |
| **P1–P4** | Priority levels: P1 = immediate, P2 = 15 min, P3 = 1 hour, P4 = monitor |
| **FP** | False Positive — alert triggered by benign activity |
| **Chain of Custody** | Documented trail of evidence handling from collection to presentation |
| **Hunt Hypothesis** | A testable assertion that a specific MITRE technique is present in the environment |
| **Playbook** | Pre-defined set of steps for responding to a specific incident type |
| **Sigma Rule** | Generic signature format for SIEM detection rules |

---

## 12. Cheat Sheet

### Quick Reference — All Commands

```bash
# === Dashboard ===
vorsyghta blue-team dashboard

# === SIEM ===
vorsyghta blue-team siem connect                              # Test connectivity
vorsyghta blue-team siem search -q "query" -h 24 -l 100      # Search logs
vorsyghta blue-team siem alerts -s critical                   # Get alerts
vorsyghta blue-team siem stats                                # Statistics

# === IDS ===
vorsyghta blue-team ids inspect -p tcp --dest-port 80 ...     # Inspect packet
vorsyghta blue-team ids rules                                 # List rules
vorsyghta blue-team ids stats                                 # Statistics

# === EDR ===
vorsyghta blue-team edr monitor -p "powershell.exe" -c "..."  # Monitor process
vorsyghta blue-team edr stats                                 # Statistics

# === Triage ===
vorsyghta blue-team triage alerts -s critical -l 50           # Triaged alerts
vorsyghta blue-team triage stats                              # Triage statistics

# === Incident Response ===
vorsyghta blue-team incident create -t "Title" -s critical \  # Create incident
  -c intrusion --systems "srv01,srv02" --mitre "T1190" --auto
vorsyghta blue-team incident show INC-20260630-0001           # Show details
vorsyghta blue-team incident list --status investigating      # List incidents
vorsyghta blue-team incident execute INC-... IR-001 \         # Execute step
  --result "Entry point identified"
vorsyghta blue-team incident report INC-...                   # Generate report

# === Threat Hunting ===
vorsyghta blue-team hunt hypotheses                           # List hypotheses
vorsyghta blue-team hunt search --technique T1003             # Hunt by technique
vorsyghta blue-team hunt search --all                         # Hunt all

# === Log Analysis ===
vorsyghta blue-team logs parse -f /var/log/auth.log \         # Parse log file
  -t linux_auth --host web-server-01
vorsyghta blue-team logs search -q "failed password" \        # Search logs
  -f /var/log/auth.log -t linux_auth

# === Forensics ===
vorsyghta blue-team forensics init -c CASE-2026-001           # Initialize case
vorsyghta blue-team forensics collect -f /var/log/auth.log \  # Collect evidence
  -s web-server-01
vorsyghta blue-team forensics report -c CASE-2026-001         # Case report
vorsyghta blue-team forensics stats                           # Statistics
```

### Priority Decision Tree

```
Alert arrives
    │
    ▼
Triage engine scores it (0-100)
    │
    ├── P1 (70-100) ──→ Immediate response
    │                     ├── Create incident: vorsyghta blue-team incident create ...
    │                     ├── Escalate to T2/T3
    │                     └── Start IR playbook with --auto
    │
    ├── P2 (50-69) ────→ Investigate within 15 min
    │                     ├── SIEM search for context
    │                     └── If real → create incident
    │
    ├── P3 (30-49) ────→ Review within 1 hour
    │                     ├── Check for related alerts
    │                     └── Monitor for escalation
    │
    ├── P4 (0-29) ─────→ Monitor
    │                     └── Watch for pattern changes
    │
    └── FP detected ───→ Suppress
                          ├── Mark as false positive
                          └── Consider tuning detection rule
```

### Escalation Path

```
Tier 1 (Triage)  ──P1/Further investigation──→  Tier 2 (IR)
                                                      │
                                              Confirmed incident
                                                      │
                                                      ▼
                                              Tier 3 (Hunt + Forensics)
                                                      │
                                              Post-incident review
                                                      │
                                                      ▼
                                              Update rules + playbooks
```

---

*This document is maintained by the Vorsyghta team. For questions, contact admin@vorsyghta.com.*
