# Executive Spear-Phishing Response Playbook

**Version:** 1.0.0  
**Team:** Security Operations Center (SOC) / Incident Response  
**Classification:** Internal Use Only  
**Last Updated:** 2025-06-25

## 1. Purpose and Scope

This playbook defines the standardized response procedure for executive spear-phishing incidents targeting C-level personnel, finance leaders, or other high-value employees. It aligns with the MITRE ATT&CK framework, specifically techniques **T1566.001** (Spear-Phishing Attachment) and **T1566.002** (Spear-Phishing Link), and supports the **Initial Access** and **Credential Access** tactics.

**Scope:**
- Detected spear-phishing emails received by executives or their delegates.
- Suspected credential compromise via malicious links or attachments.
- Post-incident containment, eradication, recovery, and lessons learned.

**Objectives:**
1. Confirm whether the email is malicious and whether credentials were compromised.
2. Contain the threat by disabling compromised accounts, blocking IOCs, and isolating affected hosts.
3. Eradicate attacker persistence and restore normal operations.
4. Document findings and update detection rules to prevent recurrence.

## 2. Roles and Responsibilities

| Role | Responsibility | SLA |
|------|----------------|-----|
| SOC Analyst | Initial triage, IOC extraction, case creation | 15 minutes |
| Incident Response Lead | Declare severity, coordinate response, external communications | 30 minutes |
| Identity & Access Team | Disable/reset accounts, enforce MFA, review sign-in logs | 1 hour |
| Endpoint Security Team | Isolate hosts, collect forensic artifacts, remediate EDR alerts | 1 hour |
| Threat Intelligence | Enrich IOCs, assess actor motivation, update watchlists | 2 hours |
| Executive Assistant | Preserve email evidence, coordinate with executive | 30 minutes |

## 3. Severity Classification

| Severity | Criteria | Response Time | Example |
|----------|----------|---------------|---------|
| **P1 - Critical** | Credential confirmed compromised, MFA bypassed, or data exfiltration observed | 15 minutes | Executive clicked link and entered credentials; attacker accessed mailbox |
| **P2 - High** | Malicious email opened or attachment executed, no confirmed credential loss | 1 hour | Attachment opened but no outbound C2 observed |
| **P3 - Medium** | Suspected phishing, no user interaction | 4 hours | Email reported by user but not opened |
| **P4 - Low** | Spam or non-targeted phishing | 24 hours | Generic phishing not targeting executives |

**Decision Criteria:**
- If the user clicked a link and entered credentials → **P1**.
- If the user opened an attachment but no macros were enabled → **P2**.
- If the email was reported before any user action → **P3**.
- If the email contains no targeted executive context → **P4**.

## 4. Detection and Initial Triage

### 4.1 Detection Sources

Monitor the following data sources for executive-targeted phishing indicators:

- **Email gateway logs** (Microsoft 365 Defender, Proofpoint, Mimecast).
- **EDR telemetry** (CrowdStrike, SentinelOne, Microsoft Defender for Endpoint).
- **SIEM correlation rules** (Splunk, Elastic, Sentinel, QRadar).
- **User reports** via the phishing-report button or SOC inbox.
- **Threat intelligence feeds** for newly registered typosquat domains.

### 4.2 Initial Triage Checklist

1. [ ] Confirm the recipient is an executive or high-value target.
2. [ ] Identify the sender address, display name, and reply-to domain.
3. [ ] Extract URLs, attachments, and email headers.
4. [ ] Check if the email was opened, if links were clicked, or if attachments were executed.
5. [ ] Search SIEM/EDR for related user-agent strings, IP addresses, or file hashes.
6. [ ] Determine if credentials were entered or MFA prompts were triggered.

### 4.3 Sample Detection Queries

**Splunk — Office 365 suspicious login after phishing link:**

```spl
index=o365 sourcetype="o365:audit:exchange" Operation="UserLoggedIn" 
| eval time_bucket=round(_time/300)*300
| join time_bucket, UserId 
    [search index=email Subject="*urgent*" OR Subject="*invoice*" OR Subject="*wire transfer*" 
     | eval time_bucket=round(_time/300)*300]
| stats count by UserId, ClientIP, ApplicationId
```

**Sigma — PowerShell encoded command execution (common post-click payload):**

```yaml
title: Encoded PowerShell Execution After Phishing
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "-enc"
      - "-EncodedCommand"
      - "powershell -nop -w hidden"
  condition: selection
level: high
```

## 5. Containment

### 5.1 Immediate Containment Steps

1. **Disable the compromised account** and revoke all active sessions.
2. **Force a password reset** and require MFA re-enrollment.
3. **Block malicious IOCs**: sender domain, URL, file hash, and C2 IP at the proxy, firewall, and email gateway.
4. **Isolate affected endpoints** from the network if malware execution is confirmed.
5. **Preserve evidence**: capture email headers, full packet captures, and endpoint forensic images.

### 5.2 Containment Verification

| Check | Expected Result | Owner |
|-------|-----------------|-------|
| Account disabled in AD / Entra ID | `AccountEnabled = false` | Identity Team |
| Active sessions revoked | No active sessions in sign-in logs | Identity Team |
| IOCs blocked | URL/domain returns NXDOMAIN or block page | Network Team |
| Endpoint isolated | EDR shows "isolated" status | Endpoint Team |
| Mail rules reviewed | No unauthorized forwarding rules | SOC Analyst |

## 6. Eradication and Recovery

### 6.1 Eradication

1. Remove malicious emails from all mailboxes using eDiscovery search and purge.
2. Reimage compromised endpoints if persistent malware is detected.
3. Reset any application-specific passwords or API keys accessible from the compromised mailbox.
4. Remove attacker-created inbox rules, calendar invites, or Teams messages.

### 6.2 Recovery

1. Restore the affected account only after MFA re-enrollment and a clean EDR scan.
2. Monitor the account for 7 days for anomalous logins, mail rule changes, or data exfiltration.
3. Confirm business-critical operations (wire transfers, sensitive communications) were not impacted.

## 7. Metrics and Success Criteria

Measure response effectiveness using the following KPIs:

| Metric | Target | Measurement |
|--------|--------|-------------|
| Mean Time to Detect (MTTD) | < 15 minutes | Time from email delivery to alert creation |
| Mean Time to Respond (MTTR) | < 1 hour | Time from alert to containment of account |
| Mean Time to Contain (MTTC) | < 2 hours | Time from alert to IOC blocking and isolation |
| Phishing Simulation Click Rate | < 5% | Monthly executive phishing exercises |
| False Positive Rate | < 10% | Triage accuracy over 30-day rolling window |

**Success Criteria for Closing the Incident:**
- [ ] No unauthorized access observed for 7 days after recovery.
- [ ] All IOCs are blocked and documented.
- [ ] Affected user has completed refresher security awareness training.
- [ ] Detection rules are updated based on new TTPs observed.
- [ ] After-action review is completed within 5 business days.

## 8. Standards and Framework Alignment

This playbook aligns with the following industry standards:

- **NIST Cybersecurity Framework (CSF):** PR.DS, PR.IP, RS.AN, RS.CO, RS.MI, RS.IM
- **MITRE ATT&CK:** T1566.001, T1566.002, T1078, T1110, T1059, T1003
- **ISO 27001:** A.5.24, A.5.25, A.5.26, A.8.15
- **CIS Controls:** 6.3, 6.4, 6.5, 7.1, 7.2, 8.5, 8.6, 17.1, 17.2

## 9. Tools and Technologies

| Function | Tool | Usage |
|----------|------|-------|
| Email analysis | Microsoft 365 Defender, Proofpoint | Header extraction, quarantine, search and purge |
| SIEM | Splunk / Elastic / Sentinel | Correlation, alerting, hunting |
| EDR | CrowdStrike / SentinelOne / MDE | Endpoint isolation, process telemetry, remediation |
| Intel enrichment | VirusTotal, URLScan, MISP | IOC enrichment and scoring |
| Forensics | Velociraptor, KAPE | Artifact collection and analysis |
| Case management | ServiceNow, TheHive | Incident tracking and reporting |

## 10. Post-Incident Activities

1. Conduct an after-action review (AAR) within 5 business days.
2. Update this playbook and detection rules based on observed attacker TTPs.
3. Update executive security awareness materials with the specific lure used.
4. Share anonymized IOCs and TTPs with threat intelligence sharing groups.
5. Track remediation actions in the risk register until closure.

## 11. Appendix: Ciicerone Attack Red-Team Mapping

When this playbook is used to drive a purple-team exercise, Ciicerone Attack translates the scenario into the following autonomous tasks:

| Phase | MITRE Technique | Ciicerone Attack Task | Agent |
|-------|-----------------|--------------|-------|
| Reconnaissance | T1589 | Gather Target Identity Information | researcher |
| Weaponization | T1566.001 | Spear-Phishing Attachment | developer |
| Delivery | T1566.002 | Spear-Phishing Link | developer |
| Initial Access | T1078 | Valid Accounts Usage | executor |
| Credential Access | T1003 | Credential Dumping | executor |
| Execution | T1059 | Command and Scripting Interpreter | executor |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | executor |

This mapping ensures that the red-team exercise directly tests the controls documented in this playbook.
