# Vorsyghta — Blue Team End-to-End Demo

**Narrative: "Operation Sentinel"** — a SOC analyst's night shift, from first
dashboard check through confirmed intrusion, containment, forensics, and
post-incident handoff. Every `vorsyghta blue-team` subcommand is exercised
in a coherent storyline.

---

## What this demo covers

| # | Phase | CLI subcommands | MITRE ATT&CK |
|---|-------|-----------------|--------------|
| 1 | Pre-flight | `blue-team --help` | — |
| 2 | Dashboard | `blue-team dashboard` | — |
| 3 | SIEM | `siem connect`, `siem stats`, `siem search`, `siem alerts` | — |
| 4 | IDS | `ids rules`, `ids stats`, `ids inspect` (×6 packets) | T1110, T1190, T1505, T1071, T1048 |
| 5 | EDR | `edr stats`, `edr monitor` (×6 processes) | T1059, T1003, T1566, T1053 |
| 6 | Log Analysis | `logs parse` (×3 sources), `logs search` (×2) | T1110, T1548, T1190, T1185, T1083 |
| 7 | Threat Hunting | `hunt hypotheses`, `hunt search` (×4 + `--all`) | T1003, T1059, T1110, T1071 |
| 8 | Alert Triage | `triage alerts`, `triage stats` | — |
| 9 | Incident Response | `incident create` (×2), `show`, `execute` (×4), `list`, `report` | T1003, T1059, T1071, T1110, T1566 |
| 10 | Forensics | `forensics init`, `collect` (×3), `stats`, `report` | — |
| 11 | Final Dashboard | `blue-team dashboard` | — |

**Total: 11 phases, ~35 commands, 8 blue-team modules exercised.**

---

## Files

```
demos/blue_team_e2e/
├── README.md                       # this file
├── run_blue_team_demo.sh           # narrative script (offline-safe)
├── sample_logs/
│   ├── auth.log                    # Linux SSH auth — brute force → success → sudo
│   ├── apache_access.log           # Apache — SQLi, XSS, web shell, C2 beacon
│   └── windows_security.log        # Windows Event IDs 4624/4625/4688/4720/4732
└── output/                         # generated reports land here
    ├── incident_report.json
    └── forensics_report.json
```

---

## Run it

### Offline (no SIEM/SOC platform required)

```bash
bash demos/blue_team_e2e/run_blue_team_demo.sh
```

The script uses the built-in SIEM simulator, IDS detector, EDR agent, and
log analyzer. No external services are required. Each phase pauses briefly
so you can read the output.

### Live (no pauses, verbose)

```bash
bash demos/blue_team_e2e/run_blue_team_demo.sh --live
```

### With a real SIEM (Splunk / Elastic / Sentinel / QRadar)

```bash
SIEM_PLATFORM=splunk \
SIEM_URL=https://splunk.acme.corp:8089 \
SIEM_API_TOKEN=<token> \
  bash demos/blue_team_e2e/run_blue_team_demo.sh
```

When `SIEM_URL` is set, the `siem connect`, `siem search`, and `siem alerts`
commands will hit the real platform instead of the simulator.

---

## Narrative walkthrough

### 02:30 — Shift begins
You're the on-call SOC analyst for Acme Corp. The pager has been quiet.
You start with `blue-team dashboard` for a single-pane view of SIEM, IDS,
EDR, IR, threat hunting, and triage posture.

### 02:35 — SIEM review
You test SIEM connectivity (`siem connect`), review simulator statistics
(`siem stats`), and run a search for `"failed login"` over the last 24h
(`siem search`). In the lab there's no real SIEM, so the simulator reports
zero ingested events — but the commands demonstrate the production flow.

### 02:40 — IDS fires
The border sensor captured six suspicious packets overnight. You replay
each through `ids inspect`:

| Packet | IDS rule | MITRE |
|--------|----------|-------|
| SSH brute force from 185.220.101.34 | IDS-005 | T1110 |
| SQL injection `/admin/users?id=1 OR 1=1` | IDS-002 | T1190 |
| Web shell upload `shell.php eval(base64_decode` | IDS-006 | T1505 |
| C2 beacon `POST /api/beacon checkin heartbeat` | IDS-009 | T1071 |
| DNS exfiltration `Z3VzdGF2ZS...acme-attacker.com` | IDS-008 | T1048 |

Every packet triggers an alert with MITRE mapping and severity.

### 02:45 — EDR confirms endpoint compromise
The EDR agent on `web-01` reports six suspicious process executions via
`edr monitor`:

| Process | Pattern | MITRE |
|---------|---------|-------|
| `powershell -enc SGVsbG8=` | Encoded command | T1059 |
| `powershell -exec bypass -File stage2.ps1` | Execution policy bypass | T1059 |
| `mimikatz sekurlsa::logonpasswords` | Credential dumping | T1003 |
| `cmd /c powershell` (parent: winword.exe) | Office macro dropper | T1566 |
| `schtasks /create /tn Update` | Persistence | T1053 |
| `reg save HKLM\SAM` | Registry hive dumping | T1003 |

### 02:50 — Log analysis correlates the chain
You ingest three log sources via `logs parse`:

- **`auth.log`** (Linux auth) — 6 failed SSH logins from 185.220.101.34,
  followed by a successful login as `admin`, then `sudo cat /etc/shadow`
  and `sudo rm -rf /var/log/auth.log` (log clearing, T1070).
- **`apache_access.log`** — SQLi (`OR 1=1`), XSS (`<script>`), path
  traversal (`../../../../etc/passwd`), web shell (`shell.php?cmd=id`),
  and periodic C2 beaconing to `/api/beacon`.
- **`windows_security.log`** — Event ID 4625 (failed logon), 4624
  (success), 4688 (process creation: powershell, mimikatz, procdump),
  4720 (user created: `svc_backup`), 4732 (user added to Domain Admins).

`logs search` then filters for `"Failed password"` and `"sudo"` to
isolate the brute-force and privilege-escalation events.

### 02:55 — Threat hunting goes proactive
You enumerate the 8 pre-built MITRE ATT&CK hypotheses (`hunt hypotheses`)
and execute targeted hunts:

- `hunt search --technique T1003` — Credential Dumping
- `hunt search --technique T1059` — Command and Scripting Interpreter
- `hunt search --technique T1110` — Brute Force
- `hunt search --technique T1071` — C2 Application Layer Protocol
- `hunt search --all` — full sweep

### 03:00 — Alert triage scores the campaign P1
`triage alerts` runs every alert through the scoring engine: severity
weight + MITRE high-priority bonus + context. The credential-dumping
and C2 alerts land at **P1 (critical)** with recommended action
"Immediate response required. Escalate to IR team. Initiate containment."

### 03:05 — Incident Response playbook executes
You create a formal critical intrusion incident:

```bash
vorsyghta blue-team incident create \
    -t "Operation Sentinel — Credential Dumping & C2" \
    -s critical -c intrusion \
    --systems web-01,dc-01 \
    --mitre T1003,T1059,T1071,T1110 \
    --auto
```

The `--auto` flag auto-executes the automated containment steps
(isolate, block IPs, disable accounts, reset credentials). You then
manually execute the detection and eradication steps via
`incident execute`, and generate the post-incident report with
`incident report` → `output/incident_report.json`.

A second phishing incident is created to demonstrate the `phishing`
playbook (PHISH-001 through PHISH-008).

### 03:30 — Forensics preserves evidence
You open forensic case `CASE-SENTINEL-2026` and collect all three log
files as evidence via `forensics collect`. Each artifact gets an
artifact ID, MD5/SHA-256 hashes, and a chain-of-custody entry. The
case report is generated to `output/forensics_report.json`.

### 06:00 — Handoff
The final `blue-team dashboard` confirms containment. You hand off to
the day shift with the incident report, forensic case, and timeline
all preserved under `output/`.

---

## Expected output

The script prints a phase banner before each step, the exact command being
run, and a `[✓]` / `[✗]` marker. At the end:

```
=============================================================================
  Operation Sentinel — complete
=============================================================================
  Phases executed : 11
  Commands passed : 33
  Commands failed : 0
  Commands skipped: 0

  Artifacts written to: demos/blue_team_e2e/output
  -rw-r--r--  1 user  staff  2048 Jun 27 03:30 forensics_report.json
  -rw-r--r--  1 user  staff  4096 Jun 27 03:10 incident_report.json
=============================================================================
```

---

## Notes

- The script never aborts on a single command failure (`set -u` only,
  not `set -e`). A missing SIEM or a CLI quirk prints `[✗]` and
  continues so the full narrative always plays out.
- The `incident execute` steps depend on capturing the incident ID from
  `incident list` output. If the ID format changes, the script falls
  back to `<skip>` for those steps rather than crashing.
- All generated artifacts (incident report, forensic report) are
  tee'd to `output/` for offline review.
- This demo is complementary to `demos/end_to_end/run_e2e_demo.sh`,
  which covers the full platform (red team + blue team + intel + RAG +
  deploy + MCP). This demo goes deep on blue team only.
