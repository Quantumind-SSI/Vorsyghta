#!/usr/bin/env bash
# =============================================================================
# Vorsyghta — Blue Team End-to-End Demo
# =============================================================================
# Narrative: "Operation Sentinel" — a SOC analyst's night shift
#
# An analyst at Acme Corp's SOC works through a real intrusion from initial
# detection through forensics and post-incident review, exercising every
# `vorsyghta blue-team` subcommand along the way:
#
#   dashboard, siem (connect/search/alerts/stats),
#   ids (inspect/rules/stats), edr (monitor/stats),
#   incident (create/show/execute/list/report),
#   hunt (search/hypotheses), logs (parse/search),
#   triage (alerts/stats), forensics (init/collect/report/stats)
#
# The demo is offline-safe (no SIEM/SOC platform required). When SIEM_URL is
# set, the SIEM/search/alerts commands will hit the real platform instead.
#
# Usage:
#   bash demos/blue_team_e2e/run_blue_team_demo.sh            # offline
#   bash demos/blue_team_e2e/run_blue_team_demo.sh --live      # verbose, no pause
#   SIEM_URL=https://splunk.acme.corp:8089 \
#     bash demos/blue_team_e2e/run_blue_team_demo.sh           # real SIEM
# =============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLE_LOGS="${SCRIPT_DIR}/sample_logs"
OUTPUT_DIR="${SCRIPT_DIR}/output"
mkdir -p "${OUTPUT_DIR}"

# --- CLI selection -----------------------------------------------------------
# Prefer the `vorsyghta` entry point; fall back to `python -m vorsyghta`.
if command -v vorsyghta >/dev/null 2>&1; then
    CLI="vorsyghta"
else
    CLI="python -m vorsyghta"
fi

# --- Flags -------------------------------------------------------------------
LIVE=0
for arg in "$@"; do
    case "$arg" in
        --live) LIVE=1 ;;
        -h|--help)
            sed -n '2,28p' "${BASH_SOURCE[0]}"
            exit 0
            ;;
    esac
done

# --- Helpers -----------------------------------------------------------------
PHASE=0
PASS=0
FAIL=0
SKIPPED=0

banner() {
    PHASE=$((PHASE + 1))
    echo
    echo "============================================================================="
    echo "  PHASE ${PHASE} — $1"
    echo "============================================================================="
}

run() {
    # run <label> <command...>
    local label="$1"; shift
    echo
    echo "── ${label} ───────────────────────────────────────────────────────────"
    echo "\$ $*"
    echo
    if [ "$LIVE" -eq 0 ]; then
        # Brief pause so the user can read each step.
        read -r -t 1 -p "" 2>/dev/null || true
    fi
    if "$@"; then
        PASS=$((PASS + 1))
        echo "  [✓] ${label}"
    else
        FAIL=$((FAIL + 1))
        echo "  [✗] ${label} (non-fatal — continuing)"
    fi
}

run_skip() {
    local label="$1"; shift
    echo
    echo "── ${label} ───────────────────────────────────────────────────────────"
    echo "  [skip] requires external dependency; not run in offline mode"
    SKIPPED=$((SKIPPED + 1))
}

narrate() {
    echo
    echo "── narrative ──────────────────────────────────────────────────────────"
    echo "$1"
    echo "────────────────────────────────────────────────────────────────────────"
}

# --- Pre-flight --------------------------------------------------------------
banner "Pre-flight — SOC shift begins"
narrate "It's 02:30 UTC. You're the on-call SOC analyst for Acme Corp.
The pager has been quiet, but the SIEM dashboard is your first stop
to confirm the estate is healthy before you grab coffee."

run "Check Vorsyghta blue-team CLI is available" \
    ${CLI} blue-team --help

# =============================================================================
# PHASE 2 — Dashboard
# =============================================================================
banner "Blue Team Dashboard — situational awareness"
narrate "You pull up the unified blue-team dashboard to get a single-pane
view of SIEM, IDS, EDR, IR, threat hunting, and triage posture."

run "Show blue-team dashboard" \
    ${CLI} blue-team dashboard

# =============================================================================
# PHASE 3 — SIEM
# =============================================================================
banner "SIEM — log aggregation, search, alerts, stats"
narrate "The dashboard shows the SIEM simulator is active (no Splunk/Elastic
configured in the lab). You test connectivity anyway — in production this
would hit the real SIEM — then review stats and attempt a search."

run "Test SIEM connectivity (will report 'not configured' offline)" \
    ${CLI} blue-team siem connect

run "Show SIEM simulator statistics" \
    ${CLI} blue-team siem stats

run "Search SIEM for 'failed login' (offline: no events ingested)" \
    ${CLI} blue-team siem search --query '"failed login"' --hours 24 --limit 10

run "List SIEM alerts (offline: requires SIEM_URL)" \
    ${CLI} blue-team siem alerts --limit 10

# =============================================================================
# PHASE 4 — IDS
# =============================================================================
banner "IDS/IPS — network detection rules and packet inspection"
narrate "You pivot to the IDS engine. First you enumerate the loaded
Snort/Suricata-style rules, then replay a series of suspicious packets
captured by the border sensor to confirm detections fire."

run "List IDS detection rules" \
    ${CLI} blue-team ids rules

run "Show IDS statistics" \
    ${CLI} blue-team ids stats

run "Inspect SSH brute-force packet (T1110)" \
    ${CLI} blue-team ids inspect \
        --protocol tcp --src-ip 185.220.101.34 --src-port 49152 \
        --dest-ip 10.0.1.10 --dest-port 22 \
        --payload "Failed password for invalid user admin"

run "Inspect SQL injection packet (T1190)" \
    ${CLI} blue-team ids inspect \
        --protocol tcp --src-ip 185.220.101.34 --src-port 49160 \
        --dest-ip 10.0.1.10 --dest-port 80 \
        --payload "GET /admin/users?id=1 OR 1=1 HTTP/1.1"

run "Inspect web shell upload packet (T1505)" \
    ${CLI} blue-team ids inspect \
        --protocol tcp --src-ip 185.220.101.34 --src-port 49170 \
        --dest-ip 10.0.1.10 --dest-port 80 \
        --payload "POST /upload.php shell.php eval(base64_decode"

run "Inspect C2 beacon packet (T1071)" \
    ${CLI} blue-team ids inspect \
        --protocol tcp --src-ip 10.0.1.10 --src-port 49180 \
        --dest-ip 185.220.101.34 --dest-port 443 \
        --payload "POST /api/beacon checkin heartbeat"

run "Inspect DNS exfiltration packet (T1048)" \
    ${CLI} blue-team ids inspect \
        --protocol udp --src-ip 10.0.1.10 --src-port 53000 \
        --dest-ip 8.8.8.8 --dest-port 53 \
        --payload "Z3VzdGF2ZS1leGZpbHRyYXRlZC1kYXRh.acme-attacker.com"

# =============================================================================
# PHASE 5 — EDR
# =============================================================================
banner "EDR — endpoint process, file, and behavior monitoring"
narrate "The IDS confirms malicious traffic from 185.220.101.34. You
escalate to endpoint telemetry. The EDR agent on web-01 reports a
suspicious PowerShell encoded command spawned by an Office parent
process — a classic macro-dropper pattern (T1566 -> T1059)."

run "Show EDR statistics" \
    ${CLI} blue-team edr stats

run "Monitor suspicious PowerShell encoded command (T1059)" \
    ${CLI} blue-team edr monitor \
        --process powershell.exe --pid 4012 \
        --cmd "powershell -enc SGVsbG8gV29ybGQ=" \
        --user admin

run "Monitor PowerShell execution-policy bypass (T1059)" \
    ${CLI} blue-team edr monitor \
        --process powershell.exe --pid 4013 \
        --cmd "powershell -exec bypass -File C:\\Temp\\stage2.ps1" \
        --user admin

run "Monitor Mimikatz invocation (T1003)" \
    ${CLI} blue-team edr monitor \
        --process mimikatz.exe --pid 4014 \
        --cmd "mimikatz.exe sekurlsa::logonpasswords" \
        --user admin

run "Monitor Office app spawning shell (T1566)" \
    ${CLI} blue-team edr monitor \
        --process cmd.exe --pid 4015 \
        --cmd "cmd /c powershell -exec bypass -File C:\\Temp\\drop.ps1" \
        --user admin --parent winword.exe

run "Monitor scheduled task creation for persistence (T1053)" \
    ${CLI} blue-team edr monitor \
        --process schtasks.exe --pid 4016 \
        --cmd "schtasks /create /tn Update /tr C:\\Temp\\beacon.exe /sc minute" \
        --user admin

run "Monitor registry hive dumping (T1003)" \
    ${CLI} blue-team edr monitor \
        --process reg.exe --pid 4017 \
        --cmd "reg save HKLM\\SAM C:\\Temp\\sam.hive" \
        --user admin

# =============================================================================
# PHASE 6 — Log Analysis
# =============================================================================
banner "Log Analysis — multi-source parsing and correlation"
narrate "With endpoint confirmation in hand, you ingest the three log
sources captured overnight: Linux auth.log, Apache access log, and
Windows security events. The LogAnalyzer parses each, normalizes them,
and runs cross-source correlation to surface the attack chain."

run "Parse Linux auth.log (brute force -> success -> sudo)" \
    ${CLI} blue-team logs parse \
        --file "${SAMPLE_LOGS}/auth.log" \
        --type linux_auth --host web-01

run "Parse Apache access log (SQLi, XSS, web shell, beacon)" \
    ${CLI} blue-team logs parse \
        --file "${SAMPLE_LOGS}/apache_access.log" \
        --type apache_access --host web-01

run "Parse Windows security events (4625, 4688, 4732)" \
    ${CLI} blue-team logs parse \
        --file "${SAMPLE_LOGS}/windows_security.log" \
        --type windows_security --host dc-01

run "Search parsed auth logs for 'Failed password'" \
    ${CLI} blue-team logs search \
        --query "Failed password" \
        --file "${SAMPLE_LOGS}/auth.log" --type linux_auth

run "Search parsed auth logs for 'sudo'" \
    ${CLI} blue-team logs search \
        --query "sudo" \
        --file "${SAMPLE_LOGS}/auth.log" --type linux_auth

# =============================================================================
# PHASE 7 — Threat Hunting
# =============================================================================
banner "Threat Hunting — MITRE ATT&CK hypotheses"
narrate "Now you go proactive. You enumerate the pre-built hunt hypotheses
mapped to MITRE ATT&CK, then execute targeted hunts for the techniques
the IDS and EDR already flagged: credential dumping (T1003), command
scripting (T1059), and brute force (T1110)."

run "List available hunt hypotheses" \
    ${CLI} blue-team hunt hypotheses

run "Hunt for T1003 (Credential Dumping)" \
    ${CLI} blue-team hunt search --technique T1003

run "Hunt for T1059 (Command and Scripting Interpreter)" \
    ${CLI} blue-team hunt search --technique T1059

run "Hunt for T1110 (Brute Force)" \
    ${CLI} blue-team hunt search --technique T1110

run "Hunt for T1071 (C2 Application Layer Protocol)" \
    ${CLI} blue-team hunt search --technique T1071

run "Execute all hunt hypotheses" \
    ${CLI} blue-team hunt search --all

# =============================================================================
# PHASE 8 — Alert Triage
# =============================================================================
banner "Alert Triage — prioritize, suppress false positives"
narrate "The detection stack has fired dozens of alerts. You run them
through the triage engine to score by priority (P1-P4), flag likely
false positives (e.g. Nessus scanner traffic), and surface the top
P1 alerts that need immediate IR escalation."

run "Get triaged alerts sorted by priority" \
    ${CLI} blue-team triage alerts --limit 20

run "Show triage statistics" \
    ${CLI} blue-team triage stats

# =============================================================================
# PHASE 9 — Incident Response
# =============================================================================
banner "Incident Response — NIST 800-61 playbook execution"
narrate "Triage confirms a P1 critical incident: confirmed credential
dumping and C2 beaconing. You create a formal incident, auto-execute
the automated containment steps (isolate, block IPs, disable accounts),
then walk through the remaining manual steps one at a time."

INCIDENT_ID=""

run "Create critical intrusion incident with auto-execution" \
    ${CLI} blue-team incident create \
        -t "Operation Sentinel — Credential Dumping & C2" \
        -s critical -c intrusion \
        --systems web-01,dc-01 \
        --mitre T1003,T1059,T1071,T1110 \
        -d "Confirmed brute force from 185.220.101.34 followed by credential dumping and C2 beaconing on web-01." \
        --auto

# Capture the incident ID from the previous command's output.
INCIDENT_ID="$(${CLI} blue-team incident list --severity critical 2>/dev/null \
    | grep -oE 'INC-[0-9]{8}-[0-9]+' | head -1)"
if [ -z "${INCIDENT_ID}" ]; then
    # Fallback: take the first incident listed.
    INCIDENT_ID="$(${CLI} blue-team incident list 2>/dev/null \
        | grep -oE 'INC-[0-9]{8}-[0-9]+' | head -1)"
fi

echo
echo "  Captured incident ID: ${INCIDENT_ID:-<none>}"

if [ -n "${INCIDENT_ID}" ]; then
    run "Show incident details and playbook" \
        ${CLI} blue-team incident show "${INCIDENT_ID}"

    run "Execute detection step IR-001 (Identify entry point)" \
        ${CLI} blue-team incident execute "${INCIDENT_ID}" IR-001 \
            --result "Entry via SSH brute force from 185.220.101.34 (T1110)"

    run "Execute containment step IR-003 (Isolate affected systems)" \
        ${CLI} blue-team incident execute "${INCIDENT_ID}" IR-003 \
            --result "web-01 and dc-01 network-isolated via EDR quarantine"

    run "Execute containment step IR-004 (Block attacker IPs)" \
        ${CLI} blue-team incident execute "${INCIDENT_ID}" IR-004 \
            --result "185.220.101.34 and 45.155.205.10 added to edge firewall blocklist"

    run "Execute eradication step IR-008 (Reset credentials)" \
        ${CLI} blue-team incident execute "${INCIDENT_ID}" IR-008 \
            --result "Password reset forced for admin, devops, deploy, svc_backup"

    run "List all incidents" \
        ${CLI} blue-team incident list

    run "Generate post-incident report (JSON)" \
        ${CLI} blue-team incident report "${INCIDENT_ID}" \
        2>&1 | tee "${OUTPUT_DIR}/incident_report.json"
else
    run_skip "Show incident details (no incident ID captured)"
    run_skip "Execute IR steps (no incident ID captured)"
    run_skip "Generate post-incident report (no incident ID captured)"
fi

# Create a second incident to demonstrate the phishing playbook.
run "Create phishing incident (PHISH playbook)" \
    ${CLI} blue-team incident create \
        -t "Spear-phish landing page delivered to CFO" \
        -s high -c phishing \
        --systems mail-01,web-01 \
        --mitre T1566,T1071 \
        -d "CFO clicked weaponized attachment; beacon observed to 185.220.101.34." \
        --auto

run "List incidents filtered by status 'investigating'" \
    ${CLI} blue-team incident list --status investigating

# =============================================================================
# PHASE 10 — Forensics
# =============================================================================
banner "Digital Forensics — evidence collection and timeline"
narrate "With containment underway, you open a forensic case to preserve
evidence for legal and post-incident review. You collect the auth.log
and Apache access log as evidence (with hash chain-of-custody), then
generate the case report."

CASE_ID="CASE-SENTINEL-2026"

run "Initialize forensic case" \
    ${CLI} blue-team forensics init --case-id "${CASE_ID}"

run "Collect auth.log as forensic evidence" \
    ${CLI} blue-team forensics collect \
        --file "${SAMPLE_LOGS}/auth.log" --source web-01

run "Collect Apache access log as forensic evidence" \
    ${CLI} blue-team forensics collect \
        --file "${SAMPLE_LOGS}/apache_access.log" --source web-01

run "Collect Windows security log as forensic evidence" \
    ${CLI} blue-team forensics collect \
        --file "${SAMPLE_LOGS}/windows_security.log" --source dc-01

run "Show forensics statistics" \
    ${CLI} blue-team forensics stats

run "Generate forensic case report (JSON)" \
    ${CLI} blue-team forensics report --case-id "${CASE_ID}" \
    2>&1 | tee "${OUTPUT_DIR}/forensics_report.json"

# =============================================================================
# PHASE 11 — Final dashboard
# =============================================================================
banner "Final Dashboard — post-incident posture"
narrate "Dawn breaks. Containment, eradication, and evidence collection
are complete. You pull the dashboard one last time to confirm the
estate has stabilized before handing off to the day shift."

run "Show final blue-team dashboard" \
    ${CLI} blue-team dashboard

# =============================================================================
# Summary
# =============================================================================
echo
echo "============================================================================="
echo "  Operation Sentinel — complete"
echo "============================================================================="
echo "  Phases executed : ${PHASE}"
echo "  Commands passed : ${PASS}"
echo "  Commands failed : ${FAIL}"
echo "  Commands skipped: ${SKIPPED}"
echo
echo "  Artifacts written to: ${OUTPUT_DIR}"
ls -la "${OUTPUT_DIR}" 2>/dev/null || true
echo
echo "  Narrative recap:"
echo "   - 02:30  Shift starts; dashboard healthy"
echo "   - 02:35  SIEM stats reviewed; no real SIEM in lab"
echo "   - 02:40  IDS fires on SSH brute force, SQLi, web shell, C2 beacon, DNS exfil"
echo "   - 02:45  EDR flags PowerShell -enc, Mimikatz, Office->cmd, schtasks, reg save"
echo "   - 02:50  Log analysis correlates auth.log + Apache + Windows events"
echo "   - 02:55  Threat hunting confirms T1003, T1059, T1110, T1071"
echo "   - 03:00  Triage scores the campaign P1 critical"
echo "   - 03:05  Incident created; NIST playbook auto-executes containment"
echo "   - 03:30  Forensic case opened; logs collected with chain of custody"
echo "   - 06:00  Final dashboard confirms containment; handoff to day shift"
echo "============================================================================="
