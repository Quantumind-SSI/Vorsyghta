# Vorsyghta — Business Logic Deep Dive

**Date:** 2026-08-16
**Method:** Traced real execution paths (not README claims). Classified each capability as
REAL / PARTIALLY-REAL / STUBBED / SIMULATED / FAKE-DATA with file:line evidence.
**Companion doc:** `AUDIT_STATE_2026-08-16.md` (security findings).

---

## TL;DR

Vorsyghta is a **real, well-engineered security *toolkit* bolted onto a *simulated demo orchestrator*.**
The low-level machinery (VM control, SSH exec, fuzzing/SAST/binary tooling, SIEM clients, RAG,
CVE/KEV feeds, quantum crypto scan) is largely genuine. But the **flagship "full-spectrum
red-vs-blue exercise" that a buyer would actually run is fabricated end-to-end**, the teams are
**disconnected silos**, and the advertised **"closed loop" / "immutable event-sourced audit trail"
is dead code**. The GRC/compliance layer is a keyword-match presented as an assessment.

**Does it produce true business value for a CISO today? — Not as an integrated platform.**
It has real *component* value (a fuzzing/recon/detection toolkit) but the headline product claims
are not backed by the running code.

---

## The central architectural problem: TWO parallel pipelines

| | Pipeline A — "Real toolkit" | Pipeline B — "Product/exercise flow" |
|---|---|---|
| Entry point | CLI subcommands (`vorsyghta red-team`, `vm`, `agent`, `blue-team`, `detect`) + MCP tools | `ExerciseOrchestrator.run_exercise()` / `POST /exercise` |
| Nature | Genuinely hits real infra/tools | Simulated, in-memory, fabricated results |
| Red team | Real `VMOperator` + SSH + nmap/nuclei/hydra + output parsing | Hardcoded 7-stage list; LLM writes *prose only*; silent `[FALLBACK CONTENT]` |
| Blue team | Real EDR patterns + real SIEM clients | **MD5 hash coin-flip** (`_detect_technique`) |
| Persistence | Red-team path writes `AttackSequenceRecord` to DB | In-memory dicts, lost on restart |

The impressive machinery in Pipeline A is **not wired into** Pipeline B, which is the flow the
README markets as the product. Pipeline B needs no Docker/Proxmox/targets/LLM keys and still
"succeeds" — proof it isn't doing real work.

---

## 1. RED TEAM — Does it work as it should? **NO (as delivered)**

| Stage | Verdict | Evidence |
|---|---|---|
| Attack planning (AI) | PARTIALLY-REAL | `vm/agent.py:144-233` real LLM prompt+parse; but single-shot, **not a ReAct loop** (`vm/agent.py:276-313`). Product flow uses hardcoded stages `core/simulator.py:89-243`. |
| VM control | REAL code / SIMULATED in product | Real Docker/Proxmox/libvirt operators `vm/operator.py:698-1213`; but exercise uses faked provisioning: `random`/`sleep`, fake IP `10.200.0.X` `core/yellow_team.py:432-490`. |
| Command execution | REAL (unused by product) | Real `asyncssh` `mcp/tools/vm_execute.py:104-169`, `operator.py:546-586`. Exercise flow never calls it. |
| Findings extraction | REAL parser / FABRICATED input | Real nmap/sqlmap parsing `core/attack_orchestrator.py:366-428`; but product flow feeds it LLM prose / empty IOCs. |
| Adaptive logic | SIMULATED | Single LLM verdict, not feedback-driven `vm/agent.py:437-482`. |

**Proof artifact:** `juice_shop_assessment_results.json` — a "vulnerability assessment" that
completed in **~16 seconds** (08:59:37→08:59:53) with **100% `[FALLBACK CONTENT]`**, `iocs: []`
everywhere, and hash-derived alerts. **No packet was ever sent to a target.**

**Known bug:** `mcp/server.py:99-102` calls `proxmox.connect()`/`get_version()` which don't exist
on `ProxmoxClient` — the MCP server's live Proxmox path is broken.

---

## 2. BLUE TEAM — Does it work as it should? **PARTIALLY; core automated path is FAKE**

| Capability | Verdict | Evidence |
|---|---|---|
| SIEM integration (Splunk/Elastic/Sentinel/QRadar) | **REAL** | Genuine aiohttp API calls + auth `integrations/siem_client.py:277-464`. |
| Detection-rule *syntax* (Sigma/SPL/KQL/ARM) | **REAL** | Valid translators `analytics/detection_rules/{sigma,splunk,elastic,sentinel}.py`. |
| Detection-rule *logic* (from TTPs) | **STUBBED** | Hardcoded per-category templates `generator.py:402-485`; `attack_vectors` used only for severity `generator.py:385`. |
| EDR detection logic | REAL | Pattern engine `defense/blue_team/edr_agent.py:73-260`. |
| EDR telemetry collection | **SIMULATED** | No psutil/ETW/Sysmon; fabricates `pid=1`,`attack.exe`,`192.0.2.100:4444` `edr_agent.py:349-390`. |
| Forensics (hash/custody) | REAL | Real MD5/SHA256 `forensics.py:304-320`. |
| Forensics (mem/disk/pcap capture) | PARTIALLY-REAL | Metadata registry only `forensics.py:107-201`. |
| Threat-hunt hypotheses | STUBBED | Canned list of 8, no LLM `intelligence/threat_hunting.py` / `threat_hunter.py:61-134`. |
| Threat-hunt execution | REAL (if SIEM connected) | `threat_hunter.py:188-217`; honest "simulated" label otherwise. |
| **Orchestrated exercise detection** | **FAKE** | `md5(technique_id) % 10 < 7`, labeled `source="siem"` — `exercise_orchestrator.py:270-274,253`. |

**Critical:** `BlueTeamBusIntegration` (the class that wires the *real* EDR/IDS/SIEM to the event
bus) is **instantiated nowhere in production** (confirmed: grep returns tests only). The real blue
team is orphaned; the automated exercise scores detection with a hash coin-flip.

---

## 3. OTHER TEAMS

| Area | Verdict | Evidence |
|---|---|---|
| Zero-day research: fuzz/SAST/binary/GDB triage | **REAL** | Real AFL++/libFuzzer/honggfuzz/semgrep/codeql/ghidra/radare2/GDB invocation + parsing `mcp/tools/discovery_tools.py:755-1581`, `research/crash_pipeline.py`. |
| CVSS/CWE mapping | REAL-computed (heuristic tables) | `crash_pipeline.py:480-512` — derived from real triage, not true CVSS vectors. |
| Threat intel: CVE + CISA-KEV | **REAL (live feeds)** | Live NVD + CISA KEV `intelligence/threat_hunting.py:167-309`. |
| Threat intel: OSINT + exploit enrichment | **STUBBED/FAKE** | LinkedIn/WHOIS/news placeholders, fabricated subdomains, hardcoded threat-intel object `intelligence/services.py:96-456,363-402`. |
| Compliance mapping (PCI/SOC2/ISO/GDPR/HIPAA) | **STUBBED** | Substring keyword match; "compliant" if >50% keywords present `core/playbook_validator.py:330-851`; GDPR status hardcoded `"compliant"` `intelligence/compliance.py:345`. |
| Compliance: NDPR / CBN (README-claimed) | **ABSENT** | Zero matches in non-test code. |
| Analytics | REAL but **DEAD CODE** | Real sklearn + aggregation `analytics/__init__.py:186-726`; imported/called nowhere; in-memory only. |
| RAG | **REAL** | FAISS/Neo4j/Chroma + real embeddings `rag/vectorstore.py:150-967`; wired to API. |
| Quantum crypto scan | **REAL** | Real openssl/ssh-keyscan subprocess `quantum/crypto_scanner.py:177-247`. |
| Quantum attack modeling | PARTIALLY-REAL | Academic qubit formulas, hardcoded confidence `quantum/vulnerability_analyzer.py:190-291`. |

---

## 4. CROSS-TEAM DATA TRANSFER — **DISCONNECTED SILOS**

The README claims a closed loop offense↔defense↔intelligence over an "immutable PostgreSQL
event log with replay." In code:

- **Event store is dead:** `PostgresEventStore.create()` appears **only in docstrings/tests**
  (`postgres_event_store.py:108,150`). Every `EventBus()` is built with **no** `event_store`
  (`exercise_orchestrator.py:94`, `api/routers/exercise.py:46`), so `_persist_event` never runs.
  Nothing is written to any event log.
- **Three unrelated audit/event mechanisms**, none shared: `PostgresEventStore` (tests only),
  `EventStore` (tests only), `audit_logger` → `MemoryAuditSink` (in-memory, no DB sink). The
  `AuditEventRecord` table is never written.
- **Red→Blue is absent/manual:** the orchestrator's blue team is the hash coin-flip; the real
  detection generator (`cli/detect.py`) takes a **manually typed technique ID** or a human-exported
  trace file (`detect from-trace`). Defense/analytics code does **zero DB reads** (no `get_session`).
- **Red/Blue→Reporting** happens only as **in-memory args within one `run_exercise()` call**;
  nothing persists for intelligence/compliance to consume later.
- **Orchestrator** is a single-process, in-memory demo chain (`_active_exercises` dict) using the
  fake blue team; results are lost on restart and not shared across workers.

**Classification: DISCONNECTED-SILOS.** The "loop" is mocked (orchestrator), manual (from-trace),
or points at a persistence layer that is never instantiated.

---

## 5. Business value for a CISO — honest assessment

### What is genuinely valuable today (component-level)
- **Vulnerability research toolkit** — real fuzzing/SAST/binary-analysis/crash-triage orchestration
  over SSH'd VMs. Usable by a skilled operator via CLI/MCP.
- **CVE + CISA-KEV intelligence** — live, correctly parsed feeds.
- **SIEM connectors** — real, reusable Splunk/Elastic/Sentinel/QRadar clients.
- **Detection-rule *formatting*** — valid Sigma/SPL/KQL emitters (content still needs a human).
- **RAG knowledge base** and **quantum/PQC crypto inventory scanner** — real, wired.

### What does NOT deliver the advertised value
- **"Autonomous red-vs-blue exercises with detection scoring"** — the default flow **fabricates**
  attacks (fallback prose) and **fabricates** detection (hash coin-flip). Any report/score/"detection
  rate" from `run_exercise` / the exercise API is **not measured** and must not be shown to a
  customer or auditor.
- **"Closed loop / continuous purple-team"** — teams are siloed; no shared persistent substrate.
- **"Immutable event-sourced audit trail for compliance"** — dead code; nothing is persisted.
- **Compliance mapping (PCI/SOC2/ISO/GDPR/NDPR/CBN)** — keyword match that trends to "compliant";
  NDPR/CBN don't exist. **Not audit-grade; a liability if presented as compliance evidence.**
- **Analytics dashboards** — real math, but unwired dead code with no data source.

### Risk framing for the CISO
1. **Integrity/trust risk (highest):** the product's headline metric (detection rate) is
   fabricated. Presenting it to a board/auditor/customer is a material misrepresentation risk.
2. **Security risk:** see companion doc — hardcoded JWT fallback (C1), unauthenticated CRUD
   routers (C2), command injection in MCP attack tools (C3/C4). An offensive tool with RCE and
   auth bypass is itself an attack surface.
3. **Compliance risk:** compliance output is not defensible evidence.

### Verdict
**Does this application produce true business value? — Partially, and not where it's marketed.**
There is real engineering worth (a fuzzing/recon/detection *toolkit* and live threat feeds), but
the **integrated "agentic purple-team platform" the README sells does not function as claimed**:
the flagship exercise is simulated, the teams don't exchange data, the audit loop is dead code, and
the compliance layer is cosmetic. As-is it is a **promising component library / demo**, **not a
trustworthy platform a CISO can rely on for real assurance or compliance.**

---

## 6. What it would take to make the claims true (high level)
1. Wire `ExerciseOrchestrator` to the **real** `AIAttackAgent`/`VMOperator`/tool server and to
   `BlueTeamBusIntegration` — delete `_detect_technique` hash flip.
2. Instantiate `EventBus(event_store=PostgresEventStore.create(...))` and add a `DatabaseAuditSink`
   so the event-sourced trail is actually persisted and replayable.
3. Make defense/analytics **read persisted red-team findings** from the DB (real red→blue handoff).
4. Replace compliance keyword-matching with real control-ID mapping + evidence, or drop the claim.
5. Fix the security Criticals (C1–C4) before any external exposure.
6. Gate all "results/score/detection-rate" outputs on a real-vs-simulation flag so fabricated runs
   can never be presented as measured.
