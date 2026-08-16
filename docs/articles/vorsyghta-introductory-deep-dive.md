---
title: "Vorsyghta: An Agentic Cyber Range That Refuses to Lie to You"
subtitle: "A technical executive deep dive into QuantumindSSI's autonomous offense-defense platform — how it works, what it measures, and why 'no fabricated results' is an architectural invariant, not a slogan."
author: QuantumindSSI
tags: [cybersecurity, ai-agents, red-team, blue-team, purple-team, mitre-attack, event-sourcing, quantumindssi]
platform: Substack
status: draft
---

# Vorsyghta: An Agentic Cyber Range That Refuses to Lie to You

*Part of the QuantumindSSI cybersecurity portfolio.*

---

## The one-paragraph version (for the executive skimming on their phone)

Most "AI security" products are a chatbot bolted onto a scanner. **Vorsyghta** is different in kind: it is an **agentic cyber range** where an organisation's entire security operation runs as **coordinated teams** — Red attacks, Blue defends, Purple correlates, and five more colour teams govern, build, remediate, review, and score — all over a single **typed event bus** with a **replayable, event-sourced audit trail**. The design decision that matters most to a CISO is not the AI. It is a hard engineering invariant: **every result you see is measured, or it is explicitly flagged `simulation=true`.** Nondeterministic language-model output is structurally banned from the audit trail, the scoring path, identity, and compliance evidence. This article explains how that is enforced in code, not in copy.

---

## 1. Why we built it: the gap between "we tested security once" and "we continuously prove it"

The status quo for most enterprises is a once-a-year penetration test, an annual phishing simulation, and a SIEM that emits more alerts than any human can triage. Each of these is a **point-in-time snapshot** of a system that changes daily. The board asks "are we secure?" and the honest answer is "we were, in Q1, against the specific things the pen-tester happened to try."

Vorsyghta's thesis is that adversary simulation should be **continuous, autonomous, and measured** — and that the offense and defense sides should be closed into a single feedback loop rather than run as disconnected engagements six months apart. An LLM-driven attacker plans and adapts across the MITRE ATT&CK kill chain; the real defensive stack (SIEM/IDS/EDR) consumes those attacks and produces **detections that are recorded, not asserted**; a coaching layer correlates the two and tells you precisely where your coverage has holes.

The result is not a report. It is a **replayable timeline** a regulator can audit and a CISO can trend over time.

---

## 2. The mental model: eight colour teams, one substrate

The security industry already speaks in "colour teams." Vorsyghta takes that vocabulary literally and makes each colour a **first-class, coordinated capability** in a single platform. This is the "one-stop shop" ambition: instead of a red-team tool, a separate blue-team tool, and a spreadsheet to reconcile them, you run one exercise and every role participates.

| Team | Role | What it does | Status* |
|---|---|---|---|
| 🔴 **Red** | Offense | Adaptive, MITRE-mapped attack simulation on isolated VMs | Implemented |
| 🔵 **Blue** | Defense | Real-time detection, correlation, response (SIEM/IDS/EDR) | Implemented |
| 🟣 **Purple** | Integration / Coaching | Correlate Red vs Blue, find detection gaps, generate the After-Action Review | Implemented |
| 🟡 **Yellow** | Builders / Infrastructure | Provision, harden, validate the exercise sandbox | Implemented |
| 🟢 **Green** | Remediation / Automation | Turn findings into fixes and detection-as-code | Partial |
| 🟠 **Orange** | Code Review / Governance | Pre-release SAST, threat modelling, compliance mapping | Partial |
| ⚪ **White** | Governance / Referee | Rules of engagement, scope enforcement, halt authority | Implemented |
| ⚫ **Black** | Observation / Evaluation | Non-interfering scoring and benchmarking of every team | Partial |

*\*The status column is deliberate. A platform whose entire pitch is "we don't fabricate results" cannot fabricate its own maturity. "Implemented" means the module is wired end-to-end into the orchestrator; "Partial" means the engine exists but a primary responsibility or CLI/agent surface is still being wired. That honesty is the product.*

Beneath the colour teams sit the **functional teams** — the corporate org-chart mapping every CISO recognises: **SOC, DFIR, Vulnerability Management, SecOps/DevSecOps, AppSec, Cloud Security, IAM, GRC, Threat Intelligence, and TPRM.** These are not separate applications. They consume the same event bus and the same store, so a full-spectrum exercise and day-to-day SOC operations share one spine.

One command runs the whole loop:

```bash
vorsyghta exercise run --scenario templates/supply_chain_compromise.yaml --teams all
# White sets rules → Yellow provisions → Red attacks → Blue defends →
# Purple correlates & writes the AAR → Green remediates → Orange reviews the rebuild →
# White verifies scope → Black scores → every event persisted to a replayable store.
```

---

## 3. The three technical pillars

### Pillar 1 — Threat simulation & red-team operations

The offensive core is an **LLM-driven attack agent** that reasons in a ReAct-style loop: it plans a multi-stage attack, executes real tooling, observes the result, and refines its next move — mirroring the OODA loop of a real adversary rather than replaying a fixed script.

- An **attack orchestrator** maps MITRE techniques to concrete tools and extracts findings automatically.
- A **VM operator** drives real hypervisors — Proxmox, libvirt/KVM, Docker — with SSH/WinRM execution and snapshot management, so attacks run on **isolated infrastructure**, not production.
- Offensive tooling (nmap, nuclei, gobuster, hydra, sqlmap, Metasploit) is exposed to the agent through a **Model Context Protocol (MCP) server** — a clean, typed tool interface rather than shelling out to strings.
- **Safety controls** are not an afterthought: network isolation, command blocklists, rate limiting, scenario approval, and audit logging gate everything the agent can touch.

### Pillar 2 — Zero-day vulnerability research

Vorsyghta's discovery toolchain goes past *known*-vulnerability scanning into finding **new** bugs, and it hands those tools to AI agents through the same MCP interface:

- **Fuzzing:** AFL++ (coverage-guided), libFuzzer (in-process), honggfuzz (closed-source binaries), radamsa-based network-protocol fuzzing, ffuf for web, and schemathesis for OpenAPI/Swagger grammars.
- **Static analysis (SAST):** Semgrep (30+ languages, OWASP/CWE rulesets), CodeQL, and Bandit.
- **Binary analysis:** Ghidra headless decompilation, radare2 (ROP gadget discovery, mitigation checks), and binary diffing to locate silently patched vulnerabilities.
- **Crash triage pipeline:** collect → deduplicate by stack-trace signature → triage under GDB → classify exploitability → map to CWE → estimate CVSS → prioritise.
- **LLM-guided mutation:** grammar- and protocol-aware mutation, boundary-value and injection payload generation, plus *semantic* mutation — the model generates edge-case inputs that pass a parser but trip a bug.
- **Vulnerability reporting:** structured findings with CWE, CVSS, reproduction steps and PoC, exported as Markdown/JSON for client delivery with executive severity summaries.

This is the part that turns "we ran a scanner" into "we ran a coverage-guided campaign, triaged the crashes, and produced a disclosure-ready report."

### Pillar 3 — Blue team, intelligence & compliance

The defensive and assurance side is where the "measured, not asserted" invariant earns its keep:

- **Detection-as-code:** Sigma, Splunk, Elastic, and Microsoft Sentinel rules auto-generated from the TTPs the red team actually executed.
- **Threat hunting:** MITRE ATT&CK hunt hypotheses, CVE intelligence, and the CISA KEV catalogue.
- **SIEM integration:** Splunk, Elastic Security, Microsoft Sentinel, IBM QRadar.
- **Event-sourced audit trail:** an immutable, replayable event log — the substrate the next section is entirely about.
- **Compliance mapping:** PCI-DSS, NDPR, GDPR, SOC 2, ISO 27001, CBN — mapped with **evidence**, not keyword matching.

---

## 4. The engineering spine: why the audit trail can't be faked

Here is the part that separates Vorsyghta from the demo-ware crowd, and the reason it belongs in the QuantumindSSI cybersecurity portfolio rather than a hackathon repo.

**Everything flows through one typed event bus into an event-sourced store.**

```
White (RoE/approve) → Yellow (provision env) → Red (agent plans → executes real tools)
        │                                               │ publishes RedTeamAttackStageEvent
        │                                               ▼
        │                    Blue (real SIEM/IDS/EDR consuming published events)
        │                                               │ publishes BlueTeamAlertEvent (MEASURED)
        ▼                                               ▼
   Purple (correlate red stages vs blue alerts → detection gaps)
        │
        ▼
   Green (gaps → detection-as-code) · Orange (governance/compliance) · GRC (evidence)
        │
        ▼
   White (score from MEASURED alerts) → ExerciseResult (simulation flag propagated)

   ALL events ──▶ EventBus ──▶ PostgresEventStore  (single replayable audit trail)
```

Two properties make this trustworthy rather than decorative:

1. **Blue detections are real.** Blue's "detection" is the actual SIEM/IDS/EDR modules consuming the red team's published events — not a probability roll. (An earlier internal audit of the codebase found a placeholder that "detected" attacks with a hash coin-flip mislabeled as coming from the SIEM. That was ripped out. We document our own past sins because a security vendor that hides them has no business auditing yours.)
2. **Cross-team reads are database-backed.** Purple, GRC, the SOC, and every report read **persisted events from the store**, not in-memory dictionaries — so the data survives restarts and is genuinely auditable.

### The uniform team interface

Every team — whether it's an LLM agent or a deterministic service — implements one small protocol:

```python
class Team(Protocol):
    name: str
    kind: Literal["agent", "service"]
    async def run(self, ctx: ExerciseContext) -> TeamResult: ...
    def subscribe(self, bus: EventBus) -> None: ...   # optional event participation
```

- **Agent teams** wrap a typed `pydantic_ai.Agent` with a validated `result_type`, guardrailed tools, and a system prompt grounded in real context (findings, scenario, MITRE). If the model's output fails validation, the team returns `status="degraded"` — **it never fabricates data to save face.**
- **Service teams** are plain async classes with precondition/postcondition assertions and explicit error handling. No silent `except: pass`.

---

## 5. The decision most vendors get wrong: where AI is allowed to think

The lazy version of "agentic security" makes *everything* an LLM call. That is how you end up with an audit trail a regulator can't trust and a compliance report that hallucinates a control.

Vorsyghta draws a hard line — **the hybrid decision**:

> LLM reasoning is used **only** where the task genuinely reasons under uncertainty: offense planning, intel synthesis, hunt hypotheses, triage narrative, remediation and training content, code-review enrichment. **Every path a CISO relies on for assurance or compliance evidence is deterministic, typed, asserted, and replayable.** Nondeterminism never enters the audit trail, scoring, IAM, or compliance-evidence paths.

Concretely:

- **Agentic (reasons under uncertainty):** Red (attack planning), Purple (gap analysis), Orange (code-review enrichment), Threat Intelligence (synthesis).
- **Deterministic (must be auditable):** the event store, Black's scoring, IAM/RBAC, and GRC evidence — **zero LLM calls on these paths.**

This is the difference between a tool that is *impressive in a demo* and one that is *defensible in an audit*.

---

## 6. The non-negotiable invariants

These are enforced in the codebase, not aspirational:

1. **No fabricated results.** Detection and scoring derive from real module output. Any simulated segment sets `simulation=true`, which propagates to every downstream report and API response.
2. **Typed boundaries.** Pydantic models at every team and store seam; no raw dicts crossing boundaries.
3. **Deterministic audit path.** Event sourcing, scoring, IAM, and GRC evidence contain **zero** LLM calls.
4. **Fail-closed security.** JWT secrets have no default; API routers require auth; tool arguments are quoted/argv-escaped against injection.
5. **Disciplined code.** Functions bounded in length and complexity, assertions on pre/postconditions, every return value checked, bounded retries with backoff. (We hold to the NASA/JPL "Power of 10" and SWEBOK v4.0 as house engineering standards.)
6. **Tests are part of the deliverable.** Each team ships happy-path, boundary, and error-path tests; the exercise flow ships an integration test proving events persist and detection is measured.

---

## 7. Who gets value on day one

| Audience | What Vorsyghta gives them |
|---|---|
| **CISOs & Heads of Security** | A continuous, measurable posture baseline; detection coverage quantified against MITRE ATT&CK; executive-ready, trendable reports. |
| **Red Team Leads** | Autonomous, LLM-driven attack agents that plan, execute, and adapt across the full kill chain on isolated infrastructure. |
| **Blue Team / SOC Managers** | Auto-generated detection rules from the TTPs actually run against you, MITRE hunt hypotheses, and NIST 800-61 IR playbooks. |
| **Vulnerability Researchers** | Fuzzing, SAST, and binary analysis behind one MCP interface, with AI-guided mutation and automated crash triage. |
| **Compliance & GRC Leads** | An immutable, replayable event-sourced audit trail that satisfies regulators — no rebuilding timelines from scattered logs. |

---

## 8. How it's packaged

Vorsyghta is **open-core**. The simulation engine, CLI, YAML template system, LLM provider abstraction, and the zero-day discovery toolchain are open source under **Apache 2.0**. The intelligence stack, event-sourced audit trail, blue-team modules, multi-team orchestration, and enterprise integrations are licensed commercially.

It runs on Python 3.11+, speaks to OpenAI, Anthropic, OpenRouter, Azure OpenAI, or a local Ollama instance, and targets Proxmox/KVM/Docker as well as AWS, Azure, and GCP for VM infrastructure.

---

## 9. The honest roadmap

Consistent with the invariants above, here is what is *not* finished: the **Green** remediation engine and **Orange** pre-release code-review engine are being wired from their current governance/awareness forms toward their full mandates, and **Black's** dedicated CLI/agent surface is in progress (its evaluation engine already scores exercises inside the orchestrator). We publish this seam on purpose. A platform selling "measured, not fabricated" earns the right to that claim only by applying it to its own maturity first.

---

## Closing

Vorsyghta is QuantumindSSI's answer to a simple, uncomfortable question: **can you prove your defenses work, on demand, with evidence a regulator would accept?** Not "did a vendor say so last spring," but a replayable, measured, continuously-updated answer.

The AI is the interesting part. The **discipline around the AI** — the typed event bus, the deterministic audit path, the `simulation=true` flag that can never be hidden — is the part that makes it trustworthy.

*Follow this Substack for the engineering deep dives to come: the event-sourcing internals, the MCP tool interface, and how we red-team our own red team.*

*— The QuantumindSSI team*
