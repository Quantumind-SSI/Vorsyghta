# Recursive SAST Pipeline vs. Current Application Plan

## Executive Summary

The `security-audit/` recursive prompting pipeline aligns directly with the Vorsyghta project's **Orange Team** mandate and supports the **Yellow Team** and **Compliance** workstreams defined in the current bank-pilot-readiness plan. It is a ready-to-integrate implementation of the LLM-enriched SAST and STRIDE threat-modeling capability that the plan currently schedules as a **Phase 3 (Weeks 15–16)** deliverable for Lanre Shittu.

## Where the Plan Already Expects This Work

### Orange Team (Phase 3, Weeks 15–16)

| Plan Requirement | Pipeline Capability | Status |
|-------------------|---------------------|--------|
| `vorsyghta/core/code_review_engine.py` — LLM-enriched SAST | `security-audit/pipeline.py` Stage 3 recursive audit loop | Implemented |
| STRIDE threat modeling from architecture specs | `security-audit/pipeline.py` Stage 2 STRIDE threat model | Implemented |
| Attack surface mapping and reduction recommendations | `security-audit/pipeline.py` Stage 1 architecture + user-flow recon | Implemented |
| Dependency vulnerability scanning | `security-audit/pipeline.py` Stage 1 SBOM + Trivy audit | Implemented |
| Maps findings to MITRE ATT&CK techniques | Pipeline threat model output can be extended to MITRE mapping | Partial |
| `vorsyghta/cli/orange_team.py` commands | Not yet integrated into CLI | Gap |
| `vorsyghta/agents/orange_team_agent.py` | Not yet integrated into agent framework | Gap |

### Yellow Team (Phase 3, Weeks 15–18)

| Plan Requirement | Pipeline Capability | Status |
|-------------------|---------------------|--------|
| IaC scanning (Terraform/Docker Compose) | Pipeline recon scans repository; extendable to IaC rules | Partial |
| CIS benchmark checks | Not yet implemented | Gap |
| Infrastructure hardening validation | Trivy SBOM audit covers dependency CVEs; add CIS + infrastructure rules | Gap |

### Compliance / White Team (Phase 3, Weeks 15–18)

| Plan Requirement | Pipeline Capability | Status |
|-------------------|---------------------|--------|
| Compliance report generator (`intelligence/compliance_report.py`) | Pipeline Stage 4 generates markdown + JSON audit reports | Implemented |
| Framework-mapped controls (GDPR/PCI-DSS/SOC2/HIPAA) | Currently generic; needs framework-specific mapping layer | Gap |
| Tamper-evident audit trail | Pipeline output is JSON/MD; not hash-chained | Gap |

## Direct Mapping to Current Plan Blockers

| Blocker | Pipeline Relevance | How It Helps |
|---------|-------------------|--------------|
| P0-4 — No API auth/RBAC | STRIDE analysis + Semgrep rules for auth gaps | Generates findings for missing auth checks, wildcard CORS |
| P0-5 — No tamper-evident audit | Pipeline report generation can be extended to include audit verification | Produces audit-style findings; needs hash-chain integration |
| P0-6 — No DB persistence | Recon identifies DB model gaps; Semgrep rules detect in-memory state | Flags unbounded `List[]` buffers and missing `tenant_id` columns |
| P0-7 — External HTTP calls | User-flow recon + STRIDE Information Disclosure | Detects air-gap bypass patterns and external requests |
| P2-3 — No rate limiting / secret management | STRIDE DoS + Information Disclosure | Generates findings for missing rate limits and secret handling |

## What the Pipeline Adds Beyond the Current Plan

1. **Recursive audit loop** — The plan calls for a single code-review engine; the pipeline adds multi-pass clean-context analysis, which increases recall and reduces anchor bias.
2. **Semgrep-in-the-loop** — The plan lists Semgrep as a tool to integrate; the pipeline already generates Semgrep rules from the STRIDE model and runs them alongside the LLM.
3. **Trivy SBOM audit** — The plan mentions dependency scanning but does not explicitly mandate SBOM generation; the pipeline includes it as a recon artifact.
4. **Deterministic + probabilistic combination** — The methodology explicitly separates high-recall candidate generation from high-precision triage, which the plan does not yet formalize.
5. **Reusable four-stage methodology** — The pipeline is a documented, repeatable methodology (`README.md`) rather than a single component.

## Gaps vs. the Plan

| Gap | Plan Owner | Recommended Action |
|-----|-----------|-------------------|
| Not wired into `vorsyghta` CLI or agent framework | Lanre | Wrap `pipeline.py` as `vorsyghta/cli/orange_team.py` and `vorsyghta/agents/orange_team_agent.py` |
| No CIS benchmark / infrastructure hardening checks | Omolara | Add Semgrep rules + recon modules for Terraform/Docker Compose/K8s manifests |
| No framework-specific compliance mapping (GDPR/PCI-DSS/SOC2/HIPAA) | Jeremiah | Extend Stage 4 triage to map findings to control frameworks |
| No hash-chain tamper-evidence on reports | Jeremiah | Integrate `DatabaseAuditSink` hash-chain output with pipeline reports |
| No MITRE ATT&CK mapping of findings | Lanre | Add `vorsyghta/intelligence/mitre_attack.py` lookups to threat model stage |
| No CI/CD integration | DevRel | Add GitHub Actions workflow to run pipeline nightly or on PR |
| Local LLM calls are currently stubbed | Lanre | Replace `_call_local_llm()` with Ollama/LM Studio integration |

## Recommended Integration Path

### Option A: Keep as Standalone Audit Tool (Immediate Value)

Use the pipeline as-is for manual security audits before bank pilot. It can run independently and feed findings into the backlog without modifying the application code.

**When:** Weeks 5–8 (Phase 1 security hardening) to identify P0/P1/P2 gaps early.

### Option B: Integrate into Orange Team (Aligns with Plan)

Convert the pipeline into the planned `vorsyghta/core/code_review_engine.py` module.

**Steps:**
1. Move `security-audit/pipeline.py` logic into `vorsyghta/core/code_review_engine.py`.
2. Add `vorsyghta/cli/orange_team.py` commands that wrap the pipeline stages.
3. Add `vorsyghta/agents/orange_team_agent.py` for agent-framework integration.
4. Store pipeline outputs in PostgreSQL via `vorsyghta/db/models/compliance.py` (Phase 3).

**When:** Weeks 15–16 (Phase 3 Orange Team).

### Option C: Shift-Left in CI/CD (Recommended for Pilot Quality)

Add the pipeline to GitHub Actions so it runs on every PR and nightly.

**Steps:**
1. Create `.github/workflows/security-audit.yml`.
2. Run Stage 1 + Stage 2 on every PR.
3. Run full Stage 3 + Stage 4 nightly with results uploaded as artifacts.
4. Block PR merge only on verified findings (Stage 4 output), not noisy Stage 2 candidates.

**When:** Phase 1 (Weeks 5–8) for immediate security feedback; fully mature by Phase 4.

## Suggested Timeline Alignment

| Week | Plan Activity | Pipeline Activity | Owner |
|------|---------------|---------------------|-------|
| 5–6 | Jeremiah: `DatabaseAuditSink` | Use pipeline recon to verify all simulation paths call audit logger | Jeremiah |
| 5–6 | Ajibola: API auth middleware | Run pipeline STRIDE + Semgrep to find auth gaps before implementation | Ajibola |
| 7–8 | Omolara: Air-gap egress controls | Run pipeline SBOM + Trivy to verify no external HTTP calls in air-gap mode | Omolara |
| 9–14 | Ajibola: Exercise orchestrator | Run pipeline recursive audit on orchestrator code as it lands | Ajibola |
| 15–16 | Lanre: Orange Team | Promote pipeline to `core/code_review_engine.py` + CLI | Lanre |
| 17–18 | Jeremiah: Compliance reports | Consume pipeline Stage 4 reports in `intelligence/compliance_report.py` | Jeremiah |
| 19–20 | DevRel: E2E tests | Add pipeline CI/CD workflow + nightly audit | DevRel |

## Conclusion

The recursive SAST pipeline is not a deviation from the current plan — it is a **ready-to-use implementation of the Orange Team deliverable** and a **force multiplier for the Phase 1 security hardening and Phase 3 compliance work**. The highest-value next step is to either:

1. **Run it immediately** against the current codebase to produce a verified-finding report for the P0/P1 blockers, or
2. **Promote it to `vorsyghta/core/code_review_engine.py`** so it becomes a first-class Orange Team component within the application.

Either path produces actionable security findings well before the bank pilot dry-run in Weeks 19–20.
