# Recursive SAST Pipeline vs. Current Application Plan

> **Platform scope.** This integration plan supplies the code-review engine for the Orange team in **capability #1** of Vorsyghta's seven-capability target. Canonical scope: **[README § Platform scope — the full target](../README.md#platform-scope--the-full-target)**.

## Executive Summary

The `security-audit/` recursive prompting pipeline aligns directly with the Vorsyghta project's **Orange Team** mandate and supports the **Yellow Team** and **Compliance** workstreams. It is a ready-to-integrate implementation of the LLM-enriched SAST and STRIDE threat-modeling capability.

## Where the Architecture Target Expects This Work

### Orange Team

| Requirement | Pipeline Capability | Status |
|-------------------|---------------------|--------|
| `vorsyghta/core/code_review_engine.py` — LLM-enriched SAST | `security-audit/pipeline.py` Stage 3 recursive audit loop | Implemented |
| STRIDE threat modeling from architecture specs | `security-audit/pipeline.py` Stage 2 STRIDE threat model | Implemented |
| Attack surface mapping and reduction recommendations | `security-audit/pipeline.py` Stage 1 architecture + user-flow recon | Implemented |
| Dependency vulnerability scanning | `security-audit/pipeline.py` Stage 1 SBOM + Trivy audit | Implemented |
| Maps findings to MITRE ATT&CK techniques | Pipeline threat model output can be extended to MITRE mapping | Partial |
| `vorsyghta/cli/orange_team.py` commands | Not yet integrated into CLI | Gap |
| `vorsyghta/agents/orange_team_agent.py` | Not yet integrated into agent framework | Gap |

### Yellow Team

| Requirement | Pipeline Capability | Status |
|-------------------|---------------------|--------|
| IaC scanning (Terraform/Docker Compose) | Pipeline recon scans repository; extendable to IaC rules | Partial |
| CIS benchmark checks | Not yet implemented | Gap |
| Infrastructure hardening validation | Trivy SBOM audit covers dependency CVEs; add CIS + infrastructure rules | Gap |

### Compliance / White Team

| Requirement | Pipeline Capability | Status |
|-------------------|---------------------|--------|
| Compliance report generator (`intelligence/compliance_report.py`) | Pipeline Stage 4 generates markdown + JSON audit reports | Implemented |
| Framework-mapped controls (GDPR/PCI-DSS/SOC2/HIPAA) | Currently generic; needs framework-specific mapping layer | Gap |
| Tamper-evident audit trail | Pipeline output is JSON/MD; not hash-chained | Gap |

## Direct Mapping to Known Blockers

| Blocker | Pipeline Relevance | How It Helps |
|---------|-------------------|--------------|
| No API auth/RBAC | STRIDE analysis + Semgrep rules for auth gaps | Generates findings for missing auth checks, wildcard CORS |
| No tamper-evident audit | Pipeline report generation can be extended to include audit verification | Produces audit-style findings; needs hash-chain integration |
| No DB persistence | Recon identifies DB model gaps; Semgrep rules detect in-memory state | Flags unbounded `List[]` buffers and missing `tenant_id` columns |
| External HTTP calls | User-flow recon + STRIDE Information Disclosure | Detects air-gap bypass patterns and external requests |
| No rate limiting / secret management | STRIDE DoS + Information Disclosure | Generates findings for missing rate limits and secret handling |

## What the Pipeline Adds Beyond the Core Requirements

1. **Recursive audit loop** — The architecture target calls for a single code-review engine; the pipeline adds multi-pass clean-context analysis, which increases recall and reduces anchor bias.
2. **Semgrep-in-the-loop** — The target lists Semgrep as a tool to integrate; the pipeline already generates Semgrep rules from the STRIDE model and runs them alongside the LLM.
3. **Trivy SBOM audit** — The target mentions dependency scanning but does not explicitly mandate SBOM generation; the pipeline includes it as a recon artifact.
4. **Deterministic + probabilistic combination** — The methodology explicitly separates high-recall candidate generation from high-precision triage, which the architecture does not yet formalize.
5. **Reusable four-stage methodology** — The pipeline is a documented, repeatable methodology (`README.md`) rather than a single component.

## Gaps and Recommended Actions

| Gap | Recommended Action |
|-----|-------------------|
| Not wired into `vorsyghta` CLI or agent framework | Wrap `pipeline.py` as `vorsyghta/cli/orange_team.py` and `vorsyghta/agents/orange_team_agent.py` |
| No CIS benchmark / infrastructure hardening checks | Add Semgrep rules + recon modules for Terraform/Docker Compose/K8s manifests |
| No framework-specific compliance mapping (GDPR/PCI-DSS/SOC2/HIPAA) | Extend Stage 4 triage to map findings to control frameworks |
| No hash-chain tamper-evidence on reports | Integrate `DatabaseAuditSink` hash-chain output with pipeline reports |
| No MITRE ATT&CK mapping of findings | Add `vorsyghta/intelligence/mitre_attack.py` lookups to threat model stage |
| No CI/CD integration | Add GitHub Actions workflow to run pipeline nightly or on PR |
| Local LLM calls are currently stubbed | Replace `_call_local_llm()` with Ollama/LM Studio integration |

## Recommended Integration Path

### Option A: Keep as Standalone Audit Tool (Immediate Value)

Use the pipeline as-is for manual security audits before a customer engagement. It can run independently and feed findings into the backlog without modifying the application code.

### Option B: Integrate into Orange Team

Convert the pipeline into the planned `vorsyghta/core/code_review_engine.py` module.

**Steps:**
1. Move `security-audit/pipeline.py` logic into `vorsyghta/core/code_review_engine.py`.
2. Add `vorsyghta/cli/orange_team.py` commands that wrap the pipeline stages.
3. Add `vorsyghta/agents/orange_team_agent.py` for agent-framework integration.
4. Store pipeline outputs in PostgreSQL via `vorsyghta/db/models/compliance.py`.

### Option C: Shift-Left in CI/CD (Recommended)

Add the pipeline to GitHub Actions so it runs on every PR and nightly.

**Steps:**
1. Create `.github/workflows/security-audit.yml`.
2. Run Stage 1 + Stage 2 on every PR.
3. Run full Stage 3 + Stage 4 nightly with results uploaded as artifacts.
4. Block PR merge only on verified findings (Stage 4 output), not noisy Stage 2 candidates.

## Conclusion

The recursive SAST pipeline is not a deviation from the architecture target — it is a **ready-to-use implementation of the Orange Team deliverable** and a **force multiplier for security hardening and compliance work**. The highest-value next step is to either:

1. **Run it immediately** against the current codebase to produce a verified-finding report for the P0/P1 blockers, or
2. **Promote it to `vorsyghta/core/code_review_engine.py`** so it becomes a first-class Orange Team component within the application.

Either path produces actionable security findings well before a customer engagement dry-run.
