# Vorsyghta Component Licensing Matrix

**Version:** 1.0
**Last Updated:** 2026-07-07
**Owner:** Vorsyghta Core Team
**Contact:** commercial@vorsyghta.io

This document is the **authoritative source** for determining which parts of Vorsyghta are open source (Apache 2.0) and which are commercial. If there is any conflict between this matrix and any other document, this matrix prevails for licensing classification.

---

## 1. Licensing Model

Vorsyghta uses an **open-core** model:

| Tier | License | What it covers |
|---|---|---|
| **Open Source Core** | Apache License 2.0 | Simulation engine, CLI, YAML template system, basic LLM provider abstraction, configuration, safety primitives, utilities. Free to use, modify, and distribute, including commercially. |
| **Commercial Modules** | Vorsyghta Commercial License | Intelligence stack, event sourcing, blue team suite, multi-team orchestration, enterprise integrations, detection rule generation, VM attack agent, RAG/RLHF, REST API, RBAC, client data ingestion. Require a paid license agreement. |

### How to identify a commercial file

Every commercial source file carries this header (or its equivalent in the file's comment syntax):

```
# Vorsyghta Commercial Module
# Licensed under the Vorsyghta Commercial License.
# See docs/licensing/COMPONENT_MATRIX.md
# Contact commercial@vorsyghta.io for licensing.
```

Files without this header that are not listed as commercial in Section 3 below are governed by Apache 2.0.

---

## 2. Decision Criteria — How a Component Is Classified

Every component is evaluated against the following criteria. A component is **commercial** if it meets two or more of these conditions; otherwise it is **open source**.

| # | Criterion | Favors Open Source | Favors Commercial |
|---|---|---|---|
| 1 | **Strategic differentiation** | Commodity / table-stakes capability | Proprietary differentiator that competitors cannot easily replicate |
| 2 | **Revenue dependency** | Not directly monetized; adoption driver | Directly sold or required for paid engagements |
| 3 | **Enterprise-only audience** | Useful to individual researchers, small teams, hobbyists | Only valuable to enterprise security programs with budget |
| 4 | **Implementation complexity / IP density** | Straightforward, well-understood patterns | Significant R&D, novel algorithms, or curated datasets |
| 5 | **Compliance / regulatory sensitivity** | General-purpose, low regulatory exposure | Touches regulated data, audit trails, or breach-notification workflows |
| 6 | **Ecosystem lock-in effect** | Keeping it open grows the community and template ecosystem | Keeping it closed protects the platform's unique value proposition |
| 7 | **Standalone utility** | Works independently and is useful on its own | Only meaningful as part of the integrated commercial platform |
| 8 | **Support burden** | Low support cost; community can self-serve | Requires dedicated support, SLAs, or professional services |

**Tiebreaker:** When a component scores equally, the default is **open source** — commercial classification must be justified by clear strategic or revenue value.

---

## 3. Component Matrix

### 3.1 Open Source Core (Apache 2.0)

| Component | Path(s) | Why Open Source |
|---|---|---|
| Simulation engine (core) | `vorsyghta/core/simulator.py`, `vorsyghta/core/models.py`, `vorsyghta/core/output_models.py`, `vorsyghta/core/exceptions.py` | Table-stakes capability; adoption driver; the foundation everyone needs. |
| Template manager | `vorsyghta/core/template_manager_pro.py`, `templates/` | YAML templates are the community's contribution surface; keeping them open grows the ecosystem. |
| CLI (core commands) | `vorsyghta/cli/__init__.py`, `vorsyghta/cli/simulate.py`, `vorsyghta/cli/templates.py`, `vorsyghta/cli/config.py` | Low support burden; standalone utility; drives adoption. |
| LLM provider abstraction | `vorsyghta/llm/base.py`, `vorsyghta/llm/manager.py`, `vorsyghta/llm/providers/`, `vorsyghta/llm/exceptions.py`, `vorsyghta/llm/models.py` | Commodity integration layer; well-understood pattern; benefits from community contributions for new providers. |
| Configuration system | `vorsyghta/config/` | General-purpose; low regulatory exposure; required by every user. |
| Safety primitives | `vorsyghta/safety/content_filter.py`, `vorsyghta/safety/models.py`, `vorsyghta/safety/exceptions.py` | Defensive safety should be open and auditable; community trust requires transparency. |
| Utilities | `vorsyghta/utils/` | Low complexity; standalone utility; minimal IP. |
| Datasets (basic) | `vorsyghta/datasets/base_processor.py`, `vorsyghta/datasets/manager.py` | Framework for community-contributed dataset processors; the processors themselves may be commercial. |
| Logging | `vorsyghta/utils/logging.py` | Commodity; low support burden. |
| Content saver | `vorsyghta/utils/auto_content_saver.py` | Simple utility; standalone. |
| `__main__` entry point | `vorsyghta/__main__.py`, `vorsyghta/__init__.py` | Required for package to function; must be open. |
| Documentation (public) | `docs/guides/`, `docs/api/`, `docs/reference/`, `docs/community/`, `docs/compliance/` | Public-facing docs must be open for adoption and contribution. |

### 3.2 Commercial Modules (Vorsyghta Commercial License)

| Component | Path(s) | Why Commercial |
|---|---|---|
| **Intelligence stack — OSINT engine** | `vorsyghta/intelligence/services.py` (OSINT portions), `vorsyghta/intelligence/integrations.py` | Proprietary differentiator; significant R&D; enterprise-only audience; directly sold. |
| **Intelligence stack — Dark web monitor** | `vorsyghta/intelligence/services.py` (dark web portions) | High IP density; regulatory sensitivity; enterprise-only; revenue-dependent. |
| **Intelligence stack — MITRE ATT&CK engine** | `vorsyghta/intelligence/mitre_attack.py`, `vorsyghta/intelligence/compliance.py`, `vorsyghta/intelligence/models.py` | Curated dataset; significant R&D; proprietary differentiator. |
| **Event sourcing & audit trail** | `vorsyghta/core/event_sourcing.py`, `vorsyghta/core/postgres_event_store.py`, `vorsyghta/core/event_bus.py`, `vorsyghta/core/event_types.py` | High IP density; regulatory sensitivity; enterprise-only; compliance-critical. |
| **Blue team suite** | `vorsyghta/defense/blue_team/`, `vorsyghta/defense/shared/` | Significant R&D; enterprise-only audience; directly sold; high support burden. |
| **Multi-team orchestration** | `vorsyghta/core/exercise_orchestrator.py`, `vorsyghta/core/team_playbooks.py` | Proprietary differentiator; only meaningful as part of integrated platform; enterprise-only. |
| **After-action review generator** | `vorsyghta/core/aar_generator.py` | IP-dense; enterprise-only; revenue-dependent. |
| **Evaluation engine** | `vorsyghta/core/evaluation_engine.py` | Enterprise-only; proprietary benchmarking logic. |
| **AI-enhanced playbooks** | `vorsyghta/core/ai_enhanced_playbooks.py`, `vorsyghta/core/playbook_validator.py` | Significant R&D; enterprise-only. |
| **Mitigation generator** | `vorsyghta/core/mitigation_generator.py` | Proprietary; enterprise-only. |
| **Batch processor** | `vorsyghta/core/batch_processor.py` | Enterprise-scale feature; enterprise-only. |
| **Advanced template manager** | `vorsyghta/core/template_manager_pro.py` (enterprise features) | Enterprise-only features layered on the open template manager. |
| **Simulation logger** | `vorsyghta/core/simulation_logger.py` | Enterprise-grade logging; compliance-sensitive. |
| **Audit logger** | `vorsyghta/core/audit_logger.py` | Regulatory sensitivity; enterprise-only. |
| **Client data ingestion / digital twin** | `vorsyghta/client_data/` | Proprietary differentiator; significant R&D; enterprise-only; directly sold. |
| **VM-based autonomous attack agent** | `vorsyghta/vm/` | High IP density; significant R&D; enterprise-only; proprietary. |
| **MCP server & agentic tools** | `vorsyghta/mcp/` | Proprietary agentic infrastructure; enterprise-only. |
| **RAG knowledge store** | `vorsyghta/rag/` | IP-dense; enterprise-only; directly sold. |
| **RLHF feedback loop** | `vorsyghta/feedback/`, `vorsyghta/llm/rlhf_multiagent.py` | Significant R&D; proprietary; enterprise-only. |
| **Advanced LLM reasoning** | `vorsyghta/llm/advanced_integration.py`, `vorsyghta/llm/advanced_prompts.py`, `vorsyghta/llm/advanced_reasoning.py`, `vorsyghta/llm/enhanced_prompts.py`, `vorsyghta/llm/fallback_chain.py`, `vorsyghta/llm/generation.py`, `vorsyghta/llm/guardrails.py`, `vorsyghta/llm/model_manager.py`, `vorsyghta/llm/prompts.py`, `vorsyghta/llm/validation.py`, `vorsyghta/llm/providers_new.py` | Proprietary prompt engineering and reasoning chains; IP-dense; enterprise-only. |
| **Detection rule generation** | `vorsyghta/analytics/` | Proprietary differentiator; enterprise-only; directly sold. |
| **Enterprise integrations** | `vorsyghta/integrations/`, `vorsyghta/deployment/` | Enterprise-only; requires dedicated support; directly sold. |
| **REST API server (enterprise tier)** | `vorsyghta/api/` | Enterprise integration tier; enterprise-only; support burden. |
| **Persistence layer (enterprise)** | `vorsyghta/db/` | Enterprise-grade persistence; compliance-sensitive; enterprise-only. |
| **RBAC & enterprise security** | `vorsyghta/security/` | Enterprise-only; regulatory sensitivity; support burden. |
| **Quantum / PQC module** | `vorsyghta/quantum/` | Significant R&D; proprietary; enterprise-only. |
| **CLI (enterprise commands)** | `vorsyghta/cli/blue_team.py`, `vorsyghta/cli/client_data.py`, `vorsyghta/cli/datasets.py` (enterprise features), `vorsyghta/cli/deploy.py`, `vorsyghta/cli/detect.py`, `vorsyghta/cli/exercise.py`, `vorsyghta/cli/feedback.py` | Enterprise-only command surfaces; require commercial modules to function. |
| **Dataset processors (curated)** | `vorsyghta/datasets/processors/` | Curated/proprietary processors; IP-dense. |
| **Internal documentation** | `docs/internal/`, `docs/plans/`, `docs/research/`, `docs/architecture/` | Internal strategy and architecture; not for public distribution. |

---

## 4. Summary by License

| License | Approximate share of codebase | Key components |
|---|---|---|
| **Apache 2.0 (Open Source)** | ~20% | Simulation engine, CLI core, templates, LLM provider abstraction, config, safety primitives, utilities, public docs |
| **Vorsyghta Commercial License** | ~80% | Intelligence stack, event sourcing, blue team, multi-team orchestration, VM agent, MCP, RAG/RLHF, advanced LLM, detection rules, integrations, REST API, RBAC, persistence, quantum, client data ingestion |

---

## 5. Commercial License Tiers

The commercial modules are available under the following tiers. Contact commercial@vorsyghta.io for pricing and terms.

| Tier | Target | Includes |
|---|---|---|
| **Team** | Small security teams (up to 25 seats) | Intelligence stack, blue team suite, detection rule generation, REST API. Single-tenant deployment. Community support. |
| **Enterprise** | Mid-to-large organizations (25+ seats) | Everything in Team, plus multi-team orchestration, event-sourced audit trail, client data ingestion / digital twin, enterprise integrations, RBAC, advanced LLM reasoning. Multi-tenant. Priority support with SLA. |
| **Mission** | Regulated industries (banks, fintech, insurance, healthcare) | Everything in Enterprise, plus compliance automation (PCI-DSS, NDPR, GDPR, SOC 2, ISO 27001, CBN), breach-notification readiness, quantum/PQC module, dedicated support engineer, on-premise air-gapped deployment. |

---

## 6. Frequently Asked Questions

**Can I use the open-source core in a commercial product?**
Yes. Apache 2.0 permits commercial use, modification, and distribution, including embedding Vorsyghta's core in a commercial product. You must comply with the Apache 2.0 terms (attribution, notice retention, state changes).

**Can I contribute to the commercial modules?**
No. The commercial modules are not accepting external contributions at this time. If you have a feature request or bug report for a commercial module, open a GitHub issue and the core team will triage it.

**I want to build a custom integration. Is the integration layer open?**
The integration base class pattern is documented, but the concrete enterprise integrations (M365, Proofpoint, KnowBe4, Slack, Splunk, Elastic, Sentinel, QRadar) are commercial. You can build your own integration against the open-source core's extension points.

**How do I get a commercial license?**
Contact commercial@vorsyghta.io with your organization name, intended use case, and seat count. The team will respond within two business days.

**What happens if I use a commercial module without a license?**
Use of any commercial module without a valid commercial license agreement constitutes copyright infringement and is prohibited. See the `LICENSE` file for details.

**Is the safety framework open source?**
Yes. The basic content filter and safety models are open source under Apache 2.0. Defensive safety should be transparent and auditable. The advanced guardrails and validation logic used in enterprise deployments are commercial.

---

## 7. Change Log

| Date | Version | Change |
|---|---|---|
| 2026-07-07 | 1.0 | Initial component matrix. Established open-core model with Apache 2.0 core and commercial modules. |

---

## 8. Contacts

| Role | Contact |
|---|---|
| Commercial licensing | commercial@vorsyghta.io |
| Open-source contributions | [GitHub Discussions](https://github.com/QuantumindSSI/Vorsyghta/discussions) |
| Security vulnerabilities | See [`SECURITY.md`](../../SECURITY.md) |
| Compliance | compliance@vorsyghta.io |

---

*This matrix is maintained by the Vorsyghta Core Team. For questions about a specific component's classification, contact commercial@vorsyghta.io.*
