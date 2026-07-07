# Ciicerone Component Licensing Matrix

**Version:** 1.0
**Last Updated:** 2026-07-07
**Owner:** Ciicerone Core Team
**Contact:** commercial@ciicerone.io

This document is the **authoritative source** for determining which parts of Ciicerone are open source (Apache 2.0) and which are commercial. If there is any conflict between this matrix and any other document, this matrix prevails for licensing classification.

---

## 1. Licensing Model

Ciicerone uses an **open-core** model:

| Tier | License | What it covers |
|---|---|---|
| **Open Source Core** | Apache License 2.0 | Simulation engine, CLI, YAML template system, basic LLM provider abstraction, configuration, safety primitives, utilities. Free to use, modify, and distribute, including commercially. |
| **Commercial Modules** | Ciicerone Commercial License | Intelligence stack, event sourcing, blue team suite, multi-team orchestration, enterprise integrations, detection rule generation, VM attack agent, RAG/RLHF, REST API, RBAC, client data ingestion. Require a paid license agreement. |

### How to identify a commercial file

Every commercial source file carries this header (or its equivalent in the file's comment syntax):

```
# Ciicerone Commercial Module
# Licensed under the Ciicerone Commercial License.
# See docs/licensing/COMPONENT_MATRIX.md
# Contact commercial@ciicerone.io for licensing.
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
| Simulation engine (core) | `ciicerone/core/simulator.py`, `ciicerone/core/models.py`, `ciicerone/core/output_models.py`, `ciicerone/core/exceptions.py` | Table-stakes capability; adoption driver; the foundation everyone needs. |
| Template manager | `ciicerone/core/template_manager_pro.py`, `templates/` | YAML templates are the community's contribution surface; keeping them open grows the ecosystem. |
| CLI (core commands) | `ciicerone/cli/__init__.py`, `ciicerone/cli/simulate.py`, `ciicerone/cli/templates.py`, `ciicerone/cli/config.py` | Low support burden; standalone utility; drives adoption. |
| LLM provider abstraction | `ciicerone/llm/base.py`, `ciicerone/llm/manager.py`, `ciicerone/llm/providers/`, `ciicerone/llm/exceptions.py`, `ciicerone/llm/models.py` | Commodity integration layer; well-understood pattern; benefits from community contributions for new providers. |
| Configuration system | `ciicerone/config/` | General-purpose; low regulatory exposure; required by every user. |
| Safety primitives | `ciicerone/safety/content_filter.py`, `ciicerone/safety/models.py`, `ciicerone/safety/exceptions.py` | Defensive safety should be open and auditable; community trust requires transparency. |
| Utilities | `ciicerone/utils/` | Low complexity; standalone utility; minimal IP. |
| Datasets (basic) | `ciicerone/datasets/base_processor.py`, `ciicerone/datasets/manager.py` | Framework for community-contributed dataset processors; the processors themselves may be commercial. |
| Logging | `ciicerone/utils/logging.py` | Commodity; low support burden. |
| Content saver | `ciicerone/utils/auto_content_saver.py` | Simple utility; standalone. |
| `__main__` entry point | `ciicerone/__main__.py`, `ciicerone/__init__.py` | Required for package to function; must be open. |
| Documentation (public) | `docs/guides/`, `docs/api/`, `docs/reference/`, `docs/community/`, `docs/compliance/` | Public-facing docs must be open for adoption and contribution. |

### 3.2 Commercial Modules (Ciicerone Commercial License)

| Component | Path(s) | Why Commercial |
|---|---|---|
| **Intelligence stack — OSINT engine** | `ciicerone/intelligence/services.py` (OSINT portions), `ciicerone/intelligence/integrations.py` | Proprietary differentiator; significant R&D; enterprise-only audience; directly sold. |
| **Intelligence stack — Dark web monitor** | `ciicerone/intelligence/services.py` (dark web portions) | High IP density; regulatory sensitivity; enterprise-only; revenue-dependent. |
| **Intelligence stack — MITRE ATT&CK engine** | `ciicerone/intelligence/mitre_attack.py`, `ciicerone/intelligence/compliance.py`, `ciicerone/intelligence/models.py` | Curated dataset; significant R&D; proprietary differentiator. |
| **Event sourcing & audit trail** | `ciicerone/core/event_sourcing.py`, `ciicerone/core/postgres_event_store.py`, `ciicerone/core/event_bus.py`, `ciicerone/core/event_types.py` | High IP density; regulatory sensitivity; enterprise-only; compliance-critical. |
| **Blue team suite** | `ciicerone/defense/blue_team/`, `ciicerone/defense/shared/` | Significant R&D; enterprise-only audience; directly sold; high support burden. |
| **Multi-team orchestration** | `ciicerone/core/exercise_orchestrator.py`, `ciicerone/core/team_playbooks.py` | Proprietary differentiator; only meaningful as part of integrated platform; enterprise-only. |
| **After-action review generator** | `ciicerone/core/aar_generator.py` | IP-dense; enterprise-only; revenue-dependent. |
| **Evaluation engine** | `ciicerone/core/evaluation_engine.py` | Enterprise-only; proprietary benchmarking logic. |
| **AI-enhanced playbooks** | `ciicerone/core/ai_enhanced_playbooks.py`, `ciicerone/core/playbook_validator.py` | Significant R&D; enterprise-only. |
| **Mitigation generator** | `ciicerone/core/mitigation_generator.py` | Proprietary; enterprise-only. |
| **Batch processor** | `ciicerone/core/batch_processor.py` | Enterprise-scale feature; enterprise-only. |
| **Advanced template manager** | `ciicerone/core/template_manager_pro.py` (enterprise features) | Enterprise-only features layered on the open template manager. |
| **Simulation logger** | `ciicerone/core/simulation_logger.py` | Enterprise-grade logging; compliance-sensitive. |
| **Audit logger** | `ciicerone/core/audit_logger.py` | Regulatory sensitivity; enterprise-only. |
| **Client data ingestion / digital twin** | `ciicerone/client_data/` | Proprietary differentiator; significant R&D; enterprise-only; directly sold. |
| **VM-based autonomous attack agent** | `ciicerone/vm/` | High IP density; significant R&D; enterprise-only; proprietary. |
| **MCP server & agentic tools** | `ciicerone/mcp/` | Proprietary agentic infrastructure; enterprise-only. |
| **RAG knowledge store** | `ciicerone/rag/` | IP-dense; enterprise-only; directly sold. |
| **RLHF feedback loop** | `ciicerone/feedback/`, `ciicerone/llm/rlhf_multiagent.py` | Significant R&D; proprietary; enterprise-only. |
| **Advanced LLM reasoning** | `ciicerone/llm/advanced_integration.py`, `ciicerone/llm/advanced_prompts.py`, `ciicerone/llm/advanced_reasoning.py`, `ciicerone/llm/enhanced_prompts.py`, `ciicerone/llm/fallback_chain.py`, `ciicerone/llm/generation.py`, `ciicerone/llm/guardrails.py`, `ciicerone/llm/model_manager.py`, `ciicerone/llm/prompts.py`, `ciicerone/llm/validation.py`, `ciicerone/llm/providers_new.py` | Proprietary prompt engineering and reasoning chains; IP-dense; enterprise-only. |
| **Detection rule generation** | `ciicerone/analytics/` | Proprietary differentiator; enterprise-only; directly sold. |
| **Enterprise integrations** | `ciicerone/integrations/`, `ciicerone/deployment/` | Enterprise-only; requires dedicated support; directly sold. |
| **REST API server (enterprise tier)** | `ciicerone/api/` | Enterprise integration tier; enterprise-only; support burden. |
| **Persistence layer (enterprise)** | `ciicerone/db/` | Enterprise-grade persistence; compliance-sensitive; enterprise-only. |
| **RBAC & enterprise security** | `ciicerone/security/` | Enterprise-only; regulatory sensitivity; support burden. |
| **Quantum / PQC module** | `ciicerone/quantum/` | Significant R&D; proprietary; enterprise-only. |
| **CLI (enterprise commands)** | `ciicerone/cli/blue_team.py`, `ciicerone/cli/client_data.py`, `ciicerone/cli/datasets.py` (enterprise features), `ciicerone/cli/deploy.py`, `ciicerone/cli/detect.py`, `ciicerone/cli/exercise.py`, `ciicerone/cli/feedback.py` | Enterprise-only command surfaces; require commercial modules to function. |
| **Dataset processors (curated)** | `ciicerone/datasets/processors/` | Curated/proprietary processors; IP-dense. |
| **Internal documentation** | `docs/internal/`, `docs/plans/`, `docs/research/`, `docs/architecture/` | Internal strategy and architecture; not for public distribution. |

---

## 4. Summary by License

| License | Approximate share of codebase | Key components |
|---|---|---|
| **Apache 2.0 (Open Source)** | ~20% | Simulation engine, CLI core, templates, LLM provider abstraction, config, safety primitives, utilities, public docs |
| **Ciicerone Commercial License** | ~80% | Intelligence stack, event sourcing, blue team, multi-team orchestration, VM agent, MCP, RAG/RLHF, advanced LLM, detection rules, integrations, REST API, RBAC, persistence, quantum, client data ingestion |

---

## 5. Commercial License Tiers

The commercial modules are available under the following tiers. Contact commercial@ciicerone.io for pricing and terms.

| Tier | Target | Includes |
|---|---|---|
| **Team** | Small security teams (up to 25 seats) | Intelligence stack, blue team suite, detection rule generation, REST API. Single-tenant deployment. Community support. |
| **Enterprise** | Mid-to-large organizations (25+ seats) | Everything in Team, plus multi-team orchestration, event-sourced audit trail, client data ingestion / digital twin, enterprise integrations, RBAC, advanced LLM reasoning. Multi-tenant. Priority support with SLA. |
| **Mission** | Regulated industries (banks, fintech, insurance, healthcare) | Everything in Enterprise, plus compliance automation (PCI-DSS, NDPR, GDPR, SOC 2, ISO 27001, CBN), breach-notification readiness, quantum/PQC module, dedicated support engineer, on-premise air-gapped deployment. |

---

## 6. Frequently Asked Questions

**Can I use the open-source core in a commercial product?**
Yes. Apache 2.0 permits commercial use, modification, and distribution, including embedding Ciicerone's core in a commercial product. You must comply with the Apache 2.0 terms (attribution, notice retention, state changes).

**Can I contribute to the commercial modules?**
No. The commercial modules are not accepting external contributions at this time. If you have a feature request or bug report for a commercial module, open a GitHub issue and the core team will triage it.

**I want to build a custom integration. Is the integration layer open?**
The integration base class pattern is documented, but the concrete enterprise integrations (M365, Proofpoint, KnowBe4, Slack, Splunk, Elastic, Sentinel, QRadar) are commercial. You can build your own integration against the open-source core's extension points.

**How do I get a commercial license?**
Contact commercial@ciicerone.io with your organization name, intended use case, and seat count. The team will respond within two business days.

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
| Commercial licensing | commercial@ciicerone.io |
| Open-source contributions | [GitHub Discussions](https://github.com/ciicerone-AI/Ciicerone/discussions) |
| Security vulnerabilities | See [`SECURITY.md`](../../SECURITY.md) |
| Compliance | compliance@ciicerone.io |

---

*This matrix is maintained by the Ciicerone Core Team. For questions about a specific component's classification, contact commercial@ciicerone.io.*
