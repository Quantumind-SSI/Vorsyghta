# Internal Brief — Lanre Shittu

**Role:** ML/AI Lead  
**GitHub:** @Shizoqua  
**Color Team:** Purple / Orange  
**Active Window:** Weeks 5–20

---

## Mission

Deliver air-gap mode for model downloads, a real Purple Team AAR generator, and the Orange Team code-review/threat-modeling capability.

---

## Atomic Tasks

### Phase 1 — Air-Gap Mode (Weeks 5–8)

| Task | Weeks | Deliverable | Unblocks |
|------|-------|-------------|----------|
| LANRE-001 | 5–6 | Air-gap flag for model downloads (`llm/model_manager.py`, `llamacpp_provider.py`) | P0-7 external HTTP calls |
| LANRE-002 | 6–7 | Pre-baked model bundle for offline deployment (`docker/ollama-models/`) | P0-7 offline deployment |
| LANRE-005 | 7–8 | LlamaCPP provider air-gap completion | P0-7 external HTTP calls |

### Phase 2 — Purple Team AAR (Weeks 9–14)

| Task | Weeks | Deliverable | Unblocks |
|------|-------|-------------|----------|
| LANRE-003 | 9–11 | Purple Team AAR generator (`core/aar_generator.py`, `cli/purple_team.py`, `db/models/aar.py`) | P0-2, P1-1 Purple stub |
| LANRE-004 | 13–14 | RLHF-driven remediation prioritization | P1-1 AAR limitations |

### Phase 3 — Orange Team (Weeks 15–18)

| Task | Weeks | Deliverable | Unblocks |
|------|-------|-------------|----------|
| LANRE-006 | 15–16 | Orange Team: AI-enriched code review + threat modeling (`core/code_review_engine.py`) | P0-2, P2-1 Orange missing |

### Phase 4 — Pilot Validation (Weeks 19–20)

| Task | Weeks | Deliverable |
|------|-------|-------------|
| LANRE-007 | 19–20 | Verify air-gap + AAR + Orange Team e2e |

---

## Key Collaboration Points

- **Omolara:** Coordinate air-gap model bundle with network egress controls.
- **Ajibola:** Depends on event bus, event store, and orchestrator.
- **David:** Blue team alerts feed AAR detection gaps.
- **Temi:** Red team patterns feed Orange Team attack surface analysis.

---

## Exit Criteria

1. `AIR_GAPPED_MODE=true` blocks all external model downloads.
2. AAR includes detection gaps and prioritized remediation.
3. Orange Team can review code for threats.
4. Pre-baked model bundle works offline.

---

## Risks

- Air-gap mode touches multiple LLM providers; must avoid regressions.
- Orange Team SAST is a new capability; needs clear scope vs. security-audit pipeline.
