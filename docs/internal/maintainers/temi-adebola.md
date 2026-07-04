# Internal Brief — Temi Adebola

**Role:** Red Team Lead  
**GitHub:** @TemidayoA  
**Color Team:** Red  
**Active Window:** Weeks 9–20

---

## Mission

Make the red team standalone and bank-scenario-ready, removing the hard dependency on the external "Ciicerone Attack" API.

---

## Atomic Tasks

### Phase 2 — Standalone Red Team (Weeks 9–14)

| Task | Weeks | Deliverable | Unblocks |
|------|-------|-------------|----------|
| TEMI-001 | 9–11 | Standalone red team engine (`core/red_team_engine.py`) | P1-6 external API dependency |
| TEMI-002 | 11–12 | Red team ORM models + persistence (`db/models/red_team.py`) | P0-6 no persistence |
| TEMI-003 | 13–14 | Wire bank scenarios to orchestrator (BEC, supply-chain, payment fraud) | P0-1 no end-to-end orchestration |

### Phase 3 — Orange Team Support (Weeks 15–18)

| Task | Weeks | Deliverable | Unblocks |
|------|-------|-------------|----------|
| TEMI-004 | 15–16 | Support Orange Team attack surface analysis | P0-2 Orange missing |

### Phase 4 — Pilot Validation (Weeks 19–20)

| Task | Weeks | Deliverable |
|------|-------|-------------|
| TEMI-005 | 19–20 | Verify BEC/supply-chain scenarios run e2e without external API |

---

## Key Collaboration Points

- **Ajibola:** Depends on event bus, ORM, and exercise orchestrator.
- **David:** Red team attack events feed blue team detection.
- **Lanre:** Red team patterns feed Orange Team threat modeling.

---

## Exit Criteria

1. `ciicerone simulate` succeeds without `CIICERONE_ATTACK_API_URL` env var.
2. Attack events publish to event bus with MITRE technique IDs.
3. Bank scenarios execute through the orchestrator.
4. External API still works when configured (no regression).

---

## Risks

- Red team work is blocked until Ajibola's event bus and ORM are ready.
- Standalone engine must match the quality of external API output.
