# Internal Brief — DevRel & PR

**Role:** Developer Relations  
**GitHub:** —  
**Color Team:** Black / Community  
**Active Window:** Weeks 9–20

---

## Mission

Deliver the end-to-end integration test, rewrite the demo as a single command, produce honest marketing materials, and build the Black Team evaluation engine.

---

## Atomic Tasks

### Phase 2 — Orchestrator Documentation (Weeks 9–14)

| Task | Weeks | Deliverable | Unblocks |
|------|-------|-------------|----------|
| DEVREL-005 | 9–14 | Document orchestrator and team integration | P1-3 manual demo/docs |

### Phase 3 — Black Team (Weeks 15–18)

| Task | Weeks | Deliverable | Unblocks |
|------|-------|-------------|----------|
| DEVREL-004 | 15–18 | Black Team evaluation engine (`core/evaluation_engine.py`) | P0-2, P2-1 Black missing |

### Phase 4 — Pilot Validation (Weeks 19–20)

| Task | Weeks | Deliverable | Unblocks |
|------|-------|-------------|----------|
| DEVREL-001 | 19 | End-to-end integration test (`tests/full/test_e2e_exercise.py`) | P1-2 no e2e tests |
| DEVREL-002 | 19 | Rewrite demo as integrated single-command flow | P1-3 manual CLI tour |
| DEVREL-003 | 20 | Update cold email and README to match reality | All P0/P1 false claims |
| DEVREL-006 | 20 | Pilot dry-run and sign-off | P1-2 no e2e tests |

---

## Key Collaboration Points

- **Ajibola:** E2E test and demo depend on the exercise orchestrator.
- **All maintainers:** E2E test verifies every team's work.
- **Marketing:** All Phase 0–3 deliverables must be complete before updating claims.

---

## Exit Criteria

1. `pytest tests/full/test_e2e_exercise.py` passes.
2. Demo runs as a single `ciicerone exercise run` command and fails on errors.
3. Cold email and README accurately reflect capabilities.
4. Black Team produces exercise scores and benchmark reports.

---

## Risks

- E2E test is the final pilot gate; it will fail if any upstream team slips.
- Marketing update must wait until all capabilities are verified.
