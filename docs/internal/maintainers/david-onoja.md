# Internal Brief — David Onoja

**Role:** Blue Team Lead (Advanced)  
**GitHub:** @ocheme1107  
**Color Team:** Blue  
**Active Window:** Weeks 9–20

---

## Mission

Wire the existing blue team simulators into the exercise orchestrator and expand detection coverage.

---

## Atomic Tasks

### Phase 2 — Blue Team Integration (Weeks 9–14)

| Task | Weeks | Deliverable | Unblocks |
|------|-------|-------------|----------|
| DAVID-001 | 9–11 | Wire blue team modules to event bus (`defense/blue_team/bus_integration.py`) | P0-1 blue team isolated |
| DAVID-002 | 11–12 | Expand detection rules: 8 → 30+ MITRE techniques | P2-2 limited coverage |
| DAVID-003 | 13–14 | Threat intel ORM models + persistence (`db/models/threat_intel.py`) | P0-6 canned threat intel |

### Phase 3 — Purple/White Team Support (Weeks 15–18)

| Task | Weeks | Deliverable | Unblocks |
|------|-------|-------------|----------|
| DAVID-004 | 15–18 | Support Purple/White team integration (AAR consumes blue alerts) | P0-2 missing teams |

### Phase 4 — Pilot Validation (Weeks 19–20)

| Task | Weeks | Deliverable |
|------|-------|-------------|
| DAVID-005 | 19–20 | Verify BEC scenario detection via event bus |

---

## Key Collaboration Points

- **Ajibola:** Depends on event bus and exercise orchestrator.
- **Ibrahim:** Ibrahim provides blue team persistence; David wires event subscriptions.
- **Lanre:** Blue team alerts feed Purple Team AAR.
- **Jeremiah:** Blue detections feed compliance mapping.

---

## Exit Criteria

1. Red team attack events trigger blue team alerts via event bus.
2. Detection rules cover 30+ MITRE techniques.
3. Threat intel is persisted, not canned.
4. BEC scenario produces detections end-to-end.

---

## Risks

- Blue team modules exist but are isolated; integration depends on Ajibola's event bus.
- Detection rule expansion must remain valid Sigma/Splunk/Elastic/Sentinel format.
