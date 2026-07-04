# Internal Brief — Jeremiah Okino

**Role:** Compliance Lead  
**GitHub:** @okino007  
**Color Team:** White  
**Active Window:** Weeks 5–20

---

## Mission

Deliver a tamper-evident audit trail, wire it into the simulation flow, build the White Team rules-of-engagement engine, and produce compliance-ready reports.

---

## Atomic Tasks

### Phase 1 — Tamper-Evident Audit (Weeks 5–8)

| Task | Weeks | Deliverable | Unblocks |
|------|-------|-------------|----------|
| JEREMIAH-001 | 5–6 | DatabaseAuditSink + audit ORM models (`db/models/audit.py`, `db/audit_sink.py`) | P0-5 AuditSink NotImplementedError |
| JEREMIAH-002 | 6–7 | Hash-chain integrity + tamper detection (`core/audit_verifier.py`, `api/routers/audit.py`) | P0-5 no tamper evidence |
| JEREMIAH-003 | 7–8 | Wire audit logging into simulation flow | P0-5 audit logger never called |

### Phase 2 — Compliance Mapping (Weeks 9–14)

| Task | Weeks | Deliverable | Unblocks |
|------|-------|-------------|----------|
| JEREMIAH-004 | 9–14 | Compliance mapping framework (`core/compliance_mapper.py`) | P0-5 no compliance mapping |

### Phase 3 — White Team + Reports (Weeks 15–18)

| Task | Weeks | Deliverable | Unblocks |
|------|-------|-------------|----------|
| JEREMIAH-005 | 15–16 | White Team rules of engagement engine (`core/rules_of_engagement.py`) | P0-2, P2-1 White missing |
| JEREMIAH-006 | 16–17 | Compliance report generator (`intelligence/compliance_report.py`) | P1-5 report stub |
| JEREMIAH-007 | 17–18 | Compliance ORM models (`db/models/compliance.py`) | P0-6 no compliance persistence |

### Phase 4 — Pilot Validation (Weeks 19–20)

| Task | Weeks | Deliverable |
|------|-------|-------------|
| JEREMIAH-008 | 19–20 | Verify audit trail, compliance reports, White Team e2e |

---

## Key Collaboration Points

- **Ajibola:** Depends on ORM base and event store wiring.
- **Ibrahim:** RBAC permissions for audit endpoints and White Team RoE.
- **Lanre:** AAR data feeds compliance report generator.
- **Omolara:** DB migrations for audit and compliance tables.

---

## Exit Criteria

1. `AuditSink.write()` no longer raises `NotImplementedError`.
2. Every simulation action emits an audit event with MITRE + compliance tags.
3. Hash chain verification detects tampered events.
4. White Team blocks exercises that violate RoE.
5. Compliance report maps findings to GDPR/PCI-DSS/SOC2/HIPAA.

---

## Risks

- Audit work depends on Ajibola's ORM foundation.
- White Team RoE requires Ibrahim's RBAC enforcement.
