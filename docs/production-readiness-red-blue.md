# Production Readiness – Red Team & Blue Team

## Red Team Production Checklist

### Engagement Gating
- [ ] Require `engagement_id` for all attacks; disable `--allow-unauthorized` in production config
- [ ] Validate engagement_id against tenant-approved engagements DB
- [ ] Enforce `VMSafetyController` lab network allow-list; block external destinations
- [ ] Scope validator: `AttackScopeValidator` with explicit targets/techniques/time_window
- [ ] Audit log all attack attempts with tamper-evident logging
- [ ] Rate limit per tenant: max concurrent simulations, per-user attack throttle

### Infrastructure
- [ ] Production LLM provider: Azure OpenAI with Key Vault secret rotation
- [ ] Database: PostgreSQL with backups, connection pooling
- [ ] Redis for rate limiting and session store
- [ ] API authentication enabled: `api.authentication.enabled: true` + JWT validation
- [ ] CORS origins locked to production domains
- [ ] Secrets never committed; use Key Vault / env vars

### Safety
- [ ] `VORSYGHTA_ALLOW_INSECURE_INTERNAL_API=false`
- [ ] Blocked keywords and content moderation enabled
- [ ] Emergency stop endpoint tested
- [ ] All commands pass `VMSafetyController.validate_command()`

## Blue Team Production Checklist

### SIEM Integration
- [ ] `SIEM_ENABLED=true` with real SIEM platform selected
- [ ] SIEM credentials via Key Vault, not env
- [ ] Log ingestion pipeline for Vorsyghta audit events
- [ ] Alert correlation rules deployed
- [ ] `SIEMClient` configured for Splunk/Elastic/Sentinel/QRadar

### EDR/IDS
- [ ] EDR_ENABLED=true with integration to real EDR
- [ ] IDS ruleset loaded and updated
- [ ] Blue team simulator disabled in production

### Incident Response
- [ ] Incident playbooks stored in DB, not hardcoded
- [ ] Automated response actions require human approval in prod
- [ ] Forensics chain-of-custody logging enabled

### Data & Compliance
- [ ] Database enabled: `database.enabled: true` with PostgreSQL
- [ ] Data retention policies enforced
- [ ] GDPR compliance mode enabled
- [ ] Audit all operations with hash-chained logs

### Environment
- [ ] `ENVIRONMENT=production`
- [ ] `DEBUG=false`
- [ ] `ALLOWED_ORIGINS` set to production domains only
- [ ] TLS termination at load balancer
- [ ] Health/readiness endpoints public, metrics private

## Shared Production Requirements
- [ ] Secrets management via Azure Key Vault
- [ ] CI/CD pipeline with security scanning
- [ ] Monitoring: Prometheus + Grafana dashboards
- [ ] Log aggregation and alerting
- [ ] Backup/restore tested
- [ ] Disaster recovery runbook documented
- [ ] Penetration test of red team controls
- [ ] Blue team SOC analyst onboarding completed

## Sign-off
- [ ] Red Team Lead
- [ ] Blue Team Lead
- [ ] Security Architect
- [ ] DevOps
