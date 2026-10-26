# Vorsyghta Data Schema Review

## Core Auth & Tenancy
**tenants**
- tenant_id PK
- id, name, is_active, created_at
**users**
- user_id PK
- tenant_id FK → tenants.tenant_id
- current_tenant_id FK → tenants.tenant_id
- role, is_active, is_verified, onboarding_complete

## Billing
**tenant_subscriptions**
- id PK
- tenant_id FK → tenants.tenant_id
- owner_user_id FK → users.user_id

## Audit
**audit_logs**
- id PK
- actor, category, severity, context JSONB, created_at

## Knowledge Service - Relational
**knowledge_entries**
- entry_id PK
- user_id FK → users.user_id NULLABLE
- tenant_id FK → tenants.tenant_id NULLABLE
- title, content JSONB, category, source, severity, confidence
**knowledge_tags**
- id PK
- entry_id FK → knowledge_entries.entry_id CASCADE

## Onboarding - Relational
**onboarding_sessions**
- session_id PK
- user_id FK → users.user_id CASCADE
- tenant_id FK → tenants.tenant_id CASCADE
**onboarding_steps**
- step_id PK
- session_id FK → onboarding_sessions.session_id CASCADE
- step_type, payload JSONB

## Red/Blue/Orange/Green/Yellow/White Teams
Each team model has:
- team_id PK
- tenant_id FK → tenants.tenant_id
- user_id FK → users.user_id  optional
- created_at

## Threat Intel
**threat_indicators**
- id PK
- tenant_id FK → tenants.tenant_id

**threat_actors**, **threat_campaigns**, **threat_ttps** etc.

## Simulation / Exercises
**simulation_results**
- id PK
- tenant_id FK → tenants.tenant_id
- user_id FK → users.user_id

**tool_tracking**
- id PK
- tenant_id FK → tenants.tenant_id

## Relationships Summary
- tenants 1—* users
- tenants 1—* knowledge_entries
- tenants 1—* onboarding_sessions
- users 1—* knowledge_entries
- users 1—* onboarding_sessions
- onboarding_sessions 1—* onboarding_steps
- knowledge_entries 1—* knowledge_tags

All tables now use UUID/varchar primary keys with foreign keys to tenants and users for full referential integrity.
