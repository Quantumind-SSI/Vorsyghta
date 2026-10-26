# Vorsyghta Fully Relational Database Analysis

## Current Relational Core

### auth
- **tenants**
  - tenant_id PK
  - id, name, is_active, created_at
- **users**
  - user_id PK
  - id, email, hashed_password, role, is_active, is_verified, onboarding_complete
  - tenant_id FK → tenants.tenant_id
  - current_tenant_id FK → tenants.tenant_id
  - reset_token, verification_token

### billing
- **tenant_subscriptions**
  - id PK
  - tenant_id FK → tenants.tenant_id
  - owner_user_id FK → users.user_id

### audit
- **audit_logs**
  - id PK
  - actor, category, severity, context JSON, description, created_at

### simulation / exercises
- **simulation_results**
- **exercises** etc.

Knowledge service currently file-based.

## Proposed Fully Relational Model

### Knowledge Service Relational Tables

Replace file-based knowledge base with relational tables:

**knowledge_entries**
- entry_id PK UUID
- title TEXT
- content JSONB
- category TEXT
- source TEXT
- severity TEXT
- confidence NUMERIC
- expires_at TIMESTAMPTZ
- created_at, updated_at
- user_id FK → users.user_id NULLABLE
- tenant_id FK → tenants.tenant_id NULLABLE
- team_scope TEXT[]

**knowledge_tags**
- id PK
- entry_id FK → knowledge_entries.entry_id ON DELETE CASCADE
- tag TEXT

**knowledge_categories**
- category TEXT PK

Relationships:
- knowledge_entries.user_id → users.user_id
- knowledge_entries.tenant_id → tenants.tenant_id
- knowledge_entries.tags → knowledge_tags

### Onboarding Relational Tables

**onboarding_sessions**
- session_id PK
- user_id FK → users.user_id
- tenant_id FK → tenants.tenant_id
- started_at, completed_at

**onboarding_steps**
- step_id PK
- session_id FK → onboarding_sessions.session_id ON DELETE CASCADE
- step_type TEXT  // profile, use_cases, environments, review
- payload JSONB
- created_at

### ER Diagram Summary

tenants 1—* users
tenants 1—* tenant_subscriptions
users 1—* audit_logs
users 1—* knowledge_entries
tenants 1—* knowledge_entries
users 1—* onboarding_sessions 1—* onboarding_steps
users 1—* simulation_results
tenants 1—* simulation_results

## Migration Path

1. Create knowledge_entries, knowledge_tags tables with FKs to users/tenants
2. Migrate existing JSON files to relational tables via script
3. Update KnowledgeBase service to use SQLAlchemy models instead of FileKnowledgeBase
4. Create onboarding_sessions and onboarding_steps tables
5. Update onboarding actions to write to relational tables in addition to knowledge_entries
6. Add Alembic migrations for all new tables

PostgreSQL remains the optimal choice for this fully relational model.
