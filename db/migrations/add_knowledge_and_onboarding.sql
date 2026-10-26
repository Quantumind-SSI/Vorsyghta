-- Knowledge Service Relational Tables
CREATE TABLE IF NOT EXISTS knowledge_entries (
    entry_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    content JSONB NOT NULL,
    category TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'manual_entry',
    severity TEXT,
    confidence NUMERIC,
    expires_at TIMESTAMPTZ,
    user_id VARCHAR REFERENCES users(user_id) ON DELETE SET NULL,
    tenant_id VARCHAR REFERENCES tenants(tenant_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS knowledge_tags (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entry_id UUID NOT NULL REFERENCES knowledge_entries(entry_id) ON DELETE CASCADE,
    tag TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_knowledge_tags_tag ON knowledge_tags(tag);

-- Onboarding Relational Tables
CREATE TABLE IF NOT EXISTS onboarding_sessions (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    tenant_id VARCHAR NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS onboarding_steps (
    step_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES onboarding_sessions(session_id) ON DELETE CASCADE,
    step_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
