CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(255) PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email VARCHAR(320) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'user',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(160) NOT NULL,
    description TEXT,
    default_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_projects_owner_id ON projects(owner_id);
CREATE INDEX IF NOT EXISTS ix_projects_owner_name ON projects(owner_id, name);

CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'queued',
    provider VARCHAR(64) NOT NULL DEFAULT 'source',
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_message TEXT,
    webhook_url VARCHAR(2048),
    queued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_scans_owner_id ON scans(owner_id);
CREATE INDEX IF NOT EXISTS ix_scans_project_id ON scans(project_id);
CREATE INDEX IF NOT EXISTS ix_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS ix_scans_owner_created ON scans(owner_id, created_at);
CREATE INDEX IF NOT EXISTS ix_scans_status_queued ON scans(status, queued_at);

CREATE TABLE IF NOT EXISTS results (
    id SERIAL PRIMARY KEY,
    scan_id UUID NOT NULL UNIQUE REFERENCES scans(id) ON DELETE CASCADE,
    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    findings JSONB NOT NULL DEFAULT '[]'::jsonb,
    warnings JSONB NOT NULL DEFAULT '[]'::jsonb,
    raw_result JSONB NOT NULL DEFAULT '{}'::jsonb,
    html_report TEXT,
    siem_jsonl TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_results_scan_id ON results(scan_id);
