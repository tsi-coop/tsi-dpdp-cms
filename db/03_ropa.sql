-- 03_ropa.sql
-- Records of Processing Activities (ROPA) schema
-- DPDP Act 2023, Section 8 accountability obligations

CREATE TABLE IF NOT EXISTS ropa_entries (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id            UUID NOT NULL REFERENCES fiduciaries(id),
    app_id                  UUID REFERENCES apps(id),
    activity_name           TEXT NOT NULL,
    purpose                 TEXT NOT NULL,
    legal_basis             VARCHAR(30) NOT NULL
                                CHECK (legal_basis IN ('consent','legal_obligation','vital_interest','legitimate_use')),
    data_categories         JSONB NOT NULL DEFAULT '[]',
    data_subject_categories JSONB NOT NULL DEFAULT '[]',
    retention_period_days   INTEGER,
    retention_start_event   VARCHAR(20)
                                CHECK (retention_start_event IN ('COLLECTION','CESSATION')),
    processors              JSONB DEFAULT '[]',
    cross_border_transfers  JSONB DEFAULT '[]',
    security_measures       TEXT,
    dpo_id                  UUID REFERENCES operators(id),
    linked_policy_ids       JSONB DEFAULT '[]',
    status                  VARCHAR(20) NOT NULL DEFAULT 'draft'
                                CHECK (status IN ('draft','active','under_review','retired')),
    version                 INTEGER NOT NULL DEFAULT 1,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ropa_history (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ropa_entry_id   UUID NOT NULL REFERENCES ropa_entries(id),
    version         INTEGER NOT NULL,
    snapshot        JSONB NOT NULL,
    changed_by      UUID REFERENCES operators(id),
    changed_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Link consent records to their governing ROPA entry
ALTER TABLE consent_records
    ADD COLUMN IF NOT EXISTS ropa_entry_id UUID REFERENCES ropa_entries(id);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_ropa_entries_fiduciary_status   ON ropa_entries (fiduciary_id, status);
CREATE INDEX IF NOT EXISTS idx_ropa_entries_fiduciary_app      ON ropa_entries (fiduciary_id, app_id);
CREATE INDEX IF NOT EXISTS idx_ropa_entries_legal_basis        ON ropa_entries (fiduciary_id, legal_basis);
CREATE INDEX IF NOT EXISTS idx_ropa_history_entry_version      ON ropa_history (ropa_entry_id, version DESC);
CREATE INDEX IF NOT EXISTS idx_consent_records_ropa_entry      ON consent_records (ropa_entry_id);
