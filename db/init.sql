-- init.sql

-- Enable uuid-ossp extension for UUID generation (used for many primary keys)
-- This needs to be done once per database
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Set default timezone for the session (optional, but good for consistency)
SET TIMEZONE TO 'Asia/Kolkata'; -- Or 'UTC' if your application primarily uses UTC internally

--
-- 1. Table: fiduciaries (Can be created now, references users)
-- Manages registered Data Fiduciary profiles.
--
CREATE TABLE IF NOT EXISTS fiduciaries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    contact_person VARCHAR(255),
    email VARCHAR(255) UNIQUE,
    phone VARCHAR(50),
    address TEXT,
    primary_domain VARCHAR(255) NOT NULL UNIQUE,
    cms_cname VARCHAR(255) UNIQUE,
    dns_txt_record_token VARCHAR(255) UNIQUE,
    domain_validation_status VARCHAR(50) NOT NULL DEFAULT 'PENDING', -- PENDING, VALIDATED, FAILED
    is_significant_data_fiduciary BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, INACTIVE, REVOKED
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

--
-- 2. Table: operators (Must be created after roles, before fiduciaries, processors, etc.)
-- CMS internal users: DPOs, Admins, Auditors, Operators
--
CREATE TABLE IF NOT EXISTS operators (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255), -- Can be NULL initially for first-time setup
    mfa_secret VARCHAR(255), -- For TOTP
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, INACTIVE, PENDING_MFA_SETUP
    role VARCHAR(20) NOT NULL,
    fiduciary_id UUID REFERENCES fiduciaries(id),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMP WITH TIME ZONE,
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

--
-- 3. Table: processors (Can be created now, references fiduciaries and users)
-- Stores registered Data Processor profiles.
--
CREATE TABLE IF NOT EXISTS apps (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    phone VARCHAR(50),
    dpa_reference VARCHAR(255),
    processing_purposes VARCHAR(1000),
    status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, INACTIVE, REVOKED
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

--
-- 4. Table: consent_policies (Can be created now, references fiduciaries)
-- Stores definitions of personal data and cookie consent policies.
--
CREATE TABLE IF NOT EXISTS consent_policies (
    id VARCHAR(255) NOT NULL,
    version VARCHAR(10) NOT NULL,
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    effective_date TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'DRAFT', -- DRAFT, ACTIVE, ARCHIVED, EXPIRED
    jurisdiction VARCHAR(5) NOT NULL,
    policy_content JSONB NOT NULL, -- Full multilingual JSON policy
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, version)
);

--
-- 5. Table: consent_records (Can be created now, references fiduciaries and consent_policies)
-- Stores every instance of Data Principal consent.
--
CREATE TABLE IF NOT EXISTS consent_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(255) NOT NULL, -- Data Principal's ID (from Data Fiduciary's system)
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    policy_id VARCHAR(255) NOT NULL,
    policy_version VARCHAR(10) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL, -- When consent was given/updated
    jurisdiction VARCHAR(5) NOT NULL,
    language_selected VARCHAR(5) NOT NULL,
    consent_status_general VARCHAR(50) NOT NULL, -- granted, denied, custom
    consent_mechanism VARCHAR(100) NOT NULL,
    ip_address VARCHAR(100) NOT NULL,
    user_agent TEXT,
    data_point_consents JSONB NOT NULL, -- Granular consent for each purpose/category
    is_active_consent BOOLEAN NOT NULL DEFAULT TRUE, -- Flag for current active consent
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (policy_id, policy_version) REFERENCES consent_policies(id, version)
);

-- FIX: Define the partial unique index separately after table creation
CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_active_consent
ON consent_records (user_id, fiduciary_id) WHERE is_active_consent IS TRUE;


--
-- 6. Table: audit_logs (Can be created now, references users)
-- Stores immutable logs of all significant system events and user actions.
--
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    user_id VARCHAR(255) NOT NULL,
    service_type VARCHAR(100) NOT NULL, -- e.g., APP, SYSTEM, DPO
    service_id UUID, -- ID of the affected entity (UUID or other string ID)
    audit_action VARCHAR(100) NOT NULL, -- e.g., POLICY_PUBLISHED, CONSENT_GIVEN, CONSENT_WITHDRAWN, ERASURE_REQUEST
    context_details TEXT -- relevant data/changes
);

--
-- 7. Table: grievances (Can be created now, references users and fiduciaries)
-- Stores Data Principal grievances.
--
CREATE TABLE IF NOT EXISTS grievances (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(255) NOT NULL, -- Data Principal's ID
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    type VARCHAR(30) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    submission_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    status VARCHAR(50) NOT NULL DEFAULT 'NEW', -- NEW, IN_PROGRESS, RESOLVED, CLOSED, ESCALATED
    assigned_dpo_user_id UUID REFERENCES operators(id),
    resolution_details TEXT,
    resolution_timestamp TIMESTAMP WITH TIME ZONE,
    communication_log JSONB,
    attachments JSONB,
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    due_date TIMESTAMP WITH TIME ZONE
);

--
-- 8. Table: api_keys (Can be created now, references apps)
--
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key_value VARCHAR(255) NOT NULL UNIQUE, -- Store hashed/encrypted value, not plain text
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    app_id UUID REFERENCES apps(id), -- Nullable if key is for a specific app
    description TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, INACTIVE, REVOKED, EXPIRED
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb, -- Array of granted API permissions
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    revoked_at TIMESTAMP WITH TIME ZONE
);

--
-- 9. Table: data_principal
--
CREATE TABLE IF NOT EXISTS data_principal (
    user_id VARCHAR(255) PRIMARY KEY , -- Data Principal's ID
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    last_consent_mechanism VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_ces_run TIMESTAMP
);

--
-- 10. Table: consent_validations
--
CREATE TABLE IF NOT EXISTS consent_validations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    app_id UUID REFERENCES apps(id), -- Nullable if key is for a specific app
    user_id VARCHAR(255) NOT NULL, -- Data Principal's ID
    purpose_id VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'VALID', -- VALID, INVALID
    accessed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

--
-- 11. Table: purge_requests (Can be created now, references users, fiduciaries, processors, legal_retention_exceptions)
--
CREATE TABLE IF NOT EXISTS purge_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(255) NOT NULL, -- Data Principal ID whose data is to be purged
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    purpose_id VARCHAR(100) NOT NULL, -- e.g., "purpose_website_analytics", "purpose_community_engagement"
    app_id UUID REFERENCES apps(id),
    trigger_event VARCHAR(100) NOT NULL, -- e.g., "ConsentWithdrawal", "RetentionPolicyExpiry", "ErasureRequest"
    status VARCHAR(50) NOT NULL DEFAULT 'PENDING', -- PENDING, IN_PROGRESS, COMPLETED, FAILED, UNDER_LEGAL_HOLD
    initiated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    details TEXT, -- Additional details or error messages or legal exception
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

--
-- 12. Table: notifications
--
CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    recipient_type VARCHAR(50) NOT NULL, -- PRINCIPAL, DPO, APP
    recipient_id VARCHAR(255) NOT NULL, -- User ID, DPO ID, App ID
    fiduciary_id UUID REFERENCES fiduciaries(id), -- Contextual Fiduciary ID
    notification_type VARCHAR(100) NOT NULL,
    read_at TIMESTAMP WITH TIME ZONE, -- When recipient read it (for IN_APP)
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

--
-- 13. Table to manage background compliance and export jobs
--

CREATE TABLE IF NOT EXISTS jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id UUID NOT NULL,
    job_type VARCHAR(20) NOT NULL, -- CES, EXPORT
    subtype VARCHAR(50),           -- CONSENT, PRINCIPAL, GRIEVANCE, AUDIT (for EXPORT)
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, RUNNING, COMPLETED, FAILED
    start_date DATE,               -- Filter for Exports
    end_date DATE,                 -- Filter for Exports
    error_message TEXT,
    output_file_path TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_jobs_status ON jobs(status) WHERE status = 'PENDING';