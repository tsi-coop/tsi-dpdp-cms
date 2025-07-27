-- init.sql

-- Enable uuid-ossp extension for UUID generation (used for many primary keys)
-- This needs to be done once per database
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Set default timezone for the session (optional, but good for consistency)
-- It's often recommended to set this to 'UTC' for server-side applications
-- and handle timezone conversions in the application layer or presentation layer.
SET TIMEZONE TO 'Asia/Kolkata'; -- Or 'UTC' if your application primarily uses UTC internally

--
-- Table: fiduciaries
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
    cms_cname VARCHAR(255) UNIQUE, -- CNAME can be null if not using aggregator mode or not yet set
    dns_txt_record_token VARCHAR(255) UNIQUE,
    domain_validation_status VARCHAR(50) NOT NULL DEFAULT 'PENDING', -- PENDING, VALIDATED, FAILED
    is_significant_data_fiduciary BOOLEAN NOT NULL DEFAULT FALSE,
    dpo_user_id UUID, -- FK to users(id) - will be added later by ALTER TABLE
    dpb_registration_id VARCHAR(100) UNIQUE,
    status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, INACTIVE, REVOKED
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by_user_id UUID, -- FK to users(id) - will be added later
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_by_user_id UUID, -- FK to users(id) - will be added later
    deleted_at TIMESTAMP WITH TIME ZONE,
    deleted_by_user_id UUID -- FK to users(id) - will be added later
);

--
-- Table: processors
-- Stores registered Data Processor profiles.
--
CREATE TABLE IF NOT EXISTS processors (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    name VARCHAR(255) NOT NULL,
    contact_person VARCHAR(255),
    email VARCHAR(255),
    phone VARCHAR(50),
    address TEXT,
    jurisdiction VARCHAR(50),
    dpa_reference VARCHAR(255) UNIQUE,
    dpa_effective_date DATE,
    dpa_expiry_date DATE,
    processing_purposes JSONB NOT NULL DEFAULT '[]'::jsonb,
    data_categories_processed JSONB NOT NULL DEFAULT '[]'::jsonb,
    security_measures_description TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, INACTIVE, REVOKED
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by_user_id UUID, -- FK to users(id) - will be added later
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_by_user_id UUID, -- FK to users(id) - will be added later
    deleted_at TIMESTAMP WITH TIME ZONE,
    deleted_by_user_id UUID, -- FK to users(id) - will be added later
    UNIQUE (fiduciary_id, name) -- Ensures a processor name is unique per fiduciary
);

--
-- Table: consent_policies
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
    created_by_user_id UUID, -- FK to users(id) - will be added later
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_by_user_id UUID, -- FK to users(id) - will be added later
    deleted_at TIMESTAMP WITH TIME ZONE,
    deleted_by_user_id UUID, -- FK to users(id) - will be added later
    PRIMARY KEY (id, version),
    UNIQUE (fiduciary_id, jurisdiction, status) -- Ensures only one active policy per fiduciary/jurisdiction at a time
);

--
-- Table: consent_records
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
    consent_mechanism VARCHAR(100) NOT NULL, -- FIX: Added missing comma here
    ip_address INET,
    user_agent TEXT,
    data_point_consents JSONB NOT NULL, -- Granular consent for each purpose/category
    is_active_consent BOOLEAN NOT NULL DEFAULT TRUE, -- Flag for current active consent
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by_user_id UUID, -- FIX: Added this column
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_by_user_id UUID, -- FIX: Added this column
    FOREIGN KEY (policy_id, policy_version) REFERENCES consent_policies(id, version),
    -- Constraint to ensure only one active consent record per user per fiduciary
    UNIQUE (user_id, fiduciary_id, is_active_consent) WHERE is_active_consent IS TRUE
);

--
-- Table: users (CMS internal users: DPOs, Admins, Auditors, Operators)
--
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    mfa_secret VARCHAR(255), -- For TOTP
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, INACTIVE, PENDING_MFA_SETUP
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMP WITH TIME ZONE,
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE,
    deleted_by_user_id UUID -- Self-referencing FK, will be added later
);

-- Add FKs to fiduciaries and processors tables that reference users(id)
-- These ALTER TABLE statements must come AFTER the 'users' table is created
ALTER TABLE fiduciaries
ADD CONSTRAINT fk_fiduciaries_dpo_user
FOREIGN KEY (dpo_user_id) REFERENCES users(id);

ALTER TABLE fiduciaries
ADD CONSTRAINT fk_fiduciaries_created_by
FOREIGN KEY (created_by_user_id) REFERENCES users(id);

ALTER TABLE fiduciaries
ADD CONSTRAINT fk_fiduciaries_last_updated_by
FOREIGN KEY (last_updated_by_user_id) REFERENCES users(id);

ALTER TABLE fiduciaries
ADD CONSTRAINT fk_fiduciaries_deleted_by
FOREIGN KEY (deleted_by_user_id) REFERENCES users(id);


ALTER TABLE processors
ADD CONSTRAINT fk_processors_created_by
FOREIGN KEY (created_by_user_id) REFERENCES users(id);

ALTER TABLE processors
ADD CONSTRAINT fk_processors_last_updated_by
FOREIGN KEY (last_updated_by_user_id) REFERENCES users(id);

ALTER TABLE processors
ADD CONSTRAINT fk_processors_deleted_by
FOREIGN KEY (deleted_by_user_id) REFERENCES users(id);

ALTER TABLE consent_policies
ADD CONSTRAINT fk_consent_policies_created_by
FOREIGN KEY (created_by_user_id) REFERENCES users(id);

ALTER TABLE consent_policies
ADD CONSTRAINT fk_consent_policies_last_updated_by
FOREIGN KEY (last_updated_by_user_id) REFERENCES users(id);

ALTER TABLE consent_policies
ADD CONSTRAINT fk_consent_policies_deleted_by
FOREIGN KEY (deleted_by_user_id) REFERENCES users(id);


--
-- Table: roles
-- Defines roles and their permissions.
--
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL UNIQUE, -- e.g., 'Admin', 'DPO', 'Auditor'
    description TEXT,
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb, -- Array of strings, e.g., ["fiduciary:create", "policy:publish"]
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

--
-- Table: user_roles (Junction table for N:M relationship between users and roles)
--
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id),
    role_id UUID NOT NULL REFERENCES roles(id),
    assigned_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    assigned_by_user_id UUID REFERENCES users(id),
    PRIMARY KEY (user_id, role_id)
);

--
-- Table: audit_logs
-- Stores immutable logs of all significant system events and user actions.
--
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    actor_user_id UUID REFERENCES users(id), -- User who performed action, NULL for system actions
    actor_system_id VARCHAR(100), -- ID of the system process/service
    action_type VARCHAR(100) NOT NULL, -- e.g., POLICY_PUBLISHED, CONSENT_UPDATED
    entity_type VARCHAR(100) NOT NULL, -- e.g., ConsentPolicy, ConsentRecord
    entity_id VARCHAR(255), -- ID of the affected entity (UUID or other string ID)
    context_details JSONB, -- JSON payload of relevant data/changes
    ip_address INET,
    status VARCHAR(50) NOT NULL, -- SUCCESS, FAILURE
    source_module VARCHAR(100) NOT NULL -- e.g., PolicyService, ConsentRecordService
);

--
-- Table: grievances
-- Stores Data Principal grievances.
--
CREATE TABLE IF NOT EXISTS grievances (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(255) NOT NULL, -- Data Principal's ID
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    subject VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    submission_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    status VARCHAR(50) NOT NULL DEFAULT 'NEW', -- NEW, IN_PROGRESS, RESOLVED, CLOSED, ESCALATED
    assigned_dpo_user_id UUID REFERENCES users(id),
    resolution_details TEXT,
    resolution_timestamp TIMESTAMP WITH TIME ZONE,
    communication_log JSONB,
    attachments JSONB,
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_by_user_id UUID REFERENCES users(id),
    due_date TIMESTAMP WITH TIME ZONE
);

--
-- Table: retention_policies
-- Defines data retention rules.
--
CREATE TABLE IF NOT EXISTS retention_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    applicable_purposes JSONB NOT NULL DEFAULT '[]'::jsonb,
    applicable_data_categories JSONB NOT NULL DEFAULT '[]'::jsonb,
    retention_duration_value INTEGER NOT NULL,
    retention_duration_unit VARCHAR(50) NOT NULL, -- DAYS, MONTHS, YEARS
    retention_start_event VARCHAR(100) NOT NULL, -- CONSENT_GIVEN, SERVICE_TERMINATED
    action_at_expiry VARCHAR(50) NOT NULL, -- DELETE, ANONYMIZE, ARCHIVE
    legal_reference TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, INACTIVE
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by_user_id UUID REFERENCES users(id),
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_by_user_id UUID REFERENCES users(id)
);

--
-- Table: api_keys (New table for API Keys Management)
--
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key_value VARCHAR(255) NOT NULL UNIQUE, -- Store hashed/encrypted value, not plain text
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    processor_id UUID REFERENCES processors(id), -- Nullable if key is for a specific Processor
    owner_type VARCHAR(50) NOT NULL, -- FIDUCIARY_APP, PROCESSOR_INTEGRATION, CMS_ADMIN_TOOL
    description TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, INACTIVE, REVOKED, EXPIRED
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb, -- Array of granted API permissions
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by_user_id UUID REFERENCES users(id),
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by_user_id UUID REFERENCES users(id)
);

--
-- Table: legal_retention_exceptions (New table for legal hold exceptions)
--
CREATE TABLE IF NOT EXISTS legal_retention_exceptions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id UUID REFERENCES fiduciaries(id), -- If specific per Fiduciary, else NULL
    exception_id VARCHAR(100) NOT NULL UNIQUE, -- e.g., "PMLA_AML_RETENTION"
    name VARCHAR(255) NOT NULL,
    legal_reference TEXT NOT NULL,
    applicable_data_categories JSONB NOT NULL DEFAULT '[]'::jsonb,
    applicable_processing_purposes JSONB NOT NULL DEFAULT '[]'::jsonb,
    retention_period_override VARCHAR(100),
    condition_for_override TEXT, -- SQL snippet, rule ID, or reference to complex evaluation logic
    status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by_user_id UUID REFERENCES users(id),
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_by_user_id UUID REFERENCES users(id)
);

--
-- Table: purge_requests (New table to track purge operations)
--
CREATE TABLE IF NOT EXISTS purge_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(255) NOT NULL, -- Data Principal ID whose data is to be purged
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    processor_id UUID REFERENCES processors(id), -- Nullable, if purge is at Fiduciary level directly
    trigger_event VARCHAR(100) NOT NULL, -- e.g., "ConsentWithdrawal", "RetentionPolicyExpiry", "ErasureRequest"
    data_categories_to_purge JSONB NOT NULL DEFAULT '[]'::jsonb,
    processing_purposes_affected JSONB NOT NULL DEFAULT '[]'::jsonb,
    status VARCHAR(50) NOT NULL DEFAULT 'PENDING', -- PENDING, IN_PROGRESS, COMPLETED, FAILED, UNDER_LEGAL_HOLD
    initiated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    records_affected_count INTEGER,
    details TEXT, -- Additional details or error messages
    legal_exception_applied_id UUID REFERENCES legal_retention_exceptions(id), -- FK if purge was legally overridden
    error_message TEXT,
    confirmed_by_entity_id UUID, -- ID of the Fiduciary/Processor if they confirm via API
    confirmed_at TIMESTAMP WITH TIME ZONE,
    created_by_user_id UUID REFERENCES users(id), -- If initiated by CMS admin/DPO
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

--
-- Table: notification_templates (For NotificationService)
--
CREATE TABLE IF NOT EXISTS notification_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    category VARCHAR(50) NOT NULL, -- e.g., Compliance, Security, Grievance
    severity VARCHAR(50) NOT NULL, -- e.g., CRITICAL, HIGH, MEDIUM, INFO
    channels_enabled JSONB NOT NULL DEFAULT '[]'::jsonb, -- e.g., ["EMAIL", "SMS", "IN_APP"]
    content_template JSONB NOT NULL, -- Multilingual text with placeholders
    action_link_template TEXT, -- URL template for clickable actions
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by_user_id UUID REFERENCES users(id),
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_by_user_id UUID REFERENCES users(id)
);

--
-- Table: notification_instances (For NotificationService)
--
CREATE TABLE IF NOT EXISTS notification_instances (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    template_id UUID NOT NULL REFERENCES notification_templates(id),
    recipient_type VARCHAR(50) NOT NULL, -- DATA_PRINCIPAL, DPO_ADMIN, DATA_PROCESSOR
    recipient_id VARCHAR(255) NOT NULL, -- User ID, Fiduciary ID, Processor ID
    fiduciary_id UUID REFERENCES fiduciaries(id), -- Contextual Fiduciary ID
    status VARCHAR(50) NOT NULL, -- SENT, FAILED, DELIVERED, READ
    channel_used VARCHAR(50) NOT NULL, -- EMAIL, SMS, IN_APP
    sent_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    payload_data JSONB, -- Actual data used to populate template
    error_details TEXT, -- If status is FAILED
    read_at TIMESTAMP WITH TIME ZONE, -- When recipient read it (for IN_APP)
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by_user_id UUID REFERENCES users(id) -- User who dispatched it (e.g., system user)
);


-- Add initial roles (optional, but good for first setup)
INSERT INTO roles (id, name, description, permissions, created_at, last_updated_at) VALUES
    (uuid_generate_v4(), 'Admin', 'Full system administration access', '["*:*"]'::jsonb, NOW(), NOW()),
    (uuid_generate_v4(), 'DPO', 'Data Protection Officer role with compliance oversight', '["policy:read", "policy:publish", "consent:read", "grievance:manage", "audit:read", "dpb_report:submit", "fiduciary:read", "processor:read", "retention:read", "purge:read", "purge:execute"]'::jsonb, NOW(), NOW()),
    (uuid_generate_v4(), 'Auditor', 'Read-only access for auditing purposes', '["policy:read", "consent:read", "grievance:read", "audit:read", "fiduciary:read", "processor:read", "retention:read", "purge:read"]'::jsonb, NOW(), NOW()),
    (uuid_generate_v4(), 'Operator', 'Limited access for operational tasks', '["grievance:manage_limited", "purge:execute_limited"]'::jsonb, NOW(), NOW());

-- Add a default admin user (IMPORTANT: CHANGE PASSWORD AFTER INITIAL SETUP)
-- You should replace 'your_initial_admin_password_hash_here' with a strong hash generated by your application
-- For a real system, initial admin creation should be part of a secure setup process, not hardcoded.
INSERT INTO users (id, username, email, password_hash, mfa_enabled, status, created_at, last_updated_at) VALUES
    (uuid_generate_v4(), 'superadmin', 'admin@tsicoop.com', 'your_initial_admin_password_hash_here', FALSE, 'ACTIVE', NOW(), NOW());

-- Assign the 'Admin' role to the default admin user
INSERT INTO user_roles (user_id, role_id, assigned_at) VALUES
    ((SELECT id FROM users WHERE username = 'superadmin'), (SELECT id FROM roles WHERE name = 'Admin'), NOW());