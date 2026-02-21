-- -----------------------------------------------------------------------------------
-- DOCKER ORGANIZATION INSTRUCTIONS:
-- 1. Save this file as '02_audit_ledger_schema.sql' inside the './db' folder.
-- 2. This script ENHANCES the existing audit_logs table created in 01_init.sql.
-- -----------------------------------------------------------------------------------

-- 1. Enhance existing Audit Logs Table with Hash Chaining & Evidence Fields
-- Adding columns for tamper-evidence as per BSA Section 62.
ALTER TABLE audit_logs 
ADD COLUMN IF NOT EXISTS prev_log_hash VARCHAR(64),
ADD COLUMN IF NOT EXISTS current_log_hash VARCHAR(64),
ADD COLUMN IF NOT EXISTS digital_signature TEXT,
ADD COLUMN IF NOT EXISTS system_metadata JSONB;

-- 2. Create Evidence Certification Table (New for High-Assurance)
-- Stores generated attestations for legal/court submission.
CREATE TABLE IF NOT EXISTS evidence_certificates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    subject_principal_id VARCHAR(255) NOT NULL,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    certifying_officer_id UUID REFERENCES operators(id),
    case_ref_id VARCHAR(100),            -- Inquiry or Board reference ID
    certificate_data JSONB NOT NULL,     -- Full snapshot of the verified chain segment
    attestation_text TEXT                -- Legally compliant declaration string
);

-- -----------------------------------------------------------------------------------
-- INDICES FOR PERFORMANCE & INTEGRITY CHECKS
-- -----------------------------------------------------------------------------------

-- Traversal index for the new hash chain
CREATE INDEX IF NOT EXISTS idx_audit_hash_traversal ON audit_logs (current_log_hash);

-- Index for principal-specific evidence discovery (if not in 01)
CREATE INDEX IF NOT EXISTS idx_audit_principal_trace ON audit_logs (user_id, timestamp DESC);

-- Index for fiduciary activity monitoring (if not in 01)
CREATE INDEX IF NOT EXISTS idx_audit_fiduciary_logs ON audit_logs (fiduciary_id, timestamp DESC);