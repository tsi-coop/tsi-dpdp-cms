-- 23_rights_requests.sql
-- Access (s.11) and correction (s.12) requests (v0.6).
--
-- The CMS tracks the request and its outcome; it holds no personal data values. For an access request the DPO
-- gathers the data from the business systems and delivers it outside the CMS; for a correction the principal
-- describes what is wrong in words. due_date is NULL unless ACCESS_SLA_DAYS / CORRECTION_SLA_DAYS are configured:
-- the legal timelines are a decision for the operator, not something the software assumes.
-- Also adds the "rights" permission to the built-in roles (DPO manage, OPERATOR write; AUDITOR already reads all).
-- Safe to re-run.

CREATE SEQUENCE IF NOT EXISTS rights_request_reference_seq;

CREATE TABLE IF NOT EXISTS rights_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    reference_number VARCHAR(30) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    type VARCHAR(20) NOT NULL CHECK (type IN ('ACCESS', 'CORRECTION')),
    description TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'NEW' CHECK (status IN ('NEW', 'IN_PROGRESS', 'FULFILLED', 'REJECTED')),
    due_date TIMESTAMP WITH TIME ZONE,
    assigned_dpo_user_id UUID REFERENCES operators(id),
    outcome_note TEXT,
    channel VARCHAR(30),
    submission_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    resolution_timestamp TIMESTAMP WITH TIME ZONE,
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_rights_requests_reference ON rights_requests (reference_number);
CREATE INDEX IF NOT EXISTS idx_rights_requests_fid_ts ON rights_requests (fiduciary_id, submission_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_rights_requests_fid_user ON rights_requests (fiduciary_id, user_id, submission_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_rights_requests_open ON rights_requests (status, due_date ASC) WHERE status IN ('NEW', 'IN_PROGRESS');

-- Role permissions: add "rights" to databases that already have the built-in roles
UPDATE roles SET permissions = array_append(permissions, 'rights:manage'), last_updated_at = NOW()
 WHERE upper(name) = 'DPO' AND fiduciary_id IS NULL AND NOT ('rights:manage' = ANY (permissions));
UPDATE roles SET permissions = array_append(permissions, 'rights:write'), last_updated_at = NOW()
 WHERE upper(name) = 'OPERATOR' AND fiduciary_id IS NULL AND NOT ('rights:write' = ANY (permissions));
