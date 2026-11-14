-- 24_nominations_and_purposes.sql
-- Nominations (DPDP s.14) and the purpose lifecycle (v0.6).
--
--  nominations      a principal's nominee for exercising their rights in the event of death or incapacity.
--                   Nominee name and contact are stored encrypted (like operator e-mail addresses).
--                   The CMS only records the nomination: the DPO verifies any later claim by the nominee.
--  purpose_states   OPEN / CLOSED per (fiduciary, purpose). CLOSED: no new grants; existing consents on that
--                   purpose are withdrawn (so the normal retention timer and purge machinery apply) and, once
--                   the governing retention period has run, the purge carries retention_action
--                   (ERASE or DE_IDENTIFY).
--  purge_requests.action   what the processor must do: ERASE (default) or DE_IDENTIFY.
-- Also adds the "purposes" permission to the built-in roles. Safe to re-run.

CREATE TABLE IF NOT EXISTS nominations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    user_id VARCHAR(255) NOT NULL,
    nominee_name_enc TEXT NOT NULL,
    nominee_contact_enc TEXT NOT NULL,
    nominee_relationship VARCHAR(50),
    valid_from TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    valid_until TIMESTAMP WITH TIME ZONE,
    status VARCHAR(10) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('PENDING', 'ACTIVE', 'EXPIRED', 'REVOKED')),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMP WITH TIME ZONE,
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_nominations_principal ON nominations (fiduciary_id, user_id, status);
CREATE INDEX IF NOT EXISTS idx_nominations_sweep ON nominations (valid_until) WHERE status IN ('PENDING', 'ACTIVE');

CREATE TABLE IF NOT EXISTS purpose_states (
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    purpose_id VARCHAR(255) NOT NULL,
    state VARCHAR(10) NOT NULL DEFAULT 'OPEN' CHECK (state IN ('OPEN', 'CLOSED')),
    retention_action VARCHAR(12) NOT NULL DEFAULT 'ERASE' CHECK (retention_action IN ('ERASE', 'DE_IDENTIFY')),
    reason TEXT,
    changed_by VARCHAR(255),
    changed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    closed_at TIMESTAMP WITH TIME ZONE,
    principals_invalidated INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (fiduciary_id, purpose_id)
);

ALTER TABLE purge_requests ADD COLUMN IF NOT EXISTS action VARCHAR(12) NOT NULL DEFAULT 'ERASE';

UPDATE roles SET permissions = array_append(permissions, 'purposes:manage'), last_updated_at = NOW()
 WHERE upper(name) = 'DPO' AND fiduciary_id IS NULL AND NOT ('purposes:manage' = ANY (permissions));
UPDATE roles SET permissions = array_append(permissions, 'purposes:read'), last_updated_at = NOW()
 WHERE upper(name) = 'OPERATOR' AND fiduciary_id IS NULL AND NOT ('purposes:read' = ANY (permissions));
