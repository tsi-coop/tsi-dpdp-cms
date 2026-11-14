-- 25_purge_and_legal_holds.sql
-- Purge confirmation evidence, the purge completion deadline flag and time-bound legal holds (v0.6).
--
--  confirmed_by / confirmed_by_type / confirmed_at   who confirmed the purge, taken from the credential (the API key's
--                       app, or the operator), never from the request body.
--  claimed_record_count what the processor SAYS it removed. The CMS cannot count records held in the processor's own
--                       systems, so this is kept as a claim and is not presented as verified.
--  sla_flagged_at       set by the daily job when PURGE_COMPLETION_SLA_DAYS is configured and the purge is still unconfirmed.
--  legal_holds          a time-bound reason to keep a principal's data (court order, investigation). While a hold is
--                       active, purges for that principal (and purpose, if named) are put on LEGAL_HOLD_APPLIED; a daily
--                       sweep releases ended holds and resumes the purges that were held by them.
-- Safe to re-run.

ALTER TABLE purge_requests ADD COLUMN IF NOT EXISTS claimed_record_count BIGINT;
ALTER TABLE purge_requests ADD COLUMN IF NOT EXISTS confirmed_by VARCHAR(255);
ALTER TABLE purge_requests ADD COLUMN IF NOT EXISTS confirmed_by_type VARCHAR(20);
ALTER TABLE purge_requests ADD COLUMN IF NOT EXISTS confirmed_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE purge_requests ADD COLUMN IF NOT EXISTS sla_flagged_at TIMESTAMP WITH TIME ZONE;

CREATE TABLE IF NOT EXISTS legal_holds (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    user_id VARCHAR(255) NOT NULL,
    purpose_id VARCHAR(255),                       -- NULL = every purpose of this principal
    reason TEXT NOT NULL,
    reference VARCHAR(100),                        -- court order / case number
    placed_by VARCHAR(255) NOT NULL,
    placed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    valid_until TIMESTAMP WITH TIME ZONE NOT NULL,
    released_at TIMESTAMP WITH TIME ZONE,
    released_by VARCHAR(255),
    release_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_legal_holds_principal ON legal_holds (fiduciary_id, user_id) WHERE released_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_legal_holds_due ON legal_holds (valid_until) WHERE released_at IS NULL;

ALTER TABLE purge_requests ADD COLUMN IF NOT EXISTS legal_hold_id UUID REFERENCES legal_holds(id);
CREATE INDEX IF NOT EXISTS idx_purge_requests_held ON purge_requests (legal_hold_id) WHERE legal_hold_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_purge_requests_open_age ON purge_requests (initiated_at) WHERE status NOT IN ('PURGE_COMPLETED', 'PURGE_CANCELLED', 'LEGAL_HOLD_APPLIED');
