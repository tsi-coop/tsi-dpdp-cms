-- 21_consent_capture.sql
-- Consent capture evidence (v0.6).
--
--  capture_mechanism     how the consent reached the CMS, taken from the authenticated path:
--                        PRINCIPAL_PORTAL (principal token), API_INTEGRATION (API key), WALLET.
--                        (consent_mechanism is NOT this: it holds the action - CONSENT_GIVEN,
--                        CONSENT_WITHDRAWN, ERASURE_REQUEST - and the CES engine reads it as such.)
--  client_metadata       what the calling system CLAIMED about the client ({user_agent, ip_address,
--                        session_id}). Kept apart from user_agent / ip_address, which the CMS observed itself.
--  supersedes_record_id  the consent record this one replaced, so the history reads as a chain:
--                        grant -> partial withdrawal -> withdrawal, never overwritten.
-- Safe to re-run.

ALTER TABLE consent_records ADD COLUMN IF NOT EXISTS capture_mechanism VARCHAR(30);
ALTER TABLE consent_records ADD COLUMN IF NOT EXISTS client_metadata JSONB;
ALTER TABLE consent_records ADD COLUMN IF NOT EXISTS supersedes_record_id UUID REFERENCES consent_records(id);

CREATE INDEX IF NOT EXISTS idx_consent_records_supersedes
    ON consent_records (supersedes_record_id) WHERE supersedes_record_id IS NOT NULL;
