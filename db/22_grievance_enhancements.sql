-- 22_grievance_enhancements.sql
-- Grievance handling (v0.6): channel, reference number, link to a consent record, principal feedback and
-- validated attachments.
--
--  channel            how the grievance arrived (PRINCIPAL_PORTAL, API_INTEGRATION, OPERATOR_CONSOLE, EMAIL, PHONE, ...).
--  reference_number   GRV-<year>-<6 digits>, unique, given to the principal so they can quote it.
--  consent_record_id  optional: the consent record the grievance is about (checked to belong to the same principal).
--  feedback_*         the principal's rating (1-5) and comment once the grievance is resolved or closed; set once.
--  grievance_attachments  files (PDF/PNG/JPEG/plain text, max 5 MB each, validated by the application) kept
--                     in the database so they follow the grievance's retention and erasure.
-- Safe to re-run.

CREATE SEQUENCE IF NOT EXISTS grievance_reference_seq;

ALTER TABLE grievances ADD COLUMN IF NOT EXISTS channel VARCHAR(30);
ALTER TABLE grievances ADD COLUMN IF NOT EXISTS reference_number VARCHAR(30);
ALTER TABLE grievances ADD COLUMN IF NOT EXISTS consent_record_id UUID REFERENCES consent_records(id);
ALTER TABLE grievances ADD COLUMN IF NOT EXISTS feedback_rating SMALLINT CHECK (feedback_rating BETWEEN 1 AND 5);
ALTER TABLE grievances ADD COLUMN IF NOT EXISTS feedback_comment TEXT;
ALTER TABLE grievances ADD COLUMN IF NOT EXISTS feedback_at TIMESTAMP WITH TIME ZONE;

-- Give existing grievances a reference number (oldest first)
WITH ordered AS (
    SELECT id, submission_timestamp FROM grievances WHERE reference_number IS NULL ORDER BY submission_timestamp, id
)
UPDATE grievances g
   SET reference_number = 'GRV-' || to_char(o.submission_timestamp, 'YYYY') || '-' || lpad(nextval('grievance_reference_seq')::text, 6, '0')
  FROM ordered o WHERE g.id = o.id;

CREATE UNIQUE INDEX IF NOT EXISTS idx_grievances_reference ON grievances (reference_number);

CREATE TABLE IF NOT EXISTS grievance_attachments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    grievance_id UUID NOT NULL REFERENCES grievances(id) ON DELETE CASCADE,
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    file_name VARCHAR(100) NOT NULL,
    content_type VARCHAR(50) NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes BETWEEN 1 AND 5242880),
    sha256 CHAR(64) NOT NULL,
    content BYTEA NOT NULL,
    uploaded_by VARCHAR(255) NOT NULL,          -- principal id, operator id or API key id
    uploaded_by_type VARCHAR(20) NOT NULL,      -- PRINCIPAL | OPERATOR | API_KEY
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_grievance_attachments_grievance ON grievance_attachments (grievance_id);
