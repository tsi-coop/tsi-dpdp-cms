-- 18_audit_ledger_integrity.sql
-- Audit ledger hardening (v0.6).
--
--  * seq:          monotonic chain position. The chain head is ORDER BY seq DESC, not by timestamp.
--  * hash_version: 1 = legacy rows (checked for linkage only), 2 = rows whose hash covers every
--                  stored column (see util/AuditChain.java).
--  * append-only:  UPDATE, DELETE and TRUNCATE on audit_logs raise.
--  * audit_chain_verifications: verdicts of the daily verifier job (also append-only).
--  * 365-day delete floors on notifications and webhook_deliveries.
--
-- Safe to re-run. Run as the table owner / a superuser.

-- 1. Chain position ------------------------------------------------------------------------
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS seq BIGINT;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS hash_version SMALLINT NOT NULL DEFAULT 1;

CREATE SEQUENCE IF NOT EXISTS audit_logs_seq_seq OWNED BY audit_logs.seq;

-- Backfill existing rows in the order the old code treated as the chain (timestamp). Only touches
-- rows with no seq yet, so a re-run changes nothing (and does not trip the append-only trigger).
WITH ordered AS (
    SELECT id, row_number() OVER (ORDER BY "timestamp", id) AS rn FROM audit_logs WHERE seq IS NULL
), base AS (
    SELECT COALESCE(MAX(seq), 0) AS m FROM audit_logs
)
UPDATE audit_logs a SET seq = ordered.rn + base.m FROM ordered, base WHERE a.id = ordered.id;

SELECT setval('audit_logs_seq_seq', GREATEST((SELECT COALESCE(MAX(seq), 0) FROM audit_logs), 1),
              (SELECT COUNT(*) > 0 FROM audit_logs));
ALTER TABLE audit_logs ALTER COLUMN seq SET DEFAULT nextval('audit_logs_seq_seq');
ALTER TABLE audit_logs ALTER COLUMN seq SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_logs_seq ON audit_logs (seq);

-- 2. Append-only ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tsi_audit_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '% is append-only: % not permitted', TG_TABLE_NAME, TG_OP;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_no_update_delete ON audit_logs;
CREATE TRIGGER trg_audit_no_update_delete BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION tsi_audit_immutable();
DROP TRIGGER IF EXISTS trg_audit_no_truncate ON audit_logs;
CREATE TRIGGER trg_audit_no_truncate BEFORE TRUNCATE ON audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION tsi_audit_immutable();

-- Belt and braces: the triggers are the control, privileges are the second layer.
-- If the application connects as a role that is NOT the table owner, also run (once):
--   REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs, audit_chain_verifications FROM <app_role>;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM PUBLIC;

-- 3. Verifier verdicts ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_chain_verifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    run_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    trigger_source VARCHAR(20) NOT NULL DEFAULT 'JOB',          -- JOB | MANUAL
    verdict VARCHAR(10) NOT NULL CHECK (verdict IN ('INTACT', 'BROKEN')),
    rows_checked BIGINT NOT NULL,
    rows_verified BIGINT NOT NULL,                              -- hash recomputed and matched (v2)
    legacy_linkage_only BIGINT NOT NULL,                        -- v1 rows: linkage checked only
    first_break_id UUID,
    first_break_seq BIGINT
);
CREATE INDEX IF NOT EXISTS idx_audit_chain_verifications_run ON audit_chain_verifications (run_at DESC);

DROP TRIGGER IF EXISTS trg_audit_chain_verifications_immutable ON audit_chain_verifications;
CREATE TRIGGER trg_audit_chain_verifications_immutable BEFORE UPDATE OR DELETE ON audit_chain_verifications
    FOR EACH ROW EXECUTE FUNCTION tsi_audit_immutable();
DROP TRIGGER IF EXISTS trg_audit_chain_verifications_no_truncate ON audit_chain_verifications;
CREATE TRIGGER trg_audit_chain_verifications_no_truncate BEFORE TRUNCATE ON audit_chain_verifications
    FOR EACH STATEMENT EXECUTE FUNCTION tsi_audit_immutable();

-- 4. 365-day delete floors -----------------------------------------------------------------
-- Rows younger than 365 days cannot be deleted. (There is no notification_deliveries table in
-- this schema: notifications is the delivery record for in-app/e-mail/SMS notices.)
CREATE OR REPLACE FUNCTION tsi_delete_floor_365d() RETURNS trigger AS $$
BEGIN
    IF OLD.created_at > NOW() - INTERVAL '365 days' THEN
        RAISE EXCEPTION '% rows must be kept for 365 days: DELETE refused', TG_TABLE_NAME;
    END IF;
    RETURN OLD;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_notifications_delete_floor ON notifications;
CREATE TRIGGER trg_notifications_delete_floor BEFORE DELETE ON notifications
    FOR EACH ROW EXECUTE FUNCTION tsi_delete_floor_365d();
DROP TRIGGER IF EXISTS trg_webhook_deliveries_delete_floor ON webhook_deliveries;
CREATE TRIGGER trg_webhook_deliveries_delete_floor BEFORE DELETE ON webhook_deliveries
    FOR EACH ROW EXECUTE FUNCTION tsi_delete_floor_365d();
