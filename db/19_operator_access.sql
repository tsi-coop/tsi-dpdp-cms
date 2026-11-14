-- 19_operator_access.sql
-- Operator access hardening (v0.6): TOTP MFA and token revocation.
--
--  operators.mfa_secret_enc    TOTP shared secret, encrypted like email_enc (pgp_sym_encrypt, base64).
--                              Set when enrolment starts; only trusted once mfa_enabled is true.
--  operators.mfa_enabled       true after the first valid code confirms enrolment.
--  operators.mfa_last_step     last accepted 30-second TOTP step; a step is accepted only once.
--  operators.mfa_failed_attempts / mfa_locked_until   5 bad codes lock MFA for 15 minutes.
--  operators.tokens_valid_after  tokens issued before this instant are rejected. Set on password
--                              change, deactivation and first MFA enrolment.
--  revoked_tokens              logged-out / revoked token ids, so revocation survives a restart and
--                              is seen by every app instance. Rows are removed after the token expires.
-- Safe to re-run.

ALTER TABLE operators ADD COLUMN IF NOT EXISTS mfa_secret_enc TEXT;
ALTER TABLE operators ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE operators ADD COLUMN IF NOT EXISTS mfa_last_step BIGINT;
ALTER TABLE operators ADD COLUMN IF NOT EXISTS mfa_failed_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operators ADD COLUMN IF NOT EXISTS mfa_locked_until TIMESTAMP WITH TIME ZONE;
ALTER TABLE operators ADD COLUMN IF NOT EXISTS tokens_valid_after TIMESTAMP WITH TIME ZONE;

CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti VARCHAR(64) PRIMARY KEY,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires ON revoked_tokens (expires_at);
