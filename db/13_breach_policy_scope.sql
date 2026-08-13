-- Scopes a breach's affected-purpose resolution to the specific policy the DPO
-- selected it from, so a purpose_id reused across two different active policies
-- can't cross-match consent records that belong to the wrong policy.

ALTER TABLE breach_incidents
    ADD COLUMN IF NOT EXISTS affected_policy_id VARCHAR(255);
