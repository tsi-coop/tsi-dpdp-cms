-- Allows a DPO to delegate a purge request's closure to a specific Operator,
-- mirroring the existing grievances.assigned_dpo_user_id pattern.
ALTER TABLE purge_requests
ADD COLUMN IF NOT EXISTS assigned_operator_id UUID REFERENCES operators(id);

CREATE INDEX IF NOT EXISTS idx_purge_requests_assigned_operator ON purge_requests (assigned_operator_id);
