-- Webhook delivery tracking and retry.
--
-- Every NOTIFICATION / PURGE webhook event is recorded here before it is sent, so a failed
-- delivery can be retried with backoff and shown to the DPO instead of being lost after a
-- single attempt. The notification / purge_requests rows themselves are the source of truth
-- and are written before any webhook fires, so polling remains the safety net.
--
--   PENDING   - waiting for an attempt (first send, or a retry scheduled at next_attempt_at)
--   DELIVERED - receiver answered 2xx
--   FAILED    - retries exhausted (or the URL/config was unusable); retry manually from the console
--
-- body is the exact JSON envelope that is signed and sent, kept as TEXT (not JSONB) so every
-- retry sends identical bytes and the receiver can de-duplicate on delivery_id. The signing
-- secret is NOT stored here: it is read from webhook_configs at each attempt. OTP webhooks are
-- deliberately never stored (their payload contains the one-time code).
--
-- next_attempt_at doubles as a lease while an attempt is in flight, so several app instances
-- can run the retry worker without double-sending.

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY,
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    category VARCHAR(20) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    body TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'DELIVERED', 'FAILED')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMP WITH TIME ZONE,
    last_attempt_at TIMESTAMP WITH TIME ZONE,
    last_http_status INTEGER,
    last_error TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_due
    ON webhook_deliveries (next_attempt_at) WHERE status = 'PENDING';
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_fiduciary
    ON webhook_deliveries (fiduciary_id, status, created_at DESC);
