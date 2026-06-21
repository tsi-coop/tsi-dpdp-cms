-- Event webhooks: lets a DPO configure a push delivery URL per category
-- (NOTIFICATION, PURGE), alongside the existing poll-based APIs.
CREATE TABLE IF NOT EXISTS webhook_configs (
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    category VARCHAR(20) NOT NULL,   -- 'NOTIFICATION' or 'PURGE'
    webhook_url TEXT NOT NULL,
    secret_enc TEXT NOT NULL,        -- pgcrypto-encrypted via DbEncryption.ENCRYPT
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_by_user_id UUID,
    PRIMARY KEY (fiduciary_id, category)
);
