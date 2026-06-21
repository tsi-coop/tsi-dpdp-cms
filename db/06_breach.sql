-- Breach Notification module (DPDP Act Section 8(6)).
-- Tracks reported personal data breach incidents and exactly which
-- Data Principals were notified for each one.

CREATE TABLE IF NOT EXISTS breach_incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    detected_at TIMESTAMP WITH TIME ZONE NOT NULL,
    reported_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    affected_purpose_id VARCHAR(255),
    affected_data_categories JSONB,
    actionable_steps TEXT NOT NULL, -- plain-language guidance given to affected principals
    severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM', -- LOW, MEDIUM, HIGH, CRITICAL
    status VARCHAR(20) NOT NULL DEFAULT 'OPEN', -- OPEN, CONTAINED, RESOLVED
    resolution_notes TEXT,
    affected_principal_count INTEGER NOT NULL DEFAULT 0,
    created_by_user_id UUID,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_breach_incidents_fiduciary ON breach_incidents (fiduciary_id, reported_at DESC);

CREATE TABLE IF NOT EXISTS breach_affected_principals (
    breach_id UUID NOT NULL REFERENCES breach_incidents(id),
    user_id VARCHAR(255) NOT NULL,
    notified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (breach_id, user_id)
);
