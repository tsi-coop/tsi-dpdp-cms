-- Lets a DPO configure the exact, plain-language, multi-language message text
-- sent to Data Principals for each notification type -- including DPO-defined
-- breach categories (e.g. BREACH_NOTIFICATION_PHISHING), not just the fixed
-- built-in types. Looked up live at list_notifications read-time -- editing a
-- message changes how past notifications display too, by design (simple, no
-- snapshotting).
CREATE TABLE IF NOT EXISTS notification_message_templates (
    fiduciary_id UUID NOT NULL REFERENCES fiduciaries(id),
    notification_type VARCHAR(100) NOT NULL,
    messages JSONB NOT NULL, -- {"en": "...", "hi": "...", ...}
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_by_user_id UUID,
    PRIMARY KEY (fiduciary_id, notification_type)
);

-- Records which category (or NULL = generic BREACH_NOTIFICATION) was actually
-- used to notify principals for a given breach incident.
ALTER TABLE breach_incidents ADD COLUMN IF NOT EXISTS notification_type VARCHAR(100);
