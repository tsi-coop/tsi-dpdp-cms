-- 17_notification_log.sql
-- Notification Log: keep what was actually sent, and tie breach notifications to their breach.
--
--  message_snapshot: the message bundle ({"en": "...", "hi": "...", ...}) in effect when the
--                    notification was created. Templates can be edited later, so without this
--                    the system cannot show what wording a principal was sent. NULL for rows
--                    created before this script, and when no message was configured.
--  breach_id:        set for breach notifications, so a breach can list who was notified and
--                    whether they have read it. NULL for every other kind and for older rows.
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS message_snapshot JSONB;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS breach_id UUID REFERENCES breach_incidents(id);

CREATE INDEX IF NOT EXISTS idx_notifications_breach
    ON notifications (breach_id) WHERE breach_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_notifications_fiduciary_created
    ON notifications (fiduciary_id, created_at DESC);
