-- 26_breach_board_intimation.sql
-- Breach intimation to the Data Protection Board (v0.6).
--
-- Separate from notifying the affected principals (notification_deadline): the Board has its own deadline and its own record.
--  board_notification_deadline  detected_at + the fiduciary's breach window (default 72 h; it can be tightened, never loosened),
--                               stored when the breach is reported. Breaches reported before this migration stay NULL ("not
--                               tracked"), so old incidents are not suddenly flagged as late.
--  board_notified_at            when the DPO recorded that the Board was informed.
--  board_reference              the Board's reference for the intimation, if any.
--  board_due_alert_at / board_missed_alert_at   set when the sweep has raised the "due soon" / "missed" alert, so each is raised once.
-- Safe to re-run.

ALTER TABLE breach_incidents ADD COLUMN IF NOT EXISTS board_notification_deadline TIMESTAMP WITH TIME ZONE;
ALTER TABLE breach_incidents ADD COLUMN IF NOT EXISTS board_notified_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE breach_incidents ADD COLUMN IF NOT EXISTS board_reference VARCHAR(100);
ALTER TABLE breach_incidents ADD COLUMN IF NOT EXISTS board_due_alert_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE breach_incidents ADD COLUMN IF NOT EXISTS board_missed_alert_at TIMESTAMP WITH TIME ZONE;

CREATE INDEX IF NOT EXISTS idx_breach_board_pending
    ON breach_incidents (board_notification_deadline)
    WHERE board_notified_at IS NULL AND board_notification_deadline IS NOT NULL;
