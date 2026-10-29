-- Breach notification deadline (DPDP Act s.8(6)).
--
-- Each new breach gets a deadline of detected_at + the fiduciary's configured hours
-- (default 72, adjustable between 1 and 72 -- a fiduciary may tighten the statutory
-- window, never loosen it). The deadline is stored on the incident when it is reported,
-- so changing the setting later does not move deadlines already running. The clock
-- stops when the incident first leaves OPEN (responded_at).
--
-- Incidents reported before this migration keep a NULL deadline: they are shown as
-- "not tracked" rather than being guessed at (backdating them would flag every old,
-- long-closed incident as overdue).

ALTER TABLE fiduciaries
    ADD COLUMN IF NOT EXISTS breach_deadline_hours INTEGER NOT NULL DEFAULT 72
        CHECK (breach_deadline_hours BETWEEN 1 AND 72);

ALTER TABLE breach_incidents
    ADD COLUMN IF NOT EXISTS notification_deadline TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS responded_at TIMESTAMP WITH TIME ZONE;

CREATE INDEX IF NOT EXISTS idx_breach_incidents_open_deadline
    ON breach_incidents (fiduciary_id, notification_deadline)
    WHERE status = 'OPEN' AND notification_deadline IS NOT NULL;
