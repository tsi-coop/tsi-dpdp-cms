-- 27_purge_processor_obligation.sql
-- A processor can tell the CMS that it must keep data a purge asks it to erase because of a legal obligation (v0.6).
--
--  processor_obligation_at / _note / _by   when, why (free text) and who (the app, or the operator) reported it.
--
-- This is a REPORT, not a legal hold: it does not change the purge's status or suspend it. The purge stays open and the DPO
-- decides (place a time-bound legal hold, or follow it up with the processor). Safe to re-run.

ALTER TABLE purge_requests ADD COLUMN IF NOT EXISTS processor_obligation_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE purge_requests ADD COLUMN IF NOT EXISTS processor_obligation_note TEXT;
ALTER TABLE purge_requests ADD COLUMN IF NOT EXISTS processor_obligation_by VARCHAR(255);
