-- Generic textual input payload for background jobs (e.g. a CSV of affected Data
-- Principal IDs uploaded for a breach notification run), so heavy/bulk work can be
-- handed off to JobManager instead of processed synchronously on the request thread.
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS input_payload TEXT;
