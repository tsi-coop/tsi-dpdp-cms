-- Tracks the last date each recurring background job successfully ran.
-- Used by JobManager to atomically claim a nightly run across restarts/instances
-- and to catch up on a run that was missed (e.g. app was down at midnight).
CREATE TABLE IF NOT EXISTS job_schedule_state (
    job_name VARCHAR(64) PRIMARY KEY,
    last_run_date DATE NOT NULL
);
