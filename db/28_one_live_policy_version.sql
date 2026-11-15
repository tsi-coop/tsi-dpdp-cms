-- 28_one_live_policy_version.sql
-- A policy can have only one ACTIVE version at a time (v0.6).
--
-- Publishing a new version makes it live and archives the old one (Ropa.activatePolicyIfComplete). This index makes the database
-- refuse a second live version of the same policy for a fiduciary, whatever the cause (two people approving at once, a manual change).
--
-- It stops with a message if a policy already has two live versions, so nothing is changed behind your back. To repair, archive
-- the older one(s) and run this again, for example:
--   UPDATE consent_policies SET status = 'ARCHIVED', last_updated_at = NOW() WHERE id = '<policy id>' AND version = '<older version>';
-- Safe to re-run.

DO $$
DECLARE dup TEXT;
BEGIN
    SELECT string_agg(id || ' (' || versions || ')', '; ') INTO dup
      FROM (SELECT id, string_agg(version, ', ' ORDER BY effective_date) AS versions
              FROM consent_policies WHERE status = 'ACTIVE'
             GROUP BY id, fiduciary_id HAVING COUNT(*) > 1) d;
    IF dup IS NOT NULL THEN
        RAISE EXCEPTION 'These policies have more than one ACTIVE version: %. Archive the older version(s) (see the comment at the top of db/28_one_live_policy_version.sql), then run this script again.', dup;
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_consent_policies_one_active
    ON consent_policies (id, fiduciary_id) WHERE status = 'ACTIVE';
