-- Policy version stamping.
--
-- Until now create_policy accepted a missing version and stored it as '', and
-- record_consent always recorded '' -- so every consent row carried a blank
-- policy_version. The application now requires a real version on create_policy
-- and stamps every consent with the policy's ACTIVE version.
--
-- This script gives existing blank-version policies the version '1.0' and
-- repoints their consent rows, but only when the policy id has exactly one
-- version. A policy id that has a blank version AND other versions is ambiguous
-- (which one did a blank consent row mean?), so it is left untouched and listed
-- in the NOTICE output for the DPO to resolve by hand.
--
-- consent_records references consent_policies(id, version), so the policy key
-- cannot simply be updated in place: the renamed policy row is inserted first,
-- the consent rows repointed, then the blank row removed -- all in one
-- transaction. audit_logs is a hash chain and is deliberately NOT touched; old
-- audit entries keep the blank version they were written with. Re-running is a
-- no-op once nothing is blank.

DO $$
DECLARE
    r RECORD;
    renamed_policies INTEGER := 0;
    repointed_consents INTEGER := 0;
    moved INTEGER;
    ambiguous_policies INTEGER := 0;
    blank_consents_left INTEGER;
BEGIN
    FOR r IN SELECT id FROM consent_policies WHERE version = '' LOOP
        IF (SELECT COUNT(*) FROM consent_policies WHERE id = r.id) = 1 THEN
            INSERT INTO consent_policies
                (id, version, fiduciary_id, effective_date, status, jurisdiction, policy_content, created_at, last_updated_at)
            SELECT id, '1.0', fiduciary_id, effective_date, status, jurisdiction, policy_content, created_at, last_updated_at
              FROM consent_policies WHERE id = r.id AND version = '';

            UPDATE consent_records SET policy_version = '1.0'
             WHERE policy_id = r.id AND policy_version = '';
            GET DIAGNOSTICS moved = ROW_COUNT;
            repointed_consents := repointed_consents + moved;

            DELETE FROM consent_policies WHERE id = r.id AND version = '';
            renamed_policies := renamed_policies + 1;
        ELSE
            ambiguous_policies := ambiguous_policies + 1;
            RAISE NOTICE 'Policy % has a blank version and other versions; left unchanged. Resolve manually.', r.id;
        END IF;
    END LOOP;

    SELECT COUNT(*) INTO blank_consents_left FROM consent_records WHERE policy_version = '';
    RAISE NOTICE 'Policy version backfill: % policy(ies) set to 1.0, % consent row(s) repointed, % ambiguous policy(ies) skipped, % consent row(s) still blank.',
        renamed_policies, repointed_consents, ambiguous_policies, blank_consents_left;
END $$;
