package org.tsicoop.dpdpcms.util;

/**
 * Audit of guardian verification for minors' consent. One query, shared by the CSV export
 * (JobManager, subtype MINOR_GUARDIAN_AUDIT) and the Principals page panel (Consent.java),
 * so the two can never disagree about what counts as a finding.
 *
 * Scope: consent records of principals the app has flagged MINOR (data_principal.age_category).
 * It checks that a guardian reference exists and is consistent; it verifies no ages and no
 * guardians, and it cannot find minors the app never flagged.
 */
public final class MinorConsentAudit {

    public static final String OK = "OK";
    public static final String MISSING_LOG = "MISSING_LOG";
    public static final String LOG_MISMATCH = "LOG_MISMATCH";

    private MinorConsentAudit() {}

    /**
     * One row per consent record of a MINOR principal, with a finding. Binds a single
     * parameter, the fiduciary id; callers append their own WHERE/ORDER on the derived table.
     */
    public static final String ROWS_SQL =
            "SELECT cr.user_id AS principal, cr.id AS consent_id, cr.policy_id, cr.policy_version, " +
            "cr.timestamp AS consent_timestamp, cr.is_active_consent AS active, " +
            "dp.guardian_id, dp.verification_status, cr.verification_log_id, " +
            "l.guardian_principal_id AS log_guardian, l.verified_at AS log_verified_at, " +
            "CASE WHEN cr.verification_log_id IS NULL THEN '" + MISSING_LOG + "' " +
            "     WHEN l.id IS NULL OR l.child_principal_id <> cr.user_id OR l.fiduciary_id <> cr.fiduciary_id " +
            "          OR (dp.guardian_id IS NOT NULL AND l.guardian_principal_id <> dp.guardian_id) THEN '" + LOG_MISMATCH + "' " +
            "     ELSE '" + OK + "' END AS finding " +
            "FROM data_principal dp " +
            "JOIN consent_records cr ON cr.user_id = dp.user_id AND cr.fiduciary_id = dp.fiduciary_id " +
            "LEFT JOIN parental_verification_logs l ON l.id = cr.verification_log_id " +
            "WHERE dp.fiduciary_id = ? AND dp.age_category = '" + Constants.AGE_MINOR + "'";
}
