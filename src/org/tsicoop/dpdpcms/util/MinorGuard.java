package org.tsicoop.dpdpcms.util;

/**
 * A principal the CMS has recorded as a MINOR (set only by a recorded guardian verification, never by what a
 * caller declares) may be given consent only against a verified guardian log for that child.
 */
public final class MinorGuard {
    private MinorGuard() {}

    /** @return the problem, or null if consent may be recorded. */
    public static String problem(String storedAgeCategory, boolean hasVerifiedGuardianLog) {
        if (storedAgeCategory != null && Constants.AGE_MINOR.equalsIgnoreCase(storedAgeCategory) && !hasVerifiedGuardianLog) {
            return "this principal is recorded as a minor: consent needs a verified guardian log (verification_log_id from record_parent_consent)";
        }
        return null;
    }
}
