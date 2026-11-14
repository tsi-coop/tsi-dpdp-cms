package org.tsicoop.dpdpcms.util;

/**
 * Keeps one bad audit entry from blocking all the others. The audit table has fixed-width columns and rejects NUL
 * characters; an unauthenticated caller controls some fields (for example the login name on a failed login), so
 * every field is cleaned and clipped to its column BEFORE it is queued and hashed.
 */
public final class AuditLimits {
    private AuditLimits() {}

    public static String userId(String s) { return clip(s, 255, "UNKNOWN"); }
    public static String serviceType(String s) { return clip(s, 100, "UNKNOWN"); }
    public static String action(String s) { return clip(s, 100, "UNKNOWN"); }
    /** context_details is TEXT: no length limit, but NUL characters are not storable. */
    public static String context(String s) { return s == null ? null : s.replace("\u0000", " "); }

    private static String clip(String s, int max, String ifNull) {
        if (s == null) return ifNull;
        String t = s.replace("\u0000", " ");
        return t.length() > max ? t.substring(0, max) : t;
    }

    /** A "data" or "constraint" SQL error (class 22 / 23) means this entry can never be stored; connection and resource errors are retried. */
    public static boolean isPoison(String sqlState) {
        return sqlState != null && (sqlState.startsWith("22") || sqlState.startsWith("23"));
    }

    /** A recent verdict is reused instead of walking the whole chain again. */
    public static boolean reuseVerdict(Long lastRunMillis, long nowMillis, long windowMillis) {
        return lastRunMillis != null && nowMillis - lastRunMillis < windowMillis;
    }
}
