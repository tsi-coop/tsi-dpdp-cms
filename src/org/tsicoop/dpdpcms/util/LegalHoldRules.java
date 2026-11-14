package org.tsicoop.dpdpcms.util;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * A legal hold stops a purge for a principal (optionally for one purpose) while a legal reason requires the data to be kept
 * (DPDP s.8(1) exception: a court order, an investigation). It is always time-bound and always has a written reason, so
 * data is never held indefinitely by accident; a sweep releases it when it ends.
 */
public final class LegalHoldRules {
    private LegalHoldRules() {}

    public static final int MIN_REASON = 10;
    public static final int MAX_DAYS = 730;

    public static String problem(String reason, Instant validUntil, Instant now) {
        if (reason == null || reason.trim().length() < MIN_REASON) return "a reason of at least " + MIN_REASON + " characters is required";
        if (validUntil == null) return "a hold must have an end date";
        if (!validUntil.isAfter(now)) return "the end date must be in the future";
        if (validUntil.isAfter(now.plus(MAX_DAYS, ChronoUnit.DAYS))) return "a hold can last at most " + MAX_DAYS + " days; renew it before it ends if it must continue";
        return null;
    }

    public static String referenceProblem(String reference) {
        return reference != null && reference.length() > 100 ? "the reference is longer than 100 characters" : null;
    }

    /** A hold that names no purpose covers all of the principal's purposes. */
    public static boolean covers(String holdPurpose, String purgePurpose) {
        return holdPurpose == null || holdPurpose.isEmpty() || holdPurpose.equals(purgePurpose);
    }
}
