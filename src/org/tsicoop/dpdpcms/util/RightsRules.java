package org.tsicoop.dpdpcms.util;

import java.util.Locale;
import java.util.Set;

/**
 * Rules for access (s.11) and correction (s.12) requests. These are rights to be fulfilled, tracked from
 * NEW to FULFILLED or REJECTED; the CMS records the request and its outcome and carries no personal data values.
 * Deadlines are NOT set here: the legal timelines are an operator decision (see slaDays).
 */
public final class RightsRules {
    private RightsRules() {}

    private static final Set<String> TYPES = Set.of("ACCESS", "CORRECTION");
    private static final Set<String> STATUSES = Set.of("NEW", "IN_PROGRESS", "FULFILLED", "REJECTED");
    public static final int MIN_TEXT = 10;
    public static final int MAX_DESCRIPTION = 2000;

    public static boolean isKnownType(String t) { return t != null && TYPES.contains(t.trim().toUpperCase(Locale.ROOT)); }
    public static boolean isKnownStatus(String s) { return s != null && STATUSES.contains(s.trim().toUpperCase(Locale.ROOT)); }

    /** NEW -> IN_PROGRESS | FULFILLED | REJECTED; IN_PROGRESS -> FULFILLED | REJECTED; FULFILLED and REJECTED are final. */
    public static boolean canTransition(String from, String to) {
        if (!isKnownStatus(from) || !isKnownStatus(to)) return false;
        String f = from.trim().toUpperCase(Locale.ROOT), t = to.trim().toUpperCase(Locale.ROOT);
        if (f.equals("NEW")) return t.equals("IN_PROGRESS") || t.equals("FULFILLED") || t.equals("REJECTED");
        if (f.equals("IN_PROGRESS")) return t.equals("FULFILLED") || t.equals("REJECTED");
        return false;
    }

    /** Closing a request must say how: the delivery note for a fulfilled request, the reason for a rejected one. */
    public static String outcomeProblem(String status, String note) {
        if (status == null) return null;
        String s = status.trim().toUpperCase(Locale.ROOT);
        if (!s.equals("FULFILLED") && !s.equals("REJECTED")) return null;
        if (note == null || note.trim().length() < MIN_TEXT) {
            return "an outcome note of at least " + MIN_TEXT + " characters is required to mark a request " + s;
        }
        return null;
    }

    public static String descriptionProblem(String description) {
        if (description == null || description.trim().length() < MIN_TEXT) return "describe the request in at least " + MIN_TEXT + " characters";
        if (description.length() > MAX_DESCRIPTION) return "the description is longer than " + MAX_DESCRIPTION + " characters";
        return null;
    }

    /** Days allowed for a request, from configuration; null (no deadline) if unset or not a sensible number. */
    public static Integer slaDays(String configured) {
        if (configured == null) return null;
        try {
            int d = Integer.parseInt(configured.trim());
            return d >= 1 && d <= 365 ? d : null;
        } catch (NumberFormatException e) { return null; }
    }

    public static boolean isOverdue(String status, Long dueMillis, long nowMillis) {
        if (dueMillis == null || !isKnownStatus(status)) return false;
        String s = status.trim().toUpperCase(Locale.ROOT);
        return (s.equals("NEW") || s.equals("IN_PROGRESS")) && nowMillis > dueMillis;
    }

    public static String referenceNumber(int year, long sequence) { return String.format("RR-%d-%06d", year, sequence); }
}
