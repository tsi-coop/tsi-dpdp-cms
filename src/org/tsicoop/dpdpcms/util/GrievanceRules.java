package org.tsicoop.dpdpcms.util;

import java.util.Locale;
import java.util.Set;

/** Pure rules for grievances: statuses, the resolution summary, channel, reference number and feedback. */
public final class GrievanceRules {
    private GrievanceRules() {}

    private static final Set<String> STATUSES = Set.of("NEW", "IN_PROGRESS", "RESOLVED", "CLOSED", "ESCALATED");
    /** Channels a caller may name. PRINCIPAL_PORTAL is not here: only a principal token earns it. */
    private static final Set<String> CHANNELS = Set.of("API_INTEGRATION", "OPERATOR_CONSOLE", "EMAIL", "PHONE", "IN_PERSON", "POSTAL", "OTHER");
    public static final int MIN_RESOLUTION_CHARS = 10;
    public static final int MAX_FEEDBACK_CHARS = 1000;

    public static boolean isKnownStatus(String s) {
        return s != null && STATUSES.contains(s.trim().toUpperCase(Locale.ROOT));
    }

    /** Closing a grievance must say what was done: RESOLVED / CLOSED need a summary of real length. */
    public static String resolutionProblem(String status, String resolutionDetails) {
        if (status == null) return null;
        String s = status.trim().toUpperCase(Locale.ROOT);
        if (!s.equals("RESOLVED") && !s.equals("CLOSED")) return null;
        if (resolutionDetails == null || resolutionDetails.trim().length() < MIN_RESOLUTION_CHARS) {
            return "a resolution summary of at least " + MIN_RESOLUTION_CHARS + " characters is required to mark a grievance " + s;
        }
        return null;
    }

    /**
     * How the grievance reached the CMS. A principal token always means PRINCIPAL_PORTAL; anyone else may name
     * one supported channel (a relayed phone call, an e-mail) or gets {@code authPathDefault}.
     * @return the channel, or null if a name was given that is not supported
     */
    public static String channel(boolean viaPrincipalJwt, String requested, String authPathDefault) {
        if (viaPrincipalJwt) return "PRINCIPAL_PORTAL";
        if (requested == null || requested.isBlank()) return authPathDefault;
        String c = requested.trim().toUpperCase(Locale.ROOT);
        return CHANNELS.contains(c) ? c : null;
    }

    public static String referenceNumber(int year, long sequence) {
        return String.format("GRV-%d-%06d", year, sequence);
    }

    public static String feedbackProblem(Object rating, String comment) {
        if (!(rating instanceof Long) || (Long) rating < 1 || (Long) rating > 5) return "rating must be a whole number from 1 to 5";
        if (comment != null && comment.length() > MAX_FEEDBACK_CHARS) return "comment is longer than " + MAX_FEEDBACK_CHARS + " characters";
        return null;
    }
}
