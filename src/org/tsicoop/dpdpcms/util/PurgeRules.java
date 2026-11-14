package org.tsicoop.dpdpcms.util;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.Set;

/** Rules for purge request status changes, who may choose which status, and the optional completion deadline. */
public final class PurgeRules {
    private PurgeRules() {}

    private static final Set<String> KNOWN = Set.of("PURGE_INITIATED", "PURGE_IN_PROGRESS", "PURGE_COMPLETED", "PURGE_FAILED", "PURGE_CANCELLED", "LEGAL_HOLD_APPLIED");
    private static final Set<String> TERMINAL = Set.of("PURGE_COMPLETED", "PURGE_CANCELLED");
    /** What a processor (API key) or an assigned operator may report. Cancelling and legal hold are decisions for the DPO. */
    private static final Set<String> REPORTABLE = Set.of("PURGE_IN_PROGRESS", "PURGE_COMPLETED", "PURGE_FAILED");

    private static String n(String s) { return s == null ? "" : s.trim().toUpperCase(Locale.ROOT); }

    public static boolean isKnownStatus(String s) { return KNOWN.contains(n(s)); }
    public static boolean isTerminal(String s) { return TERMINAL.contains(n(s)); }

    /** Final states never change (they are evidence); only the system moves a purge back to INITIATED. */
    public static boolean canMove(String from, String to) {
        if (!isKnownStatus(to)) return false;
        if (isTerminal(from)) return false;
        // A row still carrying the table's legacy default status (PENDING) is simply "not started": it may move forward.
        return !n(to).equals("PURGE_INITIATED");
    }

    /** @param callerKind API_KEY, OPERATOR, DPO or ADMIN */
    public static boolean mayChooseTarget(String callerKind, String target) {
        String k = n(callerKind);
        if (k.equals("DPO") || k.equals("ADMIN")) return isKnownStatus(target);
        return REPORTABLE.contains(n(target));
    }

    /**
     * A processor (API key) or an operator who sends LEGAL_HOLD_APPLIED is REPORTING that it must keep the data because of a
     * legal obligation. That is recorded for the DPO but does not change the purge's status or suspend it: only the DPO's own
     * (time-bound) legal hold does that.
     */
    public static boolean isProcessorObligationReport(String callerKind, String status) {
        String k = n(callerKind);
        return n(status).equals("LEGAL_HOLD_APPLIED") && (k.equals("API_KEY") || k.equals("OPERATOR"));
    }

    public static final int MIN_OBLIGATION_NOTE_CHARS = 10;
    public static final int MAX_OBLIGATION_NOTE_CHARS = 1000;

    /** @return why the explanation is not acceptable, or null */
    public static String obligationNoteProblem(String note) {
        if (note == null || note.trim().length() < MIN_OBLIGATION_NOTE_CHARS) return "'details' must say which legal obligation applies (at least " + MIN_OBLIGATION_NOTE_CHARS + " characters)";
        if (note.trim().length() > MAX_OBLIGATION_NOTE_CHARS) return "'details' is longer than " + MAX_OBLIGATION_NOTE_CHARS + " characters";
        return null;
    }

    /** The processor's own count is kept as claimed: the CMS cannot verify records held in the processor's systems. */
    public static String claimedCountProblem(Object v) {
        if (v == null) return null;
        if (!(v instanceof Long)) return "records_affected must be a whole number";
        long l = (Long) v;
        if (l < 0 || l > 1_000_000_000L) return "records_affected must be between 0 and 1,000,000,000";
        return null;
    }

    /** PURGE_COMPLETION_SLA_DAYS: unset means no deadline, and nothing is ever flagged late. */
    public static Integer slaDays(String configured) {
        if (configured == null) return null;
        try { int d = Integer.parseInt(configured.trim()); return d >= 1 && d <= 365 ? d : null; }
        catch (NumberFormatException e) { return null; }
    }

    public static boolean isPastSla(String status, Instant initiatedAt, Instant now, Integer slaDays) {
        if (slaDays == null || initiatedAt == null || !isKnownStatus(status)) return false;
        String s = n(status);
        if (isTerminal(s) || s.equals("LEGAL_HOLD_APPLIED")) return false;
        return initiatedAt.plus(slaDays, ChronoUnit.DAYS).isBefore(now);
    }
}
