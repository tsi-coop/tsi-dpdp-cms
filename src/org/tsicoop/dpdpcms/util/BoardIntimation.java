package org.tsicoop.dpdpcms.util;

import org.json.simple.JSONObject;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;

/**
 * Intimation of a personal data breach to the Data Protection Board. Separate from notifying the affected principals:
 * it has its own deadline and its own record (when it was done, and the Board's reference), and it is tracked from
 * the moment a breach is reported until the DPO records it.
 */
public final class BoardIntimation {
    private BoardIntimation() {}

    public static final long DUE_SOON_HOURS = 12;
    public static final String NOT_TRACKED = "NOT_TRACKED", COUNTING = "COUNTING", OVERDUE = "OVERDUE", MET = "MET", MET_LATE = "MET_LATE";

    public static String state(Timestamp deadline, Timestamp notifiedAt, Instant now) {
        if (deadline == null) return NOT_TRACKED;
        if (notifiedAt != null) return notifiedAt.after(deadline) ? MET_LATE : MET;
        return now.isBefore(deadline.toInstant()) ? COUNTING : OVERDUE;
    }

    public static boolean isDueSoon(Timestamp deadline, Timestamp notifiedAt, Instant now) {
        if (deadline == null || notifiedAt != null) return false;
        Instant d = deadline.toInstant();
        return now.isBefore(d) && !d.isAfter(now.plus(Duration.ofHours(DUE_SOON_HOURS)));
    }

    public static boolean isMissed(Timestamp deadline, Timestamp notifiedAt, Instant now) {
        return deadline != null && notifiedAt == null && now.isAfter(deadline.toInstant());
    }

    /** @return the problem with a recorded intimation time, or null. It cannot be in the future nor before the breach was detected. */
    public static String problem(Instant notifiedAt, Instant detectedAt, Instant now, String reference) {
        if (notifiedAt == null) return "the time the Board was informed is required";
        if (notifiedAt.isAfter(now.plus(Duration.ofMinutes(5)))) return "the time cannot be in the future";
        if (detectedAt != null && notifiedAt.isBefore(detectedAt)) return "the Board cannot have been informed before the breach was detected";
        if (reference != null && reference.length() > 100) return "the reference is longer than 100 characters";
        return null;
    }

    @SuppressWarnings("unchecked")
    public static void describe(JSONObject target, Timestamp deadline, Timestamp notifiedAt, String reference, Instant now) {
        target.put("board_notification_deadline", deadline == null ? null : deadline.toInstant().toString());
        target.put("board_state", state(deadline, notifiedAt, now));
        target.put("board_notified_at", notifiedAt == null ? null : notifiedAt.toInstant().toString());
        target.put("board_reference", reference);
        if (deadline != null && notifiedAt == null) target.put("board_seconds_remaining", Duration.between(now, deadline.toInstant()).getSeconds());
    }
}
