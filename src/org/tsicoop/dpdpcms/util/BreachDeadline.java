package org.tsicoop.dpdpcms.util;

import org.json.simple.JSONObject;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;

/**
 * The breach notification clock: a deadline of detected_at + N hours that runs while an
 * incident is OPEN and stops when it first leaves OPEN (responded_at). Pure computation --
 * no pushes or timers; the DPO dashboard reads these fields and renders the countdown.
 */
public final class BreachDeadline {

    public static final int DEFAULT_HOURS = 72;
    public static final int MIN_HOURS = 1;
    public static final int MAX_HOURS = 72; // statutory window: may be tightened, not loosened

    public static final String NOT_TRACKED = "NOT_TRACKED"; // reported before deadlines existed
    public static final String COUNTING = "COUNTING";       // OPEN, deadline still ahead
    public static final String OVERDUE = "OVERDUE";         // OPEN, deadline passed
    public static final String MET = "MET";                 // left OPEN on time
    public static final String MET_LATE = "MET_LATE";       // left OPEN after the deadline

    private BreachDeadline() {}

    public static boolean isValidHours(int hours) {
        return hours >= MIN_HOURS && hours <= MAX_HOURS;
    }

    public static Timestamp deadlineFor(Timestamp detectedAt, int hours) {
        return Timestamp.from(detectedAt.toInstant().plus(Duration.ofHours(hours)));
    }

    public static String state(String status, Timestamp deadline, Timestamp respondedAt, Instant now) {
        if (deadline == null) return NOT_TRACKED;
        if ("OPEN".equals(status)) {
            return now.isBefore(deadline.toInstant()) ? COUNTING : OVERDUE;
        }
        if (respondedAt == null) return MET; // left OPEN without a recorded time: cannot call it late
        return respondedAt.after(deadline) ? MET_LATE : MET;
    }

    /**
     * Adds notification_deadline, deadline_state and (for OPEN incidents) seconds_remaining,
     * negative once overdue. Seconds are computed on the server so the countdown does not
     * depend on the viewer's clock being right.
     */
    @SuppressWarnings("unchecked")
    public static void describe(JSONObject target, String status, Timestamp deadline, Timestamp respondedAt) {
        Instant now = Instant.now();
        target.put("notification_deadline", deadline != null ? deadline.toInstant().toString() : null);
        target.put("deadline_state", state(status, deadline, respondedAt, now));
        if (respondedAt != null) target.put("responded_at", respondedAt.toInstant().toString());
        if (deadline != null && "OPEN".equals(status)) {
            target.put("seconds_remaining", Duration.between(now, deadline.toInstant()).getSeconds());
        }
    }
}
