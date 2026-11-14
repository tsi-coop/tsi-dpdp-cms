package org.tsicoop.dpdpcms.util;

import org.json.simple.JSONObject;
import org.junit.jupiter.api.Test;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.*;

class BoardIntimationTest {
    private static final Instant NOW = Instant.parse("2026-06-01T10:00:00Z");
    private static Timestamp ts(Instant i) { return Timestamp.from(i); }

    @Test void stateFollowsTheDeadlineAndTheRecordedIntimation() {
        Timestamp deadline = ts(NOW.plus(24, ChronoUnit.HOURS));
        assertEquals("NOT_TRACKED", BoardIntimation.state(null, null, NOW));
        assertEquals("COUNTING", BoardIntimation.state(deadline, null, NOW));
        assertEquals("OVERDUE", BoardIntimation.state(deadline, null, NOW.plus(25, ChronoUnit.HOURS)));
        assertEquals("MET", BoardIntimation.state(deadline, ts(NOW.plus(2, ChronoUnit.HOURS)), NOW.plus(30, ChronoUnit.HOURS)));
        assertEquals("MET_LATE", BoardIntimation.state(deadline, ts(NOW.plus(26, ChronoUnit.HOURS)), NOW.plus(30, ChronoUnit.HOURS)));
    }

    @Test void dueSoonMeansTwelveHoursOrLessAndNotYetNotified() {
        Timestamp deadline = ts(NOW.plus(10, ChronoUnit.HOURS));
        assertTrue(BoardIntimation.isDueSoon(deadline, null, NOW));
        assertFalse(BoardIntimation.isDueSoon(ts(NOW.plus(13, ChronoUnit.HOURS)), null, NOW));
        assertFalse(BoardIntimation.isDueSoon(ts(NOW.minus(1, ChronoUnit.HOURS)), null, NOW), "already late is 'missed', not 'due soon'");
        assertFalse(BoardIntimation.isDueSoon(deadline, ts(NOW), NOW), "already notified");
        assertFalse(BoardIntimation.isDueSoon(null, null, NOW));
    }

    @Test void missedMeansPastTheDeadlineWithNoIntimation() {
        Timestamp deadline = ts(NOW.minus(1, ChronoUnit.HOURS));
        assertTrue(BoardIntimation.isMissed(deadline, null, NOW));
        assertFalse(BoardIntimation.isMissed(deadline, ts(NOW.minus(2, ChronoUnit.HOURS)), NOW));
        assertFalse(BoardIntimation.isMissed(ts(NOW.plus(1, ChronoUnit.HOURS)), null, NOW));
        assertFalse(BoardIntimation.isMissed(null, null, NOW));
    }

    @Test void theRecordedTimeMustBePlausible() {
        Instant detected = NOW.minus(10, ChronoUnit.HOURS);
        assertNull(BoardIntimation.problem(NOW.minus(1, ChronoUnit.HOURS), detected, NOW, "REF-1"));
        assertNull(BoardIntimation.problem(NOW, detected, NOW, null));
        assertNotNull(BoardIntimation.problem(NOW.plus(1, ChronoUnit.HOURS), detected, NOW, null), "not in the future");
        assertNotNull(BoardIntimation.problem(detected.minus(1, ChronoUnit.HOURS), detected, NOW, null), "not before the breach was detected");
        assertNotNull(BoardIntimation.problem(NOW, detected, NOW, "x".repeat(101)));
        assertNotNull(BoardIntimation.problem(null, detected, NOW, null));
    }

    @Test void describeAddsTheBoardFieldsAndASecondsCountdownWhileOpen() {
        JSONObject o = new JSONObject();
        BoardIntimation.describe(o, ts(NOW.plus(1, ChronoUnit.HOURS)), null, null, NOW);
        assertEquals("COUNTING", o.get("board_state"));
        assertEquals(3600L, o.get("board_seconds_remaining"));
        assertNull(o.get("board_notified_at"));
        JSONObject done = new JSONObject();
        BoardIntimation.describe(done, ts(NOW.plus(1, ChronoUnit.HOURS)), ts(NOW), "REF-9", NOW);
        assertEquals("MET", done.get("board_state"));
        assertEquals("REF-9", done.get("board_reference"));
        assertNull(done.get("board_seconds_remaining"));
    }
}
