package org.tsicoop.dpdpcms.util;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.*;

class PurgeRulesTest {
    private static final Instant NOW = Instant.parse("2026-06-01T10:00:00Z");

    @Test void knownStatuses() {
        for (String s : new String[]{"PURGE_INITIATED", "PURGE_IN_PROGRESS", "PURGE_COMPLETED", "PURGE_FAILED", "PURGE_CANCELLED", "LEGAL_HOLD_APPLIED"})
            assertTrue(PurgeRules.isKnownStatus(s), s);
        assertFalse(PurgeRules.isKnownStatus("DONE"));
        assertFalse(PurgeRules.isKnownStatus(null));
    }

    @Test void completedAndCancelledAreFinal() {
        assertTrue(PurgeRules.isTerminal("PURGE_COMPLETED"));
        assertTrue(PurgeRules.isTerminal("PURGE_CANCELLED"));
        assertFalse(PurgeRules.isTerminal("PURGE_FAILED"), "a failed purge can be retried");
        assertFalse(PurgeRules.isTerminal("LEGAL_HOLD_APPLIED"), "a hold is lifted later");
        assertFalse(PurgeRules.isTerminal("PURGE_INITIATED"));
    }

    @Test void nothingMovesOutOfAFinalState() {
        assertFalse(PurgeRules.canMove("PURGE_COMPLETED", "PURGE_IN_PROGRESS"));
        assertFalse(PurgeRules.canMove("PURGE_COMPLETED", "PURGE_FAILED"));
        assertFalse(PurgeRules.canMove("PURGE_CANCELLED", "PURGE_COMPLETED"));
    }

    @Test void openStatesMoveForwardButNeverBackToInitiated() {
        assertTrue(PurgeRules.canMove("PURGE_INITIATED", "PURGE_IN_PROGRESS"));
        assertTrue(PurgeRules.canMove("PURGE_INITIATED", "PURGE_COMPLETED"));
        assertTrue(PurgeRules.canMove("PURGE_IN_PROGRESS", "PURGE_FAILED"));
        assertTrue(PurgeRules.canMove("PURGE_FAILED", "PURGE_IN_PROGRESS"));
        assertTrue(PurgeRules.canMove("LEGAL_HOLD_APPLIED", "PURGE_IN_PROGRESS"));
        assertFalse(PurgeRules.canMove("PURGE_IN_PROGRESS", "PURGE_INITIATED"), "only the system re-initiates");
        assertFalse(PurgeRules.canMove("PURGE_INITIATED", "BOGUS"));
        assertTrue(PurgeRules.canMove("PENDING", "PURGE_IN_PROGRESS"), "a legacy 'PENDING' row is just not started");
    }

    @Test void processorsReportProgressButDoNotCancelOrHold() {
        for (String t : new String[]{"PURGE_IN_PROGRESS", "PURGE_COMPLETED", "PURGE_FAILED"}) {
            assertTrue(PurgeRules.mayChooseTarget("API_KEY", t), t);
            assertTrue(PurgeRules.mayChooseTarget("OPERATOR", t), t);
        }
        assertFalse(PurgeRules.mayChooseTarget("API_KEY", "PURGE_CANCELLED"));
        assertFalse(PurgeRules.mayChooseTarget("API_KEY", "LEGAL_HOLD_APPLIED"));
        assertFalse(PurgeRules.mayChooseTarget("OPERATOR", "PURGE_CANCELLED"));
        assertFalse(PurgeRules.mayChooseTarget("OPERATOR", "LEGAL_HOLD_APPLIED"));
        assertTrue(PurgeRules.mayChooseTarget("DPO", "PURGE_CANCELLED"));
        assertTrue(PurgeRules.mayChooseTarget("ADMIN", "LEGAL_HOLD_APPLIED"));
    }

    @Test void claimedCountMustBeASensibleWholeNumber() {
        assertNull(PurgeRules.claimedCountProblem(null));
        assertNull(PurgeRules.claimedCountProblem(0L));
        assertNull(PurgeRules.claimedCountProblem(1_000_000L));
        assertNotNull(PurgeRules.claimedCountProblem(-1L));
        assertNotNull(PurgeRules.claimedCountProblem(2_000_000_000_000L));
        assertNotNull(PurgeRules.claimedCountProblem("12"));
        assertNotNull(PurgeRules.claimedCountProblem(1.5));
    }

    @Test void theSlaExistsOnlyWhenConfigured() {
        assertNull(PurgeRules.slaDays(null));
        assertNull(PurgeRules.slaDays(""));
        assertNull(PurgeRules.slaDays("abc"));
        assertNull(PurgeRules.slaDays("0"));
        assertNull(PurgeRules.slaDays("4000"));
        assertEquals(Integer.valueOf(30), PurgeRules.slaDays("30"));
    }

    @Test void pastTheSlaMeansOpenAndOlderThanTheLimit() {
        Instant old = NOW.minus(40, ChronoUnit.DAYS), recent = NOW.minus(10, ChronoUnit.DAYS);
        assertTrue(PurgeRules.isPastSla("PURGE_INITIATED", old, NOW, 30));
        assertTrue(PurgeRules.isPastSla("PURGE_IN_PROGRESS", old, NOW, 30));
        assertTrue(PurgeRules.isPastSla("PURGE_FAILED", old, NOW, 30));
        assertFalse(PurgeRules.isPastSla("PURGE_IN_PROGRESS", recent, NOW, 30));
        assertFalse(PurgeRules.isPastSla("PURGE_COMPLETED", old, NOW, 30));
        assertFalse(PurgeRules.isPastSla("PURGE_CANCELLED", old, NOW, 30));
        assertFalse(PurgeRules.isPastSla("LEGAL_HOLD_APPLIED", old, NOW, 30), "a purge under hold is not late");
        assertFalse(PurgeRules.isPastSla("PURGE_INITIATED", old, NOW, null), "no SLA configured");
    }
}
