package org.tsicoop.dpdpcms.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RightsRulesTest {
    @Test void onlyAccessAndCorrectionAreRequestTypes() {
        assertTrue(RightsRules.isKnownType("ACCESS"));
        assertTrue(RightsRules.isKnownType("correction"));
        assertFalse(RightsRules.isKnownType("ERASURE"));   // erasure has its own flow
        assertFalse(RightsRules.isKnownType("WITHDRAWAL"));
        assertFalse(RightsRules.isKnownType(null));
    }

    @Test void statusesAreFixed() {
        for (String s : new String[]{"NEW", "IN_PROGRESS", "FULFILLED", "REJECTED"}) assertTrue(RightsRules.isKnownStatus(s), s);
        assertFalse(RightsRules.isKnownStatus("DONE"));
        assertFalse(RightsRules.isKnownStatus(null));
    }

    @Test void allowedTransitions() {
        assertTrue(RightsRules.canTransition("NEW", "IN_PROGRESS"));
        assertTrue(RightsRules.canTransition("NEW", "FULFILLED"));
        assertTrue(RightsRules.canTransition("NEW", "REJECTED"));
        assertTrue(RightsRules.canTransition("IN_PROGRESS", "FULFILLED"));
        assertTrue(RightsRules.canTransition("IN_PROGRESS", "REJECTED"));
    }

    @Test void invalidTransitionsAreRefused() {
        assertFalse(RightsRules.canTransition("FULFILLED", "IN_PROGRESS"));
        assertFalse(RightsRules.canTransition("FULFILLED", "REJECTED"));
        assertFalse(RightsRules.canTransition("REJECTED", "FULFILLED"));
        assertFalse(RightsRules.canTransition("IN_PROGRESS", "NEW"));
        assertFalse(RightsRules.canTransition("NEW", "NEW"));
        assertFalse(RightsRules.canTransition("IN_PROGRESS", "IN_PROGRESS"));
        assertFalse(RightsRules.canTransition("NEW", "BOGUS"));
        assertFalse(RightsRules.canTransition(null, "NEW"));
    }

    @Test void closingARequestNeedsAnOutcomeNote() {
        assertNotNull(RightsRules.outcomeProblem("REJECTED", null));
        assertNotNull(RightsRules.outcomeProblem("REJECTED", "no"));
        assertNotNull(RightsRules.outcomeProblem("FULFILLED", "   "));
        assertNull(RightsRules.outcomeProblem("REJECTED", "Identity could not be verified."));
        assertNull(RightsRules.outcomeProblem("FULFILLED", "Copy sent through the secure portal."));
        assertNull(RightsRules.outcomeProblem("IN_PROGRESS", null));
    }

    @Test void descriptionHasSensibleBounds() {
        assertNotNull(RightsRules.descriptionProblem(null));
        assertNotNull(RightsRules.descriptionProblem("short"));
        assertNull(RightsRules.descriptionProblem("My date of birth is wrong."));
        assertNotNull(RightsRules.descriptionProblem("x".repeat(2001)));
        assertNull(RightsRules.descriptionProblem("x".repeat(2000)));
    }

    @Test void deadlinesExistOnlyWhenConfigured() {
        // the legal timelines are not set by the code: unset means no deadline, so nothing is wrongly "overdue"
        assertNull(RightsRules.slaDays(null));
        assertNull(RightsRules.slaDays(""));
        assertNull(RightsRules.slaDays("soon"));
        assertNull(RightsRules.slaDays("0"));
        assertNull(RightsRules.slaDays("-5"));
        assertNull(RightsRules.slaDays("4000"));
        assertEquals(Integer.valueOf(30), RightsRules.slaDays("30"));
        assertEquals(Integer.valueOf(7), RightsRules.slaDays(" 7 "));
    }

    @Test void overdueMeansOpenAndPastADeadlineThatExists() {
        long now = 1_000_000L;
        assertTrue(RightsRules.isOverdue("NEW", now - 1, now));
        assertTrue(RightsRules.isOverdue("IN_PROGRESS", now - 1, now));
        assertFalse(RightsRules.isOverdue("NEW", now + 1, now));
        assertFalse(RightsRules.isOverdue("FULFILLED", now - 1, now));
        assertFalse(RightsRules.isOverdue("REJECTED", now - 1, now));
        assertFalse(RightsRules.isOverdue("NEW", null, now));
    }

    @Test void referenceNumber() { assertEquals("RR-2026-000007", RightsRules.referenceNumber(2026, 7)); }
}
