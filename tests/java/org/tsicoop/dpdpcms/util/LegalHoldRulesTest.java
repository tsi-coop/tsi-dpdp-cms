package org.tsicoop.dpdpcms.util;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.*;

class LegalHoldRulesTest {
    private static final Instant NOW = Instant.parse("2026-06-01T10:00:00Z");

    @Test void aHoldNeedsAWrittenReasonAndAnEndDate() {
        assertNotNull(LegalHoldRules.problem(null, NOW.plus(30, ChronoUnit.DAYS), NOW));
        assertNotNull(LegalHoldRules.problem("too short", NOW.plus(30, ChronoUnit.DAYS), NOW));
        assertNotNull(LegalHoldRules.problem("Court order 42/2026 pending.", null, NOW), "a hold must be time-bound");
        assertNull(LegalHoldRules.problem("Court order 42/2026 pending.", NOW.plus(30, ChronoUnit.DAYS), NOW));
    }

    @Test void theEndMustBeInTheFutureAndNotTooFar() {
        assertNotNull(LegalHoldRules.problem("Court order 42/2026 pending.", NOW.minus(1, ChronoUnit.DAYS), NOW));
        assertNotNull(LegalHoldRules.problem("Court order 42/2026 pending.", NOW, NOW));
        assertNull(LegalHoldRules.problem("Court order 42/2026 pending.", NOW.plus(730, ChronoUnit.DAYS), NOW));
        assertNotNull(LegalHoldRules.problem("Court order 42/2026 pending.", NOW.plus(731, ChronoUnit.DAYS), NOW), "renew it instead of holding open-endedly");
    }

    @Test void aReferenceIsBounded() {
        assertNull(LegalHoldRules.referenceProblem(null));
        assertNull(LegalHoldRules.referenceProblem("CASE-42/2026"));
        assertNotNull(LegalHoldRules.referenceProblem("x".repeat(101)));
    }

    @Test void aHoldCoversAPurposeOrEverything() {
        assertTrue(LegalHoldRules.covers(null, "p1"), "no purpose named: covers all purposes");
        assertTrue(LegalHoldRules.covers("p1", "p1"));
        assertFalse(LegalHoldRules.covers("p1", "p2"));
        assertTrue(LegalHoldRules.covers("", "p2"));
    }
}
