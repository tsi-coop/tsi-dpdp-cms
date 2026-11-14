package org.tsicoop.dpdpcms.util;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class PurposeAndNominationRulesTest {
    private static final Instant NOW = Instant.parse("2026-06-01T10:00:00Z");

    // ---------------- nominations (s.14) ----------------
    @Test void aReasonableNominationIsAccepted() {
        assertNull(NominationRules.problem("Asha Rao", "asha@example.com", null, null, NOW));
        assertNull(NominationRules.problem("Asha Rao", "+91 98765 43210", NOW, NOW.plus(365, ChronoUnit.DAYS), NOW));
    }

    @Test void nameAndContactAreChecked() {
        assertNotNull(NominationRules.problem(null, "asha@example.com", null, null, NOW));
        assertNotNull(NominationRules.problem("A", "asha@example.com", null, null, NOW));
        assertNotNull(NominationRules.problem("x".repeat(101), "asha@example.com", null, null, NOW));
        assertNotNull(NominationRules.problem("Asha Rao", null, null, null, NOW));
        assertNotNull(NominationRules.problem("Asha Rao", "not a contact", null, null, NOW));
        assertNotNull(NominationRules.problem("Asha Rao", "12345", null, null, NOW));
    }

    @Test void validityWindowMustMakeSense() {
        assertNotNull(NominationRules.problem("Asha Rao", "asha@example.com", NOW, NOW.minus(1, ChronoUnit.DAYS), NOW));          // ends before it starts
        assertNotNull(NominationRules.problem("Asha Rao", "asha@example.com", null, NOW.minus(1, ChronoUnit.DAYS), NOW));          // already over
        assertNotNull(NominationRules.problem("Asha Rao", "asha@example.com", null, NOW.plus(4000, ChronoUnit.DAYS), NOW));         // more than 10 years
        assertNotNull(NominationRules.problem("Asha Rao", "asha@example.com", NOW.minus(30, ChronoUnit.DAYS), null, NOW));         // starts in the past
        assertNull(NominationRules.problem("Asha Rao", "asha@example.com", NOW.plus(30, ChronoUnit.DAYS), null, NOW));             // starts later: fine
    }

    @Test void effectiveStatusFollowsTheDates() {
        assertEquals("ACTIVE", NominationRules.effectiveStatus("ACTIVE", NOW.minus(1, ChronoUnit.DAYS), null, NOW));
        assertEquals("PENDING", NominationRules.effectiveStatus("PENDING", NOW.plus(1, ChronoUnit.DAYS), null, NOW));
        assertEquals("ACTIVE", NominationRules.effectiveStatus("PENDING", NOW.minus(1, ChronoUnit.HOURS), null, NOW));
        assertEquals("EXPIRED", NominationRules.effectiveStatus("ACTIVE", NOW.minus(10, ChronoUnit.DAYS), NOW.minus(1, ChronoUnit.DAYS), NOW));
        assertEquals("REVOKED", NominationRules.effectiveStatus("REVOKED", NOW.minus(10, ChronoUnit.DAYS), NOW.plus(10, ChronoUnit.DAYS), NOW));
        assertEquals("EXPIRED", NominationRules.effectiveStatus("EXPIRED", NOW.minus(10, ChronoUnit.DAYS), null, NOW));
    }

    @Test void contactIsMaskedForStaff() {
        assertEquals("a***@example.com", NominationRules.maskContact("asha@example.com"));
        assertEquals("********3210", NominationRules.maskContact("+91 98765 43210"));
        assertEquals("***", NominationRules.maskContact("ab"));
        assertNull(NominationRules.maskContact(null));
    }

    // ---------------- purpose lifecycle ----------------
    @Test void purposeStatesAndActions() {
        assertTrue(PurposeLifecycleRules.isKnownState("OPEN"));
        assertTrue(PurposeLifecycleRules.isKnownState("closed"));
        assertFalse(PurposeLifecycleRules.isKnownState("PAUSED"));
        assertTrue(PurposeLifecycleRules.isKnownAction("ERASE"));
        assertTrue(PurposeLifecycleRules.isKnownAction("de_identify"));
        assertFalse(PurposeLifecycleRules.isKnownAction("DELETE"));
        assertFalse(PurposeLifecycleRules.isKnownAction(null));
    }

    @Test void closingNeedsAWrittenReason() {
        assertNotNull(PurposeLifecycleRules.reasonProblem(null));
        assertNotNull(PurposeLifecycleRules.reasonProblem("too short"));
        assertNull(PurposeLifecycleRules.reasonProblem("Campaign ended; purpose retired."));
    }

    private static JSONArray choices(Object... kv) {
        JSONArray a = new JSONArray();
        for (int i = 0; i < kv.length; i += 2) { JSONObject o = new JSONObject(); o.put("data_point_id", kv[i]); o.put("consent_granted", kv[i + 1]); a.add(o); }
        return a;
    }

    @Test void grantingAClosedPurposeIsReportedButDecliningIsFine() {
        Set<String> closed = Set.of("p2");
        assertEquals(List.of("p2"), PurposeLifecycleRules.closedGrants(closed, choices("p1", true, "p2", true)));
        assertTrue(PurposeLifecycleRules.closedGrants(closed, choices("p1", true, "p2", false)).isEmpty());
        assertTrue(PurposeLifecycleRules.closedGrants(Set.of(), choices("p2", true)).isEmpty());
        assertTrue(PurposeLifecycleRules.closedGrants(closed, null).isEmpty());
    }

    // ---------------- withdrawal implications ----------------
    private static JSONObject purpose(String id, boolean mandatory, String extra) {
        JSONObject p = new JSONObject();
        p.put("id", id); p.put("name", "Name of " + id); p.put("is_mandatory_for_service", mandatory);
        p.put("legal_basis", "Contract"); p.put("retention_policy", "Kept for 5 years after account closure.");
        p.put("retention_duration_value", 5L); p.put("retention_duration_unit", "YEARS"); p.put("retention_start_event", "CESSATION");
        if (extra != null) p.put("withdrawal_consequence", extra);
        return p;
    }
    private static JSONObject policy(JSONObject... ps) {
        JSONArray a = new JSONArray(); for (JSONObject p : ps) a.add(p);
        JSONObject en = new JSONObject(); en.put("data_processing_purposes", a);
        JSONObject pol = new JSONObject(); pol.put("en", en); return pol;
    }

    @Test void implicationsDescribeEachRequestedPurpose() {
        JSONArray out = WithdrawalImplications.build(policy(purpose("p1", true, null), purpose("p2", false, null)), "en", List.of("p1", "p2"), Set.of());
        assertEquals(2, out.size());
        JSONObject p1 = (JSONObject) out.get(0);
        assertEquals("p1", p1.get("purpose_id"));
        assertEquals(Boolean.TRUE, p1.get("mandatory"));
        assertTrue(((String) p1.get("consequence")).toLowerCase().contains("service"));
        assertEquals("Kept for 5 years after account closure.", p1.get("data_kept_after_withdrawal"));
        assertEquals("Contract", p1.get("legal_basis"));
        JSONObject p2 = (JSONObject) out.get(1);
        assertEquals(Boolean.FALSE, p2.get("mandatory"));
        assertNotEquals(p1.get("consequence"), p2.get("consequence"));
    }

    @Test void aPolicyAuthoredConsequenceWins() {
        JSONArray out = WithdrawalImplications.build(policy(purpose("p1", false, "You will stop receiving the weekly digest.")), "en", List.of("p1"), Set.of());
        assertEquals("You will stop receiving the weekly digest.", ((JSONObject) out.get(0)).get("consequence"));
    }

    @Test void unknownPurposesAreSkippedAndClosedOnesFlagged() {
        JSONArray out = WithdrawalImplications.build(policy(purpose("p1", false, null)), "en", List.of("p1", "nope"), Set.of("p1"));
        assertEquals(1, out.size());
        assertEquals(Boolean.TRUE, ((JSONObject) out.get(0)).get("purpose_closed"));
    }

    @Test void emptyRequestMeansEveryDeclaredPurpose() {
        JSONArray out = WithdrawalImplications.build(policy(purpose("p1", true, null), purpose("p2", false, null)), "en", List.of(), Set.of());
        assertEquals(2, out.size());
    }
}
