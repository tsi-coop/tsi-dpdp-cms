package org.tsicoop.dpdpcms.util;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ConsentCaptureTest {

    private static JSONObject policy(String... ids) throws Exception {
        JSONArray purposes = new JSONArray();
        for (String id : ids) { JSONObject p = new JSONObject(); p.put("id", id); purposes.add(p); }
        JSONObject en = new JSONObject(); en.put("data_processing_purposes", purposes);
        JSONObject policy = new JSONObject(); policy.put("en", en);
        return policy;
    }

    private static JSONArray choices(Object... kv) throws Exception {
        JSONArray a = new JSONArray();
        for (int i = 0; i < kv.length; i += 2) { JSONObject o = new JSONObject(); o.put("data_point_id", kv[i]); if (kv[i + 1] != null) o.put("consent_granted", kv[i + 1]); a.add(o); }
        return a;
    }

    // ---- what a submission may contain ----
    @Test void purposesAnsweredOnceAreValid() throws Exception {
        assertTrue(ConsentPurposes.problems(policy("a", "b"), "en", choices("a", true, "b", false)).isEmpty());
    }

    @Test void aPurposeLeftOutIsNotAnError() throws Exception {
        assertTrue(ConsentPurposes.problems(policy("a", "b"), "en", choices("a", true)).isEmpty(), "single-purpose consent");
    }

    @Test void anUnknownPurposeIsReported() throws Exception {
        List<String> p = ConsentPurposes.problems(policy("a"), "en", choices("a", true, "zzz", true));
        assertEquals(1, p.size()); assertTrue(p.get(0).contains("zzz"));
    }

    @Test void aDuplicatePurposeIsReported() throws Exception {
        List<String> p = ConsentPurposes.problems(policy("a"), "en", choices("a", true, "a", false));
        assertEquals(1, p.size()); assertTrue(p.get(0).toLowerCase().contains("duplicate"));
    }

    @Test void consentGrantedMustBeABoolean() throws Exception {
        assertFalse(ConsentPurposes.problems(policy("a"), "en", choices("a", "true")).isEmpty());
        assertFalse(ConsentPurposes.problems(policy("a"), "en", choices("a", 1L)).isEmpty());
        assertFalse(ConsentPurposes.problems(policy("a"), "en", choices("a", null)).isEmpty()); // omitted
    }

    @Test void declaringNothingIsReported() throws Exception {
        assertFalse(ConsentPurposes.problems(policy("a"), "en", new JSONArray()).isEmpty());
    }

    @Test void languageBlockIsUsedWhenPresentElseEnglish() throws Exception {
        JSONObject p = policy("a");
        JSONArray hi = new JSONArray(); JSONObject h = new JSONObject(); h.put("id", "h1"); hi.add(h);
        JSONObject hiBlock = new JSONObject(); hiBlock.put("data_processing_purposes", hi); p.put("hi", hiBlock);
        assertTrue(ConsentPurposes.problems(p, "hi", choices("h1", true)).isEmpty());
        assertTrue(ConsentPurposes.problems(p, "fr", choices("a", true)).isEmpty()); // unknown language -> en
    }

    @Test void malformedEntriesDoNotThrow() throws Exception {
        JSONArray a = new JSONArray(); a.add("not an object"); a.add(new JSONObject());
        assertFalse(ConsentPurposes.problems(policy("a"), "en", a).isEmpty());
    }

    // ---- single-purpose consent (merge) ----
    private static JSONObject entry(String id, boolean granted, String expiry) {
        JSONObject o = new JSONObject(); o.put("data_point_id", id); o.put("consent_granted", granted);
        if (expiry != null) o.put("consent_expiry", expiry);
        return o;
    }

    @Test void namingOnePurposeChangesOnlyThatOneAndKeepsTheRest() {
        JSONArray prior = new JSONArray(); prior.add(entry("a", true, "2027-01-01")); prior.add(entry("b", true, "2027-01-01")); prior.add(entry("c", false, null));
        JSONArray in = new JSONArray(); in.add(entry("b", false, null));
        JSONArray out = ConsentMerge.merge(prior, in, java.util.Set.of("a", "b", "c"), "rec-1", "1.0");
        assertEquals(3, out.size());
        assertEquals("a", ((JSONObject) out.get(0)).get("data_point_id"));
        assertEquals(Boolean.TRUE, ((JSONObject) out.get(0)).get("consent_granted"));
        assertEquals("2027-01-01", ((JSONObject) out.get(0)).get("consent_expiry"), "a carried choice keeps its expiry");
        assertEquals("rec-1", ((JSONObject) out.get(0)).get(ConsentMerge.CARRIED_FROM));
        assertEquals("1.0", ((JSONObject) out.get(0)).get(ConsentMerge.GIVEN_UNDER));
        assertEquals(Boolean.FALSE, ((JSONObject) out.get(1)).get("consent_granted"), "the named one changed");
        assertFalse(((JSONObject) out.get(1)).containsKey(ConsentMerge.CARRIED_FROM), "the new answer is not marked as carried");
        assertEquals(2, ConsentMerge.carried(out));
    }

    @Test void aNewPurposeIsAdded_aDroppedOneIsNotCarried() {
        JSONArray prior = new JSONArray(); prior.add(entry("a", true, null)); prior.add(entry("gone", true, null));
        JSONArray in = new JSONArray(); in.add(entry("new", true, null));
        JSONArray out = ConsentMerge.merge(prior, in, java.util.Set.of("a", "new"), "rec-1", "1.0");
        assertEquals(2, out.size());
        assertEquals("a", ((JSONObject) out.get(0)).get("data_point_id"));
        assertEquals("new", ((JSONObject) out.get(1)).get("data_point_id"));
    }

    @Test void noPriorRecordMeansJustTheRequest() {
        JSONArray in = new JSONArray(); in.add(entry("a", true, null));
        assertEquals(1, ConsentMerge.merge(null, in, java.util.Set.of("a", "b"), null, null).size());
    }

    @Test void theFirstSourceIsKeptWhenACarriedChoiceIsCarriedAgain() {
        JSONObject already = entry("a", true, null); already.put(ConsentMerge.CARRIED_FROM, "rec-0"); already.put(ConsentMerge.GIVEN_UNDER, "0.9");
        JSONArray prior = new JSONArray(); prior.add(already);
        JSONArray in = new JSONArray(); in.add(entry("b", true, null));
        JSONObject a = (JSONObject) ConsentMerge.merge(prior, in, java.util.Set.of("a", "b"), "rec-1", "1.0").get(0);
        assertEquals("rec-0", a.get(ConsentMerge.CARRIED_FROM));
        assertEquals("0.9", a.get(ConsentMerge.GIVEN_UNDER));
    }

    // ---- minors ----
    @Test void adultsNeedNoGuardianLog() {
        assertNull(MinorGuard.problem("ADULT", false));
        assertNull(MinorGuard.problem(null, false));
    }

    @Test void aStoredMinorNeedsAVerifiedMatchingGuardianLog() {
        assertNotNull(MinorGuard.problem("MINOR", false));
        assertNull(MinorGuard.problem("MINOR", true));
        assertNotNull(MinorGuard.problem("minor", false));
    }

    // ---- capture mechanism ----
    @Test void mechanismComesFromTheAuthenticationPath() {
        assertEquals("PRINCIPAL_PORTAL", CaptureMechanism.of(true, false));
        assertEquals("API_INTEGRATION", CaptureMechanism.of(false, true));
        assertEquals("API_INTEGRATION", CaptureMechanism.of(false, false));
        assertEquals("PRINCIPAL_PORTAL", CaptureMechanism.of(true, true)); // a principal token wins
    }
}
