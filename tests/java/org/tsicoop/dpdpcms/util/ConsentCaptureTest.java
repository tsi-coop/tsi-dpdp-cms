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

    // ---- explicit choice for every declared purpose ----
    @Test void everyPurposeAnsweredExactlyOnceIsValid() throws Exception {
        assertTrue(ConsentPurposes.problems(policy("a", "b"), "en", choices("a", true, "b", false)).isEmpty());
    }

    @Test void aMissingPurposeIsReported() throws Exception {
        List<String> p = ConsentPurposes.problems(policy("a", "b"), "en", choices("a", true));
        assertEquals(1, p.size()); assertTrue(p.get(0).contains("b"));
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

    @Test void declaringNothingForAPolicyWithPurposesIsReported() throws Exception {
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

    // ---- mode ----
    @Test void captureModeIsWarnUnlessExactlyStrict() {
        assertFalse(ConsentCaptureMode.isStrict(null));
        assertFalse(ConsentCaptureMode.isStrict("warn"));
        assertFalse(ConsentCaptureMode.isStrict("stict"));
        assertTrue(ConsentCaptureMode.isStrict("strict"));
        assertTrue(ConsentCaptureMode.isStrict(" STRICT "));
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
