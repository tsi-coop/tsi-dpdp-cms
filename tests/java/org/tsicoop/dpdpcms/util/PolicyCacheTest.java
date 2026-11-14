package org.tsicoop.dpdpcms.util;

import org.json.simple.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PolicyCacheTest {

    @BeforeEach
    void clear() { PolicyCache.clear(); }

    private static JSONObject policy(String status) {
        JSONObject o = new JSONObject();
        o.put("status", status);
        return o;
    }

    @Test
    void differentVersionsOfSamePolicyDoNotShareAnEntry() {
        PolicyCache.put("p1", "1", policy("ACTIVE"));
        assertNull(PolicyCache.get("p1", "2"));
        assertEquals("ACTIVE", PolicyCache.get("p1", "1").get("status"));
    }

    @Test
    void removeEvictsOnlyThatVersion() {
        PolicyCache.put("p1", "1", policy("DRAFT"));
        PolicyCache.put("p1", "2", policy("DRAFT"));
        PolicyCache.remove("p1", "1");
        assertNull(PolicyCache.get("p1", "1"));
        assertNotNull(PolicyCache.get("p1", "2"));
    }

    @Test
    void removeAllEvictsEveryVersionButNotOtherPolicies() {
        PolicyCache.put("p1", "1", policy("DRAFT"));
        PolicyCache.put("p1", "2", policy("DRAFT"));
        PolicyCache.put("p10", "1", policy("DRAFT"));
        PolicyCache.removeAll("p1");
        assertNull(PolicyCache.get("p1", "1"));
        assertNull(PolicyCache.get("p1", "2"));
        assertNotNull(PolicyCache.get("p10", "1"));
    }

    /** Regression: a DRAFT cached before publish/activation must not be served afterwards. */
    @Test
    void staleDraftIsNotServedAfterActivationEviction() {
        PolicyCache.put("p1", "1", policy("DRAFT"));
        PolicyCache.removeAll("p1");
        assertNull(PolicyCache.get("p1", "1"));
    }
}
