package org.tsicoop.dpdpcms.util;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * A consent submission must contain an explicit true/false choice for EVERY purpose the policy declares:
 * none missing, none repeated, none the policy does not know, each a real boolean. Silence is not consent
 * and a default is not a choice.
 */
public final class ConsentPurposes {
    private ConsentPurposes() {}

    /** @return human-readable problems; empty if the submission is complete. */
    public static List<String> problems(JSONObject policy, String language, JSONArray consents) {
        List<String> problems = new ArrayList<>();
        Set<String> declared = declaredPurposes(policy, language);
        if (declared == null) return problems; // cannot tell what the policy declares: do not guess

        Set<String> seen = new HashSet<>();
        if (consents != null) {
            for (Object o : consents) {
                if (!(o instanceof JSONObject)) { problems.add("each entry must be an object with data_point_id and consent_granted"); continue; }
                JSONObject c = (JSONObject) o;
                Object id = c.get("data_point_id");
                if (!(id instanceof String) || ((String) id).isEmpty()) { problems.add("entry without a data_point_id"); continue; }
                String pid = (String) id;
                if (!declared.contains(pid)) problems.add("unknown purpose '" + pid + "'");
                if (!seen.add(pid)) problems.add("duplicate purpose '" + pid + "'");
                if (!(c.get("consent_granted") instanceof Boolean)) problems.add("purpose '" + pid + "' needs consent_granted true or false");
            }
        }
        for (String d : declared) if (!seen.contains(d)) problems.add("no choice given for purpose '" + d + "'");
        return problems;
    }

    /** Purpose ids declared in the language block (falling back to "en"); null if the policy has none to read. */
    private static Set<String> declaredPurposes(JSONObject policy, String language) {
        if (policy == null) return null;
        Object block = language != null ? policy.get(language) : null;
        if (!(block instanceof JSONObject)) block = policy.get("en");
        if (!(block instanceof JSONObject)) return null;
        Object arr = ((JSONObject) block).get("data_processing_purposes");
        if (!(arr instanceof JSONArray)) return null;
        Set<String> ids = new LinkedHashSet<>();
        for (Object p : (JSONArray) arr) {
            if (p instanceof JSONObject && ((JSONObject) p).get("id") instanceof String) ids.add((String) ((JSONObject) p).get("id"));
        }
        return ids;
    }
}
