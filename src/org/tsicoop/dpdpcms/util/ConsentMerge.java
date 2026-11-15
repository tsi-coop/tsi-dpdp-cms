package org.tsicoop.dpdpcms.util;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Single-purpose consent: a record_consent that names only some purposes changes those and keeps the principal's other
 * choices as they were. The new record is complete, the old one stays in the history chain.
 *
 * A choice carried over from an earlier record is marked with where it came from ("carried_from_record_id" and
 * "given_under_policy_version"), so the record still shows what the principal agreed to and when; the expiry of a carried
 * choice is not renewed.
 */
public final class ConsentMerge {
    private ConsentMerge() {}

    public static final String CARRIED_FROM = "carried_from_record_id";
    public static final String GIVEN_UNDER = "given_under_policy_version";

    /**
     * @param prior        data_point_consents of the principal's active record for this policy (may be null)
     * @param incoming     the entries in this request, already stamped with expiry
     * @param declared     purpose ids the policy declares now (null: cannot tell, keep everything)
     * @param priorRecordId id of the record the prior choices come from
     * @param priorVersion  policy version of that record
     */
    public static JSONArray merge(JSONArray prior, JSONArray incoming, Set<String> declared, String priorRecordId, String priorVersion) {
        Map<String, JSONObject> byId = new LinkedHashMap<>();
        for (Object o : incoming) { JSONObject e = (JSONObject) o; byId.put((String) e.get("data_point_id"), e); }

        JSONArray out = new JSONArray();
        if (prior != null) {
            for (Object o : prior) {
                if (!(o instanceof JSONObject)) continue;
                JSONObject p = (JSONObject) o;
                Object id = p.get("data_point_id");
                if (!(id instanceof String)) continue;
                JSONObject replacement = byId.remove(id);
                if (replacement != null) { out.add(replacement); continue; }              // this request changes it
                if (declared != null && !declared.contains(id)) continue;                  // the policy no longer declares it
                JSONObject kept = new JSONObject(); kept.putAll(p);
                if (!kept.containsKey(CARRIED_FROM)) {                                    // keep the first source if carried more than once
                    kept.put(CARRIED_FROM, priorRecordId);
                    kept.put(GIVEN_UNDER, priorVersion);
                }
                out.add(kept);
            }
        }
        out.addAll(byId.values());                                                         // purposes not seen before
        return out;
    }

    /** How many entries in a merged array were carried over. */
    public static int carried(JSONArray merged) {
        int n = 0;
        for (Object o : merged) if (o instanceof JSONObject && ((JSONObject) o).containsKey(CARRIED_FROM)) n++;
        return n;
    }
}
