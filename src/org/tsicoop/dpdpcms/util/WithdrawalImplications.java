package org.tsicoop.dpdpcms.util;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.util.List;
import java.util.Set;

/**
 * What withdrawing consent for a purpose means for the principal, drawn from the policy the fiduciary published:
 * whether the purpose is needed for the service, what happens if it is withdrawn, what may be kept and why.
 * A policy can author its own "withdrawal_consequence" text per purpose; otherwise a plain default is used.
 */
public final class WithdrawalImplications {
    private WithdrawalImplications() {}

    static final String DEFAULT_MANDATORY = "This purpose is needed to provide the service. If you withdraw, you may no longer be able to use the service.";
    static final String DEFAULT_OPTIONAL = "Withdrawing stops this use of your data. You can keep using the service.";

    /** @param purposeIds the purposes asked about; empty means every purpose the policy declares */
    public static JSONArray build(JSONObject policy, String language, List<String> purposeIds, Set<String> closedPurposes) {
        JSONArray out = new JSONArray();
        if (policy == null) return out;
        Object block = language != null ? policy.get(language) : null;
        if (!(block instanceof JSONObject)) block = policy.get("en");
        if (!(block instanceof JSONObject)) return out;
        Object arr = ((JSONObject) block).get("data_processing_purposes");
        if (!(arr instanceof JSONArray)) return out;

        for (Object o : (JSONArray) arr) {
            if (!(o instanceof JSONObject)) continue;
            JSONObject p = (JSONObject) o;
            Object id = p.get("id");
            if (!(id instanceof String)) continue;
            if (purposeIds != null && !purposeIds.isEmpty() && !purposeIds.contains(id)) continue;

            boolean mandatory = Boolean.TRUE.equals(p.get("is_mandatory_for_service"));
            JSONObject imp = new JSONObject();
            imp.put("purpose_id", id);
            imp.put("name", p.get("name"));
            imp.put("mandatory", mandatory);
            Object custom = p.get("withdrawal_consequence");
            imp.put("consequence", custom instanceof String && !((String) custom).isBlank() ? custom : (mandatory ? DEFAULT_MANDATORY : DEFAULT_OPTIONAL));
            imp.put("legal_basis", p.get("legal_basis"));
            imp.put("data_kept_after_withdrawal", p.get("retention_policy"));
            if (p.get("retention_duration_value") != null) {
                JSONObject d = new JSONObject();
                d.put("value", p.get("retention_duration_value"));
                d.put("unit", p.get("retention_duration_unit"));
                d.put("start_event", p.get("retention_start_event"));
                imp.put("retention_duration", d);
            }
            imp.put("purpose_closed", closedPurposes != null && closedPurposes.contains(id));
            out.add(imp);
        }
        return out;
    }
}
