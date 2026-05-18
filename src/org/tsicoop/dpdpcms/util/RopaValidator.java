package org.tsicoop.dpdpcms.util;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

public class RopaValidator {

    public static JSONArray validate(JSONObject entry) {
        JSONArray missing = new JSONArray();

        check(missing, entry, "activity_name");
        check(missing, entry, "purpose");
        check(missing, entry, "legal_basis");
        checkArray(missing, entry, "data_categories");
        checkArray(missing, entry, "data_subject_categories");
        checkPositiveInt(missing, entry, "retention_period_days");
        check(missing, entry, "retention_start_event");
        check(missing, entry, "dpo_id");
        check(missing, entry, "security_measures");
        validateCrossBorderTransfers(missing, entry);

        return missing;
    }

    private static void check(JSONArray missing, JSONObject entry, String field) {
        Object val = entry.get(field);
        if (val == null || val.toString().trim().isEmpty()) {
            missing.add(field);
        }
    }

    private static void checkArray(JSONArray missing, JSONObject entry, String field) {
        Object val = entry.get(field);
        if (val == null) {
            missing.add(field + " (must have at least one entry)");
            return;
        }
        String str = val.toString().trim();
        if (str.equals("[]") || str.equals("null") || str.isEmpty()) {
            missing.add(field + " (must have at least one entry)");
        }
    }

    private static void checkPositiveInt(JSONArray missing, JSONObject entry, String field) {
        Object val = entry.get(field);
        if (val == null) {
            missing.add(field + " (must be greater than 0)");
            return;
        }
        try {
            int v = Integer.parseInt(val.toString());
            if (v <= 0) missing.add(field + " (must be greater than 0)");
        } catch (NumberFormatException e) {
            missing.add(field + " (invalid value)");
        }
    }

    private static void validateCrossBorderTransfers(JSONArray missing, JSONObject entry) {
        Object val = entry.get("cross_border_transfers");
        if (val == null) return;
        String str = val.toString().trim();
        if (str.equals("[]") || str.isEmpty()) return;

        try {
            org.json.simple.parser.JSONParser parser = new org.json.simple.parser.JSONParser();
            JSONArray transfers = (JSONArray) parser.parse(str);
            for (int i = 0; i < transfers.size(); i++) {
                JSONObject t = (JSONObject) transfers.get(i);
                if (t.get("destination_country") == null || t.get("destination_country").toString().trim().isEmpty()) {
                    missing.add("cross_border_transfers[" + i + "].destination_country");
                }
                if (t.get("safeguard") == null || t.get("safeguard").toString().trim().isEmpty()) {
                    missing.add("cross_border_transfers[" + i + "].safeguard");
                }
            }
        } catch (Exception e) {
            missing.add("cross_border_transfers (invalid JSON)");
        }
    }
}
