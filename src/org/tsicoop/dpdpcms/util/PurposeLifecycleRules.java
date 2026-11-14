package org.tsicoop.dpdpcms.util;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Rules for the lifecycle of a processing purpose: OPEN, or CLOSED (no new grants, existing consents invalidated). */
public final class PurposeLifecycleRules {
    private PurposeLifecycleRules() {}

    public static final int MIN_REASON = 10;
    private static final Set<String> STATES = Set.of("OPEN", "CLOSED");
    /** What the processors must do with the data once the governing retention period has run: erase it or de-identify it. */
    private static final Set<String> ACTIONS = Set.of("ERASE", "DE_IDENTIFY");

    public static boolean isKnownState(String s) { return s != null && STATES.contains(s.trim().toUpperCase(Locale.ROOT)); }
    public static boolean isKnownAction(String a) { return a != null && ACTIONS.contains(a.trim().toUpperCase(Locale.ROOT)); }

    public static String reasonProblem(String reason) {
        return reason == null || reason.trim().length() < MIN_REASON ? "a reason of at least " + MIN_REASON + " characters is required" : null;
    }

    /** Purposes in a submission that are GRANTED although closed. Declining a closed purpose is always allowed. */
    public static List<String> closedGrants(Set<String> closedPurposes, JSONArray consents) {
        Set<String> out = new LinkedHashSet<>();
        if (closedPurposes == null || closedPurposes.isEmpty() || consents == null) return new ArrayList<>();
        for (Object o : consents) {
            if (!(o instanceof JSONObject)) continue;
            JSONObject c = (JSONObject) o;
            if (Boolean.TRUE.equals(c.get("consent_granted")) && c.get("data_point_id") instanceof String && closedPurposes.contains(c.get("data_point_id"))) {
                out.add((String) c.get("data_point_id"));
            }
        }
        return new ArrayList<>(out);
    }
}
