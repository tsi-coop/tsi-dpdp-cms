package org.tsicoop.dpdpcms.util;

import org.json.simple.JSONObject;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory cache of policy rows, keyed by policy_id + version.
 * Every code path that changes a policy's status or content must evict its entry,
 * otherwise reads keep returning the old status until restart.
 */
public final class PolicyCache {
    private static final Map<String, JSONObject> CACHE = new ConcurrentHashMap<>();
    private static final char SEP = '\u0000';

    private PolicyCache() {}

    private static String key(String policyId, String version) {
        return policyId + SEP + version;
    }

    public static JSONObject get(String policyId, String version) {
        return CACHE.get(key(policyId, version));
    }

    public static void put(String policyId, String version, JSONObject policy) {
        CACHE.put(key(policyId, version), policy);
    }

    /** Evicts one version. */
    public static void remove(String policyId, String version) {
        CACHE.remove(key(policyId, version));
    }

    /** Evicts every version of a policy (for code paths that change status by id only). */
    public static void removeAll(String policyId) {
        String prefix = policyId + SEP;
        CACHE.keySet().removeIf(k -> k.startsWith(prefix));
    }

    public static void clear() {
        CACHE.clear();
    }
}
