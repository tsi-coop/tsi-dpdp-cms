package org.tsicoop.dpdpcms.util;

import org.json.simple.JSONObject;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory cache of policy rows, keyed by policy_id + version.
 * Every code path that changes a policy evicts its entry on THIS instance. Another app instance cannot be told, so
 * an entry is also only trusted for a short time (POLICY_CACHE_TTL_SECONDS, default 30): a change made elsewhere is
 * seen within that window instead of staying stale until restart.
 */
public final class PolicyCache {
    private static final class Entry {
        final JSONObject policy; final long storedAt;
        Entry(JSONObject policy, long storedAt) { this.policy = policy; this.storedAt = storedAt; }
    }

    private static final Map<String, Entry> CACHE = new ConcurrentHashMap<>();
    private static final char SEP = '\u0000';
    private static final long DEFAULT_TTL_MS = 30_000L;

    private PolicyCache() {}

    private static String key(String policyId, String version) { return policyId + SEP + version; }

    static long ttlMs() {
        try {
            String v = System.getenv("POLICY_CACHE_TTL_SECONDS");
            if (v != null) { long s = Long.parseLong(v.trim()); if (s >= 0 && s <= 3600) return s * 1000L; }
        } catch (NumberFormatException ignored) { }
        return DEFAULT_TTL_MS;
    }

    public static JSONObject get(String policyId, String version) {
        return get(policyId, version, System.currentTimeMillis(), ttlMs());
    }

    /** Package-visible for tests: explicit clock and time-to-live. */
    public static JSONObject get(String policyId, String version, long nowMillis, long ttlMillis) {
        String k = key(policyId, version);
        Entry e = CACHE.get(k);
        if (e == null) return null;
        if (nowMillis - e.storedAt > ttlMillis) { CACHE.remove(k, e); return null; }
        return e.policy;
    }

    public static void put(String policyId, String version, JSONObject policy) {
        CACHE.put(key(policyId, version), new Entry(policy, System.currentTimeMillis()));
    }

    /** Evicts one version. */
    public static void remove(String policyId, String version) { CACHE.remove(key(policyId, version)); }

    /** Evicts every version of a policy (for code paths that change status by id only). */
    public static void removeAll(String policyId) {
        String prefix = policyId + SEP;
        CACHE.keySet().removeIf(k -> k.startsWith(prefix));
    }

    public static void clear() { CACHE.clear(); }
}
