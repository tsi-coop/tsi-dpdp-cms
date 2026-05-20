package org.tsicoop.dpdpcms.framework;

import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory blocklist for revoked JWT IDs (JTI claims).
 * Entries self-expire when the original token's natural expiry passes,
 * so the map does not grow unboundedly across a long-running server.
 *
 * Limitation: state is lost on server restart. A DB-backed store
 * (e.g. a revoked_tokens table with a TTL-based cleanup job) is
 * recommended before production go-live.
 */
public class TokenBlocklist {

    private static final ConcurrentHashMap<String, Long> revokedJtis = new ConcurrentHashMap<>();

    /** Adds a JTI to the blocklist. expiresAtMs is the token's own expiry epoch-ms. */
    public static void revoke(String jti, long expiresAtMs) {
        revokedJtis.put(jti, expiresAtMs);
    }

    /**
     * Returns true when the JTI is on the blocklist and the token has not yet
     * naturally expired (stale entries are evicted lazily to keep the map clean).
     */
    public static boolean isRevoked(String jti) {
        Long expiresAt = revokedJtis.get(jti);
        if (expiresAt == null) return false;
        if (System.currentTimeMillis() > expiresAt) {
            revokedJtis.remove(jti);
            return false;
        }
        return true;
    }
}
