package org.tsicoop.dpdpcms.framework;

/**
 * Revoked JWT IDs (JTI claims). Backed by {@link OperatorSessions}: revocations are written to the
 * revoked_tokens table (db/19) as well as memory, so they survive a restart and are seen by every
 * app instance within the store's cache window. Entries expire with the token itself.
 */
public class TokenBlocklist {

    /** Adds a JTI to the blocklist. expiresAtMs is the token's own expiry epoch-ms. */
    public static void revoke(String jti, long expiresAtMs) {
        OperatorSessions.store().revokeJti(jti, expiresAtMs);
    }

    public static boolean isRevoked(String jti) {
        return OperatorSessions.store().isJtiRevoked(jti);
    }
}
