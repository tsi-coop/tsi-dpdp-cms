package org.tsicoop.dpdpcms.util;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class OperatorAccessPolicyTest {

    // ---- MFA enforcement: enrol everywhere, enforce in production (or MFA_ENFORCE) ----
    @Test
    void mfaMandatoryForAdminAndDpoWhenEnforcing() {
        assertTrue(MfaPolicy.required("ADMIN", true));
        assertTrue(MfaPolicy.required("DPO", true));
        assertTrue(MfaPolicy.required("dpo", true));
    }

    @Test
    void mfaNotRequiredForOtherRolesOrWhenNotEnforcing() {
        assertFalse(MfaPolicy.required("OPERATOR", true));
        assertFalse(MfaPolicy.required("AUDITOR", true));
        assertFalse(MfaPolicy.required("ADMIN", false));
        assertFalse(MfaPolicy.required(null, true));
    }

    @Test
    void enforcementIsOnInProductionAndCannotBeSwitchedOffThere() {
        assertTrue(MfaPolicy.enforcing(true, "false"));
        assertTrue(MfaPolicy.enforcing(true, null));
        assertFalse(MfaPolicy.enforcing(false, null));
        assertFalse(MfaPolicy.enforcing(false, "false"));
        assertTrue(MfaPolicy.enforcing(false, "true"));
        assertTrue(MfaPolicy.enforcing(false, "TRUE"));
    }

    // ---- token revocation cutoff ----
    @Test
    void tokenIssuedBeforeCutoffIsRejected() {
        Instant cutoff = Instant.parse("2026-01-01T10:00:05.500Z");
        assertTrue(SessionPolicy.issuedBeforeCutoff(Instant.parse("2026-01-01T10:00:04Z"), cutoff));
        assertFalse(SessionPolicy.issuedBeforeCutoff(Instant.parse("2026-01-01T10:00:05Z"), cutoff)); // same second: a fresh token must survive
        assertFalse(SessionPolicy.issuedBeforeCutoff(Instant.parse("2026-01-01T10:00:06Z"), cutoff));
        assertFalse(SessionPolicy.issuedBeforeCutoff(Instant.parse("2026-01-01T10:00:04Z"), null));
    }

    // ---- startup guard against dev-default secrets ----
    private static Map<String, String> goodEnv() {
        Map<String, String> m = new HashMap<>();
        m.put("JWT_SECRET", "a3f1c9d2e7b84a5f91c0d3e6f2a7b8c4d5e6f708192a3b4c5d6e7f8091a2b3c4");
        m.put("DB_ENCRYPTION_KEY", "5b2e8f1a9c3d4e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f");
        m.put("TSI_LOOKUP_SALT", "0f9e8d7c6b5a4938271605f4e3d2c1b0a9f8e7d6c5b4a39281706f5e4d3c2b1a");
        return m;
    }

    @Test
    void strongSecretsPassTheGuard() {
        assertTrue(SecretGuard.problems(goodEnv()).isEmpty());
    }

    @Test
    void shortMissingAndDevDefaultSecretsAreReported() {
        Map<String, String> m = goodEnv();
        m.put("JWT_SECRET", "short");
        m.remove("TSI_LOOKUP_SALT");
        m.put("DB_ENCRYPTION_KEY", "local-dev-enc-key-do-not-use-in-production");
        assertEquals(3, SecretGuard.problems(m).size());
    }

    @Test
    void publishedDockerComposeDefaultsAreReportedEvenWhenLongEnough() {
        Map<String, String> m = goodEnv();
        m.put("JWT_SECRET", "tsi-dpdp-cms-local-dev-secret-do-not-use-in-production");
        assertEquals(1, SecretGuard.problems(m).size());
    }
}
