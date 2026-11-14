package org.tsicoop.dpdpcms.framework;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class JWTUtilOperatorTokenTest {

    private OperatorSessions.MemoryStore store;

    @BeforeEach
    void freshStore() {
        store = new OperatorSessions.MemoryStore();
        OperatorSessions.useStore(store);
    }

    private static String signRaw(java.util.Map<String, Object> claims, String sub, Date iat) {
        return Jwts.builder().setClaims(claims).setSubject(sub).setId(java.util.UUID.randomUUID().toString())
                .setIssuedAt(iat).setExpiration(new Date(System.currentTimeMillis() + 7_200_000L))
                .signWith(Keys.hmacShaKeyFor(System.getenv("JWT_SECRET").getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                .compact();
    }

    @Test
    void operatorTokenIsTypedAndValid() {
        String t = JWTUtil.generateToken("a@b.com", "a", "DPO");
        assertTrue(JWTUtil.isTokenValid(t));
        assertFalse(JWTUtil.hasMfa(t));
        assertTrue(JWTUtil.hasMfa(JWTUtil.generateToken("a@b.com", "a", "DPO", true)));
    }

    @Test
    void untypedTokenIssuedBeforeThisProcessStartedIsStillAcceptedWhenMfaIsNotEnforced() {
        org.junit.jupiter.api.Assumptions.assumeTrue(!org.tsicoop.dpdpcms.util.MfaPolicy.enforcing(), "legacy tokens are refused once MFA is enforced");
        // lets sessions issued by the previous release survive the upgrade
        String old = signRaw(new java.util.HashMap<>(java.util.Map.of("name", "a", "role", "ADMIN")), "a@b.com",
                new Date(System.currentTimeMillis() - 3_600_000L));
        assertTrue(JWTUtil.isTokenValid(old));
    }

    @Test
    void whenMfaIsEnforcedUntypedTokensAreRefusedSoEveryoneLogsInAgain() {
        org.junit.jupiter.api.Assumptions.assumeTrue(org.tsicoop.dpdpcms.util.MfaPolicy.enforcing(), "run with MFA_ENFORCE=true");
        String old = signRaw(new java.util.HashMap<>(java.util.Map.of("name", "a", "role", "ADMIN")), "a@b.com",
                new Date(System.currentTimeMillis() - 3_600_000L));
        assertFalse(JWTUtil.isTokenValid(old));
    }

    @Test
    void anOldUntypedTokenDoesNotSurviveRestartsForever() {
        // issued 9 hours ago (longer than a new session may last) by the previous release, which allowed 10 days
        String stale = signRaw(new java.util.HashMap<>(java.util.Map.of("name", "a", "role", "ADMIN")), "a@b.com",
                new Date(System.currentTimeMillis() - 9L * 3_600_000L));
        assertFalse(JWTUtil.isTokenValid(stale));
    }

    @Test
    void untypedTokenIssuedAfterThisProcessStartedIsRejected() {
        String fresh = signRaw(new java.util.HashMap<>(java.util.Map.of("name", "a", "role", "ADMIN")), "a@b.com",
                new Date(System.currentTimeMillis() + 5_000L));
        assertFalse(JWTUtil.isTokenValid(fresh));
    }

    @Test
    void mfaChallengeAndEnrolTokensDoNotWorkAsSessions() {
        String challenge = JWTUtil.generateMfaChallengeToken("a@b.com");
        String enrol = JWTUtil.generateMfaEnrolToken("a@b.com", "a", "ADMIN");
        assertFalse(JWTUtil.isTokenValid(challenge));
        assertFalse(JWTUtil.isTokenValid(enrol));
        assertEquals("a@b.com", JWTUtil.getMfaChallengeSubject(challenge));
        assertNull(JWTUtil.getMfaChallengeSubject(enrol));
        assertNotNull(JWTUtil.getMfaEnrolClaims(enrol));
        assertNull(JWTUtil.getMfaEnrolClaims(challenge));
        assertNull(JWTUtil.getMfaEnrolClaims(JWTUtil.generateToken("a@b.com", "a", "ADMIN")));
    }

    @Test
    void sessionTokenIsNotAMfaChallenge() {
        assertNull(JWTUtil.getMfaChallengeSubject(JWTUtil.generateToken("a@b.com", "a", "ADMIN")));
    }

    @Test
    void tokensIssuedBeforeTheOperatorCutoffAreRejected() throws Exception {
        String t = JWTUtil.generateToken("a@b.com", "a", "DPO");
        assertTrue(JWTUtil.isTokenValid(t));
        store.setValidAfter("a@b.com", Instant.now().plusSeconds(10)); // e.g. password changed
        assertFalse(JWTUtil.isTokenValid(t));
        // a token for someone else is unaffected
        assertTrue(JWTUtil.isTokenValid(JWTUtil.generateToken("other@b.com", "o", "DPO")));
    }

    @Test
    void revokedTokenIsRejected() {
        String t = JWTUtil.generateToken("a@b.com", "a", "DPO");
        TokenBlocklist.revoke(JWTUtil.getJtiFromToken(t), JWTUtil.getExpiryFromToken(t).getTime());
        assertFalse(JWTUtil.isTokenValid(t));
    }

    @Test
    void ttlIsConfigurableAndDefaultsToEightHours() {
        assertEquals(480L * 60_000L, JWTUtil.operatorTtlMs(null));
        assertEquals(30L * 60_000L, JWTUtil.operatorTtlMs("30"));
        assertEquals(480L * 60_000L, JWTUtil.operatorTtlMs("garbage"));
        assertEquals(480L * 60_000L, JWTUtil.operatorTtlMs("0"));
    }
}
