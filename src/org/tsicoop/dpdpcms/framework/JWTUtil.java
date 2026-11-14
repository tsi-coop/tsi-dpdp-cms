package org.tsicoop.dpdpcms.framework;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.tsicoop.dpdpcms.util.MfaPolicy;
import org.tsicoop.dpdpcms.util.SessionPolicy;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class JWTUtil {

    private static final long DEFAULT_OPERATOR_TTL_MINUTES = 480L;   // 8 hours; override with TOKEN_TTL_MINUTES
    private static final long MFA_CHALLENGE_TTL_MS = 5 * 60_000L;    // password verified, waiting for the TOTP code
    private static final long MFA_ENROL_TTL_MS = 15 * 60_000L;       // enrol-only session
    private static final long SYNC_TOKEN_EXPIRY = 31536000000L;      // 365 days — wallet sync tokens
    private static final long PRINCIPAL_TOKEN_EXPIRY = 86400000L;    // 24 hours — data principal portal sessions
    private static final Key SECRET_KEY = loadSecretKey();
    private static final long OPERATOR_TTL_MS = operatorTtlMs(System.getenv("TOKEN_TTL_MINUTES"));
    /** Operator tokens carry typ=OPERATOR. Untyped ones are honoured only if issued before this process started. */
    private static final Instant TYPING_START = Instant.now();

    private static final String CLAIM_TYPE       = "type";
    private static final String TYPE_SYNC        = "SYNC";
    private static final String TYPE_PRINCIPAL   = "PRINCIPAL";

    private static final String CLAIM_TYP        = "typ";
    private static final String TYP_OPERATOR     = "OPERATOR";
    private static final String TYP_MFA_CHALLENGE = "MFA_CHALLENGE";
    private static final String TYP_MFA_ENROL    = "MFA_ENROL";
    private static final String CLAIM_MFA        = "mfa";

    /** Operator session lifetime in ms from TOKEN_TTL_MINUTES (default 480); invalid or non-positive falls back to the default. */
    public static long operatorTtlMs(String minutes) {
        long m = DEFAULT_OPERATOR_TTL_MINUTES;
        try {
            if (minutes != null) {
                long v = Long.parseLong(minutes.trim());
                if (v > 0) m = Math.min(v, 7L * 24 * 60);
            }
        } catch (NumberFormatException ignored) { }
        return m * 60_000L;
    }

    public static long operatorTtlSeconds() { return OPERATOR_TTL_MS / 1000; }

    private static Key loadSecretKey() {
        String secret = System.getenv("JWT_SECRET");
        if (secret == null || secret.trim().isEmpty()) {
            throw new IllegalStateException("JWT_SECRET environment variable must be set");
        }
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    // --- Token generation ---

    public static String generateAppLoginToken(String email, String type, String username, String role, String state, String city) {
        Map<String, String> claims = new HashMap<>();
        claims.put("name", username);
        claims.put("role", role);
        claims.put("type", type);
        claims.put("state", state);
        claims.put("city", city);
        return createToken(claims, email, OPERATOR_TTL_MS);
    }

    public static String generateToken(String email, String username, String role) {
        return generateToken(email, username, role, false);
    }

    /** Operator session token. {@code mfa} records whether this session passed a TOTP check. */
    public static String generateToken(String email, String username, String role, boolean mfa) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("name", username);
        claims.put("role", role);
        claims.put(CLAIM_TYP, TYP_OPERATOR);
        claims.put(CLAIM_MFA, mfa);
        return createTokenObj(claims, email, OPERATOR_TTL_MS);
    }

    /** Short-lived proof that the password was right; only {@code verify_mfa} accepts it. */
    public static String generateMfaChallengeToken(String email) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_TYP, TYP_MFA_CHALLENGE);
        return createTokenObj(claims, email, MFA_CHALLENGE_TTL_MS);
    }

    /** Enrol-only session for an operator who must enrol MFA first; no other API accepts it. */
    public static String generateMfaEnrolToken(String email, String username, String role) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("name", username);
        claims.put("role", role);
        claims.put(CLAIM_TYP, TYP_MFA_ENROL);
        return createTokenObj(claims, email, MFA_ENROL_TTL_MS);
    }

    /** Subject (email) of a valid MFA challenge token, else null. */
    public static String getMfaChallengeSubject(String token) {
        Claims c = typedClaims(token, TYP_MFA_CHALLENGE);
        return c == null ? null : c.getSubject();
    }

    /** Claims of a valid enrol-only token, else null. */
    public static Claims getMfaEnrolClaims(String token) {
        return typedClaims(token, TYP_MFA_ENROL);
    }

    private static Claims typedClaims(String token, String typ) {
        try {
            Claims claims = parseClaims(token);
            if (!typ.equals(claims.get(CLAIM_TYP))) return null;
            String jti = claims.getId();
            if (jti != null && TokenBlocklist.isRevoked(jti)) return null;
            return claims;
        } catch (Exception e) {
            return null;
        }
    }

    /** True if the operator session token was issued after a successful TOTP check. */
    public static boolean hasMfa(String token) {
        try { return Boolean.TRUE.equals(parseClaims(token).get(CLAIM_MFA)); } catch (Exception e) { return false; }
    }

    /**
     * Issues a scoped wallet sync token for the given principal / fiduciary pair.
     * The token carries userId as subject and fiduciaryId as the "fid" claim.
     * type=SYNC prevents it from being accepted on admin API paths.
     */
    public static String generateSyncToken(String userId, String fiduciaryId) {
        Map<String, String> claims = new HashMap<>();
        claims.put(CLAIM_TYPE, TYPE_SYNC);
        claims.put("fid", fiduciaryId);
        return createToken(claims, userId, SYNC_TOKEN_EXPIRY);
    }

    /**
     * Issues a 24-hour portal session token for a data principal.
     * Encodes userId as subject and fiduciaryId as the "fid" claim.
     * type=PRINCIPAL prevents it from being accepted on admin API paths.
     */
    public static String generatePrincipalToken(String userId, String fiduciaryId) {
        Map<String, String> claims = new HashMap<>();
        claims.put(CLAIM_TYPE, TYPE_PRINCIPAL);
        claims.put("fid", fiduciaryId);
        return createToken(claims, userId, PRINCIPAL_TOKEN_EXPIRY);
    }

    /**
     * Validates a principal portal token.
     * Returns the claims on success, or null when invalid/expired/revoked/wrong type.
     */
    public static Claims getPrincipalClaims(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(SECRET_KEY).build()
                    .parseClaimsJws(token).getBody();
            if (!TYPE_PRINCIPAL.equals(claims.get(CLAIM_TYPE))) return null;
            String jti = claims.getId();
            if (jti != null && TokenBlocklist.isRevoked(jti)) return null;
            return claims;
        } catch (Exception e) {
            return null;
        }
    }

    private static String createToken(Map<String, String> claims, String subject, long expiryMs) {
        return createTokenObj(new HashMap<String, Object>(claims), subject, expiryMs);
    }

    private static String createTokenObj(Map<String, Object> claims, String subject, long expiryMs) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiryMs))
                .signWith(SECRET_KEY, SignatureAlgorithm.HS256)
                .compact();
    }

    // --- Validation ---

    /**
     * Validates an admin/operator JWT.
     * Returns false for expired, tampered, blocklisted, or SYNC-typed tokens.
     */
    public static boolean isTokenValid(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(SECRET_KEY).build()
                    .parseClaimsJws(token).getBody();
            // Reject scoped tokens (SYNC, PRINCIPAL) from admin auth paths
            String tokenType = (String) claims.get(CLAIM_TYPE);
            if (TYPE_SYNC.equals(tokenType) || TYPE_PRINCIPAL.equals(tokenType)) return false;

            // Token typing: only typ=OPERATOR is a session. Untyped tokens (issued by the previous
            // release) are honoured only if they predate this process, so existing sessions survive
            // the upgrade but nothing new can be minted without a type.
            Object typ = claims.get(CLAIM_TYP);
            Instant iat = claims.getIssuedAt() == null ? null : claims.getIssuedAt().toInstant();
            if (typ == null) {
                if (iat == null || !iat.isBefore(TYPING_START)) return false;
                // Previous-release tokens lived 10 days and carry no MFA proof: honour them only while as young as a
                // new session may be, and never when MFA is enforced. (TYPING_START moves on every restart, so
                // without this an old token would survive restarts for its whole 10-day life.)
                if (!SessionPolicy.legacyTokenAcceptable(iat, Instant.now(), MfaPolicy.enforcing(), OPERATOR_TTL_MS)) return false;
            } else if (!TYP_OPERATOR.equals(typ)) {
                return false;
            }

            String jti = claims.getId();
            if (jti != null && TokenBlocklist.isRevoked(jti)) return false;

            // Revoked by password change / deactivation / first MFA enrolment
            Instant cutoff = OperatorSessions.store().validAfter(claims.getSubject());
            if (SessionPolicy.issuedBeforeCutoff(iat, cutoff)) return false;
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Validates a wallet sync token.
     * Returns the claims on success, or null when invalid/expired/revoked/wrong type.
     */
    public static Claims getSyncClaimsFromToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(SECRET_KEY).build()
                    .parseClaimsJws(token).getBody();
            if (!TYPE_SYNC.equals(claims.get(CLAIM_TYPE))) {
                System.err.println("[JWTUtil] SYNC type check failed. Got: " + claims.get(CLAIM_TYPE));
                return null;
            }
            String jti = claims.getId();
            if (jti != null && TokenBlocklist.isRevoked(jti)) {
                System.err.println("[JWTUtil] JTI is revoked: " + jti);
                return null;
            }
            return claims;
        } catch (Exception e) {
            System.err.println("[JWTUtil] getSyncClaimsFromToken failed: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            return null;
        }
    }

    // --- Claim extractors ---

    public static String getEmailFromToken(String token) {
        return parseClaims(token).getSubject();
    }

    public static String getNameFromToken(String token) {
        return (String) parseClaims(token).get("name");
    }

    public static String getRoleFromToken(String token) {
        return (String) parseClaims(token).get("role");
    }

    public static String getAccountTypeFromToken(String token) {
        return (String) parseClaims(token).get("type");
    }

    public static String getJtiFromToken(String token) {
        return parseClaims(token).getId();
    }

    public static Date getExpiryFromToken(String token) {
        return parseClaims(token).getExpiration();
    }

    private static Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY).build()
                .parseClaimsJws(token).getBody();
    }
}
