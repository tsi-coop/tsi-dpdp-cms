package org.tsicoop.dpdpcms.framework;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class JWTUtil {

    private static final long EXPIRATION_TIME = 864000000L;          // 10 days — admin sessions
    private static final long SYNC_TOKEN_EXPIRY = 31536000000L;      // 365 days — wallet sync tokens
    private static final Key SECRET_KEY = loadSecretKey();

    private static final String CLAIM_TYPE  = "type";
    private static final String TYPE_SYNC   = "SYNC";

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
        return createToken(claims, email, EXPIRATION_TIME);
    }

    public static String generateToken(String email, String username, String role) {
        Map<String, String> claims = new HashMap<>();
        claims.put("name", username);
        claims.put("role", role);
        return createToken(claims, email, EXPIRATION_TIME);
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

    private static String createToken(Map<String, String> claims, String subject, long expiryMs) {
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
            // Reject wallet sync tokens from admin auth paths
            if (TYPE_SYNC.equals(claims.get(CLAIM_TYPE))) return false;
            String jti = claims.getId();
            if (jti != null && TokenBlocklist.isRevoked(jti)) return false;
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
