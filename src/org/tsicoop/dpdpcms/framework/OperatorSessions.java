package org.tsicoop.dpdpcms.framework;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Where token revocation state lives: revoked token ids (logout) and the per-operator
 * "tokens_valid_after" cutoff (password change, deactivation, first MFA enrolment).
 * The database-backed store keeps a short in-memory cache, so a revocation made on another
 * app instance is seen within CACHE_MS. Tests swap in a MemoryStore.
 */
public final class OperatorSessions {
    private OperatorSessions() {}

    public interface Store {
        void revokeJti(String jti, long expiresAtMs);
        boolean isJtiRevoked(String jti);
        /** Cutoff for this operator, or null if none. Throws on a lookup failure so callers fail closed. */
        Instant validAfter(String email);
        void setValidAfter(String email, Instant cutoff) throws Exception;
        /** Forget cached state for an operator (after the cutoff was written by a SQL UPDATE). */
        default void forget(String email) {}
    }

    private static volatile Store store = new DbStore();

    public static Store store() { return store; }
    public static void useStore(Store s) { store = s; }
    /** Restores the real database-backed store (tests swap in a MemoryStore). */
    public static void useDatabaseStore() { store = new DbStore(); }

    /** Call after an UPDATE that set operators.tokens_valid_after, so this instance applies it at once. */
    public static void forget(String email) {
        if (email != null) store.forget(email);
    }

    // ---------------------------------------------------------------------------------------

    public static class MemoryStore implements Store {
        private final Map<String, Long> revoked = new ConcurrentHashMap<>();
        private final Map<String, Instant> cutoffs = new ConcurrentHashMap<>();

        public void revokeJti(String jti, long expiresAtMs) { revoked.put(jti, expiresAtMs); }
        public boolean isJtiRevoked(String jti) {
            Long exp = revoked.get(jti);
            if (exp == null) return false;
            if (System.currentTimeMillis() > exp) { revoked.remove(jti); return false; }
            return true;
        }
        public Instant validAfter(String email) { return cutoffs.get(email.toLowerCase()); }
        public void setValidAfter(String email, Instant cutoff) throws Exception { cutoffs.put(email.toLowerCase(), cutoff); }
        public void forget(String email) { cutoffs.remove(email.toLowerCase()); }
    }

    /** PostgreSQL-backed store (tables from db/19_operator_access.sql) with a 30-second cache. */
    static final class DbStore extends MemoryStore {
        private static final long CACHE_MS = 30_000L;
        private volatile long lastRevokedRefresh = 0;
        private final Map<String, Object[]> cutoffCache = new ConcurrentHashMap<>(); // email -> {Instant|null, fetchedAtMs}

        @Override
        public void revokeJti(String jti, long expiresAtMs) {
            super.revokeJti(jti, expiresAtMs);
            PoolDB pool = null; Connection c = null; PreparedStatement ps = null;
            try {
                pool = new PoolDB();
                c = pool.getConnection();
                ps = c.prepareStatement("INSERT INTO revoked_tokens (jti, expires_at) VALUES (?, ?) ON CONFLICT (jti) DO NOTHING");
                ps.setString(1, jti);
                ps.setTimestamp(2, new Timestamp(expiresAtMs));
                ps.executeUpdate();
            } catch (Exception e) {
                System.err.println("[OperatorSessions] Could not persist token revocation (kept in memory only): " + e.getMessage());
            } finally {
                if (pool != null) pool.cleanup(null, ps, c);
            }
        }

        @Override
        public boolean isJtiRevoked(String jti) {
            refreshRevokedIfStale();
            return super.isJtiRevoked(jti);
        }

        private void refreshRevokedIfStale() {
            long now = System.currentTimeMillis();
            if (now - lastRevokedRefresh < CACHE_MS) return;
            synchronized (this) {
                if (now - lastRevokedRefresh < CACHE_MS) return;
                PoolDB pool = null; Connection c = null; PreparedStatement ps = null; ResultSet rs = null;
                try {
                    pool = new PoolDB();
                    c = pool.getConnection();
                    try (PreparedStatement del = c.prepareStatement("DELETE FROM revoked_tokens WHERE expires_at < NOW()")) {
                        del.executeUpdate();
                    }
                    ps = c.prepareStatement("SELECT jti, expires_at FROM revoked_tokens WHERE expires_at >= NOW()");
                    rs = ps.executeQuery();
                    while (rs.next()) super.revokeJti(rs.getString(1), rs.getTimestamp(2).getTime());
                    lastRevokedRefresh = now;
                } catch (Exception e) {
                    // keep what we have; try again on the next call after a short pause
                    System.err.println("[OperatorSessions] Revocation refresh failed: " + e.getMessage());
                    lastRevokedRefresh = now - CACHE_MS + 5_000L;
                } finally {
                    if (pool != null) pool.cleanup(rs, ps, c);
                }
            }
        }

        @Override
        public Instant validAfter(String email) {
            String key = email.toLowerCase();
            Object[] hit = cutoffCache.get(key);
            long now = System.currentTimeMillis();
            if (hit != null && now - (Long) hit[1] < CACHE_MS) return (Instant) hit[0];
            PoolDB pool = null; Connection c = null; PreparedStatement ps = null; ResultSet rs = null;
            try {
                pool = new PoolDB();
                c = pool.getConnection();
                ps = c.prepareStatement("SELECT tokens_valid_after FROM operators WHERE email_hmac = " + DbEncryption.HMAC);
                DbEncryption.bindHmac(ps, 1, email);
                rs = ps.executeQuery();
                Instant v = null;
                if (rs.next() && rs.getTimestamp(1) != null) v = rs.getTimestamp(1).toInstant();
                cutoffCache.put(key, new Object[]{v, now});
                return v;
            } catch (Exception e) {
                throw new IllegalStateException("tokens_valid_after lookup failed", e);
            } finally {
                if (pool != null) pool.cleanup(rs, ps, c);
            }
        }

        @Override
        public void setValidAfter(String email, Instant cutoff) throws Exception {
            PoolDB pool = new PoolDB();
            Connection c = pool.getConnection();
            PreparedStatement ps = null;
            try {
                ps = c.prepareStatement("UPDATE operators SET tokens_valid_after = ? WHERE email_hmac = " + DbEncryption.HMAC);
                ps.setTimestamp(1, Timestamp.from(cutoff));
                DbEncryption.bindHmac(ps, 2, email);
                ps.executeUpdate();
                cutoffCache.put(email.toLowerCase(), new Object[]{cutoff, System.currentTimeMillis()});
            } finally {
                pool.cleanup(null, ps, c);
            }
        }

        @Override
        public void forget(String email) { cutoffCache.remove(email.toLowerCase()); }
    }
}
