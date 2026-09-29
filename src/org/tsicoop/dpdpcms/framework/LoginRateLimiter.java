package org.tsicoop.dpdpcms.framework;

import jakarta.servlet.http.HttpServletRequest;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Sliding-window rate limiter, generalized over an arbitrary string key
 * (an IP, or a "purpose:target" composite such as "otp-send:fid:userId").
 * Blocks a key after its configured attempt threshold within its window.
 * Default threshold (5 attempts / 15 minutes) preserves the original
 * IP-keyed login behavior; other callers can pass their own threshold.
 * Resets a key's bucket on successful authentication.
 */
public class LoginRateLimiter {

    private static final int MAX_ATTEMPTS = 5;
    private static final long WINDOW_MS = 15 * 60 * 1000L; // 15 minutes

    private static final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    private static class Bucket {
        private int count = 0;
        private long windowStart = System.currentTimeMillis();
        private final int maxAttempts;
        private final long windowMs;

        Bucket(int maxAttempts, long windowMs) {
            this.maxAttempts = maxAttempts;
            this.windowMs = windowMs;
        }

        synchronized boolean tryIncrement() {
            long now = System.currentTimeMillis();
            if (now - windowStart > windowMs) {
                count = 0;
                windowStart = now;
            }
            return ++count <= maxAttempts;
        }
    }

    /** Returns false when the key has exceeded the default attempt threshold (5 / 15 min). */
    public static boolean isAllowed(String key) {
        return isAllowed(key, MAX_ATTEMPTS, WINDOW_MS);
    }

    /** Returns false when the key has exceeded {@code maxAttempts} within {@code windowMs}. */
    public static boolean isAllowed(String key, int maxAttempts, long windowMs) {
        return buckets.computeIfAbsent(key, k -> new Bucket(maxAttempts, windowMs)).tryIncrement();
    }

    /** Clears the bucket on successful login so legitimate users are never locked out. */
    public static void recordSuccess(String key) {
        buckets.remove(key);
    }

    /** Extracts the client IP. Only trusts X-Forwarded-For when the request comes from a known proxy. */
    public static String getClientIp(HttpServletRequest req) {
        String trustedProxy = System.getenv("TRUSTED_PROXY");
        if (trustedProxy != null && !trustedProxy.isBlank()
                && trustedProxy.equals(req.getRemoteAddr())) {
            String xff = req.getHeader("X-Forwarded-For");
            if (xff != null && !xff.isBlank()) {
                return xff.split(",")[0].trim();
            }
        }
        return req.getRemoteAddr();
    }
}
