package org.tsicoop.dpdpcms.framework;

import jakarta.servlet.http.HttpServletRequest;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Sliding-window rate limiter for the login endpoint.
 * Blocks an IP after MAX_ATTEMPTS failed attempts within WINDOW_MS.
 * Keyed on the client's remote address; resets on successful authentication.
 */
public class LoginRateLimiter {

    private static final int MAX_ATTEMPTS = 5;
    private static final long WINDOW_MS = 15 * 60 * 1000L; // 15 minutes

    private static final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    private static class Bucket {
        private int count = 0;
        private long windowStart = System.currentTimeMillis();

        synchronized boolean tryIncrement() {
            long now = System.currentTimeMillis();
            if (now - windowStart > WINDOW_MS) {
                count = 0;
                windowStart = now;
            }
            return ++count <= MAX_ATTEMPTS;
        }
    }

    /** Returns false when the IP has exceeded the allowed attempt threshold. */
    public static boolean isAllowed(String ip) {
        return buckets.computeIfAbsent(ip, k -> new Bucket()).tryIncrement();
    }

    /** Clears the bucket on successful login so legitimate users are never locked out. */
    public static void recordSuccess(String ip) {
        buckets.remove(ip);
    }

    /** Extracts the client IP, preferring X-Forwarded-For when present. */
    public static String getClientIp(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.trim().isEmpty()) {
            return xff.split(",")[0].trim();
        }
        return req.getRemoteAddr();
    }
}
