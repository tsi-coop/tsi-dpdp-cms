package org.tsicoop.dpdpcms.framework;

import org.apache.commons.codec.binary.Hex;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.tsicoop.dpdpcms.service.v1.Audit;
import org.tsicoop.dpdpcms.util.Constants;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Event webhook delivery -- a push channel alongside the existing poll-based APIs
 * (list_notifications, list_purge_requests), not a replacement for them. Configured per
 * fiduciary per category (NOTIFICATION/PURGE/OTP) via Notification.java's
 * set_webhook_config/list_webhook_configs.
 *
 * NOTIFICATION and PURGE events are recorded in webhook_deliveries (db/16) before they are
 * sent. A failed attempt is retried with backoff (see BACKOFF_SECONDS) by a background worker
 * started from JobManager; once attempts are exhausted the delivery is marked FAILED, audited
 * once as WEBHOOK_DELIVERY_FAILED, and listed in the DPO console where it can be retried by
 * hand. Delivery is at-least-once: receivers should de-duplicate on delivery_id (also sent as
 * X-TSI-Delivery-Id).
 *
 * Polling is still the safety net: the underlying notifications / purge_requests row always
 * exists regardless of webhook outcome, and a dropped task or a down database never loses it.
 *
 * OTP events are NOT stored or retried: their payload carries the one-time code (it must not
 * be written to a table) and a code delivered minutes late is worse than none. They keep the
 * original single-attempt behaviour.
 */
public class WebhookDispatcher {

    // Bounded so a stuck/slow webhook target can't grow threads/sockets without limit
    // (the JDK's default HttpClient executor is an unbounded cached thread pool).
    // Queue-full tasks are dropped (logged), not blocked -- never allowed to back up onto the
    // calling request thread. A dropped tracked delivery stays PENDING and is picked up by the
    // retry worker when its lease expires.
    private static final ExecutorService DELIVERY_EXECUTOR = new ThreadPoolExecutor(
            2, 16, 60L, TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(200),
            r -> { Thread t = new Thread(r, "webhook-dispatch"); t.setDaemon(true); return t; },
            (r, executor) -> System.err.println("[WebhookDispatcher] Delivery queue full -- dropping a webhook task."));

    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .executor(DELIVERY_EXECUTOR)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);

    /** Total sends per delivery: the first attempt plus MAX_ATTEMPTS - 1 retries. */
    static final int MAX_ATTEMPTS = 6;
    /** Wait after failed attempt n (1-based): 1m, 5m, 30m, 2h, 12h -- retries span ~14.5 hours. */
    static final long[] BACKOFF_SECONDS = {60, 300, 1800, 7200, 43200};
    /** How long a claimed/in-flight attempt is protected from being picked up again. */
    private static final int LEASE_SECONDS = 120;
    private static final int CLAIM_BATCH = 50;
    private static final int KEEP_DELIVERED_DAYS = 7;
    private static final int KEEP_FAILED_DAYS = 90;
    /** Categories that are sent once and never stored (see class comment). */
    private static final Set<String> UNTRACKED_CATEGORIES = Set.of("OTP");

    private static ScheduledExecutorService retryWorker;

    private WebhookDispatcher() {}

    /**
     * Records and sends the event for (fiduciaryId, category); no-ops silently if no webhook is
     * configured for it or it's disabled. Never blocks on the network or throws back to the
     * caller (Consent/Compliance/Breach/CESService).
     */
    public static void dispatch(String fiduciaryId, String category, String eventType, JSONObject payload) {
        try {
            JSONObject config = getConfig(fiduciaryId, category);
            if (config == null || !Boolean.TRUE.equals(config.get("enabled"))) {
                return;
            }

            UUID deliveryId = UUID.randomUUID();
            String body = buildEnvelope(deliveryId, fiduciaryId, eventType, payload);

            if (UNTRACKED_CATEGORIES.contains(category)) {
                sendOnce(config, fiduciaryId, category, eventType, deliveryId, body);
                return;
            }

            try {
                insertDelivery(deliveryId, fiduciaryId, category, eventType, body);
            } catch (SQLException e) {
                // Can't record it (database trouble): fall back to the old best-effort send so the
                // event isn't also lost here. Polling still covers anything this misses.
                System.err.println("[WebhookDispatcher] Could not record webhook delivery, sending untracked: " + e.getMessage());
                sendOnce(config, fiduciaryId, category, eventType, deliveryId, body);
                return;
            }
            DELIVERY_EXECUTOR.execute(() -> attempt(new Delivery(deliveryId, fiduciaryId, category, eventType, body, 0)));
        } catch (Exception e) {
            // Webhook dispatch must never fail the calling operation.
            logDeliveryFailure(fiduciaryId, category, eventType, e.getMessage());
        }
    }

    private static String buildEnvelope(UUID deliveryId, String fiduciaryId, String eventType, JSONObject payload) {
        JSONObject envelope = new JSONObject();
        envelope.put("event_type", eventType);
        envelope.put("delivery_id", deliveryId.toString());
        envelope.put("fiduciary_id", fiduciaryId);
        envelope.put("timestamp", Instant.now().toString());
        envelope.put("data", payload);
        return envelope.toJSONString();
    }

    private static HttpRequest buildRequest(String url, String secret, String body, UUID deliveryId, int attemptNumber) throws Exception {
        return HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .header("X-TSI-Signature", "sha256=" + hmacSha256Hex(body, secret))
                .header("X-TSI-Delivery-Id", deliveryId.toString())
                .header("X-TSI-Delivery-Attempt", Integer.toString(attemptNumber))
                .timeout(REQUEST_TIMEOUT)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
    }

    // ---------------------------------------------------------------------------------------
    // Untracked single attempt (OTP, and the fallback when a delivery can't be recorded)
    // ---------------------------------------------------------------------------------------

    private static void sendOnce(JSONObject config, String fiduciaryId, String category, String eventType, UUID deliveryId, String body) {
        try {
            String webhookUrl = (String) config.get("webhook_url");
            // Re-validate at dispatch time (not just at config-save time in Notification.java) --
            // defense against DNS rebinding between when the URL was saved and now.
            if (!isSafeWebhookUrl(webhookUrl)) {
                logDeliveryFailure(fiduciaryId, category, eventType, "Webhook URL failed safety check (private/internal host).");
                return;
            }
            HttpRequest request = buildRequest(webhookUrl, (String) config.get("secret"), body, deliveryId, 1);
            HTTP_CLIENT.sendAsync(request, HttpResponse.BodyHandlers.discarding())
                    .thenAccept(response -> {
                        if (response.statusCode() < 200 || response.statusCode() >= 300) {
                            logDeliveryFailure(fiduciaryId, category, eventType, "HTTP " + response.statusCode());
                        }
                    })
                    .exceptionally(e -> {
                        logDeliveryFailure(fiduciaryId, category, eventType, e.getMessage());
                        return null;
                    });
        } catch (Exception e) {
            logDeliveryFailure(fiduciaryId, category, eventType, e.getMessage());
        }
    }

    // ---------------------------------------------------------------------------------------
    // Tracked delivery: attempt, record outcome, retry
    // ---------------------------------------------------------------------------------------

    private static final class Delivery {
        final UUID id; final String fiduciaryId; final String category; final String eventType; final String body; final int attempts;
        Delivery(UUID id, String fiduciaryId, String category, String eventType, String body, int attempts) {
            this.id = id; this.fiduciaryId = fiduciaryId; this.category = category; this.eventType = eventType; this.body = body; this.attempts = attempts;
        }
    }

    /**
     * One send attempt. The config is read fresh each time, so a changed URL or rotated secret
     * applies to retries, and a disabled or unsafe webhook counts as a failed attempt rather
     * than being sent.
     */
    private static void attempt(Delivery d) {
        try {
            JSONObject config = getConfig(d.fiduciaryId, d.category);
            if (config == null || !Boolean.TRUE.equals(config.get("enabled"))) {
                recordOutcome(d, false, null, "Webhook is not configured or is disabled.");
                return;
            }
            String webhookUrl = (String) config.get("webhook_url");
            if (!isSafeWebhookUrl(webhookUrl)) {
                recordOutcome(d, false, null, "Webhook URL failed safety check (private/internal host).");
                return;
            }
            HttpRequest request = buildRequest(webhookUrl, (String) config.get("secret"), d.body, d.id, d.attempts + 1);
            HTTP_CLIENT.sendAsync(request, HttpResponse.BodyHandlers.discarding())
                    .whenComplete((response, error) -> {
                        if (error != null) {
                            recordOutcome(d, false, null, abbreviate(error.getMessage() != null ? error.getMessage() : error.toString()));
                        } else if (response.statusCode() >= 200 && response.statusCode() < 300) {
                            recordOutcome(d, true, response.statusCode(), null);
                        } else {
                            recordOutcome(d, false, response.statusCode(), "HTTP " + response.statusCode());
                        }
                    });
        } catch (Exception e) {
            recordOutcome(d, false, null, abbreviate(e.getMessage() != null ? e.getMessage() : e.toString()));
        }
    }

    private static void recordOutcome(Delivery d, boolean delivered, Integer httpStatus, String error) {
        int attemptsAfter = d.attempts + 1;
        boolean exhausted = !delivered && attemptsAfter >= MAX_ATTEMPTS;
        long waitSeconds = (!delivered && !exhausted) ? BACKOFF_SECONDS[Math.min(attemptsAfter, BACKOFF_SECONDS.length) - 1] : 0;

        String sql = delivered
                ? "UPDATE webhook_deliveries SET status = 'DELIVERED', attempts = ?, last_attempt_at = NOW(), delivered_at = NOW(), " +
                  "last_http_status = ?, last_error = NULL, next_attempt_at = NULL WHERE id = ? AND status = 'PENDING'"
                : "UPDATE webhook_deliveries SET status = ?, attempts = ?, last_attempt_at = NOW(), last_http_status = ?, last_error = ?, " +
                  "next_attempt_at = CASE WHEN ? THEN NULL ELSE NOW() + make_interval(secs => ?) END WHERE id = ? AND status = 'PENDING'";
        PoolDB pool = null;
        Connection conn = null;
        PreparedStatement pstmt = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            if (delivered) {
                pstmt.setInt(1, attemptsAfter);
                pstmt.setObject(2, httpStatus);
                pstmt.setObject(3, d.id);
            } else {
                pstmt.setString(1, exhausted ? "FAILED" : "PENDING");
                pstmt.setInt(2, attemptsAfter);
                pstmt.setObject(3, httpStatus);
                pstmt.setString(4, error);
                pstmt.setBoolean(5, exhausted);
                pstmt.setLong(6, waitSeconds);
                pstmt.setObject(7, d.id);
            }
            pstmt.executeUpdate();
        } catch (SQLException e) {
            // Row stays PENDING with its lease; the worker will retry it when the lease lapses.
            System.err.println("[WebhookDispatcher] Could not record delivery outcome for " + d.id + ": " + e.getMessage());
            return;
        } finally {
            if (pool != null) pool.cleanup(null, pstmt, conn);
        }
        if (exhausted) {
            logDeliveryFailure(d.fiduciaryId, d.category, d.eventType,
                    "Gave up after " + attemptsAfter + " attempts (delivery " + d.id + "): " + error);
        }
    }

    private static void insertDelivery(UUID id, String fiduciaryId, String category, String eventType, String body) throws SQLException {
        // The lease keeps the retry worker off this row while the first attempt is in flight.
        String sql = "INSERT INTO webhook_deliveries (id, fiduciary_id, category, event_type, body, status, attempts, next_attempt_at) " +
                "VALUES (?, ?, ?, ?, ?, 'PENDING', 0, NOW() + make_interval(secs => ?))";
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, id);
            pstmt.setObject(2, UUID.fromString(fiduciaryId));
            pstmt.setString(3, category);
            pstmt.setString(4, eventType);
            pstmt.setString(5, body);
            pstmt.setInt(6, LEASE_SECONDS);
            pstmt.executeUpdate();
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    // ---------------------------------------------------------------------------------------
    // Retry worker
    // ---------------------------------------------------------------------------------------

    /** Starts the background retry/cleanup worker (idempotent). Called from JobManager at startup. */
    public static synchronized void startRetryWorker() {
        if (retryWorker != null) return;
        retryWorker = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "webhook-retry-worker"); t.setDaemon(true); return t;
        });
        retryWorker.scheduleWithFixedDelay(WebhookDispatcher::processDue, 30, 30, TimeUnit.SECONDS);
        retryWorker.scheduleWithFixedDelay(WebhookDispatcher::cleanup, 1, 60, TimeUnit.MINUTES);
    }

    public static synchronized void stopRetryWorker() {
        if (retryWorker != null) {
            retryWorker.shutdownNow();
            retryWorker = null;
        }
    }

    /**
     * Claims due PENDING deliveries and attempts them. Claiming pushes next_attempt_at out by the
     * lease, so concurrent app instances (FOR UPDATE SKIP LOCKED) never send the same one twice,
     * and a delivery whose attempt was lost (crash, dropped task) is retried once its lease lapses.
     */
    static void processDue() {
        String sql = "WITH due AS (SELECT id FROM webhook_deliveries WHERE status = 'PENDING' AND next_attempt_at <= NOW() " +
                "ORDER BY next_attempt_at ASC LIMIT ? FOR UPDATE SKIP LOCKED) " +
                "UPDATE webhook_deliveries w SET next_attempt_at = NOW() + make_interval(secs => ?) FROM due WHERE w.id = due.id " +
                "RETURNING w.id, w.fiduciary_id, w.category, w.event_type, w.body, w.attempts";
        List<Delivery> claimed = new ArrayList<>();
        PoolDB pool = null;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setInt(1, CLAIM_BATCH);
            pstmt.setInt(2, LEASE_SECONDS);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                claimed.add(new Delivery((UUID) rs.getObject("id"), rs.getString("fiduciary_id"), rs.getString("category"),
                        rs.getString("event_type"), rs.getString("body"), rs.getInt("attempts")));
            }
        } catch (Exception e) {
            System.err.println("[WebhookDispatcher] Retry worker could not claim deliveries: " + e.getMessage());
            return;
        } finally {
            if (pool != null) pool.cleanup(rs, pstmt, conn);
        }
        for (Delivery d : claimed) {
            DELIVERY_EXECUTOR.execute(() -> attempt(d));
        }
    }

    /** Keeps the table bounded: delivered rows are only useful briefly, failed ones for follow-up. */
    static void cleanup() {
        String sql = "DELETE FROM webhook_deliveries WHERE (status = 'DELIVERED' AND created_at < NOW() - make_interval(days => ?)) " +
                "OR (status = 'FAILED' AND created_at < NOW() - make_interval(days => ?))";
        PoolDB pool = null;
        Connection conn = null;
        PreparedStatement pstmt = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setInt(1, KEEP_DELIVERED_DAYS);
            pstmt.setInt(2, KEEP_FAILED_DAYS);
            pstmt.executeUpdate();
        } catch (Exception e) {
            System.err.println("[WebhookDispatcher] Delivery cleanup failed: " + e.getMessage());
        } finally {
            if (pool != null) pool.cleanup(null, pstmt, conn);
        }
    }

    private static String abbreviate(String s) {
        if (s == null) return null;
        return s.length() > 500 ? s.substring(0, 500) + "..." : s;
    }

    private static void logDeliveryFailure(String fiduciaryId, String category, String eventType, String reason) {
        try {
            JSONObject context = new JSONObject();
            context.put("category", category);
            context.put("event_type", eventType);
            context.put("reason", reason);
            new Audit().logEventAsync("SYSTEM", UUID.fromString(fiduciaryId), Constants.SERVICE_TYPE_SYSTEM, null,
                    "WEBHOOK_DELIVERY_FAILED", context.toJSONString());
        } catch (Exception ignored) {
            // Audit logging itself must never throw back into webhook dispatch.
        }
    }

    /**
     * Rejects webhook URLs that could be used for SSRF: non-HTTPS schemes, and hosts
     * that resolve to loopback/link-local/site-local/multicast/any-local addresses
     * (this covers the 169.254.169.254 cloud metadata endpoint via the link-local
     * range). Used both at config-save time (Notification.java) and again here at
     * dispatch time, since DNS can change between the two.
     */
    public static boolean isSafeWebhookUrl(String url) {
        if (url == null || url.isEmpty()) return false;
        try {
            URI uri = URI.create(url);
            if (!"https".equalsIgnoreCase(uri.getScheme())) {
                return false;
            }
            String host = uri.getHost();
            if (host == null || host.isEmpty()) {
                return false;
            }
            for (InetAddress addr : InetAddress.getAllByName(host)) {
                if (addr.isLoopbackAddress() || addr.isLinkLocalAddress() || addr.isSiteLocalAddress()
                        || addr.isMulticastAddress() || addr.isAnyLocalAddress()) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static String hmacSha256Hex(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return Hex.encodeHexString(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Returns {webhook_url, secret (decrypted), enabled} for (fiduciaryId, category),
     * or null if not configured.
     */
    private static JSONObject getConfig(String fiduciaryId, String category) throws SQLException {
        String sql = "SELECT webhook_url, " + DbEncryption.decryptCol("secret_enc") + " AS secret, enabled " +
                "FROM webhook_configs WHERE fiduciary_id = ? AND category = ?";
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            int idx = DbEncryption.bindKey(pstmt, 1);
            pstmt.setObject(idx++, UUID.fromString(fiduciaryId));
            pstmt.setString(idx, category);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject result = new JSONObject();
                result.put("webhook_url", rs.getString("webhook_url"));
                result.put("secret", rs.getString("secret"));
                result.put("enabled", rs.getBoolean("enabled"));
                return result;
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return null;
    }
}
