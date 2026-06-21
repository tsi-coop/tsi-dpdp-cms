package org.tsicoop.dpdpcms.framework;

import org.apache.commons.codec.binary.Hex;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.tsicoop.dpdpcms.service.v1.Audit;
import org.tsicoop.dpdpcms.util.Constants;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
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
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Best-effort, single-attempt event webhook delivery -- a push channel alongside
 * the existing poll-based APIs (list_notifications, list_purge_requests), not a
 * replacement for them. Configured per fiduciary per category (NOTIFICATION/PURGE)
 * via Notification.java's set_webhook_config/list_webhook_configs.
 *
 * No retry queue or delivery-tracking table by design: a failed delivery is logged
 * via the existing Audit fire-and-forget mechanism for DPO visibility, but the
 * underlying notifications/purge_requests row always exists regardless of webhook
 * outcome, so nothing is ever lost -- polling remains the reliable fallback.
 */
public class WebhookDispatcher {

    // Bounded so a stuck/slow webhook target can't grow threads/sockets without limit
    // (the JDK's default HttpClient executor is an unbounded cached thread pool).
    // Queue-full deliveries are dropped (logged), not blocked -- this is fire-and-forget,
    // never allowed to back up onto the calling request thread.
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

    private WebhookDispatcher() {}

    /**
     * Looks up the webhook configured for (fiduciaryId, category); no-ops silently
     * if none is configured or it's disabled. Fires asynchronously -- never blocks
     * or throws back to the caller (Consent/Compliance/Breach/CESService).
     */
    public static void dispatch(String fiduciaryId, String category, String eventType, JSONObject payload) {
        try {
            JSONObject config = getConfig(fiduciaryId, category);
            if (config == null || !Boolean.TRUE.equals(config.get("enabled"))) {
                return;
            }
            String webhookUrl = (String) config.get("webhook_url");
            String secret = (String) config.get("secret");

            JSONObject envelope = new JSONObject();
            envelope.put("event_type", eventType);
            envelope.put("fiduciary_id", fiduciaryId);
            envelope.put("timestamp", Instant.now().toString());
            envelope.put("data", payload);
            String body = envelope.toJSONString();

            String signature = hmacSha256Hex(body, secret);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(webhookUrl))
                    .header("Content-Type", "application/json")
                    .header("X-TSI-Signature", "sha256=" + signature)
                    .timeout(REQUEST_TIMEOUT)
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();

            HTTP_CLIENT.sendAsync(request, HttpResponse.BodyHandlers.ofString())
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
            // Webhook dispatch must never fail the calling operation.
            logDeliveryFailure(fiduciaryId, category, eventType, e.getMessage());
        }
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
