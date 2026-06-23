package examples.integration.notifications;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Reference polling client for the TSI DPDP CMS Notification API (/api/v1/client/notification).
 *
 * There is no push/webhook/SSE delivery for notifications in this system — consumers
 * must poll list_notifications on an interval. This class demonstrates that pattern:
 * it polls every notification — PRINCIPAL, DPO, and APP recipients alike — for the
 * fiduciary tied to your App API key, with no other configuration required, and for
 * each newly-seen notification, dispatches a placeholder [NOTIFY] call out to wherever
 * a real integration sends email/SMS/push/etc — the implementer decides the channel(s).
 *
 * Build/run (standalone, outside the project's Maven module):
 *   javac -cp json-simple-1.1.1.jar examples/integration/notifications/NotificationListener.java
 *   java  -cp .:json-simple-1.1.1.jar examples.integration.notifications.NotificationListener \
 *         http://localhost:8080 &lt;API_KEY&gt; &lt;API_SECRET&gt; [poll_seconds] [preferred_language]
 *
 * If the DPO has configured a message for a notification's type (via the Settings
 * console screen / set_notification_message), list_notifications returns it as a
 * "messages" object keyed by language code (e.g. {"en": "...", "hi": "..."}) -- this
 * bundle can carry more languages than the recipient's fiduciary actually offers (e.g.
 * seeded built-in defaults exist in 8 languages regardless of which ones a given
 * fiduciary's active policy supports). This client fetches that fiduciary's active
 * policy (get_active_policy) once per fiduciary_id seen, and only prints the languages
 * present in policy_content, with preferred_language listed first when it's one of
 * them. A real integration would instead pick the one language its recipient wants.
 *
 * Each notification is marked read via mark_notification_read right after it's
 * dispatched, and polling requests unread_only -- so persistence lives server-side
 * (the read_at column), not just in this process's in-memory seenIds set. Restarting
 * the listener will not re-show notifications already handled in a prior run.
 *
 * The API key/secret identify exactly one App, which in turn identifies exactly one
 * fiduciary server-side — there is no need to pass a fiduciary id, recipient type, or
 * recipient id; the server resolves the fiduciary from the key and, with no recipient
 * filter supplied, returns notifications for every Data Principal, DPO, and App under it.
 */
public class NotificationListener {

    private static final Map<String, String> TYPE_LABELS = new HashMap<>();
    static {
        TYPE_LABELS.put("CONSENT_GIVEN_NOTIFICATION", "Consent Given");
        TYPE_LABELS.put("WITHDRAWAL_ACKNOWLEDGMENT", "Consent Withdrawn");
        TYPE_LABELS.put("ERASURE_REQUESTED_NOTIFICATION", "Erasure Requested");
        TYPE_LABELS.put("PURGE_INIT_NOTIFICATION", "Purge Initiated");
        TYPE_LABELS.put("PURGE_CONFIRM_NOTIFICATION", "Purge Confirmed");
        TYPE_LABELS.put("PURGE_ONHOLD_NOTIFICATION", "Purge On Legal Hold");
        TYPE_LABELS.put("EXPIRY_NOTIFICATION", "Retention/Consent Expiry Reminder");
    }

    private static final Map<String, String> RECIPIENT_LABELS = new HashMap<>();
    static {
        RECIPIENT_LABELS.put("PRINCIPAL", "Data Principal ID");
        RECIPIENT_LABELS.put("DPO", "DPO ID");
        RECIPIENT_LABELS.put("APP", "App ID");
    }

    // fiduciary_id -> "name (primary_domain)", populated once at startup from the
    // public fiduciary listing so notification lines can show a human-readable
    // fiduciary instead of a bare UUID.
    private static final Map<String, String> FIDUCIARY_LABELS = new HashMap<>();

    // fiduciary_id -> set of language codes its active ("IN") policy actually supports
    // (policy_content's keys). Populated lazily, once per fiduciary_id, the first time a
    // notification for that fiduciary is dispatched -- not at startup, since most deployments
    // only ever see notifications for the one fiduciary tied to the API key.
    private static final Map<String, Set<String>> POLICY_LANGUAGES = new HashMap<>();

    private static String label(String notificationType) {
        return TYPE_LABELS.getOrDefault(notificationType, notificationType);
    }

    private static String recipientLabel(JSONObject n) {
        String recipientType = (String) n.get("recipient_type");
        return RECIPIENT_LABELS.getOrDefault(recipientType, recipientType);
    }

    private static String fiduciaryLabel(JSONObject n) {
        String fiduciaryId = (String) n.get("fiduciary_id");
        return FIDUCIARY_LABELS.getOrDefault(fiduciaryId, fiduciaryId);
    }

    /**
     * Loads the public id/name/primary_domain listing once at startup so notification
     * lines can show "name (domain)" instead of a bare fiduciary_id. Best-effort —
     * if this fails (e.g. older server without primary_domain in the listing), the
     * listener still runs and just falls back to printing the raw fiduciary_id.
     */
    private static void loadFiduciaryLabels(HttpClient httpClient, String baseUrl) {
        try {
            JSONObject body = new JSONObject();
            body.put("_func", "list_active_fiduciaries");

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/api/v1/public/principal"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body.toJSONString()))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                System.out.println("[" + Instant.now() + "] Could not load fiduciary directory (HTTP "
                        + response.statusCode() + ") — will print raw fiduciary_id instead.");
                return;
            }

            JSONArray fiduciaries = (JSONArray) new JSONParser().parse(response.body());
            for (Object o : fiduciaries) {
                JSONObject f = (JSONObject) o;
                String id = (String) f.get("fiduciary_id");
                String name = (String) f.get("name");
                String domain = (String) f.get("primary_domain");
                FIDUCIARY_LABELS.put(id, domain != null ? (name + " (" + domain + ")") : name);
            }
        } catch (Exception e) {
            System.out.println("[" + Instant.now() + "] Could not load fiduciary directory: " + e.getMessage()
                    + " — will print raw fiduciary_id instead.");
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.out.println("Usage: NotificationListener <baseUrl> <apiKey> <apiSecret> [pollSeconds] [preferredLanguage]");
            System.exit(1);
        }

        String baseUrl = args[0];
        String apiKey = args[1];
        String apiSecret = args[2];
        int pollSeconds = args.length > 3 ? Integer.parseInt(args[3]) : 30;
        String preferredLanguage = args.length > 4 ? args[4] : "en";

        String url = baseUrl + "/api/v1/client/notification";
        HttpClient httpClient = HttpClient.newHttpClient();
        Set<String> seenIds = new HashSet<>();

        loadFiduciaryLabels(httpClient, baseUrl);

        System.out.println("Polling " + url + " every " + pollSeconds
                + "s for ALL notifications under this API key's fiduciary. Ctrl+C to stop.");

        while (true) {
            try {
                JSONObject body = new JSONObject();
                body.put("_func", "list_notifications");
                body.put("page", 1L);
                body.put("limit", 50L);
                body.put("unread_only", true);

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .header("Content-Type", "application/json")
                        .header("X-API-Key", apiKey)
                        .header("X-API-Secret", apiSecret)
                        .POST(HttpRequest.BodyPublishers.ofString(body.toJSONString()))
                        .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() != 200) {
                    System.out.println("[" + Instant.now() + "] Poll failed: HTTP " + response.statusCode() + " — " + response.body());
                } else {
                    JSONArray notifications = (JSONArray) new JSONParser().parse(response.body());
                    for (Object o : notifications) {
                        JSONObject n = (JSONObject) o;
                        String id = (String) n.get("id");
                        if (!seenIds.add(id)) continue; // already dispatched in a prior poll

                        System.out.println(String.format("[%s] %-32s recipient=%s/%s fiduciary=%s id=%s",
                                n.get("created_at"),
                                label((String) n.get("notification_type")),
                                n.get("recipient_type"), n.get("recipient_id"),
                                fiduciaryLabel(n),
                                id));

                        dispatchNotify(n, preferredLanguage, httpClient, baseUrl, apiKey, apiSecret);
                        markNotificationRead(httpClient, baseUrl, apiKey, apiSecret, id);
                    }
                }
            } catch (Exception e) {
                System.out.println("[" + Instant.now() + "] Poll error: " + e.getMessage());
            }

            Thread.sleep(pollSeconds * 1000L);
        }
    }

    /**
     * Placeholder for the actual third-party dispatch (email, SMS, push, webhook — the
     * implementer's choice of channel(s)). recipient_id is the recipient's internal UUID,
     * not a contact address — a real integration must first resolve it via the fiduciary's
     * own user directory.
     *
     * If the DPO has configured a message for this notification's exact type (via the
     * Settings console screen — this covers every type uniformly, including any
     * DPO-defined breach category such as BREACH_NOTIFICATION_PHISHING), print every
     * language the recipient's fiduciary actually offers (per its active policy), with
     * preferredLanguage listed first when offered; otherwise just show the bare type
     * label. A real integration would instead pick the one language the recipient wants.
     */
    private static void dispatchNotify(JSONObject n, String preferredLanguage,
                                        HttpClient httpClient, String baseUrl, String apiKey, String apiSecret) {
        String notificationType = (String) n.get("notification_type");
        String fiduciaryId = (String) n.get("fiduciary_id");
        Set<String> policyLanguages = loadPolicyLanguages(httpClient, baseUrl, apiKey, apiSecret, fiduciaryId);
        String localizedMessages = formatAllMessages((JSONObject) n.get("messages"), preferredLanguage, policyLanguages);

        System.out.println(String.format("  [NOTIFY] To: %s: %s  Type: %s  Fiduciary: %s%s",
                recipientLabel(n), n.get("recipient_id"),
                label(notificationType),
                fiduciaryLabel(n),
                localizedMessages == null ? "" : localizedMessages));
    }

    /**
     * Fetches and caches (per fiduciary_id) the set of language codes that fiduciary's
     * active "IN" policy supports (policy_content's keys) -- the same source settings.html's
     * loadSupportedLanguages() reads. Best-effort: falls back to {"en"} if the lookup fails
     * or the fiduciary has no active policy, matching that screen's fallback.
     */
    @SuppressWarnings("unchecked")
    private static Set<String> loadPolicyLanguages(HttpClient httpClient, String baseUrl, String apiKey, String apiSecret, String fiduciaryId) {
        if (fiduciaryId == null) return Collections.singleton("en");
        Set<String> cached = POLICY_LANGUAGES.get(fiduciaryId);
        if (cached != null) return cached;

        Set<String> languages = new HashSet<>();
        try {
            JSONObject body = new JSONObject();
            body.put("_func", "get_active_policy");
            body.put("fiduciary_id", fiduciaryId);
            body.put("jurisdiction", "IN");

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/api/v1/client/policy"))
                    .header("Content-Type", "application/json")
                    .header("X-API-Key", apiKey)
                    .header("X-API-Secret", apiSecret)
                    .POST(HttpRequest.BodyPublishers.ofString(body.toJSONString()))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                JSONObject policy = (JSONObject) new JSONParser().parse(response.body());
                JSONObject policyContent = (JSONObject) policy.get("policy_content");
                if (policyContent != null) {
                    for (Object key : policyContent.keySet()) languages.add((String) key);
                }
            }
        } catch (Exception e) {
            System.out.println("[" + Instant.now() + "] Could not load active policy languages for fiduciary "
                    + fiduciaryId + ": " + e.getMessage() + " — falling back to \"en\" only.");
        }
        if (languages.isEmpty()) languages.add("en");

        POLICY_LANGUAGES.put(fiduciaryId, languages);
        return languages;
    }

    /**
     * Renders one "Message [lang]: ..." line per language that is both configured in the
     * "messages" bundle and present in policyLanguages, preferredLanguage first when it
     * qualifies. Returns null if no message survives that filter (label(notificationType)
     * is used as-is in that case).
     */
    @SuppressWarnings("unchecked")
    private static String formatAllMessages(JSONObject messages, String preferredLanguage, Set<String> policyLanguages) {
        if (messages == null || messages.isEmpty()) return null;

        StringBuilder sb = new StringBuilder();
        boolean preferredQualifies = policyLanguages.contains(preferredLanguage) && messages.get(preferredLanguage) != null;
        if (preferredQualifies) {
            sb.append("\n           Message [").append(preferredLanguage).append("]: ").append(messages.get(preferredLanguage));
        }
        for (Object key : messages.keySet()) {
            String lang = (String) key;
            if (lang.equals(preferredLanguage)) continue; // already printed first, above
            if (!policyLanguages.contains(lang)) continue; // not offered by this fiduciary's active policy
            sb.append("\n           Message [").append(lang).append("]: ").append(messages.get(lang));
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    /**
     * Marks a notification read right after dispatch, so the unread_only filter on the
     * next poll (including after a restart) excludes it -- the durable record of "already
     * handled" lives server-side, not in this process's in-memory seenIds set.
     * Fire-and-forget: a failure here must not crash the poll loop.
     */
    private static void markNotificationRead(HttpClient httpClient, String baseUrl, String apiKey, String apiSecret, String id) {
        try {
            JSONObject body = new JSONObject();
            body.put("_func", "mark_notification_read");
            body.put("id", id);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/api/v1/client/notification"))
                    .header("Content-Type", "application/json")
                    .header("X-API-Key", apiKey)
                    .header("X-API-Secret", apiSecret)
                    .POST(HttpRequest.BodyPublishers.ofString(body.toJSONString()))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                System.out.println("[" + Instant.now() + "] Could not mark notification " + id + " read: HTTP " + response.statusCode());
            }
        } catch (Exception e) {
            System.out.println("[" + Instant.now() + "] Could not mark notification " + id + " read: " + e.getMessage());
        }
    }
}
