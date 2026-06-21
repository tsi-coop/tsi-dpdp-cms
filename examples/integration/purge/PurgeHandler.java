package examples.integration.purge;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Reference interactive client for handling purge instructions
 * (/api/v1/client/compliance — list_purge_requests / update_purge_status).
 *
 * Unlike NotificationListener (which just prints, passively), this is a human-in-the-loop
 * tool: it polls for purge requests targeted at your App (status PURGE_INITIATED),
 * prints each one, and interactively asks the operator whether the underlying data has
 * actually been purged in your own system -- then writes that answer straight back into
 * the consent manager via update_purge_status.
 *
 * No in-memory "already seen" tracking is needed (unlike NotificationListener's seenIds):
 * a purge request's own status column is the source of truth. The moment this tool marks
 * one PURGE_COMPLETED/PURGE_FAILED, it stops matching the PURGE_INITIATED filter and is
 * never re-fetched or re-prompted -- including across restarts. Answering "skip" leaves it
 * PURGE_INITIATED, so it simply reappears on the next poll.
 *
 * Build/run (standalone, outside the project's Maven module):
 *   javac -cp json-simple-1.1.1.jar examples/integration/purge/PurgeHandler.java
 *   java  -cp .:json-simple-1.1.1.jar examples.integration.purge.PurgeHandler \
 *         http://localhost:8080 &lt;API_KEY&gt; &lt;API_SECRET&gt; [poll_seconds]
 *
 * The API key/secret identify exactly one App -- list_purge_requests scopes results to
 * purge requests targeting that App, PLUS orphaned ones with no linked processor at all
 * (app_id IS NULL -- see CESService.recordOrphanComplianceEvent). Orphans aren't
 * necessarily this App's responsibility, but since no app is linked, they'd otherwise be
 * invisible to every App's poll -- this tool flags them distinctly and offers a
 * "[k]nothing needed" acknowledgement instead of forcing a real/failed purge answer.
 */
public class PurgeHandler {

    // fiduciary_id -> "name (primary_domain)", populated once at startup, same approach
    // NotificationListener uses, for a human-readable fiduciary instead of a bare UUID.
    private static final Map<String, String> FIDUCIARY_LABELS = new HashMap<>();

    private static String fiduciaryLabel(JSONObject row) {
        String fiduciaryId = (String) row.get("fiduciary_id");
        return FIDUCIARY_LABELS.getOrDefault(fiduciaryId, fiduciaryId);
    }

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
            if (response.statusCode() != 200) return;

            JSONArray fiduciaries = (JSONArray) new JSONParser().parse(response.body());
            for (Object o : fiduciaries) {
                JSONObject f = (JSONObject) o;
                String id = (String) f.get("fiduciary_id");
                String name = (String) f.get("name");
                String domain = (String) f.get("primary_domain");
                FIDUCIARY_LABELS.put(id, domain != null ? (name + " (" + domain + ")") : name);
            }
        } catch (Exception e) {
            System.out.println("[" + Instant.now() + "] Could not load fiduciary directory: " + e.getMessage());
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.out.println("Usage: PurgeHandler <baseUrl> <apiKey> <apiSecret> [pollSeconds]");
            System.exit(1);
        }

        String baseUrl = args[0];
        String apiKey = args[1];
        String apiSecret = args[2];
        int pollSeconds = args.length > 3 ? Integer.parseInt(args[3]) : 30;

        String url = baseUrl + "/api/v1/client/compliance";
        HttpClient httpClient = HttpClient.newHttpClient();
        BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));

        loadFiduciaryLabels(httpClient, baseUrl);

        System.out.println("Polling " + url + " every " + pollSeconds
                + "s for PURGE_INITIATED requests under this API key's App. Ctrl+C to stop.");

        while (true) {
            try {
                JSONObject body = new JSONObject();
                body.put("_func", "list_purge_requests");
                body.put("status", "PURGE_INITIATED");
                body.put("page", 1L);
                body.put("limit", 50L);

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
                    JSONArray purgeRequests = (JSONArray) new JSONParser().parse(response.body());
                    for (Object o : purgeRequests) {
                        JSONObject pr = (JSONObject) o;
                        handlePurgeRequest(httpClient, baseUrl, apiKey, apiSecret, pr, stdin);
                    }
                    if (purgeRequests.isEmpty()) {
                        System.out.println("[" + Instant.now() + "] No pending purge requests.");
                    }
                }
            } catch (Exception e) {
                System.out.println("[" + Instant.now() + "] Poll error: " + e.getMessage());
            }

            Thread.sleep(pollSeconds * 1000L);
        }
    }

    /**
     * Prints one purge request and interactively asks the operator whether it has
     * actually been completed in their own system, writing the answer back via
     * update_purge_status. "Skip" leaves the request PURGE_INITIATED -- it will simply
     * be re-fetched and re-prompted on the next poll (or after a restart).
     */
    private static void handlePurgeRequest(HttpClient httpClient, String baseUrl, String apiKey, String apiSecret,
                                            JSONObject pr, BufferedReader stdin) throws Exception {
        // Requests with no app_id have no linked data processor (see
        // CESService.recordOrphanComplianceEvent) -- list_purge_requests now includes
        // these alongside this App's own, so they're visible instead of being invisible
        // to every App's poll. There's nothing for this App to have purged in that case.
        boolean isOrphan = pr.get("app_id") == null;

        System.out.println(String.format("[%s] Purge requested: id=%s user=%s purpose=%s trigger=%s fiduciary=%s%s",
                pr.get("initiated_at"), pr.get("id"), pr.get("user_id"), pr.get("purpose_id"),
                pr.get("trigger_event"), fiduciaryLabel(pr),
                isOrphan ? "  [NO APP LINKED -- not necessarily yours to act on]" : ""));

        if (isOrphan) {
            System.out.print("  No data processor is linked to this purpose. [k]nothing needed (acknowledge) / [y]es I have data and purged it / [n]o, failed / [s]kip: ");
        } else {
            System.out.print("  Has this purge been completed in your system? [y]es / [n]o-failed / [s]kip for now: ");
        }
        String answer = stdin.readLine();
        if (answer == null) return; // stdin closed (e.g. non-interactive run) -- leave it pending
        answer = answer.trim().toLowerCase();

        if (answer.startsWith("k")) {
            updatePurgeStatus(httpClient, baseUrl, apiKey, apiSecret, (String) pr.get("id"), "PURGE_COMPLETED",
                    "No app processor linked - acknowledged, no purge action required");
        } else if (answer.startsWith("y")) {
            System.out.print("  Optional note (Enter for default): ");
            String note = stdin.readLine();
            String details = (note != null && !note.trim().isEmpty()) ? note.trim() : "Purge completed via PurgeHandler";
            updatePurgeStatus(httpClient, baseUrl, apiKey, apiSecret, (String) pr.get("id"), "PURGE_COMPLETED", details);
        } else if (answer.startsWith("n")) {
            System.out.print("  Failure note (Enter for default): ");
            String note = stdin.readLine();
            String details = (note != null && !note.trim().isEmpty()) ? note.trim() : "Purge failed, reported via PurgeHandler";
            updatePurgeStatus(httpClient, baseUrl, apiKey, apiSecret, (String) pr.get("id"), "PURGE_FAILED", details);
        } else {
            System.out.println("  Skipped -- will ask again next poll.");
        }
    }

    private static void updatePurgeStatus(HttpClient httpClient, String baseUrl, String apiKey, String apiSecret,
                                          String id, String status, String details) {
        try {
            JSONObject body = new JSONObject();
            body.put("_func", "update_purge_status");
            body.put("id", id);
            body.put("status", status);
            body.put("details", details);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/api/v1/client/compliance"))
                    .header("Content-Type", "application/json")
                    .header("X-API-Key", apiKey)
                    .header("X-API-Secret", apiSecret)
                    .POST(HttpRequest.BodyPublishers.ofString(body.toJSONString()))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                System.out.println("  Updated " + id + " -> " + status);
            } else {
                System.out.println("  Failed to update " + id + ": HTTP " + response.statusCode() + " — " + response.body()
                        + " (it remains PURGE_INITIATED and will be retried next poll)");
            }
        } catch (Exception e) {
            System.out.println("  Failed to update " + id + ": " + e.getMessage()
                    + " (it remains PURGE_INITIATED and will be retried next poll)");
        }
    }
}
