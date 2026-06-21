# Notifications Capability — Analysis, Bug Fix, Lifecycle Coverage & Example Listener

## Context
This plan started as a read-only analysis of the `notifications` capability (is it backed by a real table? how should an implementation team consume it?). That analysis is preserved below. The user has now asked for three follow-on changes:
1. Fix the broken `status` filter in the `list_notifications` API (it references a column that doesn't exist on the table, so any caller passing `status` gets a SQL error).
2. Extend notification creation to cover the full consent lifecycle — today only `EXPIRY_NOTIFICATION` and `PURGE_INIT_NOTIFICATION` are ever produced (both from the scheduled CES job). Consent given, consent withdrawn, and erasure requested currently create **no** notification at all, even though they're exactly the events an implementation team most wants to observe in real time.
3. Add a runnable example, `examples/integration/notifications/NotificationListener.java`, that polls the API and prints all notification types (including the new lifecycle ones) to `System.out`, so an implementation team has a concrete starting point.

All three were verified directly against source (not just agent reports) before finalizing this plan.

**Status: implemented.** Parts B, C, and D below have been applied (Maven build verified clean with `mvn -q -o compile`). A test convenience was also added, beyond the original plan: `examples/integration/notifications/test-notifications.sh`, a curl+jq script that exercises `record_consent` → `withdraw_consent` → `erasure_request` against a running instance and confirms each step produces the expected notification, plus a regression check that `status` no longer triggers a SQL error.

---

## Part A — Original Analysis (unchanged)

### A1. Yes — notifications are captured in a real `notifications` table
`db/01_init.sql` (lines 207-217):
```sql
CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    recipient_type VARCHAR(50) NOT NULL,   -- PRINCIPAL, DPO, APP
    recipient_id VARCHAR(255) NOT NULL,    -- User ID, DPO ID, App ID
    fiduciary_id UUID REFERENCES fiduciaries(id),
    notification_type VARCHAR(100) NOT NULL,
    read_at TIMESTAMP WITH TIME ZONE,      -- set on mark-as-read
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
```
Indexes: `(recipient_id, created_at DESC)` and `(fiduciary_id, notification_type, created_at DESC)`. Flat in-app log — no JSONB payload, no delivery-channel/status columns.

**Writers today** — `CESService.insertNotification(recipientType, recipientId, fiduciaryId, notificationType)` (`src/org/tsicoop/dpdpcms/ces/CESService.java:529-560`), called only from the scheduled CES job (`JobManager`, every 2 min + nightly): `EXPIRY_NOTIFICATION` (5 days pre-expiry, →PRINCIPAL) and `PURGE_INIT_NOTIFICATION` (erasure/retention purge, →APP).

**Readers today** — `service/v1/Notification.java`, routed at `/api/v1/notification` (alias `/api/v1/client/notification`): `list_notifications` (SCOPE_READ, paginated, filterable by recipient/fiduciary) and `mark_notification_read` (SCOPE_WRITE, sets `read_at`).

**No UI, no delivery channel.** No bell icon anywhere in `web/console/*` or `web/rights`. No email/SMS/push/webhook/websocket/SSE — purely pull/poll via the REST API. The class-level Javadoc in `Notification.java` describes a much richer planned design (`notification_templates`/`notification_instances`, channels, severity) — none of that exists; treat it as stale/aspirational.

### A2. Recommended consumption pattern (unchanged)
Since there's no push mechanism, an implementation team should **poll** `/api/v1/notification`:
- `APP` clients: auth via `X-API-Key`/`X-API-Secret`; omit `recipient_id` (server fills it from the key); pass `fiduciary_id` when scoped.
- `PRINCIPAL`/`DPO` clients: auth via existing JWT/session; pass `recipient_type` + own `recipient_id`.
- Poll on an interval (no `since`/cursor param exists), track highest `created_at`/last-seen `id` locally to detect "new" notifications.
- Call `mark_notification_read` only for human-facing recipients; APP/machine consumers should track "last processed" locally and treat `notification_type` handling as idempotent.
- Build a dispatch table keyed on `notification_type` so new types can be added without a contract change.

---

## Part B — Fix the `status` filter bug

**File:** `src/org/tsicoop/dpdpcms/service/v1/Notification.java`

The table has no `status` column, yet `listNotificationsFromDb` builds `AND status = ?` whenever a caller passes `status` (lines 185-187), and the `_func: list_notifications` handler reads `input.get("status")` into `instanceStatus` (line 99) and forwards it (line 103). Any request that includes `status` currently throws a SQL error.

**Fix:** remove the dead/broken status-filtering code path entirely — drop the `statusFilter` parameter from `listNotificationsFromDb`'s signature and the `AND status = ?` SQL branch (lines 185-188), and stop reading/forwarding `input.get("status")` in the `list_notifications` case (lines 99, 103). The `read_at` column already exists for unread/read filtering if that's ever needed — out of scope here since it wasn't requested.

---

## Part C — Extend notification creation across the consent lifecycle

**Goal:** fire a notification on `record_consent` (consent given), `withdraw_consent` (consent withdrawn), and `erasure_request` (erasure requested) — all handled in `src/org/tsicoop/dpdpcms/service/v1/Consent.java`.

### C1. New notification type constants
**File:** `src/org/tsicoop/dpdpcms/util/Constants.java` (existing block at lines 41-46)

Add one new constant; reuse one already-defined-but-unused constant:
```java
public static final String NOTIF_CONSENT_GIVEN = "CONSENT_GIVEN_NOTIFICATION"; // new
public static final String NOTIF_ERASURE_REQUESTED = "ERASURE_REQUESTED_NOTIFICATION"; // new
// NOTIF_WITHDRAWAL_ACK already exists (line 46) — currently unused; will be wired in
```
`NOTIF_PURGE_INIT` is deliberately **not** reused for `erasure_request` — that constant already has a distinct, established meaning (CES telling an **APP** to actually purge data, fired later by the batch job). The new `NOTIF_ERASURE_REQUESTED` notifies the **PRINCIPAL** that their request was received, which is a different audience and timing.

### C2. Wire `CESService.insertNotification(...)` into `Consent.java`
`CESService.insertNotification` is `public` (instance method); the codebase's established pattern is direct cross-service instantiation (e.g. `JobManager` does `new CESService()`; `Consent.java` already does `new Audit().logEventAsync(...)`). `Consent.java` already imports a sibling-package class (`org.tsicoop.dpdpcms.ces.CESUtil`), so add `import org.tsicoop.dpdpcms.ces.CESService;` and call `new CESService().insertNotification(...)` at each success point, catching/ignoring `SQLException` from the notification insert separately so a notification failure never rolls back or fails the consent operation itself (consistent with how `Audit.logEventAsync` is fire-and-forget).

**Three insertion points, all in `Consent.java`:**

1. **`record_consent`** → `recordConsentToDb(...)`, right after `recorded = true;` (line 794) and alongside the existing `new Audit().logEventAsync(userId, fiduciaryId, "APP", appId, "CONSENT_GIVEN", ...)` call (line 811), before the final `return` (line 813):
   ```java
   new CESService().insertNotification("PRINCIPAL", userId, fiduciaryId.toString(), Constants.NOTIF_CONSENT_GIVEN);
   ```

2. **`withdraw_consent`** → `withdrawConsent(...)`, in the success block right after `result.put("action", action);` (line 649), branching on the existing `erasure` boolean (already used in this exact method to distinguish `Constants.ACTION_CONSENT_WITHDRAWN` vs `Constants.ACTION_ERASURE_REQUEST`, lines 511-513):
   ```java
   String notifType = erasure ? Constants.NOTIF_ERASURE_REQUESTED : Constants.NOTIF_WITHDRAWAL_ACK;
   new CESService().insertNotification("PRINCIPAL", userId, fiduciaryId.toString(), notifType);
   ```
   This single call site covers both **`withdraw_consent`** and **`erasure_request`**, since both routes call this same shared method (`Consent.java` switch cases at lines 235 and 250 both delegate to `withdrawConsent(...)`, differing only in the `erasure` argument).

Both insertions happen after `conn.commit()` (lines 639 / 792 respectively), so they only fire once the underlying consent-record write has actually succeeded.

---

## Part D — Example: `examples/integration/notifications/NotificationListener.java`

**Context for placement:** `examples/` currently only holds non-code data artifacts (legal evidence PDFs, ROPA/policy templates under `examples/{ropa,policy,legal}/...`) — there are no existing Java example classes, no `examples/integration/` subfolder yet, and no separate `pom.xml` there. Per the user's direction, this goes under a new `examples/integration/notifications/` path (distinguishing runnable integration-code examples from the existing data-artifact examples), written as a **single self-contained `.java` file** runnable without modifying the main Maven build.

**Design:**
- Uses `java.net.http.HttpClient` (JDK built-in, Java 15+ per the project's `maven.compiler.target`) for the HTTP call — no new dependency.
- Uses `org.json.simple` (`JSONObject`/`JSONArray`/`JSONParser`) for request/response JSON, matching the rest of the codebase's convention (`json-simple` is already a project dependency in the root `pom.xml`). The file's header comment documents that running it standalone requires `json-simple-1.1.1.jar` on the classpath, since it lives outside the WAR's Maven module. Package declaration will be `examples.integration.notifications`, e.g.: `javac -cp json-simple-1.1.1.jar examples/integration/notifications/NotificationListener.java && java -cp .:json-simple-1.1.1.jar examples.integration.notifications.NotificationListener ...`
- Command-line args (with sane defaults): base URL (default `http://localhost:8080`), `X-API-Key`, `X-API-Secret`, `recipient_type` (default `APP`), optional `recipient_id`/`fiduciary_id`, poll interval in seconds (default 30).
- Main loop: every interval, POST `{"_func":"list_notifications", "recipient_type":..., "page":1, "limit":50, ...}` to `/api/v1/notification` (no `status` field, since that's the bug being fixed/removed). Track an in-memory `Set<String>` of already-printed notification `id`s (the API has no `since` cursor) so each poll only prints genuinely new rows.
- Maps every known `notification_type` (`CONSENT_GIVEN_NOTIFICATION`, `WITHDRAWAL_ACKNOWLEDGMENT`, `ERASURE_REQUESTED_NOTIFICATION`, `PURGE_INIT_NOTIFICATION`, `EXPIRY_NOTIFICATION`, `PURGE_CONFIRM_NOTIFICATION`, `PURGE_ONHOLD_NOTIFICATION`) to a short human label via a simple lookup, with a sensible fallback for any future/unmapped type — this satisfies "listen to all notifications... across the entire consent lifecycle" without hardcoding assumptions about which types are currently wired up.
- Prints one line per new notification to `System.out`: timestamp, label, recipient, fiduciary id, notification id.
- Runs indefinitely (`while(true)` + `Thread.sleep`) until interrupted (Ctrl+C) — appropriate for a reference/demo listener.

---

## Files to change
- `src/org/tsicoop/dpdpcms/service/v1/Notification.java` — remove broken `status` filter (lines ~99, 103, 163, 185-188).
- `src/org/tsicoop/dpdpcms/util/Constants.java` — add `NOTIF_CONSENT_GIVEN`, `NOTIF_ERASURE_REQUESTED` (near existing block, lines 41-46).
- `src/org/tsicoop/dpdpcms/service/v1/Consent.java` — add `import org.tsicoop.dpdpcms.ces.CESService;`; insert notification calls at the `record_consent` success point (~line 794/811-813) and the shared `withdrawConsent` success point (~line 649), branching on `erasure`.
- `examples/integration/notifications/NotificationListener.java` — new file, standalone polling example.
- `examples/integration/notifications/test-notifications.sh` — new file, curl+jq script exercising the full lifecycle end-to-end (added per user request for "a convenient way to test").

## Verification
1. **Status filter fix:** start the app, call `/api/v1/notification` with `{"_func":"list_notifications","recipient_type":"APP","status":"anything"}` (App API key) — should now succeed and simply ignore the field, instead of a 500/SQL error.
2. **Lifecycle notifications:** call `record_consent`, then `withdraw_consent`, then `erasure_request` (or use the existing rights-portal flow) for a test principal/fiduciary, then call `list_notifications` with `recipient_type=PRINCIPAL`, `recipient_id=<that user>` and confirm three new rows appear with `notification_type` = `CONSENT_GIVEN_NOTIFICATION`, `WITHDRAWAL_ACKNOWLEDGMENT`/`ERASURE_REQUESTED_NOTIFICATION` respectively, each shortly after the corresponding action's `conn.commit()`.
3. **Example listener:** compile/run `NotificationListener.java` against a running local instance with a real App API key/secret (generated via the admin console's `generate_api_key`), trigger a consent action from another terminal/UI, and confirm the listener prints it within one poll interval without needing a restart.
