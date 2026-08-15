# Client Polling Integration Guide

**Document Version:** 1.0
**Audience:** Developers integrating downstream systems with TSI DPDP CMS.

---

## 1. Overview

This is a plain interval-polling pattern: your client calls an API on a fixed
interval (e.g. every 30s) and asks "what's new since last time?".

Two client-facing APIs use this pattern:

| API | Endpoint | What you poll for |
|---|---|---|
| Notifications | `/api/v1/client/notification` | Every notification (consent, withdrawal, purge, grievance, breach, expiry) for your fiduciary |
| Purge requests | `/api/v1/client/compliance` | Purge requests targeting your App, so you can confirm downstream deletion |

Both are authenticated the same way as any other App API call: `X-API-Key`
and `X-API-Secret` headers identify exactly one App, which resolves to
exactly one fiduciary server-side. You don't pass a fiduciary ID, and
results are scoped to that fiduciary automatically.

Reference implementations for both live in this repo:

- `examples/integration/notifications/NotificationListener.java` (with
  `notification-listener.sh` to compile and run it)
- `examples/integration/purge/PurgeHandler.java` (with `purge-handler.sh`)

### Polling vs. webhooks

If you've also set up the [Webhook Integration Guide](webhook-integration-guide.md),
webhooks get you lower latency, but delivery is best-effort and single-attempt
with no retry queue (see that guide, section 7). Polling is unconditionally
reliable - so even with webhooks configured, keep a poll running (at a longer
interval, e.g. every few minutes) as your reconciliation path for anything a
missed webhook delivery would otherwise drop.

## 2. Notification Polling

### Request

`POST /api/v1/client/notification`

```json
{
  "_func": "list_notifications",
  "unread_only": true,
  "page": 1,
  "limit": 50
}
```

`unread_only`, `page`, and `limit` are all optional. You can also filter by
`recipient_type` (`PRINCIPAL` / `DPO` / `APP`), `recipient_id`, or `status`
if you only care about a subset - omitting them (as above) returns every
notification for your fiduciary, across all recipients.

### Response

An array of notification objects:

```json
[
  {
    "id": "ntf_9f8e7d6c",
    "recipient_type": "PRINCIPAL",
    "recipient_id": "usr_555",
    "fiduciary_id": "8f2c1a90-1234-4a11-9e00-abcdef123456",
    "notification_type": "PURGE_CONFIRM_NOTIFICATION",
    "created_at": "2026-08-15T09:12:03.400Z",
    "messages": {
      "en": "Your data purge request has been completed.",
      "hi": "आपका डेटा purge अनुरोध पूरा हो गया है।"
    }
  }
]
```

`notification_type` is one of the same values documented in the
[Webhook Integration Guide](webhook-integration-guide.md#notification-types).
`messages` reflects the DPO-configured message bundle for that notification
type and may be `null` if none is configured; it can carry more languages
than the fiduciary's active policy actually supports; a real integration
should pick the one language its recipient wants (the recipient's own
preference), rather than showing every language present in the bundle.

### Marking a notification handled

After you've dispatched a notification (email, SMS, push - your choice of
channel), mark it read so it drops out of future `unread_only` polls:

```json
{ "_func": "mark_notification_read", "id": "ntf_9f8e7d6c" }
```

This is durable server-side (the `read_at` column) - not just in-memory - so
a restarted poller won't re-show notifications it already handled.

### Recommended interval

30 seconds is a reasonable default and what both example clients use. Lower
it if your use case needs faster delivery (e.g. OTP-adjacent flows); there's
no server-side rate limit specific to this endpoint beyond normal API usage.

## 3. Purge Request Polling

Unlike notifications, a purge request's own `status` column is the source of
truth - there's no separate "seen" tracking needed. Once you move a request
out of `PURGE_INITIATED`, it stops matching your poll filter and is never
re-fetched, including across restarts.

### Request

`POST /api/v1/client/compliance`

```json
{
  "_func": "list_purge_requests",
  "status": "PURGE_INITIATED",
  "page": 1,
  "limit": 50
}
```

Results are scoped to purge requests targeting your App, **plus** orphaned
requests with no processor linked at all (`app_id` is `null`). Orphans
aren't necessarily your responsibility, but since no App is linked to them,
they'd otherwise be invisible to every App's poll - treat them as
informational and acknowledge rather than assume you must act.

### Response

```json
[
  {
    "id": "prg_1a2b3c4d",
    "user_id": "usr_555",
    "purpose_id": "prp_marketing_01",
    "app_id": "app_crm",
    "fiduciary_id": "8f2c1a90-1234-4a11-9e00-abcdef123456",
    "trigger_event": "CONSENT_REVOKED",
    "initiated_at": "2026-08-15T09:12:03.512Z"
  }
]
```

### Confirming a purge

Once you've deleted (or confirmed you have nothing to delete for) the user
in your own system, write the outcome back:

```json
{
  "_func": "update_purge_status",
  "id": "prg_1a2b3c4d",
  "status": "PURGE_COMPLETED",
  "details": "Purged from CRM contact table"
}
```

For a normal integration, `status` is `PURGE_COMPLETED` or `PURGE_FAILED` -
the two example clients above only ever use these. The full set of
meaningful values also includes `PURGE_IN_PROGRESS` and `LEGAL_HOLD_APPLIED`
(the DPO Console's own dropdown offers all four); see the
[System Integration Guide](system-integration-guide.md#9-confirming-purge-status)
for the caveats around those two before using them from an integration.
For an orphan request (`app_id` is `null`) where nothing was ever held,
complete it with a `details` note explaining that, rather than reporting
failure. `details` is required on every call - use it to leave an audit
trail of what was actually done, since it becomes part of the compliance
record.

Leaving a request in `PURGE_INITIATED` (skipping it) simply means it
reappears on your next poll.

### Recommended interval

Purge requests are not latency-sensitive in the same way notifications are;
30 seconds (as shown above) is a reasonable default, but polling every few
minutes is equally fine for most integrations.

## 4. Running the Reference Clients

Both examples are self-contained Java files, built outside the project's
Maven module:

```bash
BASE_URL=http://localhost:8080 API_KEY=<uuid> API_SECRET=<secret> \
POLL_SECONDS=10 ./examples/integration/notifications/notification-listener.sh

BASE_URL=http://localhost:8080 API_KEY=<uuid> API_SECRET=<secret> \
POLL_SECONDS=10 ./examples/integration/purge/purge-handler.sh
```

`NotificationListener` just prints what it sees (a placeholder `[NOTIFY]`
line stands in for wherever a real integration would send email/SMS/push).
`PurgeHandler` is interactive - it prompts you, in the terminal, to confirm
whether each purge has actually happened in your system, then writes that
back via `update_purge_status`. Use them as a starting point, not as
production code.
