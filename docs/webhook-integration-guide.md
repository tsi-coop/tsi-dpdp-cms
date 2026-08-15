# Webhook Integration Guide

**Document Version:** 1.0
**Applies to:** TSI DPDP CMS v0.4.8+ (SSRF hardening in v0.5.0)

---

## 1. Overview

Webhooks let your external systems receive real-time push notifications when
notification, purge, or OTP-delivery events occur in TSI DPDP CMS, instead of
polling the `list_notifications` / purge-list APIs.

Webhook delivery is **best-effort and single-attempt**: there is no retry
queue or delivery-tracking table. If a delivery fails (timeout, non-2xx
response, DNS failure), the CMS logs a `WEBHOOK_DELIVERY_FAILED` audit event
for DPO visibility, but does not retry. The underlying notification or purge
request row is created regardless of webhook outcome, so **polling remains
the reliable source of truth**. Treat webhooks as a low-latency convenience
layer on top of polling, not a replacement for it.

## 2. Supported Events

Webhooks are configured per **category**. Each category has its own URL and
signing secret, configured independently.

| Category | `event_type` | Fires when |
|---|---|---|
| `NOTIFICATION` | `notification_created` | Any notification is created (consent, withdrawal, erasure, purge, grievance, breach, expiry; see notification types below) |
| `PURGE` | `purge_request_created` | A purge request is created |
| `PURGE` | `purge_request_status_updated` | A purge request's status changes (e.g. completed, legal hold applied) |
| `OTP` | `principal_otp_requested` | An OTP is generated for Rights Management App login (only fires when OTP mode is Email or Mobile, not Dummy) |

### Notification types

A `notification_created` event's `data.notification_type` field indicates
what kind of notification it is:

`CONSENT_GIVEN_NOTIFICATION`, `WITHDRAWAL_ACKNOWLEDGMENT`,
`ERASURE_REQUESTED_NOTIFICATION`, `PURGE_INIT_NOTIFICATION`,
`PURGE_CONFIRM_NOTIFICATION`, `PURGE_ONHOLD_NOTIFICATION`,
`EXPIRY_NOTIFICATION`, `GRIEVANCE_SUBMITTED_NOTIFICATION`,
`GRIEVANCE_RESOLVED_NOTIFICATION`, `GRIEVANCE_ESCALATED_NOTIFICATION`,
`GRIEVANCE_ASSIGNED_NOTIFICATION`, `BREACH_NOTIFICATION`.

You cannot subscribe to individual notification types: subscribing to the
`NOTIFICATION` category delivers all of them, and your endpoint should branch
on `data.notification_type`.

## 3. Payload Structure

All webhooks are sent as `POST` requests with a JSON body.

### Headers

| Header | Description |
|---|---|
| `Content-Type` | `application/json` |
| `X-TSI-Signature` | `sha256=<hex>`, an HMAC-SHA256 signature for verification (see §4) |

There is no separate timestamp or event-ID header: the timestamp is part of
the JSON envelope, and events don't carry a delivery/event ID today, so
de-duplication should key off `data.id` where present.

### Envelope

Every event is wrapped in the same outer shape:

```json
{
  "event_type": "notification_created",
  "fiduciary_id": "<uuid>",
  "timestamp": "2026-08-15T09:12:03.512Z",
  "data": { }
}
```

### Example: `notification_created`

```json
{
  "event_type": "notification_created",
  "fiduciary_id": "8f2c1a90-1234-4a11-9e00-abcdef123456",
  "timestamp": "2026-08-15T09:12:03.512Z",
  "data": {
    "id": "ntf_9f8e7d6c",
    "recipient_type": "PRINCIPAL",
    "recipient_id": "usr_555",
    "notification_type": "PURGE_CONFIRM_NOTIFICATION",
    "created_at": "2026-08-15T09:12:03.400Z",
    "messages": {
      "en": "Your data purge request has been completed.",
      "hi": "आपका डेटा purge अनुरोध पूरा हो गया है।"
    }
  }
}
```

`messages` reflects the DPO-configured message bundle for that fiduciary and
notification type, and may be `null` if none is configured.

### Example: `purge_request_created`

```json
{
  "event_type": "purge_request_created",
  "fiduciary_id": "8f2c1a90-1234-4a11-9e00-abcdef123456",
  "timestamp": "2026-08-15T09:12:03.512Z",
  "data": {
    "id": "prg_1a2b3c4d",
    "user_id": "usr_555",
    "purpose_id": "prp_marketing_01",
    "app_id": "app_crm",
    "trigger_event": "CONSENT_REVOKED",
    "status": "PURGE_INITIATED"
  }
}
```

### Example: `purge_request_status_updated`

```json
{
  "event_type": "purge_request_status_updated",
  "fiduciary_id": "8f2c1a90-1234-4a11-9e00-abcdef123456",
  "timestamp": "2026-08-15T09:20:11.001Z",
  "data": {
    "id": "prg_1a2b3c4d",
    "status": "PURGE_COMPLETED",
    "details": "Purged across 3 downstream systems.",
    "user_id": "usr_555"
  }
}
```

### Example: `principal_otp_requested`

```json
{
  "event_type": "principal_otp_requested",
  "fiduciary_id": "8f2c1a90-1234-4a11-9e00-abcdef123456",
  "timestamp": "2026-08-15T09:25:44.221Z",
  "data": {
    "user_id": "usr_555",
    "otp_mode": "EMAIL_OTP",
    "message": "Your verification code is 483920"
  }
}
```

Treat this payload as sensitive: it carries the OTP itself. Your endpoint
must be HTTPS (enforced, see §5) and should not log the raw body.

## 4. Security & Verification

Every webhook is signed with HMAC-SHA256 so you can verify it genuinely came
from TSI DPDP CMS.

**Algorithm:**

1. Take the **exact raw JSON body** as sent on the wire.
2. Compute `HMAC-SHA256(body, secret)` using your configured signing secret.
3. Hex-encode the digest (lowercase).
4. Compare against the value after `sha256=` in the `X-TSI-Signature` header.

Unlike some webhook systems, the signed string is **just the raw body**:
there is no `timestamp + "." + body` concatenation, and the header carries no
separate signature-version scheme beyond the `sha256=` prefix.

### Node.js example

```js
const crypto = require('crypto');

// You MUST verify against the raw request bytes, not a re-serialized
// object, so use an express.raw() / raw-body middleware on this route so
// req.body is a Buffer, not a parsed object (JSON.stringify(parsedObject)
// is not guaranteed to match the original byte-for-byte).
function verifyWebhook(rawBody, signatureHeader, secret) {
  const [scheme, hash] = signatureHeader.split('=');
  if (scheme !== 'sha256' || !hash) return false;

  const expected = crypto
    .createHmac('sha256', secret)
    .update(rawBody) // Buffer of the raw request body
    .digest('hex');

  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(expected));
}
```

### Secret management

- The secret is a plaintext value **you choose** when configuring the
  webhook; it is not generated by the system.
- It is stored encrypted server-side and is **never shown back** to you
  after saving; the settings UI only reports whether a secret is configured.
- Leaving the secret field blank on a later save keeps the existing secret
  unchanged. A secret is required the first time you enable a category.
- If you need to rotate a secret, save a new one. There is no dual-secret
  grace period, so plan for a brief cutover.

## 5. Endpoint Requirements

Your webhook URL must be **HTTPS**. Non-HTTPS URLs are rejected at
configuration time.

To prevent SSRF, the CMS also resolves your hostname and rejects it, both
when you save the config and again at every delivery (to defend against
DNS-rebinding), if any resolved address is loopback, link-local (this
blocks cloud metadata endpoints like `169.254.169.254`), private/site-local,
multicast, or any-local. Point your webhook at a publicly resolvable HTTPS
endpoint.

## 6. Setting Up a Webhook

1. Go to **DPO Console → Settings → Webhooks**.
2. Pick the card for the category you want: **Notification Webhook** or
   **Purge Webhook**. (The OTP delivery webhook is configured separately,
   under **Rights Management App**, and only applies when OTP mode is Email
   or Mobile.)
3. Enter your **Webhook URL** (must be HTTPS).
4. Enter a **Secret**.
5. Click **Save**, then **Activate**.

Only a DPO (not an Operator) can configure webhooks, and each fiduciary can
only configure webhooks for its own account.

## 7. Delivery Behavior

- Delivery is asynchronous and fire-and-forget: it never blocks or fails
  the business operation that triggered the event.
- Connect timeout: 5s. Overall request timeout: 10s.
- **No automatic retries.** A failed delivery is logged as a
  `WEBHOOK_DELIVERY_FAILED` audit event (visible in the DPO Console's Audit
  log) with the category, event type, and failure reason, but the event is
  not redelivered.
- Because there's no retry, treat the corresponding polling APIs as your
  reconciliation path: if your endpoint is down for a period, use
  `list_notifications` / the purge-list API to catch up, rather than relying
  solely on webhooks for correctness. See the
  [Client Polling Integration Guide](polling-integration-guide.md) for how
  to consume those APIs directly.

## 8. Testing

1. Create a temporary endpoint (e.g. on [Webhook.site](https://webhook.site))
   during development.
2. Register it as a webhook in DPO Console → Settings, using a test secret.
   Remember it must be HTTPS and publicly resolvable; a local
   `http://localhost` or private-network URL will be rejected.
3. Trigger an event, e.g. revoke a consent, or submit a purge/erasure
   request from the Principal Portal.
4. Inspect the delivered payload and the `X-TSI-Signature` header, and
   verify the signature locally using the secret you configured.
