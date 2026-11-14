# Webhook Integration Guide

**Document Version:** 1.1
**Applies to:** TSI DPDP CMS v0.4.8+ (SSRF hardening in v0.5.0; delivery retry and tracking in v0.5.4)

---

## 1. Overview

Webhooks let your external systems receive real-time push notifications when
notification, purge, or OTP-delivery events occur in TSI DPDP CMS, instead of
polling the `list_notifications` / purge-list APIs.

Webhook delivery is **at-least-once with automatic retries** (from v0.5.4).
Every `NOTIFICATION` and `PURGE` event is recorded before it is sent. If a
delivery fails (timeout, non-2xx response, DNS failure), the CMS retries it
with increasing delays (see §7); if it still fails after the last attempt it
is marked **Failed**, logged once as a `WEBHOOK_DELIVERY_FAILED` audit event,
and listed under **DPO Console → Compliance → Webhook Deliveries**, where the
DPO can retry it by hand. Because a delivery can be sent more than once,
your endpoint must de-duplicate (see §3). The underlying notification or purge
request row is created regardless of webhook outcome, so **polling remains
the reliable source of truth**: treat webhooks as a low-latency layer on top
of polling, not a replacement for it. (The `OTP` webhook is the exception: it
is sent once and never retried - see §7.)

## Quick start: your first webhook in 6 steps

This gets one webhook working end to end. The sections after it are the full reference.

**Step 1: Write a receiver.** Save this as `receiver.js`. It needs Node 18 or later and no packages.

```js
// receiver.js - minimal TSI DPDP CMS webhook receiver
const http = require('http');
const crypto = require('crypto');

const SECRET = process.env.WEBHOOK_SECRET;          // the secret you will enter in the console
if (!SECRET) throw new Error('Set WEBHOOK_SECRET');
const seen = new Set();                              // use a database or Redis in production

http.createServer((req, res) => {
  if (req.method !== 'POST') { res.writeHead(405).end(); return; }

  const chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', () => {
    const raw = Buffer.concat(chunks);               // the exact bytes that were signed

    // 1. Verify the signature (HMAC-SHA256 of the raw body)
    const [scheme, hash] = (req.headers['x-tsi-signature'] || '').split('=');
    const expected = crypto.createHmac('sha256', SECRET).update(raw).digest('hex');
    const ok = scheme === 'sha256' && hash && hash.length === expected.length &&
               crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(expected));
    if (!ok) { res.writeHead(401).end(); return; }

    // 2. De-duplicate: a retry carries the same delivery_id
    const event = JSON.parse(raw);
    if (seen.has(event.delivery_id)) { res.writeHead(200).end(); return; }
    seen.add(event.delivery_id);

    // 3. Answer 2xx straight away, then do the real work
    res.writeHead(200).end();
    console.log(event.event_type, event.delivery_id, JSON.stringify(event.data));
  });
}).listen(process.env.PORT || 3000, () => console.log('listening'));
```

Run it with a secret of your choice:

```bash
WEBHOOK_SECRET=choose-a-secret node receiver.js
```

The three things it does are the three rules every receiver must follow: **verify the signature on the raw body**, **de-duplicate on `delivery_id`**, and **answer `2xx` quickly** (the CMS waits at most 10 seconds).

**Step 2: Make it reachable over HTTPS.** The CMS only calls public `https://` addresses. It rejects `localhost`, private network addresses and plain `http://`, even when you test locally. Put the receiver behind HTTPS on a public hostname, or for a quick test expose it with a tunnelling tool that gives you an `https://` address.

**Step 3: Register it.** In the DPO console go to **Settings -> Webhooks**, pick **Notification Webhook**, enter your HTTPS URL and the same secret as Step 1, then click **Save** and **Activate**.

**Step 4: Trigger an event.** For example, withdraw a consent from the Rights Portal (or run the consent flow from the [System Integration Guide](system-integration-guide.md)).

**Step 5: Check it arrived.** Your receiver prints a line like `notification_created <delivery_id> {...}`.

**Step 6: Check the CMS agrees.** Open **Compliance -> Webhook Deliveries**. The delivery should show **Delivered**. If it shows **Retrying** or **Failed**, the **Last result** column says why (for example `HTTP 401` means your signature check failed: make sure both sides use the same secret, and that you verify the raw body, not a re-serialised copy).

Everything else (event types, payloads, retry timing, the DPO's Webhook Deliveries view) is in the sections below. Also set up polling as a safety net: see the [Client Polling Integration Guide](polling-integration-guide.md).

---

## 2. Supported Events

Webhooks are configured per **category**. Each category has its own URL and
signing secret, configured independently.

| Category | `event_type` | Fires when |
|---|---|---|
| `NOTIFICATION` | `notification_created` | Any notification is created (consent, withdrawal, erasure, purge, grievance, breach, expiry; see notification types below) |
| `PURGE` | `purge_request_created` | A purge request is created |
| `PURGE` | `purge_request_status_updated` | A purge request's status changes (e.g. completed, cancelled, legal hold applied) |
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
| `X-TSI-Delivery-Id` | The delivery's unique id; identical to `delivery_id` in the body and unchanged across retries |
| `X-TSI-Delivery-Attempt` | `1` for the first send, `2` and up for retries |

There is no separate timestamp header: the timestamp is part of the JSON
envelope. **De-duplicate on `delivery_id`**: a retry re-sends the identical
body (same `delivery_id`, same `timestamp`), so a delivery your endpoint
already processed - for example because your `2xx` response was lost - can
arrive again.

### Envelope

Every event is wrapped in the same outer shape:

```json
{
  "event_type": "notification_created",
  "delivery_id": "<uuid>",
  "fiduciary_id": "<uuid>",
  "timestamp": "2026-08-15T09:12:03.512Z",
  "data": { }
}
```

`delivery_id` is present on every event from v0.5.4 (the examples below omit it for brevity).

### Example: `notification_created`

```json
{
  "event_type": "notification_created",
  "fiduciary_id": "8f2c1a90-1234-4a11-9e00-abcdef123456",
  "timestamp": "2026-08-15T09:12:03.512Z",
  "data": {
    "id": "ntf_9f8e7d6c",
    "recipient_type": "PRINCIPAL",
    "recipient_id": "c-555",
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
    "user_id": "c-555",
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
    "user_id": "c-555"
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
    "user_id": "c-555",
    "otp_mode": "EMAIL_OTP",
    "message": "Your verification code is 483920"
  }
}
```

The payload carries only the `user_id` your application uses as the principal ID, with no email address or phone number. If you use opaque IDs (recommended), look up the person's email or mobile number in your own system inside your OTP endpoint, then send the code. The CMS never needs to know the contact address.

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

- Delivery is asynchronous: it never blocks or fails the business operation
  that triggered the event.
- Connect timeout: 5s. Overall request timeout: 10s. Any non-`2xx` response,
  timeout or connection error counts as a failed attempt.
- **Automatic retries.** A failed attempt is retried after 1 minute, 5
  minutes, 30 minutes, 2 hours and 12 hours - up to 6 attempts in all, over
  roughly 14.5 hours. The webhook URL and secret are read afresh on every
  attempt, so fixing a misconfigured URL or rotating the secret applies to
  deliveries that are still being retried. A retry re-sends the identical
  body with the identical `delivery_id`.
- **When retries run out** the delivery is marked **Failed** and one
  `WEBHOOK_DELIVERY_FAILED` audit event is written (visible in the DPO
  Console's Audit log). Failed deliveries are listed under **Compliance →
  Webhook Deliveries**, with the last error, and can be retried by hand once
  your endpoint is fixed (**Retry** gives it a fresh set of attempts). The list
  shows the newest first, 30 per page (use **Previous** / **Next**), and can be
  filtered to Failed, Retrying, Delivered or All. Failed
  entries are kept for 90 days and delivered entries for 7. If a webhook is
  disabled or removed, deliveries still waiting fail their remaining
  attempts and end up Failed rather than being sent.
- **Ordering is not guaranteed.** A retried event can arrive after a later
  one (for example a `purge_request_status_updated` after the status it
  predates). Use the state in `data` (e.g. the purge request's current
  status via polling) rather than arrival order when it matters.
- **OTP events are never retried or stored.** Their payload contains the
  one-time code, so it is not written to the delivery table, and a code
  delivered minutes late is useless. A failed OTP webhook is logged as
  `WEBHOOK_DELIVERY_FAILED` and the principal can request a new code.
- Polling is still your reconciliation path: if your endpoint is down for
  longer than the retry window, or a delivery ends up Failed, use
  `list_notifications` / the purge-list API to catch up. See the
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
