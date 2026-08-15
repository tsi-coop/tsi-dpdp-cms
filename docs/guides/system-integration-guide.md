# System Integration Guide

**Document Version:** 1.0
**Audience:** Developers at Data Fiduciaries and Data Processors integrating the client-facing API into their own backend stacks.

---

## 1. Overview

This guide covers the client API: the endpoints your backend calls to run notice delivery, capture consent, validate processing authorization in real time, drive a Data Principal's rights dashboard, and track purge fulfillment.

It doesn't cover:

- **Consuming events after the fact** - see the [Webhook Integration Guide](webhook-integration-guide.md) (push) and the [Client Polling Integration Guide](polling-integration-guide.md) (pull) for `list_notifications`/`list_purge_requests` and their event equivalents.
- **Policy authoring and the DPO Console workflow** - see the [Implementation Guide](implementation-guide.md).

## 2. Authentication

Every call below is `POST`, JSON body, with:

```
Content-Type: application/json
X-API-Key: <App's API key, a UUID>
X-API-Secret: <that App's API secret>
```

The key resolves server-side to exactly one App and its fiduciary - you never pass a `fiduciary_id` yourself for most calls (see per-function notes below; the exception is `get_active_policy`, which requires it explicitly). The secret is checked against a hashed value stored server-side; it is never transmitted back to you after the key is created, so store it securely at generation time.

Two things worth knowing about this auth model:

- **It's not the only auth path.** The Data Principal's own self-service rights portal authenticates with a Bearer JWT instead (issued after OTP/login), not an API key/secret. That path can call the same `_func` values, with one exception: **PURGE-scoped functions are blocked over a Principal JWT** - only App API keys can call `list_purge_requests`/`update_purge_status`.
- **Only an ADMIN console user can create or manage API keys**, and each key is granted a specific, per-key set of permission scopes at creation time (see section 3). A key with only `READ` cannot call `record_consent`.

The DPO/Operator Console uses a completely separate Bearer-JWT scheme, unrelated to this API - not covered here.

## 3. Permission Scopes

Every `_func` below requires one of three scopes, enforced on every call against the calling App's key:

| Scope | Functions |
|---|---|
| `WRITE` | `record_consent`, `record_parent_consent`, `link_user`, `withdraw_consent`, `submit_grievance`, `mark_notification_read`, `erasure_request` |
| `READ` | `get_active_consent`, `list_consent_history`, `get_consent_record_details`, `validate_consent`, `get_grievance`, `list_user_grievances`, `get_policy`, `get_active_policy`, `list_notifications`, `list_active_policies` |
| `PURGE` | `list_purge_requests`, `update_purge_status` |

This is enforced today, not aspirational - request only the scopes your integration actually needs when your fiduciary's admin issues your App's key. A processor that only validates consent, for instance, needs `READ` alone.

## 4. Routing

Each resource is one endpoint; which operation runs is chosen by the `_func` field in the JSON body, not the URL path:

| Resource | Endpoint |
|---|---|
| Policy | `POST /api/v1/client/policy` |
| Consent | `POST /api/v1/client/consent` |
| Grievance | `POST /api/v1/client/grievance` |
| Notification | `POST /api/v1/client/notification` |
| Compliance (purge) | `POST /api/v1/client/compliance` |

Always call the base path shown above. Anything appended after it (e.g. `/api/v1/client/consent/validate`) is parsed but discarded by the router - it has no effect on which function runs, and only `_func` in the body decides that. Don't rely on a trailing path segment to route your request.

## 5. Consent Collection

### Get Active Policy

```json
{ "_func": "get_active_policy", "fiduciary_id": "<uuid>", "jurisdiction": "IN" }
```

Both fields are required - this is the one call where you must pass `fiduciary_id` explicitly, since it's how the caller identifies whose policy to fetch. Returns the currently published policy content (multilingual purposes, data categories, etc.) for rendering notice.

### Get a Specific Policy Version

```json
{ "_func": "get_policy", "policy_id": "p4" }
```

For archival/audit view of a specific past version, rather than the live one.

### Record Consent

```json
{
  "_func": "record_consent",
  "user_id": "data_principal_xyz123",
  "policy_id": "p13",
  "policy_version": "",
  "timestamp": "2025-11-30T10:00:00Z",
  "jurisdiction": "IN",
  "language_selected": "en",
  "consent_status_general": "custom",
  "consent_mechanism": "preference_center_save_click",
  "ip_address": "192.168.1.10",
  "user_agent": "Mozilla/5.0 ...",
  "data_point_consents": [
    {
      "data_point_id": "purpose_account_management",
      "consent_granted": true,
      "purpose_agreed_to": "Account Registration & Management",
      "timestamp_updated": "2025-10-07T05:22:25.529Z"
    }
  ]
}
```

Required: `user_id`, `policy_id`, and `data_point_consents` (each entry requires `data_point_id`, `consent_granted`, `purpose_agreed_to`, `timestamp_updated`). Everything else is optional context.

**Gotcha:** whatever you send for `consent_status_general` is ignored - the server always records `CONSENT_GIVEN` for this call. Don't rely on that field to represent a partial/declined state; per-purpose grant/deny lives in `data_point_consents`.

### Link Identity

```json
{
  "_func": "link_user",
  "anonymous_user_id": "data_principal_xyz123",
  "authenticated_user_id": "sat@sat.com"
}
```

Consolidates an anonymous pre-login session's consent history onto the authenticated account ID, once the user logs in.

## 6. Processing & Validation

### Validate Consent

```json
{ "_func": "validate_consent", "user_id": "sat@sat.com", "required_purpose_id": "purpose_marketing_offers" }
```

Lightweight boolean-style check for whether a specific purpose is currently granted - call this from your processor before acting on the data, not just once at collection time. Every successful validation is recorded (`consent_validations` table); this record is what later determines which Apps get notified when that principal's data needs to be purged (see section 8).

## 7. User Rights & Dashboard

### Get Active Consent State

```json
{ "_func": "get_active_consent", "user_id": "sat@sat.com" }
```

Full current consent state for a principal - drives a rights/preference dashboard.

### Withdraw Consent

```json
{ "_func": "withdraw_consent", "user_id": "sat@sat.com", "reason": "" }
```

`reason` is optional. You do not pass `fiduciary_id` - it's resolved from your API key.

### Erasure Request

```json
{ "_func": "erasure_request", "user_id": "sat@sat.com", "reason": "" }
```

Same shape as `withdraw_consent`; only the `_func` value differs, and the server-side handling is what diverges (see section 8 - this is not an immediate purge).

### Grievances

```json
// Submit
{
  "_func": "submit_grievance",
  "user_id": "sat@sat.com",
  "type": "ERASURE_REQUEST",
  "subject": "Request to delete my account data",
  "description": "I would like all my personal data associated with my account to be permanently deleted from your systems as per my right to erasure.",
  "attachments": [],
  "language": "en"
}

// List a user's grievances
{ "_func": "list_user_grievances", "user_id": "sat@sat.com" }

// Get one
{ "_func": "get_grievance", "grievance_id": "fac73135-ab28-43e0-9cf4-5d20053e61f6" }
```

`type`, `subject`, and `description` are required on submit; `attachments` and `language` are optional.

## 8. Erasure Requests and the Purge Lifecycle

`erasure_request` does **not** synchronously create a purge request. It:

1. Deactivates the principal's current consent record and inserts a new one marking the erasure request.
2. Resets an internal flag that queues the principal for the nightly Consent Expiry Service (CES) batch job.

The actual `purge_requests` rows - and the `purge_request_created` webhook, and the entries that show up when you poll `list_purge_requests` - are created later, when that nightly batch runs (up to ~24h later, not immediately). For each purpose the principal had consented to, CES looks up which Apps previously called `validate_consent` for that purpose and creates a purge request targeting each one; a purpose no App ever validated still gets a purge request recorded (with no App attached) so the DPO isn't blind to it, but no App is notified since none is linked.

Design accordingly: don't build an integration that expects `erasure_request` to trigger an immediate downstream purge call. From here, the flow is identical to what's already documented in the [Webhook Integration Guide](webhook-integration-guide.md) and [Client Polling Integration Guide](polling-integration-guide.md) - `PURGE_INITIATED` → your App fetches or receives the request → you purge in your own system → `update_purge_status`.

## 9. Confirming Purge Status

```json
{
  "_func": "update_purge_status",
  "id": "4ab8acb4-1cd6-4234-a981-01ceb23101a5",
  "status": "PURGE_COMPLETED",
  "details": ""
}
```

`id`, `status`, and `details` are all required. Meaningful `status` values (matching what the DPO Console itself offers): `PURGE_IN_PROGRESS`, `PURGE_COMPLETED`, `PURGE_FAILED`, `LEGAL_HOLD_APPLIED`.

**Caveat:** the API does not validate `status` against that list, and does not check that a request belongs to your fiduciary before applying the update. Only ever call this with an `id` your App itself received from `list_purge_requests` or a `purge_request_created` event - never construct or guess an `id`. Reserve `LEGAL_HOLD_APPLIED` for genuine Section 8(1) legal-hold cases; it's not restricted to DPO-only use at the API layer today, so treat it as a status your integration should set deliberately and rarely, not a default.

## 10. Notification & Purge Polling/Webhooks

Once you've called `validate_consent` or `erasure_request`, ongoing notification and purge-request delivery is covered separately - see the [Webhook Integration Guide](webhook-integration-guide.md) for push delivery and the [Client Polling Integration Guide](polling-integration-guide.md) for the reliable polling alternative (`list_notifications`, `mark_notification_read`, `list_purge_requests`).
