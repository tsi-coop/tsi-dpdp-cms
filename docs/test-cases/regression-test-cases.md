# Regression Test Cases

A living regression suite for TSI DPDP CMS, organized by capability area.
Run relevant sections before every release; add new cases as features
change. This is a first pass covering critical paths per area, not an
exhaustive combinatorial suite - add edge cases as they matter.

## How to use this document

- **Type** - `API`: executable directly against the running instance (curl
  or the JMeter suite in `tests/`), no browser needed. `UI`: requires a
  console/portal walkthrough; no browser-automation tooling exists in this
  repo yet, so these are manual today.
- **Priority** - `Critical` (release-blocking if broken), `High`, `Medium`.
- **Last Verified** - `version · date · pass/fail`. Update this field, not
  the test case itself, each time you run it. A blank field means never
  run. A case that hasn't been touched in several releases is a signal to
  re-check it, not assume it still passes.
- Test cases reference the exact `_func` / endpoint / console page so
  they can be executed without re-deriving what to click or call.
- Cross-references to `docs/api/openapi.yaml` (client API contract),
  `tests/load-testing-plan.md` (load/concurrency), and the six items in
  the standards work (`RELEASE_NOTES.md` v0.5.2) are called out inline
  rather than duplicated.

## Table of Contents

1. [Bootstrap & Initial Setup](#1-bootstrap--initial-setup)
2. [Admin Console](#2-admin-console)
3. [DPO Console](#3-dpo-console)
4. [Data Principal Rights Portal](#4-data-principal-rights-portal)
5. [Client API](#5-client-api)
6. [Public API](#6-public-api)
7. [Webhooks](#7-webhooks)
8. [Purge Lifecycle (End-to-End)](#8-purge-lifecycle-end-to-end)
9. [Cross-Cutting / Non-Functional](#9-cross-cutting--non-functional)

---

## 1. Bootstrap & Initial Setup

### TC-BOOT-01: First-run setup succeeds with a valid token
**Type:** API · **Priority:** Critical
**Preconditions:** Fresh deployment, `TSI_BOOTSTRAP_TOKEN` set, no admin exists yet.
**Steps:** `POST /api/v1/bootstrap/setup` with `_func: initial_setup`, correct `setup_token`, `email`, `name`, `password` (≥12 chars).
**Expected Result:** `201`, `{success:true, data:{user_id, role:"ADMIN"}}`. A Super Administrator now exists.
**Last Verified:**

### TC-BOOT-02: Setup rejected with missing/wrong token
**Type:** API · **Priority:** Critical
**Steps:** Call `initial_setup` with an incorrect or missing `setup_token`.
**Expected Result:** `401 Unauthorized`, `"Invalid or missing setup token."` - checked *before* any DB access, so no information about system state leaks.
**Last Verified:** v0.5.2 · 2026-09-28 · pass

### TC-BOOT-03: Setup disabled when `TSI_BOOTSTRAP_TOKEN` unset
**Type:** API · **Priority:** Critical
**Preconditions:** Deployment with the env var unset.
**Steps:** Call `initial_setup` with any payload.
**Expected Result:** `503 Setup Disabled` - fails closed, matching `JWT_SECRET`/`DB_ENCRYPTION_KEY`'s fail-fast pattern.
**Last Verified:**

### TC-BOOT-04: Setup permanently disabled once an admin exists
**Type:** API · **Priority:** Critical
**Preconditions:** An admin already exists (from TC-BOOT-01).
**Steps:** Call `initial_setup` again with a valid token and a *different* email/name/password.
**Expected Result:** `409 Conflict`, `"System is already configured..."`. Concurrent double-submission (two simultaneous requests on an empty table) must not create two admins - `SERIALIZABLE` isolation should abort the loser with SQLState `40001`, surfaced as the same 409.
**Last Verified:** v0.5.2 · 2026-09-28 · pass (tested with the real setup token; admin already existed on this instance, giving the 409 path directly)

### TC-BOOT-05: Setup rate-limited per source IP
**Type:** API · **Priority:** High
**Steps:** Send 6 rapid `initial_setup` calls from the same IP (any payload shape).
**Expected Result:** The 6th call returns `429 Too Many Requests` (default limiter: 5/15min, key `"setup:" + ip`).
**Caution:** don't run this against an instance where you still need to complete a real first-run setup - it shares an apparent source IP with your own subsequent legitimate attempt for 15 minutes.
**Last Verified:** v0.5.2 · 2026-09-28 · pass (verified code path reachable with 1 call; full 6-call exhaustion deliberately not run against a real deployment - see session notes)

---

## 2. Admin Console

### 2.1 Authentication & Session

### TC-ADM-01: Admin login success
**Type:** UI · **Priority:** Critical
**Steps:** Navigate to `/console/`, log in with valid ADMIN credentials.
**Expected Result:** Redirected to admin dashboard; session cookie set (`HttpOnly`, `SameSite=Strict`, `Secure` outside `local` env).
**Last Verified:**

### TC-ADM-02: Admin login rate-limited after failed attempts
**Type:** API · **Priority:** High
**Steps:** POST to the operator login function 6 times with a wrong password, same IP.
**Expected Result:** 6th attempt returns `429` (5/15min limiter, pre-existing, unrelated to this release's OTP rate-limiting work).
**Last Verified:** v0.5.2 · 2026-09-28 · pass

### TC-ADM-03: Console pages require a server-side session, not just client JS
**Type:** API · **Priority:** Critical
**Steps:** `curl` any `/console/admin/*.html` or `/console/dpo/*.html` page directly, no session cookie.
**Expected Result:** `302` redirect to login, not `200` with page content. (Regression check for the v0.5.1 fix - [`docs/security-fixes/1.md`](../security-fixes/1.md), [`3.md`](../security-fixes/3.md).)
**Last Verified:** v0.5.2 · 2026-09-28 · pass

### TC-ADM-04: Logout clears the session
**Type:** UI · **Priority:** Medium
**Steps:** Log in, click Logout, then try to reload a console page directly (e.g. via back button or bookmark).
**Expected Result:** Redirected to login; the cleared cookie (`Max-Age=0`) is not accepted.
**Last Verified:**

### TC-ADM-05: Password recovery via Master Recovery Key
**Type:** UI · **Priority:** High
**Steps:** Use the "break-glass" recovery flow with a valid Master Recovery Key to reset an admin password.
**Expected Result:** Password reset succeeds; recovery key is single-use (rejected on reuse).
**Last Verified:**

### 2.2 Fiduciary Management

### TC-ADM-06: Create a Fiduciary
**Type:** UI · **Priority:** Critical
**Steps:** Admin Console → Fiduciaries → create new, save.
**Expected Result:** Fiduciary appears in the list with a UUID; becomes selectable in App/API Key creation.
**Last Verified:**

### TC-ADM-07: Deactivated Fiduciary drops out of public listing
**Type:** API · **Priority:** High
**Steps:** Deactivate a Fiduciary in console; call public `list_active_fiduciaries`.
**Expected Result:** Deactivated Fiduciary no longer appears; existing principal logins for it are rejected ("Fiduciary not found or inactive.").
**Last Verified:** v0.5.2 · 2026-09-28 · pass (created a throwaway test Fiduciary via `create_fiduciary`, confirmed listed, deactivated via `update_fiduciary` status=INACTIVE, confirmed excluded and login rejected; fixture fully deleted afterward)

### TC-ADM-08: Verify DNS domain validation
**Type:** UI · **Priority:** Medium
**Steps:** On a Fiduciary with validation pending, click "Verify DNS".
**Expected Result:** Live TXT lookup runs; status becomes `VALIDATED`/`FAILED`/stays `PENDING`. Confirm this does **not** gate activation, API key issuance, or consent/erasure traffic - purely informational (per v0.5.0 release notes).
**Last Verified:**

### 2.3 App & API Key Management

### TC-ADM-09: Create an App under a Fiduciary
**Type:** UI · **Priority:** Critical
**Steps:** Admin Console → Apps → create under a chosen Fiduciary.
**Expected Result:** App created, selectable for API Key generation.
**Last Verified:**

### TC-ADM-10: Generate an API Key with specific scopes
**Type:** UI · **Priority:** Critical
**Steps:** Apps → API Keys → generate for an App, select a subset of `READ`/`WRITE`/`PURGE`.
**Expected Result:** Key + secret shown exactly once. Confirm the secret cannot be retrieved again (reload the page - it should show "configured", not the raw value).
**Last Verified:**

### TC-ADM-11: API key scope enforcement
**Type:** API · **Priority:** Critical
**Steps:** Using a `READ`-only key, call a `WRITE`-scoped function (e.g. `record_consent`).
**Expected Result:** `401 Unauthorized` - insufficient scope. Cross-reference [`docs/api/openapi.yaml`](../api/openapi.yaml)'s `x-tsi-scope` per function.
**Last Verified:** v0.5.2 · 2026-09-28 · pass (READ-only key: READ call succeeded 200, WRITE and PURGE calls both cleanly rejected 401)

### TC-ADM-12: Revoke an API Key
**Type:** UI · **Priority:** High
**Steps:** Revoke a key in console; immediately call any client function with it.
**Expected Result:** `401`, `"Invalid or inactive API Key/Secret."` Confirm the 60s in-memory permissions cache (`InputProcessor.permissionsMap`) doesn't let a revoked key keep working past that window.
**Last Verified:**

### TC-ADM-13: Malformed (non-UUID) API key fails cleanly, not with a 500
**Type:** API · **Priority:** Critical
**Steps:** Call any client function with `X-API-Key: not-a-uuid`.
**Expected Result:** `401`, single JSON error object. **Regression case for a v0.5.2 bug fix** - previously crashed to `500 Internal Server Error` leaking an exception message.
**Last Verified:** v0.5.2 · 2026-09-28 · pass

### TC-ADM-14: Invalid API key returns exactly one JSON error object
**Type:** API · **Priority:** Critical
**Steps:** Call any client function with a well-formed-but-nonexistent key, and again with no `X-API-Key`/`X-API-Secret` headers at all.
**Expected Result:** Both cases return a single, valid JSON object (not two concatenated objects). **Regression case for a v0.5.2 bug fix.**
**Last Verified:** v0.5.2 · 2026-09-28 · pass

### 2.4 CMS Users / Operators

### TC-ADM-15: Create an operator/DPO console user
**Type:** UI · **Priority:** High
**Steps:** Admin Console → Users → create, assign role (`ADMIN`/`DPO`/`OPERATOR`).
**Expected Result:** New user can log in with the assigned role's permissions.
**Last Verified:**

### TC-ADM-16: Deactivate a user
**Type:** UI · **Priority:** Medium
**Steps:** Deactivate a user; attempt login with their credentials.
**Expected Result:** Login rejected.
**Last Verified:**

### 2.5 White-Labeling

### TC-ADM-17: `BRAND_NAME` rebrands console, rights portal, tour, report footers
**Type:** UI · **Priority:** Medium
**Steps:** Set `BRAND_NAME` (≤12 chars) at deploy time; load each surface.
**Expected Result:** Brand name replaced consistently everywhere; layouts (sidebar, title bar, report footer) don't overflow.
**Last Verified:**

### TC-ADM-18: `BRAND_NAME` over 12 characters fails fast at startup
**Type:** API · **Priority:** Medium
**Steps:** Set `BRAND_NAME` to a 13+ character value; start the app.
**Expected Result:** Application refuses to start with a clear error, same pattern as `JWT_SECRET`/`DB_ENCRYPTION_KEY`.
**Last Verified:**

---

## 3. DPO Console

### 3.1 RoPA & Policy Authoring

### TC-DPO-01: Create a RoPA entry
**Type:** UI · **Priority:** High
**Steps:** DPO Console → RoPA → create entry for a processing activity.
**Expected Result:** Entry saved, selectable when validating policy completeness.
**Last Verified:**

### TC-DPO-02: Compile and validate a multilingual JSON policy
**Type:** UI · **Priority:** Critical
**Steps:** Paste/upload a policy JSON (see `examples/policy/*/`) via the policy editor.
**Expected Result:** Saved as `DRAFT`. Validation catches an unmapped data category / missing purpose field.
**Last Verified:**

### TC-DPO-03: Publish a policy (DRAFT → UNDER_REVIEW → ACTIVE)
**Type:** UI · **Priority:** Critical
**Steps:**
1. Publish a DRAFT policy. Confirm it lands in `UNDER_REVIEW`, not `ACTIVE` - by design, this is a deliberate gate, not a bug: a policy cannot go live until it's been reviewed.
2. Complete RoPA review/approval for every RoPA entry linked to that `policy_id`.
**Expected Result:** After step 1, the policy is `UNDER_REVIEW` and does **not** yet appear via `get_active_policy`/`list_active_policies`. Only after step 2 (every linked RoPA entry reaches `active`/`retired`) does it flip to `ACTIVE` and become visible. (Confirmed as intentional product behavior, not an API-only artifact - `Policy.publishPolicyInDb` sets `UNDER_REVIEW`; `Ropa.activatePolicyIfComplete` is the actual activation trigger.)
**Last Verified:** v0.5.2 · 2026-09-28 · confirmed as designed (product owner confirmed the review gate is intentional; the two-stage transition itself was verified live at the API level under TC-DPO-04, this UI walkthrough of the actual RoPA review screen is still open)

### TC-DPO-04: Cannot have two ACTIVE versions of the same policy simultaneously
**Type:** API · **Priority:** Critical
**Steps:** With a policy already `ACTIVE`, attempt to publish a second version of the same `policy_id`.
**Expected Result:** Rejected with a conflict error; the prior active version must be retired first.
**Last Verified:** v0.5.2 · 2026-09-28 · pass (tested with a throwaway policy: published v1 to `UNDER_REVIEW`, created v2 with an overlapping purpose ID, attempted to publish v2 -> `409 Conflict`, "Publication Conflict: ... already defined in other active policies". Conflict check scans both `ACTIVE` and `UNDER_REVIEW` policies, so the protection holds even before a policy reaches full `ACTIVE` status. Fixture fully deleted afterward.)

### TC-DPO-05: A Fiduciary can run multiple concurrently-active policies
**Type:** UI · **Priority:** High
**Steps:** Publish an ACTIVE customer policy and an ACTIVE employee policy for the same Fiduciary.
**Expected Result:** Both active simultaneously; `list_active_policies` returns both; rights portal persona selection scopes correctly to each.
**Last Verified:**

### 3.2 Breach Notification

### TC-DPO-06: Report a breach
**Type:** UI · **Priority:** Critical
**Steps:** DPO Console → Breach → Report Breach, select affected purpose(s) grouped by active policy.
**Expected Result:** Breach record created; affected-principal resolution scoped to the selected policy only (not cross-policy).
**Last Verified:**

### TC-DPO-07: Notify affected principals and generate the PDF record
**Type:** UI · **Priority:** High
**Steps:** From a reported breach, trigger notification + generate PDF.
**Expected Result:** `BREACH_NOTIFICATION` created per affected principal; PDF download succeeds and contains the breach details.
**Last Verified:**

### TC-DPO-08: Bulk-notify via CSV upload through the Job Manager
**Type:** UI · **Priority:** Medium
**Steps:** Upload a CSV of affected principal IDs for a breach.
**Expected Result:** Job Manager processes the batch; notifications created for each listed principal.
**Last Verified:**

### 3.3 Grievance Management

### TC-DPO-09: Grievance appears in DPO queue on submission
**Type:** UI · **Priority:** Critical
**Steps:** Submit a grievance from the rights portal (see TC-RTS-09); check DPO Console → Grievances.
**Expected Result:** New grievance visible, `status: NEW`, correct SLA `due_date` (30 days default, 7 days if `type=ERASURE_REQUEST`).
**Last Verified:**

### TC-DPO-10: Assign and resolve a grievance within SLA
**Type:** UI · **Priority:** High
**Steps:** Assign to a DPO user; resolve with resolution details before `due_date`.
**Expected Result:** Status `RESOLVED`; `GRIEVANCE_RESOLVED_NOTIFICATION` fires to the principal.
**Last Verified:**

### TC-DPO-11: Grievance escalation past due date
**Type:** UI · **Priority:** Medium
**Steps:** Let a grievance pass its `due_date` unresolved.
**Expected Result:** Status/flag reflects escalation; `GRIEVANCE_ESCALATED_NOTIFICATION` fires.
**Last Verified:**

### 3.4 Legal / Audit Evidence

### TC-DPO-12: Generate BSA Section 63 court-ready evidence export
**Type:** UI · **Priority:** Medium
**Steps:** Legal module → generate evidence export for a date range / event.
**Expected Result:** Export produced with the certification metadata the guide describes; matches audit log entries for that period.
**Last Verified:**

### TC-DPO-13: Audit log entries are immutable
**Type:** UI · **Priority:** High
**Steps:** Attempt to view/edit an existing audit log entry through any console path.
**Expected Result:** No edit/delete affordance exists anywhere in the UI or API for audit rows.
**Last Verified:**

### 3.5 Job Manager

### TC-DPO-14: Consent Expiry Service (CES) nightly batch creates purge requests
**Type:** API · **Priority:** Critical
**Preconditions:** A principal has called `erasure_request` (see TC-CLI-14) more than 24h ago (or trigger the job manually if supported).
**Steps:** Check `purge_requests` / `list_purge_requests` after the batch window.
**Expected Result:** One purge request per purpose the principal had consented to; an App that called `validate_consent` for that purpose is linked (`app_id` set); a purpose no App validated still gets a request recorded with `app_id: null` (orphan).
**Last Verified:** v0.5.2 · 2026-09-28 · pass (confirmed via existing data, not a live-triggered run: 4 real purge_requests already present, one per purpose a prior erasure_request covered, all correctly orphaned since no App had validated those purposes)

### TC-DPO-15: Export job (CONSENT / PRINCIPAL / GRIEVANCE / AUDIT)
**Type:** UI · **Priority:** Medium
**Steps:** Trigger each export subtype with a date range via Job Manager.
**Expected Result:** Job transitions `PENDING → RUNNING → COMPLETED`; `output_file_path` populated; file downloadable and contains the expected rows.
**Last Verified:**

### 3.6 Webhook & Notification Configuration

### TC-DPO-16: Configure and activate a Notification webhook
**Type:** UI · **Priority:** High
**Steps:** Settings → Webhooks → Notification card, set an HTTPS URL + secret, Save, Activate.
**Expected Result:** Saved; a subsequent `notification_created` event delivers to the URL, signed per [Webhook Integration Guide](../guides/webhook-integration-guide.md) §4.
**Last Verified:**

### TC-DPO-17: Non-HTTPS or private/loopback webhook URL rejected
**Type:** UI · **Priority:** High
**Steps:** Attempt to save `http://...` or a URL resolving to `169.254.169.254` / loopback / private range.
**Expected Result:** Rejected at save time (and would be re-checked at delivery time for DNS-rebinding, per the guide §5).
**Last Verified:**

### TC-DPO-18: Webhook delivery failure doesn't block the business operation
**Type:** API · **Priority:** High
**Steps:** Configure a webhook pointed at an unreachable endpoint; trigger a notification event.
**Expected Result:** The triggering operation (e.g. consent record) still succeeds; `WEBHOOK_DELIVERY_FAILED` audit event logged; no retry attempted.
**Last Verified:** v0.5.2 · 2026-09-28 · pass (configured a NOTIFICATION webhook on a throwaway Fiduciary pointed at a URL guaranteed to fail; `record_consent` still returned `201`; `audit_logs` confirmed a `WEBHOOK_DELIVERY_FAILED` row with the failure reason. Fixture fully deleted afterward.)

### 3.7 Rights Management App Config / OTP Mode

### TC-DPO-19: Switch OTP delivery mode (Dummy / Email / Mobile)
**Type:** UI · **Priority:** High
**Steps:** Settings → Rights Management App, change OTP mode.
**Expected Result:** Rights portal login behavior changes accordingly (fixed `1234` vs. real dispatched code); `principal_otp_requested` webhook fires only in Email/Mobile mode.
**Last Verified:**

---

## 4. Data Principal Rights Portal

### TC-RTS-01: Login with Dummy OTP
**Type:** UI · **Priority:** Critical
**Steps:** `/rights/index.html`, select org, enter any ID, OTP `1234`.
**Expected Result:** Redirected to dashboard; session token stored in `sessionStorage`.
**Last Verified:** v0.5.2 · 2026-09-28 · pass (via API equivalent, `principal_login`)

### TC-RTS-02: Full Email/Mobile OTP round trip
**Type:** UI · **Priority:** Critical
**Preconditions:** Fiduciary's Rights App OTP mode set to Email or Mobile.
**Steps:** Request OTP, receive via configured channel/webhook, submit within 5 minutes.
**Expected Result:** Login succeeds; OTP is single-use (resubmitting the same code fails).
**Last Verified:**

### TC-RTS-03: Persona selection before credentials
**Type:** UI · **Priority:** Medium
**Steps:** Select an organisation with multiple `data_subject_categories`; confirm persona pills appear before the credentials form.
**Expected Result:** Selected persona scopes which policy is pre-selected post-login (but all policies remain viewable).
**Last Verified:**

### TC-RTS-04: Manage Consent - toggle and save preferences
**Type:** UI · **Priority:** Critical
**Steps:** Toggle optional purposes, leave mandatory ones (disabled), Save.
**Expected Result:** Success banner shown (and screen-reader announced via `aria-live` - see TC-RTS-11); `record_consent` call succeeds; reload reflects saved state.
**Last Verified:**

### TC-RTS-05: Consent History - view record details
**Type:** UI · **Priority:** High
**Steps:** History tab → click "Details" on a record.
**Expected Result:** Modal opens with per-purpose grant/deny and compliance context (policy version, mechanism, timestamp).
**Last Verified:**

### TC-RTS-06: Withdraw consent (full and partial)
**Type:** UI · **Priority:** Critical
**Steps:** Open Withdraw modal; (a) deselect all → full withdrawal, (b) deselect only some purposes → partial.
**Expected Result:** (a) all purposes marked withdrawn; (b) only selected purposes withdrawn, others remain active. Warning shown about mandatory-purpose withdrawal restricting service access.
**Last Verified:**

### TC-RTS-07: Submit an erasure request
**Type:** UI · **Priority:** Critical
**Steps:** History tab → Erasure Request → confirm.
**Expected Result:** Confirmation dialog warns it's irreversible; consent record marked accordingly; no immediate purge (see [§8](#8-purge-lifecycle-end-to-end)).
**Last Verified:**

### TC-RTS-08: Self-verify consent for a purpose
**Type:** UI · **Priority:** Medium
**Steps:** History tab → Verify My Consent, pick a purpose, Check Status.
**Expected Result:** Shows granted/not-granted matching actual state.
**Last Verified:**

### TC-RTS-09: Submit a grievance from the portal
**Type:** UI · **Priority:** High
**Steps:** Grievances tab → New Request, fill subject/description, submit.
**Expected Result:** Appears in principal's own list; also appears in DPO queue (TC-DPO-09).
**Last Verified:**

### TC-RTS-10: Download / QR the Portable Consent Artifact (PCA)
**Type:** UI · **Priority:** Medium
**Steps:** Toggle PCA QR popover; download the JSON artifact.
**Expected Result:** QR renders; downloaded JSON contains `sync_token`, `policy_ref`, `consents`.
**Last Verified:**

### TC-RTS-11: Accessibility - keyboard and screen reader
**Type:** UI · **Priority:** Critical
**Steps:** Tab through login + dashboard without a mouse; open/close both modals via Escape and Tab-cycling; run a screen reader through the save/error flows.
**Expected Result:** All interactive elements reachable in logical order; modals trap focus and restore it on close; status changes are announced via `aria-live`. **Full detail:** v0.5.2 accessibility work (RELEASE_NOTES.md).
**Last Verified:** v0.5.2 · 2026-09-28 · pass

### TC-RTS-12: Verifiable parental consent (Section 9)
**Type:** UI · **Priority:** High
**Steps:** Trigger the minor/guardian flow (age category `MINOR`) with guardian OTP identification.
**Expected Result:** `record_parent_consent` logs the verification; consent then recorded against the child's principal ID with `verification_log_id` linked.
**Last Verified:**

---

## 5. Client API

Full request/response contract: [`docs/api/openapi.yaml`](../api/openapi.yaml)
(viewer: `docs/api/index.html`). These cases check behavior, not schema
shape - the OpenAPI spec is the source of truth for the latter.

### 5.1 Policy (`/api/v1/client/policy`)

### TC-CLI-01: `get_active_policy` requires explicit `fiduciary_id`
**Type:** API · **Priority:** High
**Steps:** Call with valid `jurisdiction` but no `fiduciary_id`, authenticated via Principal JWT.
**Expected Result:** `400` - this function never auto-resolves `fiduciary_id`, unlike most of the API.
**Last Verified:** v0.5.2 · 2026-09-28 · pass

### TC-CLI-02: `get_policy` returns raw JSON text; `get_active_policy` returns parsed object
**Type:** API · **Priority:** Medium
**Steps:** Call both for the same policy/version.
**Expected Result:** `get_policy`'s `policy_content` is a string; `get_active_policy`'s is a parsed object. (Real, documented API inconsistency - not a bug to fix, just to keep consistent.)
**Last Verified:** v0.5.2 · 2026-09-28 · pass

### 5.2 Consent (`/api/v1/client/consent`)

### TC-CLI-03: `record_consent` ignores `policy_version`/`timestamp`/`ip_address`/`jurisdiction`
**Type:** API · **Priority:** Medium
**Steps:** Send all four fields with deliberately wrong values; inspect the stored record via `get_active_consent`.
**Expected Result:** Server's own values are used regardless (active policy version, server time, hashed real remote IP, hardcoded `"IN"`). Confirms documented behavior hasn't silently changed.
**Last Verified:** v0.5.2 · 2026-09-28 · pass

### TC-CLI-04: `record_consent` rejects a non-active policy reference
**Type:** API · **Priority:** High
**Steps:** Call with a `policy_id` that exists but isn't `ACTIVE` for the resolved fiduciary.
**Expected Result:** `400`, policy-not-found-or-not-owned message.
**Last Verified:** v0.5.2 · 2026-09-28 · pass

### TC-CLI-05: `withdraw_consent`/`erasure_request` return 200 with `success:false` on business failure
**Type:** API · **Priority:** High
**Steps:** Call `withdraw_consent` for a `user_id` with no consent record at all.
**Expected Result:** HTTP `200`, `{success:false, message:"No consent record found for withdrawal."}` - **not** a 4xx. Confirms callers must check `success`, not status code, for this pair.
**Last Verified:** v0.5.2 · 2026-09-28 · pass

### TC-CLI-06: `withdraw_consent` partial withdrawal via `purpose_ids`
**Type:** API · **Priority:** High
**Steps:** Call with `purpose_ids` naming a subset of granted purposes.
**Expected Result:** Only listed purposes flip to denied; others remain granted.
**Last Verified:** v0.5.2 · 2026-09-28 · pass

### TC-CLI-07: Principal JWT `user_id` mismatch is rejected
**Type:** API · **Priority:** Critical
**Steps:** Authenticate as principal A's JWT; call any `/consent` or `/grievance` function with `user_id` set to principal B.
**Expected Result:** `403`, regardless of which function was requested.
**Last Verified:** v0.5.2 · 2026-09-28 · pass

### TC-CLI-08: `validate_consent` records the validation for later purge targeting
**Type:** API · **Priority:** Critical
**Steps:** Call `validate_consent` for a purpose from a specific App's API key; later trigger CES (TC-DPO-14).
**Expected Result:** That App is linked (`app_id`) on the resulting purge request for that purpose.
**Last Verified:** v0.5.2 · 2026-09-28 · pass (confirmed fully with a real API key: a fresh consent + validate_consent call left a non-null `app_id` in `consent_validations` for the calling App)

### 5.3 Grievance (`/api/v1/client/grievance`)

### TC-CLI-09: `submit_grievance` accepts any `type` string; only `ERASURE_REQUEST` changes SLA
**Type:** API · **Priority:** Medium
**Steps:** Submit with `type: "SOMETHING_MADE_UP"` and separately with `type: "erasure_request"` (lowercase).
**Expected Result:** Both accepted (201); only the erasure-request one (case-insensitive) gets the 7-day SLA instead of 30.
**Last Verified:** v0.5.2 · 2026-09-28 · pass (erasure_request -> 7-day SLA, arbitrary type -> 30-day, confirmed via due_date diff)

### 5.4 Notification (`/api/v1/client/notification`)

### TC-CLI-10: `mark_notification_read` field is `id`, not `instance_id`
**Type:** API · **Priority:** Low
**Steps:** Omit `id`; read the error message.
**Expected Result:** `400`, `"[$: required property 'id' not found]"` - caught by the JSON-Schema pre-check (`web/WEB-INF/validator/mark_notification_read.jschema`), which correctly names `id`. **Correction after running this live:** `Notification.java`'s own service-level check has a bug (its message names `instance_id` instead of `id`), but that code path is unreachable via the real API - the schema pre-check always rejects a missing `id` first. Documented here as dead code, not a live-observable bug.
**Last Verified:** v0.5.2 · 2026-09-28 · pass (schema-layer message correct; service-level `instance_id` bug confirmed unreachable)

### TC-CLI-11: `list_notifications` from a Principal JWT without body `fiduciary_id`
**Type:** API · **Priority:** Medium
**Steps:** Authenticate via Principal JWT only (no API key), call `list_notifications` with no `fiduciary_id` in body.
**Expected Result:** **Known bug**, confirmed live: `500`, `"Cannot invoke \"String.length()\" because \"name\" is null"` - a `NullPointerException` inside the fiduciary-resolution fallback, not a clean `400`. (Earlier source-only analysis had guessed an unguarded `UUID.fromString(null)` as the cause; the actual live error is this NPE instead - source hypotheses need runtime confirmation, not just a read-through.) Tracked here until fixed; re-verify after any fix lands.
**Last Verified:** v0.5.2 · 2026-09-28 · bug confirmed live (500, as expected - not a passing case, a tracked known issue)

### 5.5 Compliance / Purge (`/api/v1/client/compliance`)

### TC-CLI-12: PURGE scope blocked over Principal JWT
**Type:** API · **Priority:** Critical
**Steps:** Authenticate via Principal JWT; call `list_purge_requests` or `update_purge_status`.
**Expected Result:** `403` - PURGE functions are API-key-only, unconditionally.
**Last Verified:** v0.5.2 · 2026-09-28 · pass

### TC-CLI-13: `update_purge_status` doesn't check request ownership
**Type:** API · **Priority:** High
**Steps:** Using Fiduciary A's API key (PURGE scope), call `update_purge_status` with an `id` belonging to Fiduciary B.
**Expected Result:** **Known, accepted gap** (documented in the System Integration Guide) - the update succeeds regardless of fiduciary ownership. This case exists to confirm it's still true, not to flag it as new.
**Last Verified:** v0.5.2 · 2026-09-28 · pass (update succeeded on an orphaned request; the cross-fiduciary-ownership half of this case needs a second Fiduciary's purge request, not available on this single-tenant test instance - not yet fully verified)

### TC-CLI-14: `list_purge_requests` includes orphaned requests
**Type:** API · **Priority:** Medium
**Steps:** Call `list_purge_requests` where at least one request has `app_id: null`.
**Expected Result:** Orphaned requests appear alongside the calling App's own, with `app_name: "No Linked Processor"`.
**Last Verified:** v0.5.2 · 2026-09-28 · pass
---

## 6. Public API

### TC-PUB-01: `list_active_fiduciaries` returns only active ones
**Type:** API · **Priority:** Medium
**Steps:** Call with no auth required.
**Expected Result:** Deactivated Fiduciaries excluded (cross-reference TC-ADM-07).
**Last Verified:** v0.5.2 · 2026-09-28 · pass (only one active Fiduciary exists on this instance, so the exclusion half of this case is unverified - only confirmed the endpoint returns active ones correctly)

### TC-PUB-02: `request_principal_otp` rate-limited per target (3/hour) and per IP (20/15min)
**Type:** API · **Priority:** Critical
**Steps:** Call 4 times for the same `fiduciary_id`+`user_id`.
**Expected Result:** 4th call returns `429`. **v0.5.2 fix, verified live.**
**Last Verified:** v0.5.2 · 2026-09-28 · pass

### TC-PUB-03: `principal_login` rate-limited per target (5/15min) and per IP (20/15min)
**Type:** API · **Priority:** Critical
**Steps:** Call 6 times for the same `fiduciary_id`+`user_id`+any OTP.
**Expected Result:** 6th call returns `429`. **v0.5.2 fix, verified live** - this closes the OTP brute-force path (the more severe half of the original rate-limiting gap, since `principal_login` is the actual verification step).
**Last Verified:** v0.5.2 · 2026-09-28 · pass

### TC-PUB-04: OTP is single-use and expires after 5 minutes
**Type:** API · **Priority:** High
**Steps:** Request a real OTP (Email/Mobile mode); use it successfully once, then try again; separately, wait >5min and try an unused one.
**Expected Result:** Reuse rejected ("Invalid or expired OTP"); expiry rejected the same way.
**Last Verified:**

---

## 7. Webhooks

Full contract: [Webhook Integration Guide](../guides/webhook-integration-guide.md).

### TC-WHK-01: Signature verification (HMAC-SHA256 over raw body)
**Type:** API · **Priority:** High
**Steps:** Capture a delivered webhook payload + `X-TSI-Signature`; recompute HMAC over the exact raw bytes with the configured secret.
**Expected Result:** Signatures match. Confirm it's the raw body only (no timestamp concatenation).
**Last Verified:**

### TC-WHK-02: All four event/category combinations fire correctly
**Type:** API · **Priority:** High
**Steps:** Trigger one event per row of the guide's §2 table (`notification_created`, `purge_request_created`, `purge_request_status_updated`, `principal_otp_requested`).
**Expected Result:** Each delivers the documented envelope + `data` shape.
**Last Verified:**

### TC-WHK-03: Failed delivery doesn't retry
**Type:** API · **Priority:** Medium
**Steps:** Point a webhook at an endpoint that returns 500; trigger an event; wait; trigger again.
**Expected Result:** Exactly one delivery attempt per event; `WEBHOOK_DELIVERY_FAILED` logged each time, no automatic retry.
**Last Verified:**

---

## 8. Purge Lifecycle (End-to-End)

### TC-PRG-01: Full erasure-to-confirmation round trip
**Type:** API · **Priority:** Critical
**Steps:**
1. Principal calls `erasure_request` (TC-RTS-07 / TC-CLI equivalent).
2. Wait for the nightly CES batch (or trigger manually) - TC-DPO-14.
3. App polls `list_purge_requests` (`status: PURGE_INITIATED`) or receives `purge_request_created` webhook.
4. App purges downstream, calls `update_purge_status` with `PURGE_COMPLETED`.
5. Check `list_notifications` for `PURGE_CONFIRM_NOTIFICATION` to the principal.
**Expected Result:** Every step completes; no step is skipped or short-circuited (erasure_request must **not** create the purge row synchronously - that's a separate, deliberate design point worth re-checking after any refactor).
**Last Verified:** v0.5.2 · 2026-09-28 · pass (steps 1-2 had already happened via prior manual testing; completed steps 3-5 live: update_purge_status -> PURGE_COMPLETED -> PURGE_CONFIRM_NOTIFICATION confirmed)

### TC-PRG-02: Legal hold on a purge request
**Type:** API · **Priority:** Medium
**Steps:** Call `update_purge_status` with `status: LEGAL_HOLD_APPLIED`.
**Expected Result:** Accepted (not server-restricted to DPO-only today - by design, per the guide's caveat); `PURGE_ONHOLD_NOTIFICATION` fires.
**Last Verified:** v0.5.2 · 2026-09-28 · pass (LEGAL_HOLD_APPLIED accepted, PURGE_ONHOLD_NOTIFICATION confirmed)
---

## 9. Cross-Cutting / Non-Functional

### TC-XCUT-01: Security headers present on every response
**Type:** API · **Priority:** Medium
**Steps:** Inspect headers on any `/api/*` response.
**Expected Result:** `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Permissions-Policy` all present.
**Last Verified:** v0.5.2 · 2026-09-28 · pass

### TC-XCUT-02: CORS origin enforcement
**Type:** API · **Priority:** Medium
**Steps:** With `ALLOWED_ORIGINS` set, send an admin-category request with a disallowed `Origin` header.
**Expected Result:** `403 Forbidden`. Client-API calls (server-to-server, typically no `Origin`) are not subject to this check.
**Last Verified:** v0.5.2 · 2026-09-28 · pass

### TC-XCUT-04: OpenAPI spec validates and stays in sync with source
**Type:** API · **Priority:** Medium
**Steps:** `npx @redocly/cli lint docs/api/openapi.yaml`. Spot-check 2-3 functions' actual behavior against the spec after any service-code change.
**Expected Result:** Lints clean. No undocumented behavior drift.
**Last Verified:** v0.5.2 · 2026-09-28 · pass

### TC-XCUT-05: Build integrity
**Type:** API · **Priority:** Critical
**Steps:** `mvn compile` (or `mvn package` before an actual deploy - `compile` alone does not refresh the WAR used by `docker compose build`).
**Expected Result:** Clean build, no errors.
**Last Verified:** v0.5.2 · 2026-09-28 · pass

### TC-XCUT-06: Ownership/security docs present
**Type:** API · **Priority:** Low
**Steps:** Confirm `CONTRIBUTING.md` and `SECURITY.md` exist at repo root.
**Expected Result:** Present, non-empty.
**Last Verified:** v0.5.2 · 2026-09-28 · pass

### TC-XCUT-07: No unused/unreferenced cloud-vendor dependencies
**Type:** API · **Priority:** Low
**Steps:** `grep -r "software.amazon.awssdk" pom.xml`.
**Expected Result:** No match. Production key management runs only through `DB_ENCRYPTION_KEY`.
**Last Verified:** v0.5.2 · 2026-09-28 · pass

### TC-XCUT-08: Multi-tenant / Aggregator (Consent Manager) mode
**Type:** UI · **Priority:** High
**Steps:** Configure the system in Consent Manager mode per the System Design doc §1.2; onboard two distinct Fiduciaries under it.
**Expected Result:** Each Fiduciary's data (policies, consents, apps) stays isolated; console navigation correctly scopes an operator to their assigned Fiduciary/Fiduciaries.
**Last Verified:**
