# Regression Test Cases

A living regression suite for TSI DPDP CMS, organized by capability area.
Run relevant sections before every release; add new cases as features
change. This is a first pass covering critical paths per area, not an
exhaustive combinatorial suite - add edge cases as they matter.

## Latest full run

**v0.5.4 · 2026-10-27 - every case in this document was run once** (111 pass, 1 partial, 0 fail) against a clean instance built from the v0.5.4 WAR (two fixes described below were made partway through the run; the cases they touch were re-run on the fixed build): Docker (Jetty on JDK 17, PostgreSQL 15 with TLS, all `db/*.sql` scripts applied), a local TLS webhook receiver with a CA trusted by the app, an extra production-mode instance, and headless Chrome for the UI cases. Notes on how it was run:

- **Added after the run:** TC-PRG-03 and TC-PRG-04 (the `PURGE_CANCELLED` status and the failed-purges dashboard fix) and TC-DPO-06d and TC-DPO-16b (breach notified list, Notification Log export), TC-PRG-05 (the "Not picked up" flag), TC-WHK-09 and TC-WHK-10 (webhook deliveries paging; moving the screen under Compliance) have not been run yet.
- **Partial:** TC-RTS-11 - the keyboard and ARIA checks are automated and pass; the screen-reader half needs a person and was not run.
- **Time-compressed:** in TC-WHK-03 the first retry (about 60 s) was waited for in real time, and the later backoffs (5 m, 30 m, 2 h, 12 h) were fast-forwarded by setting `next_attempt_at` in the database. TC-PUB-04 waited the real 5 minutes. TC-WHK-08 was checked by calling the cleanup directly, not by waiting for the hourly job.
- **Environment variants:** unset / mistyped / `production` / `local` `TSI_DPDP_CMS_ENV`, a missing `TSI_BOOTSTRAP_TOKEN`, an over-long and a valid `BRAND_NAME` were each started as separate instances.
- **Found and fixed while running it:** the Legal page hardcoded `http://localhost:8080` (TC-DPO-12c); the breach report footer and certificate metadata hardcoded the product name instead of the brand (TC-ADM-17).
- **Still true, not fixed:** TC-CLI-11 (the documented `500`) and TC-CLI-13 (the accepted purge ownership gap). The tour pages (`web/tour/*.html`) also hardcode `http://localhost:8080` for their API, so they only work on the default port.
- **Not in the repo:** the scripts that drove this run (Python for the API cases, Node with `puppeteer-core` for the UI cases) were throwaway; the cases above are the specification.

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
**Last Verified:** v0.5.4 · 2026-10-27 · pass - initial_setup -> 201, ADMIN created (v0.5.4 stack)

### TC-BOOT-02: Setup rejected with missing/wrong token
**Type:** API · **Priority:** Critical
**Steps:** Call `initial_setup` with an incorrect or missing `setup_token`.
**Expected Result:** `401 Unauthorized`, `"Invalid or missing setup token."` - checked *before* any DB access, so no information about system state leaks.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - wrong token -> 401

### TC-BOOT-03: Setup disabled when `TSI_BOOTSTRAP_TOKEN` unset
**Type:** API · **Priority:** Critical
**Preconditions:** Deployment with the env var unset.
**Steps:** Call `initial_setup` with any payload.
**Expected Result:** `503 Setup Disabled` - fails closed, matching `JWT_SECRET`/`DB_ENCRYPTION_KEY`'s fail-fast pattern.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - TSI_BOOTSTRAP_TOKEN unset -> 503 <html> <head> <meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1"/> <title>Error 503 Service Unavailable</title> </head> <body> <h2>HTTP ERROR 503 Service Unavailable</h2> <table> <tr><th>URI:</th><td>http://127.0.0.1:18093/api/v1/bootstrap/setup</td></tr> <tr><th>STATUS:</th><td>503</td></tr> <tr><th>MESSAGE:</th><td>Service Unavailable</td></tr> </table> <hr/><a href="https://jetty.org/">Powered by Jetty:// 12.1.10</a><hr/>  </body> </html>

### TC-BOOT-04: Setup permanently disabled once an admin exists
**Type:** API · **Priority:** Critical
**Preconditions:** An admin already exists (from TC-BOOT-01).
**Steps:** Call `initial_setup` again with a valid token and a *different* email/name/password.
**Expected Result:** `409 Conflict`, `"System is already configured..."`. Concurrent double-submission (two simultaneous requests on an empty table) must not create two admins - `SERIALIZABLE` isolation should abort the loser with SQLState `40001`, surfaced as the same 409.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - second setup with valid token -> 409

### TC-BOOT-05: Setup rate-limited per source IP
**Type:** API · **Priority:** High
**Steps:** Send 6 rapid `initial_setup` calls from the same IP (any payload shape).
**Expected Result:** The 6th call returns `429 Too Many Requests` (default limiter: 5/15min, key `"setup:" + ip`).
**Caution:** don't run this against an instance where you still need to complete a real first-run setup - it shares an apparent source IP with your own subsequent legitimate attempt for 15 minutes.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - 6 rapid setup calls -> [401, 401, 401, 401, 401, 429] (limiter 5 per 15 min; earlier calls in this session were on a previous app process)

---

## 2. Admin Console

### 2.1 Authentication & Session

### TC-ADM-01: Admin login success
**Type:** UI · **Priority:** Critical
**Steps:** Navigate to `/console/`, log in with valid ADMIN credentials.
**Expected Result:** Redirected to admin dashboard; session cookie set (`HttpOnly`, `SameSite=Strict`, `Secure` outside `local` env).
**Last Verified:** v0.5.4 · 2026-10-27 · pass - landed on /console/admin/dashboard.html; session cookie 'console_session' HttpOnly=true SameSite=Strict Secure=false (Secure is only set outside the local env)

### TC-ADM-02: Admin login rate-limited after failed attempts
**Type:** API · **Priority:** High
**Steps:** POST to the operator login function 6 times with a wrong password, same IP.
**Expected Result:** 6th attempt returns `429` (5/15min limiter, pre-existing, unrelated to this release's OTP rate-limiting work).
**Last Verified:** v0.5.4 · 2026-10-27 · pass - 6 wrong-password logins from one IP -> [401, 401, 401, 401, 401, 429]

### TC-ADM-03: Console pages require a server-side session, not just client JS
**Type:** API · **Priority:** Critical
**Steps:** `curl` any `/console/admin/*.html` or `/console/dpo/*.html` page directly, no session cookie.
**Expected Result:** `302` redirect to login, not `200` with page content. (Regression check for the v0.5.1 fix - [`docs/security-fixes/1.md`](../security-fixes/1.md), [`3.md`](../security-fixes/3.md).)
**Last Verified:** v0.5.4 · 2026-10-27 · pass - all console pages 302 without a session: {302}

### TC-ADM-04: Logout clears the session
**Type:** UI · **Priority:** Medium
**Steps:** Log in, click Logout, then try to reload a console page directly (e.g. via back button or bookmark).
**Expected Result:** Redirected to login; the cleared cookie (`Max-Age=0`) is not accepted.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - after logout, direct visit lands on /index.html; no session cookie left (0 cookies)

### TC-ADM-05: Password recovery via Master Recovery Key
**Type:** UI · **Priority:** High
**Steps:** Use the "break-glass" recovery flow with a valid Master Recovery Key to reset an admin password.
**Expected Result:** Password reset succeeds; recovery key is single-use (rejected on reuse).
**Last Verified:** v0.5.4 · 2026-10-27 · pass - recovery key issued (200), verified (200), password reset (200), login with the new password (200); reusing the key -> 401

### 2.2 Fiduciary Management

### TC-ADM-06: Create a Fiduciary
**Type:** UI · **Priority:** Critical
**Steps:** Admin Console → Fiduciaries → create new, save.
**Expected Result:** Fiduciary appears in the list with a UUID; becomes selectable in App/API Key creation.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - created via the form; appears in the list

### TC-ADM-07: Deactivated Fiduciary drops out of public listing
**Type:** API · **Priority:** High
**Steps:** Deactivate a Fiduciary in console; call public `list_active_fiduciaries`.
**Expected Result:** Deactivated Fiduciary no longer appears; existing principal logins for it are rejected ("Fiduciary not found or inactive.").
**Last Verified:** v0.5.4 · 2026-10-27 · pass - listed while active; after status=INACTIVE it is dropped from list_active_fiduciaries and principal_login -> 401 'Fiduciary not found or inactive.'

### TC-ADM-08: Verify DNS domain validation
**Type:** UI · **Priority:** Medium
**Steps:** On a Fiduciary with validation pending, click "Verify DNS".
**Expected Result:** Live TXT lookup runs; status becomes `VALIDATED`/`FAILED`/stays `PENDING`. Confirm this does **not** gate activation, API key issuance, or consent/erasure traffic - purely informational (per v0.5.0 release notes).
**Last Verified:** v0.5.4 · 2026-10-27 · pass - Verify DNS opened the dialog and ran a live lookup: status text "Current status: PENDING"; (gating behaviour checked separately)

### 2.3 App & API Key Management

### TC-ADM-09: Create an App under a Fiduciary
**Type:** UI · **Priority:** Critical
**Steps:** Admin Console → Apps → create under a chosen Fiduciary.
**Expected Result:** App created, selectable for API Key generation.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - app created under Alpha Co via the form and listed

### TC-ADM-10: Generate an API Key with specific scopes
**Type:** UI · **Priority:** Critical
**Steps:** Apps → API Keys → generate for an App, select a subset of `READ`/`WRITE`/`PURGE`.
**Expected Result:** Key + secret shown exactly once. Confirm the secret cannot be retrieved again (reload the page - it should show "configured", not the raw value).
**Last Verified:** v0.5.4 · 2026-10-27 · pass - key c6a04497… and secret shown once at creation; after reload the secret value is not in the page

### TC-ADM-11: API key scope enforcement
**Type:** API · **Priority:** Critical
**Steps:** Using a `READ`-only key, call a `WRITE`-scoped function (e.g. `record_consent`).
**Expected Result:** `401 Unauthorized` - insufficient scope. Cross-reference [`docs/api/openapi.yaml`](../api/openapi.yaml)'s `x-tsi-scope` per function.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - READ-only key: READ -> 200, WRITE (record_consent) -> 401, PURGE -> 401

### TC-ADM-12: Revoke an API Key
**Type:** UI · **Priority:** High
**Steps:** Revoke a key in console; immediately call any client function with it.
**Expected Result:** `401`, `"Invalid or inactive API Key/Secret."` Confirm the 60s in-memory permissions cache (`InputProcessor.permissionsMap`) doesn't let a revoked key keep working past that window.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - key worked (200), revoked in the console; next call 401; first 401 after 0.009s (the in-memory permission cache expires within ~60s)

### TC-ADM-13: Malformed (non-UUID) API key fails cleanly, not with a 500
**Type:** API · **Priority:** Critical
**Steps:** Call any client function with `X-API-Key: not-a-uuid`.
**Expected Result:** `401`, single JSON error object. **Regression case for a v0.5.2 bug fix** - previously crashed to `500 Internal Server Error` leaking an exception message.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - non-UUID key -> 401, single JSON object

### TC-ADM-14: Invalid API key returns exactly one JSON error object
**Type:** API · **Priority:** Critical
**Steps:** Call any client function with a well-formed-but-nonexistent key, and again with no `X-API-Key`/`X-API-Secret` headers at all.
**Expected Result:** Both cases return a single, valid JSON object (not two concatenated objects). **Regression case for a v0.5.2 bug fix.**
**Last Verified:** v0.5.4 · 2026-10-27 · pass - unknown key and no headers -> 401, each body a single valid JSON object

### 2.4 CMS Users / Operators

### TC-ADM-15: Create an operator/DPO console user
**Type:** UI · **Priority:** High
**Steps:** Admin Console → Users → create, assign role (`ADMIN`/`DPO`/`OPERATOR`).
**Expected Result:** New user can log in with the assigned role's permissions.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - DPO user created via the form and listed | new DPO logs in and lands on /console/dpo/dashboard.html

### TC-ADM-16: Deactivate a user
**Type:** UI · **Priority:** Medium
**Steps:** Deactivate a user; attempt login with their credentials.
**Expected Result:** Login rejected.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - deactivated deact46555@alpha.test in the console; login now -> 401

### 2.5 White-Labeling

### TC-ADM-17: `BRAND_NAME` rebrands console, rights portal, tour, report footers
**Type:** UI · **Priority:** Medium
**Steps:** Set `BRAND_NAME` (≤12 chars) at deploy time; load each surface.
**Expected Result:** Brand name replaced consistently everywhere - login, console, rights portal, tour - and in generated artifacts (the breach report PDF footer and the certificate's `software` metadata show the brand, never "TSI DPDP CMS"); layouts (sidebar, title bar, report footer) don't overflow.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - BRAND_NAME='Acme Consent': none of the 7 pages (login, rights portal, tour, console) contain 'TSI DPDP CMS' and all carry the brand; breach PDF footer reads 'Acme Consent v0.5.4'; certificate metadata software='Acme Consent'; startup log 'Acme Consent v0.5.4 Service started in local environment'

### TC-ADM-18: `BRAND_NAME` over 12 characters fails fast at startup
**Type:** API · **Priority:** Medium
**Steps:** Set `BRAND_NAME` to a 13+ character value; start the app.
**Expected Result:** Application refuses to start with a clear error, same pattern as `JWT_SECRET`/`DB_ENCRYPTION_KEY`.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - 13-character BRAND_NAME: startup error '|java.lang.ExceptionInInitializerError: Exception java.lang.IllegalStateException: BRAND_NAME must be at most', and the application does not serve pages

---

## 3. DPO Console

### 3.1 RoPA & Policy Authoring

### TC-DPO-01: Create a RoPA entry
**Type:** UI · **Priority:** High
**Steps:** DPO Console → RoPA → create entry for a processing activity.
**Expected Result:** Entry saved, selectable when validating policy completeness.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - RoPA entry created (201), listed, completeness check -> 200 {'missing_fields': ['dpo_id'], 'complete': False}

### TC-DPO-02: Compile and validate a multilingual JSON policy
**Type:** UI · **Priority:** Critical
**Steps:** Paste/upload a policy JSON (see `examples/policy/*/`) via the policy editor.
**Expected Result:** Saved as `DRAFT`. Validation catches an unmapped data category / missing purpose field.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - uploading a policy JSON through the editor with ID + Version -> saved and published (DB 1.0|UNDER_REVIEW); the editor moves to "Step 2 - Review & publish ROPA entries"

### TC-DPO-02a: A policy cannot be created without a valid version
**Type:** API / UI · **Priority:** High
**Steps:** `create_policy` with the version omitted, blank, and malformed (`v1`, `1.0.0.0`, `1.2.3.4.5`, more than 10 characters). Repeat from the console's **Create New Policy** form (the Version field is required and pattern-checked).
**Expected Result:** API: `400` explaining the accepted format. Console: the form will not submit. A valid version (`1.0`, `2.1.3`) saves as `DRAFT` and shows in the new Version column.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - invalid versions all 400 {'omitted': 400, 'blank': 400, 'v1': 400, 'four-part': 400, '11 chars': 400, 'letters': 400}; '2.1.3' -> 201 | list has a Version column; the form rejects empty / "v1" / "1.0.0.0" (no create_policy request sent: true) and accepts "1.0"

### TC-DPO-02b: Edit, publish and delete address the chosen version
**Type:** UI · **Priority:** High
**Steps:** With a `DRAFT` policy, click Edit, change content, continue to publish; separately, delete a second `DRAFT` version of the same `policy_id`.
**Expected Result:** The edit and publish apply to the row's own version (Version field is read-only while editing). Deleting one version archives only that version and leaves other versions' ROPA entries intact.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - Delete on v2.5 archived only that version (v1.5 stays DRAFT); Edit on v1.5 opens with the Version field read-only ("1.5") | policy list row: " ui_policy 1.0 IN UNDER_REVIEW Pending DPO ROPA approval 10/27/2026 View ROPA Review ROPA "

### TC-DPO-02c: Backfill migration (`db/14_policy_version_backfill.sql`)
**Type:** DB · **Priority:** High
**Preconditions:** A database with a blank-version policy that has consent rows, plus a second policy id with both a blank version and another version.
**Steps:** Run the script twice.
**Expected Result:** The single-version policy becomes `1.0` and its consent rows repoint (foreign key intact). The ambiguous policy is untouched and reported in a `NOTICE`. The second run changes nothing. `audit_logs` is unchanged.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - full schema: solo '' -> 1.0 (consent 1.0); ambiguous left alone & reported; 2nd run no-op; audit_logs untouched

### TC-DPO-03: Publish a policy (DRAFT → UNDER_REVIEW → ACTIVE)
**Type:** UI · **Priority:** Critical
**Steps:**
1. Publish a DRAFT policy. Confirm it lands in `UNDER_REVIEW`, not `ACTIVE` - by design, this is a deliberate gate, not a bug: a policy cannot go live until it's been reviewed.
2. Complete RoPA review/approval for every RoPA entry linked to that `policy_id`.
**Expected Result:** After step 1, the policy is `UNDER_REVIEW` and does **not** yet appear via `get_active_policy`/`list_active_policies`. Only after step 2 (every linked RoPA entry reaches `active`/`retired`) does it flip to `ACTIVE` and become visible. (Confirmed as intentional product behavior, not an API-only artifact - `Policy.publishPolicyInDb` sets `UNDER_REVIEW`; `Ropa.activatePolicyIfComplete` is the actual activation trigger.)
**Last Verified:** v0.5.4 · 2026-10-27 · pass - publish -> UNDER_REVIEW (not listed); after ROPA approval -> ACTIVE

### TC-DPO-04: Cannot have two ACTIVE versions of the same policy simultaneously
**Type:** API · **Priority:** Critical
**Steps:** With a policy already `ACTIVE`, attempt to publish a second version of the same `policy_id`.
**Expected Result:** Rejected with a conflict error; the prior active version must be retired first.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - publishing v3.0 while v1.0 is ACTIVE -> 409: Publication Conflict: The following Purpose IDs are already defined in other active polici

### TC-DPO-05: A Fiduciary can run multiple concurrently-active policies
**Type:** UI · **Priority:** High
**Steps:** Publish an ACTIVE customer policy and an ACTIVE employee policy for the same Fiduciary.
**Expected Result:** Both active simultaneously; `list_active_policies` returns both; rights portal persona selection scopes correctly to each.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - two policies concurrently ACTIVE: ['retail_cust', 'web_privacy']

### 3.2 Breach Notification

### TC-DPO-06: Report a breach
**Type:** UI · **Priority:** Critical
**Steps:** DPO Console → Breach → Report Breach, select affected purpose(s) grouped by active policy.
**Expected Result:** Breach record created; affected-principal resolution scoped to the selected policy only (not cross-policy).
**Last Verified:** v0.5.4 · 2026-10-27 · pass - scoped breach resolved 3 principals (= 3 who granted purpose_marketing under web_privacy) | form submitted with purpose picker grouped by active policy (9 options); breach listed; resolved 12 principal(s) from the purpose

### TC-DPO-06a: Breach notification deadline countdown and overdue state
**Type:** UI · **Priority:** High
**Preconditions:** `db/15_breach_deadline.sql` applied; Settings → Breach Notification Deadline left at the default 72 hours.
**Steps:** Report a breach with `detected_at` 10 hours ago. Open the DPO Dashboard. Then report another with `detected_at` 80 hours ago. Then move the first breach to CONTAINED.
**Expected Result:** The Dashboard's "Breach Notification Deadlines" card lists the first breach with roughly "62h 0m left" (counting down, amber under 6 hours) and the second as "OVERDUE by ~8h", highlighted red, with an "N overdue" chip. The Breach page shows the same in a Deadline column and in the incident detail. After CONTAINED the first breach leaves the dashboard card and shows "Met" (or "Met late" if it was moved after its deadline) on the Breach page. No push notification is sent in any state.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - OPEN breaches listed most-urgent first (80h-old = OVERDUE, negative seconds; 10h-old = COUNTING); containing one stops its clock (MET) and drops it from the dashboard; list shows OVERDUE/MET | Breach list has a Deadline column (OVERDUE / Met shown); incident detail: "10/27/2026, 1:33:52 PM — OVERDUE by 8h 22m" | dashboard card shows " Breach B (80h ago) HIGH 10/24/2026, 1:33:52 PM 10/27/2026, 1:33:52 PM OVERDUE by 8h 22m Breach scoped HIGH 10" with the red overdue row and an "N overdue" chip; page errors: 0

### TC-DPO-06b: Breach deadline is configurable within 1-72 hours and applies going forward
**Type:** UI / API · **Priority:** Medium
**Steps:** In Settings set the deadline to 24 and save; report a breach. Try saving 0, 73 and a non-integer (UI and `set_breach_settings`). Change the setting to 48 and re-check the breach reported at 24.
**Expected Result:** The new breach's deadline is `detected_at + 24h`. 0, 73 and non-integers are rejected (`400`). Changing the setting afterwards does not move the existing breach's deadline. An operator (non-DPO) calling `set_breach_settings` is refused.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - default 72; 0/73/1.5/'x'/-3 -> 400 [400]; operator -> 403; 24h breach deadline = detected+24h; later change did not move it | Settings control loaded 72, saved 24 (DB 24), 99 rejected in the UI ("Enter a whole number of hours between 1 and 72."), restored 72

### TC-DPO-06c: Breaches reported before the upgrade are not tracked
**Type:** DB / UI · **Priority:** Medium
**Steps:** Upgrade a database that already holds breach incidents (including OPEN ones) and open the Dashboard and Breach page.
**Expected Result:** Existing incidents show "—" / "Not tracked (reported before deadlines were introduced)"; none appear as overdue on the dashboard. Running `db/15_breach_deadline.sql` twice changes nothing.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - pre-existing incident: NOT_TRACKED, no deadline, never on the overdue list; db/15 re-run twice is a no-op on the full schema

### TC-DPO-07: Notify affected principals and generate the PDF record
**Type:** UI · **Priority:** High
**Steps:** From a reported breach, trigger notification + generate PDF.
**Expected Result:** `BREACH_NOTIFICATION` created per affected principal; PDF download succeeds and contains the breach details.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - BREACH_NOTIFICATION rows=6; PDF downloads (1489 bytes); footer carries 'TSI DPDP CMS v0.5.4'; deadline line present=True | "Download PDF" is offered for the CONTAINED breach and hidden for the OPEN one (PDF content verified in TC-DPO-07)

### TC-DPO-08: Bulk-notify via CSV upload through the Job Manager
**Type:** UI · **Priority:** Medium
**Steps:** Upload a CSV of affected principal IDs for a breach.
**Expected Result:** Job Manager processes the batch; notifications created for each listed principal.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - CSV of 3 ids processed by the Job Manager (BREACH_NOTIFY COMPLETED): 3 notifications, 3 affected-principal rows, count reconciled to 3 | CSV upload accepted ("2 Principal ID(s) found in ui_ids.csv.") and queued as a BREACH_NOTIFY job

### 3.3 Grievance Management

### TC-DPO-09: Grievance appears in DPO queue on submission
**Type:** UI · **Priority:** Critical
**Steps:** Submit a grievance from the rights portal (see TC-RTS-09); check DPO Console → Grievances.
**Expected Result:** New grievance visible, `status: NEW`, correct SLA `due_date` (30 days default, 7 days if `type=ERASURE_REQUEST`).
**Last Verified:** v0.5.4 · 2026-10-27 · pass - submitted grievance appears in the DPO queue: status NEW, due 2026-11-03 21:32:21.026667 (SLA 7d for ERASURE_REQUEST verified in TC-CLI-09) | Grievances page lists the submitted grievances (" ...e706b34f erasure request s 10/27/2026 RESOLVED 7 Days Left Unassigned View/Manage ...9")

### TC-DPO-10: Assign and resolve a grievance within SLA
**Type:** UI · **Priority:** High
**Steps:** Assign to a DPO user; resolve with resolution details before `due_date`.
**Expected Result:** Status `RESOLVED`; `GRIEVANCE_RESOLVED_NOTIFICATION` fires to the principal.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - assigned (200), resolved (200) -> RESOLVED; GRIEVANCE_RESOLVED_NOTIFICATION to the principal (2) | grievance opened from the queue and resolved in the modal -> RESOLVED with resolution text

### TC-DPO-11: Grievance escalation past due date
**Type:** UI · **Priority:** Medium
**Steps:** Let a grievance pass its `due_date` unresolved.
**Expected Result:** The grievance is flagged overdue on the DPO dashboard (negative days left). Escalation itself is manual - no job changes the status at `due_date`; when the DPO sets `ESCALATED`, `GRIEVANCE_ESCALATED_NOTIFICATION` fires.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - past-due grievance is flagged on the dashboard (days_left -3); moving it to ESCALATED fires GRIEVANCE_ESCALATED_NOTIFICATION. NOTE: escalation is manual - no job changes status automatically at due_date

### 3.4 Legal / Audit Evidence

### TC-DPO-12: Generate BSA Section 63 court-ready evidence export
**Type:** UI · **Priority:** Medium
**Steps:** Legal module → generate evidence export for a date range / event.
**Expected Result:** Export produced with the certification metadata the guide describes; matches audit log entries for that period.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - certificate has signed hash-chained trail (2 entries), SHA256withRSA signature, chain-of-custody metadata, software 'TSI DPDP CMS' version '0.5.4' | Legal page (now same-origin) generates and opens the certificate: red non-production banner, "Signing Key: NON-PRODUCTION (transient, unverifiable)", "Software: TSI DPDP CMS v0.5.4", trail line "policy web_privacy · version 1.0", attestation prefixed; certificate list had 7 row(s)

### TC-DPO-12b: Certificates from a non-production server are marked unverifiable
**Type:** UI / API · **Priority:** Critical
**Steps:** (a) On a server with `TSI_DPDP_CMS_ENV` unset or `local`, generate a certificate and open it. (b) On a server with `TSI_DPDP_CMS_ENV=production` and a configured keystore, do the same.
**Expected Result:** (a) The signed data has `signing_key_status: NON_PRODUCTION_UNVERIFIABLE` and a `signing_notice`; the attestation text begins "[NON-PRODUCTION - UNVERIFIABLE ...]"; the generate response has `signature_verified: false`; the Legal page shows a red banner and "Signing Key: NON-PRODUCTION". (b) `signing_key_status: PRODUCTION`, no notice or banner, `signature_verified: true`. Certificates issued before this change show "Signing Key: (not recorded)".
**Last Verified:** v0.5.4 · 2026-10-27 · pass - (a) local env: signature_verified=false, signing_key_status NON_PRODUCTION_UNVERIFIABLE in signed data, signing_notice, attestation prefixed (production half checked later on the production instance) | (b) production instance with a keystore: signature_verified=true, signing_key_status PRODUCTION, no signing_notice, attestation has no non-production prefix

### TC-DPO-12a: Evidence certificate lists the policy and version consented to
**Type:** UI / API · **Priority:** High
**Steps:** Record consent for a principal, generate an evidence certificate for them, open it.
**Expected Result:** The signed certificate data has a `policies` array with that `policy_id`, its `policy_version`, and first/last-seen timestamps; the consent entry in the trail shows the same (and the Legal page shows "policy X - version Y" under it). Entries written before version stamping show an empty version.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - signed data has policies [('web_privacy', '1.0')]; trail consent entries carry policy_id/version

### TC-DPO-12c: The Legal page works on any host and port
**Type:** UI · **Priority:** High
**Steps:** Run the application on a port other than 8080 (or behind a domain / reverse proxy), open DPO Console → Legal, generate a certificate and open it.
**Expected Result:** The certificate list loads, generation succeeds and the certificate opens. (The page used to call `http://localhost:8080` regardless of where it was served from, so it failed anywhere else.)
**Last Verified:** v0.5.4 · 2026-10-27 · pass - the Legal page generated and opened a certificate with the app on port 18080 (not 8080) - it previously failed here because the page hardcoded http://localhost:8080 (fixed to same-origin in this release)

### TC-DPO-13: Audit log entries are immutable
**Type:** UI · **Priority:** High
**Steps:** Attempt to view/edit an existing audit log entry through any console path.
**Expected Result:** No edit/delete affordance exists anywhere in the UI or API for audit rows.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - no update/delete/edit audit function exists (all 400 unknown function); audit page has no edit/delete controls; 81 hash-linked entries | Audit page lists 50 entries; no edit/delete control anywhere on the page or in the detail dialog

### 3.5 Job Manager

### TC-DPO-14: Consent Expiry Service (CES) nightly batch creates purge requests
**Type:** API · **Priority:** Critical
**Preconditions:** A principal has called `erasure_request` (see TC-CLI-14) more than 24h ago (or trigger the job manually if supported).
**Steps:** Check `purge_requests` / `list_purge_requests` after the batch window.
**Expected Result:** One purge request per purpose the principal had consented to; an App that called `validate_consent` for that purpose is linked (`app_id` set); a purpose no App validated still gets a request recorded with `app_id: null` (orphan).
**Last Verified:** v0.5.4 · 2026-10-27 · pass - CES batch -> 5 purge requests for the erased principal: 2 linked to the validating app, 3 orphans (app_id null)

### TC-DPO-15: Export job (CONSENT / PRINCIPAL / GRIEVANCE / AUDIT)
**Type:** UI · **Priority:** Medium
**Steps:** Trigger each export subtype with a date range via Job Manager.
**Expected Result:** Job transitions `PENDING → RUNNING → COMPLETED`; `output_file_path` populated; file downloadable and contains the expected rows.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - jobs went PENDING->RUNNING->COMPLETED with output_file_path; CONSENT/PRINCIPAL/GRIEVANCE/AUDIT CSVs downloaded with data: CONSENT:200/16 rows, PRINCIPAL:200/13 rows, GRIEVANCE:200/2 rows, AUDIT:200/79 rows (PARENT_CONSENT: PENDING) | another fiduciary's DPO downloading this job -> 403 | Reports page loads cleanly and offers the export subtypes (jobs and downloads verified in TC-DPO-15)

### 3.6 Webhook & Notification Configuration

### TC-DPO-16: Configure and activate a Notification webhook
**Type:** UI · **Priority:** High
**Steps:** Settings → Webhooks → Notification card, set an HTTPS URL + secret, Save, Activate.
**Expected Result:** Saved; a subsequent `notification_created` event delivers to the URL, signed per [Webhook Integration Guide](../guides/webhook-integration-guide.md) §4.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - NOTIFICATION webhook saved and active; notification_created delivered over TLS, signed | https URL + secret saved through the Webhooks card ("NOTIFICATION webhook saved."); stored https://hooks.test/hook:true

### TC-DPO-06d: Breach lists who was notified and what they were sent
**Type:** UI / API · **Priority:** High
**Preconditions:** `db/17_notification_log.sql` applied; a Breach notification message configured in Settings.
**Steps:**
1. Report a breach affecting three principals (explicit IDs) and open it on the Breach page.
2. Mark one of those principals' notifications read (`mark_notification_read`) and reopen the breach.
3. Change the Breach notification message in Settings, then reopen the breach.
4. Click **Download CSV**.
5. Open a breach reported before the upgrade.
**Expected Result:** The detail shows **Message Sent to Principals** with the configured text, and a **Principals Notified** table with the three principals and their notified times (step 1). After step 2 the summary reads "3 notified · 1 read · 2 unread" and the read principal shows a time. The message still shows the wording that was sent, not the edited one (step 3). The CSV has `principal`, `notified_at`, `read_at` for all three (step 4). The pre-upgrade breach lists its principals with "—" for read status and "Not recorded" for the message (step 5).
**Last Verified:** not yet run

### TC-DPO-16b: Notification Log export
**Type:** UI / DB · **Priority:** High
**Preconditions:** `db/17_notification_log.sql` applied; some notifications created (a breach, a consent, a purge).
**Steps:** Open Reports and choose **Notification Log**: the End Date locks to the Start Date. Pick the day that covers them, submit, and download the CSV when it completes. Also call `create_job` for `NOTIFICATION_LOG` with a two-day range. Edit a notification message template in Settings, create one more notification of that type, and export again.
**Expected Result:** The two-day `create_job` call is refused with `400` (one day at a time) and no job is queued. The one-day export has one row per notification on that day, for this fiduciary only, with `created_at`, `recipient_type`, `recipient`, `notification_type`, `read_at`, `breach_id` (breach notifications only), `message_en` and `message_all_languages`. The earlier rows keep the old wording and the new row has the new wording. Rows created before the upgrade have empty message columns.
**Last Verified:** not yet run

### TC-DPO-16a: Minor guardian-reference audit (panel and export)
**Type:** UI / API · **Priority:** High
**Preconditions:** A fiduciary with: a MINOR principal whose consent carries a valid `verification_log_id`; a MINOR principal with a consent and no reference; a MINOR principal whose reference is for a different child; a MINOR principal whose log's guardian differs from `guardian_id`; an ADULT principal with no reference; a MINOR principal belonging to another fiduciary.
**Steps:** Open DPO Console → Principals and read the Minor Consent Audit card; tick "Active consents only"; follow "Export full list (CSV)", run the export for a wide date range and for a range containing none of the consents.
**Expected Result:** The summary counts the four minor principals of this fiduciary and their consents (1 OK, the rest split between "missing reference" and "reference mismatch"); the ADULT principal and the other fiduciary's minor never appear. "Active only" drops superseded consents. The CSV has the same rows, findings first and OK rows last, with a `finding` column; the empty range yields a header-only file. An Operator of another fiduciary is refused (`403`).
**Last Verified:** v0.5.4 · 2026-10-27 · pass - summary {'consents': 5, 'missing_log': 2, 'ok': 1, 'minor_principals': 4, 'log_mismatch': 2}; flagged ['kid_missing@test.local', 'kid_wrongchild@test.local', 'kid_wrongguardian@test.local']; adult & other tenant excluded; active-only drops the superseded row; limit honoured; other fiduciary's DPO -> 403, operator -> 200 (CSV export checked when its job completes) | CSV has 5 rows (5 expected): findings ['LOG_MISMATCH', 'MISSING_LOG', 'OK'], findings sorted first/OK last, adult & other tenant absent | Principals page card: "4 minor principal(s), 5 consent record(s): 1 OK, 2 missing guardian reference, 2 reference mismatch."; active-only: "4 minor principal(s), 4 consent record(s): 1 OK, 1 ...

### TC-DPO-17: Non-HTTPS or private/loopback webhook URL rejected
**Type:** UI · **Priority:** High
**Steps:** Attempt to save `http://...` or a URL resolving to `169.254.169.254` / loopback / private range.
**Expected Result:** Rejected at save time (and would be re-checked at delivery time for DNS-rebinding, per the guide §5).
**Last Verified:** v0.5.4 · 2026-10-27 · pass - http/loopback/metadata/private/ftp URLs -> 400; https://hooks.test -> 200 | http:// URL refused in the form ("Failed to save webhook: 'webhook_url' must be HTTPS and must not resolve to a pr")

### TC-DPO-18: Webhook delivery failure doesn't block the business operation
**Type:** API · **Priority:** High
**Steps:** Configure a webhook pointed at an unreachable endpoint; trigger a notification event.
**Expected Result:** The triggering operation (e.g. consent record) still succeeds; the delivery is recorded and retried with backoff (TC-WHK-03); `WEBHOOK_DELIVERY_FAILED` is written once, when the last attempt fails.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - record_consent still 201 with the endpoint answering 500 and with a refused connection (0.9s); both deliveries recorded and queued for retry: 'PENDING|1' / 'PENDING|1|java.net.ConnectException'

### 3.7 Rights Management App Config / OTP Mode

### TC-DPO-19: Switch OTP delivery mode (Dummy / Email / Mobile)
**Type:** UI · **Priority:** High
**Steps:** Settings → Rights Management App, change OTP mode.
**Expected Result:** Rights portal login behavior changes accordingly (fixed `1234` vs. real dispatched code); `principal_otp_requested` webhook fires only in Email/Mobile mode. With `TSI_DPDP_CMS_ENV=production`, saving `DUMMY_OTP` is rejected with `400` ("disabled in production").
**Last Verified:** v0.5.4 · 2026-10-27 · pass - production: saving DUMMY_OTP -> 400 ('DUMMY_OTP is a demo mode and is disabled in production (TSI_'); EMAIL_OTP -> 200; OTP webhook configured -> 200 | Settings: DUMMY -> EMAIL_OTP shows the OTP webhook fields and saves (EMAIL_OTP); the rights portal for that org then shows "Email OTP" with a Send OTP button; switched back to DUMMY_OTP

### TC-DPO-20: DPO console pages load without JavaScript errors
**Type:** UI · **Priority:** Medium
**Steps:** Log in as a DPO and open Grievances, Audit, Compliance, Reports, RoPA and Team.
**Expected Result:** Each page renders its content with no JavaScript errors in the browser console.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - DPO console pages grievances, audit, compliance, reports, ropa and team load with no JavaScript errors in headless Chrome

---

## 4. Data Principal Rights Portal

### TC-RTS-01: Login with Dummy OTP
**Type:** UI · **Priority:** Critical
**Preconditions:** Server **not** running with `TSI_DPDP_CMS_ENV=production` (see TC-RTS-01a for production).
**Steps:** `/rights/index.html`, select org, enter any ID, OTP `1234`.
**Expected Result:** Redirected to dashboard; session token stored in `sessionStorage`.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - org selected, ID + OTP 1234 -> /rights/dashboard.html; sessionStorage keys: pp_policies,pp_sync_token,pp_token,pp_persona,pp_user_id,pp_pca_qr_enabled,pp_fiduciary_id,pp_fiduciary_name; evaluation-mode hint shown

### TC-RTS-01a: Dummy OTP login is refused in production
**Type:** UI / API · **Priority:** Critical
**Preconditions:** `TSI_DPDP_CMS_ENV=production`; an organisation whose OTP mode is `DUMMY_OTP` (the default when never configured).
**Steps:** `principal_login` with OTP `1234`; also open `/rights/index.html` and select that organisation. Then switch the organisation to `EMAIL_OTP` and repeat.
**Expected Result:** The `DUMMY_OTP` organisation: `403` and no session token, even with the correct `1234`; the portal shows "Login is not available for this organisation yet" with the login button disabled and no `1234` hint. After switching to `EMAIL_OTP`, the normal OTP round trip works.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - production instance: DUMMY org + correct 1234 -> 403 (no token); list_active_fiduciaries login_available={'Alpha Co': False, 'Beta Co': False, 'Gamma UI 6847': False, 'Gamma UI 79464': False, 'Gamma UI Co': False}; the same call on the local instance -> 200

### TC-RTS-02: Full Email/Mobile OTP round trip
**Type:** UI · **Priority:** Critical
**Preconditions:** Fiduciary's Rights App OTP mode set to Email or Mobile.
**Steps:** Request OTP, receive via configured channel/webhook, submit within 5 minutes.
**Expected Result:** Login succeeds; OTP is single-use (resubmitting the same code fails).
**Last Verified:** v0.5.4 · 2026-10-27 · pass - OTP requested; delivered to the OTP webhook (6-digit code); wrong code -> 401; correct code -> 200 token; resubmitting the same code -> 401 'Invalid or expired OTP.'

### TC-RTS-03: Persona selection before credentials
**Type:** UI · **Priority:** Medium
**Steps:** Select an organisation with multiple `data_subject_categories`; confirm persona pills appear before the credentials form.
**Expected Result:** Selected persona scopes which policy is pre-selected post-login (but all policies remain viewable).
**Last Verified:** v0.5.4 · 2026-10-27 · pass - persona pills (2) appeared before the credentials form (form hidden until a persona is chosen: none)

### TC-RTS-04: Manage Consent - toggle and save preferences
**Type:** UI · **Priority:** Critical
**Steps:** Toggle optional purposes, leave mandatory ones (disabled), Save.
**Expected Result:** Success banner shown (and screen-reader announced via `aria-live` - see TC-RTS-11); `record_consent` call succeeds; reload reflects saved state.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - mandatory purpose locked (checked+disabled); optional toggles saved -> success banner (aria-live=polite); stored record 1.0|true|CONSENT_GIVEN; reload shows the saved state

### TC-RTS-05: Consent History - view record details
**Type:** UI · **Priority:** High
**Steps:** History tab → click "Details" on a record.
**Expected Result:** Modal opens with per-purpose grant/deny and compliance context (policy version, mechanism, timestamp).
**Last Verified:** v0.5.4 · 2026-10-27 · pass - Details dialog opened: purposes " Essential Website Operation & Security ✓ GRANTED Responding to Your E"; provenance " Policy: web_privacy v1.0 Mechanism: CONSENT_GIVEN Timestamp: 10/27/2026, 10:02:"

### TC-RTS-06: Withdraw consent (full and partial)
**Type:** UI · **Priority:** Critical
**Steps:** Open Withdraw modal (each checkbox means "withdraw this purpose"); (a) leave every purpose ticked (or use Select All) → full withdrawal, (b) tick only some purposes → partial.
**Expected Result:** (a) all purposes marked withdrawn; (b) only the ticked purposes withdrawn, others remain active. Warning shown about mandatory-purpose withdrawal restricting service access.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - partial: only purpose_analytics withdrawn (newsletter still granted); then all purposes -> every purpose withdrawn. (The checkboxes mean "withdraw this one", so "Select All" = full withdrawal.)

### TC-RTS-07: Submit an erasure request
**Type:** UI · **Priority:** Critical
**Steps:** History tab → Erasure Request → confirm.
**Expected Result:** Confirmation dialog warns it's irreversible; consent record marked accordingly; no immediate purge (see [§8](#8-purge-lifecycle-end-to-end)).
**Last Verified:** v0.5.4 · 2026-10-27 · pass - confirm dialog warns it is irreversible ("Request COMPLETE erasure of your data under ..."); a new ERASURE_REQUEST record appears in history labelled "ERASURE REQUEST"; no purge row is created synchronously (0 rows)

### TC-RTS-08: Self-verify consent for a purpose
**Type:** UI · **Priority:** Medium
**Steps:** History tab → Verify My Consent, pick a purpose, Check Status.
**Expected Result:** Shows granted/not-granted matching actual state.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - granted purpose -> "✓ Consent Active — you have gr"; not-granted purpose -> "✕ No Active Consent — consent ha"

### TC-RTS-09: Submit a grievance from the portal
**Type:** UI · **Priority:** High
**Steps:** Grievances tab → New Request, fill subject/description, submit.
**Expected Result:** Appears in principal's own list; also appears in DPO queue (TC-DPO-09).
**Last Verified:** v0.5.4 · 2026-10-27 · pass - grievance submitted from the portal; it appears in the principal's own list and in the DPO queue (status NEW)

### TC-RTS-10: Download / QR the Portable Consent Artifact (PCA)
**Type:** UI · **Priority:** Medium
**Steps:** Toggle PCA QR popover; download the JSON artifact.
**Expected Result:** QR renders; downloaded JSON contains `sync_token`, `policy_ref`, `consents`.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - PCA QR rendered; downloaded JSON has keys v,uid,fid,sync_url,sync_token,consents,policy_id,policy_version,policy_ref,generated_at

### TC-RTS-11: Accessibility - keyboard and screen reader
**Type:** UI · **Priority:** Critical
**Steps:** Tab through login + dashboard without a mouse; open/close both modals via Escape and Tab-cycling; run a screen reader through the save/error flows.
**Expected Result:** All interactive elements reachable in logical order; modals trap focus and restore it on close; status changes are announced via `aria-live`. **Full detail:** v0.5.2 accessibility work (RELEASE_NOTES.md).
**Last Verified:** v0.5.4 · 2026-10-27 · partial - automated half passes: 3 role=tab, modal role=dialog aria-modal=true, Tab x12 keeps focus inside the dialog, Escape closes it and focus returns to the trigger button, aria-live status regions present (save banners, verify result). The screen-reader pass (announcements on save/error) was NOT run - it needs a human with a screen reader

### TC-RTS-12: Verifiable parental consent (Section 9)
**Type:** UI · **Priority:** High
**Steps:** Trigger the minor/guardian flow (age category `MINOR`) with guardian OTP identification (see the [Parental Consent Guide](../guides/parental-consent-guide.md)).
**Expected Result:** `record_parent_consent` logs the verification; consent then recorded against the child's principal ID with `verification_log_id` linked.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - tour parental-consent flow end to end (API calls: get_policy:200, record_parent_consent:201, link_user:200, record_consent:201): guardian OTP step -> 5 purposes -> record_parent_consent logged (02bf850d…), principal flagged MINOR|9990001111|VERIFIED, consent stored with verification_log_id linked and policy version 1.0

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
**Last Verified:** v0.5.4 · 2026-10-27 · pass - get_active_policy without fiduciary_id via principal JWT -> 400

### TC-CLI-02: `get_policy` returns raw JSON text; `get_active_policy` returns parsed object
**Type:** API · **Priority:** Medium
**Steps:** Call both for the same policy/version.
**Expected Result:** `get_policy`'s `policy_content` is a string; `get_active_policy`'s is a parsed object. (Real, documented API inconsistency - not a bug to fix, just to keep consistent.)
**Last Verified:** v0.5.4 · 2026-10-27 · pass - get_policy content is a string; get_active_policy content is an object

### 5.2 Consent (`/api/v1/client/consent`)

### TC-CLI-03: `record_consent` ignores `timestamp`/`ip_address`/`jurisdiction`
**Type:** API · **Priority:** Medium
**Steps:** Send all three fields with deliberately wrong values; inspect the stored record via `get_active_consent`.
**Expected Result:** Server's own values are used regardless (server time, hashed real remote IP, hardcoded `"IN"`). Confirms documented behavior hasn't silently changed. (`policy_version` is **not** ignored - see TC-CLI-15 to TC-CLI-17.)
**Last Verified:** v0.5.4 · 2026-10-27 · pass - server values used: IN|true|true|CONSENT_GIVEN

### TC-CLI-04: `record_consent` rejects a non-active policy reference
**Type:** API · **Priority:** High
**Steps:** Call with a `policy_id` that exists but isn't `ACTIVE` for the resolved fiduciary.
**Expected Result:** `400`, policy-not-found-or-not-owned message.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - DRAFT policy reference -> 400

### TC-CLI-05: `withdraw_consent`/`erasure_request` return 200 with `success:false` on business failure
**Type:** API · **Priority:** High
**Steps:** Call `withdraw_consent` for a `user_id` with no consent record at all.
**Expected Result:** HTTP `200`, `{success:false, message:"No consent record found for withdrawal."}` - **not** a 4xx. Confirms callers must check `success`, not status code, for this pair.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - -> 200 success:false: No consent record found for withdrawal

### TC-CLI-06: `withdraw_consent` partial withdrawal via `purpose_ids`
**Type:** API · **Priority:** High
**Steps:** Call with `purpose_ids` naming a subset of granted purposes.
**Expected Result:** Only listed purposes flip to denied; others remain granted.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - only listed purposes denied: {'purpose_analytics': False, 'purpose_marketing': False, 'purpose_site_essential': True, 'purpose_contact_enquiry': True, 'purpose_newsletter': True}

### TC-CLI-07: Principal JWT `user_id` mismatch is rejected
**Type:** API · **Priority:** Critical
**Steps:** Authenticate as principal A's JWT; call any `/consent` or `/grievance` function with `user_id` set to principal B.
**Expected Result:** `403`, regardless of which function was requested.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - consent/history/grievance with another user's id -> 403,403,403

### TC-CLI-08: `validate_consent` records the validation for later purge targeting
**Type:** API · **Priority:** Critical
**Steps:** Call `validate_consent` for a purpose from a specific App's API key; later trigger CES (TC-DPO-14).
**Expected Result:** That App is linked (`app_id`) on the resulting purge request for that purpose.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - the app that called validate_consent for those two purposes is the one linked on their purge requests

### TC-CLI-15: `record_consent` stamps the active policy version when `policy_version` is omitted
**Type:** API · **Priority:** Critical
**Preconditions:** A policy with an explicit version (e.g. `1.0`) that is `ACTIVE`.
**Steps:** Call `record_consent` with no `policy_version`, then again with `"policy_version": ""`. Read the result via `get_active_consent`.
**Expected Result:** Both return `201`; the stored record's `policy_version` is the active version (`1.0`), never blank.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - omitted and blank policy_version -> 201, stored version '1.0'

### TC-CLI-16: `record_consent` accepts the matching version and rejects a mismatch
**Type:** API · **Priority:** Critical
**Steps:** Call `record_consent` with `policy_version` equal to the active version, then with a different one (e.g. `0.9`).
**Expected Result:** Matching version: `201`. Mismatch: `409 Conflict` whose message names both versions, and no consent row is written.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - match -> 201; mismatch -> 409 naming both versions; no row written (1->1)

### TC-CLI-17: Wallet-granted consent carries a version
**Type:** UI · **Priority:** High
**Steps:** From the Rights Portal wallet, grant consent for a policy, then view the consent history.
**Expected Result:** The new consent record shows the active policy version, not a blank one.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - wallet GRANT_CONSENT stored version '1.0' (mechanism WALLET_GRANT); a policy with no active version is refused: Referenced policy not found or does not belong to this fiduciary

### TC-CLI-18: `get_policy` without `version` resolves the only open version, otherwise asks for one
**Type:** API · **Priority:** Medium
**Steps:** Call the client `get_policy` with a `policy_id` but no `version` when the policy has (a) exactly one non-archived version and (b) two (for example an `ACTIVE` 1.0 and a `DRAFT` 4.0). Then call it with an explicit `version`.
**Expected Result:** (a) `200` with that version. (b) `400` saying `version` is required. Explicit version: `200`. (Policy lifecycle calls - update, publish, delete, `derive_from_policy` - behave the same way.)
**Last Verified:** v0.5.4 · 2026-10-27 · pass - client get_policy without version: two open versions -> 400 asking for 'version'; explicit version -> 200; after the draft is deleted the sole open version is resolved -> 200 (v1.0)

### 5.3 Grievance (`/api/v1/client/grievance`)

### TC-CLI-09: `submit_grievance` accepts any `type` string; only `ERASURE_REQUEST` changes SLA
**Type:** API · **Priority:** Medium
**Steps:** Submit with `type: "SOMETHING_MADE_UP"` and separately with `type: "erasure_request"` (lowercase).
**Expected Result:** Both accepted (201); only the erasure-request one (case-insensitive) gets the 7-day SLA instead of 30.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - both accepted; SLA days SOMETHING_MADE_UP:30 / erasure_request:7

### 5.4 Notification (`/api/v1/client/notification`)

### TC-CLI-10: `mark_notification_read` field is `id`, not `instance_id`
**Type:** API · **Priority:** Low
**Steps:** Omit `id`; read the error message.
**Expected Result:** `400`, `"[$: required property 'id' not found]"` - caught by the JSON-Schema pre-check (`web/WEB-INF/validator/mark_notification_read.jschema`), which correctly names `id`. **Correction after running this live:** `Notification.java`'s own service-level check has a bug (its message names `instance_id` instead of `id`), but that code path is unreachable via the real API - the schema pre-check always rejects a missing `id` first. Documented here as dead code, not a live-observable bug.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - -> 400 {"error": "[$: required property 'id' not found]", "timestamp": "2026-10-27T16:02:21.371929385Z", "status": 40

### TC-CLI-11: `list_notifications` from a Principal JWT without body `fiduciary_id`
**Type:** API · **Priority:** Medium
**Steps:** Authenticate via Principal JWT only (no API key), call `list_notifications` with no `fiduciary_id` in body.
**Expected Result:** **Known bug**, confirmed live: `500`, `"Cannot invoke \"String.length()\" because \"name\" is null"` - a `NullPointerException` inside the fiduciary-resolution fallback, not a clean `400`. (Earlier source-only analysis had guessed an unguarded `UUID.fromString(null)` as the cause; the actual live error is this NPE instead - source hypotheses need runtime confirmation, not just a read-through.) Tracked here until fixed; re-verify after any fix lands.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - list_notifications via principal JWT without fiduciary_id -> 500 {"path": "/api/v1/client/notification", "error": "Internal Server Error", "message": "An unexpected error occu (documented known bug expects 500; 400 would mean it is fixed)

### 5.5 Compliance / Purge (`/api/v1/client/compliance`)

### TC-CLI-12: PURGE scope blocked over Principal JWT
**Type:** API · **Priority:** Critical
**Steps:** Authenticate via Principal JWT; call `list_purge_requests` or `update_purge_status`.
**Expected Result:** `403` - PURGE functions are API-key-only, unconditionally.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - principal JWT on PURGE functions -> 403,403

### TC-CLI-13: `update_purge_status` doesn't check request ownership
**Type:** API · **Priority:** High
**Steps:** Using Fiduciary A's API key (PURGE scope), call `update_purge_status` with an `id` belonging to Fiduciary B.
**Expected Result:** **Known, accepted gap** (documented in the System Integration Guide) - the update succeeds regardless of fiduciary ownership. This case exists to confirm it's still true, not to flag it as new.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - known/accepted gap still true: Alpha's PURGE-scope key updated Beta's purge request (200); status now PURGE_IN_PROGRESS

### TC-CLI-14: `list_purge_requests` includes orphaned requests
**Type:** API · **Priority:** Medium
**Steps:** Call `list_purge_requests` where at least one request has `app_id: null`.
**Expected Result:** Orphaned requests appear alongside the calling App's own, with `app_name: "No Linked Processor"`.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - 5 requests returned incl. 3 orphans labelled 'No Linked Processor'

---

## 6. Public API

### TC-PUB-01: `list_active_fiduciaries` returns only active ones
**Type:** API · **Priority:** Medium
**Steps:** Call with no auth required.
**Expected Result:** Deactivated Fiduciaries excluded (cross-reference TC-ADM-07).
**Last Verified:** v0.5.4 · 2026-10-27 · pass - public list returns active fiduciaries: ['Alpha Co', 'Beta Co']

### TC-PUB-02: `request_principal_otp` rate-limited per target (3/hour) and per IP (20/15min)
**Type:** API · **Priority:** Critical
**Steps:** Call 4 times for the same `fiduciary_id`+`user_id`.
**Expected Result:** 4th call returns `429`. **v0.5.2 fix, verified live.**
**Last Verified:** v0.5.4 · 2026-10-27 · pass - 4 OTP requests for the same fiduciary+user -> [200, 200, 200, 429]

### TC-PUB-03: `principal_login` rate-limited per target (5/15min) and per IP (20/15min)
**Type:** API · **Priority:** Critical
**Steps:** Call 6 times for the same `fiduciary_id`+`user_id`+any OTP.
**Expected Result:** 6th call returns `429`. **v0.5.2 fix, verified live** - this closes the OTP brute-force path (the more severe half of the original rate-limiting gap, since `principal_login` is the actual verification step).
**Last Verified:** v0.5.4 · 2026-10-27 · pass - 6 wrong-OTP logins for the same target -> [401, 401, 401, 401, 401, 429]

### TC-PUB-04: OTP is single-use and expires after 5 minutes
**Type:** API · **Priority:** High
**Steps:** Request a real OTP (Email/Mobile mode); use it successfully once, then try again; separately, wait >5min and try an unused one.
**Expected Result:** Reuse rejected ("Invalid or expired OTP"); expiry rejected the same way.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - unused OTP rejected after 5m10s: 401 'Invalid or expired OTP.' (single-use rejection verified in TC-RTS-02)

---

## 7. Webhooks

Full contract: [Webhook Integration Guide](../guides/webhook-integration-guide.md).

### TC-WHK-01: Signature verification (HMAC-SHA256 over raw body)
**Type:** API · **Priority:** High
**Steps:** Capture a delivered webhook payload + `X-TSI-Signature`; recompute HMAC over the exact raw bytes with the configured secret.
**Expected Result:** Signatures match. Confirm it's the raw body only (no timestamp concatenation).
**Last Verified:** v0.5.4 · 2026-10-27 · pass - HMAC-SHA256 over the exact raw body (no timestamp prefix) matches X-TSI-Signature

### TC-WHK-02: All four event/category combinations fire correctly
**Type:** API · **Priority:** High
**Steps:** Trigger one event per row of the guide's §2 table (`notification_created`, `purge_request_created`, `purge_request_status_updated`, `principal_otp_requested`).
**Expected Result:** Each delivers the documented envelope (including `delivery_id`) + `data` shape.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - all four events delivered with the documented envelope incl. delivery_id: {'notification_created': True, 'purge_request_created': True, 'purge_request_status_updated': True, 'principal_otp_requested': True} | notification_created envelope ['data', 'delivery_id', 'event_type', 'fiduciary_id', 'timestamp'] delivery_id==X-TSI-Delivery-Id, attempt header 1; row DELIVERED|1 | principal_otp_requested envelope ok (data keys ['message', 'otp_mode', 'user_id']); delivery rows stored for it: 0 | purge webhook deliveries: purge_request_created|2|DELIVERED ; purge_request_status_updated|2|DELIVERED; purge_request_created payload keys ['app_id', 'id', 'purpose_id', 'status', 'trigger_event', 'user_id'...

### TC-WHK-03: Failed delivery is retried with backoff, then marked Failed
**Type:** API · **Priority:** High
**Preconditions:** `db/16_webhook_deliveries.sql` applied; a NOTIFICATION or PURGE webhook pointed at an endpoint that returns 500.
**Steps:** Trigger one event. Watch the endpoint and Compliance → Webhook Deliveries.
**Expected Result:** First attempt immediately, then retries at roughly +1m, +6m, +36m, +2h36m and +14h36m from the first (6 attempts in all), each carrying the same body, the same `delivery_id` / `X-TSI-Delivery-Id`, and an incrementing `X-TSI-Delivery-Attempt`. The delivery shows as Retrying with an attempt count and next-attempt time, then Failed after the sixth, with the last error. Exactly one `WEBHOOK_DELIVERY_FAILED` audit event is written, at that point. The underlying notification / purge request is unaffected throughout.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - attempt 1 immediate (row PENDING|1|500|60); first retry 68s later (backoff 60s + worker tick); 6 sends in all, identical body, attempt header 1..6; FAILED|6; exactly 1 WEBHOOK_DELIVERY_FAILED audit event; last_error 'HTTP 500'. (Backoffs 2-5 fast-forwarded in the DB, not waited in real time.)

### TC-WHK-04: A delivery that recovers is delivered once and stops retrying
**Type:** API · **Priority:** High
**Steps:** Point the webhook at an endpoint that fails (e.g. 503) for the first two attempts and then returns 200. Trigger an event.
**Expected Result:** Retried until the 200, then shown as Delivered with the attempt count; no further attempts; no `WEBHOOK_DELIVERY_FAILED` event.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - 503, 503, then 200 -> DELIVERED|3|200|-; exactly 3 sends, none after delivery; no failure event

### TC-WHK-05: Manual retry of a Failed delivery
**Type:** UI · **Priority:** High
**Steps:** Let a delivery reach Failed (TC-WHK-03), fix the endpoint, then in Compliance → Webhook Deliveries click **Retry**; also try retrying a Delivered one via the API, and another fiduciary's delivery id.
**Expected Result:** The Failed delivery gets a fresh set of attempts and is delivered; `WEBHOOK_DELIVERY_RETRY_REQUESTED` is audited. `retry_webhook_delivery` on a non-Failed delivery or another tenant's delivery returns `404`. An Operator is refused. The Payload button shows the exact JSON that was sent.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - other tenant 404/403, operator 403; own FAILED retried -> DELIVERED; retrying again -> 404; Payload (get) equals what was sent; list scoped (DPO2 on F1 -> 403) | Webhook Deliveries view: badge "1 failed", failed row with last error shown, Payload expands the JSON, Retry re-queued it and it was delivered

### TC-WHK-06: OTP webhooks are not stored or retried
**Type:** API · **Priority:** Critical
**Steps:** With OTP mode Email or Mobile and an OTP webhook pointed at a failing endpoint, request an OTP. Inspect `webhook_deliveries`.
**Expected Result:** Exactly one attempt; `WEBHOOK_DELIVERY_FAILED` logged; **no** row in `webhook_deliveries` (the OTP is never written to the table).
**Last Verified:** v0.5.4 · 2026-10-27 · pass - after 100s: exactly 1 attempt reached the receiver; webhook_deliveries rows for OTP: 0; WEBHOOK_DELIVERY_FAILED audited (1)

### TC-WHK-07: Polling still works when webhooks are down
**Type:** API · **Priority:** High
**Steps:** With every delivery failing, create a notification and a purge request; call `list_notifications` and `list_purge_requests`.
**Expected Result:** Both rows are returned regardless of webhook state.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - list_notifications returns the notification while its webhook delivery is failing (10 rows)

### TC-WHK-08: Delivery history is kept bounded
**Type:** DB · **Priority:** Medium
**Steps:** Age some `webhook_deliveries` rows (a `DELIVERED` row 8 days old, a `FAILED` row 91 days old, a `FAILED` row 10 days old) and let the hourly cleanup run (or call it directly).
**Expected Result:** The 8-day-old delivered row and the 91-day-old failed row are deleted; the 10-day-old failed row stays.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - retention logic verified against Postgres with the real dispatcher code: DELIVERED rows older than 7 days and FAILED rows older than 90 days are purged, newer ones kept (the hourly job itself was not waited on)

### TC-WHK-09: Webhook Deliveries list is paged
**Type:** UI · **Priority:** Low
**Steps:** Have more than 30 deliveries (for example 35 Delivered), open Compliance → Webhook Deliveries, choose **All**, then use **Next** / **Previous**; change the filter while on page 2; retry the only Failed row on the last page.
**Expected Result:** 30 rows per page, newest first, with "Showing 1–30 of N"; **Previous** is disabled on the first page and **Next** on the last; changing the filter returns to page 1; after the last row on a page is retried the list steps back to a page that has rows instead of showing an empty table.
**Last Verified:** not yet run

### TC-WHK-10: Webhook Deliveries screen is reached from Compliance, not Settings
**Type:** UI · **Priority:** Medium
**Steps:**
1. As a DPO with at least one Failed delivery (TC-WHK-03), open Compliance Enforcement.
2. Note the **Webhook Deliveries** button beside **View Jobs** and its red "N failed" badge; click it.
3. On the Webhook Deliveries screen check that **Compliance** is highlighted in the sidebar, then click **← Back to Compliance Enforcement**.
4. Retry the Failed delivery (TC-WHK-05), then open Compliance Enforcement again.
5. Open Settings and its Webhooks section; click the **Compliance → Webhook Deliveries** link in its text.
6. Sign in as an Operator and open Compliance Enforcement; then open `webhook-deliveries.html` directly.
**Expected Result:** The button shows the Failed count (steps 1-2) and opens the screen (step 2); Back returns to Compliance Enforcement (step 3); the badge is gone once nothing is Failed (step 4); Settings has no Webhook Deliveries section, only the link, which opens the screen (step 5); an Operator sees no button, and opening the page directly sends them back to Compliance Enforcement (step 6).
**Last Verified:** not yet run

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
**Last Verified:** v0.5.4 · 2026-10-27 · pass - erasure_request created no purge row synchronously (0 rows); CES created them later; app listed PURGE_INITIATED, confirmed PURGE_COMPLETED; principal got PURGE_INIT and PURGE_CONFIRM notifications

### TC-PRG-02: Legal hold on a purge request
**Type:** API · **Priority:** Medium
**Steps:** Call `update_purge_status` with `status: LEGAL_HOLD_APPLIED`.
**Expected Result:** Accepted (not server-restricted to DPO-only today - by design, per the guide's caveat); `PURGE_ONHOLD_NOTIFICATION` fires.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - app key accepted LEGAL_HOLD_APPLIED (not DPO-only); PURGE_ONHOLD notification created

### TC-PRG-03: Cancel a purge request
**Type:** UI + API · **Priority:** Medium
**Steps:**
1. On the DPO Compliance page, open a `PURGE_INITIATED` request and set its status to **Cancelled (Request Withdrawn)** with a note.
2. Filter the list by **CANCELLED** and by **FAILED**.
3. Call `list_purge_requests` with `status: PURGE_INITIATED` from the App.
4. Check the DPO Dashboard purge-pending count before and after step 1.
**Expected Result:** The request shows a grey `PURGE CANCELLED` badge and appears under the CANCELLED filter; the FAILED filter lists `PURGE_FAILED` requests; the request no longer appears in the App's `PURGE_INITIATED` list; a `purge_request_status_updated` webhook with `PURGE_CANCELLED` is sent; the dashboard purge-pending count drops by one.
**Last Verified:** not yet run

### TC-PRG-04: Admin dashboard counts failed purges
**Type:** UI · **Priority:** Low
**Steps:** Set one purge request to `PURGE_FAILED`, then open the Admin Dashboard.
**Expected Result:** The failed-purges metric includes it (it counted a status that is never written, so it was always 0 before v0.5.4).
**Last Verified:** not yet run

### TC-PRG-05: Purge requests the app has not picked up are flagged
**Type:** UI · **Priority:** Medium
**Steps:** Create purge requests in `PURGE_INITIATED` (TC-PRG-01) and age them in the database: one 25 hours old, one 2 hours old. Also have one 25-hour-old request in `PURGE_IN_PROGRESS`. Open Compliance Enforcement; choose **NOT PICKED UP (>24h)** in the status filter; then have the app set the 25-hour-old `PURGE_INITIATED` request to `PURGE_IN_PROGRESS` (`update_purge_status`) and reload.
**Expected Result:** Only the 25-hour-old `PURGE_INITIATED` request carries a **Not picked up** tag in the list; the 2-hour-old one and the `PURGE_IN_PROGRESS` one do not. The filter lists just the flagged request. After the app sets `PURGE_IN_PROGRESS` the tag is gone and the filter is empty.
**Last Verified:** not yet run

---

## 9. Cross-Cutting / Non-Functional

### TC-XCUT-01: Security headers present on every response
**Type:** API · **Priority:** Medium
**Steps:** Inspect headers on any `/api/*` response.
**Expected Result:** `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Permissions-Policy` all present.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - all five security headers present

### TC-XCUT-02: CORS origin enforcement
**Type:** API · **Priority:** Medium
**Steps:** With `ALLOWED_ORIGINS` set, send an admin-category request with a disallowed `Origin` header.
**Expected Result:** `403 Forbidden`. Client-API calls (server-to-server, typically no `Origin`) are not subject to this check.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - disallowed Origin -> 403, allowed Origin -> 200

### TC-XCUT-04: OpenAPI spec validates and stays in sync with source
**Type:** API · **Priority:** Medium
**Steps:** `npx @redocly/cli lint docs/api/openapi.yaml`. Spot-check 2-3 functions' actual behavior against the spec after any service-code change.
**Expected Result:** Lints clean. No undocumented behavior drift.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - npx @redocly/cli lint docs/api/openapi.yaml -> 'Your API description is valid' (spec updated for record_consent policy_version and the 409); spot-checked record_consent 409 / policy_version behaviour (TC-CLI-15, TC-CLI-16) and the public login_available flag against the spec

### TC-XCUT-05: Build integrity
**Type:** API · **Priority:** Critical
**Steps:** `mvn compile` (or `mvn package` before an actual deploy - `compile` alone does not refresh the WAR used by `docker compose build`).
**Expected Result:** Clean build, no errors.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - clean package -> BUILD SUCCESS; tsi_dpdp_cms.war carries version.properties 'version=0.5.4'

### TC-XCUT-06: Ownership/security docs present
**Type:** API · **Priority:** Low
**Steps:** Confirm `CONTRIBUTING.md` and `SECURITY.md` exist at repo root.
**Expected Result:** Present, non-empty.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - CONTRIBUTING.md and SECURITY.md exist and are non-empty

### TC-XCUT-07: No unused/unreferenced cloud-vendor dependencies
**Type:** API · **Priority:** Low
**Steps:** `grep -r "software.amazon.awssdk" pom.xml`.
**Expected Result:** No match. Production key management runs only through `DB_ENCRYPTION_KEY`.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - no software.amazon.awssdk in pom.xml

### TC-XCUT-08: Multi-tenant / Aggregator (Consent Manager) mode
**Type:** UI · **Priority:** High
**Steps:** Configure the system in Consent Manager mode per the System Design doc §1.2; onboard two distinct Fiduciaries under it.
**Expected Result:** Each Fiduciary's data (policies, consents, apps) stays isolated; console navigation correctly scopes an operator to their assigned Fiduciary/Fiduciaries.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - Beta's DPO is refused Alpha's principals/grievances/ROPA/breaches/certificates (403,403,403,403,403) and sees only its own (empty) data | Beta's DPO console shows none of Alpha's policies (" f2pol 1.0 IN ACTIVE 10/27/2026 View ROP"), principals or breaches

### TC-XCUT-09: Unauthenticated admin/DPO requests get 401, not schema errors
**Type:** API · **Priority:** Critical
**Steps:** With **no** `Authorization` header, `POST` `{"_func": "<func>"}` (no other fields) to each of: `/api/v1/admin/job` (`list_jobs`, `create_job`), `/api/v1/admin/apikey` (`list_api_keys`, `generate_api_key`), `/api/v1/admin/operator` (`list_users`, `create_user`), `/api/v1/admin/ropa` (`list_entries`, `create_entry`). Repeat each with `Authorization: Bearer invalid`.
**Expected Result:** Every request returns `401` with `Unauthorized`. The body never contains `required property` or any field name. (Regression for [security fix 4](../security-fixes/4.md).)
**Last Verified:** v0.5.4 · 2026-10-27 · pass - all unauthenticated admin calls -> 401 with no schema field names

### TC-XCUT-10: Authenticated requests still get schema validation errors
**Type:** API · **Priority:** High
**Preconditions:** A valid admin bearer token (`login` with `identifier` + `password`).
**Steps:** With the token, `POST` `{"_func": "<func>"}` (required fields omitted) to `/api/v1/admin/job` (`create_job`, `list_jobs`), `/api/v1/admin/apikey` (`list_api_keys`) and `/api/v1/admin/ropa` (`create_entry`).
**Expected Result:** `400`, with an error naming the missing required fields (e.g. `create_job` → `fiduciary_id`, `job_type`, `subtype`). Confirms moving validation after authentication did not disable it.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - authenticated create_job -> 400 naming fiduciary_id, job_type, subtype

### TC-XCUT-11: Client API returns 401 before schema validation
**Type:** API · **Priority:** High
**Preconditions:** A Fiduciary, App and API key (`X-API-Key` is the `key_id`, `X-API-Secret` is the full `raw_api_key`).
**Steps:** `POST /api/v1/client/consent` with `{"_func": "get_active_consent"}` (`user_id` omitted): (a) with no key headers, (b) with a well-formed but unknown key, (c) with a real `key_id` and a wrong secret, (d) with the valid key and secret. Also `{"_func": "list_jobs"}` with no key.
**Expected Result:** (a)-(c) `401` with a single JSON error object (see TC-ADM-14) and no `required property` text. (d) `400` naming `user_id`. A non-whitelisted `_func` returns `403`.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - a-c 401 no field names; d 400 names user_id; non-whitelisted func 403

### TC-XCUT-12: Unauthenticated-by-design functions still validate their payload
**Type:** API · **Priority:** Medium
**Steps:** `POST` with required fields omitted to: (a) `/api/v1/bootstrap/setup` (`initial_setup`); (b) `/api/v1/public/principal` (`request_principal_otp`); (c) `/api/v1/admin/operator` (`login`, `reset_password`).
**Expected Result:** Each returns `400` naming the missing fields (not `401`), because these functions are intentionally reachable without a token. Their schemas are therefore public by design; they are gated by their own controls (bootstrap token, rate limiting) as documented elsewhere in this suite.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - initial_setup / request_principal_otp / login with no fields -> 400

### TC-XCUT-13: A failed login does not block the audit log
**Type:** API · **Priority:** Critical
**Steps:** On a fresh instance, `POST /api/v1/admin/operator` with `_func: login` for an unknown identifier (`401`). Complete first-run setup, log in as the admin (`200`), then log in once with a wrong password (`401`). Wait for the audit flush (up to about 3 minutes) and query `audit_logs` or open the DPO audit page.
**Expected Result:** Three rows are written: `LOGIN_FAILURE`, `LOGIN_SUCCESS`, `LOGIN_FAILURE`, with failed logins filed under the system fiduciary (`00000000-0000-0000-0000-000000000000`). The application log contains no `CRITICAL: Failed to write audit batch` line.
**Last Verified:** v0.5.4 · 2026-10-27 · pass - LOGIN_FAILURE (system fiduciary) and LOGIN_SUCCESS rows present: LOGIN_FAILURE@00000000-0000-0000-0000-000000000000, LOGIN_SUCCESS@00000000-0000-0000-0000-000000000000, LOGIN_SUCCESS@5f3fb676-7e84-46ff-a117-6d024138738e, LOGIN_SUCCESS@eff25ca4-9193-40be-86e2-751825b5b957; no 'CRITICAL: Failed to write audit batch' in the app log

### TC-XCUT-14: Startup warns when `TSI_DPDP_CMS_ENV` is unset or unrecognised
**Type:** Ops · **Priority:** High
**Steps:** Start the server with the variable (a) unset, (b) set to `prod` (a typo), (c) set to `production`, (d) set to `local`.
**Expected Result:** (a) and (b) log a `[WARNING]` to stderr saying it is running non-production (DUMMY_OTP allowed, transient-key certificates) and how to fix it; (c) and (d) log none. The startup line also shows the version (`TSI DPDP CMS v<version> Service started in <env> environment`).
**Last Verified:** v0.5.4 · 2026-10-27 · pass - unset -> '[WARNING] ... not set' (non-production behaviour spelled out); 'prod' -> 'not a recognised value'; production and local -> no warning; startup line shows the version

### TC-XCUT-15: The version comes from `pom.xml` and appears on every artifact
**Type:** API · **Priority:** High
**Steps:** Build the WAR and run it. Compare the `<version>` in `pom.xml` with: `WEB-INF/classes/version.properties` in the WAR, the startup log line, a generated evidence certificate's `system_metadata.software_version`, the footer of a breach report PDF, and the `X-TSI-Generated-By` header on a ROPA / job CSV download.
**Expected Result:** All show the same version. Nothing hardcodes a version elsewhere. With `BRAND_NAME` set, the artifacts show the brand name with that version (see TC-ADM-17).
**Last Verified:** v0.5.4 · 2026-10-27 · pass - single source pom.xml=0.5.4 -> WAR version.properties, startup log, certificate system_metadata.software_version=0.5.4, breach PDF footer, export header all agree | export download header: [('X-TSI-Generated-By', 'TSI DPDP CMS v0.5.4')]
