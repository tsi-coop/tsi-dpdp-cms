# Java changes to close the Intelehealth gaps

Companion to [dpdp-compliance-gaps-vs-intelehealth.md](dpdp-compliance-gaps-vs-intelehealth.md). Each item says what to change in this repo. Reference implementation: `Intelehealth/intelehealth-cmp-tsi` `origin/main` (Python); the file names below point to what to read there. Nothing here was prototyped. Next free migration is `db/18_*.sql`.

## 1. Audit ledger (P1, small)

| Change | Where |
|---|---|
| `db/18_audit_ledger_integrity.sql`: `BEFORE UPDATE OR DELETE` and `BEFORE TRUNCATE` triggers on `audit_logs` that raise. Also `REVOKE UPDATE, DELETE, TRUNCATE` from the app role. | New. Ref: `db/19_audit_ledger_integrity.sql` |
| Serialise chain writes: take `pg_advisory_xact_lock(<const>)` before reading the chain head and inserting. Check that the `EventLog` batch re-queue cannot fork the chain. | `framework/EventLog.java`, `service/v1/Audit.java` |
| Hash every stored column; use strictly increasing UTC timestamps. Keep reading old rows as linkage-only. | Same |
| `verify_audit_chain` function (ADMIN: whole chain; DPO: report filtered to own tenant, walk the unfiltered chain). Add `.jschema` and a permission mapping. Reuse the walker already in `Legal.java`. | `Audit.java`, `Legal.java`, `web/WEB-INF/validator/` |
| Daily `JobManager` task that verifies and stores a verdict (`audit_chain_verifications`); show BROKEN on the console audit page. | `job/JobManager.java`, `web/console/dpo/audit.html` |
| Delete floor (365 days) triggers on `notification_deliveries`, `webhook_deliveries`, `notifications`. | Same migration |
| Later (P2): yearly partitioning and archive of `audit_logs`. Do it after the principal-ID work so the table is rewritten once. | Ref: `db/32`, `db/33` |

## 2. Principal data protection (P1, large)

Reuse the existing pgcrypto scheme from `db/04_gaps.sql` (`_enc` plus `_hmac`) and `DbEncryption.decryptCol`.

1. **Migration `db/19_principal_pii_encryption.sql`.** For every table with a principal `user_id`/`guardian_id` (consent_records, data_principal, grievances, purge_requests, notifications, parental_verification_logs, breach affected-principals, jobs input, webhook/notification logs): add `<col>_enc`, `<col>_hmac`, backfill, drop the plaintext, rebuild keys and indexes on the HMAC (`idx_unique_active_consent`, `data_principal` PK, history indexes). Abort if rows exist and `app.enc_key` is unset. Ref: `db/34_principal_pii_encryption.sql`.
2. **Helper class** `util/PrincipalId.java`: `hmac(value)` (trim, keep case), `encrypt`, `decrypt`, `mask`. Replace every `WHERE user_id = ?` with `user_id_hmac = ?` across the 25 files that touch it (`Consent`, `Principal`, `Grievance`, `Compliance`, `Notification`, `Breach`, `Wallet`, `Legal`, `AdminDash`, `CESService`, `WebhookDispatcher`, `JobManager`, ...). Ref: `pii.py`, `services/pii.py`.
3. **Separate key** `PII_LOOKUP_KEY` for the HMAC; refuse to start in production without a distinct one. Add a `RekeyLookup` utility. Ref: P16-04.
4. **Audit ledger:** store principal-valued keys in `context_details` as the existing `LookupHasher` pseudonym; encrypt `source_ip` (hash covers the ciphertext).
5. **Encrypt** `consent_records.ip_address` (currently `INET`, so the column type changes to TEXT), guardian `verification_ref_id` and `proof_metadata`.
6. **Masking in console responses:** operator-facing endpoints return masked IDs and no IPs. Only API-key callers (own tenant), PURGE-scope processors and the principal themselves get plaintext.
7. **Reveal:** new `service/v1/Pii.java` with `reveal_user_id` (permission `pii:reveal`, DPO own tenant, ADMIN any; never API key or principal token). Write the `PII_REVEALED` audit row first, then return the value. Cap 20/min and 200/24 h per operator; alert at 50/hour. Ref: `services/pii.py`, P15, P16-05.
8. **Certificates:** sign `principal_id_hmac`, not the plaintext. Keep the PKCS12 asymmetric signing in `Legal.java`; do not move to HMAC signing.
9. Document in a new `docs/security/KEY_MANAGEMENT.md` that `DB_ENCRYPTION_KEY` loss makes principals unattributable and rotation needs a re-encrypt migration.

## 3. Operator access (P1, medium)

| Change | Where |
|---|---|
| **TOTP MFA** for operators: `operators.mfa_secret_enc`, `mfa_enabled`, `mfa_last_step`. Functions `enrol_mfa`, `verify_mfa`; login returns an MFA challenge; accept each step once; lock 15 min after 5 bad codes; refuse re-enrolment on an MFA-enabled account; revoke older tokens on first enrolment. Require `mfa=true` claim for audit reads. | `Operator.java`, `framework/JWTUtil.java`. Ref: `totp.py`, defects #3, #8 |
| **Roles and permissions table** (`roles`: name, `fiduciary_id`, permissions array). Seed ADMIN (`*`), DPO, OPERATOR, **AUDITOR** (read-only). Map each `(service, _func)` to `<resource>:read\|write\|manage` and deny by default. A role creator cannot grant what they do not hold. Replace the hard-coded role checks in `Operator.java` and the scope map in `InterceptingFilter.java` (extend the existing `CLIENT_FUNC_SCOPES` idea to an admin map). | `InterceptingFilter.java`, `Operator.java`, new `service/v1/Role.java`. Ref: `services/roles.py`, `db/16` |
| **Tenant binding:** a non-ADMIN operator with NULL `fiduciary_id` is refused at authentication; `fiduciary_id` in the request body is overwritten from the token for fiduciary-scoped operators; every by-id read and write adds `AND fiduciary_id = ?`. Audit each `service/v1/*.java` for by-id queries without it. | `InterceptingFilter.java`, all services |
| **Token typing:** add `typ` (`operator` or `principal`) to `JWTUtil.generateToken`; admin routes require `operator`. | `JWTUtil.java`, `InterceptingFilter.java` |
| **Revocation on password change or deactivation:** `operators.tokens_valid_after`, checked next to `TokenBlocklist`. | `Operator.java`, `TokenBlocklist.java` |
| **Recovery throttling:** put the recovery-key verify and reset paths behind `LoginRateLimiter`, keyed by HMAC of the lower-cased email and by IP, escalating locks; honour `X-Forwarded-For` only behind `TRUSTED_PROXY_IPS`. | `AdminSetup.java`/`Operator.java`, `LoginRateLimiter.java` |
| **Startup guard:** refuse published dev defaults for secrets when `TSI_DPDP_CMS_ENV` is not local. | `util/Env.java` |
| P2: OIDC SSO (`sso_login`, nonce), `list_access_report`, API-key expiry swept to EXPIRED. | `Operator.java`, `ApiKey.java` |

## 4. Data Principal rights and purpose lifecycle (P1, medium-large)

| Change | Where |
|---|---|
| **Nominations (s.14):** table `nominations` (principal, nominee name/contact encrypted, `valid_from`, `valid_until`, status PENDING/ACTIVE/EXPIRED/REVOKED); client functions `create_nomination`, `list_nominations`, `revoke_nomination`; sweep to expire. Add to rights portal. | New `service/v1/Rights.java`, `JobManager`, `web/rights/`. Ref: `rights.py`, `db/14` |
| **Access (s.11) and correction (s.12) requests:** one `rights_requests` table with a `type` column (ACCESS, CORRECTION), statuses NEW/IN_PROGRESS/FULFILLED/REJECTED, a per-type SLA `due_date` and an assigned DPO. API `submit_rights_request`, `get_rights_request`, `list_user_rights_requests`, `list_rights_requests`, `assign_rights_request`, `update_rights_request_status`; a "My Rights" section in the rights app; a DPO console page with a read-only data-map panel; submit, fulfil and reject notifications and audit events. Replace the bare `CORRECTION_REQUEST` and `DATA_ACCESS_REQUEST` grievance options and remove the stray `ERASURE_REQUEST` option. Full design: `access-and-correction-requests.md`. | `Rights.java` (or `RightsRequest.java`), `Notification.java`, `Constants.java`, `web/rights/dashboard.html`, `web/console/dpo/` |
| **Purpose lifecycle:** table `purpose_states` (OPEN/CLOSED); `set_purpose_state`, `close_purpose`, `list_purpose_lifecycle`. Closing invalidates consents on that purpose, defers to the governing retention period, then raises a purge with `action` ERASE or DE_IDENTIFY. `record_consent` refuses to grant a closed purpose (403) but allows declining it. | New `Purpose.java`, `Consent.java`, `Compliance.java`. Ref: `services/lifecycle.py` |
| **Re-consent:** `request_reconsent`, `notify_policy_change`; notify only after the new version is ACTIVE (this is also open in `gaps.md` P10-02). | `Policy.java`, `Ropa.java` |
| **Withdrawal implications** endpoint (per-purpose consequence, mandatory flag, legal retention). | `Consent.java` |
| **Decide DD-01/DD-05** first: open-ended consent plus a named quarterly purpose review. Adapt Intelehealth's register and `PURPOSE_VALIDITY_REVIEW.md`, do not copy its clinical decisions. | `docs/` |

## 5. Consent capture (P1/P2, small-medium)

All in `Consent.java` (`record_consent`, around L120-180).

- **Evidence:** `consentMechanism` is hard-coded `CONSENT_GIVEN` (L129) and `user_agent` is read from the body (L131). Take `User-Agent` from the request header, set mechanism from the authenticated path, and move caller claims into a `client_metadata` JSON column. IP is already `req.getRemoteAddr()`; add a trusted-proxy-aware resolver so nginx deployments do not store the proxy's address.
- **Explicit choices:** require a `consent_granted` boolean for every declared purpose (no omission, duplicates or defaults).
- **Append on withdrawal:** keep history with `supersedes_record_id` rather than overwrite. Relax `idx_unique_active_consent` to `(user_id_hmac, fiduciary_id, policy_id)` if you adopt one active consent per policy (decision needed).
- **Minors:** read the stored `age_category`; a stored MINOR cannot be declared ADULT; require a `VERIFIED` guardian log; remove `age_category`, `verification_status`, `guardian_id` from `link_user` input. Verify `EXISTING_ACCOUNT` (guardian is an adult principal of the fiduciary); `DIGILOCKER` through a configured verifier URL.
- **Grievances:** add `channel`, `reference_number`, `consent_record_id`, auto-assign to the tenant's DPO, an upload function with type allow-list and size limit, resolution summary required, feedback function (`Grievance.java`; `db/18`+).

## 6. Erasure, retention and breach (P1, small-medium)

- `confirm_purge_status`: derive the confirming identity from the credential, require the API key's app to match the purge's `app_id`, store the processor's claimed count apart from CMS-verified counts, and let only an operator confirm a whole-account erasure (`Compliance.java`).
- `erasure_request` via API key: require an existing consent record for that principal.
- Review `erase_cms_copy` equivalent against every principal table (including the new ones). Run the `gaps.md` section 4 cases first (P7-01, P8-01, P8-02).
- Retention policy CRUD with a 7-year floor judged in the policy's own unit; time-bound legal hold released by a sweep; unconfirmed purges past `PURGE_COMPLETION_SLA_DAYS` flagged to the DPO (`Compliance.java`, `JobManager.java`).
- **Board intimation:** add `board_notification_deadline`, `board_notified_at` to breaches (alongside the existing `BreachDeadline`), a DPO action to record the intimation, and sweep alerts `BREACH_BOARD_DEADLINE_DUE/MISSED`. Ref: `jobs.flag_breach_board_deadlines`.

## 7. Assurance (P1, run in parallel with the above)

1. Add JUnit 5 and Mockito to `pom.xml`; add `src/test`. Start with a regression test per item in this file and per open case in `gaps.md` section 4. Add DB-backed tests against Postgres (Testcontainers or the compose DB).
2. CI: GitHub Actions running `mvn verify` and a Docker build. Ref: Intelehealth `.github/workflows/main.yml`.
3. Pen-test suite (auth, authorisation, injection, SSRF, transport, lockout, reveal). Port the cases from `python_port/pentest/` as HTTP tests; write a plan and report under `docs/security/`.
4. Docs under `docs/security/`: `ISMS_CONTROL_MAP.md` (Rule 6(1)(a)-(g) to control, owner, evidence), `KEY_MANAGEMENT.md`, `LOG_RETENTION.md`, `MONITORING_AND_REVIEW.md`, `OUTBOUND_DESTINATIONS.md`, `BREACH_RESPONSE_RUNBOOK.md`, `PURPOSE_VALIDITY_REVIEW.md`, and a DPO decision register with named owners.

## Suggested order

1. Section 1 and the section 5 evidence fixes (small, no schema risk beyond triggers).
2. Section 7.1-7.2 so later work lands with tests.
3. Section 3 (MFA, roles, tenant binding, token typing).
4. Section 6 (purge binding, board intimation).
5. Section 4 (nominations, correction, purpose lifecycle).
6. Section 2 last and alone: it rewrites most queries and needs a tested migration, a key-loss note and a release of its own. Ship the reveal, masking and audit pseudonyms in the same release.

---

# Release plan

Core feature changes ship in v0.6. Cross-cutting changes ship in v0.7. The sections above give the detail for each row; section numbers are in brackets. The Intelehealth port has changed since this plan was first written (its P12 to P17 rounds); the v0.7 table picks up those changes.

## v0.6: core features

| Item | Type | Notes | Status |
|---|---|---|---|
| Stale policy cache after publish (P1) | Fix | Key the policy cache by `policy_id` + version in `Policy.java`. Call `policyCache.remove(...)` on publish, update and delete. Fix `get_policy` returning DRAFT instead of ACTIVE until restart. Write a failing test first. | Open |
| Audit ledger (P1) [1] | Feature | Advisory lock so the chain stays linear. Hash `service_type`, `service_id` and `eventtime`, with a `hash_version` column. Block UPDATE, DELETE and TRUNCATE on `audit_logs`. `verify_audit_chain` plus a daily verifier job. Write security events synchronously. 365-day delete floors on notification and webhook delivery tables. | Open |
| Operator access (P1) [3] | Feature | TOTP MFA, mandatory for ADMIN and DPO. Roles and permissions table with an AUDITOR role, deny by default, no escalation. Tenant binding. Token typing, configurable TTL, no `?auth=` URLs. Revoke tokens on password change or deactivation. Rate-limit recovery-key paths. Startup guard against dev-default secrets. | Open |
| Consent capture (P1/P2) [5] | Feature | `User-Agent` from the header, mechanism from the auth path. `client_metadata` column and a trusted-proxy-aware IP resolver. Explicit `consent_granted` for every declared purpose. Keep history on withdrawal with `supersedes_record_id`. Minors use the stored `age_category` and a VERIFIED guardian log; `link_user` stops accepting age or guardian fields. Grievance channel, reference number, DPO auto-assign, attachments, required resolution summary, feedback. | Open |
| Data Principal rights and purpose lifecycle (P1) [4] | Feature | Nominations (s.14). Access (s.11) and correction (s.12) requests through one `rights_requests` table, API, rights app section, DPO console and data-map panel. Purpose lifecycle (`purpose_states`): close, invalidate consents, defer to retention, then erase or de-identify. Refuse a grant on a closed purpose (403); allow declining. Re-consent only after the new version is ACTIVE; mark the old version SUPERSEDED. Withdrawal-implications endpoint. Decide DD-01 and DD-05 first. | Open |
| Erasure, retention and breach (P1) [6] | Feature | `confirm_purge_status` takes identity from the credential, binds to the purge's app, stores claimed and verified counts separately. `erasure_request` via API key needs an existing consent record. Erasure covers every principal table (`ERASURE_TARGETS` list and a test). Retention policy CRUD with a 7-year floor and time-bound legal hold. Flag purges past `PURGE_COMPLETION_SLA_DAYS`. Breach Board intimation: 72-hour deadline, `board_notified_at`, DPO action, sweep alerts. Fix the date-only `Instant.parse` in `Consent.java:454`. | Open |
| Principal data protection (P1) [2] | Feature | Encrypt principal and guardian IDs and look them up by HMAC columns. Separate `PII_LOOKUP_KEY` and a `RekeyLookup` utility. Encrypt `consent_records.ip_address` and guardian proof fields. Mask IDs and IPs in console responses. `reveal_user_id` behind `pii:reveal`, audit row first, with rate limits (20 per minute, 200 per 24 hours, alert at 50 per hour). Pseudonymise principal keys in audit logs and webhook payloads. Sign certificates over the HMAC. Write `KEY_MANAGEMENT.md`. Rewrites most queries: build it last in the release, behind its own tested migration and rollback plan. | Open |

## v0.7: cross-cutting changes

| Item | Type | Notes | Status |
|---|---|---|---|
| Test harness and CI (P1) [7] | Feature | JUnit 5, Mockito and Testcontainers; `src/test`; GitHub Actions running `mvn verify` and a Docker build. A regression test per item in the v0.6 and v0.7 tables. If possible, land the harness and CI at the start of v0.6 work so v0.6 fixes ship with tests; the release stays v0.7 for the full suite. | Open |
| Outbound and SSRF hardening (P1) | Fix | `OUTBOUND_ALLOWED_HOSTS` allow-list for webhooks, SMS and push gateways; refuse empty or `*` outside local. Connect to the validated IP with no second DNS lookup and no redirects. Judge IPv4-mapped, NAT64, 6to4 and Teredo IPv6 by the IPv4 address they embed. | Open |
| Tenant isolation in depth (P1) | Feature | Row-level security on tenant tables with a tenant reader role. A key stops working when its fiduciary is inactive. Issue an API key only after the app records its contact details. Centralise the tenant check into one class and add a DB `CHECK` for non-ADMIN operators. Add a cross-tenant test for every by-id query. | Open |
| Erasure correctness (P1) | Fix | Order the metadata scrub before the generic re-key loop in the erasure path. Re-key to a random token per erasure. Purpose-scoped de-identify path. Fix the legal-hold check race. Delete grievance attachments on whole-account erasure. | Open |
| Consent record immutability (P1) | Feature | Make `consent_records` append-only at the database level, with an opt-in maintenance guard. | Open |
| Operator-initiated actions (P2) | Feature | A console operator's withdrawal or erasure request needs a grievance reference or a written reason of at least 10 characters. Audit it as `OPERATOR:<id>` with service type `DPO_CONSOLE`. | Open |
| Alerts and anomaly sweeps (P2) | Feature | An alerts service (notify, acknowledge, list). Sweeps flag bulk PII reveals, repeated audit reads and failed logins. Log an `AUDIT_LOG_READ` event for every audit read. | Open |
| Health and heartbeat (P2) | Feature | `/healthz` and a worker heartbeat so a stalled background job is visible. | Open |
| Web hardening (P2) | Fix | Escape all console output. HSTS and related security headers. CSV formula-injection defence. Reject malformed JSON bodies. Every service function has a `.jschema` and validation fails closed. | Open |
| Supply chain (P2) | Feature | OWASP dependency-check or an SBOM in CI, plus pinned dependency versions. | Open |
| Audit archive and continuity (P2) | Feature | Yearly partitioning and archive of `audit_logs` (do it after the principal-ID work). `BACKUP_AND_CONTINUITY.md` and a restore test that recomputes the audit chain after a restore. | Open |
| Pen-test suite (P1) | Feature | Port the cases from `python_port/pentest/` as HTTP tests. Publish a plan and a dated report under `docs/security/`. Commission an external test before relying on it. | Open |
| Security documentation (P1) | Feature | Adapt, do not copy, from Intelehealth: `ISMS_CONTROL_MAP.md`, `LOG_RETENTION.md`, `MONITORING_AND_REVIEW.md`, `OUTBOUND_DESTINATIONS.md`, `BREACH_RESPONSE_RUNBOOK.md`, `PURPOSE_VALIDITY_REVIEW.md`, and the DPO decision register with named owners. `KEY_MANAGEMENT.md` ships with principal data protection in v0.6. | Open |

Deferred (P2, not in either release): OIDC SSO, `list_access_report`, API-key expiry sweep, persisted per-principal OTP lockout for multi-instance deployments.

---

# Exact implementation steps

Written after reading the Java code paths involved. Class and file names are real; SQL and code are sketches to adapt, not tested. Do the phases in order. Every phase ends with tests (see Phase 0).

## Facts about the current Java code that shape the steps

| Fact | Where | Consequence |
|---|---|---|
| Audit chain is serialised only by `synchronized` on one JVM and a cached `lastKnownHash`. The hash covers fiduciary, user, action, time and details, but **not** `service_type`, `service_id`. Head is read with `ORDER BY timestamp DESC`. | `Audit.logEvents`, `calculateHash`, `initLastKnownHash` | Two app instances can fork the chain. Use a DB lock and a tie-break on the head query. |
| `EventLog` is an empty class. Audit entries are queued in memory and flushed in batches. | `framework/EventLog.java`, `Audit.logEventAsync` | A crash loses queued events. Consider flushing synchronously for security events (login, reveal, purge). |
| Admin tokens last 10 days; `TokenBlocklist` is in memory, lost on restart. Admin auth also reads the token from `?auth=` when no header is present. | `JWTUtil.EXPIRATION_TIME`, `TokenBlocklist`, `InputProcessor.getAdminAuthToken` | Cut the TTL, persist revocation, delete the query-string path. |
| Token typing exists only as a deny-list (`SYNC`, `PRINCIPAL` rejected). Untyped tokens pass. The `type` claim is also used by `generateAppLoginToken`. | `JWTUtil.isTokenValid` | Switch to an allow-list on a new claim, not `type`. |
| Tenant check is a private `rejectIfNotOwnFiduciary` copied into `Legal`, `Ropa`, `Audit` and others, each querying `operators`. | `service/v1/*` | Centralise it; add a test that every by-id query is tenant-scoped. |
| `LoginRateLimiter` is in memory, keyed by raw strings. The API client cache key is `apiKey + ":" + apiSecret`. | `LoginRateLimiter`, `InputProcessor.isValidApiClient` | Fine for one instance; move to a DB table for HA. Stop putting the secret in a map key (hash it). |
| `operators.status` already allows `PENDING_MFA_SETUP`; no MFA columns exist. | `db/01_init.sql` | Placeholder only. |
| Console login sets a session cookie. | `InputProcessor.setConsoleSessionCookie` | Matters for the DD-04 "no cookies" decision; decide before copying it. |
| `DbEncryption.HMAC` lower-cases and trims; the pgcrypto helpers take `(value, key)` bind pairs. | `framework/DbEncryption.java` | Principal IDs: Intelehealth keeps case (OTP subjects are case-sensitive, commit `aadeb9f`). Add a case-preserving variant. |

## Phase 0: test and CI harness (do first)

1. `pom.xml`: add test-scope `org.junit.jupiter:junit-jupiter`, `org.mockito:mockito-core`, `org.testcontainers:postgresql`, `org.testcontainers:junit-jupiter`; add `maven-surefire-plugin` 3.x.
2. Create `src/test/java/org/tsicoop/dpdpcms/`. Add `DbTestBase` that starts Postgres 17 via Testcontainers, runs `db/01..N` in order with `app.enc_key` set, and exposes a `PoolDB`.
3. Make `PoolDB` and `DbEncryption` testable: read config from system properties as a fallback to env (`DbEncryption` throws at class load if `DB_ENCRYPTION_KEY` is unset).
4. `.github/workflows/ci.yml`: `mvn -B verify`, then `docker build .`, on every push and pull request.
5. Write the first tests as characterisation tests for the current behaviour: audit chain intact after a batch, tenant rejection on a cross-tenant `get_*`, withdrawal scoped by purpose. Then add one test per change below before making the change.

## Phase 1: audit ledger (migration `db/18_audit_ledger_integrity.sql`)

1. Migration:
   ```sql
   CREATE OR REPLACE FUNCTION tsi_audit_immutable() RETURNS trigger AS $$
   BEGIN RAISE EXCEPTION 'audit_logs is append-only: % not permitted', TG_OP; END $$ LANGUAGE plpgsql;
   CREATE TRIGGER trg_audit_no_update_delete BEFORE UPDATE OR DELETE ON audit_logs
     FOR EACH ROW EXECUTE FUNCTION tsi_audit_immutable();
   CREATE TRIGGER trg_audit_no_truncate BEFORE TRUNCATE ON audit_logs
     FOR EACH STATEMENT EXECUTE FUNCTION tsi_audit_immutable();
   ```
   Also add a monotonic `seq BIGSERIAL` column so the chain head is `ORDER BY seq DESC`, not timestamp.
2. Same migration: 365-day delete floor triggers on `notification_deliveries`, `webhook_deliveries`, `notifications` (`BEFORE DELETE ... WHEN (OLD.created_at > NOW() - INTERVAL '365 days')` raise). Check each table's timestamp column name first.
3. `Audit.logEvents`: after `conn.setAutoCommit(false)`, run `SELECT pg_advisory_xact_lock(727001)`; then read the head with `SELECT current_log_hash FROM audit_logs ORDER BY seq DESC LIMIT 1` **inside the same transaction** on every flush (drop the cached `lastKnownHash`). This removes the fork risk across instances and the "reset to null on failure" workaround.
4. `Audit.calculateHash`: add `service_type`, `service_id`, `eventtime` as stored. Bump a `hash_version` column (default 1 for old rows, 2 for new); the verifier branches on it, so old rows are checked for linkage only.
5. New `Audit` function `verify_audit_chain`:
   - Walk rows in `seq` order in pages of 5,000; recompute hash by `hash_version`; check `prev_log_hash` equals the previous row's `current_log_hash`.
   - Return `{rows_checked, rows_verified, legacy_linkage_only, first_break_id}`.
   - ADMIN sees the whole report. A DPO walks the **unfiltered** chain but gets only counts and broken-row ids for their fiduciary (filtering first reports false breaks; Intelehealth P6-01).
   - Add `web/WEB-INF/validator/verify_audit_chain.jschema` and add the function to the admin permission map.
6. `JobManager`: add a daily task that runs the verifier and inserts into `audit_chain_verifications(id, run_at, verdict, rows_checked, first_break_id)`; make it append-only too. `web/console/dpo/audit.html`: show the latest verdict and a "Verify" button.
7. Security events (`LOGIN_*`, `PII_REVEALED`, purge confirmation) must not be lost on crash: add `Audit.logEventSync(...)` that writes in the caller's transaction path and use it for those.
8. Tests: UPDATE/DELETE/TRUNCATE on `audit_logs` fail; two threads flushing concurrently produce one linear chain; tampering a `context_details` value makes `verify_audit_chain` report a break.

## Phase 2: consent evidence and quick fixes (no schema risk)

`Consent.record_consent` (about L120-180):

1. Replace `userAgent = (String) input.get("user_agent")` with `req.getHeader("User-Agent")`; keep the body value as `client_metadata.user_agent`.
2. Add `client_metadata JSONB` to `consent_records` (migration `db/19`); store `{ "user_agent": ..., "ip_address": ..., "session_id": ... }` claimed by the integrator.
3. Set `consentMechanism` from the authenticated path: `PRINCIPAL_PORTAL` when `auth_via_principal_jwt` is set, `API_INTEGRATION` for an API key.
4. IP: use `LoginRateLimiter.getClientIp(req)` (it already honours `TRUSTED_PROXY`) for the stored IP, not `req.getRemoteAddr()`.
5. Require `consent_granted` as a boolean for every purpose declared in the policy's block for the chosen language; reject missing, duplicate or unknown purpose ids with 400. Today `data_point_consents` is taken as given.
6. `link_user`: remove `age_category`, `verification_status`, `guardian_id` from input (and its `.jschema`); `INSERT ... ON CONFLICT DO UPDATE` must never overwrite a stored value with a default.
7. Minors: in `record_consent`, read the stored `age_category`; if MINOR, require a `parental_verification_logs` row with `VERIFIED` status and refuse a body that declares ADULT.
8. Tests for each of the above.

## Phase 3: operator security

### 3a. Token hardening
1. `JWTUtil`: add claim `typ` (`OPERATOR`) in `generateToken`; add `isOperatorToken`. In `isTokenValid` require `typ == OPERATOR`, but accept untyped tokens issued before a `TOKEN_TYPING_START` instant (process start) so deployed sessions survive the upgrade.
2. `EXPIRATION_TIME`: 10 days to a configurable `TOKEN_TTL_MINUTES` (default 480).
3. `InputProcessor.getAdminAuthToken`: delete the `req.getParameter("auth")` branch. Check `web/console` and `Job` GET export for callers; replace them with an authenticated fetch that returns bytes (Intelehealth P6-03 returns the file base64 in JSON).
4. Revocation: migration `db/20_session_revocation.sql`: `revoked_tokens(jti PK, expires_at)` and `operators.tokens_valid_after TIMESTAMPTZ`. `TokenBlocklist.revoke` writes both memory and DB; `isRevoked` checks memory then DB; a cleanup task deletes expired rows. In `isTokenValid`, reject when `iat < tokens_valid_after` for that operator. Set `tokens_valid_after = NOW()` on password change, deactivation, MFA first enrolment.
5. Startup guard in `util/Env`: outside `local`, refuse to start if `JWT_SECRET`, `DB_ENCRYPTION_KEY`, `TSI_LOOKUP_SALT` are shorter than 32 characters or equal a published dev value.
6. Recovery paths (`verify_recovery_key`, reset): wrap in `LoginRateLimiter` with keys `recovery:email:<hash>` and `recovery:ip:<ip>`; audit each attempt. Key by an HMAC of `lower(trim(email))`, never the raw address.

### 3b. TOTP MFA
1. Migration `db/21_operator_mfa.sql`:
   ```sql
   ALTER TABLE operators
     ADD COLUMN mfa_secret_enc TEXT, ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
     ADD COLUMN mfa_enrolled_at TIMESTAMPTZ, ADD COLUMN mfa_verified_at TIMESTAMPTZ,
     ADD COLUMN mfa_last_counter BIGINT, ADD COLUMN mfa_failed_attempts INT NOT NULL DEFAULT 0,
     ADD COLUMN mfa_locked_until TIMESTAMPTZ;
   ```
2. `framework/Totp.java` (no new dependency): base32 encode/decode, HMAC-SHA1 via `javax.crypto.Mac`, 6 digits, 30 s step, window of one step either side, constant-time compare. Port from Intelehealth `totp.py` (about 60 lines). Unit-test with the RFC 6238 vectors.
3. `Operator.java`: new functions
   - `enrol_mfa`: refuse if `mfa_enabled` unless the token has `mfa=true` (and then still refuse to replace: 409). Generate a secret, store it with `DbEncryption.ENCRYPT`, set `mfa_enabled=false`, return the `otpauth://totp/<issuer>:<email>?secret=...&issuer=...` URI.
   - `verify_mfa`: load the caller's own secret only; if `mfa_locked_until > now` return 429; find the matching counter; accept only when `counter > mfa_last_counter` (single-use), via `UPDATE ... WHERE mfa_last_counter IS NULL OR mfa_last_counter < ?`; on failure increment `mfa_failed_attempts` and lock for 15 min at 5; on success set `mfa_enabled=true`, set `tokens_valid_after` if it was the first enrolment, and return a token with claim `mfa=true`.
4. `handleLogin`: if `mfa_enabled`, issue a token with `mfa=false` and return `mfa_required: true`.
5. `InterceptingFilter` admin branch: after `processAdminHeader`, if the operator has MFA enabled and the token's `mfa` claim is not true, return 403 unless `func` is `verify_mfa`, `logout`. Read the flag in the same query that loads the operator, not from the token.
6. `Audit` read functions require `mfa=true` for any role (when MFA is enabled for the account).
7. Policy: make MFA **mandatory for ADMIN and DPO** (a Java improvement over the port): login returns `mfa_enrol_required` until enrolled; add a `MFA_REQUIRED_ROLES` setting.
8. Console: login page second step; a profile page to enrol (QR via the `qrcodejs` already vendored under `web/`, if present).
9. Tests: RFC vectors; replay of the same code fails; 5 wrong codes lock; password-only token is refused on every admin function except `verify_mfa`/`logout`.

### 3c. Roles and permissions
1. Migration `db/22_roles.sql`: `roles(id, name, fiduciary_id NULL, permissions TEXT[], builtin BOOLEAN, UNIQUE(name, fiduciary_id))`; seed ADMIN `{*}`, DPO, OPERATOR, AUDITOR (all `*:read` plus `audit:read`). Add `operators.role_id`, backfill from `operators.role`; keep `role` as a display copy.
2. New `util/Permissions.java` holding one table `Map<"service.func", "resource:action">` generated from the existing `*.java` `switch (func)` blocks. A function with no entry needs `*` (deny by default). Verbs `get_`, `list_`, `export_`, `verify_` map to `read`; everything else to `write`; `validate_*` is `write` where it logs or notifies (Intelehealth D11).
3. `InterceptingFilter`: after authentication, `Permissions.require(operator, service, func)`; 403 otherwise. Load permissions in the same query as the operator record.
4. New `Role.java` service (`create_role`, `update_role`, `delete_role`, `list_roles`): a caller can only grant permissions they hold; a non-global caller creates roles only for their own fiduciary; global roles need `*`.
5. Remove the scattered `"ADMIN".equalsIgnoreCase(...)` checks one service at a time, replacing them with permission checks; keep the tenant check separate.
6. Tests: AUDITOR can read audit and cannot write; role creator cannot escalate; every `case` string in every service appears in `Permissions` (fails the build when a new function is added without a mapping).

### 3d. Tenant binding
1. Create `framework/Tenant.java` with `UUID callerFiduciary(req)` and `boolean denyIfNotOwn(UUID fid, req, res)`. Resolve once per request in `InterceptingFilter` and put in a request attribute; delete the per-service copies in `Legal`, `Ropa`, `Audit`, `Compliance`, `Breach`, and others.
2. In `InterceptingFilter`, for a non-ADMIN operator overwrite `fiduciary_id` in the body with the operator's own; refuse (403) a non-ADMIN operator whose `fiduciary_id` is NULL.
3. Migration `db/23_operator_tenant_guard.sql`: `UPDATE operators SET status='INACTIVE' WHERE role <> 'ADMIN' AND fiduciary_id IS NULL`, plus `CHECK (role = 'ADMIN' OR fiduciary_id IS NOT NULL)`.
4. Audit every by-id read and write (`WHERE id = ?`) for a missing `AND fiduciary_id = ?`: `grep -n "WHERE id = ?" service/v1/*.java`, and add a cross-tenant test for each.

## Phase 4: purge, erasure, breach

1. `Compliance.update_purge_status` / `confirm_purge_status`: take the confirming identity from the authenticated credential (`X-API-Key` row or operator id), never from the body. Require `apps.id = purge_requests.app_id` for API keys. A whole-account erasure (purpose `ALL`) can only be confirmed by an operator.
2. Store `claimed_record_count` (processor) and `verified_record_count` (CMS) in separate columns.
3. `Consent.erasure_request` via API key: refuse (404) when no `consent_records` row exists for that principal and fiduciary.
4. Walk `gaps.md` section 4: write failing tests for P7-01, P8-01, P8-02, P10-01/04, P11-03, P10-02, P12-01 and fix what fails. `Consent.java:454` `Instant.parse(expiryStr)` must accept date-only.
5. Erasure coverage: list every table with a principal column (`grep -n "user_id\|guardian" db/*.sql`); write one `ERASURE_TARGETS` list in code; a test creates a row in each and checks none survives an erasure.
6. Breach Board intimation: migration `db/24_breach_board.sql` adds `board_notification_deadline` (= detection + 72 h, configurable, reuse `BreachDeadline`) and `board_notified_at`, `board_reference`. `Breach` gets `record_board_intimation`. A `JobManager` sweep raises an alert and DPO notice as the deadline nears (due at 12 h left) and when missed. Show on the dashboard and in the PDF.
7. SLA: `JobManager` sweep flags purge requests older than `PURGE_COMPLETION_SLA_DAYS` still not confirmed.

## Phase 5: Data Principal rights and purpose lifecycle

1. Migration `db/25_rights.sql`: `nominations(id, fiduciary_id, user_id_hmac, nominee_name_enc, nominee_contact_enc, valid_from, valid_until, status, created_at)`; `rights_requests(id, fiduciary_id, user_id_hmac, type, description, status, due_date, assigned_dpo_user_id, outcome_note, submission_timestamp, resolution_timestamp, last_updated_at)` with indexes on `(fiduciary_id, submission_timestamp DESC)`, `(fiduciary_id, user_id_hmac, submission_timestamp DESC)` and `(status, due_date)`; `purpose_states(fiduciary_id, policy_id, purpose_id, state, closed_at, closed_by, reason, PRIMARY KEY (fiduciary_id, policy_id, purpose_id))`.
   (Until Phase 6 ships, use `user_id` plaintext columns and convert in Phase 6.)
2. New `Rights.java`: `create_nomination`, `list_nominations`, `revoke_nomination`, `submit_rights_request`, `get_rights_request`, `list_user_rights_requests`, `list_rights_requests`, `assign_rights_request`, `update_rights_request_status` (DPO), as specified in `access-and-correction-requests.md` section 5. The DPO console page and its data-map panel go under `web/console/dpo/`. Add the client scope map entries in `InterceptingFilter.CLIENT_FUNC_SCOPES` and `CLIENT_ALLOWED_FUNCS`; add `.jschema` files; add pages to `web/rights/`.
3. Nomination state: PENDING if `valid_from` is in the future, effective status computed on read, a `JobManager` sweep flips ACTIVE to EXPIRED.
4. New `Purpose.java`: `set_purpose_state`, `close_purpose`, `list_purpose_lifecycle`. `close_purpose` runs in one transaction: set CLOSED; mark consent entries on that purpose as invalid; look up the governing retention policy; create a purge request with `action` ERASE or DE_IDENTIFY and the retention hold; audit.
5. `Consent.record_consent`: granting a CLOSED purpose returns 403; declining or omitting it is allowed. `validate_consent` returns false for a closed purpose.
6. `Policy` activation: in `Ropa.java:~799` when a version goes ACTIVE, mark the previous ACTIVE version `SUPERSEDED`; send the re-consent notice at that point (not at UNDER_REVIEW). Add `request_reconsent` and `notify_policy_change`.
7. `Consent.get_withdrawal_implications`: for the named purposes return consequence text, mandatory flag, and legal retention from `retention_policies`.
8. Decide DD-01 and DD-05 (see `docs/dpo_decision_register.md` in the Intelehealth repo) and record the owner before turning off any expiry handling.

## Phase 6: principal identifier encryption (own release)

Order matters; each step is a separate commit so it can be reviewed and rolled back.

1. **Inventory.** `grep -n "user_id\|guardian_principal_id\|child_principal_id\|subject_principal_id" db/*.sql src -r`; list each table and column, plus code that reads it (about 190 references in 17 service files; `Consent.java` has 40, `Grievance` 19, `Compliance` 15, `Breach` 11).
2. **Helper.** `util/PrincipalId.java`:
   - `hmac(String)`: `encode(hmac(trim(?), PII_LOOKUP_KEY, 'sha256'), 'hex')` (case kept, trim only). Compute in SQL as `DbEncryption.HMAC` does, but with the lookup key and no `lower()`.
   - `encrypt`/`decrypt` using `DbEncryption.ENCRYPT` and `decryptCol`.
   - `mask("abc12345")` returns `ab****45`.
3. **Config.** `PII_LOOKUP_KEY` env var (min 32 chars; must differ from `DB_ENCRYPTION_KEY` in production; falls back to it elsewhere). Add to `server/.example`, `docker-compose.yml`, the deployment guides and `Env` startup checks.
4. **Migration `db/26_principal_pii_encryption.sql`** (guard: if any table has rows and `current_setting('app.enc_key', true)` is empty, `RAISE EXCEPTION` before changing anything). Per table: add `<col>_enc TEXT`, `<col>_hmac TEXT`; backfill with `encode(pgp_sym_encrypt(col, key), 'base64')` and the HMAC; set `NOT NULL`; drop the plaintext column; recreate indexes and keys on `<col>_hmac` under the same names (`idx_unique_active_consent`, `data_principal` PK, `idx_consent_records_*`, `idx_grievances_*`, `idx_purge_requests_user_search`, `idx_audit_logs_user_timestamp`). Run on a copy of production first and time it.
5. **Code, one service per commit**, in this order: `Consent`, `Principal`, `Wallet`, `Grievance`, `Compliance`, `Notification`, `Breach`, `Ropa`/`CESService`, `Legal`, `AdminDash`, `Job`/`JobManager`, `WebhookDispatcher`. Rules:
   - `WHERE user_id = ?` becomes `WHERE user_id_hmac = <HMAC>`.
   - `INSERT` writes both `_enc` and `_hmac`.
   - Reads that must return the ID (API-key and principal callers) use `decryptCol`; console reads return `PrincipalId.mask`.
   - Never return `_enc` or `_hmac`.
   - Run the Phase 0 characterisation tests after each service.
6. **Evidence columns.** `consent_records.ip_address` `INET` becomes `ip_address_enc TEXT`; same for guardian `verification_ref_id` and `proof_metadata`; erasure writes the encrypted `0.0.0.0`. `client_metadata.ip_address` becomes `ip_address_enc` inside the JSON.
7. **Audit.** In `Audit.logEventAsync` the `userId` argument already goes through `LookupHasher` elsewhere; make that central: store `LookupHasher` output in `audit_logs.user_id` and replace principal-valued keys inside `context_details` with their pseudonym (a set `PRINCIPAL_DETAIL_KEYS`, applied at any depth). Add `source_ip_enc` and a SQL function to decrypt it for console reads. The hash covers the stored (encrypted) value.
8. **Webhooks and alerts.** In `webhook_deliveries` and notification payloads store principal keys as `<key>_enc` plus `<key>_hmac`; `WebhookDispatcher` decrypts at send time. Add a one-off sweep that seals rows queued before the change.
9. **Certificates.** `Legal` signs `principal_id_hmac`; keep the PKCS12 asymmetric signature. Record which lookup key produced the HMAC so old certificates keep verifying. On erasure, a certificate must still verify and report `subject_erased`.
10. **Reveal.** New `Pii.java` `reveal_user_id`: requires permission `pii:reveal` (DPO own tenant, ADMIN any), operator token only (never API key or principal token); write the `PII_REVEALED` audit row with `logEventSync` first, then return the plaintext; cap 20 per minute and 200 per rolling 24 h per operator (DB-backed counters); `JobManager` raises an alert when one operator reveals 50 or more in an hour. Console: a "Reveal" control on the principals page.
11. **Rekey tool.** `util/RekeyLookup.java` main class: recompute every `_hmac` under the current `PII_LOOKUP_KEY`. Document what cannot be rotated (audit IPs, signed certificates) in `docs/security/KEY_MANAGEMENT.md`.
12. **Rollout.** Take a backup (`backup/backup.sh`), run `restore.sh` to a scratch DB to prove it, run the migration, run the smoke test, then deploy the new WAR. State in the release notes that losing `DB_ENCRYPTION_KEY` makes every principal unattributable and that API response shapes change (masked IDs, no IP for operators).

## Phase 7: assurance documents and pen test

1. `docs/security/ISMS_CONTROL_MAP.md`: one row per DPDP Rules 2025 Rule 6(1)(a)-(g) clause: control, code location, owner role, evidence, review cadence. Rows for items outside the repo (TLS, backups, vendor contracts) are marked "outside the repo" and stay open until a named owner fills them in.
2. `KEY_MANAGEMENT.md`, `LOG_RETENTION.md` (table of the Phase 1 floors), `MONITORING_AND_REVIEW.md` (anomaly sweeps), `OUTBOUND_DESTINATIONS.md` (webhooks, SMS/push gateways, Sarvam AI voice call from the tour page), `BREACH_RESPONSE_RUNBOOK.md`, `PURPOSE_VALIDITY_REVIEW.md`.
3. `docs/dpo_decision_register.md` with named owners and review dates.
4. Pen test: add `tests/pentest/` HTTP tests (JUnit or the existing JMeter plan) covering unauthenticated access to every admin function, principal token on admin, cross-tenant by-id reads, SQL injection on search fields, SSRF on webhook URLs, login/OTP/recovery lockout, reveal rate limit, `?auth=` rejection, CSP and security headers. Publish a plan and a dated report under `docs/security/`. Commission an external test before relying on it.

## Acceptance checklist per phase

- New migration is idempotent and listed in the upgrade section of `README.md` and the production guide.
- `.jschema` exists for every new function (a test fails if one is missing).
- Every new function has a permission-map entry and a tenant check.
- A regression test exists for each fix; `mvn verify` passes in CI.
- `RELEASE_NOTES.md` states behaviour changes operators must know.
