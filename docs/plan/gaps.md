# Gaps: Functional Feedback

Source: external review of the Python port ("the port") and its test matrix. Nothing in the review was executed. The Java verification below was done by reading `src/` at v0.5.4 (2026-11-05); nothing was run.

Legend for the Java column:
- **OK**: Java v0.5.4 already does the right thing. Gap is port-only.
- **Open**: Java shows the same weakness, or the review's claim is plausible in Java. Needs a test or fix.
- **Unverified**: Not determinable from a quick read. Needs a test.

## 1. Matrix defects (mostly inherited from Java)

The matrix reports these as functional defects found over its 18 revisions, several as "pre-existing code".

| Area | Defect the matrix found | Ref | Java v0.5.4 |
|---|---|---|---|
| Purpose handling | Purpose IDs not canonicalised on write. A CLOSED purpose could validate as GRANTED under a different case, and a decision naming both `purpose_id` and `id` could authorise a different purpose. Fixed there by one canonicalisation helper plus DB triggers. | P10-01, P10-04 | **Open.** `Consent.java:458` and `:1319` compare with `equalsIgnoreCase`, so case-variants match at read time. No write-time canonicalisation seen. Test closed-purpose and mixed-case cases. |
| Erasure / purge | Erasure applied tenant-wide instead of per principal. | P7-01 | **Unverified.** `Consent.withdrawConsent(..., erasure=true)` takes `userId`; confirm the SQL scopes by user. |
| Erasure / purge | Purge status committed before the legal-hold refusal. | P8-02 | **Unverified.** Check ordering in `Compliance.java` purge status handler (~L135, L380). |
| Erasure / purge | `DE_IDENTIFY` branch raised at runtime. | P8-01 | **Unverified.** Exercise the DE_IDENTIFY path. |
| Policy lifecycle | Activating a version never retired the previous one, so consent could be taken on a superseded notice. | P11-03 | **Open (likely).** Activation is in `Ropa.java:799` (sets ACTIVE). No retire/archive of the prior version seen there. `Policy.publish` only rejects purpose-ID collisions with other ACTIVE/UNDER_REVIEW policies (`Policy.java:791-807`). The 409 version-mismatch check in `Consent.java:157` mitigates at record time. |
| Policy lifecycle | `publish_policy` notified principals while the version was still UNDER_REVIEW, so the demanded re-consent could not be given. | P10-02 | **Open (likely).** `Policy.java:811` sets UNDER_REVIEW and DPO activates via ROPA approval. Check where the re-consent notification fires. |
| Date handling | Date-only `consent_expiry` made every withdrawal return a 500. | P12-01 | **Open (likely).** `Consent.java:454` does `Instant.parse(expiryStr)`, which throws on a date-only value. Test with a stored date-only expiry. |
| Open-ended consent | DD-01 says no caller may attach an expiry, and the schema refuses one. Only safe if the quarterly purpose review (DD-05) happens, and it has no named owner. | DD-01, DD-05 | **Decision needed.** Java derives expiry from the policy (`CESUtil.appendConsentExpiry`) and honours a stored `consent_expiry` at read. Confirm callers cannot supply one. DD-05 owner undecided. |

## 2. Port-only gaps (read, not run)

Java v0.5.4 already handles every item below, so these are parity gaps in the port, not Java defects.

| Area | Observation | Where (port) | Java v0.5.4 reference |
|---|---|---|---|
| Open-ended consent | `_point_granted` honours a caller-supplied `consent_expiry`, contradicting DD-01. | `services/consent.py` | n/a (see DD-01 above) |
| Withdrawal | Deactivates all of the principal's active consents and ignores `purpose_id`. | `consent.py:_withdraw` | OK: `withdraw_consent` scopes by `policy_id` and `purpose_ids` (`Consent.java:283-292`) |
| Grievances | `add_grievance_communication` only calls `update_grievance_status`, never appends to the communication log. | `compliance.py` | `Grievance.java` has `communication_log`; confirm the append path |
| Grievances | Fixed 30-day due date, no SLA or escalation. | `compliance.py` | OK: SLA by type (`calculateDueDate`, erasure vs default) and `GRIEVANCE_ESCALATED` |
| Admin dashboard | `get_admin_metrics` counts `status = 'FAILED'`. | `admin.py` | OK: counts `PURGE_FAILED` (`AdminDash.java:157`) |
| Stub: ROPA | `derive_from_policy` returns "completed" and does nothing. | `governance.py` | OK: `RopaDeriver` (`Ropa.java:304`) |
| Stub: domain check | `validate_fiduciary_domain` marks any domain VALIDATED, no DNS check. | `catalog.py` | OK: `DnsVerifier.verifyDnsTxtRecord` (`Fiduciary.java:273`) |
| Stub: jobs | `create_job` only inserts PENDING. No worker, so `download_file` returns an empty path. | `governance.py` | OK: `job/JobManager.java` |
| Stub: delivery | `dispatch_notification` only inserts a row. Stored webhook configs are never delivered. | `governance.py` | OK: `WebhookDispatcher.java` |
| Wallet | `sync` and unknown actions return `{"success": true}`. | `consent.py:WalletService` | OK: explicit action switch (`Wallet.java:68-84`) |
| Consent recording | `record_consent` does not check the policy exists, is active, or matches the version. | `consent.py` | OK: 409 on version mismatch (`Consent.java:157`) |
| Breach | No 72-hour deadline or countdown, no Board or principal intimation. | `compliance.py` | OK: `BreachDeadline` with configurable hours (`Breach.java:187-199`) |
| Breach | `download_breach_report` returns JSON, not PDF. | `compliance.py` | OK: PDF via OpenPDF (`Breach.java`) |
| Rights portal | `list_active_fiduciaries` omits `otp_mode`. | `consent.py:PrincipalService` | OK: `otp_mode` in rights app config (`Notification.java:222`, `db/12_rights_app_config.sql`) |
| Rights portal | `principal_login` returns only the token, not policies, `sync_token`, `pca_qr_enabled` or persona. | `consent.py` | `Principal.java` handles persona; confirm full login payload |
| Missing vs Java | Webhook delivery log and retries, notification log, minor-guardian audit, `PURGE_CANCELLED`, backup/restore scripts. | n/a | All present in Java: `db/16_webhook_deliveries.sql`, `db/17_notification_log.sql`, `util/MinorConsentAudit.java`, `Constants.EVENT_PURGE_CANCELLED`, `backup/backup.sh`, `backup/restore.sh` |

## 3. Takeaways

- Several items are Java behaviours the port was meant to mirror. One parity table against the v0.5.x release notes would cover both the security and the functional gaps. Section 2 above is a first cut.
- The matrix's "Exists" counts mean "an API exists and behaves as the BRD says". They do not show that the port's stubs and missing worker, delivery and PDF pieces work. None of those should be read as done.
- Decide who owns DD-05 (quarterly purpose review). The open-ended-consent decision depends on it.

## 4. Follow-ups for Java

Candidate regression cases (add to `docs/test-cases/regression-test-cases.md` if confirmed):

1. Mixed-case and closed-purpose validation (P10-01, P10-04).
2. Per-principal erasure scope (P7-01), legal-hold ordering (P8-02), DE_IDENTIFY path (P8-01).
3. Activating a new policy version while an older one is ACTIVE (P11-03).
4. Re-consent notification timing relative to UNDER_REVIEW vs ACTIVE (P10-02).
5. Date-only `consent_expiry` through `withdraw_consent` (P12-01).
6. Grievance communication append persists to `communication_log`.

## 5. Schema-per-tenant multi-tenancy: level of effort

Today tenancy is a `fiduciary_id` column. This section estimates moving to one Postgres schema per Fiduciary in a single database. It is a sizing estimate from reading the code and DDL, not a design. Nothing was prototyped.

### Current footprint (measured 2026-11-05)

| Item | Count |
|---|---|
| Tables in `db/*.sql` | 24 (about 20 carry `fiduciary_id`; `fiduciaries`, `operators`, `api_keys` and a few others are cross-tenant by nature) |
| Java files referencing `fiduciary_id` | 25 (about 385 references) |
| SQL statements (`prepareStatement`/`executeQuery`/`executeUpdate`) | about 417 |
| DB connection acquisition points | about 175 `new PoolDB(...)` and 177 `getConnection()` calls |
| Pool | One HikariCP pool (`PoolDB`, max 15), one JDBC URL, no per-request tenant hook |
| Migrations | 18 hand-run SQL files, no migration tool, no per-tenant runner |

### Work breakdown (person-days)

| # | Work item | Notes | Days |
|---|---|---|---|
| 1 | Design decision and ADR | Which tables are shared vs per-tenant; tenant resolution rules; rollback plan | 3-4 |
| 2 | Tenant context and pool | Resolve tenant per request (body, API key, operator session, rights-portal pre-login) into a thread-local. Set `search_path` on borrow and reset on return in `PoolDB`. Cover async paths (`AsyncEmailTask`, `WebhookDispatcher`, `JobManager`). | 6-9 |
| 3 | Schema split | Shared schema: `fiduciaries`, `operators`, a key-to-tenant lookup for `api_keys`, scheduler state. Tenant schema: the other tables. Rewrite DDL and FKs (cross-schema FKs to `fiduciaries` need care). Indexes that lead with `fiduciary_id` get rebuilt. | 5-6 |
| 4 | Code changes in 25 files | Keep the `fiduciary_id` column to limit risk (defence in depth), so most statements need no edit. The cost is in cross-tenant code: `AdminDash`, `Audit`, `Operator` (ADMIN spanning tenants), `Fiduciary`, `Job`, `Notification`, and any principal view spanning fiduciaries (check Aggregator Mode and wallet). Each needs explicit schema switching or a shared-schema read. | 10-15 |
| 5 | Provisioning and migration tooling | Create a schema and apply `db/*.sql` on Fiduciary onboarding. Add a per-tenant migration runner (Flyway or similar) so later `db/NN_*.sql` changes reach every schema. | 6-10 |
| 6 | Data migration | Split existing single-schema data into tenant schemas. Reconcile row counts per table. Re-verify the `audit_logs` hash chain per tenant. Dry run on a production copy. Cutover and rollback runbook. | 5-8 |
| 7 | Background jobs | `JobManager` loops over active fiduciaries and runs CES, export and breach-notify jobs. Each job must run under the right schema. | 3-5 |
| 8 | Backup/restore, setup, docs | `backup.sh`/`restore.sh` become per-schema or per-tenant. Update `AdminSetup`, setup guides, `docker-compose`. | 3-5 |
| 9 | Test and hardening | Rerun the 112-case regression. Add cross-tenant isolation tests (tenant A cannot read B via every API). Load test the pool, since the 250-entry prepared-statement cache interacts with per-request `search_path` changes. | 10-15 |
| | **Total** | | **about 51-77 person-days** |

Roughly 2.5 to 3.5 months for one engineer, or 6 to 8 weeks for two. Add about 20 percent if the migration tool and cross-tenant admin reporting are not agreed up front.

### Main risks

- **Tenant leakage on a pooled connection.** A missed `search_path` reset sends the next request to the wrong tenant. Needs a borrow/return hook and a test that fails closed (no default schema).
- **Pre-login tenant resolution.** The rights portal is public and currently passes `fiduciary_id` in the body. It must be validated before switching schema.
- **Cross-tenant features.** Admin metrics, ADMIN operators, principal IDs shared across fiduciaries (`data_principal` has a composite key for this), and aggregator-style views all lose the simple `WHERE` filter.
- **Scale.** Hundreds of schemas are fine. Thousands make migrations slow and bloat the catalog. Confirm the expected tenant count.
- **Tooling.** PgBouncer in transaction mode does not mix with session-level `search_path`; use `SET LOCAL` inside transactions if it is introduced.
- **Audit ledger.** The hash chain and `evidence_certificates` need a per-tenant chain, and a decision on whether the chain restarts at cutover.

### Cheaper options to consider first

| Option | What it gives | Rough days |
|---|---|---|
| Postgres row-level security on `fiduciary_id` | DB-enforced isolation using the existing column. Set `app.fiduciary_id` per connection. Same tenant-context plumbing as item 2, no schema split or migration runner. | 15-25 |
| Schema per tenant (above) | Cleaner per-tenant backup, restore and erase; easier per-tenant data residency. | 51-77 |
| Database per tenant | Strongest isolation, per-tenant encryption keys and backups. Needs a pool per tenant. | 60-90 |

If the driver is isolation assurance for customers or auditors, RLS delivers most of it for about a third of the effort. If the driver is per-tenant backup/restore, erasure or data residency, schema-per-tenant is justified. The driver is not stated in the request and should be confirmed before committing.
