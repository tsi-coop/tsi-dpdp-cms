# Item 7: principal data protection. Evaluation before building

**Status:** evaluation only, nothing built. Written against the code at the `v0.6` commit.
**What item 7 is:** stop storing data principals' identifiers (and the IP addresses and guardian proof that go with them) in plain
text; look principals up by a keyed hash instead; show masked identifiers to operators; allow an audited, rate-limited "reveal".

## 1. How big it really is (measured)

| Measure | Count |
|---|---|
| Java files that read or write a principal column | 24 (17 service/CES/job files with real logic) |
| Heaviest files (references) | `Consent` 53, `Compliance` 31, `Grievance` 26, `Rights` 25, `CESService` 18, `Notification` 14, `JobManager` 14, `Breach` 11 |
| SQL statements that filter by a principal column | about 40 |
| INSERTs that write a principal column | about 20 |
| Places a principal id is put into a response, payload or export | about 35 across 12 files |
| Tables with a principal-identity column (`ErasureTargets`) | 12 tables, 15 columns |
| Keys / constraints / `ON CONFLICT` that depend on the plaintext id | 16 index or key definitions; `data_principal` primary key, `idx_unique_active_consent`, 3 `ON CONFLICT (user_id, fiduciary_id)` sites |
| Console pages that display principal ids | 12 (including the four built in this release) |
| DB test classes whose fixtures insert plaintext `user_id` with raw SQL | about 12 |

Item 7 changes the shape of the whole data layer. It is the largest and riskiest piece of the release, not a bolt-on.

## 2. What must change, by layer

1. **Keys and config.** New `PII_LOOKUP_KEY` (separate from `DB_ENCRYPTION_KEY`, startup guard, never changes without a re-key). Loss of
   `DB_ENCRYPTION_KEY` makes every principal unattributable: this needs a written key-custody decision (see section 5).
2. **Schema.** For each of the 15 columns: `<col>_enc` (pgcrypto, as `operators.email_enc` already does), `<col>_hmac` (lookup), and (my
   addition) `<col>_mask` so lists can show `ab****45` without decrypting every row. Primary key, unique index and `ON CONFLICT` targets move
   to the HMAC. `consent_records.ip_address` (INET) becomes encrypted text; guardian `verification_ref_id` and `proof_metadata` are encrypted.
3. **Code.** One `PrincipalId` helper (`hmac`, `encrypt`, `decrypt`, `mask`). Every `WHERE user_id = ?` becomes `user_id_hmac = ?`; every
   INSERT writes both columns; every read that must return an id decrypts (API-key and principal callers) or masks (console).
4. **Audit ledger.** New events store a pseudonym instead of the principal id (a central rule in `Audit`, not 20 call sites).
5. **Webhooks, jobs, exports.** Stored webhook bodies and job payloads contain principal ids inside JSON; CSV exports print them.
6. **Certificates.** Evidence certificates sign the HMAC, with a record of which key produced it.
7. **Reveal.** New `Pii` service, permission `pii:reveal`, audit row written first, 20/minute and 200/day per operator, alert at 50/hour.
8. **Re-key tool and key-management document.**

## 3. Things that make it harder than the plan says

1. **The audit ledger cannot be cleaned.** `audit_logs` is append-only and hash-chained (item 2). Rows already written hold plaintext principal
   ids in `user_id` and `context_details`; they cannot be changed without breaking the chain. Only new rows can be pseudonymised. Rewriting
   history means a one-time "re-genesis" that discards tamper-evidence continuity. **Decision needed** (section 5).
2. **Partial-match search disappears.** The console searches principals, audit rows, purge requests and certificates with `ILIKE '%term%'`.
   A keyed hash only supports **exact** match. Searching by half an id stops working.
3. **Processors need the real id.** Purge requests, webhooks and `validate_consent` are how apps find the person to purge; those paths must
   keep returning plaintext to authenticated API keys (decrypt on read), so the API contract for processors cannot change.
4. **Daily DPO work is built around ids.** Rights requests, grievances, purge requests, legal holds, breach lists all show the principal id.
   With masking, the DPO reveals an id to act on it, and the reveal limit (20 per minute) is tight for a busy desk. Which screens show the
   real id and which mask it is a product decision.
5. **`notifications.recipient_id` is mixed**: it holds a principal id, a DPO id or an app id depending on `recipient_type`. Only PRINCIPAL rows
   are encrypted; the lookups have to branch.
6. **Performance.** Decrypting per row costs time. Lists must use the `_mask` column; the nightly CES scan and exports decrypt (acceptable in
   the background); backfilling millions of rows in one transaction is not: it needs batches.
7. **Exports.** `JobManager` writes CSVs with principal ids. Masked exports are useless to an auditor; plaintext exports undo the protection.
8. **Test churn.** About a dozen DB test classes create principals with raw SQL. They all need a fixture helper first.

## 4. Recommended approach: expand / contract, in two releases

The plan drops the plaintext column in the same migration. That is irreversible once running: a mistake means restoring a backup. I
recommend instead:

**Release A (this release, if you want it in v0.6):**
1. Add `_enc`, `_hmac`, `_mask` columns **alongside** the plaintext. Backfill in batches. Add (not yet use) HMAC indexes.
2. Dual-write: every INSERT/UPDATE writes plaintext and encrypted forms.
3. Switch **reads and lookups** to the HMAC, one service per commit in the plan's order (`Consent`, `Principal`, `Wallet`, `Grievance`,
   `Compliance`, `Notification`, `Breach`, `Ropa`/`CES`, `Legal`, `AdminDash`, `Job`). Console responses mask.
4. Audit pseudonymisation for new events, `Pii.reveal`, certificate change, key-management document.
   Rollback at any point = redeploy the previous WAR; the plaintext is still there.

**Release B (a later release, after it has run clean in production):**
5. Verify nothing reads the plaintext (log/assert for one cycle), then drop the plaintext columns and move the primary key.
   Rollback of this step is a backup restore, so it ships alone, after a rehearsal on a production copy.

This keeps "no mistakes" achievable: every step before B is reversible.

## 5. Decisions needed from you

1. **Release strategy:** expand/contract over two releases (recommended), or one release with the plan's single migration and a restore as the
   only rollback?
2. **Audit history:** leave existing audit rows as they are (only new events pseudonymised; simple, history keeps plaintext), or a one-time
   re-genesis of the chain (cleaner, but ends tamper-evidence continuity)?
3. **Search:** accept exact-match only for principal id search?
4. **Which screens mask:** mask everywhere and reveal on demand, or show the real id on the screens where a DPO acts on a request (rights
   requests, grievances, purge requests, legal holds) and mask lists and exports only?
5. **Exports:** masked by default with an audited "unmasked export" option for DPO/ADMIN, or plaintext as today?
6. **Key custody:** who holds `PII_LOOKUP_KEY` and `DB_ENCRYPTION_KEY`, where are they backed up, and is a managed KMS in scope? (Losing
   `DB_ENCRYPTION_KEY` makes every principal unattributable.)
7. **Audit retention (your 7-year note):** see section 7.

## 6. Test and rollout plan

* First commit: a fixture helper so tests stop inserting plaintext ids by hand. Then a characterisation test per service **before** its
  conversion, and the same test must pass after.
* Migration rehearsal: restore a production backup to a scratch database, run the migration, time it, check row counts and that every
  `_hmac` is non-null and unique where the plaintext was.
* A test that fails if any code path writes a principal column without its `_hmac` (the `ErasureTargets` list already names every column).
* Rollout: backup, restore to scratch to prove it, migrate, smoke test, deploy. State in the release notes which response shapes change.

## 7. Audit log retention (the "7-year floor")

Understood as a floor on how long audit rows must be kept. Today `audit_logs` cannot be deleted at all (item 2), which is stricter than a
floor. A 7-year floor only becomes meaningful when **archiving** exists: yearly partitions, with rows allowed to leave the live table only
after 7 years, into an archive that is still verifiable. The plan already says to do partitioning **after** item 7 so the table is rewritten
once. Recommendation: record the rule now in `LOG_RETENTION.md`, and build partition-and-archive straight after item 7.

## 8. Rough sizing

| Piece | Size |
|---|---|
| Key config, helper, fixture helper, guard test | S |
| Expand migration with batched backfill, rehearsal | M |
| Service conversion (17 files, one commit each) | L (most of the work) |
| Console masking, reveal control, 12 pages | M |
| Audit pseudonymisation, certificates | M |
| `Pii` reveal service, rate limits, alerts | M |
| Re-key tool, `KEY_MANAGEMENT.md`, runbook | S |
| Test churn | L |

Realistically several focused sessions, with review and a production-copy rehearsal between releases. I would not start before the current
`v0.6` work has been exercised in staging, because item 7 sits on top of all of it.
