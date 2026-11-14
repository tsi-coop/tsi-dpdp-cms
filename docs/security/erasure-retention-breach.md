# Erasure, retention and breach (v0.6, item 6)

Migrations `db/25_purge_and_legal_holds.sql`, `db/26_breach_board_intimation.sql` and `db/27_purge_processor_obligation.sql`.

## Purge confirmation (`update_purge_status`)

* An **API key** can confirm only a purge assigned to **its own app** (`purge_requests.app_id`), within its own fiduciary. A purge with
  no linked app cannot be confirmed by a key. (Before, any key of the fiduciary could.)
* **Who confirmed it comes from the credential** (the key's app or the operator), stored as `confirmed_by`, `confirmed_by_type`,
  `confirmed_at`; a value in the request body is ignored.
* The processor's count (`records_affected`) is stored as **`claimed_record_count`**: the CMS cannot verify records held in a processor's
  own systems, so it is a claim and is shown as one. (The plan also mentioned a CMS-verified count; there is nothing the CMS could
  honestly verify, so it was not invented.)
* Status values are validated. `PURGE_COMPLETED` and `PURGE_CANCELLED` are **final**: nothing changes them afterwards (409).
  Processors and operators may report in progress, completed or failed; **cancelling and legal hold are the DPO's decision**.
* **A processor that must keep the data** (a legal obligation of its own, for example tax records) can say so by sending `LEGAL_HOLD_APPLIED`
  with `details` of at least 10 characters. This is a **report**: it is recorded (`processor_obligation_at`, `_note`, `_by`, audit
  `PURGE_PROCESSOR_LEGAL_OBLIGATION`), the DPO is notified, and Compliance shows "Processor: legal obligation" with the text. It does **not**
  change the purge's status or suspend it, and the CMS has not verified it. The DPO decides: place a time-bound legal hold (below) if it is
  right, or follow it up with the processor. The principal is not notified automatically.
* The plan's "only an operator may confirm a whole-account erasure (purpose `ALL`)" does not apply: this CMS raises one purge per purpose
  and app, there is no `ALL` purge.

## Erasure through an API key

`erasure_request` from an integration now needs an existing consent record for that principal (404 otherwise), so a key cannot create
erasure records and purge requests for anyone it can name.

## Purge completion deadline

`PURGE_COMPLETION_SLA_DAYS` (1-365). **Unset by default: nothing is flagged.** When set, a daily job flags purges still unconfirmed after
that many days (`sla_flagged_at`, audit `PURGE_SLA_BREACHED`, one notice per fiduciary to its DPO, an "Overdue" tag in Compliance). A
purge under legal hold is not late.

## Legal holds

`place_legal_hold`, `list_legal_holds`, `release_legal_hold` (DPO / ADMIN; `purposes` is not needed, permission `purges:manage`).
* Always **time-bound** (end date at most 730 days away) with a written reason; optional case reference and optional single purpose.
* Placing a hold puts the principal's open purges on `LEGAL_HOLD_APPLIED`; a purge that falls due while a hold covers it is recorded but
  **not released to the processor**, and the principal gets the existing "on legal hold" notice.
* A sweep every few minutes ends holds whose date has passed and **resumes the purges they deferred** (processor notified, audited). A purge
  put on hold by hand (no hold record) is never resumed automatically. Another active hold keeps a purge held.

## Breach: Board intimation

* Every new breach is tracked for the Data Protection Board from the moment it is reported: `board_notification_deadline` = detected +
  the fiduciary's breach window (default 72 h, tighten-only). Older breaches stay "not tracked".
* `record_board_intimation` (DPO / ADMIN, once only): when the Board was informed (not in the future, not before detection) and the Board's
  reference. The breach page has a button; the PDF report shows it.
* The breach PDF can be downloaded at any status (an open breach is marked "INTERIM REPORT"), so a report can go to the Board within 72 hours while the incident is still being handled.
* A sweep alerts the DPO **once** when the deadline is within 12 hours and **once** when it has been missed
  (`BREACH_BOARD_DEADLINE_DUE` / `_MISSED` audit events and a notice). The DPO dashboard shows two clocks per breach: telling the principals
  and informing the Board.

## Other fixes

* **Date-only expiry:** a `consent_expiry` of `2027-01-31` no longer throws (consent validation and the retention engine). A date ends the
  consent at the start of the next day (UTC); an unreadable value counts as expired, never as valid forever. A purpose with no expiry no
  longer inherits the previous purpose's expiry.
* **ERASURE_TARGETS:** `ErasureTargets` lists every column that holds a principal's identity and what is *intended* for it on erasure.
  `ErasureTargetsTest` fails if a migration adds such a column that is not listed. It executes nothing: whether the CMS erases or
  pseudonymises its own copy at all is a legal decision (evidence of consent and of the erasure against the right to erasure) for your counsel.

## Not done

* **Retention policy CRUD with a 7-year floor:** retention today lives in each policy purpose and the ROPA entries, so a separate "retention
  policy" with a floor has no clear home. It needs a decision on what the floor applies to (a data category? a legal obligation in the
  ROPA?) before it is built.
* **CMS-side erasure/pseudonymisation** (see above), and the "re-key to a random token" step from the plan, wait on that decision.
* Operator-initiated withdrawal/erasure needing a written reason (listed separately in the plan).
* Notification texts for the new alerts are English only.

## Review fixes (from the code review of the first v0.6 commit)

* **MFA and audit:** AUDITOR must now enrol MFA when it is enforced (it reads the audit trail); the audit MFA gate applies only to roles that
  can enrol, so OPERATOR (never prompted) is not locked out of the console.
* **Login rate limit:** a correct password followed by the MFA step no longer counts as a failed attempt.
* **Audit robustness:** audit fields are cleaned and clipped before queueing; a batch that fails is retried entry by entry so one
  unstorable entry can no longer block every login; a failed login is queued instead of written inline.
* **Notification texts:** a fiduciary with no stored template now gets the built-in text instead of a blank notice.
* **Secret guard:** an unedited placeholder (`<<...>>`, `change-me`, ...) is refused; a short `DB_ENCRYPTION_KEY` / `TSI_LOOKUP_SALT` (which
  cannot be changed without re-encrypting data) is a warning, a short `JWT_SECRET` still refuses to start.
* **Audit chain check:** a recent verdict (5 minutes) is reused instead of walking every audit row again; the daily run has its own thread.
* **Access denials:** reported per person, not once per kind of denial.
* **Old sessions:** tokens from the previous release are accepted for at most the new session lifetime, and not at all once MFA is enforced.
* **Policy cache:** entries expire after 30 seconds (`POLICY_CACHE_TTL_SECONDS`), so a change made on another instance is seen quickly.
* **Docs links:** `docs/plan/README.md`, `docs/plan/python-sdk.md` and `examples/integration/README.md` still link to the two plan files that were
  deleted (`integrations-roadmap.md`, `google-tag-manager-template.md`); restore the files or remove the links.
