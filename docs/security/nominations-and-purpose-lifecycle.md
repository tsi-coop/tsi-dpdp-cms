# Nominations, purpose lifecycle and withdrawal implications (v0.6, part B of "Data Principal rights")

Migration `db/24_nominations_and_purposes.sql`. Services: `Rights` (nominations), new `Purpose`, and additions to `Consent`.

## Nominations (DPDP s.14)

A data principal can nominate a person to exercise their rights if they die or become unable to.

* **What the CMS does:** records the nomination. It grants the nominee **no access**: the DPO verifies any later claim.
* **Stored encrypted:** nominee name and contact use the same database encryption as operator e-mail addresses. The audit trail
  records `NOMINATION_CREATED` / `NOMINATION_REVOKED` with the nomination id only, never the nominee's details.
* **Who sees what:** the principal sees what they entered; a DPO/ADMIN sees the name and a **masked** contact (`a***@example.com`,
  `********3210`); an OPERATOR sees nothing. Only the principal (or an API key naming them) can create or revoke.
* **Rules:** name 2-100 characters; contact is an e-mail address or phone number; optional relationship; optional end date
  (at most 10 years, in the future); a future start date makes it PENDING; at most 5 current nominations per principal.
* **Status:** PENDING, ACTIVE, EXPIRED, REVOKED. The daily job (`NOMINATION_SWEEP`) expires nominations past their end date and
  activates PENDING ones whose start date has arrived; the status shown is also worked out from the dates at read time.
* Functions: `create_nomination`, `list_nominations`, `revoke_nomination` (`/api/v1/client/rights`).

## Purpose lifecycle

`close_purpose` / `reopen_purpose` / `set_purpose_state`, `list_purpose_lifecycle` (DPO console), `list_closed_purposes` (portal and
apps). Permission `purposes:manage` (DPO) / `purposes:read` (OPERATOR); the migration adds it to existing roles.

**Closing a purpose does this:**
1. Records it as CLOSED (with a written reason, 10+ characters, in the audit log), so **no new consent can be granted** for it.
2. Withdraws the purpose from every principal whose active consent grants it, using the **normal partial-withdrawal path**: the
   history is chained (`supersedes_record_id`, capture mechanism `PURPOSE_CLOSED`), the action value is still `CONSENT_WITHDRAWN`
   (so the existing retention handling works unchanged), and each principal gets a `PURPOSE_CLOSED_NOTIFICATION`.
3. The existing retention engine then raises the purge once the purpose's governing retention period has run.
4. That purge carries `action` = **ERASE** or **DE_IDENTIFY**, as the DPO chose. Processors see it in `get_purge_request`,
   `list_purge_requests` and the purge webhook. A principal's own erasure request is always ERASE.

**Granting a closed purpose** in `record_consent` (and from the wallet) is refused with **403**; declining it, and granting other
purposes, is fine. This is always on, not behind a mode.

**Reopening** allows grants again; it does not restore old consents (principals opt in afresh).

**Large tenants:** one call processes up to 2,000 principals; if there are more the answer says `more_to_process` and the DPO presses
the button again. Closing is safe to repeat and keeps the action already chosen unless a new one is named.

## Withdrawal implications

`get_withdrawal_implications` (`/api/v1/client/consent`, `policy_id` and optional `purpose_ids`, `language`) returns, per purpose:
whether it is needed for the service, what happens if consent is withdrawn, the legal basis, what may be kept and for how long.
It is built from the published policy: `is_mandatory_for_service`, `legal_basis`, `retention_policy`, `retention_duration_*`; a policy may
add its own `withdrawal_consequence` text per purpose, otherwise a plain default is used. The rights portal shows it **before** a
withdrawal; if it cannot be loaded the withdrawal still goes ahead (withdrawing is a right).

## What it looks like

* **Rights portal:** a **Nominee** section under My Rights (add, list, revoke); closed purposes shown as closed and switched off in
  Manage Consent; the consequences shown before a withdrawal.
* **DPO console:** a **Purposes** page (list with state, principals with consent, retention action, last change; close and reopen
  dialogs).

## Decisions assumed

The plan said to decide **DD-01 / DD-05** (open-ended consent plus a named quarterly purpose review) before turning off any expiry
handling. Nothing here turns expiry handling off. The purpose lifecycle is the mechanism a quarterly review would use to close a
purpose; the review itself (who, when, what is recorded) is a process decision that remains with you.

## Not done

* **Re-consent** (`request_reconsent`, notifying principals of a policy change only after the new version is ACTIVE, marking the old
  version SUPERSEDED): there is no existing notification or status for it to build on, so it is a separate piece of work.
* Notification texts are English only.
* The DPO dashboard overdue count and report exports for rights requests; OpenAPI entries for the new functions.
