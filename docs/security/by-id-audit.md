# By-id query audit (cross-tenant access)

**What was checked.** Every handler that takes a record id from the request and reads or changes that record
(about 140 `WHERE ... id = ?` statements across the 17 services). For each: does anything confirm the record
belongs to the caller's fiduciary, for **all three kinds of caller**: operator token, client API key, and
principal (data subject) token?

**The common pattern.** Operator calls were mostly protected (load the record, compare its fiduciary with the
operator's). API-key and principal callers have no operator role, and several ownership helpers returned
"allowed" when the role was null, so those callers skipped the check.

## Findings and status

| # | Where | Problem | Severity | Status |
|---|---|---|---|---|
| 1 | `Compliance.update_purge_status` | An API key could change any fiduciary's purge request (erasure evidence) and fire its webhook | High | **Fixed**, tested |
| 2 | `Consent.link_user` | `UPDATE consent_records ... WHERE user_id = ?` was not scoped to a fiduciary: naming another tenant's principal as the "anonymous" id reassigned that person's records | High | **Fixed** (`AND fiduciary_id = ?`), tested |
| 3 | Client API (`Consent`, `Compliance`, `Grievance`) | The body's `fiduciary_id` took precedence over the API key's own fiduciary | High | **Fixed** for every function that calls the ownership helper (reads, withdraw, erasure, purge, record_consent, record_parent_consent, link_user). Central rewrite of the body value follows `ACCESS_CONTROL_MODE` (see below) |
| 4 | `Policy.get_policy` | No ownership check: any caller could read any fiduciary's policy, including drafts | Medium-High | **Fixed**, tested |
| 5 | Ownership helpers in `Compliance`, `Grievance`, `Consent` | `callerRole == null` (API key / principal) bypassed the check | Medium-High | **Fixed**: one shared rule, `InputProcessor.callerOwns` |
| 6 | `Notification.mark_notification_read` | Updated by id with no owner check (breach read-receipts are compliance evidence) | Medium | **Fixed**, tested |
| 7 | Principal tokens on `get_grievance`, `get_consent_record_details` | A principal could read another principal's record by id (same fiduciary) | Medium (needs a known UUID) | **Fixed**, tested |
| 8 | `assign_purge_request`, `assign_grievance` | Assignee could be an operator of another fiduciary | Low-Medium | **Fixed**: assignee must be an active operator of the same fiduciary, tested |
| 9 | `Audit.get_audit_log` | A log row with no `fiduciary_id` skipped the check | Low | **Fixed**: platform-level rows are ADMIN-only, tested |

## The shared rule

`InputProcessor.callerOwns(req, recordFiduciaryId)`:

* ADMIN: allowed.
* Everyone else: allowed only if the fiduciary they are **bound to by their credential** equals the record's.
  That fiduciary is: the operator's own (`operators.fiduciary_id`); the principal token's `fid` claim; or the API
  key's (`api_keys.fiduciary_id`, only after key and secret validated). It is never taken from the request body.
* A caller that cannot be resolved, an account with no fiduciary, or a record with no fiduciary is **refused**.

`RecordOwnership` holds the pure rule and is unit tested.

## Behaviour changes to be aware of

* An API key that sends another fiduciary's `fiduciary_id` now gets **403** on the functions above (it used to
  succeed). A caller that omits `fiduciary_id`, or sends its own, is unaffected.
* `get_policy` now returns **403** for a policy of another fiduciary (including from the rights app or tour pages
  if they ever requested someone else's policy; each caller reads only its own).
* `mark_notification_read` returns **404** (not 200) when the notification is not visible to the caller.

## Still open (not changed, by design)

* **Central body rewrite for the client API** (`AccessControl.checkClient`) follows `ACCESS_CONTROL_MODE`: in
  shadow mode it only logs `ACCESS_SHADOW_TENANT CLIENT_FOREIGN_FIDUCIARY_IN_BODY`; in enforce mode it also
  replaces a foreign `fiduciary_id` and fills a missing one. Functions that do not call the ownership helper and
  resolve the fiduciary from the body (see `Wallet`, `Principal`, `Notification.list_notifications`) rely on it.
* **Second-step statements** such as `UPDATE ... WHERE id = ?` run only after the ownership check passed. They are
  safe today; adding `AND fiduciary_id = ?` to them is optional hardening.
* A caller without access to a record gets 403, which confirms the id exists. Returning 404 for everything
  would hide that; not changed.
* `Notification.post` fails with a 500 (not a security issue) when a principal token omits `fiduciary_id`; enforce
  mode's fill step avoids it.
* `Wallet` (sync tokens) and the public `Principal` functions were read but not changed.
