# Consent capture and grievance handling (v0.6)

Migrations: `db/21_consent_capture.sql`, `db/22_grievance_enhancements.sql`.

## Consent evidence (`record_consent`, withdrawal, wallet)

| What | Before | Now |
|---|---|---|
| User agent | taken from the request **body** | taken from the `User-Agent` **header**; what the caller claims goes to `client_metadata.user_agent` |
| Client address | the TCP peer (the proxy's address behind nginx) | `ClientIp`: `X-Forwarded-For` is believed only when the peer is in `TRUSTED_PROXY`, read from the **right** (a client cannot choose its own recorded address by sending the header). Stored pseudonymised, as before |
| Claims by the calling system | not kept | `client_metadata` JSONB: `user_agent`, `ip_address`, `session_id` (as claimed, never trusted) |
| How it was captured | not recorded | `capture_mechanism`: `PRINCIPAL_PORTAL` (principal token), `API_INTEGRATION` (API key), `WALLET` |
| History | a new record each time, no link | `supersedes_record_id` links each record to the one it replaced; nothing is overwritten |
| Withdrawal evidence | placeholder address, no user agent | the real observed address and user agent, the capture mechanism and the supersedes link |

**Deliberate difference from the plan:** the plan said to set `consent_mechanism` from the auth path. That column holds the
*action* (`CONSENT_GIVEN`, `CONSENT_WITHDRAWN`, `ERASURE_REQUEST`) and the CES engine, the exports and the rights portal
read it as such, so its values were left alone and the capture path went into the new `capture_mechanism` column.

## Explicit choices and minors: `CONSENT_CAPTURE_MODE`

* **Always enforced:** every `data_point_consents` entry must be an object with a `data_point_id` and a real `true`/`false`
  (a missing value used to fail later with a 500).
* **Governed by the mode** (`warn` by default, `strict` to reject):
  * every purpose the policy declares must be answered exactly once, none unknown or repeated;
  * a principal recorded as a MINOR needs a `verification_log_id` that points to a guardian log for that child at this fiduciary.
* In `warn` mode a breach of those rules is accepted and recorded as an audit event `CONSENT_CAPTURE_WARNING` listing the
  problems. Read those events, fix the integrations, then set `strict`.

**Who is a minor.** Only a recorded guardian verification (`record_parent_consent`) marks a principal as a MINOR; it also stores
the guardian and `VERIFIED`. `link_user` no longer accepts `age_category`, `guardian_id` or `verification_status` (they are
ignored and noted as `LINK_USER_DECLARED_FIELDS_IGNORED`), and it never overwrites a stored value: previously a declared
ADULT replaced a stored MINOR. `record_parent_consent` now also requires child and guardian to be different.

## Grievances

* **Reference number** `GRV-<year>-<6 digits>`, unique, returned on submit and shown in lists. Existing grievances were back-filled.
* **Channel**: `PRINCIPAL_PORTAL` is set by the principal token and cannot be claimed; an API key may relay `EMAIL`, `PHONE`,
  `IN_PERSON`, `POSTAL`, `OTHER` (default `API_INTEGRATION`); operators default to `OPERATOR_CONSOLE`.
* **Consent record link** (`consent_record_id`): optional, must be this principal's record at this fiduciary.
* **Auto-assignment**: a new grievance goes to the fiduciary's oldest active DPO account (and that DPO is notified).
* **Resolution summary**: `RESOLVED` and `CLOSED` need at least 10 characters; statuses are validated
  (`NEW`, `IN_PROGRESS`, `RESOLVED`, `CLOSED`, `ESCALATED`).
* **Attachments** (`upload_grievance_attachment`, `get_grievance_attachment`): PDF, PNG, JPEG or plain text, 5 MB each,
  5 per grievance; the bytes must match the declared type; file names are reduced to safe characters; stored in the database
  with a SHA-256; the principal, the fiduciary's operators (an OPERATOR only if assigned) and the fiduciary's own API key
  (naming the principal) can read them.
* **Feedback** (`submit_grievance_feedback`): the principal rates 1 to 5 with an optional comment, once, after the grievance
  is resolved or closed.
* `submit_grievance` now also checks the grievance is filed against the **caller's own fiduciary**.

## Not done in this change

* **User interfaces:** the rights app and the DPO console do not yet show the reference number, channel, attachments or
  the feedback form. The API returns all of it.
* Grievance attachments are not yet removed on whole-account erasure (that belongs with the erasure work).
* The withdrawal and erasure paths in `Wallet` keep their placeholder client address (no request context there).
* No general request-size limit exists in `InputProcessor` (it reads the whole body); only attachments are size-checked.
* The wording of the grievance **type** options (the bare access/correction/erasure choices) is unchanged; the rights-request
  work replaces them.
