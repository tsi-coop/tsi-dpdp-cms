# Access control

Operator API calls (`/api/v1/admin/...`) pass through one check, `framework/AccessControl.java`:

1. **Permission** - the function must be allowed for the operator's role (`util/AccessMap.java` lists what every
   function needs; `roles` table / `util/RolePermissions.java` say what each role holds).
2. **Tenant** - a DPO, OPERATOR or AUDITOR acts only on their own fiduciary. A different `fiduciary_id` in the
   request body is replaced with theirs; a missing one is filled in; an account with no fiduciary is refused.
   ADMIN is platform-wide and never bound.

Both checks are always enforced: denials return 403, a body `fiduciary_id` is rewritten, and an internal error in
the check refuses the request. There is no setting to turn this off.

## Upgrading

1. Apply `db/20_roles.sql`. Startup prints `Access control: ENFORCED ...`.
2. Before go-live, exercise every role (ADMIN, DPO, OPERATOR, AUDITOR) through their screens in staging.
3. Refusals are written to stderr and to the audit log as `ACCESS_DENIED` (with the reason, role, `service.function`
   and the operator's fiduciary), once per person and case per minute. Filter the console audit page by `ACCESS_DENIED`.
4. For each refusal decide: the map or role is **wrong** (fix `AccessMap` / `roles`) or the caller is **wrong**
   (nothing to change). A refusal of something users legitimately do is a bug in the map.

## Things to know

* A function that is **not in the map** is denied (logged `DENY_UNMAPPED`). A unit test
  fails the build if a service gains a function that is missing from the map.
* `AUDITOR` reads everything, changes nothing, and has no API keys or admin metrics.
* `ADMIN` is always `*` in code; editing the `roles` table cannot lock the administrator out. Role changes in the
  table take effect within 60 seconds.
* Services still do their own checks (own-fiduciary, assigned-to-me). Those stay as the second layer.
* Record-level ownership checks for by-id requests are always on ; see
  `by-id-audit.md`. Client API calls (API key / principal token) get the same tenant rule as operators:
  a foreign `fiduciary_id` in the body is replaced by the credential's own.

## Where the built-in roles are deliberately as open as before (review these)

These mirror what the services allowed before this change, to avoid breaking screens. Tightening any of them is a
one-line edit in `RolePermissions` and `db/20_roles.sql`:

* OPERATOR can read audit logs (`audit:read`) and certificates (`certificates:read`) of its own fiduciary.
* OPERATOR can list and view operator accounts of its own fiduciary (`users:read`).
* OPERATOR and AUDITOR can call the self-service functions (`update_user`, `generate_recovery_key`,
  `list_notifications`, `mark_notification_read`), which the service limits to the caller's own account.

## MFA enrolment (authenticator app)

* **Who is asked:** with `TSI_DPDP_CMS_ENV=production` (or `MFA_ENFORCE=true`) every ADMIN, DPO and AUDITOR must enrol at their next
  login. Otherwise enrolment is optional per operator (the `mfa_enabled` flag): an operator with it on is always challenged.
* **Enrolling:** the login page shows a **QR code** to scan with any authenticator app, with the secret key underneath for typing in
  ("Can't scan? Enter this key manually"). If the QR library cannot load (for example no internet), only the key is shown.
* **Name in the app:** the account appears under your brand, taken from `BRAND_NAME` (default "TSI DPDP CMS"), so staff recognise it.
* **First run:** a fresh installation with no administrator sends the login page to the setup screen instead of the login form.
