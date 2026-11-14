# Access control rollout (shadow mode, then enforce)

Operator API calls (`/api/v1/admin/...`) pass through one check, `framework/AccessControl.java`:

1. **Permission** — the function must be allowed for the operator's role (`util/AccessMap.java` lists what every
   function needs; `roles` table / `util/RolePermissions.java` say what each role holds).
2. **Tenant** — a DPO, OPERATOR or AUDITOR acts only on their own fiduciary. A different `fiduciary_id` in the
   request body is replaced with theirs; a missing one is filled in; an account with no fiduciary is refused.
   ADMIN is platform-wide and never bound.

`ACCESS_CONTROL_MODE` selects the behaviour:

| Value | Effect |
|---|---|
| `shadow` (default; also any other/unset value) | Nothing is blocked or changed. Each case that *would* be refused is logged. |
| `enforce` | Denials return 403; body `fiduciary_id` is rewritten; an internal error in the check refuses the request. |

## Rolling out

1. Apply `db/20_roles.sql`. Deploy with the default (shadow). Startup prints `Access control: SHADOW ...`.
2. Use the system normally, ideally with every role (ADMIN, DPO, OPERATOR) exercising their screens in staging first.
3. Read the findings. Each distinct case is reported once per hour as a line on stderr and as an audit event:
   `ACCESS_SHADOW_DENY` (permission) or `ACCESS_SHADOW_TENANT` (`UNBOUND_ACCOUNT` / `FOREIGN_FIDUCIARY_IN_BODY`),
   with role, `service.function` and the operator's fiduciary. In the console audit page filter by action `ACCESS_SHADOW_DENY`.
4. For each finding decide: the map or role is **wrong** (fix `AccessMap` / `roles`) or the caller is **wrong**
   (nothing to change; enforcing will refuse it). A finding on something users legitimately do is a bug in the map.
5. When a representative period shows only findings you accept, set `ACCESS_CONTROL_MODE=enforce` and restart.
   Rollback is setting it back to `shadow`.

## Things to know

* A function that is **not in the map** is denied under enforce (and logged `DENY_UNMAPPED` in shadow). A unit test
  fails the build if a service gains a function that is missing from the map.
* `AUDITOR` (read everything, change nothing, no API keys or admin metrics) **cannot be created until
  `ACCESS_CONTROL_MODE=enforce`**: the older per-service checks only block OPERATOR, so before enforcement an
  AUDITOR would behave like a DPO.
* `ADMIN` is always `*` in code; editing the `roles` table cannot lock the administrator out. Role changes in the
  table take effect within 60 seconds.
* Services still do their own checks (own-fiduciary, assigned-to-me). Those stay as the second layer.
* Record-level ownership checks for by-id requests are always on (not part of shadow mode); see
  `by-id-audit.md`. Client API calls (API key / principal token) get the same tenant rule as operators:
  in shadow mode a foreign `fiduciary_id` in the body is logged as `CLIENT_FOREIGN_FIDUCIARY_IN_BODY`, in
  enforce mode it is replaced by the credential's own.

## Where the built-in roles are deliberately as open as before (review these)

These mirror what the services allowed before this change, to avoid breaking screens. Tightening any of them is a
one-line edit in `RolePermissions` and `db/20_roles.sql`:

* OPERATOR can read audit logs (`audit:read`) and certificates (`certificates:read`) of its own fiduciary.
* OPERATOR can list and view operator accounts of its own fiduciary (`users:read`).
* OPERATOR and AUDITOR can call the self-service functions (`update_user`, `generate_recovery_key`,
  `list_notifications`, `mark_notification_read`), which the service limits to the caller's own account.
