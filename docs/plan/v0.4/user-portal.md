# Data Principal Self-Service Portal
**TSI DPDP Consent Management System - Design & Implementation Plan**
Version: 0.4 | Status: Implemented

---

## 1. What is the User Portal?

The Data Principal Self-Service Portal (`web/rights/`) is a generic, fiduciary-agnostic web interface that allows any registered data principal to independently manage their consent and exercise their data rights — without requiring technical knowledge, API credentials, or assistance from the fiduciary's support team.

It is the principal-facing counterpart to the operator-facing admin console (`web/console/`).

The portal provides three capabilities:

| Capability | Description |
|-----------|-------------|
| **Consent Management** | View the fiduciary's active consent policy and update preferences using a structured toggle UI |
| **Consent History & Verification** | Browse the full history of consent records, inspect granular purpose-level decisions, and self-verify whether consent is active for a specific purpose |
| **Requests & Grievances** | Submit, track, and review formal data rights requests — erasure, portability, correction, and general complaints |

The portal is designed to be embedded by any data fiduciary using the system. A single deployment serves all configured fiduciaries: fiduciary context is selected at login via a dropdown or pre-specified using the `?fid=` URL parameter, enabling white-label or deep-linked deployments.

---

## 2. Why Do We Need This?

### 2.1 Regulatory Obligation

Section 11 of the Digital Personal Data Protection Act 2023 grants every Data Principal the right to:
- **Withdraw consent** at any time (Section 11(2))
- **Access information** about their consent and data processing (Section 11(1))
- **Nominate a grievance** and receive redressal within 30 days (Sections 13–14)

Without a self-service portal, fiduciaries must handle these requests manually, creating operational bottlenecks, inconsistent response times, and an audit trail that lives outside the CMS.

### 2.2 Gap in the Existing Tour Pages

The existing `web/tour/` pages (`consent-collector.html`, `user-dashboard.html`) require the user to enter `X-API-Key` and `X-API-Secret` directly in the browser — a developer credential intended for server-to-server integrations. These pages are demonstration tools, not a deployable principal interface. A production portal must:

- Authenticate principals using identity they actually possess (email or mobile), not API credentials they cannot be expected to know
- Scope all access to a specific fiduciary without exposing API key material
- Work generically for any fiduciary configured in the CMS

### 2.3 Principal UX Requirement

A data principal exercising their right to withdraw or inquire must not be required to understand the system's technical architecture. The portal provides a self-contained, plain-language interface aligned with the language of the fiduciary's own consent policy.

---

## 3. Business Outcomes

### 3.1 Compliance Enablement
- Fiduciaries can point their privacy notice's "Manage my preferences" link directly to the portal
- Withdrawal and erasure requests are captured in the CMS and visible to DPOs in real time — no email-based manual intake
- Grievances are logged with timestamps and SLA deadlines automatically enforced

### 3.2 Reduced Support Load
- Principals self-serve consent withdrawal, erasure, and data access requests
- DPOs review and action requests from within the existing DPO console — no new tooling required

### 3.3 Fiduciary Flexibility
- Any fiduciary's principal can reach the portal at `?fid=<uuid>`
- Fiduciaries can embed a pre-scoped link in their privacy notice, app, or email footer
- The OTP default (`1234`) enables immediate testing without SMS/email infrastructure; the placeholder is explicitly marked for replacement

---

## 4. Design Decisions

### 4.1 No API Credentials in the Browser

Client APIs (`/api/v1/client/*`) were designed for server-to-server calls authenticated by `X-API-Key` + `X-API-Secret`. The portal introduces a new authentication path — a **PRINCIPAL JWT** — that:
- Is issued after the principal authenticates with their own identifier (email/mobile) and an OTP
- Encodes the `user_id` and `fiduciary_id` as JWT claims (type `PRINCIPAL`)
- Is accepted by the existing client API endpoints as a Bearer token
- Grants READ and WRITE scope but explicitly blocks PURGE operations

This preserves the existing client API contract for app integrations while opening a distinct, scoped authentication channel for principals.

### 4.2 SessionStorage over LocalStorage

Session data is stored in `sessionStorage` rather than `localStorage`. This means:
- The session is automatically destroyed when the browser tab or window is closed
- No persistent token is left on a shared device
- The portal is re-authenticated on each visit, matching the expectation for a privacy-sensitive interface

### 4.3 Fiduciary Pre-selection via URL Parameter

The `?fid=<uuid>` URL parameter allows a fiduciary to distribute a deep link that pre-selects their organisation at the login screen. When `?fid` is present:
- The fiduciary dropdown is hidden
- The fiduciary name is fetched from the public API and shown as a non-editable badge
- The login form is scoped to that fiduciary without any choice required from the principal

This supports embedding the portal link in a fiduciary's privacy centre, mobile app, or email notification.

### 4.4 Security Guard on User ID

When a request is made to the client consent or grievance APIs using a PRINCIPAL JWT, the backend enforces that the `user_id` in the request body matches the `sub` claim in the JWT. This prevents a principal from querying another principal's records by crafting a request with a different `user_id`.

---

## 5. Architecture

### 5.1 Request Flow

```
Browser → GET /rights/index.html?fid=<uuid>
                │
                ▼
         POST /api/v1/public/principal { list_active_fiduciaries }
         (No auth — public endpoint)
                │
                ▼
         User fills email / mobile + OTP "1234"
                │
                ▼
         POST /api/v1/public/principal { principal_login, fiduciary_id, user_id, otp }
                │
         InterceptingFilter: category=public → authenticated=true
                │
         Principal.java: validates OTP, checks fiduciary ACTIVE,
                         fetches active policy_id, issues PRINCIPAL JWT
                │
                ▼
         saveSession() to sessionStorage → redirect to dashboard.html
                │
                ▼
         Dashboard loads → requireAuth() → session valid
                │
         POST /api/v1/client/policy { get_active_policy }  Authorization: Bearer <jwt>
         POST /api/v1/client/consent { list_consent_history }  Authorization: Bearer <jwt>
         POST /api/v1/client/grievance { list_user_grievances }  Authorization: Bearer <jwt>
                │
         InterceptingFilter: category=client
           → Bearer token present → getPrincipalClaims(token) → type=PRINCIPAL ✓
           → scope ≠ PURGE → stamp request attributes: fiduciary_id, principal_user_id, auth_via_principal_jwt=true
           → authenticated=true
                │
         Consent/Grievance.java: user_id from body must equal principal_user_id from JWT → enforced
```

### 5.2 Session Storage Schema

All session keys use the prefix `pp_` and live in `sessionStorage`:

| Key | Type | Contents |
|-----|------|---------|
| `pp_token` | string | PRINCIPAL JWT (24-hour expiry) |
| `pp_user_id` | string | Email or mobile number used to log in |
| `pp_fiduciary_id` | string | UUID of the selected fiduciary |
| `pp_fiduciary_name` | string | Display name of the fiduciary |
| `pp_policy_id` | string | Active policy ID at time of login (may be empty) |

### 5.3 PRINCIPAL JWT Structure

```
Header: { alg: HS256 }
Payload: {
    sub:  "user@example.com",    // user_id (email or mobile)
    fid:  "uuid",                // fiduciary_id
    type: "PRINCIPAL",           // token type — blocks use on admin paths
    jti:  "uuid",                // unique token ID for revocation
    iat:  <unix timestamp>,
    exp:  <iat + 86400>          // 24-hour expiry
}
```

`isTokenValid()` in `JWTUtil.java` rejects tokens with `type=PRINCIPAL` on admin API paths, the same way it rejects `type=SYNC` wallet tokens.

---

## 6. Implementation

### Step 1 — JWT Utility Extension
**Modified:** `src/org/tsicoop/dpdpcms/framework/JWTUtil.java`

| Addition | Description |
|----------|-------------|
| `TYPE_PRINCIPAL = "PRINCIPAL"` | Token type constant |
| `PRINCIPAL_TOKEN_EXPIRY = 86400000L` | 24-hour expiry in milliseconds |
| `generatePrincipalToken(userId, fiduciaryId)` | Issues a scoped PRINCIPAL JWT |
| `getPrincipalClaims(token)` | Validates type, checks blocklist, returns claims or null |
| Updated `isTokenValid()` | Now also rejects `type=PRINCIPAL` on admin paths |

---

### Step 2 — Filter Extension
**Modified:** `src/org/tsicoop/dpdpcms/framework/InterceptingFilter.java`

**Addition 1 — `public` API category**
```java
private static final String PUBLIC_URI_PATH = "public";
private static final Set<String> PUBLIC_ALLOWED_FUNCS = new HashSet<>(Arrays.asList(
    "principal_login",
    "list_active_fiduciaries"
));
```
Routes matching `/api/v1/public/*` bypass authentication entirely. Only functions in `PUBLIC_ALLOWED_FUNCS` are accepted; all others return 403.

**Addition 2 — PRINCIPAL JWT auth for client APIs**

For `/api/v1/client/*` requests, the filter now checks for a Bearer token before falling back to `X-API-Key` / `X-API-Secret`:

```
Authorization: Bearer <principal-jwt>
    → getPrincipalClaims(token) → type=PRINCIPAL ✓
    → scope is PURGE? → 403 Forbidden
    → stamp req.setAttribute("fiduciary_id", fid)
    → stamp req.setAttribute("principal_user_id", sub)
    → stamp req.setAttribute("auth_via_principal_jwt", true)
    → authenticated = true
```

---

### Step 3 — Principal Service
**New file:** `src/org/tsicoop/dpdpcms/service/v1/Principal.java`

Implements `Action`. Dispatches on `_func`:

| Function | Behaviour |
|----------|-----------|
| `list_active_fiduciaries` | `SELECT id, name FROM fiduciaries WHERE status='ACTIVE' ORDER BY name` — returns JSON array of `{ fiduciary_id, name }` with no PII |
| `principal_login` | Validates OTP (default: `1234`), confirms fiduciary is ACTIVE, fetches the active `policy_id` for the fiduciary, calls `JWTUtil.generatePrincipalToken()`, writes an audit event, returns `{ success, token, user_id, fiduciary_id, fiduciary_name, policy_id }` |

The OTP validation line is explicitly marked for replacement:
```java
// TODO: replace with real OTP verification (SMS/email)
if (!PLACEHOLDER_OTP.equals(otp)) { ... }
```

---

### Step 4 — Consent & Grievance Guards
**Modified:** `src/org/tsicoop/dpdpcms/service/v1/Consent.java`
**Modified:** `src/org/tsicoop/dpdpcms/service/v1/Grievance.java`

Two changes applied to both files in the `post()` method:

**Change 1 — fiduciary_id fallback from request attribute**
```java
if (fiduciaryIdStr == null) {
    Object fidAttr = req.getAttribute("fiduciary_id");
    if (fidAttr != null) fiduciaryIdStr = fidAttr.toString();
}
// fall back to API key lookup if still null
if (fiduciaryIdStr == null) {
    fiduciaryIdStr = new Fiduciary().getFiduciaryId(...);
}
```

**Change 2 — user_id mismatch guard**
```java
Boolean viaPrincipalJwt = (Boolean) req.getAttribute("auth_via_principal_jwt");
if (Boolean.TRUE.equals(viaPrincipalJwt) && userId != null) {
    String principalUserId = (String) req.getAttribute("principal_user_id");
    if (!userId.equals(principalUserId)) {
        OutputProcessor.errorResponse(res, 403, "Forbidden",
            "User ID mismatch: token does not authorize access to the requested principal.", uri);
        return;
    }
}
```

---

### Step 5 — Service Registry
**Modified:** `web/WEB-INF/_processor.tsi`

```
/api/v1/principal=org.tsicoop.dpdpcms.service.v1.Principal
```

---

### Step 6 — JSON Schema Validators
**New file:** `web/WEB-INF/validator/principal_login.jschema`
**New file:** `web/WEB-INF/validator/list_active_fiduciaries.jschema`

Required fields validated at the framework layer before the service is invoked.

---

### Step 7 — Frontend
**New directory:** `web/rights/`

| File | Purpose |
|------|---------|
| `portal.js` | Shared session management, `apiCall()` with Bearer auth, `requireAuth()` redirect guard, escaping and formatting helpers |
| `index.html` | Login page: fiduciary dropdown or `?fid` pre-selection badge, email/mobile + OTP form, inline error display, redirect to `dashboard.html` on success |
| `dashboard.html` | 3-tab portal: Manage Consent, Consent History, Requests & Grievances |

---

## 7. API Reference

### `POST /api/v1/public/principal` — No authentication required

**`list_active_fiduciaries`**
```json
Request:  { "_func": "list_active_fiduciaries" }
Response: [ { "fiduciary_id": "<uuid>", "name": "<string>" }, ... ]
```

**`principal_login`**
```json
Request:
{
  "_func": "principal_login",
  "fiduciary_id": "<uuid>",
  "user_id": "user@example.com",
  "otp": "1234"
}

Response (200):
{
  "success": true,
  "token": "<principal-jwt>",
  "user_id": "user@example.com",
  "fiduciary_id": "<uuid>",
  "fiduciary_name": "Example Organisation",
  "policy_id": "WEB_POLICY_V1"
}

Response (401): { "status": 401, "error": "Unauthorized", "message": "Invalid OTP." }
```

---

### `POST /api/v1/client/*` — PRINCIPAL Bearer JWT

All existing client API functions remain unchanged. The portal uses the following subset:

| Endpoint | Function | Scope |
|----------|----------|-------|
| `/api/v1/client/policy` | `get_active_policy` | READ |
| `/api/v1/client/policy` | `get_policy` | READ |
| `/api/v1/client/consent` | `get_active_consent` | READ |
| `/api/v1/client/consent` | `list_consent_history` | READ |
| `/api/v1/client/consent` | `get_consent_record_details` | READ |
| `/api/v1/client/consent` | `validate_consent` | READ |
| `/api/v1/client/consent` | `record_consent` | WRITE |
| `/api/v1/client/consent` | `withdraw_consent` | WRITE |
| `/api/v1/client/consent` | `erasure_request` | WRITE |
| `/api/v1/client/grievance` | `list_user_grievances` | READ |
| `/api/v1/client/grievance` | `submit_grievance` | WRITE |

PURGE-scoped functions are rejected with 403 when called with a PRINCIPAL token.

---

## 8. Files Created / Modified

### New Files

| File | Purpose |
|------|---------|
| `src/.../service/v1/Principal.java` | Public authentication service — login and fiduciary listing |
| `web/rights/index.html` | Login page |
| `web/rights/dashboard.html` | Main portal dashboard (3 tabs) |
| `web/rights/portal.js` | Shared session and API utilities |
| `web/WEB-INF/validator/principal_login.jschema` | JSON schema for `principal_login` |
| `web/WEB-INF/validator/list_active_fiduciaries.jschema` | JSON schema for `list_active_fiduciaries` |

### Modified Files

| File | Change |
|------|--------|
| `src/.../framework/JWTUtil.java` | PRINCIPAL token generation and validation; `isTokenValid()` updated to reject PRINCIPAL type |
| `src/.../framework/InterceptingFilter.java` | Added `public` API category; added PRINCIPAL JWT auth path for client APIs |
| `src/.../service/v1/Consent.java` | fiduciary_id fallback from request attribute; user_id mismatch guard |
| `src/.../service/v1/Grievance.java` | Same as Consent.java |
| `web/WEB-INF/_processor.tsi` | Registered `/api/v1/principal` service mapping |

---

## 9. Verification

### 9.1 API Verification (curl / Postman)

| Test | Expected Result |
|------|----------------|
| `POST /api/v1/public/principal { list_active_fiduciaries }` — no headers | 200, JSON array of `{ fiduciary_id, name }` |
| `POST /api/v1/public/principal { principal_login, otp:"1234" }` | 200, JSON with `token` field |
| Same with `otp:"9999"` | 401 Unauthorized |
| Same with inactive fiduciary_id | 401 Unauthorized |
| `POST /api/v1/public/principal { unknown_func }` | 403 Forbidden |
| Client policy call with `Authorization: Bearer <principal-jwt>` | 200, active policy JSON |
| Client consent `list_consent_history` with PRINCIPAL token | 200, consent array |
| Client consent with `user_id` ≠ token subject | 403 Forbidden |
| Client consent `list_purge_requests` with PRINCIPAL token | 403 Forbidden (PURGE scope blocked) |
| Admin API `POST /api/v1/admin/operator { list_users }` with PRINCIPAL token | 401 Unauthorized |

### 9.2 Browser Verification

| Test | Expected Result |
|------|----------------|
| Navigate to `/rights/` | Fiduciary dropdown loads from live API |
| Navigate to `/rights/?fid=<valid-uuid>` | Dropdown hidden, fiduciary name shown as badge |
| Navigate to `/rights/?fid=<invalid-uuid>` | Error message: "Fiduciary not found or inactive" |
| Login with `1234` | Session written to sessionStorage, redirect to dashboard |
| Inspect DevTools → Application → sessionStorage | All 5 `pp_*` keys present |
| Close tab, reopen `dashboard.html` directly | Redirect to `index.html` (session cleared) |
| Dashboard Tab 1 | Preference center loads with toggles from policy; pre-populated from active consent |
| Save preferences | Green confirmation banner appears; consent record created in CMS |
| Dashboard Tab 2 | Consent history table renders; Detail modal shows purpose breakdown |
| Verify consent for a purpose | Badge shows ACTIVE or NOT GRANTED inline |
| Withdraw All | Confirm dialog → record updated → table refreshes |
| Dashboard Tab 3 | Grievance list renders; new request form expands and submits |
| Logout | sessionStorage cleared, redirected to login page |

---

## 10. Planned Enhancements

| Enhancement | Description |
|-------------|-------------|
| Real OTP integration | Replace `PLACEHOLDER_OTP = "1234"` in `Principal.java` with call to an SMS/email OTP service; add OTP generation endpoint to the `public` API |
| OTP rate limiting | Add IP-based rate limiting in `Principal.java` to prevent brute-force OTP attempts |
| Principal JWT revocation | On logout, add PRINCIPAL token JTI to `TokenBlocklist` so the 24-hour window cannot be exploited on a shared device |
| Fiduciary branding | Accept `logo_url` and `primary_colour` from the fiduciary record; apply to the login page to support white-label deployments |
| Multi-language login page | Detect browser language and render the login page in the fiduciary's available policy languages |
| Notification tab | Add a fourth tab to the dashboard surfacing `list_notifications` (already in the client API) |
| Mobile-first layout | The current layout uses a desktop-first card approach; a responsive tab-sheet layout would improve usability on mobile where most consent interactions occur |
